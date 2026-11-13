"""khada3 : serveur DNS qui note, appareil par appareil, les domaines contactés.

Les requêtes sont relayées vers un vrai serveur DNS ; les domaines de bloquer.txt reçoivent « n'existe pas ».
Chaque nouvel appareil déclenche une alerte Telegram (voir messager.py).
"""
import json
import os
import re
import socket
import socketserver
import sqlite3
import subprocess
import threading
import time
import urllib.request
from pathlib import Path

import messager
import qui

ICI = Path(__file__).parent
BASE = ICI / "khada3.db"
LISTE = ICI / "bloquer.txt"
AUTORISER = ICI / "autoriser.txt"
PUBLIQUE = ICI / "listes/publique.txt"
CANDIDATS = ICI / "listes/candidats.txt"  # liste plus stricte, non appliquée : ce que l'agent a le droit de proposer
URL_CANDIDATS = os.environ.get("KHADA3_CANDIDATS_URL", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt")
DOMAINE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$")
URL_PUBLIQUE = os.environ.get("KHADA3_LISTE_URL", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts")  # vide : désactivée
ECOUTE = os.environ.get("KHADA3_ECOUTE", "127.0.0.1")  # 0.0.0.0 sur le serveur, jamais sur un réseau qui n'est pas le nôtre
PORT = int(os.environ.get("KHADA3_PORT", "5300"))  # 53 sur le serveur
AMONTS = [(ip.strip(), 53) for ip in os.environ.get("KHADA3_AMONT", "1.1.1.1,9.9.9.9").split(",")]  # le suivant si le premier ne répond pas
SANTE = "sante.khada3.invalid"  # question que khada3 se pose à lui-même : répondue sur place, jamais notée

verrou = threading.RLock()  # réentrant : décider d'une proposition puis bloquer le domaine le reprend
db = sqlite3.connect(BASE, check_same_thread=False)
db.executescript("""
CREATE TABLE IF NOT EXISTS requetes (t REAL, ip TEXT, domaine TEXT, bloque INTEGER);
CREATE TABLE IF NOT EXISTS appareils (ip TEXT PRIMARY KEY, mac TEXT, vu_le REAL);
CREATE INDEX IF NOT EXISTS requetes_t ON requetes (t);
CREATE TABLE IF NOT EXISTS domaines (domaine TEXT PRIMARY KEY, ip TEXT);
CREATE TABLE IF NOT EXISTS propositions (id INTEGER PRIMARY KEY, t REAL, domaine TEXT UNIQUE, raison TEXT, etat TEXT DEFAULT 'attente');
CREATE TABLE IF NOT EXISTS habitudes (ip TEXT, genre TEXT, valeur TEXT, PRIMARY KEY (ip, genre, valeur));
""")
if "nom" not in [c[1] for c in db.execute("PRAGMA table_info(appareils)")]:
    db.execute("ALTER TABLE appareils ADD COLUMN nom TEXT")  # bases créées avant les noms d'appareils
GARDER = 30 * 86400  # au-delà, les requêtes sont effacées
APPRENTISSAGE = 86400  # un appareil neuf contacte tout : pas d'alerte « première fois » pendant son premier jour
MAX_ALERTES = 10  # par heure : une appli neuve qui contacte 30 pisteurs ne doit pas inonder Telegram
alertes = []  # dates des dernières alertes envoyées
cache, verrou_cache = {}, threading.Lock()


def lire_question(paquet):
    """Renvoie (domaine, fin de la question) ; ValueError si le paquet est mal formé."""
    if len(paquet) < 12 or paquet[4:6] != b"\x00\x01":  # une seule question, comme tous les clients
        raise ValueError("paquet DNS inattendu")
    i, morceaux = 12, []
    while True:
        n = paquet[i]
        if n == 0:
            break
        if n > 63 or i + 1 + n > len(paquet):  # 63 max ; pas de compression dans une question
            raise ValueError("nom invalide")
        morceaux.append(paquet[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    fin = i + 5  # octet nul + type + classe
    if fin > len(paquet):
        raise ValueError("question tronquée")
    return ".".join(morceaux).lower(), fin


def sauter_nom(paquet, i):
    """Position après un nom DNS (compressé ou non) dans une réponse."""
    while True:
        n = paquet[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:  # pointeur de compression : 2 octets, fin du nom
            return i + 2
        i += 1 + n


def lire_reponse(reponse, fin):
    """Adresses IPv4 et plus petit TTL des réponses ; IndexError si le paquet est tronqué."""
    i, ips, ttl = fin, [], None
    for _ in range(int.from_bytes(reponse[6:8], "big")):
        i = sauter_nom(reponse, i)
        type_, duree, taille = int.from_bytes(reponse[i:i + 2], "big"), int.from_bytes(reponse[i + 4:i + 8], "big"), int.from_bytes(reponse[i + 8:i + 10], "big")
        if i + 10 + taille > len(reponse):
            raise IndexError("réponse tronquée")
        if type_ == 1 and taille == 4:
            ips.append(socket.inet_ntoa(reponse[i + 10:i + 14]))
        ttl = duree if ttl is None else min(ttl, duree)
        i += 10 + taille
    return ips, ttl


def reponse_vide(paquet, fin, code):
    """Réponse sans enregistrement : code 3 = domaine inexistant, 2 = échec du serveur."""
    drapeaux = 0x8080 | (paquet[2] & 0x79) << 8 | code  # réponse + opcode et RD du client + RA
    return paquet[:2] + drapeaux.to_bytes(2, "big") + b"\x00\x01" + b"\x00" * 6 + paquet[12:fin]


class Liste:
    """Fichier de domaines relu dès qu'il change ; un domaine couvre tous ses sous-domaines.
    Accepte « domaine » ou le format hosts « 0.0.0.0 domaine » des listes publiques."""
    def __init__(self, chemin):
        self.chemin, self.date, self.domaines = chemin, None, set()

    def contient(self, domaine):
        date = self.chemin.stat().st_mtime if self.chemin.exists() else None
        if date != self.date:
            lignes = self.chemin.read_text().split("\n") if date else []
            self.domaines = set()
            for ligne in lignes:
                mots = ligne.split("#")[0].lower().split()
                if len(mots) == 2 and mots[0] in ("0.0.0.0", "127.0.0.1"):
                    mots = mots[1:]
                if len(mots) == 1 and "." in mots[0] and mots[0] != "0.0.0.0":
                    self.domaines.add(mots[0])
            self.date = date
        morceaux = domaine.split(".")
        return any(".".join(morceaux[i:]) in self.domaines for i in range(len(morceaux)))


liste, autorises, publique, candidats = Liste(LISTE), Liste(AUTORISER), Liste(PUBLIQUE), Liste(CANDIDATS)


def est_bloque(domaine):
    return not autorises.contient(domaine) and (liste.contient(domaine) or publique.contient(domaine))


def telecharger(urls, chemin, taille_min):
    """Premier lien qui marche, écrit d'un coup (jamais de fichier à moitié écrit pendant qu'on le lit)."""
    for url in urls:
        try:
            requete = urllib.request.Request(url, headers={"User-Agent": "khada3 (+https://github.com/onezdtr/khada3)"})  # DB-IP refuse Python-urllib
            donnees = urllib.request.urlopen(requete, timeout=60).read()
        except OSError as e:
            erreur = e
            continue
        if len(donnees) < taille_min:
            erreur = ValueError(f"{url} : fichier trop petit, téléchargement suspect")
            continue
        chemin.parent.mkdir(exist_ok=True)
        provisoire = chemin.with_name(chemin.name + ".tmp")
        provisoire.write_bytes(donnees)
        provisoire.replace(chemin)
        print(f"{chemin.name} updated ({len(donnees) // 1024} KB)", flush=True)
        return
    print(f"{chemin.name} not updated:", erreur, flush=True)


def maj_listes():
    """Liste de blocage et entreprises chaque semaine, pays chaque mois ; on revérifie chaque jour."""
    while True:
        mois = time.strftime("%Y-%m"), time.strftime("%Y-%m", time.localtime(time.time() - 28 * 86400))
        for chemin, jours, urls, taille_min in (
                (PUBLIQUE, 7, [URL_PUBLIQUE] if URL_PUBLIQUE else [], 100_000),
                (CANDIDATS, 7, [URL_CANDIDATS] if URL_CANDIDATS else [], 100_000),
                (qui.DISCONNECT, 7, [qui.URL_DISCONNECT], 50_000),
                (qui.DBIP, 30, [qui.URL_DBIP.format(mois=m) for m in mois], 1_000_000)):  # le fichier du mois sort parfois en retard
            if urls and (not chemin.exists() or chemin.stat().st_mtime < time.time() - jours * 86400):
                telecharger(urls, chemin, taille_min)
        time.sleep(86400)


def mac_de(ip):
    """Adresse MAC vue dans la table ARP du serveur (vide pour la machine elle-même)."""
    try:
        for ligne in Path("/proc/net/arp").read_text().splitlines()[1:]:
            champs = ligne.split()
            if champs[0] == ip:
                return champs[3]
    except OSError:
        pass
    return ""


OUI = Path("/usr/share/hwdata/oui.txt")  # paquet hwdata : fabricants des cartes réseau
fabricants = {}


def fabricant(mac):
    """Fabricant d'après le début de l'adresse MAC ; les iPhone et Android récents en tirent une au hasard."""
    if len(mac) < 8:
        return ""
    if int(mac[1], 16) & 2:  # bit « adresse locale » : MAC aléatoire, pas de fabricant
        return "private MAC address"
    if not fabricants and OUI.exists():
        for ligne in OUI.read_text(errors="replace").splitlines():
            if "(hex)" in ligne:
                prefixe, _, nom = ligne.partition("(hex)")
                fabricants[prefixe.strip().replace("-", ":").lower()] = nom.strip()
    return fabricants.get(mac[:8].lower(), "")


def nom_tailscale(ip):
    """Nom de la machine dans Tailscale (pas d'adresse MAC à travers le tunnel) ; vide hors Tailscale."""
    if not ip.startswith("100."):
        return ""
    try:
        etat = json.loads(subprocess.run(["tailscale", "status", "--json"], capture_output=True, timeout=3).stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        return ""
    for machine in [etat.get("Self") or {}, *(etat.get("Peer") or {}).values()]:
        if ip in (machine.get("TailscaleIPs") or []):
            return (machine.get("DNSName") or "").split(".")[0]  # le HostName d'un iPhone vaut « localhost »
    return ""


def nommer_tailscale(db):
    """Au démarrage : nomme les appareils Tailscale déjà vus et encore sans nom."""
    for (ip,) in db.execute("SELECT ip FROM appareils WHERE nom IS NULL AND ip LIKE '100.%'").fetchall():
        if nom := nom_tailscale(ip):
            db.execute("UPDATE appareils SET nom = ? WHERE ip = ?", (nom, ip))
    db.commit()


def nom_appareil(db, ip):
    nom, mac = db.execute("SELECT nom, mac FROM appareils WHERE ip = ?", (ip,)).fetchone() or (None, "")
    return nom or f"{fabricant(mac or '') or 'device'} {ip}"


def nouveautes(db, ip, domaine):
    """Pays de serveur et entreprises que cet appareil contacte pour la première fois (les retient au passage)."""
    adresse = db.execute("SELECT ip FROM domaines WHERE domaine = ?", (domaine,)).fetchone()
    entreprise, categorie = qui.entreprise(domaine)
    vues = []
    for genre, valeur, texte in (("pays", qui.pays(adresse and adresse[0]), "a server in {}"), ("entreprise", entreprise, f"{{}} ({categorie})")):
        if valeur and db.execute("INSERT OR IGNORE INTO habitudes VALUES (?, ?, ?)", (ip, genre, valeur)).rowcount:
            vues.append(texte.format(valeur))
    return vues


def alerter(texte):
    maintenant = time.time()
    alertes[:] = [t for t in alertes if t > maintenant - 3600]
    if len(alertes) < MAX_ALERTES:  # shortcut: au-delà, l'alerte est perdue (l'habitude reste notée) ; les regrouper si ça arrive souvent
        alertes.append(maintenant)
        threading.Thread(target=messager.envoyer, args=(texte,)).start()


def noter(ip, domaine, bloque):
    with verrou:
        vu_le = db.execute("SELECT vu_le FROM appareils WHERE ip = ?", (ip,)).fetchone()
        if not vu_le:
            db.execute("INSERT INTO appareils (ip, mac, vu_le, nom) VALUES (?, ?, ?, ?)", (ip, mac_de(ip), time.time(), nom_tailscale(ip) or None))
        db.execute("INSERT INTO requetes VALUES (?, ?, ?, ?)", (time.time(), ip, domaine, int(bloque)))
        vues = [] if bloque else nouveautes(db, ip, domaine)  # bloqué : l'appareil n'a rien contacté
        nom = nom_appareil(db, ip)
        db.commit()
    if not vu_le:
        mac = mac_de(ip)
        alerter(f"New device on the network: {nom} {mac}\nFirst domain: {domaine}")
    elif vues and vu_le[0] < time.time() - APPRENTISSAGE:
        alerter(f"{nom} contacted {' and '.join(vues)} for the first time\nDomain: {domaine}")


def pics_nocturnes(db, maintenant):
    """Appareils qui, entre 0 h et 6 h, ont fait dans l'heure passée 3 fois plus de requêtes que d'habitude (moyenne horaire sur 7 jours)."""
    if time.localtime(maintenant - 3600).tm_hour >= 6:
        return []
    messages = []
    for ip, n in db.execute("SELECT ip, COUNT(*) FROM requetes WHERE t >= ? GROUP BY ip", (maintenant - 3600,)).fetchall():
        moyenne = db.execute("SELECT COUNT(*) / 168.0 FROM requetes WHERE ip = ? AND t >= ? AND t < ?",
                             (ip, maintenant - 7 * 86400, maintenant - 3600)).fetchone()[0]
        if n >= max(100, 3 * moyenne):
            top = db.execute("SELECT domaine, COUNT(*) FROM requetes WHERE ip = ? AND t >= ? GROUP BY domaine ORDER BY COUNT(*) DESC LIMIT 3",
                             (ip, maintenant - 3600)).fetchall()
            messages.append(f"{nom_appareil(db, ip)}: {n} requests between {time.strftime('%H:%M', time.localtime(maintenant - 3600))} "
                            f"and {time.strftime('%H:%M', time.localtime(maintenant))}, usually {moyenne:.0f} an hour.\n"
                            + "\n".join(f"{d} ({k})" for d, k in top))
    return messages


def recevoir(sock, n):
    donnees = b""
    while len(donnees) < n:
        morceau = sock.recv(n - len(donnees))
        if not morceau:
            raise ConnectionError("connexion fermée")
        donnees += morceau
    return donnees


def noter_ip(domaine, reponse, fin):
    """Première adresse du domaine, pour retrouver le pays de son serveur."""
    try:
        ips, _ = lire_reponse(reponse, fin)
    except IndexError:
        return
    if ips:
        try:
            with verrou:
                db.execute("INSERT OR REPLACE INTO domaines VALUES (?, ?)", (domaine, ips[0]))
                db.commit()
        except sqlite3.Error as e:
            print("ip not logged:", e, flush=True)


def relayer(paquet, tcp=False):
    """Essaie chaque serveur amont dans l'ordre ; lève la dernière erreur si aucun ne répond."""
    for amont in AMONTS:
        try:
            return relayer_vers(amont, paquet, tcp)
        except OSError as e:
            erreur = e
    raise erreur


def relayer_vers(amont, paquet, tcp):
    """En TCP pour les réponses trop grosses pour l'UDP (le client réessaie en TCP quand le bit TC est levé)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as s:
        s.settimeout(3)
        if tcp:
            s.connect(amont)
            s.sendall(len(paquet).to_bytes(2, "big") + paquet)
            return recevoir(s, int.from_bytes(recevoir(s, 2), "big"))
        s.sendto(paquet, amont)
        return s.recv(4096)


def depuis_cache(paquet, fin, perime=False):
    """perime : accepte une réponse expirée, pour que les sites déjà vus marchent encore quand l'amont est en panne."""
    with verrou_cache:
        entree = cache.get(paquet[12:fin])
    if entree and (perime or entree[0] > time.time()):
        return paquet[:2] + entree[1][2:]  # la réponse gardée, avec l'identifiant de la nouvelle question
    return None


def mettre_en_cache(paquet, fin, reponse):
    """shortcut: les TTL ne sont pas décomptés (un client peut voir jusqu'à 5 min de trop) ; les réécrire si ça gêne."""
    if reponse[2] & 0x02 or reponse[3] & 0x0F not in (0, 3):  # tronquée, ou erreur du serveur
        return
    try:
        _, ttl = lire_reponse(reponse, fin)
    except IndexError:
        return
    with verrou_cache:
        if len(cache) > 5000:
            cache.clear()
        cache[paquet[12:fin]] = (time.time() + min(ttl if ttl is not None else 60, 300), reponse)


def traiter(paquet, ip, tcp=False):
    """Réponse à une question DNS, ou None si ce n'en est pas une."""
    try:
        domaine, fin = lire_question(paquet)
    except (ValueError, IndexError):
        return None
    if domaine == SANTE:
        return reponse_vide(paquet, fin, 0)
    bloque = est_bloque(domaine)
    if bloque:
        reponse = reponse_vide(paquet, fin, 3)
    elif not (reponse := depuis_cache(paquet, fin)):
        try:
            reponse = relayer(paquet, tcp)
            mettre_en_cache(paquet, fin, reponse)
            noter_ip(domaine, reponse, fin)
        except OSError:
            reponse = depuis_cache(paquet, fin, perime=True) or reponse_vide(paquet, fin, 2)
    try:
        noter(ip, domaine, bloque)
    except sqlite3.Error as e:  # un journal raté ne doit jamais priver l'appareil de sa réponse
        print("not logged:", e, flush=True)
    return reponse


class GestionUDP(socketserver.BaseRequestHandler):
    def handle(self):
        paquet, sock = self.request
        reponse = traiter(paquet, self.client_address[0])
        if reponse:
            sock.sendto(reponse, self.client_address)


class GestionTCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            while True:  # un client peut enchaîner plusieurs questions sur la même connexion
                paquet = recevoir(self.request, int.from_bytes(recevoir(self.request, 2), "big"))
                reponse = traiter(paquet, self.client_address[0], tcp=True)
                if not reponse:
                    return
                self.request.sendall(len(reponse).to_bytes(2, "big") + reponse)
        except OSError:
            pass


def apprendre(db):
    """Remplit les habitudes depuis l'historique, pour qu'une mise à jour n'envoie pas une alerte par entreprise déjà connue."""
    if db.execute("SELECT 1 FROM habitudes LIMIT 1").fetchone():
        return
    for ip, domaine in db.execute("SELECT DISTINCT ip, domaine FROM requetes WHERE bloque = 0").fetchall():
        nouveautes(db, ip, domaine)
    db.commit()


def purger():
    """Chaque heure : efface le vieil historique et cherche les pics de trafic nocturnes."""
    while True:
        with verrou:
            db.execute("DELETE FROM requetes WHERE t < ?", (time.time() - GARDER,))
            db.commit()
            pics = pics_nocturnes(db, time.time())
        for texte in pics:
            alerter("Unusual night activity\n" + texte)
        time.sleep(3600)


def en_forme():
    """Vrai si le serveur DNS répond et que la base n'est pas bloquée."""
    question = os.urandom(2) + bytes.fromhex("0100000100000000000000") + b"".join(
        bytes([len(m)]) + m.encode() for m in SANTE.split(".")) + b"\x00\x00\x01\x00\x01"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            s.sendto(question, ("127.0.0.1", PORT))
            if s.recv(512)[:2] != question[:2]:
                return False
        with verrou:
            db.execute("SELECT 1")
        return True
    except (OSError, sqlite3.Error):
        return False


def veiller():
    """Chien de garde systemd (WatchdogSec) : sans signe de vie, systemd redémarre khada3 au lieu de le laisser figé."""
    adresse = os.environ.get("NOTIFY_SOCKET")
    if not adresse:
        return  # lancé à la main, sans systemd
    if adresse.startswith("@"):
        adresse = "\0" + adresse[1:]
    while True:
        if en_forme():
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
                s.sendto(b"WATCHDOG=1", adresse)
        time.sleep(10)


if __name__ == "__main__":
    import web  # ici, pas en haut : web importe ce module
    apprendre(db)
    nommer_tailscale(db)
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    tcp = socketserver.ThreadingTCPServer((ECOUTE, PORT), GestionTCP)
    serveur = socketserver.ThreadingUDPServer((ECOUTE, PORT), GestionUDP)
    print(f"khada3 listening on {ECOUTE}:{PORT} (UDP and TCP), upstream {', '.join(a[0] for a in AMONTS)}", flush=True)
    for cible in (tcp.serve_forever, veiller, purger, maj_listes, messager.ecouter, lambda: web.servir(ECOUTE)):
        threading.Thread(target=cible, daemon=True).start()
    serveur.serve_forever()
