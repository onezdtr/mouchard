"""mouchard : serveur DNS qui note, appareil par appareil, les domaines contactés.

Les requêtes sont relayées vers un vrai serveur DNS ; les domaines de bloquer.txt reçoivent « n'existe pas ».
Chaque nouvel appareil déclenche une alerte Telegram (bot du chasseur d'alternance).
"""
import json
import os
import socket
import socketserver
import sqlite3
import threading
import time
import urllib.request
from pathlib import Path

ICI = Path(__file__).parent
BASE = ICI / "mouchard.db"
LISTE = ICI / "bloquer.txt"
CONFIG = Path.home() / ".config/alternance"
ECOUTE = os.environ.get("MOUCHARD_ECOUTE", "127.0.0.1")  # 0.0.0.0 sur le serveur, jamais sur un réseau qui n'est pas le nôtre
PORT = int(os.environ.get("MOUCHARD_PORT", "5300"))  # 53 sur le serveur
AMONT = (os.environ.get("MOUCHARD_AMONT", "1.1.1.1"), 53)

verrou = threading.Lock()
db = sqlite3.connect(BASE, check_same_thread=False)
db.executescript("""
CREATE TABLE IF NOT EXISTS requetes (t REAL, ip TEXT, domaine TEXT, bloque INTEGER);
CREATE TABLE IF NOT EXISTS appareils (ip TEXT PRIMARY KEY, mac TEXT, vu_le REAL);
CREATE INDEX IF NOT EXISTS requetes_t ON requetes (t);
""")


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


def reponse_vide(paquet, fin, code):
    """Réponse sans enregistrement : code 3 = domaine inexistant, 2 = échec du serveur."""
    drapeaux = 0x8080 | (paquet[2] & 0x79) << 8 | code  # réponse + opcode et RD du client + RA
    return paquet[:2] + drapeaux.to_bytes(2, "big") + b"\x00\x01" + b"\x00" * 6 + paquet[12:fin]


class Liste:
    """bloquer.txt, relu dès qu'il change : un domaine bloque aussi tous ses sous-domaines."""
    def __init__(self, chemin):
        self.chemin, self.date, self.domaines = chemin, None, set()

    def contient(self, domaine):
        date = self.chemin.stat().st_mtime if self.chemin.exists() else None
        if date != self.date:
            lignes = self.chemin.read_text().split("\n") if date else []
            self.domaines = {l.split("#")[0].strip().lower() for l in lignes} - {""}
            self.date = date
        morceaux = domaine.split(".")
        return any(".".join(morceaux[i:]) in self.domaines for i in range(len(morceaux)))


liste = Liste(LISTE)


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


def alerter(texte):
    """Ne fait rien si le bot n'est pas configuré ; une alerte ratée ne doit pas couper le DNS."""
    try:
        jeton, chat = (CONFIG / "telegram").read_text().strip(), (CONFIG / "telegram_chat").read_text().strip()
        corps = json.dumps({"chat_id": int(chat), "text": texte}).encode()
        urllib.request.urlopen(urllib.request.Request(f"https://api.telegram.org/bot{jeton}/sendMessage", corps,
                                                      {"Content-Type": "application/json"}), timeout=10)
    except (OSError, ValueError) as e:
        print("alerte non envoyée :", e, flush=True)


def noter(ip, domaine, bloque):
    with verrou:
        nouveau = db.execute("SELECT 1 FROM appareils WHERE ip = ?", (ip,)).fetchone() is None
        if nouveau:
            db.execute("INSERT INTO appareils VALUES (?, ?, ?)", (ip, mac_de(ip), time.time()))
        db.execute("INSERT INTO requetes VALUES (?, ?, ?, ?)", (time.time(), ip, domaine, int(bloque)))
        db.commit()
    if nouveau:
        threading.Thread(target=alerter, args=(f"Nouvel appareil sur le réseau : {ip} {mac_de(ip)}\n1er domaine : {domaine}",)).start()


def relayer(paquet):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(3)
        s.sendto(paquet, AMONT)
        return s.recv(4096)


class Gestion(socketserver.BaseRequestHandler):
    def handle(self):
        paquet, sock = self.request
        try:
            domaine, fin = lire_question(paquet)
        except (ValueError, IndexError):
            return  # on ignore ce qui n'est pas une requête DNS
        bloque = liste.contient(domaine)
        try:
            reponse = reponse_vide(paquet, fin, 3) if bloque else relayer(paquet)
        except OSError:
            reponse = reponse_vide(paquet, fin, 2)
        sock.sendto(reponse, self.client_address)
        noter(self.client_address[0], domaine, bloque)


if __name__ == "__main__":
    serveur = socketserver.ThreadingUDPServer((ECOUTE, PORT), Gestion)
    print(f"mouchard écoute sur {ECOUTE}:{PORT}, relais {AMONT[0]}", flush=True)
    serveur.serve_forever()
