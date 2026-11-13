"""Tableau de bord de khada3 : appareils, domaines en direct, blocage, et questions à l'agent IA.

Lancé par khada3.py. L'historique DNS est privé : toute requête doit porter le jeton (~/.config/khada3/jeton).
"""
import json
import os
import secrets
import sqlite3
import time
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import messager
import qui
import resume
from khada3 import AUTORISER, BASE, DOMAINE, LISTE, est_bloque, fabricant, verrou

PORT_WEB = int(os.environ.get("KHADA3_PORT_WEB", "8053"))
FICHIER_JETON = Path.home() / ".config/khada3/jeton"
PAGE = Path(__file__).parent / "page.html"


def jeton():
    if not FICHIER_JETON.exists():
        FICHIER_JETON.parent.mkdir(parents=True, exist_ok=True)
        FICHIER_JETON.write_text(secrets.token_urlsafe(9))
        FICHIER_JETON.chmod(0o600)
    return FICHIER_JETON.read_text().strip()


def etat(ip=None):
    db = sqlite3.connect(BASE)
    appareils = [dict(zip(("ip", "mac", "nom", "requetes", "bloquees", "dernier"), l)) for l in db.execute(
        """SELECT a.ip, a.mac, a.nom, COUNT(r.t), COALESCE(SUM(r.bloque), 0), MAX(r.t) FROM appareils a
           LEFT JOIN requetes r ON r.ip = a.ip AND r.t >= ? GROUP BY a.ip ORDER BY MAX(r.t) DESC""",
        (time.time() - 86400,))]
    for a in appareils:
        a["fabricant"] = fabricant(a["mac"] or "")
    filtre, params = ("AND ip = ?", (ip,)) if ip else ("", ())
    domaines = [{"domaine": d, "requetes": n, "bloque": est_bloque(d)} for d, n in db.execute(  # état actuel, pas l'historique
        f"""SELECT domaine, COUNT(*) FROM requetes WHERE t >= ? {filtre}
            GROUP BY domaine ORDER BY COUNT(*) DESC LIMIT 60""", (time.time() - 86400, *params))]
    direct = [dict(zip(("t", "ip", "domaine", "bloque"), l)) for l in db.execute(
        f"SELECT t, ip, domaine, bloque FROM requetes WHERE t >= 0 {filtre} ORDER BY t DESC LIMIT 40", params)]
    ips = dict(db.execute("SELECT domaine, ip FROM domaines"))
    for d in domaines:
        d["entreprise"], d["categorie"] = qui.entreprise(d["domaine"])
        d["pays"] = qui.pays(ips.get(d["domaine"]))
    par_pays = {}
    for domaine, n in db.execute(f"SELECT domaine, COUNT(*) FROM requetes WHERE t >= ? AND bloque = 0 {filtre} GROUP BY domaine",
                                 (time.time() - 86400, *params)):
        code = qui.pays(ips.get(domaine)) or "?"
        par_pays[code] = par_pays.get(code, 0) + n
    pays = sorted(({"pays": p, "requetes": n} for p, n in par_pays.items()), key=lambda x: -x["requetes"])[:12]
    propositions = [dict(zip(("id", "domaine", "raison"), l)) for l in db.execute(
        "SELECT id, domaine, raison FROM propositions WHERE etat = 'attente' ORDER BY t DESC")]
    return {"appareils": appareils, "domaines": domaines, "direct": direct, "pays": pays, "propositions": propositions,
            "heures": heures(db, filtre, params)}


def heures(db, filtre, params, maintenant=None):
    """Les 24 dernières heures, heure par heure : requêtes, bloquées et les 5 domaines les plus demandés."""
    debut = (maintenant or time.time()) // 3600 * 3600 - 23 * 3600  # début de l'heure, il y a 23 h
    cases = [{"t": debut + k * 3600, "requetes": 0, "bloquees": 0, "top": []} for k in range(24)]
    for k, domaine, n, bloquees in db.execute(
            f"""SELECT CAST((t - ?) / 3600 AS INTEGER), domaine, COUNT(*), SUM(bloque) FROM requetes WHERE t >= ? {filtre}
                GROUP BY 1, domaine ORDER BY 1, COUNT(*) DESC""", (debut, debut, *params)):
        case = cases[min(k, 23)]
        case["requetes"] += n
        case["bloquees"] += bloquees
        if len(case["top"]) < 5:
            case["top"].append({"domaine": domaine, "requetes": n})
    return cases


def valide(domaine):
    domaine = domaine.strip().lower()
    if not DOMAINE.match(domaine):
        raise ValueError("domaine invalide")
    return domaine


def retirer(fichier, domaine):
    if fichier.exists():
        lignes = fichier.read_text().split("\n")
        fichier.write_text("\n".join(l for l in lignes if l.split("#")[0].strip().lower() != domaine))


def ajouter(fichier, domaine):
    with fichier.open("a") as f:
        f.write(domaine + "\n")


def bloquer(domaine):
    domaine = valide(domaine)
    with verrou:
        retirer(AUTORISER, domaine)
        if not est_bloque(domaine):
            ajouter(LISTE, domaine)
    return domaine


def debloquer(domaine):
    """Retire le domaine de bloquer.txt ; s'il reste bloqué (liste publique, domaine parent), il passe dans autoriser.txt."""
    domaine = valide(domaine)
    with verrou:
        retirer(LISTE, domaine)
        if est_bloque(domaine):
            ajouter(AUTORISER, domaine)
    return domaine


def nommer(ip, nom):
    nom = " ".join(nom.split())[:40] or None  # vide : on efface le nom
    with verrou, sqlite3.connect(BASE) as db:  # le « with » annule la transaction en cas d'erreur, sinon la base reste verrouillée
        if not db.execute("UPDATE appareils SET nom = ? WHERE ip = ?", (nom, ip)).rowcount:
            raise ValueError("appareil inconnu")
    return nom


def decider(ident, accepter):
    """Oui ou non à une proposition de l'agent ; renvoie le domaine."""
    with verrou, sqlite3.connect(BASE) as db:
        ligne = db.execute("SELECT domaine FROM propositions WHERE id = ? AND etat = 'attente'", (ident,)).fetchone()
        if not ligne:
            raise ValueError("suggestion already handled or unknown")
        db.execute("UPDATE propositions SET etat = ? WHERE id = ?", ("acceptee" if accepter else "refusee", ident))
        if accepter:
            bloquer(ligne[0])
    return ligne[0]


def demander(question):
    if not resume.cle():
        return "The agent has no API key: put it in ~/.config/khada3/cle."
    appareils = resume.donnees(time.time() - 86400)
    if not appareils:
        return "No DNS request in the last 24 hours: nothing to analyse."
    try:
        if not question:
            texte, nouvelles = resume.rapport()
            for p in nouvelles:
                messager.proposer(p)
            return texte + (f"\n\n{len(nouvelles)} new suggestion(s) below." if nouvelles else "")
        return resume.demander(json.dumps(appareils, ensure_ascii=False), question)
    except (urllib.error.URLError, TimeoutError, KeyError, ValueError) as e:
        return f"The agent could not answer ({e})."


class Gestion(BaseHTTPRequestHandler):
    def repondre(self, code, corps, type_="application/json; charset=utf-8"):
        donnees = corps if isinstance(corps, bytes) else json.dumps(corps, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", type_)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(donnees)

    def autorise(self):
        recu = self.headers.get("X-Jeton") or parse_qs(urlparse(self.path).query).get("jeton", [""])[0]
        return secrets.compare_digest(recu.encode(), jeton().encode())

    def do_GET(self):
        url = urlparse(self.path)
        if not self.autorise():
            return self.repondre(403, b"Missing token: open the URL printed when khada3 starts.", "text/plain")
        if url.path == "/":
            return self.repondre(200, PAGE.read_bytes(), "text/html; charset=utf-8")
        if url.path == "/api/etat":
            return self.repondre(200, etat(parse_qs(url.query).get("ip", [None])[0]))
        self.repondre(404, {"erreur": "inconnu"})

    def do_POST(self):
        if not self.autorise():
            return self.repondre(403, {"erreur": "jeton"})
        try:
            corps = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 10_000)) or b"{}")
            if self.path == "/api/bloquer":
                return self.repondre(200, {"bloque": bloquer(str(corps.get("domaine", "")))})
            if self.path == "/api/decider":
                return self.repondre(200, {"domaine": decider(int(corps.get("id", 0)), bool(corps.get("accepter")))})
            if self.path == "/api/debloquer":
                return self.repondre(200, {"debloque": debloquer(str(corps.get("domaine", "")))})
            if self.path == "/api/nommer":
                return self.repondre(200, {"nom": nommer(str(corps.get("ip", "")), str(corps.get("nom", "")))})
            if self.path == "/api/question":
                return self.repondre(200, {"reponse": demander(str(corps.get("question", ""))[:500])})
        except (ValueError, TypeError) as e:
            return self.repondre(400, {"erreur": str(e)})
        self.repondre(404, {"erreur": "inconnu"})

    def log_message(self, *_):
        pass  # le jeton passe dans l'URL : on ne le garde pas dans les journaux


def servir(ecoute):
    print(f"dashboard: http://{'127.0.0.1' if ecoute == '0.0.0.0' else ecoute}:{PORT_WEB}/?jeton={jeton()}", flush=True)
    ThreadingHTTPServer((ecoute, PORT_WEB), Gestion).serve_forever()
