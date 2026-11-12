"""Tableau de bord de mouchard : appareils, domaines en direct, blocage, et questions à l'agent IA.

Lancé par mouchard.py. L'historique DNS est privé : toute requête doit porter le jeton (~/.config/mouchard/jeton).
"""
import json
import os
import re
import secrets
import sqlite3
import time
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import resume
from mouchard import BASE, LISTE, liste

PORT_WEB = int(os.environ.get("MOUCHARD_PORT_WEB", "8053"))
FICHIER_JETON = Path.home() / ".config/mouchard/jeton"
PAGE = Path(__file__).parent / "page.html"
DOMAINE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$")


def jeton():
    if not FICHIER_JETON.exists():
        FICHIER_JETON.parent.mkdir(parents=True, exist_ok=True)
        FICHIER_JETON.write_text(secrets.token_urlsafe(9))
        FICHIER_JETON.chmod(0o600)
    return FICHIER_JETON.read_text().strip()


def etat(ip=None):
    db = sqlite3.connect(BASE)
    appareils = [dict(zip(("ip", "mac", "requetes", "bloquees", "dernier"), l)) for l in db.execute(
        """SELECT a.ip, a.mac, COUNT(r.t), COALESCE(SUM(r.bloque), 0), MAX(r.t) FROM appareils a
           LEFT JOIN requetes r ON r.ip = a.ip AND r.t >= ? GROUP BY a.ip ORDER BY MAX(r.t) DESC""",
        (time.time() - 86400,))]
    filtre, params = ("AND ip = ?", (ip,)) if ip else ("", ())
    domaines = [dict(zip(("domaine", "requetes", "bloque"), l)) for l in db.execute(
        f"""SELECT domaine, COUNT(*), MAX(bloque) FROM requetes WHERE t >= ? {filtre}
            GROUP BY domaine ORDER BY COUNT(*) DESC LIMIT 60""", (time.time() - 86400, *params))]
    direct = [dict(zip(("t", "ip", "domaine", "bloque"), l)) for l in db.execute(
        f"SELECT t, ip, domaine, bloque FROM requetes WHERE t >= 0 {filtre} ORDER BY t DESC LIMIT 40", params)]
    return {"appareils": appareils, "domaines": domaines, "direct": direct}


def bloquer(domaine):
    domaine = domaine.strip().lower()
    if not DOMAINE.match(domaine):
        raise ValueError("domaine invalide")
    if not liste.contient(domaine):
        with LISTE.open("a") as f:
            f.write(domaine + "\n")
    return domaine


def demander(question):
    if not resume.cle():
        return "L'agent n'a pas de clé : mets-la dans ~/.config/mouchard/cle."
    appareils = resume.donnees(time.time() - 86400)
    if not appareils:
        return "Aucune requête DNS en 24 h : rien à analyser."
    try:
        return resume.demander(json.dumps(appareils, ensure_ascii=False), question or None)
    except (urllib.error.URLError, TimeoutError, KeyError) as e:
        return f"L'agent n'a pas pu répondre ({e})."


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
            return self.repondre(403, b"Jeton manquant : ouvre l'adresse affichee au lancement de mouchard.", "text/plain")
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
            if self.path == "/api/question":
                return self.repondre(200, {"reponse": demander(str(corps.get("question", ""))[:500])})
        except ValueError as e:
            return self.repondre(400, {"erreur": str(e)})
        self.repondre(404, {"erreur": "inconnu"})

    def log_message(self, *_):
        pass  # le jeton passe dans l'URL : on ne le garde pas dans les journaux


def servir(ecoute):
    print(f"tableau de bord : http://{'127.0.0.1' if ecoute == '0.0.0.0' else ecoute}:{PORT_WEB}/?jeton={jeton()}", flush=True)
    ThreadingHTTPServer((ecoute, PORT_WEB), Gestion).serve_forever()
