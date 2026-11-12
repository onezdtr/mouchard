"""Agent du soir : une IA lit les domaines des dernières 24 h et explique en clair qui parle à qui.

Usage : python3 resume.py           -> envoie le résumé sur Telegram
        python3 resume.py --ecran   -> l'affiche seulement
"""
import json
import os
import sqlite3
import sys
import time
import urllib.request
from pathlib import Path

from mouchard import BASE, alerter

MODELE = os.environ.get("MOUCHARD_MODELE", "gemini-3.1-flash-lite")
LANGUE = os.environ.get("MOUCHARD_LANGUE", "English")  # langue du rapport du jour
CONSIGNE = f"""You are the network administrator of a home. You get, device by device, the domains contacted
in the last 24 hours (number of requests, and how many were blocked). Write in plain {LANGUE}, for Telegram:
- one line per device: what it does, judging by its domains (e.g. "TV box: mostly ads and audience tracking");
- anything suspicious or surprising (trackers, unexpected countries, activity at night);
- a "Block?" list of ad or tracking domains, never suggesting a domain the device needs to work.
No markdown, 1500 characters at most. Only mention domains present in the data."""


def donnees(depuis):
    """Pour chaque appareil, ses 40 domaines les plus demandés depuis `depuis`."""
    db = sqlite3.connect(BASE)
    lignes = db.execute("""SELECT r.ip, a.mac, r.domaine, COUNT(*), SUM(r.bloque),
                                  SUM(CAST(strftime('%H', r.t, 'unixepoch', 'localtime') AS INTEGER) < 6)
                           FROM requetes r LEFT JOIN appareils a ON a.ip = r.ip
                           WHERE r.t >= ? GROUP BY r.ip, r.domaine ORDER BY r.ip, COUNT(*) DESC""", (depuis,)).fetchall()
    appareils = {}
    for ip, mac, domaine, n, bloques, nuit in lignes:
        app = appareils.setdefault(ip, {"ip": ip, "mac": mac, "domaines": []})
        if len(app["domaines"]) < 40:  # shortcut: top 40 par appareil pour tenir dans le prompt ; agréger par domaine parent si trop court
            app["domaines"].append({"domaine": domaine, "requetes": n, "bloquees": bloques, "entre_0h_et_6h": nuit})
    return list(appareils.values())


CONSIGNE_QUESTION = """You are the network administrator of a home. You get, device by device, the domains contacted
in the last 24 hours, then a question. Answer briefly and simply, in the language of the question, using only this data;
if the data cannot answer it, say so."""


def cle():
    """La variable GEMINI_API_KEY, sinon le fichier ~/.config/mouchard/cle (pour ne pas la taper en clair)."""
    fichier = Path.home() / ".config/mouchard/cle"
    return os.environ.get("GEMINI_API_KEY") or (fichier.read_text().strip() if fichier.exists() else "")


def demander(donnees_json, question=None):
    """Sans question : le résumé du soir. Avec : la réponse de l'agent à cette question."""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{MODELE}:generateContent"
    texte = donnees_json + (f"\n\nQuestion: {question}" if question else "")
    corps = {"systemInstruction": {"parts": [{"text": CONSIGNE_QUESTION if question else CONSIGNE}]},
             "contents": [{"role": "user", "parts": [{"text": texte}]}]}
    req = urllib.request.Request(url, json.dumps(corps).encode(), {
        "Content-Type": "application/json", "x-goog-api-key": cle()})
    reponse = json.load(urllib.request.urlopen(req, timeout=120))
    return "".join(p.get("text", "") for p in reponse["candidates"][0]["content"]["parts"])


if __name__ == "__main__":
    appareils = donnees(time.time() - 86400)
    if not appareils:
        texte = "mouchard: no DNS request in the last 24 hours. Is the server running?"
    else:
        texte = "mouchard, daily report\n\n" + demander(json.dumps(appareils, ensure_ascii=False))
    print(texte) if "--ecran" in sys.argv else alerter(texte[:4000])
