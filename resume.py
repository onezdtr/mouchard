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

from mouchard import BASE, alerter

MODELE = os.environ.get("MOUCHARD_MODELE", "gemini-3.1-flash-lite")
CONSIGNE = """Tu es l'administrateur réseau d'une maison. On te donne, appareil par appareil, les domaines
contactés en 24 h (nombre de requêtes, et combien ont été bloquées). Écris en français simple, pour Telegram :
- une ligne par appareil : ce qu'il fait, d'après ses domaines (ex. « box TV : surtout de la pub et des mesures d'audience ») ;
- ce qui est suspect ou surprenant (traqueurs, pays inattendu, activité la nuit) ;
- une liste « À bloquer ? » de domaines de pub ou de pistage, sans jamais proposer un domaine indispensable.
Pas de markdown, 1500 caractères maximum. Ne cite que des domaines présents dans les données."""


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


def demander(donnees_json):
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{MODELE}:generateContent"
    corps = {"systemInstruction": {"parts": [{"text": CONSIGNE}]},
             "contents": [{"role": "user", "parts": [{"text": donnees_json}]}]}
    req = urllib.request.Request(url, json.dumps(corps).encode(), {
        "Content-Type": "application/json", "x-goog-api-key": os.environ["GEMINI_API_KEY"]})
    reponse = json.load(urllib.request.urlopen(req, timeout=120))
    return "".join(p.get("text", "") for p in reponse["candidates"][0]["content"]["parts"])


if __name__ == "__main__":
    appareils = donnees(time.time() - 86400)
    if not appareils:
        texte = "mouchard : aucune requête DNS en 24 h. Le serveur tourne-t-il ?"
    else:
        texte = "mouchard, résumé du jour\n\n" + demander(json.dumps(appareils, ensure_ascii=False))
    print(texte) if "--ecran" in sys.argv else alerter(texte[:4000])
