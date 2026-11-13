"""Agent du soir : une IA lit les domaines des dernières 24 h et explique en clair qui parle à qui.

Il propose aussi des domaines à bloquer : rien n'est bloqué sans un « oui » (tableau de bord ou bouton Telegram).

Usage : python3 resume.py           -> envoie le rapport et les propositions sur Telegram
        python3 resume.py --ecran   -> les affiche seulement
"""
import json
import os
import sqlite3
import sys
import time
import urllib.request
from pathlib import Path

import qui
import messager
from khada3 import BASE, DOMAINE, candidats, est_bloque, fabricant, verrou

MODELE = os.environ.get("KHADA3_MODELE", "gemini-3.1-flash-lite")
LANGUE = os.environ.get("KHADA3_LANGUE", "English")  # langue du rapport du jour
CONSIGNE = f"""You are the network administrator of a home. You get, device by device, the domains contacted
in the last 24 hours: number of requests, how many were blocked, the company behind the domain and its activity
when known (from the Disconnect tracker list), and the country of its server. Device names may be set by the owner,
otherwise use the maker. Write in plain {LANGUE}, for Telegram:
- one line per device: what it does, judging by its domains (e.g. "TV box: mostly ads and audience tracking");
- anything suspicious or surprising (trackers, unexpected countries, activity at night).
Put this text in "rapport": no markdown, 1500 characters at most.
In "a_bloquer", list up to 8 ad or tracking domains worth blocking, each with a one-sentence reason in {LANGUE};
only domains whose "bloquable" is true (listed as trackers by a curated blocklist, and not blocked yet).
An empty list is fine when nothing deserves it.
Only mention domains present in the data."""
SCHEMA = {"type": "OBJECT", "required": ["rapport", "a_bloquer"], "properties": {
    "rapport": {"type": "STRING"},
    "a_bloquer": {"type": "ARRAY", "items": {"type": "OBJECT", "required": ["domaine", "raison"],
                                             "properties": {"domaine": {"type": "STRING"}, "raison": {"type": "STRING"}}}}}}


def donnees(depuis):
    """Pour chaque appareil, ses 40 domaines les plus demandés depuis `depuis`."""
    db = sqlite3.connect(BASE)
    lignes = db.execute("""SELECT r.ip, a.mac, a.nom, r.domaine, COUNT(*), SUM(r.bloque),
                                  SUM(CAST(strftime('%H', r.t, 'unixepoch', 'localtime') AS INTEGER) < 6)
                           FROM requetes r LEFT JOIN appareils a ON a.ip = r.ip
                           WHERE r.t >= ? GROUP BY r.ip, r.domaine ORDER BY r.ip, COUNT(*) DESC""", (depuis,)).fetchall()
    appareils, ips = {}, dict(db.execute("SELECT domaine, ip FROM domaines"))
    for ip, mac, nom, domaine, n, bloques, nuit in lignes:
        app = appareils.setdefault(ip, {"ip": ip, "nom": nom, "fabricant": fabricant(mac or ""), "domaines": []})
        if len(app["domaines"]) < 40:  # shortcut: top 40 par appareil pour tenir dans le prompt ; agréger par domaine parent si trop court
            entreprise, categorie = qui.entreprise(domaine)
            app["domaines"].append({"domaine": domaine, "requetes": n, "bloquees": bloques, "bloquable": candidats.contient(domaine) and not est_bloque(domaine), "entre_0h_et_6h": nuit,
                                    "entreprise": entreprise, "categorie": categorie, "pays_serveur": qui.pays(ips.get(domaine))})
    return list(appareils.values())


CONSIGNE_QUESTION = """You are the network administrator of a home. You get, device by device, the domains contacted
in the last 24 hours (with the company, activity and server country when known), then a question. Answer briefly and simply, in the language of the question, using only this data;
if the data cannot answer it, say so."""


def cle():
    """La variable GEMINI_API_KEY, sinon le fichier ~/.config/khada3/cle (pour ne pas la taper en clair)."""
    fichier = Path.home() / ".config/khada3/cle"
    return os.environ.get("GEMINI_API_KEY") or (fichier.read_text().strip() if fichier.exists() else "")


def demander(donnees_json, question=None):
    """Sans question : le rapport du soir, en JSON (SCHEMA). Avec : la réponse de l'agent à cette question."""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{MODELE}:generateContent"
    texte = donnees_json + (f"\n\nQuestion: {question}" if question else "")
    corps = {"systemInstruction": {"parts": [{"text": CONSIGNE_QUESTION if question else CONSIGNE}]},
             "contents": [{"role": "user", "parts": [{"text": texte}]}]}
    if not question:
        corps["generationConfig"] = {"responseMimeType": "application/json", "responseSchema": SCHEMA}
    req = urllib.request.Request(url, json.dumps(corps).encode(), {
        "Content-Type": "application/json", "x-goog-api-key": cle()})
    reponse = json.load(urllib.request.urlopen(req, timeout=120))
    return "".join(p.get("text", "") for p in reponse["candidates"][0]["content"]["parts"])


def rapport():
    """(texte du rapport, nouvelles propositions enregistrées) ; les propositions sont filtrées avant d'être gardées."""
    appareils = donnees(time.time() - 86400)
    if not appareils:
        return "khada3: no DNS request in the last 24 hours. Is the server running?", []
    reponse = json.loads(demander(json.dumps(appareils, ensure_ascii=False)))
    vus = {d["domaine"] for a in appareils for d in a["domaines"]}
    nouvelles = []
    with verrou, sqlite3.connect(BASE) as db:
        for p in reponse.get("a_bloquer", [])[:8]:
            domaine, raison = str(p.get("domaine", "")).strip().lower(), " ".join(str(p.get("raison", "")).split())[:300]
            # garde-fou : un domaine vu, dans la liste candidate (Hagezi Pro), pas déjà bloqué, jamais proposé deux fois.
            # Sans ça, le modèle a proposé connectivitycheck.gstatic.com, dont Android a besoin pour savoir s'il a Internet.
            if domaine in vus and DOMAINE.match(domaine) and candidats.contient(domaine) and not est_bloque(domaine):
                curseur = db.execute("INSERT OR IGNORE INTO propositions (t, domaine, raison) VALUES (?, ?, ?)", (time.time(), domaine, raison))
                if curseur.rowcount:
                    nouvelles.append({"id": curseur.lastrowid, "domaine": domaine, "raison": raison})
    return "khada3, daily report\n\n" + reponse.get("rapport", ""), nouvelles


if __name__ == "__main__":
    texte, propositions = rapport()
    if "--ecran" in sys.argv:
        print(texte, *(f"\n? {p['domaine']}: {p['raison']}" for p in propositions))
    else:
        messager.envoyer(texte)
        for p in propositions:
            messager.proposer(p)
