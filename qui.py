"""Qui est derrière un domaine : l'entreprise et son activité (liste Disconnect), et le pays de son serveur (DB-IP).

Les deux fichiers sont téléchargés dans listes/ par mouchard.py ; sans eux, tout répond « inconnu ».
"""
import bisect
import csv
import gzip
import json
import socket
import struct
from pathlib import Path

DOSSIER = Path(__file__).parent / "listes"
DISCONNECT = DOSSIER / "disconnect.json"
DBIP = DOSSIER / "dbip-pays.csv.gz"
URL_DISCONNECT = "https://raw.githubusercontent.com/disconnectme/disconnect-tracking-protection/master/services.json"
URL_DBIP = "https://download.db-ip.com/free/dbip-country-lite-{mois}.csv.gz"

# un domaine peut être dans plusieurs catégories : on garde la plus parlante (pub et mesure avant empreinte, contenu en dernier)
PRIORITE = ["Cryptomining", "Advertising", "Analytics", "FingerprintingInvasive", "Social", "FingerprintingGeneral",
            "EmailAggressive", "Email", "Anti-fraud", "ConsentManagers", "Content"]
NOMS = {"FingerprintingInvasive": "fingerprinting", "FingerprintingGeneral": "fingerprinting", "Cryptomining": "cryptomining",
        "Advertising": "advertising", "Analytics": "analytics", "Social": "social", "EmailAggressive": "email tracking",
        "Email": "email tracking", "Anti-fraud": "anti-fraud", "ConsentManagers": "consent", "Content": "content"}


class Charge:
    """Recharge un fichier de données quand il change (mêmes règles que mouchard.Liste)."""
    def __init__(self, chemin, lire):
        self.chemin, self.lire, self.date, self.valeur = chemin, lire, None, None

    def __call__(self):
        date = self.chemin.stat().st_mtime if self.chemin.exists() else None
        if date != self.date:
            try:
                self.valeur = self.lire(self.chemin) if date else None
            except (OSError, ValueError, EOFError) as e:  # fichier abîmé : on fait comme s'il n'existait pas
                print("could not read", self.chemin.name, e, flush=True)
                self.valeur = None
            self.date = date
        return self.valeur


def lire_disconnect(chemin):
    """{domaine: (entreprise, catégorie)}"""
    donnees, resultat = json.loads(chemin.read_text())["categories"], {}
    for categorie in reversed(PRIORITE):  # la plus intrusive écrit en dernier
        for entree in donnees.get(categorie, []):
            for entreprise, sites in entree.items():
                for domaines in sites.values():
                    if isinstance(domaines, list):
                        for d in domaines:
                            resultat[d.lower()] = (entreprise, NOMS[categorie])
    return resultat


def lire_dbip(chemin):
    """(débuts des plages IPv4 triés, codes pays) pour une recherche par dichotomie"""
    debuts, pays = [], []
    with gzip.open(chemin, "rt") as f:
        for debut, _, code in csv.reader(f):
            if ":" not in debut:  # IPv6 ignorée
                debuts.append(struct.unpack("!I", socket.inet_aton(debut))[0])
                pays.append(code)
    return debuts, pays


entreprises = Charge(DISCONNECT, lire_disconnect)
plages = Charge(DBIP, lire_dbip)


def entreprise(domaine):
    """(entreprise, catégorie) ou (None, None) ; un domaine connu couvre ses sous-domaines."""
    table = entreprises() or {}
    morceaux = domaine.split(".")
    for i in range(len(morceaux) - 1):
        if (trouve := table.get(".".join(morceaux[i:]))):
            return trouve
    return None, None


def pays(ip):
    """Code pays à 2 lettres (« US »), ou None."""
    donnees = plages()
    if not donnees or not ip:
        return None
    try:
        n = struct.unpack("!I", socket.inet_aton(ip))[0]
    except OSError:
        return None
    i = bisect.bisect_right(donnees[0], n) - 1
    code = donnees[1][i] if i >= 0 else None
    return None if code in (None, "ZZ") else code
