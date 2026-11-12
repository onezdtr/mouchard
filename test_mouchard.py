import os
import tempfile
from pathlib import Path

import mouchard

# requête « A exemple.fr », id 0xabcd, RD levé
REQUETE = bytes.fromhex("abcd01000001000000000000") + b"\x07exemple\x02fr\x00" + b"\x00\x01\x00\x01"


def test_lire_question():
    domaine, fin = mouchard.lire_question(REQUETE)
    assert domaine == "exemple.fr" and fin == len(REQUETE)


def test_paquets_mal_formes():
    for mauvais in (b"", REQUETE[:14], REQUETE[:-2], REQUETE[:12] + b"\x50" + b"a" * 80):
        try:
            mouchard.lire_question(mauvais)
        except (ValueError, IndexError):
            continue
        raise AssertionError(mauvais)


def test_reponse_bloquee():
    _, fin = mouchard.lire_question(REQUETE)
    r = mouchard.reponse_vide(REQUETE, fin, 3)
    assert r[:2] == b"\xab\xcd"  # même identifiant
    assert r[2] == 0x81 and r[3] == 0x83  # réponse, RD recopié, RA, domaine inexistant
    assert r[4:12] == b"\x00\x01" + b"\x00" * 6 and r[12:] == REQUETE[12:]


def test_liste_sous_domaines_et_relecture():
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "bloquer.txt"
        f.write_text("# commentaire\ndoubleclick.net  # pub\n")
        liste = mouchard.Liste(f)
        assert liste.contient("ad.doubleclick.net") and liste.contient("doubleclick.net")
        assert not liste.contient("notdoubleclick.net") and not liste.contient("net")
        f.write_text("exemple.fr\n")
        os.utime(f, (1, 1))  # date différente même si l'écriture tombe dans la même seconde
        assert liste.contient("www.exemple.fr") and not liste.contient("ad.doubleclick.net")


def test_bloquer_refuse_les_domaines_invalides():
    import web
    for mauvais in ("", "pas un domaine", "a\nb.com", "x" * 300 + ".com", "../etc", "com"):
        try:
            web.bloquer(mauvais)
        except ValueError:
            continue
        raise AssertionError(mauvais)
    assert web.DOMAINE.match("ads.tiktok.com") and web.DOMAINE.match("_dns.example.fr")


# réponse à REQUETE : 2 enregistrements A dont le nom pointe vers la question (compression 0xc00c), TTL 120 et 30
REPONSE = (bytes.fromhex("abcd81800001000200000000") + REQUETE[12:]
           + bytes.fromhex("c00c00010001000000780004") + bytes([93, 184, 215, 14])
           + bytes.fromhex("c00c000100010000001e0004") + bytes([93, 184, 215, 15]))


def test_lire_reponse():
    _, fin = mouchard.lire_question(REQUETE)
    assert mouchard.lire_reponse(REPONSE, fin) == (["93.184.215.14", "93.184.215.15"], 30)
    try:
        mouchard.lire_reponse(REPONSE[:-3], fin)
        raise AssertionError("réponse tronquée acceptée")
    except IndexError:
        pass


def test_cache_garde_la_reponse_avec_le_nouvel_identifiant():
    _, fin = mouchard.lire_question(REQUETE)
    mouchard.cache.clear()
    mouchard.mettre_en_cache(REQUETE, fin, REPONSE)
    autre = b"\x12\x34" + REQUETE[2:]
    assert mouchard.depuis_cache(autre, fin) == b"\x12\x34" + REPONSE[2:]
    mouchard.cache.clear()
    tronquee = REPONSE[:2] + bytes([REPONSE[2] | 0x02]) + REPONSE[3:]
    mouchard.mettre_en_cache(REQUETE, fin, tronquee)
    assert mouchard.depuis_cache(REQUETE, fin) is None


def test_renommage_refuse_ne_verrouille_pas_la_base():
    import sqlite3
    import web
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "t.db")
        sqlite3.connect(base).executescript("CREATE TABLE appareils (ip TEXT PRIMARY KEY, mac TEXT, vu_le REAL, nom TEXT);"
                                            "CREATE TABLE requetes (t REAL, ip TEXT, domaine TEXT, bloque INTEGER);")
        ancienne, web.BASE = web.BASE, base
        try:
            web.nommer("10.9.9.9", "x")
            raise AssertionError("appareil inconnu accepté")
        except ValueError:
            pass
        finally:
            web.BASE = ancienne
        c = sqlite3.connect(base, timeout=0.5)
        c.execute("INSERT INTO requetes VALUES (1, 'a', 'b', 0)")  # lèverait « database is locked »
        c.commit()


def test_liste_format_hosts():
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "hosts"
        f.write_text("# en-tête\n127.0.0.1 localhost\n0.0.0.0 0.0.0.0\n0.0.0.0 ads.exemple.com  # pub\n127.0.0.1 traque.fr\n::1 ip6-localhost\n")
        liste = mouchard.Liste(f)
        assert liste.contient("ads.exemple.com") and liste.contient("x.traque.fr")
        assert liste.domaines == {"ads.exemple.com", "traque.fr"}


def test_autoriser_passe_avant_les_listes():
    with tempfile.TemporaryDirectory() as d:
        anciennes = mouchard.liste, mouchard.autorises, mouchard.publique
        (Path(d) / "pub").write_text("0.0.0.0 cdn.exemple.com\n")
        (Path(d) / "perso").write_text("exemple.org\n")
        (Path(d) / "ok").write_text("cdn.exemple.com\n")
        mouchard.liste, mouchard.autorises, mouchard.publique = (mouchard.Liste(Path(d) / n) for n in ("perso", "ok", "pub"))
        try:
            assert not mouchard.est_bloque("cdn.exemple.com") and mouchard.est_bloque("www.exemple.org")
        finally:
            mouchard.liste, mouchard.autorises, mouchard.publique = anciennes


def test_qui_entreprise_et_pays():
    import gzip
    import json
    import qui
    with tempfile.TemporaryDirectory() as d:
        dis = Path(d) / "dis.json"
        dis.write_text(json.dumps({"categories": {
            "Content": [{"Pubco": {"https://pub.co/": ["pub.co"], "performance": "true"}}],
            "Advertising": [{"Pubco": {"https://pub.co/": ["pub.co"]}}],
            "Social": [{"Amis": {"https://amis.fr/": ["amis.fr"]}}]}}))
        ip = Path(d) / "ip.csv.gz"
        with gzip.open(ip, "wt") as f:
            f.write("0.0.0.0,0.255.255.255,ZZ\n1.0.0.0,1.0.0.255,AU\n2.0.0.0,2.255.255.255,FR\n::,ffff::,US\n")
        anciens = qui.entreprises, qui.plages
        qui.entreprises, qui.plages = qui.Charge(dis, qui.lire_disconnect), qui.Charge(ip, qui.lire_dbip)
        try:
            assert qui.entreprise("ads.pub.co") == ("Pubco", "advertising")  # la pub passe avant le contenu
            assert qui.entreprise("amis.fr") == ("Amis", "social") and qui.entreprise("co") == (None, None)
            assert qui.pays("2.4.5.6") == "FR" and qui.pays("1.0.0.9") == "AU"
            assert qui.pays("0.1.2.3") is None and qui.pays("pas une ip") is None and qui.pays(None) is None
        finally:
            qui.entreprises, qui.plages = anciens



def test_proposition_acceptee_bloque_le_domaine_une_seule_fois():
    import sqlite3
    import web
    with tempfile.TemporaryDirectory() as d:
        base, perso = os.path.join(d, "t.db"), Path(d) / "bloquer.txt"
        sqlite3.connect(base).executescript("CREATE TABLE propositions (id INTEGER PRIMARY KEY, t REAL, domaine TEXT UNIQUE, raison TEXT, etat TEXT DEFAULT 'attente');"
                                            "INSERT INTO propositions (t, domaine, raison) VALUES (1, 'pub.exemple.com', 'pub'), (2, 'mesure.exemple.com', 'stats');")
        sauve = web.BASE, web.LISTE, web.AUTORISER, mouchard.liste, mouchard.autorises, mouchard.publique
        web.BASE, web.LISTE, web.AUTORISER = base, perso, Path(d) / "autoriser.txt"
        mouchard.liste, mouchard.autorises, mouchard.publique = mouchard.Liste(perso), mouchard.Liste(web.AUTORISER), mouchard.Liste(Path(d) / "rien")
        try:
            assert web.decider(1, True) == "pub.exemple.com" and mouchard.est_bloque("x.pub.exemple.com")
            assert web.decider(2, False) == "mesure.exemple.com" and not mouchard.est_bloque("mesure.exemple.com")
            for ident in (1, 2, 99):  # déjà décidée ou inconnue
                try:
                    web.decider(ident, True)
                    raise AssertionError(ident)
                except ValueError:
                    pass
            assert perso.read_text() == "pub.exemple.com\n"
        finally:
            web.BASE, web.LISTE, web.AUTORISER, mouchard.liste, mouchard.autorises, mouchard.publique = sauve


def test_agent_ne_peut_proposer_que_des_pisteurs_reconnus():
    import json
    import sqlite3
    import time
    import resume
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "t.db")
        db = sqlite3.connect(base)
        db.executescript("CREATE TABLE requetes (t REAL, ip TEXT, domaine TEXT, bloque INTEGER);"
                         "CREATE TABLE appareils (ip TEXT PRIMARY KEY, mac TEXT, vu_le REAL, nom TEXT);"
                         "CREATE TABLE domaines (domaine TEXT PRIMARY KEY, ip TEXT);"
                         "CREATE TABLE propositions (id INTEGER PRIMARY KEY, t REAL, domaine TEXT UNIQUE, raison TEXT, etat TEXT DEFAULT 'attente');")
        for dom in ("connectivitycheck.gstatic.com", "unagi-na.amazon.com", "deja.bloque.com"):
            db.execute("INSERT INTO requetes VALUES (?, '10.0.0.2', ?, 0)", (time.time(), dom))
        db.commit()
        (Path(d) / "cand").write_text("unagi-na.amazon.com\nbloque.com\npas-vu.com\n")
        (Path(d) / "perso").write_text("deja.bloque.com\n")
        sauve = resume.BASE, resume.demander, resume.candidats, mouchard.liste, mouchard.autorises, mouchard.publique
        resume.BASE, resume.candidats = base, mouchard.Liste(Path(d) / "cand")
        mouchard.liste, mouchard.autorises, mouchard.publique = mouchard.Liste(Path(d) / "perso"), mouchard.Liste(Path(d) / "x"), mouchard.Liste(Path(d) / "y")
        proposees = ["connectivitycheck.gstatic.com", "unagi-na.amazon.com", "deja.bloque.com", "pas-vu.com"]
        resume.demander = lambda *a: json.dumps({"rapport": "ok", "a_bloquer": [{"domaine": x, "raison": "r"} for x in proposees]})
        try:
            _, nouvelles = resume.rapport()
            assert [p["domaine"] for p in nouvelles] == ["unagi-na.amazon.com"]
            _, nouvelles = resume.rapport()
            assert nouvelles == []  # jamais deux fois
        finally:
            resume.BASE, resume.demander, resume.candidats, mouchard.liste, mouchard.autorises, mouchard.publique = sauve


def test_messager_boutons_et_questions():
    import messager
    import web
    appels = []
    sauve = web.decider, web.demander
    web.decider = lambda ident, accepter: appels.append((ident, accepter)) or "pub.exemple.com"
    web.demander = lambda q: f"réponse à {q}"
    try:
        assert messager.traiter({"callback_query": {"data": "b:7"}}, "1") == "pub.exemple.com blocked."
        assert messager.traiter({"callback_query": {"data": "i:8"}}, "1") == "pub.exemple.com ignored."
        assert appels == [(7, True), (8, False)]
        assert messager.traiter({"callback_query": {"data": "b:pas-un-nombre"}}, "1").startswith("Nothing done")
        assert messager.traiter({"message": {"text": "qui parle la nuit ?"}}, "1") == "réponse à qui parle la nuit ?"
        assert messager.traiter({"message": {}}, "1") is None
    finally:
        web.decider, web.demander = sauve


if __name__ == "__main__":
    for nom, f in list(globals().items()):
        if nom.startswith("test_"):
            f()
    print("ok")
