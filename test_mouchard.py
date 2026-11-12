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


if __name__ == "__main__":
    for nom, f in list(globals().items()):
        if nom.startswith("test_"):
            f()
    print("ok")
