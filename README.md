# mouchard

Serveur DNS maison qui montre, appareil par appareil, à qui parlent les objets du réseau, et un agent IA qui l'explique chaque soir.

- `mouchard.py` : relaie les requêtes DNS, les note dans `mouchard.db`, bloque les domaines de `bloquer.txt` (relu à chaud), alerte sur Telegram à chaque nouvel appareil.
- `web.py` + `page.html` : tableau de bord (appareils, domaines, direct, bouton Bloquer) et questions à l'agent ; adresse avec jeton affichée au lancement (port 8053).
- `resume.py` : envoie les dernières 24 h à Gemini et poste le résumé sur Telegram (`--ecran` pour l'afficher seulement).

```
python3 mouchard.py                                    # 127.0.0.1:5300 pour essayer
MOUCHARD_ECOUTE=0.0.0.0 MOUCHARD_PORT=53 python3 mouchard.py   # sur le serveur
dig @127.0.0.1 -p 5300 example.com
GEMINI_API_KEY=... python3 resume.py --ecran
python3 test_mouchard.py
```

La clé Gemini se lit dans `GEMINI_API_KEY` ou dans `~/.config/mouchard/cle` (chmod 600). Le jeton du tableau de bord est créé dans `~/.config/mouchard/jeton`.

Python 3 seul, sans dépendance.
