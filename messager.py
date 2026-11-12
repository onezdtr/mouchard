"""Telegram : alertes, rapport du jour, propositions de blocage avec boutons, et questions à l'agent.

Bot propre à mouchard : ~/.config/mouchard/telegram (jeton BotFather). Le premier chat qui lui écrit est
appairé (~/.config/mouchard/telegram_chat), et lui seul est ensuite écouté.
Sans ce bot, les messages partent par le bot du chasseur d'alternance, sans boutons ni questions :
on ne peut pas écouter un bot qu'un autre programme écoute déjà.
"""
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

PROPRE = Path.home() / ".config/mouchard"
SECOURS = Path.home() / ".config/alternance"


def lire(fichier):
    return fichier.read_text().strip() if fichier.exists() else None


def bot():
    """(jeton, chat, propre) : notre bot s'il est configuré, sinon celui du chasseur."""
    if lire(PROPRE / "telegram"):
        return lire(PROPRE / "telegram"), lire(PROPRE / "telegram_chat"), True
    return lire(SECOURS / "telegram"), lire(SECOURS / "telegram_chat"), False


def appel(jeton, methode, delai=15, **params):
    req = urllib.request.Request(f"https://api.telegram.org/bot{jeton}/{methode}", json.dumps(params).encode(),
                                 {"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=delai))["result"]


def envoyer(texte, boutons=None):
    """Ne fait rien si aucun bot n'est configuré ; un message raté ne doit jamais couper le DNS."""
    jeton, chat, propre = bot()
    if not (jeton and chat):
        return
    params = {"chat_id": int(chat), "text": texte[:4000], "disable_web_page_preview": True}
    if boutons and propre:  # les boutons ne servent que si c'est nous qui écoutons les réponses
        params["reply_markup"] = {"inline_keyboard": [boutons]}
    try:
        appel(jeton, "sendMessage", **params)
    except (OSError, ValueError, KeyError) as e:
        print("telegram message not sent:", e, flush=True)


def proposer(p):
    envoyer(f"Block {p['domaine']}?\n{p['raison']}",
            [{"text": "Block", "callback_data": f"b:{p['id']}"}, {"text": "Ignore", "callback_data": f"i:{p['id']}"}])


def traiter(maj, chat):
    """Un message ou un appui sur bouton venant du chat appairé ; renvoie le texte de réponse."""
    import resume
    import web
    if "callback_query" in maj:
        action, _, ident = maj["callback_query"].get("data", "").partition(":")
        try:
            domaine = web.decider(int(ident), action == "b")
        except ValueError as e:
            return f"Nothing done: {e}"
        return f"{domaine} blocked." if action == "b" else f"{domaine} ignored."
    texte = maj.get("message", {}).get("text", "").strip()
    if texte in ("/start", "/help"):
        return "mouchard is listening. Ask me anything about your network, or send /report for the daily report."
    if texte == "/report":
        rapport, propositions = resume.rapport()
        for p in propositions:
            proposer(p)
        return rapport
    return web.demander(texte[:500]) if texte else None


def ecouter():
    """Boucle de lecture du bot propre (long polling) ; ne démarre pas sans lui."""
    jeton, _, propre = bot()
    if not (jeton and propre):
        return
    decalage = 0
    while True:
        try:
            mises_a_jour = appel(jeton, "getUpdates", delai=60, offset=decalage, timeout=50)
        except (OSError, ValueError, KeyError) as e:
            print("telegram polling error:", e, flush=True)
            time.sleep(30)
            continue
        for maj in mises_a_jour:
            decalage = maj["update_id"] + 1
            source = maj.get("callback_query", {}).get("message", maj.get("message", {})).get("chat", {})
            chat = lire(PROPRE / "telegram_chat")
            if not chat and "message" in maj:  # appairage : le premier à écrire devient le propriétaire
                chat = str(source.get("id"))
                (PROPRE / "telegram_chat").write_text(chat)
                (PROPRE / "telegram_chat").chmod(0o600)
            if str(source.get("id")) != chat:
                continue  # quelqu'un d'autre a trouvé le bot : on l'ignore
            try:
                reponse = traiter(maj, chat)
            except (OSError, ValueError, KeyError, urllib.error.URLError) as e:
                reponse = f"Error: {e}"
            try:
                if "callback_query" in maj:
                    appel(jeton, "answerCallbackQuery", callback_query_id=maj["callback_query"]["id"], text=(reponse or "")[:190])
                    message = maj["callback_query"]["message"]
                    appel(jeton, "editMessageText", chat_id=int(chat), message_id=message["message_id"],
                          text=f"{message.get('text', '')}\n→ {reponse}")  # les boutons disparaissent : impossible de répondre deux fois
                elif reponse:
                    envoyer(reponse)
            except (OSError, ValueError, KeyError) as e:
                print("telegram reply not sent:", e, flush=True)
