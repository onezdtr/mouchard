# mouchard

**A home DNS server that shows who every device on your network is talking to, and an AI agent that explains it in plain words.**

*Mouchard* is French for "snitch": your smart TV, phone and speakers report to dozens of servers every hour. This one reports on them.

![mouchard dashboard: radar of devices, live DNS feed, and the AI agent answering "which device talks to trackers the most?"](docs/demo.gif)

<sub>Demo recorded with simulated devices. The interface is in French.</sub>

## What it does

- **Logs every DNS lookup, per device.** Point your network at mouchard and every domain each device looks up is recorded.
- **Radar dashboard.** Each device is a blip: the busier it is, the closer it sits to the centre, and it pings on every new request. Click one to see only its traffic.
- **Blocks trackers.** Domains in `bloquer.txt` (and all their subdomains) get "does not exist" back. Block one in a click from the dashboard; the list reloads without a restart.
- **Ask the agent.** Type a question ("which device talks to trackers the most?", "what was my TV doing at 3 am?") and Gemini answers from the last 24 hours of data, and nothing else.
- **Daily report.** `resume.py` sends a summary per device to Telegram, with a list of domains worth blocking. It only suggests: nothing is blocked without you.
- **New device alert.** A Telegram message the first time an unknown device shows up on the network.

## How it works

```
 devices ──DNS──▶ mouchard.py ──▶ upstream DNS (1.1.1.1 or your router)
                      │
                      ├─ blocked? ─▶ NXDOMAIN
                      ▼
                  mouchard.db (SQLite) ◀── web.py + page.html (dashboard, port 8053)
                                       ◀── resume.py ──▶ Gemini ──▶ Telegram
```

Plain Python 3 standard library: no dependencies, no framework. The DNS part only parses the question name and forwards the raw packet, so answers are exactly what the upstream server sent.

## Quick start

Try it on your own machine, without touching your network:

```sh
python3 mouchard.py                      # DNS on 127.0.0.1:5300, dashboard URL printed at start
dig @127.0.0.1 -p 5300 example.com       # the lookup appears on the dashboard
python3 test_mouchard.py                 # tests
```

To see your own computer's traffic on Linux with systemd-resolved (replace `wlan0` with your interface):

```sh
sudo resolvectl dns wlan0 127.0.0.1:5300   # route this machine's DNS through mouchard
sudo resolvectl dns wlan0 <your router>    # undo
```

## On a home server

Run it on an always-on machine (an old laptop works fine) and listen on the network:

```sh
sudo MOUCHARD_ECOUTE=0.0.0.0 MOUCHARD_PORT=53 python3 mouchard.py
```

Then set that machine's IP as the DNS server in your router's DHCP settings, or device by device. Every device then shows up on the radar.

| Variable | Default | Meaning |
|---|---|---|
| `MOUCHARD_ECOUTE` | `127.0.0.1` | Address to listen on (`0.0.0.0` for the whole network) |
| `MOUCHARD_PORT` | `5300` | DNS port (`53` on a server) |
| `MOUCHARD_PORT_WEB` | `8053` | Dashboard port |
| `MOUCHARD_AMONT` | `1.1.1.1` | Upstream DNS server |
| `MOUCHARD_MODELE` | `gemini-3.1-flash-lite` | Gemini model used by the agent |

**AI agent:** put a [Gemini API key](https://aistudio.google.com/apikey) in `~/.config/mouchard/cle` (`chmod 600`) or in `GEMINI_API_KEY`.
**Telegram:** the bot token and chat id are read from `~/.config/alternance/telegram` and `~/.config/alternance/telegram_chat`. Without them, alerts are simply skipped.

## Privacy and security

- The DNS log is a browsing history. The dashboard refuses every request without the token stored in `~/.config/mouchard/jeton` (created on first run).
- Domain names come from the network and are never inserted as HTML in the page.
- The data stays on the machine, except the last 24 hours of domains sent to Gemini when the agent answers or writes the report, and the messages sent to your own Telegram bot.
- **Only run mouchard on a network you own.** Logging other people's traffic on a school, office or public network without permission is illegal in most countries.

## Files

| File | Role |
|---|---|
| `mouchard.py` | DNS server: forward, block, log, new-device alert |
| `web.py`, `page.html` | Dashboard and the agent's endpoint |
| `resume.py` | Daily report (`--ecran` prints it instead of sending it) |
| `bloquer.txt` | Blocklist, one domain per line |
| `test_mouchard.py` | Tests |
