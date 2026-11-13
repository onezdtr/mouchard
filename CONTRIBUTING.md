# Contributing to khada3

Thanks for your interest. Bug reports, ideas and pull requests are welcome.

## Run it and test it

```sh
python3 khada3.py          # DNS on 127.0.0.1:5300, dashboard URL printed at start
python3 test_khada3.py     # must print "ok"
```

Nothing to install: Python 3 and its standard library only.

## The rules

- **No dependencies.** khada3 runs on any machine with Python 3. A pull request that adds a package will not be merged; a few lines of standard library almost always do the job.
- **Never cut the internet.** khada3 sits between every device and the web. A failure (logging, lists, Telegram, the agent) must never stop a DNS answer.
- **The data stays home.** No telemetry, no external service except the ones listed in the README. Anything that sends data out must be opt-in and documented.
- **The agent proposes, you decide.** It never blocks anything on its own.
- **Add a test** for any new logic in `test_khada3.py`.
- Keep it small: the simplest change that works.

The code and its comments are in French; the interface, the README and the agent prompts are in English. Contributions in either language are welcome.

## Security

Please do not open a public issue for a security problem. Use **Security → Report a vulnerability** on GitHub instead.
