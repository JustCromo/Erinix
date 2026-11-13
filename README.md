# Erinix

Host-based intrusion detection for Linux, part of the **Nemirix** suite alongside Vulpnix.

Erinix is built to watch what happens on a machine: it links events into attack chains
(for example: many missing pages, then an injection attempt) and raises alerts that grow in
severity as an attack progresses. Alerts are written for people first (what happened, why it
matters, what to do) with the technical details one click away.

> Status: alpha. The detection engine, the console and the web dashboard work today with
> recorded or simulated events (`erinix demo`). Reading live logs is the next step.

## Quick start

```bash
git clone git@github.com:JustCromo/Erinix.git
cd Erinix
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
python -m pytest -q
erinix install-app
```

`erinix install-app` adds an `erinix` command that works without activating the venv, an
"Erinix" entry in your application menu and its icon. Everything is written under your home folder;
no root needed. Remove it with `erinix uninstall-app`.

Requires Python 3.11 or newer. There are no runtime dependencies.

## Try it

```bash
erinix demo        # load simulated attacks into Erinix
erinix             # open the console
erinix status      # what needs your attention, in plain language
erinix alerts      # the list; then: erinix alert 1   (add --tech for the technical side)
erinix ui          # open the web dashboard in your browser
```

To watch it work in real time, open the dashboard on the **Live** page and, in a second terminal, play a staged attack:

```bash
erinix demo --live    # normal traffic with an attack in the middle (Ctrl-C stops it)
erinix live           # the same stream of events, in the terminal (--suspicious shows only attack events)
```

Inside the console, type the same commands without `erinix`.

## The dashboard

`erinix ui` starts a small local web server (127.0.0.1 only) and opens your browser with a private
sign-in link that works once. The dashboard shows the same facts as the console: a plain-language
summary, the alerts with "See more" for technical details, and what Erinix is watching (and what it
cannot see). The **Live** page updates by itself, about twice a second: the events as they happen on the left, and on
the right every attack in progress with its steps shown as done, happening now or still to come. Stop it with `erinix stop`. The look is a forest night with the hedgehog's orange and glass panels; for a warmer, brown-based palette change `data-palette="bosco"` to `"sottobosco"` in `src/erinix/web/static/index.html`. If the link says it was already used, run `erinix ui` again for a new one.

If the box-drawing symbols look misaligned in your terminal font, run with plain characters: `ERINIX_ASCII=1 erinix`.

## For scripts and desktop widgets

Every information command has `--json`:

```bash
erinix status --json
erinix alerts --json
erinix sources --json
```

## Other commands

`erinix doctor` (what this machine allows), `erinix rules list`, `erinix rules validate`,
`erinix replay <scenario>` (web, webquiet, ssh, revshell, bruteforce, shadow, admin).

## Rules

Rules live in `rules/*.toml`. They describe what to look for and, in plain English, what an alert
means (`title`, `why`, `next`). `erinix rules validate` checks them. Rule files must be owned by root
or by the user running Erinix and must not be writable by others.

## Security

See [SECURITY.md](SECURITY.md). Design notes: [docs/PLANNING.md](docs/PLANNING.md).

## License

MIT.
