# Erinix

Host-based intrusion detection for Linux, part of the **Nemirix** suite alongside Vulpnix.

Erinix is built to watch what happens on a machine: it links events into attack chains
(for example: many missing pages, then an injection attempt) and raises alerts
that grow in severity as an attack progresses.

> Status: alpha. Today it detects from recorded or simulated events; reading
> live logs and the web dashboard are the next steps.

## What it can do today

- **Detection engine**: attack chains with progressive alerts, sliding windows and bounded memory.
- **Web attacks** (Caddy access logs): SQL injection, path traversal, command and script injection,
  attack-tool user agents, page scanning followed by an attack, password guessing on a login form.
- **SSH password guessing** (sshd logs), including log-injection tricks.
- **Console**: full-screen interface with the commands below.
- **Rules**: plain TOML files, validated strictly. No code and no regular expressions in rules.

## Install

```bash
git clone git@github.com:JustCromo/Erinix.git
cd Erinix
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
python -m pytest -q
```

Requires Python 3.11 or newer. There are no runtime dependencies.

## Try it

```bash
erinix                         # open the console
erinix doctor                  # what Erinix can use on this machine
erinix rules list              # the loaded rules
erinix replay web              # a simulated attack on a web app, with its alerts
erinix replay webquiet         # normal web traffic: no alerts expected
erinix replay ssh              # SSH password guessing
erinix replay revshell         # compromised web server -> shell -> root
```

Other scenarios: `bruteforce`, `shadow`, `admin`. Add `--fast` to skip the pauses.
Inside the console, type the same commands without `erinix`.

## Rules

Rules live in `rules/*.toml`. `erinix rules validate` checks them. Rule files must be owned by root
or by the user running Erinix and must not be writable by others.

## Security

See [SECURITY.md](SECURITY.md). Design notes: [docs/PLANNING.md](docs/PLANNING.md).

## License

MIT.
