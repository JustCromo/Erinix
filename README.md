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
sign-in link that works once (if it says the link was already used, run `erinix ui` again). Stop it with `erinix stop`.
A menu on the left leads to four pages:

- **Home**: the answer to "is everything OK?" in one plain sentence, the few incidents that need you,
  and a small live strip.
- **Incidents**: everything suspicious, grouped by who is behind it (one attacker, one incident, with every
  attack inside). Filter by type of attack. Open one to see what to do first, then what happened in order.
- **Live**: every event as it happens (about twice a second), attack events highlighted; the incidents that are
  active right now sit above the stream. Each attack shows its steps as done, happening now or still to come.
- **System**: what Erinix watches (and what it cannot see), a chart of the last 24 hours, and the colours.

Look: one palette, "Stone and indigo" (warm paper, indigo ink), in a light and a dark variant. The dashboard follows your system by default;
force one in **System > Appearance** or with `erinix theme light|dark|auto`. The console always uses the dark variant.
Fonts and icons ship with Erinix (Nunito, SIL Open Font License): the page never loads anything from the internet.

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


## Watching a real machine

```
erinix                            # starts watching AND opens the live cockpit, in one terminal
erinix --elevate                  # same, and asks for your sudo password to see every program
erinix ui                         # the web dashboard (opens in the browser)
erinix watch                      # watch without a screen (for a service or a second terminal)
erinix --console                  # the older scrolling console
```

In the cockpit: `Tab` moves between panels, `Enter` opens a row, `/` searches, `:` runs any command (`alerts`, `status`,
`help`...), `x` closes an incident, `r` shows routine activity, `p` pauses the feed, `w` gives the dashboard link,
`R` raises the view to every program (sudo password), `?` shows all keys. Only one Erinix watches at a time; a second
one opens as a viewer of the same data.

## Port scans

A scan (for example `nmap`) knocks on many ports and almost never finishes a connection, so it leaves nothing in
`/proc`. With root (`erinix --elevate`, or `R` in the cockpit) Erinix also listens to incoming packets and raises an
incident when one address touches many **different** ports: 10 in 10 seconds (fast), 25 in 5 minutes (slow), or 100
or more (wide, high severity). It sees the packets before the firewall, so closed ports count too, even if only
one port is open. Counted as probes: SYN-only packets (the usual scan and connect scan) and the null, FIN and Xmas
scans. Not counted: ACK scans, UDP scans, and traffic from this machine itself or from loopback. Without root the
detector is off, and `status` says so. The source address of a scan can be forged: an incident is a signal, and
blocking (`b`) always asks first.

## Health check (assessment)

```
erinix assess            # 19 read-only checks: SSH, accounts, permissions, open ports, firewall, kernel, suspicious files, startup changes
erinix assess --all      # also lists what passed
```

Each finding says what was found and how to fix it, and the score goes from 0 to 100. Erinix only LOOKS: it never changes a file
or a setting. Checks that need root (for example empty passwords in `/etc/shadow`) say "could not check" instead of guessing.
The agent repeats the check every half hour; the result shows in the cockpit (Health panel, `a` to check now) and on the
dashboard (Health page).

## Response (mitigation)

Erinix can act, but only with a short closed list, always showing what it will do first, and never from the web page:

```
block 203.0.113.50 --minutes 60   # drop traffic from one address for a while (nftables, table "erinix"); it expires by itself
unblock 203.0.113.50              # lift it
kill 4242                         # stop a program (checked against its start time, so a reused number is never hit)
fix ssh.keys                      # restore safe permissions on what the Health check flagged
actions                           # everything Erinix has done, in order
undo 3                            # reverse a block or a fix
```

In the cockpit: select a row and press `b` (block its address), `k` (stop the program) or `f` (fix a Health finding); a box shows
exactly what will happen and nothing is done until you press `y`. Things that need root run through the root helper (`R`).
Safety rules: nft is called with a fixed argument list (never a command built from text), addresses of this machine, your
router and special ranges cannot be blocked, blocks always expire (default 1 hour, at most 24), a fix finds its own targets and
only ever touches a few known files (`/etc/passwd`, `/etc/shadow`, sudoers, `~/.ssh`), never follows links, and the root helper
checks every request again. The journal lives in the private store.

Why not `sudo erinix`? `sudo` uses its own short PATH, so a command installed in your home or in a venv is "not found".
`erinix --elevate` (or `R`) does it safely instead: only a tiny helper runs as root, and all it does is READ `/proc` and
send a plain list to your normal user's Erinix. The helper runs `python -m erinix helper` from the same install, so for
daily use install Erinix where only root can write; Erinix warns you when it is a development install.

Without a settings file Erinix looks at what it can read: running programs and network connections (from `/proc`),
SSH logins (journal or `/var/log/auth.log`), common web server logs, and Docker containers running Caddy, nginx or Apache.
What it cannot read is shown in the dashboard with the reason. Settings live in `~/.config/erinix/config.toml`
(or `/etc/erinix/config.toml`); the file must not be writable by others:

```toml
[agent]
interval = 0.5

[[source]]
name = "Website"
kind = "docker"          # file | journal | docker
container = "caddy"
format = "caddy"         # caddy | combined (nginx, Apache) | ssh
```

Honest limits: programs are found by looking at `/proc` every half second, so a program that lives less than that can be
missed (kernel-level sensing with root is planned); without root only your own programs are tied to their connections;
reading the journal needs the `systemd-journal` group; Docker needs the `docker` group.
