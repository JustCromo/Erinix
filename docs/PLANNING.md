# Erinix: planning and design decisions

Living document. It explains **what** we decided and **why**, especially for security.
The `README.md` explains how to install and use the tool.

Working rule: every new security or architecture decision is added here, in the right
section and in the final log.

Last updated: October 24, 2026.

---

## 1. Goal and scope

Erinix is a **host-based** IDS for Linux, with optional active response. It does not just
log single events: it reasons about **attack chains**, that is, sequences of linked steps
(compromised service, shell, outbound connection, privilege escalation), like an attacker
following the strategy learned in pen tests.

Priorities, in this order:

1. **Detection**: the part that must work better than anything else.
2. **Response**: a few actions (terminate the process tree, block an IP), done with the utmost care.
3. **Incident assessment, web console, Vulpnix integration**: built on top of the first two.

Out of scope for now: packet-level network traffic analysis (NIDS), statistical anomaly detection, multi-host.

## 2. The Nemirix suite

- **Nemirix**: the suite (the name comes from *Nemi*, the sacred grove where the *rex Nemorensis* kept watch without ever lowering his guard, and from the Gaulish suffix *-rix*, "king").
- **Vulpnix**: risk assessment, the *before* of an attack (posture of the machine).
- **Erinix**: detection, response and incident assessment, the *during* and the *after*.

Principles:

- **Every tool works on its own**, from its own terminal. The web console is the meeting point and shows the installed modules.
- **Compartmentalization**: each tool has its own system user and its own database, readable only by that user. Compromising one does not give access to the other's data.
- **Suite recognition**: a registry folder owned by root, where each tool drops its own card (name, version, local channel, public key).
- **Against anyone pretending to be a tool**: communication over local Unix sockets (the kernel tells who is on the other side, which cannot be forged) and **signed** reports; if the signature does not match, the report is rejected.
- **Common data contract**: Vulpnix's versioned JSON schema as the base, same severity scale, same conventions.

## 3. Technical stack

| Choice | Reason |
|---|---|
| **Python** for agent and web | Mastered by the author: in a project that is defended in interviews this matters more than theoretical speed. Python is memory-safe. The heavy lifting is done by the kernel (eBPF/auditd), not by Python. |
| **FastAPI + SQLite** for console and DB | Local architecture for the first version. One file, zero configuration. |
| **Rules in TOML** | See section 6. Parser included in Python (`tomllib`), **zero external dependencies**. |
| **Minimal, version-pinned dependencies** | Every library inside a root process is attack surface. |

Agent and web are **separate processes**: the agent has the privileges, the web app is **never** root.

## 4. Sensors

**eBPF (CO-RE) is the main sensor. auditd is the fallback. The minimal mode is the last safety net.**

- **eBPF**: programs inside the kernel attached to the points of interest, already-structured events, filtering upstream.
  **CO-RE** (compile once, run everywhere) was chosen instead of bcc: no compiler on the protected machine,
  instant startup, and it is the recommended practice today. Requires a kernel with BTF; builds for x86_64 and ARM.
- **auditd**: fallback on old kernels or kernels without BTF.
- **Minimal**: `/proc` and authentication logs, at intervals. It sees less and later, but it is not blind.

Operating rules:

- At startup Erinix checks privileges, eBPF/BTF support and auditd state, picks the mode and **always declares which one it is and what it cannot see** (sensor status event, also shown in the console).
- It can be forced by hand (`--sensor auditd`). If the forced mode is not available, Erinix **refuses to start** instead of silently degrading.
- Hot mode switch: the new sensor starts **before** the old one stops, duplicates are discarded, so there is never a moment of blindness.
- **Anti-downgrade**: an attacker might want to force a switch to a sensor that sees less. Only root can request the switch, through the local control channel, and every switch raises an alert.
- The correlation engine **does not know where events come from**: it always receives the same format.
- The mode choice lives in `sensors/selector.py` (detection of privileges, kernel, BTF, auditd) and can be checked with `erinix doctor`. Without root the plan is "observer", and `doctor` also says what would be possible with privileges.

## 5. Privileges

- **Main mode: root**, because eBPF, auditd, IP blocking and process termination require it.
- **Rootless mode**: "observer that warns". It reads `/proc` and the accessible logs, opens decoys on high ports, sends alerts. It cannot use eBPF/auditd or act. It clearly declares its limits at startup.
- As a systemd service: only the necessary capabilities, read-only filesystem where possible.

## 6. Rules (`rules/*.toml`)

**Why TOML and not YAML**: `tomllib` is in the standard library, so there is no external dependency and less attack
surface. YAML parsers have historically been a source of vulnerabilities, and `PyYAML` would be one more package inside a privileged process.
The price is a slightly more verbose syntax for chains.

Two kinds of rule:

- **`[[indicator]]`**: a single event that is already suspicious.
- **`[[chain]]`** with `[[chain.step]]`: a sequence of linked steps (at least 2).

Concepts:

- **`link`**: what makes the steps the same story. `process_tree` (the process of the first step or one of its descendants), `login_session` (same login session), `remote_ip` (same remote address).
- **`window_seconds`**: how long the steps have to happen in.
- **`count`**: the step needs N events (e.g. 5 failed logins).
- **`response`**: `report_only` (default), `interactive`, `auto`. It can be overridden per step, because the response is attached to the step and not to the end of the chain (timeliness).
- **`mitre`**: related MITRE ATT&CK techniques.
- **Web requests** (`web.request`) can be matched on `contains` (a substring of the request after normalization: decoding, case-folding and similar clean-up), `user_agent_contains`, `method`, `status`, `path` and `path_prefix`. Rule values are normalized the same way, substrings need at least 3 characters, and there are still no regular expressions.

Rule security (checked at startup by `erinix rules validate`):

1. **Declarative only**: no code, no `eval`.
2. **No regular expressions**: only exact values, prefixes and lists (this removes ReDoS).
3. **Closed schema**: an unknown field invalidates the rule. The fields allowed in `match` depend on the event type.
4. **Malformed rule = rule discarded and reported**, never executed; the others stay active.
5. **Trusted files**: owned by root (or by the user running Erinix), not writable by group/others, not symlinks, folder included. If the folder itself is untrustworthy, nothing is loaded.
6. **Hard limits**: file size, number of rules, steps, items per list, string length.
7. **Always absolute paths**, control characters forbidden.
8. **A rule with response `auto` must have `justification`**: the author has to write why the certainty is absolute. This makes the automatic behavior reviewable.
9. **Sanitized output**: everything that comes from external files is cleaned before being printed.

## 7. Event model

One common format for all sensors, with an "envelope" (id, monotonic clock for ordering and wall clock for display, source, process, login session) and a content part per family: process, network, privileges, file, authentication, **sensor status**.

Security choices:

1. **Process identity = PID + start time.** PIDs get recycled: an old PID that is reassigned must not inherit another process's chain.
2. **Never trust the process name** (`comm`): an attacker can rename it to `sshd` in an instant. The executable path seen by the kernel is what counts. A mismatch is a weak signal, to be put in context (it is normal for scripts and interpreters).
3. **`loginuid`**: tells a shell started from a login (admin) from one started by a service (likely exploit).
4. **Everything that comes from processes is hostile input**: limited lengths, invalid bytes handled without loss or crash, limited number of arguments.
5. **Data stored raw, escaping only on output** (adopted proposal, to be reconfirmed): the evidence stays intact and the dashboard cannot become an attack vector.
6. **Reserved lane**: critical events (exec, uid changes, network, sensor status) travel on a channel with its own space.
7. **Process tree with bounded memory**: exited processes are sacrificed first; if a live process is lost it is **counted and declared**.
8. **The sensor must report when it is blind**: startup, mode, lost events, stopped sensor.
9. **Canonical paths from sensors**: file paths must arrive already resolved (no `/etc/../etc/shadow`, no symlinks) and the executable must be the one seen by the kernel. The engine compares exact strings and trusts the sensor on this point.
10. **Log lines are hostile text** (web and sshd logs): parsers use no regular expressions and parse sshd lines from the END (a user name can carry a fake "from <ip>" tail meant to frame someone else); a line counts as sshd only if the syslog program tag sits right after the host name; the web client address comes from Caddy's `client_ip`/`remote_ip` and never from forwarded headers; sizes are bounded, and malformed lines are rejected, never guessed.

## 8. Correlation and alerts

- **A single alert per chain in progress**, which is updated (same `alert_id`, growing `revision`). No multiple notifications for the same attack.
- **Progressive severity**: equal to the highest among the completed steps. It reports already from the first step, because timeliness matters.
- **The response is attached to the step**: for example "service spawns a shell" followed by "outbound connection" is already a confirmed reverse shell, and action is taken before the attacker looks for escalation. The alert reports the response level of the step just reached.

How the engine reasons (`engine/correlator.py`):

- **One instance per "story"**, identified by the rule's link: the root of the process tree (`process_tree`), the login session (`login_session`) or the remote address (`remote_ip`).
- **Steps are completed in order.** A single event completes at most one step.
- **Sliding window for `count`** (like fail2ban): for a step with `count = 5`, any 5 events within the last `window_seconds` count. Chosen for simplicity and predictability; slow attacks are covered by a second rule with a longer window and a higher threshold, without complicating the engine.
- **After the first step** the whole chain must finish within `window_seconds` of its start; then the instance expires and a new story can begin.
- **Process tree updated by the engine**: a process with the same PID but a different start time is another process and does not inherit the chain.
- **Indicators**: one alert per (rule, source) pair, where the source is the process or the remote address; the same rule alerts again for the same source after 5 minutes; duplicates are **counted** (`suppressed_duplicates`), not silently ignored.
- **Comparisons without regex**: exact values, prefixes, lists. An unknown field never matches (it fails closed). An unknown executable does not count as "unexpected" (the sensor may simply not see it).

Engine memory and overload:

- **Instance limit per rule.** At the limit, **only** candidates that have not completed any step are sacrificed (oldest first); chains that have already advanced are never touched. If there is nothing to sacrifice, the new candidate is refused.
- **Every sacrifice or refusal is counted** and raises a critical `engine-overload` alert (at most one per minute): a flood is an attack signal, not a technical detail.
- Spilling excess events to disk is the job of the lane-based bus (section 9), not of the engine.

## 9. Overload resistance

Overload is itself an attack signal: noise is often there to hide the real attack. The approach is built by analogy with DDoS:

| Against a DDoS | In Erinix |
|---|---|
| Per-source limit | Event quota per process tree, user or remote IP |
| Filter close to the origin | eBPF filters inside the kernel, before Python |
| Temporary block (blacklist with expiry) | Termination of the tree or IP block with expiry |
| Tell legitimate from bot | Untouchable list and known services |
| Reserved lanes (QoS) | Separate channel for critical events |
| Absorb the peak | Large buffers and spill to disk |
| Monitor and alert | Reaching the limit is a critical alarm |

Principles:

- **The guard is never lowered**: during a flood sensitivity goes up, not down.
- **No silent drops**: excess is deferred (to disk), not thrown away; if something is lost, it is **counted and declared**.
- **The response hits the point closest to the origin** (the child process, the remote IP), never a service in the untouchable list: otherwise the attacker would use Erinix to lock the administrator out.
- Honest limit: with eBPF, if the kernel-to-user buffer fills up, it is the kernel that loses events. The risk is reduced (large buffer, filters in the kernel) and losses are counted.

## 10. Active response

Levels per rule: **auto** (a few chains with absolute certainty, with justification), **interactive** (notification and a dedicated screen with the full chain), **report only**.

Protections (they apply to **all** actions, `auto` included):

1. **Observe only by default**: response is enabled by explicit choice, never at first start. An `auto` rule is inert until response is enabled.
2. **Untouchable list**: PID 1, Erinix itself, the administrator's session and its parents, their IP, localhost, critical services.
3. **Expiring blocks**: if Erinix crashes nothing permanent is left behind (it "fails open").
4. **Dry-run mode** ("I would have blocked X").
5. **Action limit** over time: too many actions are more likely a bug than an attack.
6. **Master switch** to turn off all automatic behavior.
7. **If the user does not answer, nothing happens**: no action "on timeout".
8. **Authenticated confirmations**: only from the authenticated console, otherwise an attacker would use Erinix against the user.
9. **No command built from external data**: IPs are validated and passed as arguments, never in shell strings.
10. **A single passage point** (`guard.py`) between rules and actions: every future action inherits the protections.

## 11. Deception (honeyports)

Decoys, not "false positives": a legitimate user has no reason to touch a service that does not exist, so whoever does is almost certainly an attacker.

- **Hybrid**: eBPF detects the scan; a small Erinix process answers on the decoy ports with fake banners. Simulating a whole service in eBPF would be a nightmare.
- **Decoys are shown only to the scanning IP**, by redirecting its connections; normal users see nothing.
- **No banning on the scan alone**: in a SYN scan the source IP can be forged and innocent IPs would get banned. Banning happens **only after a completed connection** and an interaction with the decoy.
- **The decoy never becomes an entry point**: banner, a few bytes read, no execution, unprivileged user, isolated process.
- **Vulpnix recognizes the decoys** (through the suite registry) and excludes them from the real risk.
- To check before competitions: that decoys are allowed by the rules.

## 12. Incident assessment and Vulpnix integration

After the response Erinix assesses what happened: **reconstruction** (timeline, entry point, how far the attacker got), **outcome of the response**, **persistence check** (users, SSH keys, cron jobs, services left behind by the attacker: stopping the shell is not enough) and **mitigations** linked to the steps of the chain.

The loop with Vulpnix: Vulpnix says where to look, Erinix sees and stops, the mitigations from the incident become what Vulpnix checks at the next scan. The Vulpnix report read by Erinix is **input to validate and whose signature must be verified**, not absolute truth.

## 13. Interface: console and commands

Principle: the agent (a privileged service) is neither started nor controlled from the web app. Console and web are two **clients** of the same local API: closing either one does not switch protection off, and a compromised client does not have the agent's powers.

- **`erinix` opens a full-screen console** (alternate screen, like Vulpnix): information box and mascot at the top, `erinix ▸` prompt right below, status bar at the bottom. The same commands work from the command line (`erinix doctor`), for systemd, scripts and tests. A single command registry feeds both. `--plain` (or `TERM=dumb`) opens the classic line-based console.
- **Closed table of commands**: every command is an entry with function, help and usage. No shell execution, no commands built from external text.
- **Zero dependencies**: standard library only (`termios`, `select`). The terminal building blocks (keys, mouse, selection) start from Vulpnix's experience, with a few fixes: incremental UTF-8 decoding (accented letters are not split), highlighting that keeps the colors, clipboard copy with a size limit.
- **Sanitized output**: every text coming from files or processes goes through `safe()`, and the console lets only text and color sequences through to the terminal: no OSC sequence (clipboard, title), no cursor movement or screen clearing can be injected by a command or a hostile process. Widths are computed on the plain text.
- **Protected paste** (bracketed paste): pasted text goes into the line and never executes anything; line breaks become spaces and the length is limited.
- **Resizing**: tables and panels are blocks that are redrawn at the current width (at most 120 columns, for readability), also when the terminal grows again; text lines stay whole and are only cut at display time.
- **Mouse**: wheel and PgUp/PgDn to scroll; dragging selects and copies to the clipboard. The terminal is always restored (screen, mouse, cursor), even on errors or signals.
- **History** in `~/.local/state/erinix/history` with 0600 permissions: it is not read unless it belongs to the user and is not accessible to others, and it is never written through a symlink. Commands marked `sensitive` do not end up in the history. As root it always uses root's own home, never `$HOME` (which `sudo` may keep pointing at the caller's): root must never write into a directory that an unprivileged user controls.
- **Colors**: information and highlights in hedgehog tones (light brown for information, dark brown for borders, cold orange for titles and commands); everything else in the terminal's default color; red, green and yellow reserved for alerts (severity: `low` green, `medium` yellow, `high` red, `critical` white on red). Truecolor, 256 and 16 color support, or none: `NO_COLOR` is respected, it can be forced with `ERINIX_COLOR=always|never` and turned off for a single command with `--no-color`. ASCII fallback if the terminal is not UTF-8.
- **Local web** (built): `erinix ui` opens the page; listening only on `127.0.0.1`; access through a one-time link issued by the service after checking, via the kernel, who is asking (root or group `erinix`); `Host` header check against DNS rebinding; CSRF protection; blocking approvals only from authenticated sessions.

Current commands: `help`, `version`, `doctor` (machine capabilities and planned sensor), `rules validate`, `rules list`, `replay` (simulated attacks: `revshell`, `bruteforce`, `shadow`, `admin`).

Planned commands: `start`, `stop`, `status`, `ui`, `watch`, `alerts`, `incident`, `response` (status, dry-run, enable, panic), `block` (list, release), `sensor` (status, switch).

## 14. Web console and delivery

- A single **family console**, which shows the installed modules: Vulpnix only, Erinix only, or both (integrated view).
- **Separate DBs** per tool. The console does not touch the DBs: it queries each tool through its local channel, read-only and with the bare minimum.
- Report export in HTML, Markdown and JSON.
- The web app is also **the target of the VSPT** (vulnerability scanning and pen test) required by the assignment: secure by design (argon2, parameterized queries, CSRF, security headers, login rate limit, escaping of all input from the tools), OWASP Top 10 as the reference, then scans, manual tests, report and a second verification test. The lab requires HTTPS and authentication on the reachable interface.

## 15. Residual risks (to declare in the report)

- The **console** sees both tools: it is the only place where they meet. It is reduced (read-only, its own user, no file access), not eliminated.
- An attacker who gets **root** can stop Erinix: the goal is to **notice it** (stopped sensor as an alarm), not to prevent it.
- With eBPF the kernel can lose events if the buffer fills up: they are counted and declared.
- Every rule can produce false positives; `auto` rules are few, justified and reviewable.

## 16. Work plan and dates

- **November 6, 2026**: red team vs blue team challenge (Raspberry Pi). "Competition-ready" Erinix: sensor, a few solid chains, decoys, response with expiry and untouchable list, terminal alerts, no web console. Erinix is built for **any Linux**, not tailored to the Raspberry Pi.
- **November 19, 2026**: final delivery (risk assessment tool and web application, with VSPT). Nemirix console, Vulpnix integration, incident assessment, report.

Development order: event model and process tree (done), rules (done), correlation engine (done), basic console and commands (done), web and sshd log parsers with their rules (done), alert store, dashboard and console views fed by demo data (done), live log sources and the agent, guard and response, lane-based bus, eBPF sensor, auditd fallback, decoys.

## 17. Decision log

| Date | Decision | Why |
|---|---|---|
| 2026-10-24 | Python + FastAPI + SQLite | Language I master, tight schedule |
| 2026-10-24 | eBPF main, auditd fallback, minimal | Maximum visibility, nobody is left without protection |
| 2026-10-24 | eBPF with CO-RE (not bcc) | No compiler on the protected machine, modern practice |
| 2026-10-24 | Root as the main mode, rootless as observer | Privileges are needed for sensors and response |
| 2026-10-24 | Hybrid response (auto only with absolute certainty, interactive elsewhere) | Balance between timeliness and mistakes |
| 2026-10-24 | No silent drops under flood; reserved lane | "Never lower the guard" |
| 2026-10-24 | Separate DBs and users per tool; suite registry and signing | Compartmentalization |
| 2026-10-24 | Single console that adapts to the installed tools | One target to secure |
| 2026-10-24 | Honeyports with ban only after a completed connection | IP spoofing in a SYN scan would get innocents banned |
| 2026-10-24 | Rules in **TOML**, zero dependencies, no regex, `auto` with justification | Less attack surface, no ReDoS, reviewable automation |
| 2026-10-24 | The rules file/folder must be trusted (owner, permissions, no symlinks) | Whoever writes the rules controls the tool |
| 2026-10-24 | `count` with a sliding window; slow attacks covered by long-window rules | Simple, predictable, already used by fail2ban |
| 2026-10-24 | Engine: bounded instances per rule, only non-advanced candidates are sacrificed, with a critical alert | A flood must not be able to erase an attack in progress, nor go unnoticed |
| 2026-10-24 | Interactive console and command line from the same registry; separate agent, CLI and web as clients | Closing the interface must not switch protection off; a compromised client does not have the agent's powers |
| 2026-10-24 | Hedgehog-tone palette for information, traffic light for alerts; `NO_COLOR` respected | Readability and a visual identity consistent with the suite |
| 2026-10-24 | Full-screen console with hedgehog mascot, sectioned boxes, mouse and copy; classic console as fallback | Same experience as Vulpnix, with no dependencies |
| 2026-10-24 | Command output is made of redrawable blocks, not pre-laid-out lines | When the terminal grows again, tables must grow back instead of staying at the width they were printed at |
| 2026-10-24 | Interface, messages, comments, docstrings and documentation in English, like Vulpnix | A consistent suite that can be presented to companies |
| 2026-10-24 | History file as root lives in root's home, never in `$HOME`; the console never ends silently (signals and closed stdin are declared) | A symlink in a user-controlled directory would turn a root write into privilege escalation; a silent exit is impossible to diagnose |
| 2026-11-12 | Web attacks are detected from the Caddy access log, with normalized requests and rules without regex; sshd from its log, parsed from the end | The Raspberry runs web apps behind Caddy: most attacks there never show up as processes |
| 2026-11-12 | Erinix must run on the user's own PC too: sources are configurable, nothing is hard-wired to one app | Daily use, not only the Raspberry |
| 2026-11-13 | Console, dashboard and scripts all read ONE shared private SQLite store, instead of calling an agent API (for now) | Simpler and safer for a single user; an API or socket with peer checks comes with multi-user setups |
| 2026-11-13 | Alerts carry plain-language text written in the rule (`title`, `why`, `next`); technical details sit behind "See more" / `--tech` | Easy to read first, nothing technical lost |
| 2026-11-13 | Dashboard: loopback only, login by a one-time link from `erinix ui`, host check, CSRF header, strict CSP, plain JavaScript that never builds HTML | A local web page must not become the easiest way in |
| 2026-11-13 | `erinix install-app` adds a launcher, a menu entry and the icon under the user's home; no venv activation, no root | Use Erinix like a normal app |

### Still to decide or reconfirm

- Severity scale shared with Vulpnix (here: `low`, `medium`, `high`, `critical`; it must be aligned with Vulpnix's schema).
- Hostile data: stored raw in the DB with escaping on output (adopted proposal).
- eBPF loading layer from Python (an existing library or a small C component).
- Rules of the red vs blue challenge (decoys, IP blocks, service availability).
- Console colors: Vulpnix uses a solid orange, Erinix browns and a cold orange. To confirm that the difference in hue is intentional.
