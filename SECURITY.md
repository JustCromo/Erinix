# Security policy

## Reporting a vulnerability

Please report security problems **privately** through GitHub: open the repository's
"Security" tab and choose "Report a vulnerability". Do not open a public issue.

Include what you found, how to reproduce it and the version (`erinix --version`).

## Security model in short

- Erinix is a monitoring tool: **it does not replace a firewall or a web application firewall**.
  Detection is heuristic and can miss attacks.
- Everything read from logs and from the system is treated as **untrusted input**: sizes are
  bounded, formats are validated and malformed data is rejected instead of guessed.
- Rules are data, not code. Rule files must be trusted (owner and permissions are checked).
- The console never forwards untrusted text to the terminal unfiltered.
- Running as root is only needed for features that require it; the history file of a root session
  never lives in a directory controlled by an unprivileged user.
- The web dashboard listens on the local machine only, signs you in with a one-time link, checks the
  address it was called by, protects changes against forged requests and loads nothing from other sites.
- The alert store is a private file readable only by its owner.
- No secrets belong in the repository, in rules or in documentation.

## Supported versions

Only the latest release receives security fixes while the project is in alpha.
