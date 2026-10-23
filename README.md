# SSH config checker

![tests](https://github.com/twistedsol/sshd-config-checker/actions/workflows/tests.yml/badge.svg)

A small Python tool that reads an `sshd_config` file (the settings file for an SSH server) and flags risky settings. It only reads text files and never connects to a server. Standard library only, no installs.

## Run it

```
python sshd_checker.py sample_configs/01_risky_server.conf
python sshd_checker.py sample_configs/*.conf
python sshd_checker.py sample_configs/02_default_style.conf --format json
```

On Windows I use `py -3.13` instead of `python`. On a Linux server you can point it at `/etc/ssh/sshd_config`.

Three sample configs are included. They are made up for practice:

| File | What it is | Findings |
|---|---|---|
| `01_risky_server.conf` | A badly set up server | 12 (3 high) |
| `02_default_style.conf` | Looks normal but leaves gaps | 4 (0 high) |
| `03_hardened.conf` | A hardened server | 0 |

## What it checks

| Rule | Severity | Flags |
|---|---|---|
| root-login | high | `PermitRootLogin yes` |
| empty-passwords | high | `PermitEmptyPasswords yes` |
| protocol-1 | high | Protocol 1 allowed |
| password-auth | medium | Password logins allowed, or not set (the default is yes) |
| pubkey-disabled | medium | Key login turned off |
| max-auth-tries | medium | More than 6 tries |
| hostbased-auth / user-environment / gateway-ports | medium | The setting is `yes` |
| rhosts / strict-modes | medium | `IgnoreRhosts no` / `StrictModes no` |
| weak-ciphers / weak-macs | medium | CBC, 3DES, arcfour, MD5, `-96` and similar |
| x11-forwarding | low | X11 forwarding on |
| login-grace | low | Login window over 60 seconds |
| no-idle-timeout | low | Idle sessions never closed |
| no-allowlist | low | No `AllowUsers` or `AllowGroups` |

## Options

- `--format text|json` (default text)
- `--min-severity low|medium|high` hides findings below that level
- `--fail-on low|medium|high` sets which level makes the exit code 1 (default high)

Exit codes: `0` nothing at or above `--fail-on`, `1` findings, `2` bad input (missing or unreadable file).

## Test it

```
python -m unittest -v
```

41 tests cover the file parser, each rule and its edges (6 vs 7 tries, 60 vs 120 seconds), bad input, the command line and the sample files. GitHub Actions runs them on Python 3.10 and 3.12.

## How I built it

I used AI to help write the code and tests, then ran everything myself, read each rule and checked the sample results by hand. The rules follow common SSH hardening advice.

## Limits

- It reads the file only. The real running server may be set differently, for example by an included file or a command-line flag.
- Lines after a `Match` line are not checked, because they only apply to certain users or hosts. The tool prints a note when it skips them.
- It does not know your system's built-in defaults beyond the ones named above.
- Cipher and MAC lists change over time, so the weak list needs updating.

## Next ideas

- Follow `Include` lines
- Add a score out of 100
- Add an HTML report
