#!/usr/bin/env python3
"""SSH server config checker.

Reads sshd_config files and flags risky settings. It only reads text files:
it never connects to a server.

Exit codes: 0 = nothing at or above --fail-on, 1 = findings, 2 = bad input.
"""
import argparse
import json
import re
import sys

SEVERITIES = {"low": 1, "medium": 2, "high": 3}

WEAK_CIPHER_WORDS = ("3des", "arcfour", "blowfish", "cast128", "-cbc")
WEAK_MAC_WORDS = ("hmac-md5", "-96", "umac-64")


class ConfigError(Exception):
    """Raised when a config file cannot be used."""


def parse_config(text):
    """Return (settings, has_match). First value wins, like sshd.

    Keys are lower case. Everything after a Match line is ignored because
    those settings only apply to some users or hosts.
    """
    settings = {}
    has_match = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"\s*=\s*|\s+", line, maxsplit=1)
        key = parts[0].lower()
        value = parts[1].strip().strip('"') if len(parts) > 1 else ""
        if key == "match":
            has_match = True
            break
        settings.setdefault(key, value)
    return settings, has_match


def load_config(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return parse_config(handle.read())
    except FileNotFoundError:
        raise ConfigError("file not found: %s" % path)
    except UnicodeDecodeError:
        raise ConfigError("not a text file: %s" % path)
    except OSError as exc:
        raise ConfigError("cannot read %s: %s" % (path, exc.strerror))


def _finding(rule, severity, message, fix):
    return {"rule": rule, "severity": severity, "message": message, "fix": fix}


def _is(settings, key, wanted):
    return settings.get(key, "").lower() == wanted


def _seconds(value):
    """Turn '120', '2m' or '1h' into seconds, or None if unreadable."""
    match = re.fullmatch(r"(\d+)([smhdw]?)", value.strip().lower())
    if not match:
        return None
    factor = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    return int(match.group(1)) * factor[match.group(2)]


def _list(settings, key):
    return [v.strip().lower().lstrip("+-^") for v in settings.get(key, "").split(",") if v.strip()]


def check_config(settings):
    findings = []

    root = settings.get("permitrootlogin", "").lower()
    if root == "yes":
        findings.append(_finding(
            "root-login", "high", "Root can log in over SSH.",
            "Set PermitRootLogin no (or prohibit-password) and use sudo."))

    if _is(settings, "permitemptypasswords", "yes"):
        findings.append(_finding(
            "empty-passwords", "high", "Accounts with empty passwords can log in.",
            "Set PermitEmptyPasswords no."))

    protocol = settings.get("protocol", "")
    if protocol and "1" in protocol.replace(" ", "").split(","):
        findings.append(_finding(
            "protocol-1", "high", "SSH protocol 1 is allowed, and it is broken.",
            "Remove the Protocol line (protocol 2 is the only one now)."))

    if not _is(settings, "passwordauthentication", "no"):
        if "passwordauthentication" in settings:
            note = "Password logins are allowed."
        else:
            note = "PasswordAuthentication is not set, and the default is yes."
        findings.append(_finding(
            "password-auth", "medium", note,
            "Use keys and set PasswordAuthentication no."))

    if _is(settings, "pubkeyauthentication", "no"):
        findings.append(_finding(
            "pubkey-disabled", "medium", "Key-based login is turned off.",
            "Set PubkeyAuthentication yes."))

    tries = settings.get("maxauthtries", "")
    if tries.isdigit() and int(tries) > 6:
        findings.append(_finding(
            "max-auth-tries", "medium", "MaxAuthTries is %s, which allows many guesses." % tries,
            "Set MaxAuthTries to 4 or less."))

    for key, rule, why in (
            ("hostbasedauthentication", "hostbased-auth", "Host-based login is on."),
            ("permituserenvironment", "user-environment", "Users can set their own environment."),
            ("gatewayports", "gateway-ports", "Forwarded ports are open to every network."),
    ):
        if _is(settings, key, "yes"):
            findings.append(_finding(rule, "medium", why, "Set %s no." % key))
    if _is(settings, "ignorerhosts", "no"):
        findings.append(_finding(
            "rhosts", "medium", "Old .rhosts trust files are honoured.", "Set IgnoreRhosts yes."))
    if _is(settings, "strictmodes", "no"):
        findings.append(_finding(
            "strict-modes", "medium", "File permission checks are off.", "Set StrictModes yes."))

    ciphers = _list(settings, "ciphers")
    bad_c = [c for c in ciphers if any(w in c for w in WEAK_CIPHER_WORDS)]
    if bad_c:
        findings.append(_finding(
            "weak-ciphers", "medium", "Weak ciphers allowed: %s." % ", ".join(bad_c),
            "Keep only chacha20-poly1305 and AES-GCM/CTR ciphers."))
    macs = _list(settings, "macs")
    bad_m = [m for m in macs if any(w in m for w in WEAK_MAC_WORDS)]
    if bad_m:
        findings.append(_finding(
            "weak-macs", "medium", "Weak MACs allowed: %s." % ", ".join(bad_m),
            "Use hmac-sha2-*-etm or umac-128-etm MACs."))

    if _is(settings, "x11forwarding", "yes"):
        findings.append(_finding(
            "x11-forwarding", "low", "X11 forwarding is on.", "Set X11Forwarding no unless needed."))

    grace = _seconds(settings.get("logingracetime", ""))
    if grace is not None and (grace == 0 or grace > 60):
        findings.append(_finding(
            "login-grace", "low", "Unauthenticated connections may stay open for %s." % settings["logingracetime"],
            "Set LoginGraceTime to 30 or 60 seconds."))

    alive = settings.get("clientaliveinterval", "0")
    if not alive.isdigit() or int(alive) == 0:
        findings.append(_finding(
            "no-idle-timeout", "low", "Idle sessions are never closed.",
            "Set ClientAliveInterval 300 and ClientAliveCountMax 2."))

    if not any(k in settings for k in ("allowusers", "allowgroups")):
        findings.append(_finding(
            "no-allowlist", "low", "No AllowUsers or AllowGroups limit.",
            "Name the users or groups that may log in over SSH."))

    findings.sort(key=lambda f: (-SEVERITIES[f["severity"]], f["rule"]))
    return findings


def filter_findings(findings, min_severity):
    floor = SEVERITIES[min_severity]
    return [f for f in findings if SEVERITIES[f["severity"]] >= floor]


def format_text(results):
    lines = []
    for name, findings in results:
        lines.append("%s: %d finding(s)" % (name, len(findings)))
        for f in findings:
            lines.append("  [%s] %s: %s" % (f["severity"].upper(), f["rule"], f["message"]))
            lines.append("      Fix: %s" % f["fix"])
        if not findings:
            lines.append("  No findings.")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def format_json(results):
    return json.dumps([{"config": n, "findings": f} for n, f in results], indent=2) + "\n"


def build_parser():
    parser = argparse.ArgumentParser(description="Check sshd_config files for risky settings.")
    parser.add_argument("files", nargs="+", help="sshd_config file(s)")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--min-severity", choices=tuple(SEVERITIES), default="low",
                        help="hide findings below this level")
    parser.add_argument("--fail-on", choices=tuple(SEVERITIES), default="high",
                        help="exit 1 if any finding is at or above this level")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    results = []
    worst = 0
    for path in args.files:
        try:
            settings, has_match = load_config(path)
        except ConfigError as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 2
        findings = check_config(settings)
        for f in findings:
            worst = max(worst, SEVERITIES[f["severity"]])
        results.append((path, filter_findings(findings, args.min_severity)))
        if has_match:
            print("note: %s has Match blocks, which are not checked." % path, file=sys.stderr)
    output = format_json(results) if args.format == "json" else format_text(results)
    sys.stdout.write(output)
    return 1 if worst >= SEVERITIES[args.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
