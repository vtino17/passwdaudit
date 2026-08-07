#!/usr/bin/env python3
"""passwdaudit - audit /etc/passwd and /etc/shadow for account risks.

The account database is where backdoors hide: a second UID-0 account, a user with
an empty password field, a system account that kept a login shell, a password
still hashed with MD5. passwdaudit reads passwd (and shadow, if it can) and
reports these by severity. It reads files only and changes nothing.

    sudo passwdaudit                       # /etc/passwd + /etc/shadow
    passwdaudit --passwd ./passwd --shadow ./shadow

Shadow is only readable by root; without it, the password-hash checks are skipped
and noted. Exit status is non-zero on any HIGH or CRITICAL finding.
"""
from __future__ import annotations

import argparse
import os
import sys

# login shells that mean "this account cannot log in interactively"
NOLOGIN_SHELLS = {"", "/usr/sbin/nologin", "/sbin/nologin", "/bin/false",
                  "/usr/bin/false", "/bin/sync", "/dev/null"}

# shadow hash prefixes -> (label, ok?)
HASH_INFO = {
    "$1$": ("MD5-crypt", False),
    "$2a$": ("bcrypt", True), "$2b$": ("bcrypt", True), "$2y$": ("bcrypt", True),
    "$5$": ("SHA-256", True), "$6$": ("SHA-512", True),
    "$y$": ("yescrypt", True), "$gy$": ("gost-yescrypt", True), "$7$": ("scrypt", True),
}


class Finding:
    def __init__(self, level: str, msg: str):
        self.level, self.msg = level, msg


def parse_passwd(text: str) -> list[list[str]]:
    rows = []
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 7:
            rows.append(parts)
    return rows


def parse_shadow(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 2:
            out[parts[0]] = parts[1]
    return out


def audit(passwd_rows: list[list[str]], shadow: dict[str, str] | None) -> list[Finding]:
    out: list[Finding] = []
    uids: dict[str, list[str]] = {}
    names: dict[str, int] = {}

    for row in passwd_rows:
        name, pw, uid, gid, gecos, home, shell = row[:7]
        uids.setdefault(uid, []).append(name)
        names[name] = names.get(name, 0) + 1

        # UID 0 that is not root
        if uid == "0" and name != "root":
            out.append(Finding("CRITICAL", f"account {name!r} has UID 0: a second superuser (backdoor risk)"))

        # password field in passwd should be 'x' (or '*'); anything else is suspect
        if pw == "":
            out.append(Finding("CRITICAL", f"{name}: empty password field in passwd (login with no password)"))
        elif pw not in ("x", "*", "!"):
            out.append(Finding("HIGH", f"{name}: password hash stored in /etc/passwd (should be 'x' -> shadow)"))

        # system account (UID < 1000, not root) with a real login shell
        try:
            uid_n = int(uid)
        except ValueError:
            uid_n = -1
            out.append(Finding("HIGH", f"{name}: non-numeric UID {uid!r}"))
        if 0 < uid_n < 1000 and shell not in NOLOGIN_SHELLS:
            out.append(Finding("MEDIUM", f"{name} (UID {uid}) is a system account but has a login shell {shell!r}"))

    # duplicate UIDs
    for uid, holders in uids.items():
        if len(holders) > 1:
            lvl = "CRITICAL" if uid == "0" else "HIGH"
            out.append(Finding(lvl, f"UID {uid} is shared by {', '.join(holders)} (accounts should have unique UIDs)"))
    # duplicate names
    for name, n in names.items():
        if n > 1:
            out.append(Finding("HIGH", f"username {name!r} appears {n} times in passwd"))

    # shadow checks
    if shadow is None:
        out.append(Finding("INFO", "shadow not read (needs root); password-hash checks skipped"))
    else:
        passwd_names = {row[0] for row in passwd_rows}
        for row in passwd_rows:
            name, pw = row[0], row[1]
            if pw == "x" and name not in shadow:
                out.append(Finding("HIGH", f"{name}: passwd delegates to shadow but no shadow record exists"))
        for name in sorted(set(shadow) - passwd_names):
            out.append(Finding("MEDIUM", f"{name}: orphaned shadow record has no passwd account"))
        for name, h in shadow.items():
            if h == "":
                out.append(Finding("CRITICAL", f"{name}: empty password in shadow (passwordless login)"))
            elif h in ("!", "*", "!!", "!*") or h.startswith("!"):
                continue  # locked / no password set
            else:
                label = next((v for k, v in HASH_INFO.items() if h.startswith(k)), None)
                if label is None:
                    if len(h) == 13 and "$" not in h:
                        out.append(Finding("HIGH", f"{name}: DES-crypt password hash (obsolete, crackable)"))
                elif not label[1]:
                    out.append(Finding("HIGH", f"{name}: weak {label[0]} password hash; rehash with yescrypt/SHA-512"))

    if not out or all(f.level == "INFO" for f in out):
        out.append(Finding("OK", "no account risks found"))
    return out


RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "OK": 0}
COLOR = {"CRITICAL": "\033[1;31m", "HIGH": "\033[31m", "MEDIUM": "\033[33m",
         "LOW": "\033[36m", "INFO": "\033[90m", "OK": "\033[32m"}
RESET = "\033[0m"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="passwdaudit", description="audit /etc/passwd and /etc/shadow")
    p.add_argument("--passwd", default="/etc/passwd")
    p.add_argument("--shadow", default="/etc/shadow")
    p.add_argument("--no-color", action="store_true")
    a = p.parse_args(argv)
    use_color = sys.stdout.isatty() and not a.no_color

    if not os.path.exists(a.passwd):
        print(f"passwdaudit: cannot read {a.passwd}", file=sys.stderr)
        return 2
    with open(a.passwd, encoding="utf-8", errors="replace") as fh:
        rows = parse_passwd(fh.read())

    shadow: dict[str, str] | None = None
    if os.path.exists(a.shadow):
        try:
            with open(a.shadow, encoding="utf-8", errors="replace") as fh:
                shadow = parse_shadow(fh.read())
        except PermissionError:
            shadow = None

    findings = audit(rows, shadow)
    worst = 0
    for f in sorted(findings, key=lambda x: -RANK[x.level]):
        worst = max(worst, RANK[f.level])
        tag = f"{COLOR[f.level]}{f.level:<8}{RESET}" if use_color else f"{f.level:<8}"
        print(f"  {tag} {f.msg}")
    return 1 if worst >= RANK["HIGH"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
