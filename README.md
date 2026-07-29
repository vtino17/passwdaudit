# passwdaudit

Audit `/etc/passwd` and `/etc/shadow` for the account risks that hide in plain
sight.

The account database is where backdoors live: a second UID-0 account, a user with
an empty password field, a system account that kept its login shell, a password
still hashed with MD5. passwdaudit reads passwd (and shadow, if it can) and
reports these by severity. It reads files only and changes nothing.

It is a single Python file with no dependencies and exits non-zero on any HIGH or
CRITICAL finding.

## Usage

```sh
sudo passwdaudit                                  # /etc/passwd + /etc/shadow
passwdaudit --passwd ./passwd --shadow ./shadow   # audit exported copies
```

`/etc/shadow` is only readable by root; run under `sudo` for the password-hash
checks. Without it, those checks are skipped and the report says so.

Example:

```
$ sudo passwdaudit
  CRITICAL account 'backdoor' has UID 0: a second superuser (backdoor risk)
  CRITICAL alice: empty password in shadow (passwordless login)
  HIGH     UID 1000 is shared by alice, dupe (accounts should have unique UIDs)
  HIGH     backdoor: weak MD5-crypt password hash; rehash with yescrypt/SHA-512
  MEDIUM   svc (UID 200) is a system account but has a login shell '/bin/bash'
```

## What it checks

- **A second UID-0 account** (anything but `root`) — an instant root backdoor.
- **Empty password fields** — in passwd, or `::` in shadow (login with no
  password).
- **Duplicate UIDs and usernames.**
- **System accounts with a login shell** — a UID below 1000 that is not on a
  `nologin`/`false` shell.
- **Weak password hashes** — MD5-crypt (`$1$`) and DES; `$5$`/`$6$`/bcrypt/
  yescrypt are recognised as fine. A password hash stored in `/etc/passwd`
  itself (rather than `x` → shadow) is flagged.

Locked accounts (`!`/`*` in shadow) and `nologin` system accounts are correctly
left quiet.

## Caveat

This audits the files. It does not check password *age* policy (that lives in
`/etc/login.defs` and the shadow date fields), sudo/group membership, or home
directory permissions. A finding may be intentional (some appliances share a
UID), so read before acting.

## Tests

```sh
./tests/run.sh
```

Builds passwd/shadow fixtures with a backdoor, a duplicate UID, an empty
password, an MD5 hash and a clean database, and asserts the findings — including
that SHA-512 and locked accounts stay quiet.

## License

MIT. See `LICENSE`.
