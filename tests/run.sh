#!/usr/bin/env bash
# passwdaudit tests. Read-only; fixtures in a temp dir.
set -uo pipefail
cd "$(dirname "$0")/.."
PA="python3 passwdaudit.py"
pass=0; fail=0
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

assert() {   # <desc> <expect> -- <cmd...>
    local desc="$1" expect="$2"; shift 2; [[ "$1" == "--" ]] && shift
    local out; out="$("$@" 2>&1)"
    if grep -qF -- "$expect" <<<"$out"; then printf '  PASS  %s\n' "$desc"; pass=$((pass+1))
    else printf '  FAIL  %s\n        wanted: %s\n        got: %s\n' "$desc" "$expect" "$out"; fail=$((fail+1)); fi
}
refute() {   # <desc> <needle> -- <cmd...>
    local desc="$1" needle="$2"; shift 2; [[ "$1" == "--" ]] && shift
    local out; out="$("$@" 2>&1)"
    if grep -qF -- "$needle" <<<"$out"; then printf '  FAIL  %s (found %s)\n' "$desc" "$needle"; fail=$((fail+1))
    else printf '  PASS  %s\n' "$desc"; pass=$((pass+1)); fi
}
assert_exit() {  # <desc> <code> -- <cmd...>
    local desc="$1" want="$2"; shift 2; [[ "$1" == "--" ]] && shift
    "$@" >/dev/null 2>&1; local rc=$?
    if [[ "$rc" == "$want" ]]; then printf '  PASS  %s\n' "$desc"; pass=$((pass+1))
    else printf '  FAIL  %s (exit %s want %s)\n' "$desc" "$rc" "$want"; fail=$((fail+1)); fi
}

echo "== syntax =="
if python3 -c "import ast; ast.parse(open('passwdaudit.py').read())"; then
    echo "  PASS  passwdaudit.py parses"; pass=$((pass+1))
else echo "  FAIL  syntax"; fail=$((fail+1)); fi

# a passwd full of problems
cat > "$T/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/bash
backdoor:x:0:0:evil:/root:/bin/bash
svc:x:200:200:svc:/home/svc:/bin/bash
alice:x:1000:1000:Alice:/home/alice:/bin/bash
dupe:x:1000:1000:Dupe:/home/dupe:/bin/bash
EOF
cat > "$T/shadow" <<'EOF'
root:$6$abc$def:19000:0:99999:7:::
backdoor:$1$xy$zzz:19000:0:99999:7:::
alice::19000:0:99999:7:::
EOF

echo "== passwd risks =="
assert "second UID 0 is CRITICAL"   "has UID 0"                 -- $PA --passwd "$T/passwd" --shadow "$T/shadow" --no-color
assert "duplicate UID flagged"      "UID 1000 is shared"        -- $PA --passwd "$T/passwd" --shadow "$T/shadow" --no-color
assert "system acct login shell"    "system account but has a login shell" -- $PA --passwd "$T/passwd" --shadow "$T/shadow" --no-color
assert_exit "problems exit non-zero" 1 -- $PA --passwd "$T/passwd" --shadow "$T/shadow" --no-color

echo "== shadow risks =="
assert "empty shadow password CRIT" "passwordless login"        -- $PA --passwd "$T/passwd" --shadow "$T/shadow" --no-color
assert "MD5 hash is weak"           "weak MD5-crypt"            -- $PA --passwd "$T/passwd" --shadow "$T/shadow" --no-color

echo "== a clean account database passes =="
cat > "$T/pgood" <<'EOF'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alice:x:1000:1000:Alice:/home/alice:/bin/bash
EOF
cat > "$T/sgood" <<'EOF'
root:$6$abc$def:19000:0:99999:7:::
daemon:*:19000:0:99999:7:::
alice:$y$j9T$abc:19000:0:99999:7:::
EOF
assert "clean db is OK"             "no account risks found"    -- $PA --passwd "$T/pgood" --shadow "$T/sgood" --no-color
assert_exit "clean db exits zero"   0 -- $PA --passwd "$T/pgood" --shadow "$T/sgood" --no-color
refute "SHA-512 root not flagged"   "root: weak"                -- $PA --passwd "$T/pgood" --shadow "$T/sgood" --no-color

echo "== shadow unreadable -> checks skipped, noted =="
assert "missing shadow noted"       "password-hash checks skipped" -- $PA --passwd "$T/pgood" --shadow "$T/does-not-exist" --no-color

echo
echo "== $pass passed, $fail failed =="
[[ $fail -eq 0 ]]
