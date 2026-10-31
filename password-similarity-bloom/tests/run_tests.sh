#!/usr/bin/env bash
# Feeds candidate passwords to the checker and compares the final decision with expectations.
# Usage: bash tests/run_tests.sh [path-to-binary]
BIN="${1:-bin/password_checker}"
pass=0; fail=0

check() {
    local input="$1" expected="$2" out actual
    out=$(printf '%s\nq\n' "$input" | "$BIN")
    if [[ "$expected" == "INVALID" ]]; then
        grep -q "Invalid length" <<<"$out" && actual="INVALID" || actual="(no error shown)"
    else
        actual=$(grep -m1 '^FINAL:' <<<"$out" | awk '{print $2}')
    fi
    if [[ "$actual" == "$expected" ]]; then
        printf 'PASS  %-16s -> %s\n' "$input" "$actual"; pass=$((pass+1))
    else
        printf 'FAIL  %-16s expected %s, got %s\n' "$input" "$expected" "$actual"; fail=$((fail+1))
    fi
}

check football23   REJECT   # exact dataset entry
check football2    REJECT   # digit change
check football1    REJECT
check princess9    REJECT
check jasmine2     REJECT
check "pass@word"  REJECT   # symbol substitution
check mysecure     ACCEPT
check rainfall     ACCEPT
check "ch@mpion"   ACCEPT
check Tr0ub4dor    ACCEPT
check abc          INVALID  # too short
check averylongpassword INVALID  # too long

echo; echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
