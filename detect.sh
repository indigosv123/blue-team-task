#!/usr/bin/env bash
# detect.sh - Decrypt a Vigenere-encrypted web access log and detect attacks.
# Usage: ./detect.sh access.log.enc
# Exit:  1 if any attack detected, 0 if clean, 2 on usage/input error.

KEY="MAYDAY"
BRUTE_THRESHOLD=5

if [[ $# -ne 1 || ! -r "$1" ]]; then
    echo "Usage: $0 <encrypted_log_file>" >&2
    exit 2
fi

# ---- Step 1: decrypt (Vigenere, key resets every line, key advances only on letters)
decrypt() {
    LC_ALL=C awk -v key="$KEY" '
    BEGIN { U="ABCDEFGHIJKLMNOPQRSTUVWXYZ"; L="abcdefghijklmnopqrstuvwxyz"; klen=length(key) }
    {
        out=""; ki=0
        for (j=1; j<=length($0); j++) {
            c=substr($0,j,1)
            shift=index(U, substr(key, (ki % klen)+1, 1)) - 1
            if ((p=index(U,c)) > 0)      { out=out substr(U, (p-1-shift+26)%26+1, 1); ki++ }
            else if ((p=index(L,c)) > 0) { out=out substr(L, (p-1-shift+26)%26+1, 1); ki++ }
            else                         { out=out c }
        }
        print out
    }' "$1"
}

PLAIN="$(decrypt "$1")"

# ---- Step 2: detect.  Each function prints "<count> <ip>" per offending IP, highest first.
# Log format: IP - - [time] "METHOD PATH PROTO" STATUS ...  -> status is the field after the quoted request.

brute_force() {
    awk -v t="$BRUTE_THRESHOLD" '
    { split($0, a, "\""); split(a[3], b, " "); if (b[1]=="401") n[$1]++ }
    END { for (ip in n) if (n[ip] >= t) print n[ip], ip }' | sort -k1,1nr
}

sql_injection() {
    grep -iE "DROP TABLE|OR 1=1|OR '1'='1'" | awk '{print $1}' | sort | uniq -c | awk '{print $1, $2}' | sort -k1,1nr
}

dir_traversal() {
    grep -E '\.\./' | awk '{print $1}' | sort | uniq -c | awk '{print $1, $2}' | sort -k1,1nr
}

found=0

while read -r count ip; do
    [[ -z "$ip" ]] && continue
    echo "[ALERT] Brute force from $ip ($count failed logins)"; found=1
done <<< "$(brute_force <<< "$PLAIN")"

while read -r count ip; do
    [[ -z "$ip" ]] && continue
    echo "[ALERT] SQL injection from $ip ($count attempts)"; found=1
done <<< "$(sql_injection <<< "$PLAIN")"

while read -r count ip; do
    [[ -z "$ip" ]] && continue
    echo "[ALERT] Directory traversal from $ip ($count attempts)"; found=1
done <<< "$(dir_traversal <<< "$PLAIN")"

if [[ $found -eq 1 ]]; then
    exit 1
else
    echo "[OK] No attacks detected"
    exit 0
fi
