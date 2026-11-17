#!/usr/bin/env bash
# Step 5 - concurrent streaming sessions.
#
# Starts one Secure Stream Server and N Secure Proxies, then makes every proxy download every movie in
# streamserver/media at the same time (plus one seek per proxy). Every download is compared byte by byte
# with the original file, and the proxies' [stats] reports are summed up at the end.
#
# Usage (from the project root, macOS / Linux / Git Bash):
#   tests/concurrency.sh [config dir = configs/aes-gcm] [proxies = 3] [rounds = 2]
# Ports: server 19081, proxies 19090, 19091, ... (so it does not clash with a demo on 8080/8081).

set -u
CFG=${1:-configs/aes-gcm}
PROXIES=${2:-3}
ROUNDS=${3:-2}
MEDIA=streamserver/media
SERVER_PORT=19081
PROXY_BASE=19090
WORK=$(mktemp -d)
PIDS=()

# Java on Windows (Git Bash) separates classpath entries with ';' and needs Windows paths; elsewhere ':'
case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN*) SEP=';'; native() { cygpath -w "$1"; } ;;
    *) SEP=':'; native() { echo "$1"; } ;;
esac
BCPROV=lib/bcprov-jdk18on-1.86.jar

# Time in seconds with decimals. GNU date (Linux, Git Bash) knows %N; macOS date prints a literal "N",
# so there perl is used (macOS perl always has Time::HiRes; minimal Linux perl may not)
now() {
    local t
    t=$(date +%s.%N 2>/dev/null)
    case "$t" in
        *N* | "") t=$(perl -MTime::HiRes=time -e 'printf "%.3f\n", time' 2>/dev/null || date +%s) ;;
    esac
    echo "$t"
}

cleanup() { kill "${PIDS[@]}" 2>/dev/null; wait "${PIDS[@]}" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

wait_port() {
    for _ in $(seq 1 50); do
        (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null && return 0
        sleep 0.2
    done
    echo "port $1 did not open" >&2
    exit 1
}

[ -f "$CFG/servercrypto.config" ] || { echo "no config pair in $CFG" >&2; exit 1; }
MOVIES=()
for f in "$MEDIA"/*.mp4; do MOVIES+=("$(basename "$f")"); done
[ ${#MOVIES[@]} -gt 0 ] || { echo "no .mp4 files in $MEDIA" >&2; exit 1; }

echo "Compiling..."
javac --release 21 -d "$WORK/server" streamserver/*.java common/*.java || exit 1
javac --release 21 -d "$WORK/proxy" streamproxy/*.java common/*.java || exit 1

java -cp "$(native "$WORK/server")$SEP$BCPROV" OriginSocketServer $SERVER_PORT "$MEDIA" "$CFG/servercrypto.config" > "$WORK/server.log" 2>&1 &
PIDS+=($!)
wait_port $SERVER_PORT
for ((p = 0; p < PROXIES; p++)); do
    java -cp "$(native "$WORK/proxy")$SEP$BCPROV" ProxySocketServer $((PROXY_BASE + p)) localhost $SERVER_PORT "$CFG/proxycrypto.config" \
        > "$WORK/proxy$p.log" 2>&1 &
    PIDS+=($!)
    wait_port $((PROXY_BASE + p))
done

TOTAL=$((PROXIES * (ROUNDS * ${#MOVIES[@]} + 1)))
echo "Config $CFG | $PROXIES proxies | movies: ${MOVIES[*]} | $ROUNDS rounds"
echo "Starting $TOTAL downloads at the same time..."

START=$(now)
JOBS=()
for ((p = 0; p < PROXIES; p++)); do
    for ((r = 0; r < ROUNDS; r++)); do
        for m in "${MOVIES[@]}"; do
            curl -s -o "$WORK/p$p-r$r-$m" "http://localhost:$((PROXY_BASE + p))/video/$m" &
            JOBS+=($!)
        done
    done
    # One seek per proxy: second half of the first movie
    SIZE=$(wc -c < "$MEDIA/${MOVIES[0]}" | tr -d ' ')
    curl -s -o "$WORK/p$p-seek" -H "Range: bytes=$((SIZE / 2))-" "http://localhost:$((PROXY_BASE + p))/video/${MOVIES[0]}" &
    JOBS+=($!)
done
wait "${JOBS[@]}"
END=$(now)
sleep 0.5 # let the proxies print their last reports

OK=0
FAIL=0
for ((p = 0; p < PROXIES; p++)); do
    for ((r = 0; r < ROUNDS; r++)); do
        for m in "${MOVIES[@]}"; do
            if cmp -s "$WORK/p$p-r$r-$m" "$MEDIA/$m"; then OK=$((OK + 1)); else FAIL=$((FAIL + 1)); echo "  DIFFERENT: proxy $p round $r $m"; fi
        done
    done
    if tail -c +$((SIZE / 2 + 1)) "$MEDIA/${MOVIES[0]}" | cmp -s - "$WORK/p$p-seek"; then OK=$((OK + 1)); else FAIL=$((FAIL + 1)); echo "  DIFFERENT: proxy $p seek"; fi
done

BYTES=$(cat "$WORK"/p*-* | wc -c | tr -d ' ')
COMPLETED=$(cat "$WORK"/proxy*.log | grep -c 'COMPLETED')
ABORTED=$(cat "$WORK"/proxy*.log | grep -c -E 'ABORTED|CONNECTION_CLOSED')
SERVED=$(grep -c '^Request:' "$WORK/server.log")
# awk instead of bc: Git Bash has no bc
SECONDS_TAKEN=$(awk -v s="$START" -v e="$END" 'BEGIN { printf "%.2f", e - s }')
MB=$(awk -v b="$BYTES" 'BEGIN { printf "%.1f", b / 1048576 }')
MBPS=$(awk -v b="$BYTES" -v t="$SECONDS_TAKEN" 'BEGIN { printf "%.1f", (t > 0 ? b / 1048576 / t : 0) }')

echo
echo "Downloads identical to the original : $OK / $TOTAL  (different: $FAIL)"
echo "Requests served by the server       : $SERVED"
echo "Proxy reports COMPLETED / ABORTED   : $COMPLETED / $ABORTED"
echo "Data delivered to the clients       : $MB MB in ${SECONDS_TAKEN} s ($MBPS MB/s aggregate)"
echo
echo "Per-request throughput reported by the proxies (MB/s):"
grep -h -o '[0-9.]* MB/s' "$WORK"/proxy*.log | awk '{ s += $1; n++; if (min == "" || $1 < min) min = $1; if ($1 > max) max = $1 }
    END { if (n) printf "  n=%d  min %.1f  avg %.1f  max %.1f\n", n, min, s / n, max }'

[ "$FAIL" -eq 0 ] && [ "$ABORTED" -eq 0 ] && echo "RESULT: OK" || { echo "RESULT: FAILED"; exit 1; }
