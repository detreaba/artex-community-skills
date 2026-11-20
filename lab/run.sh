#!/usr/bin/env bash
# artex-lab runner: ./run.sh <slug> <probe-script>
# probe script: $1=variant  $2=base_url ; raw response -> stdout
set -uo pipefail
cd "$(dirname "$0")"
SLUG="${1:?usage: run.sh <slug> <probe-script>}"
PROBE="${2:?usage: run.sh <slug> <probe-script>}"
[ -f "$SLUG/${COMPOSE:-compose.yml}" ] || { echo "no such slug: $SLUG"; exit 2; }
[ -f "$PROBE" ] || { echo "no probe: $PROBE"; exit 2; }

SCHEME=${SCHEME:-http}
if [ -z "${PORTS:-}" ]; then
case "$SLUG" in
  php2shell)   PORTS=(8081 8082) ;;
  node2shell)  PORTS=(8083 8084); SCHEME=http ;;
  nginx2shell) PORTS=(8085 8086); SCHEME=http ;;
  ruby-onigmo) PORTS=(8087 8088); SCHEME=http ;;
  java4shell)  PORTS=(8089 8090); SCHEME=http ;;
  *) echo "add PORTS for $SLUG here (vulnerable patched)" && exit 2 ;;
esac
fi
PORTS=(${PORTS[*]})

exec 9>/tmp/artex-lab.lock; flock -n 9 || { echo "lab busy (another runner holds fixtures); retry in 60s"; exit 75; }
TS="$(date -u +%Y%m%dT%H%M%SZ)"
EV="$SLUG/evidence/$TS"; mkdir -p "$EV"
docker compose -f "$SLUG/${COMPOSE:-compose.yml}" up -d || { rm -rf "$EV"; exit 3; }
trap 'docker compose -f "$SLUG/${COMPOSE:-compose.yml}" down -v >/dev/null 2>&1' EXIT
for p in "${PORTS[@]}"; do   # wait for listeners (slower runtimes like ruby); java4shell has none yet -> times out harmlessly
  for _ in $(seq 1 15); do
    curl -s -o /dev/null --max-time 1 "$SCHEME://127.0.0.1:$p/" && break
    sleep 1
  done
done
for i in 0 1; do
  v=$([ "$i" = 0 ] && echo vulnerable || echo patched)
  "$PROBE" "$v" "$SCHEME://127.0.0.1:${PORTS[$i]}" > "$EV/$v.stdout" 2> "$EV/$v.stderr"
  echo "exit=$?" > "$EV/$v.meta"
  cp "$PROBE" "$EV/probe.sh"
done
echo "EVIDENCE=$PWD/$EV"
