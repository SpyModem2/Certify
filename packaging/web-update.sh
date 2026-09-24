#!/usr/bin/env bash
set -uo pipefail

config=/etc/certify/certify.conf
source_file=/etc/certify/update-source
[[ -r "$config" ]] || exit 1
set -a
# shellcheck disable=SC1090
source "$config"
set +a
data_dir="${CERTIFY_DATA_DIR:-/var/lib/certify}"
request="$data_dir/update.request"
status_file="$data_dir/update-status.json"

write_status() {
  local state="$1" message="$2" timestamp_field="$3" temporary
  temporary="${status_file}.tmp"
  python3 - "$state" "$message" "$timestamp_field" >"$temporary" <<'PY'
import json
import sys
from datetime import UTC, datetime
state, message, field = sys.argv[1:]
print(json.dumps({"update_status": state, "message": message, field: datetime.now(UTC).isoformat()}))
PY
  chown certify:certify "$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$status_file"
}

rm -f "$request"
if [[ ! -r "$source_file" ]]; then
  write_status failed "Keine Update-Quelle konfiguriert. Installation erneut ausführen." finished_at
  exit 1
fi
source_root="$(cat "$source_file")"
if [[ ! -x "$source_root/packaging/update-online.sh" ]]; then
  write_status failed "Die konfigurierte Online-Update-Quelle ist nicht verfügbar." finished_at
  exit 1
fi

write_status running "Update wird vorbereitet; der Dienst wird anschließend neu gestartet." started_at
log="$data_dir/update.log"
if "$source_root/packaging/update-online.sh" >"$log" 2>&1; then
  write_status success "Update erfolgreich abgeschlossen." finished_at
else
  result=$?
  tail_message="$(tail -n 1 "$log" 2>/dev/null || true)"
  write_status failed "Update fehlgeschlagen: ${tail_message:-Details stehen in update.log.}" finished_at
  exit "$result"
fi
