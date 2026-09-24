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
request="$data_dir/update-check.request"
status_file="$data_dir/update-check-status.json"
rm -f "$request"

write_status() {
  local state="$1" available="$2" current="$3" latest="$4" message="$5" temporary
  temporary="${status_file}.tmp"
  python3 - "$state" "$available" "$current" "$latest" "$message" >"$temporary" <<'PY'
import json
import sys
from datetime import UTC, datetime

state, available, current, latest, message = sys.argv[1:]
print(json.dumps({
    "check_status": state,
    "update_available": available == "true",
    "latest_version": latest or None,
    "checked_at": datetime.now(UTC).isoformat(),
    "check_message": message,
    "checked_version": current,
}))
PY
  chown certify:certify "$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$status_file"
}

current="$(/opt/certify/venv/bin/python -c 'import certify; print(certify.__version__)' 2>/dev/null || true)"
if [[ ! -r "$source_file" ]]; then
  write_status failed false "$current" "" "Die Update-Prüfung ist noch nicht konfiguriert."
  exit 1
fi
source_root="$(cat "$source_file")"
if [[ ! -d "$source_root/.git" ]]; then
  write_status failed false "$current" "" "Die konfigurierte Update-Quelle ist nicht verfügbar."
  exit 1
fi

owner="$(stat -c %U "$source_root")"
git_repo() {
  if [[ "$owner" != root ]]; then runuser -u "$owner" -- git -C "$source_root" "$@"; else git -C "$source_root" "$@"; fi
}
remote="${CERTIFY_UPDATE_REMOTE:-origin}"
if ! git_repo fetch --tags --prune "$remote" >/dev/null 2>&1; then
  write_status failed false "$current" "" "Die Update-Quelle konnte nicht erreicht werden. Bitte später erneut prüfen."
  exit 1
fi
branch="$(git_repo symbolic-ref --quiet --short HEAD 2>/dev/null || true)"
if [[ -z "$branch" ]]; then
  write_status failed false "$current" "" "Für die automatische Prüfung muss die Update-Quelle einem Branch folgen."
  exit 1
fi
latest="$(git_repo show "refs/remotes/${remote}/${branch}:VERSION" 2>/dev/null | tr -d '[:space:]')"
if [[ ! "$current" =~ ^[0-9]+([.][0-9]+)*([+-][0-9A-Za-z.-]+)?$ || ! "$latest" =~ ^[0-9]+([.][0-9]+)*([+-][0-9A-Za-z.-]+)?$ ]]; then
  write_status failed false "$current" "$latest" "Die Versionsinformationen der Update-Quelle sind ungültig."
  exit 1
fi

first="$(printf '%s\n%s\n' "$current" "$latest" | sort -V | head -n1)"
if [[ "$current" != "$latest" && "$first" == "$current" ]]; then
  write_status success true "$current" "$latest" "Version ${latest} ist verfügbar."
else
  write_status success false "$current" "$latest" "Die installierte Version ist aktuell."
fi
