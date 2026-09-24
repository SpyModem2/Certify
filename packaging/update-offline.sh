#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=packaging/update-common.sh
source "$root/packaging/update-common.sh"

[[ -f "$root/dist/SHA256SUMS" ]] || {
  echo "dist/SHA256SUMS fehlt. Bitte das vollstaendige Update-Paket verwenden." >&2
  exit 1
}
echo "Pruefe das Offline-Paket ..."
(cd "$root" && sha256sum --check dist/SHA256SUMS)
shopt -s nullglob
wheels=("$root"/dist/certify_server-*.whl)
[[ ${#wheels[@]} -eq 1 ]] || { echo "Genau ein Certify-Wheel in dist/ erwartet." >&2; exit 1; }
CERTIFY_UPDATE_FILES_ROOT="$root" certify_update "${wheels[0]}" --no-index --find-links "$root/wheelhouse"
