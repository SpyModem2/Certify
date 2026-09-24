#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
rm -rf "$root/wheelhouse" "$root/dist"
mkdir -p "$root/wheelhouse" "$root/dist"
python3 -m pip wheel --wheel-dir "$root/wheelhouse" "${root}[dev]"
python3 -m pip wheel --no-deps --wheel-dir "$root/dist" "$root"
(cd "$root" && sha256sum wheelhouse/*.whl dist/*.whl > dist/SHA256SUMS)
tar --exclude='dist/certify-update-*.tar.gz' \
  -czf "$root/dist/certify-update-$(date +%Y%m%d%H%M%S).tar.gz" \
  -C "$root" README.md LICENSE packaging dist wheelhouse
echo "Offline-Update-Paket wurde unter dist/certify-update-*.tar.gz erstellt."
