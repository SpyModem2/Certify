#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
python3 -m pip wheel --wheel-dir "$root/wheelhouse" "$root[dev]"
python3 -m pip wheel --no-deps --wheel-dir "$root/dist" "$root"
sha256sum "$root"/wheelhouse/*.whl "$root"/dist/*.whl > "$root/dist/SHA256SUMS"
