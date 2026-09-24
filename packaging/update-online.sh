#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=packaging/update-common.sh
source "$root/packaging/update-common.sh"
certify_update "$root"
