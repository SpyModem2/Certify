#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID} -ne 0 ]]; then echo "run as root" >&2; exit 1; fi
version="${CERTIFY_VERSION:-0.1.0}"
id certify &>/dev/null || useradd --system --home-dir /var/lib/certify --shell /sbin/nologin certify
install -d -m 0750 -o certify -g certify /var/lib/certify
install -d -m 0750 -o root -g certify /etc/certify /opt/certify
python3 -m venv /opt/certify/venv
/opt/certify/venv/bin/pip install "certify-server==${version}"
root="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=packaging/install-common.sh
source "$root/packaging/install-common.sh"
finish_install "$root"
