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
if [[ ! -e /etc/certify/certify.conf ]]; then
  install -m 0640 -o root -g certify "$root/packaging/certify.conf.example" /etc/certify/certify.conf
fi
install -m 0644 "$root/packaging/certify.service" /etc/systemd/system/certify.service
systemctl daemon-reload
echo "Edit /etc/certify/certify.conf, run /opt/certify/venv/bin/certify init-admin admin, then enable the service."
