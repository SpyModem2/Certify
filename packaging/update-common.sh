#!/usr/bin/env bash
# Transactional update helpers shared by the online and offline updater.

certify_healthcheck() {
  local python="$1" expected_version="$2" host
  host="$(sed -n 's/^CERTIFY_TRUSTED_HOSTS=//p' /etc/certify/certify.conf | head -n1 | cut -d, -f1)"
  host="${host:-localhost}"
  "$python" - "$host" "$expected_version" <<'PY'
import http.client
import json
import ssl
import sys

host, expected = sys.argv[1:]
connection = http.client.HTTPSConnection("127.0.0.1", 443, timeout=3,
    context=ssl._create_unverified_context())
connection.request("GET", "/health", headers={"Host": host})
response = connection.getresponse()
payload = json.loads(response.read())
if response.status != 200 or payload != {"status": "ok", "version": expected}:
    raise SystemExit(f"Unerwartete Health-Antwort ({response.status}): {payload!r}")
PY
}

certify_update() {
  local install_source="$1"
  shift
  # Declare install_dir before deriving paths from it. With `set -u` (as used
  # by both updater entry points), expansions in a single local declaration
  # happen before any of that declaration's assignments take effect.
  local install_dir=/opt/certify
  local active="$install_dir/venv"
  local candidate="$install_dir/venv.new" previous="$install_dir/venv.previous"
  local files_root="${CERTIFY_UPDATE_FILES_ROOT:-$install_source}"
  local expected_version attempt

  [[ ${EUID} -eq 0 ]] || { echo "Das Update muss als root ausgefuehrt werden." >&2; return 1; }
  [[ -x "$active/bin/certify" && -f /etc/certify/certify.conf ]] || {
    echo "Keine bestehende Certify-Installation gefunden. Bitte zuerst den Installer ausfuehren." >&2; return 1;
  }
  for command in python3 flock systemctl install; do
    command -v "$command" >/dev/null || { echo "${command} wurde nicht gefunden." >&2; return 1; }
  done

  exec 9>"$install_dir/update.lock"
  flock -n 9 || { echo "Ein anderes Certify-Update laeuft bereits." >&2; return 1; }

  echo "[2/6] Neue Version in einer separaten Umgebung vorbereiten ..."
  rm -rf "$candidate"
  python3 -m venv "$candidate"
  if ! "$candidate/bin/pip" install "$@" "$install_source"; then
    rm -rf "$candidate"
    echo "Update konnte nicht vorbereitet werden; die laufende Version blieb unveraendert." >&2
    return 1
  fi
  if ! expected_version="$("$candidate/bin/python" -c 'import certify; from importlib.metadata import version; from certify.api import create_app; from certify.cli import main; installed = version("certify-server"); assert certify.__version__ == installed; print(installed)')"; then
    rm -rf "$candidate"
    echo "Die neue Version hat den Selbsttest nicht bestanden; die laufende Version blieb unveraendert." >&2
    return 1
  fi

  echo "[3/6] Systemdateien installieren und Python-Umgebung umschalten ..."
  cp -a /etc/systemd/system/certify.service "$install_dir/certify.service.previous"
  cp -a /usr/local/sbin/certify-configure-tls "$install_dir/configure-tls.previous"
  install -m 0644 "$files_root/packaging/certify.service" /etc/systemd/system/certify.service
  install -m 0755 "$files_root/packaging/configure-tls.sh" /usr/local/sbin/certify-configure-tls
  install -m 0644 "$files_root/packaging/certify-update.service" /etc/systemd/system/certify-update.service
  install -m 0644 "$files_root/packaging/certify-update-check.service" /etc/systemd/system/certify-update-check.service
  install -m 0644 "$files_root/packaging/certify-update-check.timer" /etc/systemd/system/certify-update-check.timer
  local maintenance_data_dir
  maintenance_data_dir="$(sed -n 's/^CERTIFY_DATA_DIR=//p' /etc/certify/certify.conf | head -n1)"
  sed "s|@CERTIFY_DATA_DIR@|${maintenance_data_dir:-/var/lib/certify}|g" \
    "$files_root/packaging/certify-update.path" >/etc/systemd/system/certify-update.path
  chmod 0644 /etc/systemd/system/certify-update.path
  sed "s|@CERTIFY_DATA_DIR@|${maintenance_data_dir:-/var/lib/certify}|g" \
    "$files_root/packaging/certify-update-check.path" >/etc/systemd/system/certify-update-check.path
  chmod 0644 /etc/systemd/system/certify-update-check.path
  install -m 0755 "$files_root/packaging/web-update.sh" /usr/local/sbin/certify-web-update
  install -m 0755 "$files_root/packaging/check-update.sh" /usr/local/sbin/certify-update-check
  systemctl stop certify || true
  rm -rf "$previous"
  mv "$active" "$previous"
  mv "$candidate" "$active"

  echo "[4/6] systemd neu laden und Certify vollstaendig neu starten ..."
  systemctl daemon-reload
  systemctl enable --now certify-update.path certify-update-check.path certify-update-check.timer
  if ! systemctl restart certify; then
    attempt=0
  else
    attempt=1
  fi

  echo "[5/6] Dienststatus und laufende Version ${expected_version} pruefen ..."
  while (( attempt > 0 && attempt <= 30 )); do
    if systemctl is-active --quiet certify && certify_healthcheck "$active/bin/python" "$expected_version" >/dev/null 2>&1; then
      rm -f "$install_dir/certify.service.previous"
      rm -f "$install_dir/configure-tls.previous"
      echo "[6/6] Update auf Certify ${expected_version} erfolgreich abgeschlossen."
      echo "Die vorherige Python-Umgebung liegt unter ${previous}."
      return 0
    fi
    sleep 1
    ((attempt++))
  done

  echo "Die neue Version wurde nicht gesund gestartet. Vorherige Version wird wiederhergestellt." >&2
  systemctl stop certify || true
  rm -rf "$candidate"
  mv "$active" "$candidate"
  mv "$previous" "$active"
  mv "$install_dir/certify.service.previous" /etc/systemd/system/certify.service
  mv "$install_dir/configure-tls.previous" /usr/local/sbin/certify-configure-tls
  systemctl daemon-reload
  systemctl restart certify || true
  rm -rf "$candidate"
  return 1
}
