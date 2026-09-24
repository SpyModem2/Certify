#!/usr/bin/env bash
# Transactional update helpers shared by the online and offline updater.

certify_update() {
  local install_source="$1"
  shift
  local install_dir=/opt/certify
  local active="$install_dir/venv"
  local candidate="$install_dir/venv.new"
  local previous="$install_dir/venv.previous"
  local was_active=false

  [[ ${EUID} -eq 0 ]] || { echo "Das Update muss als root ausgefuehrt werden." >&2; return 1; }
  [[ -x "$active/bin/certify" && -f /etc/certify/certify.conf ]] || {
    echo "Keine bestehende Certify-Installation gefunden. Bitte zuerst den Installer ausfuehren." >&2
    return 1
  }
  command -v python3 >/dev/null || { echo "python3 wurde nicht gefunden." >&2; return 1; }

  # Do not allow two administrators or automation jobs to update concurrently.
  exec 9>"$install_dir/update.lock"
  flock -n 9 || { echo "Ein anderes Certify-Update laeuft bereits." >&2; return 1; }

  echo "[1/4] Neue Version in einer separaten Umgebung vorbereiten ..."
  rm -rf "$candidate"
  python3 -m venv "$candidate"
  if ! "$candidate/bin/pip" install "$@" "$install_source"; then
    rm -rf "$candidate"
    echo "Update konnte nicht vorbereitet werden; die laufende Version blieb unveraendert." >&2
    return 1
  fi
  if ! "$candidate/bin/python" -c 'import certify; from certify.api import create_app; from certify.cli import main' >/dev/null; then
    rm -rf "$candidate"
    echo "Die neue Version hat den Selbsttest nicht bestanden; die laufende Version blieb unveraendert." >&2
    return 1
  fi

  echo "[2/4] Dienst kurz anhalten und Version umschalten ..."
  if systemctl is-active --quiet certify; then
    was_active=true
    systemctl stop certify
  fi
  rm -rf "$previous"
  mv "$active" "$previous"
  mv "$candidate" "$active"

  echo "[3/4] Certify starten und Installation pruefen ..."
  systemctl daemon-reload
  if [[ "$was_active" == true ]]; then
    if ! systemctl restart certify || ! systemctl is-active --quiet certify; then
      echo "Die neue Version startet nicht. Vorherige Version wird wiederhergestellt." >&2
      rm -rf "$candidate"
      mv "$active" "$candidate"
      mv "$previous" "$active"
      systemctl restart certify || true
      rm -rf "$candidate"
      return 1
    fi
  fi

  echo "[4/4] Update abgeschlossen. Die vorherige Version liegt unter ${previous}."
  echo "Konfiguration, TLS-Schluessel und Daten wurden nicht veraendert."
}
