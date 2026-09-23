#!/usr/bin/env bash
# Gemeinsamer, interaktiver Konfigurationsdialog fuer Online- und Offline-Installation.

ask() {
  local variable="$1" prompt="$2" default="$3" answer
  printf '\n%s\n' "$prompt"
  read -r -p "Wert [${default}]: " answer
  printf -v "$variable" '%s' "${answer:-$default}"
}

ask_config_value() {
  local variable="$1" prompt="$2" default="$3" value
  while true; do
    ask value "$prompt" "$default"
    if [[ "$value" =~ ^[a-zA-Z0-9._,@:/+-]+$ ]]; then
      printf -v "$variable" '%s' "$value"
      return
    fi
    echo "Bitte keine Leerzeichen, Anfuehrungszeichen oder Sonderzeichen verwenden."
  done
}

ask_yes_no() {
  local prompt="$1" default="$2" answer
  read -r -p "${prompt} [${default}]: " answer
  answer="${answer:-$default}"
  [[ "$answer" =~ ^([jJ]|[jJ][aA]|[yY]|[yY][eE][sS])$ ]]
}

configure_certify() {
  local config_file=/etc/certify/certify.conf
  if [[ -e "$config_file" ]]; then
    echo "Vorhandene Konfiguration wird beibehalten: ${config_file}"
    return
  fi

  if [[ "${CERTIFY_NON_INTERACTIVE:-false}" == "true" || ! -t 0 ]]; then
    local secret
    secret="${CERTIFY_SECRET:-$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')}"
    cat >"$config_file" <<EOF
CERTIFY_DATA_DIR=${CERTIFY_DATA_DIR:-/var/lib/certify}
CERTIFY_SECRET=${secret}
CERTIFY_SESSION_MINUTES=${CERTIFY_SESSION_MINUTES:-30}
CERTIFY_TRUSTED_HOSTS=${CERTIFY_TRUSTED_HOSTS:-localhost,127.0.0.1}
CERTIFY_DEBUG=false
CERTIFY_SMTP_HOST=${CERTIFY_SMTP_HOST:-localhost}
CERTIFY_SMTP_PORT=${CERTIFY_SMTP_PORT:-25}
CERTIFY_MAIL_FROM=${CERTIFY_MAIL_FROM:-certify@localhost}
EOF
    chmod 0640 "$config_file"
    chown root:certify "$config_file"
    echo "Konfiguration wurde aus CERTIFY_*-Variablen erstellt: ${config_file}"
    return
  fi

  echo
  echo "=== Certify einrichten ==="
  echo "Die folgenden Fragen legen fest, wie Benutzer Certify erreichen und"
  echo "wie das System E-Mails versendet. Vorgaben koennen mit Enter uebernommen werden."
  local trusted_hosts session_minutes smtp_host smtp_port mail_from secret
  ask_config_value trusted_hosts \
    "Unter welchen DNS-Namen wird Certify im Browser aufgerufen? Mehrere Namen mit Komma trennen (keine https://-Adresse)." \
    "$(hostname -f 2>/dev/null || hostname),localhost,127.0.0.1"
  ask session_minutes \
    "Nach wie vielen Minuten ohne erneute Anmeldung soll eine Sitzung ablaufen?" "30"
  while [[ ! "$session_minutes" =~ ^[1-9][0-9]*$ ]]; do
    echo "Bitte eine ganze Zahl groesser als 0 eingeben."
    ask session_minutes "Sitzungsdauer in Minuten:" "30"
  done
  ask_config_value smtp_host \
    "Wie lautet der DNS-Name des SMTP-Servers fuer Benachrichtigungen? 'localhost' nutzt einen lokalen Mail-Relay." \
    "localhost"
  ask smtp_port "Auf welchem TCP-Port nimmt der SMTP-Server Verbindungen an?" "25"
  while [[ ! "$smtp_port" =~ ^[0-9]+$ ]] || (( smtp_port < 1 || smtp_port > 65535 )); do
    echo "Bitte eine Portnummer zwischen 1 und 65535 eingeben."
    ask smtp_port "SMTP-Port:" "25"
  done
  ask_config_value mail_from "Welche Absenderadresse sollen Certify-E-Mails tragen?" "certify@localhost"
  secret="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"

  cat >"$config_file" <<EOF
CERTIFY_DATA_DIR=/var/lib/certify
CERTIFY_SECRET=${secret}
CERTIFY_SESSION_MINUTES=${session_minutes}
CERTIFY_TRUSTED_HOSTS=${trusted_hosts}
CERTIFY_DEBUG=false
CERTIFY_SMTP_HOST=${smtp_host}
CERTIFY_SMTP_PORT=${smtp_port}
CERTIFY_MAIL_FROM=${mail_from}
EOF
  chmod 0640 "$config_file"
  chown root:certify "$config_file"
  echo
  echo "Konfiguration gespeichert: ${config_file}"
}

finish_install() {
  local root="$1"
  configure_certify
  install -m 0644 "$root/packaging/certify.service" /etc/systemd/system/certify.service
  systemctl daemon-reload

  if [[ "${CERTIFY_NON_INTERACTIVE:-false}" != "true" && -t 0 ]]; then
    echo
    echo "=== Erstes Administratorkonto ==="
    echo "Dieses Konto verwaltet spaeter Benutzer, Systeme und Zertifikate."
    local admin_name
    local -a certify_environment
    ask_config_value admin_name "Wie soll der Anmeldename des ersten Administrators lauten?" "admin"
    mapfile -t certify_environment < <(grep '^CERTIFY_' /etc/certify/certify.conf)
    runuser -u certify -- env "${certify_environment[@]}" \
      /opt/certify/venv/bin/certify init-admin "$admin_name"
    if ask_yes_no "Soll Certify jetzt gestartet und bei jedem Systemstart aktiviert werden?" "ja"; then
      systemctl enable --now certify
      echo "Certify wurde gestartet."
    else
      echo "Spaeter starten mit: systemctl enable --now certify"
    fi
  else
    echo "Administratorkonto anlegen: set -a; source /etc/certify/certify.conf; sudo -E -u certify /opt/certify/venv/bin/certify init-admin admin"
    echo "Danach starten: systemctl enable --now certify"
  fi
}
