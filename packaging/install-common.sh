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

install_packages() {
  command -v dnf >/dev/null 2>&1 || {
    echo "Erforderliche RHEL-Pakete koennen nicht installiert werden: dnf wurde nicht gefunden." >&2
    return 1
  }
  echo "Installiere erforderliche RHEL-Pakete: $*"
  dnf install -y "$@"
}

install_required_packages() {
  # Install explicitly instead of assuming a particular RHEL base image. dnf is
  # idempotent and leaves already installed packages untouched.
  install_packages \
    python3 python3-pip openssl ca-certificates \
    coreutils grep sed hostname \
    shadow-utils util-linux systemd policycoreutils

  local command
  for command in python3 openssl install useradd runuser systemctl restorecon; do
    command -v "$command" >/dev/null 2>&1 || {
      echo "Erforderliches Programm fehlt nach der Paketinstallation: ${command}" >&2
      return 1
    }
  done

  python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 12))' || {
    echo "Certify benoetigt Python 3.12 oder neuer." >&2
    return 1
  }
}

configure_firewall() {
  local tls_mode="$1"
  local -a services=(https)

  if ! command -v firewall-cmd >/dev/null 2>&1; then
    echo "firewall-cmd ist nicht installiert; keine Firewall-Regel wurde geaendert."
    return
  fi
  if ! firewall-cmd --state >/dev/null 2>&1; then
    echo "firewalld ist nicht aktiv; keine Firewall-Regel wurde geaendert."
    return
  fi

  # The standalone Let's Encrypt authenticator also needs HTTP for initial
  # issuance and all later renewals.
  if [[ "$tls_mode" == "letsencrypt" ]]; then
    services+=(http)
  fi
  local service
  for service in "${services[@]}"; do
    firewall-cmd --permanent --add-service="$service"
    firewall-cmd --add-service="$service"
  done
  echo "firewalld wurde fuer folgende Dienste freigeschaltet: ${services[*]}"
}

configure_selinux() {
  local state
  if ! command -v getenforce >/dev/null 2>&1; then
    echo "SELinux-Werkzeuge wurden nicht gefunden; keine Dateikontexte wurden angepasst."
    return
  fi
  state="$(getenforce)"
  if [[ "$state" == "Disabled" ]]; then
    echo "SELinux ist deaktiviert; keine Dateikontexte wurden angepasst."
    return
  fi
  if ! command -v restorecon >/dev/null 2>&1; then
    install_packages policycoreutils || return 1
    command -v restorecon >/dev/null 2>&1 || {
      echo "restorecon fehlt auch nach der Installation von policycoreutils." >&2
      return 1
    }
  fi

  # Re-apply the distribution policy after creating files below /etc, /opt and
  # /var. Port 443 is part of the RHEL http_port_t policy and therefore needs
  # no local, difficult-to-maintain SELinux port override.
  restorecon -RF /etc/certify /opt/certify /var/lib/certify \
    /etc/systemd/system/certify.service /usr/local/sbin/certify-configure-tls
  echo "SELinux-Dateikontexte fuer Certify wurden wiederhergestellt (${state})."
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

configure_tls() {
  local root="$1" mode host cert key chain domain email
  install -m 0750 "$root/packaging/configure-tls.sh" /usr/local/sbin/certify-configure-tls

  if [[ "${CERTIFY_NON_INTERACTIVE:-false}" == "true" || ! -t 0 ]]; then
    mode="${CERTIFY_TLS_MODE:-self-signed}"
  else
    echo
    echo "=== HTTPS/TLS einrichten ==="
    echo "1: Self-Signed (sofort nutzbar), 2: eigenes Zertifikat, 3: Let's Encrypt"
    ask mode "Welche TLS-Quelle soll verwendet werden?" "1"
    case "$mode" in 1) mode=self-signed;; 2) mode=custom;; 3) mode=letsencrypt;; esac
  fi

  case "$mode" in
    self-signed)
      host="${CERTIFY_TLS_HOSTNAME:-${CERTIFY_TRUSTED_HOSTS:-}}"
      host="${host%%,*}"
      if [[ -z "$host" ]]; then
        host="$(sed -n 's/^CERTIFY_TRUSTED_HOSTS=//p' /etc/certify/certify.conf | cut -d, -f1)"
      fi
      host="${host:-$(hostname -f 2>/dev/null || hostname)}"
      if [[ "${CERTIFY_NON_INTERACTIVE:-false}" != "true" && -t 0 ]]; then
        ask_config_value host "Fuer welchen DNS-Namen/IP soll das Self-Signed-Zertifikat gelten?" "$host"
      fi
      /usr/local/sbin/certify-configure-tls self-signed "$host"
      ;;
    custom)
      cert="${CERTIFY_TLS_CERT_FILE:-}"; key="${CERTIFY_TLS_KEY_FILE:-}"; chain="${CERTIFY_TLS_CHAIN_FILE:-}"
      if [[ "${CERTIFY_NON_INTERACTIVE:-false}" != "true" && -t 0 ]]; then
        ask cert "Pfad zum PEM-Serverzertifikat:" "$cert"
        ask key "Pfad zum PEM-Private-Key:" "$key"
        ask chain "Pfad zur PEM-Zertifikatskette (optional):" "$chain"
      fi
      [[ -n "$cert" && -n "$key" ]] || { echo "CERTIFY_TLS_CERT_FILE und CERTIFY_TLS_KEY_FILE sind erforderlich." >&2; return 1; }
      if [[ -n "$chain" ]]; then /usr/local/sbin/certify-configure-tls custom "$cert" "$key" "$chain"; else /usr/local/sbin/certify-configure-tls custom "$cert" "$key"; fi
      ;;
    letsencrypt)
      domain="${CERTIFY_TLS_DOMAIN:-}"; email="${CERTIFY_TLS_EMAIL:-}"
      if [[ "${CERTIFY_NON_INTERACTIVE:-false}" != "true" && -t 0 ]]; then
        ask_config_value domain "Oeffentlich erreichbarer DNS-Name fuer Let's Encrypt:" "$domain"
        ask_config_value email "E-Mail-Adresse fuer Ablauf- und Kontohinweise (oder -):" "$email"
      fi
      [[ -n "$domain" && -n "$email" ]] || { echo "CERTIFY_TLS_DOMAIN und CERTIFY_TLS_EMAIL sind erforderlich." >&2; return 1; }
      if ! command -v certbot >/dev/null 2>&1; then
        install_packages certbot
      fi
      command -v certbot >/dev/null 2>&1 || { echo "certbot fehlt nach der Paketinstallation." >&2; return 1; }
      /usr/local/sbin/certify-configure-tls letsencrypt "$domain" "$email"
      ;;
    *) echo "Unbekannter CERTIFY_TLS_MODE: $mode" >&2; return 1 ;;
  esac

  CERTIFY_SELECTED_TLS_MODE="$mode"
}

finish_install() {
  local root="$1"
  configure_certify
  configure_tls "$root"
  install -m 0644 "$root/packaging/certify.service" /etc/systemd/system/certify.service
  configure_firewall "$CERTIFY_SELECTED_TLS_MODE"
  configure_selinux
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
      echo "Certify wurde gestartet. HTTPS ist auf Port 443 erreichbar."
    else
      echo "Spaeter starten mit: systemctl enable --now certify"
    fi
  else
    echo "Administratorkonto anlegen: set -a; source /etc/certify/certify.conf; sudo -E -u certify /opt/certify/venv/bin/certify init-admin admin"
    echo "Danach starten: systemctl enable --now certify"
  fi
}
