#!/usr/bin/env bash
set -euo pipefail

# All certificate sources end up at these stable paths so the service unit does
# not need to know whether a certificate is local, imported, or ACME-managed.
TLS_DIR="${CERTIFY_TLS_DIR:-/etc/certify/tls}"
CERT_FILE="$TLS_DIR/fullchain.pem"
KEY_FILE="$TLS_DIR/privkey.pem"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
CERTBOT_BIN="${CERTBOT_BIN:-certbot}"
SYSTEMCTL_BIN="${SYSTEMCTL_BIN:-systemctl}"
TLS_OWNER="${CERTIFY_TLS_OWNER:-root:certify}"

usage() {
  cat >&2 <<'EOF'
Usage:
  certify-configure-tls self-signed HOSTNAME [DAYS]
  certify-configure-tls custom CERTIFICATE PRIVATE_KEY [CHAIN]
  certify-configure-tls letsencrypt DOMAIN EMAIL
  certify-configure-tls sync-letsencrypt DOMAIN

Custom files must be PEM encoded. CHAIN is appended to the leaf certificate.
Let's Encrypt uses standalone HTTP-01, so port 80 must be publicly reachable.
EOF
  exit 2
}

if [[ ${EUID} -ne 0 && "${CERTIFY_TLS_ALLOW_UNPRIVILEGED:-false}" != "true" ]]; then
  echo "Dieses Kommando muss als root ausgefuehrt werden." >&2
  exit 1
fi

prepare_directory() {
  install -d -m 0750 "$TLS_DIR"
  if [[ ${EUID} -eq 0 ]]; then chown "$TLS_OWNER" "$TLS_DIR"; fi
}

validate_pair() {
  local cert="$1" key="$2" cert_pub key_pub
  "$OPENSSL_BIN" x509 -in "$cert" -noout -checkend 0 >/dev/null
  "$OPENSSL_BIN" pkey -in "$key" -noout -check >/dev/null
  cert_pub="$($OPENSSL_BIN x509 -in "$cert" -pubkey -noout | $OPENSSL_BIN pkey -pubin -outform DER 2>/dev/null | $OPENSSL_BIN dgst -sha256)"
  key_pub="$($OPENSSL_BIN pkey -in "$key" -pubout -outform DER 2>/dev/null | $OPENSSL_BIN dgst -sha256)"
  [[ "$cert_pub" == "$key_pub" ]] || { echo "Zertifikat und privater Schluessel passen nicht zusammen." >&2; return 1; }
}

activate_pair() {
  local cert="$1" key="$2" staged_cert staged_key
  prepare_directory
  staged_cert="$(mktemp "$TLS_DIR/.fullchain.XXXXXX")"
  staged_key="$(mktemp "$TLS_DIR/.privkey.XXXXXX")"
  trap 'rm -f "${staged_cert:-}" "${staged_key:-}"' RETURN
  install -m 0644 "$cert" "$staged_cert"
  install -m 0640 "$key" "$staged_key"
  if [[ ${EUID} -eq 0 ]]; then chown "$TLS_OWNER" "$staged_cert" "$staged_key"; fi
  mv -f "$staged_cert" "$CERT_FILE"
  mv -f "$staged_key" "$KEY_FILE"
  trap - RETURN
}

reload_if_running() {
  if "$SYSTEMCTL_BIN" is-active --quiet certify.service 2>/dev/null; then
    "$SYSTEMCTL_BIN" restart certify.service
  fi
}

mode="${1:-}"
case "$mode" in
  self-signed)
    [[ $# -ge 2 && $# -le 3 ]] || usage
    host="$2"; days="${3:-825}"
    [[ "$days" =~ ^[1-9][0-9]*$ ]] || { echo "DAYS muss eine positive Zahl sein." >&2; exit 2; }
    prepare_directory
    tmp_cert="$(mktemp "$TLS_DIR/.selfsigned-cert.XXXXXX")"
    tmp_key="$(mktemp "$TLS_DIR/.selfsigned-key.XXXXXX")"
    trap 'rm -f "$tmp_cert" "$tmp_key"' EXIT
    if [[ "$host" =~ ^[0-9a-fA-F:.]+$ ]]; then san="IP:$host"; else san="DNS:$host"; fi
    "$OPENSSL_BIN" req -x509 -newkey rsa:3072 -sha256 -nodes -days "$days" \
      -subj "/CN=$host" -addext "subjectAltName=$san" -addext "basicConstraints=critical,CA:FALSE" \
      -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
      -addext "extendedKeyUsage=serverAuth" -keyout "$tmp_key" -out "$tmp_cert"
    validate_pair "$tmp_cert" "$tmp_key"
    activate_pair "$tmp_cert" "$tmp_key"
    echo "Self-Signed-Zertifikat fuer $host wurde unter $TLS_DIR installiert."
    ;;
  custom)
    [[ $# -ge 3 && $# -le 4 ]] || usage
    cert="$2"; key="$3"; chain="${4:-}"
    [[ -r "$cert" && -r "$key" ]] || { echo "Zertifikat oder Schluessel ist nicht lesbar." >&2; exit 1; }
    validate_pair "$cert" "$key"
    combined="$(mktemp)"; trap 'rm -f "$combined"' EXIT
    cat "$cert" >"$combined"
    if [[ -n "$chain" ]]; then [[ -r "$chain" ]] || { echo "Zertifikatskette ist nicht lesbar." >&2; exit 1; }; cat "$chain" >>"$combined"; fi
    activate_pair "$combined" "$key"
    echo "Eigenes Zertifikat wurde unter $TLS_DIR installiert."
    ;;
  letsencrypt)
    [[ $# -eq 3 ]] || usage
    domain="$2"; email="$3"
    command=("$CERTBOT_BIN" certonly --standalone --non-interactive --agree-tos --domain "$domain")
    if [[ "$email" == "-" ]]; then command+=(--register-unsafely-without-email); else command+=(--email "$email"); fi
    "${command[@]}"
    "$0" sync-letsencrypt "$domain"
    hook_dir="${CERTIFY_LETSENCRYPT_HOOK_DIR:-/etc/letsencrypt/renewal-hooks/deploy}"
    install -d -m 0755 "$hook_dir"
    printf '#!/usr/bin/env bash\nexec %q sync-letsencrypt %q\n' "$0" "$domain" >"$hook_dir/certify-tls"
    chmod 0755 "$hook_dir/certify-tls"
    echo "Let's-Encrypt-Zertifikat installiert; certbot renew aktualisiert Certify automatisch."
    exit 0
    ;;
  sync-letsencrypt)
    [[ $# -eq 2 ]] || usage
    live_dir="${CERTIFY_LETSENCRYPT_LIVE_DIR:-/etc/letsencrypt/live}/$2"
    validate_pair "$live_dir/fullchain.pem" "$live_dir/privkey.pem"
    activate_pair "$live_dir/fullchain.pem" "$live_dir/privkey.pem"
    ;;
  *) usage ;;
esac

reload_if_running
