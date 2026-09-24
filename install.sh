#!/usr/bin/env bash
# Bootstrap fuer die Online-Erstinstallation direkt aus dem Git-Repository.
set -euo pipefail

repository_url="${CERTIFY_REPOSITORY_URL:-https://github.com/SpyModem2/Certify.git}"
revision="${1:-${CERTIFY_GIT_REF:-main}}"
checkout=""

if [[ ${EUID} -ne 0 ]]; then
  echo "Die Installation muss als root ausgefuehrt werden (z. B. mit 'curl ... | sudo bash')." >&2
  exit 1
fi

command -v dnf >/dev/null 2>&1 || {
  echo "dnf wurde nicht gefunden. Dieser Installer ist fuer RHEL-basierte Systeme vorgesehen." >&2
  exit 1
}

# Bei einem Pipe-Aufruf gehoert stdin zunaechst curl. Fuer den anschliessenden
# Konfigurationsdialog verbinden wir ihn wieder mit dem aufrufenden Terminal.
if [[ -t 1 && -r /dev/tty ]]; then
  exec </dev/tty
fi

echo "Installiere die zum Abrufen von Certify benoetigten Systempakete ..."
dnf install -y git ca-certificates

git check-ref-format --branch "$revision" >/dev/null 2>&1 || {
  echo "Ungueltige Git-Revision: ${revision}" >&2
  exit 1
}

checkout="$(mktemp -d /tmp/certify-install.XXXXXXXX)"
cleanup() {
  [[ -z "$checkout" ]] || rm -rf -- "$checkout"
}
trap cleanup EXIT

echo "Lade Certify (${revision}) aus ${repository_url} ..."
git clone --quiet --depth 1 --branch "$revision" -- "$repository_url" "$checkout"

echo "Starte die interaktive Certify-Installation ..."
"$checkout/packaging/install-online.sh"
