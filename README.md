# Certify

Certify ist eine selbst betriebene Zertifikatsverwaltung für RHEL-basierte
Systeme. Das Projekt bündelt ACME-Aufträge, personalisierte Konten,
optionale TOTP-MFA, die Verteilung von Zertifikaten und eine
manipulationserkennbare Audit-Kette in einer zweisprachigen Webanwendung.

> **Projektstatus:** Die erste Version ist ein sicherheitsorientiertes,
> lauffähiges Fundament. ACME- und Zielsystem-Adapter besitzen bewusst klare
> Schnittstellen; produktive Provider werden schrittweise ergänzt und müssen
> vor ihrem Einsatz integrativ geprüft werden.

## Funktionen

- lokale Benutzerkonten mit `scrypt`-Passworthashes, verbindlicher Kennwortkomplexität,
  Sperre der letzten 20 Kennwörter und optionaler TOTP-MFA
- persönliche, widerrufbare API-Keys, die niemals mehr Rechte als ihr Benutzer haben
  und auf reinen Lesezugriff eingeschränkt werden können
- Rollen `admin`, `operator` und `auditor`
- HTTP-01- und DNS-01-Provider-Schnittstellen inklusive Custom-DNS-Webhook
- Zertifikatsinventar für verwaltete Schlüssel und externe CSR
- Zieladapter für Linux/SSH, IIS/PowerShell-over-SSH und FortiGate 7.4
- benutzerbezogene Zertifikatszuweisung, CSR-Upload und verschlüsselte lokale Schlüssel
- Systeminventar und explizite Zertifikat-System-Zuordnung; Zugangsdaten werden AEAD-verschlüsselt
- wählbare E-Mail-Benachrichtigungsstufen über einen lokalen SMTP-Relay
- append-only Audit-Log mit HMAC-verketteten Einträgen und Verifikation
- Deutsch und Englisch über den `Accept-Language`-Header
- SQLite im Einzelknotenbetrieb; keine Redis-, Celery- oder Docker-Abhängigkeit
- systemd-Unit und Offline-Wheelhouse-Installationsskript für RHEL 10

Details zu Architektur, Sicherheitsgrenzen und Erweiterungspunkten stehen in
[`docs/architecture.md`](docs/architecture.md).

## Schnellstart für die Entwicklung

Python 3.12 oder neuer wird vorausgesetzt.

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
export CERTIFY_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
certify init-admin admin
certify serve --host 127.0.0.1 --port 8080
```

Beim Anlegen des Administrators wird das initiale Passwort interaktiv
abgefragt. Das Webfrontend ist anschließend unter `http://127.0.0.1:8080/`
erreichbar; die API-Dokumentation liegt unter `http://127.0.0.1:8080/docs`.

## Webfrontend

Die responsive Weboberfläche bildet die vorhandenen Arbeitsabläufe
rollenabhängig ab: Dashboard, Zertifikate und CSR-/Schlüsselaktionen,
Zielsysteme, Benutzer, persönliche API-Keys, Benachrichtigungen,
Audit-Verifikation und Kontosicherheit. Sie wird ohne externes CDN direkt vom
Certify-Dienst ausgeliefert und benötigt keinen separaten Frontend-Build. Neue
Funktionsbereiche können über die zentrale Seitenregistrierung in
`src/certify/web/assets/app.js` ergänzt werden.

## Kennwort- und API-Key-Sicherheit

Kennwörter müssen mindestens 14 Zeichen sowie Groß- und Kleinbuchstaben, eine
Ziffer und ein Sonderzeichen enthalten. Beim Ändern eines Kennworts dürfen die
letzten 20 Kennwörter nicht erneut verwendet werden. Die API beschreibt diese
Regel ebenfalls direkt an allen Kennwortfeldern.

Angemeldete Benutzer erstellen persönliche Schlüssel über `POST /api/v1/api-keys`
mit `scope: "read"` (nur lesende Requests) oder `scope: "read_write"`. Ein Key
übernimmt immer Rolle und Objektzuweisungen seines Benutzers und kann diese nie
erweitern. Das Schlüsselgeheimnis wird nur einmal ausgegeben; serverseitig liegt
nur ein mit dem Systemgeheimnis gebildeter HMAC. `GET /api/v1/api-keys` listet
Metadaten, `DELETE /api/v1/api-keys/{id}` widerruft einen Key sofort. Der Key wird
wie eine Sitzung als `Authorization: Bearer certify_…` gesendet. Aus
Sicherheitsgründen können API-Keys keine weiteren Keys erzeugen.

## Konfiguration

| Variable | Bedeutung | Vorgabe |
|---|---|---|
| `CERTIFY_DATA_DIR` | Datenbank- und Zustandsverzeichnis | `/var/lib/certify` |
| `CERTIFY_SECRET` | Schlüssel für Sitzungen und Audit-HMAC | keine sichere Vorgabe |
| `CERTIFY_SESSION_MINUTES` | Sitzungsdauer | `30` |
| `CERTIFY_TRUSTED_HOSTS` | kommaseparierte Hostnamen | `localhost,127.0.0.1` |
| `CERTIFY_DEBUG` | Entwicklungsmodus | `false` |
| `CERTIFY_SMTP_HOST` / `CERTIFY_SMTP_PORT` | lokaler SMTP-Relay | `localhost` / `25` |
| `CERTIFY_MAIL_FROM` | Absenderadresse | `certify@localhost` |

Ohne explizites `CERTIFY_SECRET` startet der Server nicht. Geheimnisse gehören
in eine root-lesbare Environment-Datei, nicht in die Kommandozeile oder ins
Repository.

## Offline-Installation

Auf einem verbundenen Build-System:

```bash
./packaging/build-wheelhouse.sh
```

Das erzeugte Projektverzeichnis samt `dist/` und `wheelhouse/` auf den
Zielserver übertragen und dort als `root` ausführen:

```bash
./packaging/install-offline.sh
```

Das Installationsprogramm führt anschließend Schritt für Schritt durch die
Konfiguration. Es erklärt jede benötigte Angabe (Browser-DNS-Namen,
Sitzungsdauer, Mailserver und Administratorkonto), erzeugt das Systemgeheimnis
automatisch und kann den Dienst direkt starten. Für automatisierte Installationen
kann `CERTIFY_NON_INTERACTIVE=true` zusammen mit den in der Tabelle genannten
`CERTIFY_*`-Variablen gesetzt werden.

Container werden weder benötigt noch unterstützt.

## Online-Installation

Wenn der Zielserver PyPI erreichen kann, installiert das Online-Skript die über
`CERTIFY_VERSION` auswählbare veröffentlichte Version samt Abhängigkeiten:

```bash
sudo CERTIFY_VERSION=0.1.0 ./packaging/install-online.sh
```

## Zertifikate mehreren Systemen zuweisen

Beim Anlegen eines Zertifikats kann `target_ids` eine Liste aller Zielsysteme
enthalten. Vorhandene Zuordnungen lassen sich atomar ersetzen; dies ist
insbesondere für Wildcard-Zertifikate gedacht:

```http
PUT /api/v1/certificates/42/targets
Content-Type: application/json

{"target_ids": [3, 7, 11]}
```

Die Zertifikatsliste liefert die zugeordneten Systeme im Feld `targets` zurück.

## Tests

```bash
python -m pytest
python -m compileall -q src tests
```

## Lizenz

Apache-2.0, siehe [`LICENSE`](LICENSE).
