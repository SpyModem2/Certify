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
  Sperre der letzten 20 Kennwörter und optionaler TOTP-MFA per QR-Code
- Pflege des eigenen Namens und der E-Mail-Adresse sowie administrative Bearbeitung
  von Namen, E-Mail-Adresse, Rolle, Kontostatus und TOTP-Einstellungen
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

## Einzeilige Online-Installation

Auf einem frisch bereitgestellten RHEL-10-System startet dieser Befehl die
vollständige interaktive Installation (Root-Rechte, `dnf`, erreichbare
Paketquellen und Internetzugang werden vorausgesetzt):

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/SpyModem2/Certify/main/install.sh)"
```

Der Befehl lädt den Bootstrap-Installer vom Branch `main`. Hinweise zur Prüfung
des Skripts, zur Installation eines anderen Branches oder Tags sowie zur
Offline-Installation stehen unter [Installation auf RHEL 10](#installation-auf-rhel-10).

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
Dieser HTTP-Aufruf ist nur fuer die lokale Entwicklung gedacht; die
Systeminstallation aktiviert immer HTTPS.

## Webfrontend

Die responsive Weboberfläche bildet die vorhandenen Arbeitsabläufe
rollenabhängig ab: Dashboard, Zertifikate und CSR-/Schlüsselaktionen,
Zielsysteme, Benutzer, persönliche API-Keys, Benachrichtigungen,
Audit-Verifikation und Kontosicherheit. Sie wird ohne externes CDN direkt vom
Certify-Dienst ausgeliefert und benötigt keinen separaten Frontend-Build. Neue
Funktionsbereiche können über die zentrale Seitenregistrierung in
`src/certify/web/assets/app.js` ergänzt werden.

Benutzer können ihren Vor- und Nachnamen sowie ihre E-Mail-Adresse unter
„Konto & Sicherheit“ selbst pflegen. Administratoren können in der
Benutzerverwaltung Namen, E-Mail-Adresse, Rolle und Kontostatus bearbeiten und
eine bestehende TOTP-Konfiguration entfernen. Bei der TOTP-Einrichtung wird ein
QR-Code für Authenticator-Apps angezeigt; erst die erfolgreiche Bestätigung mit
einem sechsstelligen Code aktiviert TOTP. Ein abgebrochener Einrichtungsversuch
verwirft das noch unbestätigte TOTP-Geheimnis.

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
| `CERTIFY_PASSWORD_MAX_AGE_DAYS` | Optionale maximale Kennwortgültigkeit in Tagen; leer = deaktiviert | leer |
| `CERTIFY_TRUSTED_HOSTS` | kommaseparierte Hostnamen | `localhost,127.0.0.1` |
| `CERTIFY_DEBUG` | Entwicklungsmodus | `false` |
| `CERTIFY_SMTP_HOST` / `CERTIFY_SMTP_PORT` | lokaler SMTP-Relay | `localhost` / `25` |
| `CERTIFY_MAIL_FROM` | Absenderadresse | `certify@localhost` |

## Installation auf RHEL 10

Die Installationsskripte sind für eine direkte systemd-Installation auf RHEL 10
vorgesehen; Container werden weder benötigt noch unterstützt. Online- und
Offline-Installation erzeugen dieselbe Verzeichnisstruktur und verwenden
denselben Konfigurationsdialog.

### Voraussetzungen und Installationsvarianten

Auf dem **Zielserver** werden Root-Rechte und der RHEL-Paketmanager `dnf`
benötigt. Python 3.12, `pip`, OpenSSL und alle weiteren Laufzeitwerkzeuge
installiert das Skript selbst. Abhängig von der gewählten Konfiguration kommen
folgende Voraussetzungen hinzu:

- **Online:** Der Zielserver kann die Python-Abhängigkeiten aus dem Internet
  laden. Certify selbst wird immer aus dem lokalen Projektverzeichnis installiert.
- **Offline:** Ein separates Build-System mit Internetzugang, Python und `pip`
  erstellt vorab alle Wheels. Es sollte dieselbe RHEL-Version, CPU-Architektur
  und Python-Version wie der Zielserver verwenden, damit binäre Wheels
  kompatibel sind.
- **Let's Encrypt:** Der öffentliche DNS-Name zeigt auf den Zielserver, TCP-Port
  80 ist aus dem Internet erreichbar. Die Installation installiert `certbot`
  bei Bedarf; Certbot verwendet den Standalone-HTTP-01-Authenticator.
- **RHEL-Paketquellen:** `dnf` muss auf dem Zielserver auf erreichbare oder lokal
  eingebundene Paketquellen zugreifen können. Das gilt auch bei der
  Offline-Installation, wenn erforderliche RPM-Pakete noch fehlen.

### Online-Installation

#### Installation mit dem Ein-Zeilen-Befehl

Auf einem frisch bereitgestellten RHEL-10-Zielserver kann die vollständige
Online-Erstinstallation direkt aus diesem Repository gestartet werden:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/SpyModem2/Certify/main/install.sh)"
```

Der Bootstrap-Installer installiert Git und CA-Zertifikate, lädt den Branch
`main` in ein temporäres Verzeichnis und startet anschließend den vorhandenen
interaktiven Online-Installer. Das temporäre Checkout wird am Ende wieder
entfernt. Der Konfigurationsdialog bleibt auch beim Aufruf über die Pipe mit
dem Terminal verbunden.

Soll gezielt ein anderer Branch oder ein Release-Tag installiert werden, kann
dessen Name als Argument angegeben werden (nur vertrauenswürdige Refs
verwenden):

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/SpyModem2/Certify/main/install.sh)" -- <BRANCH-ODER-TAG>
```

Vor dem Ausführen eines aus dem Internet geladenen Skripts empfiehlt es sich,
den Inhalt unter der angegebenen URL zu prüfen. Voraussetzungen sind
Root-Rechte, `dnf`, erreichbare RHEL-Paketquellen sowie Internetzugriff auf
GitHub und die Python-Paketquellen.

#### Erste Installation aus dem Git-Repository

Die folgenden Schritte sind auf dem RHEL-10-Zielserver auszuführen. Befehle mit
`sudo` benötigen ein Konto mit Administratorrechten. Das Repository sollte als
normaler Benutzer ausgecheckt werden; nur das Installationsskript läuft als
`root`.

1. System aktualisieren und Git installieren:

   ```bash
   sudo dnf upgrade -y
   sudo dnf install -y git
   ```

2. Repository klonen und in das Projektverzeichnis wechseln:

   ```bash
   git clone https://github.com/SpyModem2/Certify.git
   cd Certify
   ```

   Wurde das Repository bereits geklont oder als vorbereitete VM ausgeliefert,
   reicht stattdessen der Wechsel in das vorhandene Projektverzeichnis.

3. Vor der Installation den gewünschten Branch auswählen und den aktuellen
   Stand laden. `<BRANCH>` ist beispielsweise `main`; die verfügbaren Branches
   zeigt `git branch -a` an:

   ```bash
   git fetch --prune
   git switch <BRANCH>
   git pull --ff-only
   git status
   ```

   `git status` sollte keine lokalen Änderungen melden. `--ff-only` verhindert,
   dass beim Aktualisieren unbemerkt ein Merge-Commit auf dem Server entsteht.
   Für eine reproduzierbare Installation kann anstelle eines Branches ein
   freigegebener Tag ausgecheckt werden (`git switch --detach <TAG>`).

4. Installer aus dem Wurzelverzeichnis des Repositories starten:

   ```bash
   sudo ./packaging/install-online.sh
   ```

5. Die Fragen zu Hostnamen, Sitzung, SMTP und TLS beantworten. Anschließend ein
   starkes Passwort für das erste Administratorkonto vergeben und die Frage
   nach dem Start des Dienstes mit `ja` beantworten. Bei einer
   Self-Signed-Installation muss der beim TLS-Schritt angegebene Hostname auch
   in der Liste der vertrauenswürdigen Hosts enthalten sein.

6. Installation und HTTPS-Erreichbarkeit prüfen (Hostname anpassen):

   ```bash
   sudo systemctl status certify --no-pager
   curl --cacert /etc/certify/tls/fullchain.pem https://certify.intern/
   sudo journalctl -u certify -n 50 --no-pager
   ```

   Danach ist die Anmeldung im Browser unter `https://<HOSTNAME>/` mit dem im
   Installer angelegten Administratorkonto möglich. Bei einem Self-Signed-
   Zertifikat muss dessen Vertrauen auf den zugreifenden Clients separat
   eingerichtet werden.

Das Skript installiert Certify aus dem aktuellen lokalen Checkout in eine
eigene virtuelle Umgebung. Aus dem Internet werden neben den durch `dnf`
installierten RHEL-Paketen ausschließlich die Python-Abhängigkeiten geladen.

#### Erneute Ausführung vor der ersten Inbetriebnahme

Falls zwischen dem Klonen und der eigentlichen Erstinstallation Zeit vergangen
ist, den Checkout unmittelbar vorher aktualisieren und danach den Installer
starten:

```bash
cd Certify
git status
git pull --ff-only
sudo ./packaging/install-online.sh
```

Lokale Änderungen müssen vor `git pull` bewusst committed, verworfen oder mit
`git stash` zwischengespeichert werden. Die Laufzeitdaten liegen nicht im
Repository, sondern unter `/var/lib/certify`; Konfiguration und Schlüssel
liegen unter `/etc/certify`. Sie werden durch `git pull` daher nicht verändert.

### Offline-Installation

1. Auf einem kompatiblen **Build-System mit Internetzugang** das Wheelhouse
   erstellen:

   ```bash
   ./packaging/build-wheelhouse.sh
   ```

2. Das **gesamte Projektverzeichnis** einschließlich der neu erzeugten
   Verzeichnisse `dist/` und `wheelhouse/` auf den Zielserver übertragen. Die
   Datei `dist/SHA256SUMS` enthält die beim Build erzeugten Prüfsummen der
   Projekt- und Abhängigkeits-Wheels.

3. Auf dem Zielserver aus dem Projektverzeichnis installieren. Für die
   Anwendung und ihre Python-Abhängigkeiten ist hierbei kein Netzzugriff
   erforderlich; fehlende RHEL-Pakete bezieht `dnf` aus den konfigurierten
   Online- oder Offline-Paketquellen:

   ```bash
   sudo ./packaging/install-offline.sh
   ```

### Ablauf der interaktiven Installation

Beide Installationsvarianten führen durch dieselben Schritte:

1. Alle benötigten RHEL-Pakete installieren und deren Werkzeuge prüfen. Dazu
   gehören Python samt `pip`, OpenSSL, CA-Zertifikate, systemd sowie die für
   Benutzer-, Datei- und SELinux-Verwaltung benötigten Werkzeuge. `certbot` wird
   bei Auswahl von Let's Encrypt zusätzlich installiert.
2. Systembenutzer `certify`, Datenverzeichnis und Python-Umgebung anlegen.
3. Browser-DNS-Namen, Sitzungsdauer und SMTP-Einstellungen abfragen und ein
   zufälliges Systemgeheimnis erzeugen.
4. Eine TLS-Quelle wählen: Self-Signed, vorhandene PEM-Dateien oder Let's
   Encrypt. Self-Signed ist der Standard und ohne weitere Infrastruktur sofort
   nutzbar, verursacht im Browser aber eine Zertifikatswarnung.
5. Das erste Administratorkonto interaktiv anlegen. Das Kennwort wird verdeckt
   abgefragt und muss die oben beschriebene Kennwortrichtlinie erfüllen.
6. Optional den Dienst sofort aktivieren und starten.

Eine laufende `firewalld` wird dauerhaft und sofort für HTTPS freigeschaltet.
Bei Let's Encrypt wird zusätzlich HTTP für Ausstellung und Erneuerung geöffnet.
Bei aktivem SELinux stellt das Skript die vorgesehenen Dateikontexte wieder her.

Die Installation legt insbesondere folgende Pfade an:

| Pfad | Inhalt |
|---|---|
| `/opt/certify/venv` | Anwendung und Python-Abhängigkeiten |
| `/etc/certify/certify.conf` | Laufzeitkonfiguration und Systemgeheimnis |
| `/etc/certify/tls/` | aktives Zertifikat und privater Schlüssel |
| `/var/lib/certify` | Datenbank und persistente Anwendungsdaten |
| `/etc/systemd/system/certify.service` | systemd-Unit |
| `/usr/local/sbin/certify-configure-tls` | Werkzeug zum Wechseln des TLS-Zertifikats |

## Updates

Ein Update ersetzt die Python-Umgebung unter `/opt/certify` und aktualisiert
auch die systemd-Unit sowie das TLS-Hilfsprogramm. Konfiguration,
TLS-Zertifikate und die Datenbank bleiben erhalten. Die neue
Version wird zuerst vollständig in einer separaten Umgebung installiert und
per Import-Selbsttest geprüft. Erst danach hält das Skript den Dienst kurz an
und schaltet die Umgebung um. Kann Certify anschließend nicht starten, wird
automatisch die vorherige Version wiederhergestellt. Parallele Updates werden
durch eine Sperrdatei verhindert.

### Online aktualisieren

Im vorhandenen, sauberen Git-Checkout genügt der Aufruf des Updaters:

```bash
cd Certify
sudo ./packaging/update-online.sh
```

Der Updater bricht bei lokalen Änderungen sicher ab, holt Branch und Tags von
`origin` und aktualisiert den aktuellen Branch ausschließlich per Fast-Forward.
Für einen bestimmten Release-Tag kann beispielsweise
`CERTIFY_UPDATE_REF=v0.2.0 sudo -E ./packaging/update-online.sh` verwendet werden;
ein Rücksprung oder divergierender Stand wird ebenfalls abgelehnt. Ein anderer
Remote lässt sich mit `CERTIFY_UPDATE_REMOTE` wählen.

Danach baut das Skript zunächst eine separate Python-Umgebung auf, installiert
die mitgelieferten Systemdateien, lädt systemd neu und startet Certify immer
neu. Es wartet bis zu 30 Sekunden auf `/health` und vergleicht dort die laufende
Version mit der soeben installierten Version. Bei einem Fehler werden Umgebung
und systemd-Unit automatisch zurückgerollt und der vorherige Dienst gestartet.

### Offline aktualisieren

Auf einem kompatiblen RHEL-Buildsystem mit Internetzugang wird ein vollständiges
Paket erzeugt:

```bash
./packaging/build-wheelhouse.sh
```

Die erzeugte Datei `dist/certify-update-*.tar.gz` auf den Certify-Server
übertragen, in ein leeres Verzeichnis entpacken und dort ausführen:

```bash
tar -xzf certify-update-*.tar.gz
sudo ./packaging/update-offline.sh
```

Der Offline-Updater kontrolliert vorab alle Wheel-Prüfsummen und benötigt für
Python-Pakete keinen Netzzugriff. Das Buildsystem muss dieselbe RHEL-Version,
CPU-Architektur und Python-Version wie das Ziel haben. Release-Tags erzeugen
zusätzlich automatisch ein versioniertes Quellarchiv, ein Anwendungs-Wheel und
deren Prüfsummen als Release-Dateien. Das vollständige Offline-Paket wird wegen
plattformabhängiger Abhängigkeiten weiterhin auf einem kompatiblen RHEL-System
gebaut.

Nach einem erfolgreichen Update bleibt genau eine Rückfallversion unter
`/opt/certify/venv.previous` liegen; beim nächsten erfolgreichen Update wird sie
ersetzt. Der Dienst läuft nach einem erfolgreichen Update geprüft auf der neuen
Version.

### Unbeaufsichtigte Installation

Mit `CERTIFY_NON_INTERACTIVE=true` entfallen alle Rückfragen. Die
Laufzeitkonfiguration wird aus den Variablen der Tabelle im Abschnitt
[Konfiguration](#konfiguration) erstellt; ein nicht gesetztes `CERTIFY_SECRET`
wird dabei sicher generiert. Anders als im Dialog legt das Skript jedoch **kein
Administratorkonto an und startet den Dienst nicht**.

Installationsspezifische Variablen:

| Variable | Werte / Bedeutung | Vorgabe |
|---|---|---|
| `CERTIFY_TLS_MODE` | `self-signed`, `custom` oder `letsencrypt` | `self-signed` |
| `CERTIFY_TLS_HOSTNAME` | DNS-Name oder IP für Self-Signed-Zertifikat | erster Trusted Host beziehungsweise Hostname |
| `CERTIFY_TLS_CERT_FILE` | lesbares PEM-Serverzertifikat bei `custom` | erforderlich |
| `CERTIFY_TLS_KEY_FILE` | passender lesbarer PEM-Private-Key bei `custom` | erforderlich |
| `CERTIFY_TLS_CHAIN_FILE` | optionale PEM-Zertifikatskette bei `custom` | leer |
| `CERTIFY_TLS_DOMAIN` | öffentlicher DNS-Name bei `letsencrypt` | erforderlich |
| `CERTIFY_TLS_EMAIL` | Let's-Encrypt-Kontaktadresse; `-` verzichtet auf E-Mail | erforderlich |

Beispiel für eine vollständige Offline-Installation mit Self-Signed-
Zertifikat:

```bash
sudo env \
  CERTIFY_NON_INTERACTIVE=true \
  CERTIFY_TLS_MODE=self-signed \
  CERTIFY_TLS_HOSTNAME=certify.intern \
  CERTIFY_TRUSTED_HOSTS=certify.intern \
  CERTIFY_SMTP_HOST=mail.intern \
  CERTIFY_MAIL_FROM=certify@intern \
  ./packaging/install-offline.sh

# Anschließend einmalig den Administrator anlegen und den Dienst starten:
sudo bash -c 'set -a; source /etc/certify/certify.conf; \
  runuser -u certify -- /opt/certify/venv/bin/certify init-admin admin'
sudo systemctl enable --now certify
```

Für ein eigenes Zertifikat werden stattdessen `CERTIFY_TLS_MODE=custom`,
`CERTIFY_TLS_CERT_FILE` und `CERTIFY_TLS_KEY_FILE` gesetzt; für Let's Encrypt
`CERTIFY_TLS_MODE=letsencrypt`, `CERTIFY_TLS_DOMAIN` und `CERTIFY_TLS_EMAIL`.

### Installation prüfen

```bash
sudo systemctl status certify --no-pager
curl --cacert /etc/certify/tls/fullchain.pem https://certify.intern/
sudo journalctl -u certify -n 50 --no-pager
```

Beim eigenen oder einem Let's-Encrypt-Zertifikat kann `curl` ohne `--cacert`
verwendet werden, sofern die ausstellende CA auf dem System als vertrauenswürdig
gilt. Der aufgerufene Hostname muss in `CERTIFY_TRUSTED_HOSTS` und im Zertifikat
enthalten sein.

### HTTPS-Zertifikat nachträglich wechseln

Der Dienst verwendet nach seinem Start Port 443. Die Installation richtet
mindestens ein Self-Signed-Zertifikat ein. Das TLS-Werkzeug prüft Ablauf und
Übereinstimmung von Zertifikat und Schlüssel, installiert den privaten Schlüssel mit
restriktiven Rechten und startet einen bereits laufenden Dienst neu:

```bash
sudo certify-configure-tls self-signed certify.intern
sudo certify-configure-tls custom server.pem server.key chain.pem
sudo certify-configure-tls letsencrypt certify.example.com admin@example.com
```

Bei Let's Encrypt installiert es außerdem einen Deploy-Hook, der erneuerte
Zertifikate für Certify übernimmt. Port 80 muss daher auch für spätere
Erneuerungen erreichbar bleiben.

Das Systemgeheimnis in `/etc/certify/certify.conf` darf nach der ersten
Inbetriebnahme nicht unbedacht geändert werden: Es schützt unter anderem
Sitzungen und Audit-HMACs. Geheimnisse gehören nicht in die Kommandozeile oder
ins Repository.

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
