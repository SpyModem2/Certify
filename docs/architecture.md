# Architektur und Sicherheitsmodell

## Zielbild

Certify ist eine Einzelknoten-Anwendung für RHEL 10.2. FastAPI stellt eine
REST-Schnittstelle und eine responsive, direkt vom Dienst ausgelieferte
Single-Page-Oberfläche bereit. Das Frontend verwendet keine externen CDN- oder
Laufzeitabhängigkeiten; Navigation und Seitenrenderer sind zentral registriert,
damit neue Funktionsbereiche ergänzt werden können. SQLite vermeidet einen
verpflichtenden Datenbankdienst.
Zeitgesteuerte Erneuerungen werden zukünftig durch einen systemd-Timer und
einen transaktionalen Jobbestand in derselben Datenbank ausgeführt. Dadurch
sind weder Redis noch Celery noch Container erforderlich.

## Komponenten

* **Identität:** lokale, personalisierte Konten; Passwörter werden mit scrypt
  gehasht. Komplexität wird zentral erzwungen und die letzten 20 Hashes je Konto
  verhindern Wiederverwendung. Die TOTP-Implementierung akzeptiert ein Zeitfenster
  von ±30 Sekunden.
* **API-Authentisierung:** persönliche API-Keys werden nur einmal ausgegeben und
  danach ausschließlich als mit dem Master-Secret gebildeter HMAC gespeichert.
  Sie übernehmen Rolle und Zuweisungen des Kontos und besitzen zusätzlich einen
  `read`- oder `read_write`-Scope. Widerruf und letzte Nutzung werden gespeichert.
* **ACME:** Aufträge erlauben HTTP-01 oder DNS-01. Die Provider-Grenze trennt
  die Protokollsteuerung von DNS-Zugangsdaten. Ein lokaler JSON-Hook ermöglicht
  beliebige Anbieter ohne deren SDK-Abhängigkeiten.
* **Schlüssel:** Ein Auftrag ist entweder `managed` oder `csr`. Im CSR-Modus
  verlässt der private Schlüssel das Zielsystem nicht. Verwaltete Schlüssel
  dürfen nach expliziter Autorisierung heruntergeladen und verteilt werden.
  Neu erzeugte Schlüssel und System-Zugangsdaten liegen AES-256-GCM-verschlüsselt
  mit kontextgebundenen Authentifizierungsdaten in SQLite. Der Schlüssel wird
  mittels HKDF vom ausschließlich extern konfigurierten Master-Secret abgeleitet.
* **Delegation:** Administratoren weisen Zertifikate explizit Benutzern und
  Zielsystemen zu. Operatoren sehen und bearbeiten ausschließlich ihre
  Zuweisungen; dazu gehören CSR-Upload und lokale Schlüsselerzeugung.
* **Benachrichtigung:** Benutzer wählen `none`, `errors`, `expiry` oder `all`;
  der lokale SMTP-Relay übernimmt Transport und Richtlinien.
* **Verteilung:** Adapter kapseln Linux via OpenSSH, IIS via PowerShell-over-SSH
  und FortiOS 7.4 via dessen REST-API. Host-Key-Prüfung ist bei SSH zwingend.
  Remote-Kommandos sollen auf vorher freigegebene Skripte beschränkt werden.
* **Audit:** Jeder sicherheitsrelevante Vorgang wird mit HMAC-SHA-256 an den
  vorherigen Datensatz gekettet. Der Schlüssel liegt außerhalb der Datenbank.

## Audit-Grenzen

Die Hashkette macht nachträgliche Änderungen und Löschungen innerhalb einer
vorliegenden Kette erkennbar. Sie verhindert nicht, dass ein Angreifer mit
Zugriff auf Datenbank **und** Applikationsschlüssel eine neue Kette erzeugt
oder das Ende abschneidet. Für echte Revisionssicherheit muss der Betrieb daher
regelmäßig signierte Prüfpunkte an ein unabhängiges WORM-Ziel oder Remote-SIEM
übertragen und dessen Aufbewahrungsrichtlinien organisatorisch absichern.

## Secrets

Die Datenbank darf keine Klartext-Passwörter oder API-Keys enthalten. TOTP-Secrets
und verwaltete private Schlüssel benötigen vor einem Produktiveinsatz eine
Envelope-Verschlüsselung über einen austauschbaren Key-Provider (zum Beispiel
PKCS#11 oder systemd Credentials). API-Antworten und Logs dürfen Secrets nie
ausgeben. Backups sind verschlüsselt und mit restriktiven Dateirechten abzulegen.

## Geplante Adapter

Die stabile Plugin-Schnittstelle soll zuerst folgende DNS-APIs aufnehmen:
RFC 2136, Cloudflare, Route 53, Azure DNS, Google Cloud DNS, Hetzner, IONOS,
DigitalOcean, OVH und PowerDNS. Der Custom-Hook bleibt als universeller Adapter.
Für Zielsysteme folgen Apache, nginx, HAProxy, IIS, FortiGate 7.4, Kubernetes,
F5 BIG-IP und weitere Firewall-Produkte. Jeder Adapter benötigt Integrations-
und Rollbacktests gegen die konkret unterstützte Produktversion.

## Noch nicht produktionsreif

Das Fundament implementiert Identität, Autorisierung, Inventar, Downloads,
Adaptergrenzen und Audit-Verifikation. Die tatsächliche ACME-State-Machine,
Schlüsselverschlüsselung, TOTP-Aktivierungsabläufe, FortiOS-Netzwerkaufrufe,
Hintergrund-Erneuerungen, Rate Limits, CSRF-Schutz für künftige Cookie-Sitzungen
und externe Audit-Prüfpunkte müssen vor einer produktiven Freigabe ergänzt und
sicherheitsgeprüft werden.
