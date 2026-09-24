"use strict";

const state = { token: sessionStorage.getItem("certify_token"), me: null, certificates: [], targets: [], users: [], keys: [], audit: [] };
const pages = [
  { id: "dashboard", label: "Übersicht", icon: "⌂", roles: ["admin", "operator", "auditor"] },
  { id: "certificates", label: "Zertifikate", icon: "◇", roles: ["admin", "operator", "auditor"] },
  { id: "targets", label: "Zielsysteme", icon: "▣", roles: ["admin", "operator"] },
  { id: "users", label: "Benutzer", icon: "♙", roles: ["admin"] },
  { id: "api-keys", label: "API-Schlüssel", icon: "⌁", roles: ["admin", "operator", "auditor"] },
  { id: "notifications", label: "Benachrichtigungen", icon: "○", roles: ["admin", "operator", "auditor"] },
  { id: "audit", label: "Audit-Protokoll", icon: "✓", roles: ["admin", "auditor"] },
  { id: "settings", label: "Konto & Sicherheit", icon: "⚙", roles: ["admin", "operator", "auditor"] },
];
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const esc = (value = "") => String(value).replace(/[&<>'"]/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]);
const formatDate = value => {
  if (!value) return "–";
  const text = String(value);
  const hasTimezone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(text);
  const date = new Date(hasTimezone ? text : `${text.replace(" ", "T")}Z`);
  return Number.isNaN(date.getTime()) ? "–" : new Intl.DateTimeFormat("de-DE", { dateStyle: "medium", timeStyle: "short" }).format(date);
};
const roleLabel = role => ({ admin: "Administrator", operator: "Operator", auditor: "Auditor" })[role] || role;

async function api(path, options = {}) {
  const headers = { ...(options.body ? { "Content-Type": "application/json" } : {}), ...(state.token ? { Authorization: `Bearer ${state.token}` } : {}), ...options.headers };
  const response = await fetch(path, { ...options, headers });
  if (response.status === 401 && path !== "/api/v1/auth/login") { logout(); throw new Error("Die Sitzung ist abgelaufen."); }
  if (!response.ok) {
    let detail = `Anfrage fehlgeschlagen (${response.status})`;
    try { const data = await response.json(); detail = Array.isArray(data.detail) ? data.detail.map(item => item.msg).join(", ") : data.detail || detail; } catch (_) { /* no JSON body */ }
    throw new Error(detail);
  }
  if (response.status === 204) return null;
  const type = response.headers.get("content-type") || "";
  return type.includes("json") ? response.json() : response;
}

function toast(message, error = false) {
  const node = document.createElement("div"); node.className = `toast${error ? " error" : ""}`; node.textContent = message;
  $("#toast-region").append(node); setTimeout(() => node.remove(), 4200);
}
function openModal(title, kicker, body) { $("#modal-title").textContent = title; $("#modal-kicker").textContent = kicker; $("#modal-body").innerHTML = body; $("#modal").showModal(); }
function closeModal() { $("#modal").close(); }
function formJson(form) { return Object.fromEntries(new FormData(form).entries()); }
function empty(title, copy) { return `<div class="empty"><strong>${esc(title)}</strong><span>${esc(copy)}</span></div>`; }
function badge(value) { return `<span class="badge ${esc(value)}">${esc(value)}</span>`; }

async function login(event) {
  event.preventDefault(); const data = formJson(event.currentTarget); if (!data.totp_code) delete data.totp_code;
  $("#login-error").textContent = "";
  try {
    const result = await api("/api/v1/auth/login", { method: "POST", body: JSON.stringify(data) });
    state.token = result.access_token; sessionStorage.setItem("certify_token", state.token); if (result.password_change_required) location.hash = "settings"; await bootstrap();
  } catch (error) { $("#login-error").textContent = error.message; }
}
function logout() { state.token = null; state.me = null; sessionStorage.removeItem("certify_token"); $("#app-view").hidden = true; $("#login-view").hidden = false; }

async function bootstrap() {
  try { state.me = await api("/api/v1/users/me"); } catch (error) { logout(); return; }
  $("#login-view").hidden = true; $("#app-view").hidden = false;
  $("#user-name").textContent = state.me.username; $("#user-role").textContent = roleLabel(state.me.role); $("#user-avatar").textContent = state.me.username[0].toUpperCase();
  renderNav(); await navigate(state.me.password_change_required ? "settings" : (location.hash.slice(1) || "dashboard")); checkHealth();
}
function renderNav() {
  const available = pages.filter(page => page.roles.includes(state.me.role));
  $("#main-nav").innerHTML = `<div class="nav-section">Arbeitsbereich</div>${available.slice(0, 3).map(navItem).join("")}<div class="nav-section">Verwaltung</div>${available.slice(3).map(navItem).join("")}`;
}
function navItem(page) { return `<a class="nav-link" href="#${page.id}" data-page="${page.id}"><span class="nav-icon">${page.icon}</span><span>${page.label}</span></a>`; }
async function navigate(id) {
  const page = pages.find(item => item.id === id && item.roles.includes(state.me.role)) || pages[0];
  location.hash = page.id; $$(".nav-link[data-page]").forEach(link => link.classList.toggle("active", link.dataset.page === page.id));
  $("#breadcrumb").textContent = page.label; $("#page-title").textContent = page.label; $("#content").innerHTML = `<div class="empty">Daten werden geladen …</div>`; $("#content").focus();
  try { await renderers[page.id](); } catch (error) { $("#content").innerHTML = empty("Inhalt konnte nicht geladen werden", error.message); toast(error.message, true); }
  $(".sidebar").classList.remove("open");
}
async function checkHealth() { try { await api("/health"); $("#health-pill").classList.remove("offline"); } catch (_) { $("#health-pill").classList.add("offline"); } }
function intro(title, copy, action = "") { return `<div class="page-intro"><div><h2>${title}</h2><p>${copy}</p></div>${action}</div>`; }

async function loadCore() {
  const tasks = [api("/api/v1/certificates")];
  if (["admin", "operator"].includes(state.me.role)) tasks.push(api("/api/v1/targets")); else tasks.push(Promise.resolve([]));
  if (state.me.role === "admin") tasks.push(api("/api/v1/users")); else tasks.push(Promise.resolve([]));
  [state.certificates, state.targets, state.users] = await Promise.all(tasks);
}
const certRows = certificates => certificates.map(cert => `<tr><td><div class="cell-main">${esc(cert.common_name)}</div><div class="cell-sub">${esc(cert.sans.join(", ") || "Keine SANs")}</div></td><td>${badge(cert.status)}</td><td>${esc(cert.challenge)}</td><td>${esc(cert.key_mode)}</td><td>${cert.targets.map(target => esc(target.name)).join(", ") || "–"}</td><td><div class="table-actions"><button class="small-button" data-cert-detail="${cert.id}">Details</button>${["admin", "operator"].includes(state.me.role) ? `<button class="small-button" data-cert-key="${cert.id}">Schlüssel</button>` : ""}</div></td></tr>`).join("");

async function dashboard() {
  await loadCore();
  const pending = state.certificates.filter(item => item.status === "pending").length;
  $("#content").innerHTML = `${intro(`Guten Tag, ${esc(state.me.username)}.`, "Hier ist der aktuelle Stand Ihrer Zertifikatslandschaft.")}
    <section class="stats"><article class="stat-card"><span class="label">Zertifikate gesamt</span><strong>${state.certificates.length}</strong><small>im Inventar</small></article><article class="stat-card"><span class="label">Ausstehend</span><strong>${pending}</strong><small>benötigen Bearbeitung</small></article><article class="stat-card"><span class="label">Zielsysteme</span><strong>${state.targets.length}</strong><small>konfigurierte Ziele</small></article><article class="stat-card"><span class="label">Systemzustand</span><strong>OK</strong><small>Audit und API erreichbar</small></article></section>
    <div class="dashboard-grid"><section class="panel"><header><h3>Aktuelle Zertifikate</h3><a href="#certificates" class="button">Alle anzeigen</a></header><div class="table-wrap">${state.certificates.length ? `<table class="data-table"><thead><tr><th>Name</th><th>Status</th><th>Challenge</th><th>Modus</th><th>Ziele</th><th></th></tr></thead><tbody>${certRows(state.certificates.slice(0, 5))}</tbody></table>` : empty("Noch keine Zertifikate", "Legen Sie den ersten Zertifikatsauftrag an.")}</div></section>
    <section class="panel"><header><h3>Schnellzugriff</h3></header><div class="panel-body quick-actions">${["admin", "operator"].includes(state.me.role) ? `<button class="quick-action" data-action="new-certificate"><span class="action-icon">＋</span><span><b>Zertifikat anlegen</b><small>Neuen Auftrag vorbereiten</small></span></button>` : ""}${state.me.role === "admin" ? `<button class="quick-action" data-action="new-target"><span class="action-icon">▣</span><span><b>Zielsystem anbinden</b><small>Deployment-Ziel konfigurieren</small></span></button>` : ""}<button class="quick-action" data-go="settings"><span class="action-icon">⚙</span><span><b>Sicherheit</b><small>Passwort und Konto</small></span></button></div></section></div>`;
  bindCertificateActions();
}

async function certificates() {
  await loadCore(); const create = ["admin", "operator"].includes(state.me.role) ? `<button class="button primary" data-action="new-certificate">＋ Zertifikat anlegen</button>` : "";
  $("#content").innerHTML = `${intro("Zertifikate", "Zentrale Übersicht aller für Sie sichtbaren Zertifikate und Aufträge.", create)}<div class="toolbar"><input class="search" id="certificate-search" type="search" placeholder="Zertifikate durchsuchen …"></div><section class="panel"><div class="table-wrap" id="certificate-table">${certificateTable(state.certificates)}</div></section>`;
  $("#certificate-search").addEventListener("input", event => { const q = event.target.value.toLowerCase(); $("#certificate-table").innerHTML = certificateTable(state.certificates.filter(item => item.common_name.toLowerCase().includes(q) || item.sans.some(san => san.toLowerCase().includes(q)))); bindCertificateActions(); }); bindCertificateActions();
}
function certificateTable(items) { return items.length ? `<table class="data-table"><thead><tr><th>Common Name / SAN</th><th>Status</th><th>Challenge</th><th>Schlüssel</th><th>Zielsysteme</th><th>Aktionen</th></tr></thead><tbody>${certRows(items)}</tbody></table>` : empty("Keine Zertifikate gefunden", "Passen Sie die Suche an oder legen Sie ein Zertifikat an."); }
function bindCertificateActions() {
  $$(`[data-cert-detail]`).forEach(button => button.onclick = () => showCertificate(Number(button.dataset.certDetail)));
  $$(`[data-cert-key]`).forEach(button => button.onclick = () => generateKey(Number(button.dataset.certKey)));
}
function newCertificate() {
  openModal("Zertifikat anlegen", "Neuer Auftrag", `<form id="certificate-form" class="grid-form"><label>Common Name<input name="common_name" placeholder="service.example.org" required></label><label>Challenge<select name="challenge"><option value="dns-01">DNS-01</option><option value="http-01">HTTP-01</option></select></label><label class="full">Subject Alternative Names<input name="sans" placeholder="www.example.org, api.example.org"></label><label>ACME-Verzeichnis<input name="acme_directory" type="url" value="https://acme-v02.api.letsencrypt.org/directory" required></label><label>Schlüsselmodus<select name="key_mode"><option value="managed">Von Certify verwaltet</option><option value="csr">Externe CSR</option></select></label><label class="full">CSR (nur bei externem Schlüssel)<textarea name="csr_pem" placeholder="-----BEGIN CERTIFICATE REQUEST-----"></textarea></label><div class="full"><label>Zielsysteme</label><div class="check-list">${state.targets.length ? state.targets.map(target => `<label><input type="checkbox" name="target_ids" value="${target.id}">${esc(target.name)} · ${esc(target.adapter)}</label>`).join("") : `<span class="muted">Keine Zielsysteme verfügbar.</span>`}</div></div><div class="modal-actions full"><button type="button" class="button" data-close>Abbrechen</button><button class="button primary">Auftrag anlegen</button></div></form>`);
  $("#certificate-form").onsubmit = async event => { event.preventDefault(); const raw = formJson(event.target); raw.sans = raw.sans.split(",").map(item => item.trim()).filter(Boolean); raw.target_ids = $$('[name="target_ids"]:checked', event.target).map(item => Number(item.value)); if (!raw.csr_pem) raw.csr_pem = null; try { await api("/api/v1/certificates", { method: "POST", body: JSON.stringify(raw) }); closeModal(); toast("Zertifikatsauftrag wurde angelegt."); navigate("certificates"); } catch (error) { toast(error.message, true); } };
}
function showCertificate(id) {
  const cert = state.certificates.find(item => item.id === id); if (!cert) return;
  openModal(cert.common_name, "Zertifikatdetails", `<dl class="detail-list"><dt>Status</dt><dd>${badge(cert.status)}</dd><dt>SANs</dt><dd>${esc(cert.sans.join(", ") || "–")}</dd><dt>Challenge</dt><dd>${esc(cert.challenge)}</dd><dt>Schlüsselmodus</dt><dd>${esc(cert.key_mode)}</dd><dt>Zielsysteme</dt><dd>${cert.targets.map(item => esc(item.name)).join(", ") || "–"}</dd><dt>Gültig bis</dt><dd>${formatDate(cert.not_after)}</dd><dt>Erstellt</dt><dd>${formatDate(cert.created_at)}</dd></dl>${["admin", "operator"].includes(state.me.role) ? `<div class="modal-actions"><button class="button" data-download="${id}">PEM herunterladen</button><button class="button" data-csr="${id}">CSR hochladen</button></div>` : ""}`);
}
async function generateKey(id) { if (!confirm("Einen neuen privaten Schlüssel und CSR erzeugen?")) return; try { const result = await api(`/api/v1/certificates/${id}/generate-key`, { method: "POST" }); openModal("CSR erzeugt", "Schlüsselverwaltung", `<p class="muted">Der private Schlüssel wurde verschlüsselt gespeichert.</p><div class="code-box">${esc(result.csr_pem)}</div>`); toast("Schlüssel und CSR wurden erzeugt."); } catch (error) { toast(error.message, true); } }

async function targets() {
  state.targets = await api("/api/v1/targets");
  $("#content").innerHTML = `${intro("Zielsysteme", "Systeme, auf denen Certify Zertifikate bereitstellt.", state.me.role === "admin" ? `<button class="button primary" data-action="new-target">＋ Zielsystem</button>` : "")}<section class="panel"><div class="table-wrap">${state.targets.length ? `<table class="data-table"><thead><tr><th>Name</th><th>Adapter</th><th>Host</th><th>Status</th><th>Erstellt</th></tr></thead><tbody>${state.targets.map(item => `<tr><td class="cell-main">${esc(item.name)}</td><td>${esc(item.adapter)}</td><td>${esc(item.hostname || item.ip_address || "–")}</td><td>${badge(item.enabled ? "active" : "inactive")}</td><td>${formatDate(item.created_at)}</td></tr>`).join("")}</tbody></table>` : empty("Keine Zielsysteme", "Binden Sie Linux, IIS oder FortiGate als Ziel an.")}</div></section>`;
}
function newTarget() {
  openModal("Zielsystem anbinden", "Infrastruktur", `<form id="target-form" class="grid-form"><label>Name<input name="name" required placeholder="Webserver Produktion"></label><label>Adapter<select name="adapter"><option value="linux-ssh">Linux via SSH</option><option value="iis-ssh">IIS via PowerShell/SSH</option><option value="fortigate-7.4">FortiGate 7.4</option></select></label><label>Hostname<input name="hostname" placeholder="web01.example.org"></label><label>IP-Adresse<input name="ip_address" placeholder="192.0.2.10"></label><label class="full">Adapter-Konfiguration (JSON)<textarea name="config">{}</textarea></label><label class="full">Zugangsdaten (JSON, verschlüsselt gespeichert)<textarea name="credentials">{}</textarea></label><div class="modal-actions full"><button type="button" class="button" data-close>Abbrechen</button><button class="button primary">Zielsystem speichern</button></div></form>`);
  $("#target-form").onsubmit = async event => { event.preventDefault(); const raw = formJson(event.target); try { raw.config = JSON.parse(raw.config); raw.credentials = JSON.parse(raw.credentials); await api("/api/v1/targets", { method: "POST", body: JSON.stringify(raw) }); closeModal(); toast("Zielsystem wurde angelegt."); navigate("targets"); } catch (error) { toast(error.message, true); } };
}

async function users() {
  state.users = await api("/api/v1/users");
  $("#content").innerHTML = `${intro("Benutzer", "Personalisierte Zugänge und rollenbasierte Berechtigungen.", `<button class="button primary" data-action="new-user">＋ Benutzer</button>`)}<section class="panel"><div class="table-wrap"><table class="data-table"><thead><tr><th>Benutzer</th><th>Name</th><th>Rolle</th><th>E-Mail</th><th>TOTP</th><th>Status</th><th>Aktionen</th></tr></thead><tbody>${state.users.map(item => `<tr><td class="cell-main">${esc(item.username)}</td><td>${esc([item.first_name, item.last_name].filter(Boolean).join(" ") || "–")}</td><td>${badge(item.role)}</td><td>${esc(item.email || "–")}</td><td>${badge(item.totp_enabled ? "active" : "inactive")}</td><td>${badge(item.active ? "active" : "inactive")}</td><td><div class="table-actions"><button class="small-button" data-edit-user="${item.id}">Bearbeiten</button>${item.totp_enabled ? `<button class="small-button" data-reset-totp="${item.id}">TOTP entfernen</button>` : ""}</div></td></tr>`).join("")}</tbody></table></div></section>`;
}
function newUser() {
  openModal("Benutzer anlegen", "Identität", `<form id="user-form" class="grid-form"><label>Benutzername<input name="username" required pattern="[a-zA-Z0-9_.@-]+"></label><label>Vorname<input name="first_name" required maxlength="128"></label><label>Nachname<input name="last_name" required maxlength="128"></label><label>Rolle<select name="role"><option value="operator">Operator</option><option value="auditor">Auditor</option><option value="admin">Administrator</option></select></label><label class="full">E-Mail<input name="email" type="email" required></label><label class="full">Initiales Passwort<input name="password" type="password" minlength="14" required><span class="muted">Mindestens 14 Zeichen mit Groß-/Kleinbuchstaben, Zahl und Sonderzeichen.</span></label><div class="modal-actions full"><button type="button" class="button" data-close>Abbrechen</button><button class="button primary">Benutzer anlegen</button></div></form>`);
  $("#user-form").onsubmit = async event => { event.preventDefault(); const raw = formJson(event.target); try { await api("/api/v1/users", { method: "POST", body: JSON.stringify(raw) }); closeModal(); toast("Benutzer wurde angelegt."); navigate("users"); } catch (error) { toast(error.message, true); } };
}
function editUser(id) {
  const user = state.users.find(item => item.id === id); if (!user) return;
  openModal("Benutzer bearbeiten", user.username, `<form id="edit-user-form" class="grid-form"><label>Vorname<input name="first_name" value="${esc(user.first_name || "")}" required maxlength="128"></label><label>Nachname<input name="last_name" value="${esc(user.last_name || "")}" required maxlength="128"></label><label class="full">E-Mail <span class="optional">optional</span><input name="email" type="email" value="${esc(user.email || "")}"></label><label>Rolle<select name="role"><option value="operator">Operator</option><option value="auditor">Auditor</option><option value="admin">Administrator</option></select></label><label>Status<select name="active"><option value="true">Aktiv</option><option value="false">Deaktiviert</option></select></label><div class="modal-actions full"><button type="button" class="button" data-close>Abbrechen</button><button class="button primary">Änderungen speichern</button></div></form>`);
  $('[name="role"]', $("#edit-user-form")).value = user.role; $('[name="active"]', $("#edit-user-form")).value = String(Boolean(user.active));
  $("#edit-user-form").onsubmit = async event => { event.preventDefault(); const raw = formJson(event.target); raw.active = raw.active === "true"; raw.email ||= null; try { await api(`/api/v1/users/${id}`, { method: "PUT", body: JSON.stringify(raw) }); closeModal(); toast("Benutzer wurde aktualisiert."); navigate("users"); } catch (error) { toast(error.message, true); } };
}

async function apiKeys() {
  state.keys = await api("/api/v1/api-keys");
  $("#content").innerHTML = `${intro("API-Schlüssel", "Persönliche, widerrufbare Zugänge für Automatisierung.", `<button class="button primary" data-action="new-key">＋ API-Schlüssel</button>`)}<section class="panel"><div class="table-wrap">${state.keys.length ? `<table class="data-table"><thead><tr><th>Name</th><th>Berechtigung</th><th>Letzte Nutzung</th><th>Status</th><th></th></tr></thead><tbody>${state.keys.map(item => `<tr><td class="cell-main">${esc(item.name)}</td><td>${esc(item.scope)}</td><td>${formatDate(item.last_used_at)}</td><td>${badge(item.revoked_at ? "revoked" : "active")}</td><td>${item.revoked_at ? "" : `<button class="small-button" data-revoke-key="${item.id}">Widerrufen</button>`}</td></tr>`).join("")}</tbody></table>` : empty("Keine API-Schlüssel", "Erstellen Sie einen Schlüssel für sichere Automatisierung.")}</div></section>`;
}
function newKey() {
  openModal("API-Schlüssel erstellen", "Automatisierung", `<form id="key-form"><label>Name<input name="name" required placeholder="Deployment Pipeline"></label><label>Berechtigung<select name="scope"><option value="read">Nur lesen</option><option value="read_write">Lesen und schreiben</option></select></label><div class="modal-actions"><button type="button" class="button" data-close>Abbrechen</button><button class="button primary">Schlüssel erstellen</button></div></form>`);
  $("#key-form").onsubmit = async event => { event.preventDefault(); try { const result = await api("/api/v1/api-keys", { method: "POST", body: JSON.stringify(formJson(event.target)) }); $("#modal-body").innerHTML = `<p class="muted">Dieser Schlüssel wird nur einmal angezeigt. Speichern Sie ihn jetzt sicher.</p><div class="code-box">${esc(result.key)}</div><div class="modal-actions"><button class="button primary" type="button" data-copy="${esc(result.key)}">In Zwischenablage kopieren</button></div>`; } catch (error) { toast(error.message, true); } };
}

async function notifications() {
  $("#content").innerHTML = `${intro("Benachrichtigungen", "Steuern Sie persönliche E-Mail-Hinweise und Systemmeldungen.")}<div class="dashboard-grid"><section class="panel"><header><h3>Meine Einstellungen</h3></header><div class="panel-body"><form id="notification-form"><label>E-Mail-Adresse<input name="email" type="email" value="${esc(state.me.email || "")}"></label><label>Benachrichtigungsstufe<select name="level"><option value="none">Keine</option><option value="errors">Nur Fehler</option><option value="expiry">Fehler und Ablauf</option><option value="all">Alle Ereignisse</option></select></label><button class="button primary" type="submit">Einstellungen speichern</button></form></div></section>${state.me.role === "admin" ? `<section class="panel"><header><h3>Systemmeldung senden</h3></header><div class="panel-body"><form id="send-notification-form"><label>Kategorie<select name="category"><option value="errors">Fehler</option><option value="expiry">Ablauf</option><option value="issued">Ausgestellt</option></select></label><label>Betreff<input name="subject" required></label><label>Nachricht<textarea name="message" required></textarea></label><button class="button primary">Senden</button></form></div></section>` : ""}</div>`;
  $('[name="level"]').value = state.me.notify_level;
  $("#notification-form").onsubmit = async event => { event.preventDefault(); const raw = formJson(event.target); raw.email ||= null; try { const result = await api("/api/v1/users/me/notifications", { method: "PUT", body: JSON.stringify(raw) }); state.me.email = result.email; state.me.notify_level = result.level; toast("Benachrichtigungen wurden gespeichert."); } catch (error) { toast(error.message, true); } };
  if ($("#send-notification-form")) $("#send-notification-form").onsubmit = async event => { event.preventDefault(); try { const result = await api("/api/v1/notifications/send", { method: "POST", body: JSON.stringify(formJson(event.target)) }); toast(`Nachricht an ${result.recipients} Empfänger gesendet.`); event.target.reset(); } catch (error) { toast(error.message, true); } };
}

async function auditPage() {
  const [verification, entries] = await Promise.all([api("/api/v1/audit/verify"), api("/api/v1/audit?limit=200")]); state.audit = entries;
  $("#content").innerHTML = `${intro("Audit-Protokoll", "Nachvollziehbare, kryptographisch verkettete Sicherheitsereignisse.")}<div class="audit-valid ${verification.valid ? "" : "invalid"}">${verification.valid ? "✓ Audit-Kette ist vollständig und gültig." : `⚠ Audit-Kette ist ab Eintrag ${esc(verification.broken_at)} beschädigt.`}</div><section class="panel"><div class="table-wrap">${entries.length ? `<table class="data-table"><thead><tr><th>Sequenz</th><th>Zeitpunkt</th><th>Akteur</th><th>Aktion</th><th>Ressource</th><th>Details</th></tr></thead><tbody>${entries.map(item => `<tr><td>#${item.sequence}</td><td>${formatDate(item.occurred_at)}</td><td class="cell-main">${esc(item.actor)}</td><td>${esc(item.action)}</td><td>${esc(item.resource)}</td><td><code>${esc(JSON.stringify(item.details))}</code></td></tr>`).join("")}</tbody></table>` : empty("Noch keine Einträge", "Sicherheitsrelevante Ereignisse erscheinen hier.")}</div></section>`;
}

async function settings() {
  $("#content").innerHTML = `${intro("Konto & Sicherheit", "Persönliche Kontodaten und Zugangsschutz.")}${state.me.password_change_required ? `<div class="audit-valid invalid">Ihr Passwort ist abgelaufen. Ändern Sie es, bevor Sie fortfahren.</div>` : ""}<div class="dashboard-grid"><section class="panel"><header><h3>Kontodetails</h3></header><div class="panel-body"><dl class="detail-list"><dt>Benutzername</dt><dd>${esc(state.me.username)}</dd><dt>Rolle</dt><dd>${roleLabel(state.me.role)}</dd><dt>Konto erstellt</dt><dd>${formatDate(state.me.created_at)}</dd></dl><form id="profile-form" class="grid-form"><label>Vorname<input name="first_name" value="${esc(state.me.first_name || "")}" required maxlength="128"></label><label>Nachname<input name="last_name" value="${esc(state.me.last_name || "")}" required maxlength="128"></label><div class="full"><button class="button primary">Namen aktualisieren</button></div></form><form id="email-form"><label>E-Mail-Adresse<input name="email" type="email" value="${esc(state.me.email || "")}" required></label><button class="button primary">E-Mail aktualisieren</button></form></div></section><section class="panel"><header><h3>Passwort ändern</h3></header><div class="panel-body"><form id="password-form"><label>Aktuelles Passwort<input name="current_password" type="password" required></label><label>Neues Passwort<input name="new_password" type="password" minlength="14" required></label><button class="button primary">Passwort aktualisieren</button></form></div></section><section class="panel"><header><h3>Zwei-Faktor-Authentifizierung</h3></header><div class="panel-body"><p class="muted">${state.me.totp_enabled ? "TOTP ist aktiviert. Zum Neueinrichten bestätigen Sie zuerst einen Code der bisherigen Authenticator-App." : "Schützen Sie Ihr Konto mit einem zeitbasierten Einmalcode aus Ihrer Authenticator-App."}</p><button id="totp-setup" class="button primary">${state.me.totp_enabled ? "TOTP neu einrichten" : "TOTP einrichten"}</button></div></section></div>`;
  $("#password-form").onsubmit = async event => { event.preventDefault(); try { await api("/api/v1/users/me/password", { method: "PUT", body: JSON.stringify(formJson(event.target)) }); event.target.reset(); state.me.password_change_required = false; toast("Passwort wurde geändert."); settings(); } catch (error) { toast(error.message, true); } };
  $("#email-form").onsubmit = async event => { event.preventDefault(); try { const result = await api("/api/v1/users/me/email", { method: "PUT", body: JSON.stringify(formJson(event.target)) }); state.me.email = result.email; toast("E-Mail-Adresse wurde geändert."); } catch (error) { toast(error.message, true); } };
  $("#profile-form").onsubmit = async event => { event.preventDefault(); try { const result = await api("/api/v1/users/me/name", { method: "PUT", body: JSON.stringify(formJson(event.target)) }); state.me.first_name = result.first_name; state.me.last_name = result.last_name; toast("Name wurde geändert."); } catch (error) { toast(error.message, true); } };
  if ($("#totp-setup")) $("#totp-setup").onclick = async () => { try { const currentCode = state.me.totp_enabled ? prompt("Aktuellen sechsstelligen TOTP-Code eingeben:") : null; if (state.me.totp_enabled && currentCode === null) return; const result = await api("/api/v1/users/me/totp/setup", { method: "POST", body: JSON.stringify(currentCode ? { current_code: currentCode } : {}) }); let setupPending = true; openModal("TOTP einrichten", "Zwei-Faktor-Authentifizierung", `<p class="muted">Scannen Sie den QR-Code mit Ihrer Authenticator-App. Alternativ können Sie den Schlüssel oder die URI manuell hinterlegen.</p><div class="totp-qr"><img src="${esc(result.qr_code)}" alt="QR-Code für die Einrichtung der Zwei-Faktor-Authentifizierung" width="220" height="220"><span>Mit der Authenticator-App scannen</span></div><label>Geheimer Schlüssel</label><div class="code-box">${esc(result.secret)}</div><label>Authenticator-URI</label><div class="code-box">${esc(result.otpauth_uri)}</div><form id="totp-confirm-form"><label>Sechsstelliger Code<input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" required></label><div class="modal-actions"><button type="button" class="button" data-close>Abbrechen</button><button class="button primary">TOTP aktivieren</button></div></form>`); $("#modal").addEventListener("close", async () => { if (!setupPending) return; setupPending = false; try { await api("/api/v1/users/me/totp/setup", { method: "DELETE" }); } catch (error) { toast(error.message, true); } }, { once: true }); $("#totp-confirm-form").onsubmit = async event => { event.preventDefault(); try { await api("/api/v1/users/me/totp/confirm", { method: "POST", body: JSON.stringify(formJson(event.target)) }); setupPending = false; state.me.totp_enabled = 1; closeModal(); toast("TOTP wurde aktiviert."); settings(); } catch (error) { toast(error.message, true); } }; } catch (error) { toast(error.message, true); } };
}

const renderers = { dashboard, certificates, targets, users, "api-keys": apiKeys, notifications, audit: auditPage, settings };
document.addEventListener("click", async event => {
  const action = event.target.closest("[data-action]")?.dataset.action;
  if (action === "new-certificate") newCertificate(); if (action === "new-target") newTarget(); if (action === "new-user") newUser(); if (action === "new-key") newKey(); if (action === "refresh") navigate(location.hash.slice(1));
  const go = event.target.closest("[data-go]")?.dataset.go; if (go) navigate(go);
  if (event.target.closest("[data-close]")) closeModal();
  const download = event.target.closest("[data-download]")?.dataset.download; if (download) { try { const response = await api(`/api/v1/certificates/${download}/download`); const blob = await response.blob(); const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = `certificate-${download}.pem`; link.click(); URL.revokeObjectURL(link.href); } catch (error) { toast(error.message, true); } }
  const csr = event.target.closest("[data-csr]")?.dataset.csr; if (csr) { openModal("CSR hochladen", "Schlüsselverwaltung", `<form id="csr-form"><label>PEM-kodierte CSR<textarea name="csr_pem" required></textarea></label><div class="modal-actions"><button class="button primary">CSR speichern</button></div></form>`); $("#csr-form").onsubmit = async e => { e.preventDefault(); try { await api(`/api/v1/certificates/${csr}/csr`, { method: "PUT", body: JSON.stringify(formJson(e.target)) }); closeModal(); toast("CSR wurde gespeichert."); navigate("certificates"); } catch (error) { toast(error.message, true); } }; }
  const resetTotp = event.target.closest("[data-reset-totp]")?.dataset.resetTotp; if (resetTotp && confirm("TOTP-Einstellungen dieses Benutzers entfernen?")) { try { await api(`/api/v1/users/${resetTotp}/totp`, { method: "DELETE" }); toast("TOTP-Einstellungen wurden entfernt."); navigate("users"); } catch (error) { toast(error.message, true); } }
  const editUserId = event.target.closest("[data-edit-user]")?.dataset.editUser; if (editUserId) editUser(Number(editUserId));
  const revoke = event.target.closest("[data-revoke-key]")?.dataset.revokeKey; if (revoke && confirm("Diesen API-Schlüssel unwiderruflich widerrufen?")) { try { await api(`/api/v1/api-keys/${revoke}`, { method: "DELETE" }); toast("API-Schlüssel wurde widerrufen."); navigate("api-keys"); } catch (error) { toast(error.message, true); } }
  const copy = event.target.closest("[data-copy]")?.dataset.copy; if (copy) { await navigator.clipboard.writeText(copy); toast("In die Zwischenablage kopiert."); }
});
window.addEventListener("hashchange", () => state.me && navigate(location.hash.slice(1)));
$("#login-form").addEventListener("submit", login); $("#logout-button").addEventListener("click", logout); $("#menu-button").addEventListener("click", () => $(".sidebar").classList.toggle("open"));
if (state.token) bootstrap();
