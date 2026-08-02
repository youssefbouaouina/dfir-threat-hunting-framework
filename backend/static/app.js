/* DFIR Threat Hunting — analyst dashboard logic.
   Talks to the same FastAPI backend that serves this page. Uses a short-lived
   bearer token when AUTH_ENABLED=true (POST /auth/login), otherwise calls are
   unauthenticated (lab/demo mode). */
const $ = (sel) => document.querySelector(sel);
const state = { token: localStorage.getItem("dfir_token") || null };

async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  if (state.token) headers["Authorization"] = `Bearer ${state.token}`;
  const resp = await fetch(path, { ...opts, headers });
  if (resp.status === 401) {
    showToast("Authentication required — log in first");
    logout();
    throw new Error("unauthorized");
  }
  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`${path} → ${resp.status}: ${body.slice(0, 200)}`);
  }
  const text = await resp.text();
  return text ? JSON.parse(text) : null;
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function showToast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.hidden = false;
  setTimeout(() => { t.hidden = true; }, 4000);
}

function login() {
  const api_key = $("#api-key").value.trim();
  if (!api_key) { showToast("Enter the admin API key"); return; }
  api("/auth/login", { method: "POST", body: JSON.stringify({ api_key }) })
    .then((r) => {
      state.token = r.token;
      localStorage.setItem("dfir_token", r.token);
      renderAuth();
      loadAll();
    })
    .catch(() => showToast("Login failed"));
}

function logout() {
  state.token = null;
  localStorage.removeItem("dfir_token");
  renderAuth();
}

function renderAuth() {
  $("#login-box").hidden = !!state.token;
  $("#user-box").hidden = !state.token;
}

/* ---------------- views ---------------- */
function switchView(name) {
  document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
  document.querySelectorAll(".nav-btn").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
  $(`#view-${name}`).classList.add("active");
  if (name === "overview") loadOverview();
  if (name === "endpoints") loadEndpoints();
  if (name === "detections") loadDetections();
  if (name === "runs") loadRuns();
  if (name === "artifacts") loadArtifacts();
  if (name === "audit") loadAudit();
}

async function loadOverview() {
  const health = await api("/health");
  const summary = await api("/detections/summary");
  const cards = $("#health-cards");
  const m = health.metrics || {};
  cards.innerHTML = [
    ["Artifacts", m.artifacts ?? 0],
    ["Unprocessed", m.artifacts_unprocessed ?? 0],
    ["Detections", m.detections ?? 0],
    ["Endpoints", m.endpoints ?? 0],
    ["Detection runs", m.detection_runs ?? 0],
    ["Hosts", m.hosts ?? 0],
  ].map(([lbl, num]) => `<div class="card"><div class="num">${num}</div><div class="lbl">${esc(lbl)}</div></div>`).join("");
  $("#summary-box").textContent = JSON.stringify(summary, null, 2);
}

async function loadEndpoints() {
  const rows = await api("/endpoints");
  $("#endpoints-table tbody").innerHTML = rows.map((e) => `
    <tr>
      <td>${e.id}</td>
      <td>${esc(e.hostname)}</td>
      <td>${esc(e.os)}</td>
      <td>${esc(e.agent_version || "-")}</td>
      <td><span class="badge ${e.status === "online" ? "online" : "offline"}">${esc(e.status)}</span></td>
      <td>${esc((e.last_seen || "").slice(0, 19))}</td>
      <td>${e.config?.interval_seconds ?? 300}</td>
      <td>${esc((e.config?.collectors || []).join(", "))}</td>
      <td>
        <button class="secondary" onclick="runCollection(${e.id})">Run collection</button>
        <button class="secondary" onclick="editConfig(${e.id})">Edit config</button>
      </td>
    </tr>`).join("");
}

async function runCollection(id) {
  try {
    const r = await api(`/endpoints/${id}/run-collection`, { method: "POST" });
    showToast(`Queued ${r.command} for ${r.hostname} (cmd #${r.command_id})`);
  } catch (e) { showToast(e.message); }
}

function editConfig(id) {
  const interval = prompt("Collection interval (seconds, min 10):");
  if (interval === null) return;
  api(`/endpoints/${id}/config`, { method: "PUT", body: JSON.stringify({ interval_seconds: Number(interval) }) })
    .then(() => { showToast("Config updated"); loadEndpoints(); })
    .catch((e) => showToast(e.message));
}

function addEndpoint() {
  const hostname = $("#new-hostname").value.trim();
  if (!hostname) { showToast("Enter a hostname"); return; }
  api("/endpoints/enroll", { method: "POST", body: JSON.stringify({ hostname, os: "linux" }) })
    .then(() => { $("#new-hostname").value = ""; showToast(`Enrolled ${hostname}`); loadEndpoints(); })
    .catch((e) => showToast(e.message));
}

async function loadDetections() {
  const host = $("#det-host-filter").value.trim();
  const sev = $("#det-severity-filter").value.trim();
  const params = new URLSearchParams();
  if (host) params.set("host", host);
  if (sev) params.set("severity", sev);
  const rows = await api(`/detections?${params}`);
  $("#detections-table tbody").innerHTML = rows.map((d) => `
    <tr>
      <td>${d.id}</td>
      <td>${esc(d.host)}</td>
      <td>${esc(d.rule_title)}<br><span class="badge ${d.triage_status}">${esc(d.triage_status)}</span></td>
      <td>${esc(d.technique_id || "-")} ${esc(d.technique_name || "")}</td>
      <td>${esc(d.severity)}</td>
      <td>${esc(d.triage_notes || "")}</td>
      <td>
        <select onchange="triage(${d.id}, this.value)">
          <option value="">Triage…</option>
          <option value="acknowledged">Acknowledge</option>
          <option value="true_positive">True positive</option>
          <option value="false_positive">False positive</option>
          <option value="reviewed">Reviewed</option>
        </select>
      </td>
    </tr>`).join("");
}

async function triage(id, status) {
  if (!status) return;
  const notes = prompt("Triage notes (optional):");
  try {
    await api(`/detections/${id}`, { method: "PATCH", body: JSON.stringify({ status, notes }) });
    showToast(`Detection #${id} → ${status}`);
    loadDetections();
  } catch (e) { showToast(e.message); }
}

async function loadRuns() {
  const rows = await api("/detection-runs");
  $("#runs-table tbody").innerHTML = rows.map((r) => `
    <tr>
      <td>${r.id}</td>
      <td>${esc(r.trigger)}</td>
      <td>${esc(r.status)}</td>
      <td>${esc(r.host || "-")}</td>
      <td>${r.rescan ? "yes" : "no"}</td>
      <td>${esc((r.started_at || "").slice(0, 19))}</td>
      <td>${r.artifacts_scanned}</td>
      <td>${r.detections_found}</td>
      <td>${esc(JSON.stringify(r.by_severity || {}))}</td>
    </tr>`).join("");
}

async function loadArtifacts() {
  const params = new URLSearchParams();
  const host = $("#art-host-filter").value.trim();
  const type = $("#art-type-filter").value.trim();
  const limit = $("#art-limit").value.trim();
  if (host) params.set("host", host);
  if (type) params.set("artifact_type", type);
  if (limit) params.set("limit", limit);
  const rows = await api(`/artifacts?${params}`);
  $("#artifacts-table tbody").innerHTML = rows.map((a) => `
    <tr>
      <td>${a.id}</td>
      <td>${esc(a.host)}</td>
      <td>${esc(a.artifact_type)}</td>
      <td>${esc(a.collected_at)}</td>
      <td>${a.processed ? "yes" : "no"}</td>
      <td><pre>${esc(JSON.stringify(a.data).slice(0, 200))}</pre></td>
    </tr>`).join("");
}

async function loadAudit() {
  const rows = await api("/audit-logs");
  $("#audit-table tbody").innerHTML = rows.map((a) => `
    <tr>
      <td>${a.id}</td>
      <td>${esc((a.created_at || "").slice(0, 19))}</td>
      <td>${esc(a.actor || "-")}</td>
      <td>${esc(a.action)}</td>
      <td><pre>${esc(JSON.stringify(a.detail || {}))}</pre></td>
    </tr>`).join("");
}

function loadAll() {
  loadOverview().catch(() => {});
  loadEndpoints().catch(() => {});
  loadDetections().catch(() => {});
  loadRuns().catch(() => {});
  loadArtifacts().catch(() => {});
  loadAudit().catch(() => {});
}

/* ---------------- wire-up ---------------- */
$("#login-btn").addEventListener("click", login);
$("#logout-btn").addEventListener("click", logout);
$("#run-detect-btn").addEventListener("click", async () => {
  const params = new URLSearchParams();
  const host = $("#detect-host").value.trim();
  if (host) params.set("host", host);
  if ($("#detect-rescan").checked) params.set("rescan", "true");
  try {
    const r = await api(`/detect?${params}`, { method: "POST" });
    $("#detect-result").textContent = `scanned ${r.artifacts_scanned}, found ${r.detections_found}`;
    loadOverview();
    loadRuns();
  } catch (e) { showToast(e.message); }
});
$("#refresh-endpoints").addEventListener("click", loadEndpoints);
$("#add-endpoint-btn").addEventListener("click", addEndpoint);
$("#apply-det-filters").addEventListener("click", loadDetections);
$("#refresh-runs").addEventListener("click", loadRuns);
$("#apply-art-filters").addEventListener("click", loadArtifacts);
$("#refresh-audit").addEventListener("click", loadAudit);
document.querySelectorAll(".nav-btn").forEach((b) =>
  b.addEventListener("click", () => switchView(b.dataset.view))
);

renderAuth();
switchView("overview");
