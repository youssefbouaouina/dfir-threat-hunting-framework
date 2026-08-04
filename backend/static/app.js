/* DFIR Threat Hunting — brutalist operations report.
   Vanilla JS talking to the FastAPI backend. Uses a short-lived bearer token
   when AUTH_ENABLED=true (POST /auth/login), otherwise unauthenticated. */
const $ = (sel) => document.querySelector(sel);
const state = { token: localStorage.getItem("dfir_token") || null };

async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  if (state.token) headers["Authorization"] = `Bearer ${state.token}`;
  const resp = await fetch(path, { ...opts, headers });
  if (resp.status === 401) {
    showToast("AUTHENTICATION REQUIRED — LOG IN FIRST");
    logout();
    throw new Error("unauthorized");
  }
  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`${path} -> ${resp.status}: ${body.slice(0, 200)}`);
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
  if (!api_key) { showToast("ENTER THE ADMIN API KEY"); return; }
  api("/auth/login", { method: "POST", body: JSON.stringify({ api_key }) })
    .then((r) => {
      state.token = r.token;
      localStorage.setItem("dfir_token", r.token);
      renderAuth();
      loadAll();
    })
    .catch(() => showToast("LOGIN FAILED"));
}

function logout() {
  state.token = null;
  localStorage.removeItem("dfir_token");
  renderAuth();
}

function renderAuth() {
  $("#login-box").hidden = !!state.token;
  $("#user-box").hidden = !state.token;
  $("#user-label").textContent = "AUTH OK";
}

function ts() {
  $("#ov-timestamp").textContent = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

/* ---------------- views ---------------- */
let overviewTimer = null;
let currentReportId = null;

function switchView(name) {
  document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
  document.querySelectorAll(".nav-btn").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
  $(`#view-${name}`).classList.add("active");
  clearInterval(overviewTimer);
  overviewTimer = null;
  if (name === "overview") {
    loadOverview();
    overviewTimer = setInterval(() => loadOverview().catch(() => {}), 15000);
  }
  if (name === "endpoints") loadEndpoints();
  if (name === "incidents") loadIncidents();
  if (name === "report") loadReport(currentReportId);
  if (name === "detections") loadDetections();
  if (name === "runs") loadRuns();
  if (name === "artifacts") loadArtifacts();
  if (name === "audit") loadAudit();
}

/* ---------------- overview ---------------- */
async function loadOverview() {
  ts();
  const health = await api("/health");
  const summary = await api("/detections/summary");
  const m = health.metrics || {};
  const cards = $("#health-cards");
  const total = m.artifacts ?? 0;
  cards.innerHTML = [
    ["ARTIFACTS", m.artifacts ?? 0, false],
    ["UNPROCESSED", m.artifacts_unprocessed ?? 0, (m.artifacts_unprocessed ?? 0) > 0],
    ["DETECTIONS", m.detections ?? 0, (m.detections ?? 0) > 0],
    ["ENDPOINTS", m.endpoints ?? 0, false],
    ["HOSTS", m.hosts ?? 0, false],
    ["RUNS", m.detection_runs ?? 0, false],
  ].map(([lbl, num, hot]) => `
    <div class="stat ${hot ? "hot" : ""}">
      <div class="num">${num}</div><div class="lbl">${esc(lbl)}</div>
    </div>`).join("");

  const sched = $("#scheduler-box");
  try {
    const s = await api("/scheduler/status");
    const next = s.next_run_time ? new Date(s.next_run_time).toLocaleString() : "—";
    sched.textContent = `RUNNING: ${s.running ? "YES" : "NO"}
INTERVAL: ${s.interval_seconds}s
NEXT RUN: ${next}`;
  } catch {
    sched.textContent = "SCHEDULER STATUS UNAVAILABLE";
  }

  const sev = summary.by_severity || {};
  const sevOrder = ["critical", "high", "medium", "low", "info", "unknown"];
  const sevRows = sevOrder
    .filter((k) => sev[k])
    .map((k) => `<tr><td><span class="badge ${esc(k)}">${esc(k.toUpperCase())}</span></td><td class="num-col">${sev[k]}</td></tr>`)
    .join("");
  $("#severity-tbody").innerHTML = sevRows || "<tr><td colspan='2'>NO DETECTIONS ON RECORD</td></tr>";

  const tech = summary.by_technique || {};
  const techRows = Object.entries(tech)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 15)
    .map(([k, n]) => `<tr><td>${esc(k)}</td><td class="num-col">${n}</td></tr>`)
    .join("");
  $("#attck-tbody").innerHTML = techRows || "<tr><td colspan='2'>NO TECHNIQUE HITS</td></tr>";
}

/* ---------------- endpoints ---------------- */
async function loadEndpoints() {
  const rows = await api("/endpoints");
  $("#endpoints-tbody").innerHTML = rows.map((e) => `
    <tr>
      <td>${e.id}</td>
      <td><strong>${esc(e.hostname)}</strong></td>
      <td>${esc(e.os)}</td>
      <td>${esc(e.agent_version || "-")}</td>
      <td><span class="badge ${esc(e.status)}">${esc(e.status.toUpperCase())}</span></td>
      <td><span class="badge ${esc(e.criticality || "standard")}">${esc((e.criticality || "standard").toUpperCase())}</span></td>
      <td>${esc((e.last_seen || "").slice(0, 19))}</td>
      <td>${e.config?.interval_seconds ?? 300}s</td>
      <td>
        <button class="secondary" onclick="openReport(${e.id})">REPORT</button>
        <button class="secondary" onclick="runCollection(${e.id})">COLLECT</button>
        <button class="ghost" onclick="editConfig(${e.id})">CFG</button>
      </td>
    </tr>`).join("") || "<tr><td colspan='9'>NO ENDPOINTS ENROLLED</td></tr>";
}

async function runCollection(id) {
  try {
    const r = await api(`/endpoints/${id}/run-collection`, { method: "POST" });
    showToast(`QUEUED ${r.command.toUpperCase()} FOR ${r.hostname} (CMD #${r.command_id})`);
  } catch (e) { showToast(e.message); }
}

async function scanAll() {
  try {
    const r = await api("/endpoints/scan-all", { method: "POST" });
    showToast(`SCAN ALL: ${r.commands_queued ?? r.queued?.length ?? 0} COMMAND(S) QUEUED ACROSS ${r.endpoints_targeted} ENDPOINT(S)`);
  } catch (e) { showToast(e.message); }
}

function editConfig(id) {
  const interval = prompt("COLLECTION INTERVAL (SECONDS, MIN 10):");
  if (interval === null) return;
  const criticality = prompt("CRITICALITY (low | standard | important | critical):", "standard");
  if (criticality === null) return;
  api(`/endpoints/${id}/config`, {
    method: "PUT",
    body: JSON.stringify({ interval_seconds: Number(interval), criticality }),
  })
    .then(() => { showToast("CONFIG UPDATED"); loadEndpoints(); })
    .catch((e) => showToast(e.message));
}

function addEndpoint() {
  const hostname = $("#new-hostname").value.trim();
  if (!hostname) { showToast("ENTER A HOSTNAME"); return; }
  api("/endpoints/enroll", { method: "POST", body: JSON.stringify({ hostname, os: "linux" }) })
    .then(() => { $("#new-hostname").value = ""; showToast(`ENROLLED ${hostname}`); loadEndpoints(); })
    .catch((e) => showToast(e.message));
}

/* ---------------- endpoint report ---------------- */
function openReport(id) {
  currentReportId = id;
  switchView("report");
}

async function loadReport(id) {
  const r = await api(`/endpoints/${id}/report`);
  const e = r.endpoint;
  $("#report-title").textContent = `ENDPOINT REPORT — ${esc(e.hostname.toUpperCase())}`;

  const sevBadges = Object.entries(r.detections.by_severity || {})
    .map(([k, n]) => `<span class="badge ${esc(k)}">${esc(k.toUpperCase())} ${n}</span>`)
    .join(" ");

  $("#report-body").innerHTML = `
    <div class="report-hero">
      <div>
        <div class="hero-name">${esc(e.hostname)}</div>
        <div class="hero-meta">
          OS ${esc(e.os)} · AGENT ${esc(e.agent_version || "-")} ·
          STATUS <span class="badge ${esc(e.status)}">${esc(e.status.toUpperCase())}</span> ·
          CRITICALITY <span class="badge ${esc(e.criticality)}">${esc((e.criticality || "standard").toUpperCase())}</span> ·
          TEAM ${esc(e.team || "default")} ·
          LAST SEEN ${esc((e.last_seen || "").slice(0, 19))}
        </div>
        <div class="hero-meta">INTERVAL ${e.config?.interval_seconds ?? 300}s · COLLECTORS ${esc((e.config?.collectors || []).join(", "))}</div>
      </div>
      <div class="hero-actions">
        <button onclick="runCollection(${e.id})">RUN COLLECTION NOW</button>
        <button onclick="runHostDetection('${esc(e.hostname)}')">RUN DETECTION</button>
      </div>
    </div>

    <div class="report-grid">
      <div class="block">
        <h3>ARTIFACTS (${r.artifacts.total} TOTAL · ${r.artifacts.unprocessed} UNPROCESSED)</h3>
        <table class="report-table">
          <thead><tr><th>TYPE</th><th>COUNT</th></tr></thead>
          <tbody>
            ${Object.entries(r.artifacts.by_type || {}).map(([k, n]) =>
              `<tr><td>${esc(k)}</td><td class="num-col">${n}</td></tr>`).join("")
              || "<tr><td colspan='2'>NO ARTIFACTS</td></tr>"}
          </tbody>
        </table>
      </div>

      <div class="block">
        <h3>DETECTIONS (${r.detections.total} TOTAL)</h3>
        <p class="ctrl-row">${sevBadges || "<span class='stamp'>CLEAN</span>"}</p>
        <table class="report-table">
          <thead><tr><th>SEVERITY</th><th>COUNT</th></tr></thead>
          <tbody>
            ${Object.entries(r.detections.by_severity || {}).map(([k, n]) =>
              `<tr><td><span class="badge ${esc(k)}">${esc(k.toUpperCase())}</span></td><td class="num-col">${n}</td></tr>`).join("")
              || "<tr><td colspan='2'>NO DETECTIONS</td></tr>"}
          </tbody>
        </table>
      </div>

      <div class="block">
        <h3>INCIDENTS (${r.incidents.length})</h3>
        <table class="report-table">
          <thead><tr><th>ID</th><th>TITLE</th><th>SEVERITY</th><th>STATUS</th></tr></thead>
          <tbody>
            ${r.incidents.map((i) =>
              `<tr><td>${i.id}</td><td>${esc(i.title)}</td><td><span class="badge ${esc(i.severity)}">${esc(i.severity.toUpperCase())}</span></td><td><span class="badge ${esc(i.status)}">${esc(i.status.toUpperCase())}</span></td></tr>`).join("")
              || "<tr><td colspan='4'>NO INCIDENTS</td></tr>"}
          </tbody>
        </table>
      </div>

      <div class="block">
        <h3>RUN HISTORY</h3>
        <table class="report-table">
          <thead><tr><th>ID</th><th>TRIGGER</th><th>STATUS</th><th>SCANNED</th><th>FOUND</th></tr></thead>
          <tbody>
            ${r.run_history.map((run) =>
              `<tr><td>${run.id}</td><td>${esc(run.trigger)}</td><td><span class="badge ${esc(run.status)}">${esc(run.status.toUpperCase())}</span></td><td class="num-col">${run.artifacts_scanned}</td><td class="num-col">${run.detections_found}</td></tr>`).join("")
              || "<tr><td colspan='5'>NO RUNS FOR THIS HOST</td></tr>"}
          </tbody>
        </table>
      </div>
    </div>`;
}

async function runHostDetection(hostname) {
  try {
    const r = await api(`/detect?host=${encodeURIComponent(hostname)}`, { method: "POST" });
    showToast(`DETECTION: SCANNED ${r.artifacts_scanned}, FOUND ${r.detections_found}`);
    loadReport(currentReportId);
  } catch (e) { showToast(e.message); }
}

/* ---------------- incidents ---------------- */
async function loadIncidents() {
  const [rows, summary] = await Promise.all([api("/incidents"), api("/incidents/summary")]);
  const byStatus = summary.by_status || {};
  const bySev = summary.by_severity || {};
  $("#incident-stats").innerHTML = [
    ["OPEN", byStatus.open ?? 0, "open"],
    ["RESOLVED", byStatus.resolved ?? 0, "resolved"],
    ["CRITICAL", bySev.critical ?? 0, "critical"],
    ["HIGH", bySev.high ?? 0, "high"],
  ].map(([lbl, n, cls]) => `<span class="stamp ${cls}">${lbl}: ${n}</span>`).join("");

  $("#incidents-tbody").innerHTML = rows.map((i) => `
    <tr>
      <td>${i.id}</td>
      <td><strong>${esc(i.title)}</strong><br>
        <span class="badge">${esc(i.signature.includes("chain") ? "CHAIN" : "CAMPAIGN")}</span>
        ${esc(i.hosts.map((h) => h.toUpperCase()).join(" / "))}</td>
      <td><span class="badge ${esc(i.severity)}">${esc(i.severity.toUpperCase())}</span></td>
      <td><span class="badge ${esc(i.status)}">${esc(i.status.toUpperCase())}</span></td>
      <td class="num-col">${i.host_count}</td>
      <td class="num-col">${i.detection_count}</td>
      <td>${esc((i.first_seen || "").slice(0, 19))}</td>
      <td>
        <select onchange="triageIncident(${i.id}, this.value)">
          <option value="">TRIAGE…</option>
          <option value="acknowledged">ACKNOWLEDGE</option>
          <option value="resolved">RESOLVE</option>
          <option value="false_positive">FALSE POSITIVE</option>
        </select>
      </td>
    </tr>`).join("") || "<tr><td colspan='8'>NO INCIDENTS — GRID IS CLEAN</td></tr>";
}

async function triageIncident(id, status) {
  if (!status) return;
  try {
    await api(`/incidents/${id}`, { method: "PATCH", body: JSON.stringify({ status }) });
    showToast(`INCIDENT #${id} -> ${status.toUpperCase()}`);
    loadIncidents();
  } catch (e) { showToast(e.message); }
}

/* ---------------- detections ---------------- */
async function loadDetections() {
  const params = new URLSearchParams();
  const host = $("#det-host-filter").value.trim();
  const sev = $("#det-severity-filter").value.trim();
  if (host) params.set("host", host);
  if (sev) params.set("severity", sev);
  const rows = await api(`/detections?${params}`);
  $("#detections-tbody").innerHTML = rows.map((d) => `
    <tr>
      <td>${d.id}</td>
      <td><strong>${esc(d.host)}</strong></td>
      <td>${esc(d.rule_title)}<br><span class="badge">${esc(d.rule_id)}</span>
        ${d.technique_id ? `<br>${esc(d.technique_id)} ${esc(d.technique_name || "")}` : ""}</td>
      <td><span class="badge ${esc(d.severity)}">${esc(d.severity.toUpperCase())}</span></td>
      <td><span class="badge ${esc(d.triage_status)}">${esc(d.triage_status.toUpperCase())}</span>${d.triage_notes ? `<br><small>${esc(d.triage_notes)}</small>` : ""}</td>
      <td>
        <select onchange="triage(${d.id}, this.value)">
          <option value="">TRIAGE…</option>
          <option value="acknowledged">ACKNOWLEDGE</option>
          <option value="true_positive">TRUE POSITIVE</option>
          <option value="false_positive">FALSE POSITIVE</option>
          <option value="reviewed">REVIEWED</option>
        </select>
      </td>
    </tr>`).join("") || "<tr><td colspan='6'>NO DETECTIONS</td></tr>";
}

async function triage(id, status) {
  if (!status) return;
  const notes = prompt("TRIAGE NOTES (OPTIONAL):");
  try {
    await api(`/detections/${id}`, { method: "PATCH", body: JSON.stringify({ status, notes }) });
    showToast(`DETECTION #${id} -> ${status.toUpperCase()}`);
    loadDetections();
  } catch (e) { showToast(e.message); }
}

/* ---------------- runs ---------------- */
async function loadRuns() {
  const rows = await api("/detection-runs");
  $("#runs-tbody").innerHTML = rows.map((r) => `
    <tr>
      <td>${r.id}</td>
      <td>${esc(r.trigger.toUpperCase())}</td>
      <td><span class="badge ${esc(r.status)}">${esc(r.status.toUpperCase())}</span></td>
      <td>${esc(r.host || "ALL")}</td>
      <td>${esc((r.started_at || "").slice(0, 19))}</td>
      <td class="num-col">${r.artifacts_scanned}</td>
      <td class="num-col">${r.detections_found}</td>
      <td>${esc(JSON.stringify(r.by_severity || {}))}</td>
    </tr>`).join("") || "<tr><td colspan='8'>NO RUNS YET</td></tr>";
}

/* ---------------- artifacts ---------------- */
async function loadArtifacts() {
  const params = new URLSearchParams();
  const host = $("#art-host-filter").value.trim();
  const type = $("#art-type-filter").value.trim();
  const limit = $("#art-limit").value.trim();
  if (host) params.set("host", host);
  if (type) params.set("artifact_type", type);
  if (limit) params.set("limit", limit);
  const rows = await api(`/artifacts?${params}`);
  $("#artifacts-tbody").innerHTML = rows.map((a) => `
    <tr>
      <td>${a.id}</td>
      <td>${esc(a.host)}</td>
      <td>${esc(a.artifact_type)}</td>
      <td>${esc(a.collected_at)}</td>
      <td>${a.processed ? "Y" : "<span class='badge new'>N</span>"}</td>
      <td><pre>${esc(JSON.stringify(a.data).slice(0, 200))}</pre></td>
    </tr>`).join("") || "<tr><td colspan='6'>NO ARTIFACTS</td></tr>";
}

/* ---------------- audit ---------------- */
async function loadAudit() {
  const rows = await api("/audit-logs");
  $("#audit-tbody").innerHTML = rows.map((a) => `
    <tr>
      <td>${a.id}</td>
      <td>${esc((a.created_at || "").slice(0, 19))}</td>
      <td>${esc(a.actor || "-")}</td>
      <td><strong>${esc(a.action.toUpperCase())}</strong></td>
      <td><pre>${esc(JSON.stringify(a.detail || {}))}</pre></td>
    </tr>`).join("") || "<tr><td colspan='5'>TRAIL EMPTY</td></tr>";
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
    $("#detect-result").textContent = `SCANNED ${r.artifacts_scanned}, FOUND ${r.detections_found}`;
    loadOverview();
    loadRuns();
  } catch (e) { showToast(e.message); }
});
$("#scan-all-btn").addEventListener("click", scanAll);
$("#scan-all-btn-2").addEventListener("click", scanAll);
$("#refresh-endpoints").addEventListener("click", loadEndpoints);
$("#add-endpoint-btn").addEventListener("click", addEndpoint);
$("#report-back").addEventListener("click", () => switchView("endpoints"));
$("#apply-det-filters").addEventListener("click", loadDetections);
$("#refresh-runs").addEventListener("click", loadRuns);
$("#apply-art-filters").addEventListener("click", loadArtifacts);
$("#refresh-audit").addEventListener("click", loadAudit);
document.querySelectorAll(".nav-btn").forEach((b) =>
  b.addEventListener("click", () => switchView(b.dataset.view))
);

renderAuth();
switchView("overview");
