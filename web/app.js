"use strict";
// sqlmap_auto frontend. Project required. Tool single-choice. The SAME options
// component (SCHEMAS) drives both the scan composer and the template editor.

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

const state = {
  view: "dashboard",
  projectId: null, projects: [],
  parsed: null, params: [],
  scans: [], allScans: [], templates: [], settings: {},
  boardKey: "",
  treeExpanded: null, treeKey: "", currentTarget: null,
  detailId: null, detailOffset: 0, detailCache: "",
  editingTplId: null,
  skipCollapsed: true,   // auto-skipped params start collapsed at the bottom
  headerCollapsed: true, // Header-location params start collapsed too
  ruleScope: "global",   // filter-rules sub-tab: "global" | "project"
  tplTool: "sqlmap",     // template editor sub-tab: "sqlmap" | "ghauri"
  ipSeconds: 60, ipRemaining: 60,
};

// ===== option schemas (keys = backend driver option names) ================
const COMMON_TOGGLES = [
  { key: "force_ssl", label: "強制 HTTPS" },
  { key: "random_agent", label: "隨機 User-Agent" },
];
const COMMON_FIELDS = [
  { key: "proxy", label: "Proxy", type: "text", placeholder: "http://127.0.0.1:8080" },
  { key: "restrict_ip", label: "限制來源 IP(備忘)", type: "text", placeholder: "留空=不限制" },
  { key: "extra_flags", label: "額外參數(原樣傳給工具)", type: "text", wide: true, placeholder: "例:--prefix ) --suffix -- -" },
];
// sqlmap dests verified against sqlmap-1.10/lib/parse/cmdline.py
// ghauri flags verified against ghauri-1.4.3/ghauri/scripts/ghauri.py (no --tamper/--risk)
const SCHEMAS = {
  sqlmap: {
    fields: [
      { key: "level", label: "Level", type: "select", options: [["", "預設(1)"], ["1", "1"], ["2", "2"], ["3", "3"], ["4", "4"], ["5", "5"]] },
      { key: "risk", label: "Risk", type: "select", options: [["", "預設(1)"], ["1", "1"], ["2", "2"], ["3", "3"]] },
      { key: "technique", label: "Technique", type: "text", placeholder: "BEUSTQ(預設全部)" },
      { key: "dbms", label: "DBMS", type: "text", placeholder: "mysql / mssql…" },
      { key: "threads", label: "Threads", type: "number", min: 1, max: 20, placeholder: "1" },
      { key: "tamper", label: "Tamper", type: "text", placeholder: "space2comment,between" },
      { key: "timeout", label: "Timeout(秒)", type: "number", min: 1, placeholder: "30" },
      { key: "time_sec", label: "Time-sec 延遲", type: "number", min: 1, placeholder: "5" },
      { key: "delay", label: "Delay(秒)", type: "number", min: 0, placeholder: "0" },
      { key: "retries", label: "Retries", type: "number", min: 0, placeholder: "3" },
      { key: "prefix", label: "Prefix", type: "text" },
      { key: "suffix", label: "Suffix", type: "text" },
    ],
    toggles: [
      { key: "get_banner", label: "取 banner" }, { key: "get_current_user", label: "目前使用者" },
      { key: "get_current_db", label: "目前資料庫" }, { key: "get_hostname", label: "主機名" },
      { key: "get_dbs", label: "列舉 DB" }, { key: "is_dba", label: "是否 DBA" },
    ],
  },
  ghauri: {
    fields: [
      { key: "level", label: "Level (1-3)", type: "select", options: [["", "預設(1)"], ["1", "1"], ["2", "2"], ["3", "3"]] },
      { key: "technique", label: "Technique", type: "text", placeholder: "BEST(預設)" },
      { key: "dbms", label: "DBMS", type: "text", placeholder: "mysql / mssql…" },
      { key: "threads", label: "Threads", type: "number", min: 1, max: 20, placeholder: "1" },
      { key: "timeout", label: "Timeout(秒)", type: "number", min: 1, placeholder: "30" },
      { key: "time_sec", label: "Time-sec 延遲", type: "number", min: 1, placeholder: "5" },
      { key: "delay", label: "Delay(秒)", type: "number", min: 0, placeholder: "0" },
      { key: "retries", label: "Retries", type: "number", min: 0, placeholder: "3" },
      { key: "prefix", label: "Prefix", type: "text" },
      { key: "suffix", label: "Suffix", type: "text" },
    ],
    toggles: [
      { key: "get_banner", label: "取 banner" }, { key: "get_current_user", label: "目前使用者" },
      { key: "get_current_db", label: "目前資料庫" }, { key: "get_hostname", label: "主機名" },
      { key: "get_dbs", label: "列舉 DB" },
    ],
  },
};

// ===== helpers ============================================================
async function api(path, method = "GET", body) {
  const opt = { method, headers: {} };
  if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  const res = await fetch(path, opt);
  if (!res.ok) { let m = res.statusText; try { m = (await res.json()).detail || m; } catch (e) {} throw new Error(m); }
  const ct = res.headers.get("content-type") || "";
  return ct.includes("json") ? res.json() : res.text();
}
function toast(msg, kind = "") { const t = $("#toast"); t.textContent = msg; t.className = "toast " + kind; setTimeout(() => t.classList.add("hidden"), 2800); }
function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function fmtTime(ms) { return ms ? new Date(ms).toLocaleString() : ""; }
function fmtDur(ms) { if (!ms && ms !== 0) return ""; const s = Math.round(ms / 1000); return s < 60 ? s + "s" : Math.floor(s / 60) + "m" + (s % 60) + "s"; }

// ===== shared options renderer (composer + template editor) ===============
function renderFieldHtml(f) {
  const wide = f.wide ? " wide" : "";
  if (f.type === "select") {
    const opts = f.options.map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join("");
    return `<label class="field${wide}"><span>${esc(f.label)}</span><select data-optkey="${f.key}">${opts}</select></label>`;
  }
  const attrs = [f.min != null ? `min="${f.min}"` : "", f.max != null ? `max="${f.max}"` : "", f.placeholder ? `placeholder="${esc(f.placeholder)}"` : ""].join(" ");
  return `<label class="field${wide}"><span>${esc(f.label)}</span><input data-optkey="${f.key}" type="${f.type}" ${attrs}></label>`;
}
function renderToggleHtml(t) { return `<label class="check"><input type="checkbox" data-optkey="${t.key}"> ${esc(t.label)}</label>`; }
function renderOptions(tool, gridSel, togglesSel, labelSel) {
  const schema = SCHEMAS[tool]; if (!schema) return;
  const fields = schema.fields.concat(COMMON_FIELDS);
  const toggles = COMMON_TOGGLES.concat(schema.toggles);
  $(gridSel).innerHTML = fields.map(renderFieldHtml).join("");
  $(togglesSel).innerHTML = toggles.map(renderToggleHtml).join("");
  if (labelSel && $(labelSel)) $(labelSel).textContent = tool + " 選項";
}
function gatherOptions(gridSel, togglesSel) {
  const o = {};
  $$(`${gridSel} [data-optkey], ${togglesSel} [data-optkey]`).forEach(el => {
    const k = el.dataset.optkey;
    if (el.type === "checkbox") { if (el.checked) o[k] = true; }
    else { const v = el.value.trim(); if (v !== "") o[k] = el.type === "number" ? Number(v) : v; }
  });
  return o;
}
function applyOptions(o, gridSel, togglesSel) {
  o = o || {};
  $$(`${gridSel} [data-optkey], ${togglesSel} [data-optkey]`).forEach(el => {
    const k = el.dataset.optkey;
    if (el.type === "checkbox") el.checked = !!o[k];
    else el.value = (k in o && o[k] != null) ? o[k] : "";
  });
}

// ===== IP / health ========================================================
async function refreshIp() {
  try {
    const info = await api("/api/ip");
    const pub = $("#ipPublic"), loc = $("#ipLocal");
    pub.textContent = info.public || "—";
    pub.classList.toggle("unknown", !info.public);
    loc.textContent = info.local || "未能偵測";
    loc.classList.toggle("unknown", !info.local);
    if (info.all && info.all.length) loc.title = "所有網卡: " + info.all.join(", ");
  } catch (e) {
    $("#ipPublic").textContent = "—";
    $("#ipLocal").textContent = "未能偵測"; $("#ipLocal").classList.add("unknown");
  }
}
function updateIpCountdown() { const el = $("#ipCountdown"); if (el) el.textContent = state.ipRemaining + "s"; }
function doIpRefresh() { refreshIp(); state.ipRemaining = state.ipSeconds; updateIpCountdown(); }
function setIpSeconds(sec) { state.ipSeconds = Math.max(5, Math.min(3600, Number(sec) || 60)); state.ipRemaining = state.ipSeconds; updateIpCountdown(); }
function ipTick() {
  state.ipRemaining -= 1;
  if (state.ipRemaining <= 0) { doIpRefresh(); return; }
  updateIpCountdown();
}
async function refreshHealth() {
  try {
    const h = await api("/api/health"); const dot = $("#healthDot");
    dot.className = "health-dot " + (h.sqlmap_present ? "ok" : "off");
    dot.title = h.sqlmap_present ? "sqlmap 引擎就緒" : "尚未安裝 sqlmap(請執行 bootstrap.bat)";
  } catch (e) {}
}

// ===== projects ===========================================================
async function loadProjects() {
  state.projects = await api("/api/projects");
  if (!state.projects.length) { state.projectId = null; updateCurrentProjectLabel(); showProjectsView(true); openNewProject(); return false; }
  let pid = null;
  try { pid = Number(localStorage.getItem("projectId")) || null; } catch (e) {}
  if (!state.projects.some(p => p.id === pid)) pid = state.projects[0].id;
  setProject(pid);
  return true;
}
function updateCurrentProjectLabel() {
  const p = state.projects.find(x => x.id === state.projectId);
  const el = $("#currentProject");
  if (el) el.textContent = p ? p.name : "—";
}
function setProject(pid) {
  state.projectId = pid;
  state.treeExpanded = null; state.treeKey = "";   // reload tree expand-state per project
  updateCurrentProjectLabel();
  try { localStorage.setItem("projectId", String(pid)); } catch (e) {}
  const p = state.projects.find(x => x.id === pid);
  if (p && p.restrict_ip) { const el = $('#optGrid [data-optkey="restrict_ip"]'); if (el && !el.value) el.value = p.restrict_ip; }
}
function requireProject() { if (state.projectId == null) { toast("請先建立並選擇一個專案", "err"); showProjectsView(true); return false; } return true; }

function showProjectsView(firstRun) {
  setView("projects");
  $("#projectsBackBtn").classList.toggle("hidden", !!firstRun && state.projectId == null);
  window.scrollTo(0, 0);
  renderProjectsList();
}
function renderProjectsList() {
  const box = $("#projectsList");
  if (!state.projects.length) {
    box.innerHTML = `<div class="empty">尚無專案。<button class="btn primary sm" id="emptyNewProject">＋ 建立第一個專案</button></div>`;
    const b = $("#emptyNewProject", box); if (b) b.onclick = openNewProject;
    return;
  }
  box.innerHTML = state.projects.map(p => `
    <div class="project-card ${p.id === state.projectId ? "current" : ""}">
      <div class="pc-main">
        <div class="pc-top"><span class="pc-name">${esc(p.name)}</span>${p.id === state.projectId ? '<span class="badge tested">目前</span>' : ""}</div>
        <div class="pc-note">${esc(p.note || "—")}</div>
        <div class="pc-meta"><span class="mono-val">${esc(p.restrict_ip || "無限制IP")}</span> · ${esc(fmtTime(p.created_at))}</div>
      </div>
      <div class="pc-actions">
        <button class="btn sm" data-enter="${p.id}">進入</button>
        <button class="btn ghost sm danger-btn" data-delp="${p.id}">刪除</button>
      </div>
    </div>`).join("");
  $$("[data-enter]", box).forEach(b => b.onclick = () => { setProject(Number(b.dataset.enter)); showDashboard(); loadScans(); });
  $$("[data-delp]", box).forEach(b => b.onclick = async () => {
    const id = Number(b.dataset.delp);
    const proj = state.projects.find(x => x.id === id);
    const ok = await confirmModal({
      title: "刪除專案",
      message: `確定刪除專案 <b>${esc(proj ? proj.name : id)}</b>?此專案的掃描與紀錄將一併移除,無法復原。`,
      okText: "刪除",
    });
    if (!ok) return;
    await api(`/api/projects/${id}`, "DELETE");
    if (state.projectId === id) { try { localStorage.removeItem("projectId"); } catch (e) {} state.projectId = null; }
    await loadProjects(); renderProjectsList();
    toast("已刪除", "ok");
  });
}
function openNewProject() {
  $("#npName").value = ""; $("#npNote").value = ""; $("#npIp").value = "";
  showModal("newProjectModal");
  setTimeout(() => { const el = $("#npName"); if (el) el.focus(); }, 50);
}
async function createProjectEntry() {
  const name = $("#npName").value.trim();
  if (!name) { toast("請填專案名稱", "err"); return; }
  try {
    const p = await api("/api/projects", "POST", { name, note: $("#npNote").value.trim(), restrict_ip: $("#npIp").value.trim() });
    $("#npName").value = ""; $("#npNote").value = ""; $("#npIp").value = "";
    closeModals();
    await loadProjects(); setProject(p.id);
    showDashboard(); loadScans(); loadTemplates(true);
    toast("專案已建立並進入", "ok");
  } catch (e) { toast("建立失敗:" + e.message, "err"); }
}

// ===== parse ==============================================================
async function pasteFromClipboard() {
  try {
    const text = await navigator.clipboard.readText();
    if (!text || !text.trim()) { toast("剪貼簿是空的", "err"); return; }
    $("#rawInput").value = text;
    parseRequest();          // paste + parse in one click
  } catch (e) {
    toast("無法讀取剪貼簿,請改用 Ctrl+V 貼上", "err");
  }
}
async function parseRequest() {
  if (!requireProject()) return;
  const raw = $("#rawInput").value.trim();
  $("#parseWarn").textContent = "";
  if (!raw) { toast("請先貼上請求或 URL", "err"); return; }
  try {
    const r = await api("/api/parse", "POST", { raw, project_id: state.projectId });
    state.parsed = r; state.params = r.parsed.params.map(p => ({ ...p }));
    const warns = r.parsed.warnings || [];
    $("#parseWarn").textContent = warns.length ? "⚠ " + warns.join("；") : "";
    renderParseSummary(r); renderParams();
    locateInTree(r);
    $("#resultCard").classList.remove("hidden");
    $("#optionsCard").classList.remove("hidden");
  } catch (e) { toast("解析失敗:" + e.message, "err"); }
}
// Locate the just-parsed endpoint inside the right-hand tree: expand ancestors,
// highlight it, and scroll it into view. If untested, a synthetic "current"
// node is shown at the right level so you can see where it sits.
function locateInTree(r) {
  const { host, path } = _epParts({ endpoint: r.endpoint, url: r.parsed.url });
  state.currentTarget = { host, path };
  if (!state.treeExpanded) state.treeExpanded = loadTreeExpanded();
  state.treeExpanded.add("h:" + host);
  // expand every ancestor path prefix so the located endpoint is revealed
  let acc = "";
  for (const seg of path.split("/").filter(x => x !== "")) { acc += "/" + seg; state.treeExpanded.add("p:" + host + "|" + acc); }
  saveTreeExpanded();
  renderTreeIfChanged(true);
  setTimeout(() => { const el = document.querySelector(".cur-tag"); if (el) el.scrollIntoView({ behavior: "smooth", block: "center" }); }, 60);
}
function renderParseSummary(r) {
  const p = r.parsed;
  const rows = [
    ["方法", p.method], ["Scheme", p.scheme], ["Host", p.host || "—"], ["路徑", p.path],
    ["Content-Type", p.content_type || "—"], ["Header 數", Object.keys(p.headers || {}).length],
    ["Cookie 數", Object.keys(p.cookies || {}).length], ["Body 長度", (p.body || "").length],
    ["端點簽名", r.endpoint],
  ];
  $("#parseSummary").innerHTML = rows.map(([k, v]) => `<div class="kv"><b>${k}</b><span>${esc(v)}</span></div>`).join("") +
    `<div class="kv wide"><b>URL</b><span class="mono-val">${esc(p.url)}</span></div>` +
    `<div class="hint-line">送給工具的請求會用你貼上的<b>原始請求</b>(僅換行正規化),解析只用來挑參數與去重。</div>`;
}
function priorBadge(p) {
  if (p.prior_vulnerable) return `<span class="badge vuln">曾有漏洞×${p.prior_test_count}</span>`;
  if (p.prior_status === "clean") return `<span class="badge clean">測過無洞×${p.prior_test_count}</span>`;
  if (p.prior_status === "tested") return `<span class="badge tested">測過×${p.prior_test_count}</span>`;
  return `<span class="badge none">未測</span>`;
}
// Row colour tracks the CHECKBOX (will-be-tested), NOT the auto-skip flag.
// Auto-skip only sets the INITIAL checked state and moves the param into the
// SEPARATE "已自動略過" region below the table.
function paramRowHtml(i) {
  const p = state.params[i];
  return `<tr class="prow ${p.selected ? "sel" : "unsel"}" data-row="${i}">
    <td><input type="checkbox" data-idx="${i}" ${p.selected ? "checked" : ""}></td>
    <td class="pname">${esc(p.name)}</td>
    <td><span class="loc-chip">${esc(p.location)}</span></td>
    <td class="val-cell" title="${esc(p.value)}">${esc(p.value)}</td>
    <td>${p.filtered ? `<span class="badge skip" title="${esc(p.filter_reason || "")}">自動略過</span>` : ""}</td>
    <td>${priorBadge(p)}</td>
  </tr>`;
}
function wireParamRows(root) {
  $$('input[type=checkbox][data-idx]', root).forEach(cb => cb.onchange = () => {
    const i = parseInt(cb.dataset.idx, 10);
    state.params[i].selected = cb.checked;
    const tr = cb.closest("tr");
    if (tr) { tr.classList.toggle("sel", cb.checked); tr.classList.toggle("unsel", !cb.checked); }
  });
}
// A collapsible sub-region (Header params / auto-skipped) below the main table.
// Toggling flips a class on the EXISTING node (so grid-rows can animate the
// height) instead of re-rendering, and records the state so later full
// re-renders keep it.
function renderParamRegion(box, idxList, cfg) {
  if (!box) return;
  if (!idxList.length) { box.innerHTML = ""; return; }
  const collapsed = cfg.collapsed;
  box.innerHTML =
    `<button type="button" class="skip-head">
       <span class="caret">${collapsed ? "▸" : "▾"}</span>
       <span>${cfg.title} <b>${idxList.length}</b> 項</span>
       <span class="skip-hint">${cfg.hint}</span>
     </button>
     <div class="skip-body${collapsed ? " collapsed" : ""}"><div class="skip-body-inner">
       <table class="params">
         <thead><tr><th></th><th>參數</th><th>位置</th><th>樣本值</th><th>過濾</th><th>過去測試</th></tr></thead>
         <tbody>${idxList.map(paramRowHtml).join("")}</tbody>
       </table>
     </div></div>`;
  wireParamRows(box);
  const head = $(".skip-head", box), body = $(".skip-body", box), caret = $(".caret", box);
  head.onclick = () => {
    const isCol = body.classList.toggle("collapsed");
    caret.textContent = isCol ? "▸" : "▾";
    cfg.set(isCol);
  };
}
function renderParams() {
  const tb = $("#paramsTable tbody");
  if (!state.params.length) {
    tb.innerHTML = `<tr><td colspan="6" style="color:var(--fg-dim)">沒有偵測到參數。可在 URL 加 ?id=1 之類再試。</td></tr>`;
    renderParamRegion($("#headerParams"), [], {}); renderParamRegion($("#skipParams"), [], {});
    return;
  }
  const idxs = state.params.map((_, i) => i);
  const isHeader = i => state.params[i].location === "HEADER";
  const main = idxs.filter(i => !state.params[i].filtered && !isHeader(i));
  const headers = idxs.filter(isHeader);
  const skipped = idxs.filter(i => state.params[i].filtered && !isHeader(i));
  // main table: the real test candidates (GET/POST/JSON/COOKIE, not auto-skipped)
  tb.innerHTML = main.length ? main.map(paramRowHtml).join("")
    : `<tr><td colspan="6" style="color:var(--fg-dim)">主要參數都在下方分區(Header / 已略過)。</td></tr>`;
  wireParamRows(tb);
  // Header injection points — their OWN region (uncommon, default unchecked)
  renderParamRegion($("#headerParams"), headers, {
    title: "Header 位置參數(預設不勾)", hint: "較少見的注入點,需要才勾",
    collapsed: state.headerCollapsed, set: v => state.headerCollapsed = v,
  });
  // Rule-matched noise — its OWN region (default unchecked)
  renderParamRegion($("#skipParams"), skipped, {
    title: "已自動略過", hint: "判定為雜訊,預設不勾選",
    collapsed: state.skipCollapsed, set: v => state.skipCollapsed = v,
  });
}
function selectParams(mode) {
  state.params.forEach(p => {
    if (mode === "all") p.selected = true;
    else if (mode === "none") p.selected = false;
    else if (mode === "suggest") p.selected = !p.filtered && p.location !== "HEADER";
  });
  renderParams();
}

// ===== composer tool + templates ==========================================
function selectedTool() { const el = $('input[name="tool"]:checked'); return el ? el.value : ""; }
function selectTool(tool, opts) {
  opts = opts || {};
  const radio = $(`input[name="tool"][value="${tool}"]`); if (radio) radio.checked = true;
  renderOptions(tool, "#optGrid", "#optToggles", "#optToolLabel");
  $("#toolOptions").classList.remove("hidden");
  populateTemplateDropdown(tool);
  try { localStorage.setItem("lastTool", tool); } catch (e) {}
  const p = state.projects.find(x => x.id === state.projectId);
  if (p && p.restrict_ip) { const el = $('#optGrid [data-optkey="restrict_ip"]'); if (el && !el.value) el.value = p.restrict_ip; }
  if (opts.autoDefault) {
    const def = (state.templates || []).find(t => t.is_default && t.data && t.data.tool === tool);
    if (def) { applyOptions(def.data.options || {}, "#optGrid", "#optToggles"); $("#templateSelect").value = String(def.id); }
  }
}
function populateTemplateDropdown(tool) {
  const list = (state.templates || []).filter(t => t.data && t.data.tool === tool);
  $("#templateSelect").innerHTML = '<option value="">（不套用範本）</option>' +
    list.map(t => `<option value="${t.id}">${esc(t.name)}${t.is_default ? " ★預設" : ""}</option>`).join("");
  $("#tplHint").textContent = list.length ? "" : "此工具尚無範本(可到範本設定建立)";
}
function applySelectedTemplate() {
  const id = Number($("#templateSelect").value);
  const t = (state.templates || []).find(x => x.id === id);
  if (!t) return;
  applyOptions(t.data.options || {}, "#optGrid", "#optToggles");
  toast(`已套用範本「${t.name}」`, "ok");
}

// ===== launch =============================================================
async function launch() {
  if (!requireProject()) return;
  if (!state.parsed) { toast("請先解析請求", "err"); return; }
  const tool = selectedTool();
  if (!tool) { toast("請先選擇工具(sqlmap 或 ghauri)", "err"); return; }
  // block "deselect everything then launch": sqlmap would test nothing and
  // ghauri would (previously) test everything — neither is what the user meant.
  if (state.params.length && !state.params.some(p => p.selected)) {
    toast("請至少勾選一個參數再開始掃描", "err"); return;
  }
  const opts = gatherOptions("#optGrid", "#optToggles");
  const btn = $("#launchBtn"); btn.disabled = true;
  try {
    const r = await api("/api/scans", "POST", {
      raw: $("#rawInput").value.trim(), force_ssl: !!opts.force_ssl, project_id: state.projectId,
      tool, options: opts, params: state.params, extra_flags: opts.extra_flags || "", restrict_ip: opts.restrict_ip || "",
    });
    toast(`已加入掃描 #${(r.launched[0] || {}).id || ""}(背景執行中)`, "ok");
    await loadScans();
  } catch (e) { toast("啟動失敗:" + e.message, "err"); }
  finally { btn.disabled = false; }
}

// ===== sidebar board ======================================================
async function loadScans() {
  if (state.projectId == null) { state.allScans = []; state.scans = []; renderBoardIfChanged(true); renderTreeIfChanged(true); return; }
  const q = new URLSearchParams({ project_id: state.projectId, limit: 500, slim: 1 });
  try { state.allScans = await api("/api/scans?" + q.toString()); } catch (e) { return; }
  const status = $("#statusFilter").value;
  state.scans = status ? state.allScans.filter(s => s.status === status) : state.allScans;
  renderBoardIfChanged();
  renderTreeIfChanged();
}
function boardSignature() { return state.scans.map(s => `${s.id}:${s.status}:${s.vulnerable}`).join("|") + "@" + state.detailId; }
function renderBoardIfChanged(force) {
  const key = boardSignature();
  if (!force && key === state.boardKey) return;
  state.boardKey = key;
  const board = $("#scanBoard");
  $("#boardEmpty").classList.toggle("hidden", state.scans.length > 0);
  board.innerHTML = state.scans.map(renderScanRow).join("");
  $$(".scan-row", board).forEach(el => el.onclick = () => openScanDetail(parseInt(el.dataset.id, 10)));
  $$("[data-rowstop]", board).forEach(b => b.onclick = (e) => { e.stopPropagation(); stopScan(parseInt(b.dataset.rowstop, 10)); });
  $$("[data-rowdel]", board).forEach(b => b.onclick = (e) => { e.stopPropagation(); deleteScan(parseInt(b.dataset.rowdel, 10)); });
}
function renderScanRow(s) {
  const st = scanState(s);   // vuln | running | clean | other  -> left accent + chip colour
  const vuln = s.vulnerable ? '<span class="vuln-flag">●</span>' : "";
  const time = s.started_at ? new Date(s.started_at).toLocaleTimeString() : new Date(s.created_at).toLocaleTimeString();
  const dur = s.duration_ms ? " · " + fmtDur(s.duration_ms) : "";
  const canStop = s.status === "running" || s.status === "queued";
  return `<div class="scan-row st-${st} ${s.id === state.detailId ? "active" : ""}" data-id="${s.id}">
    <span class="status-chip ${s.status}">${s.status}</span>
    <div class="scan-row-main">
      <div class="scan-row-top"><span class="scan-tool">${esc(s.tool)}</span>${vuln}<span class="scan-meta">#${s.id} ${time}${dur}</span></div>
      <div class="scan-ep" title="${esc(s.endpoint || s.url)}">${esc(s.endpoint || s.url)}</div>
    </div>
    ${canStop
      ? `<button class="row-stop" data-rowstop="${s.id}" title="強制停止">停</button>`
      : `<button class="row-del" data-rowdel="${s.id}" title="刪除此掃描紀錄">✕</button>`}
  </div>`;
}
async function stopAll() {
  if (!state.scans.some(s => s.status === "running" || s.status === "queued")) { toast("目前沒有執行中的掃描", ""); return; }
  const ok = await confirmModal({
    title: "全部停止",
    message: "強制停止本專案<b>所有執行中/佇列中</b>的掃描?",
    okText: "全部停止",
  });
  if (!ok) return;
  try { const r = await api(`/api/scans/stop_all?project_id=${state.projectId}`, "POST"); toast(`已送出停止 ${r.stopped} 個`, "ok"); }
  catch (e) { toast("停止失敗:" + e.message, "err"); }
}

// ===== right test-record tree ============================================
function treeStoreKey() { return "treeExpanded:" + state.projectId; }
function loadTreeExpanded() { try { return new Set(JSON.parse(localStorage.getItem(treeStoreKey()) || "[]")); } catch (e) { return new Set(); } }
function saveTreeExpanded() { try { localStorage.setItem(treeStoreKey(), JSON.stringify(Array.from(state.treeExpanded || []))); } catch (e) {} }
function splitEndpoint(s) {
  const full = s.endpoint || ("? " + (s.url || ""));
  const sp = full.indexOf(" ");
  const method = sp >= 0 ? full.slice(0, sp) : "?";
  const rest = sp >= 0 ? full.slice(sp + 1) : full;
  const slash = rest.indexOf("/");
  const host = slash >= 0 ? rest.slice(0, slash) : rest;
  const path = slash >= 0 ? rest.slice(slash) : "/";
  return { host: host || "(未知主機)", ep: method + " " + path };
}
// A node's colour encodes the WORST state among its scans:
//   vuln(red) > running(orange) > clean/done(green) > other:error/killed(grey) > untested(grey)
// This is the single "severity" axis. The current-searched path is shown on a
// SEPARATE axis (the accent connector line) so the two never clash.
function scanState(s) {
  if (s.vulnerable) return "vuln";
  if (s.status === "running" || s.status === "queued") return "running";
  if (s.status === "done") return "clean";
  return "other"; // error / killed / stopped
}
const STATE_RANK = { vuln: 0, running: 1, clean: 2, other: 3, untested: 4 };
function worstOf(states) {
  let best = "untested";
  for (const s of states) if (STATE_RANK[s] < STATE_RANK[best]) best = s;
  return best;
}
function aggState(scans) {
  if (!scans || !scans.length) return "untested";
  return worstOf(scans.map(scanState));
}
// ---- path trie (VSCode style): group by PATH only (GET/POST of the same path
// stay together, method shown per scan), and compact single-child chains into a
// single row so shared prefixes read cleanly and branches create real levels ----
function _epParts(s) {
  const { host, ep } = splitEndpoint(s);
  const sp = ep.indexOf(" ");
  const path = (sp >= 0 ? ep.slice(sp + 1) : ep) || "/";
  return { host, path };
}
function _tnode(seg, path) { return { seg, path, children: new Map(), scans: [], synthetic: false }; }
function buildPathTree(scans, current) {
  const hosts = {};
  const root = (host) => (hosts[host] = hosts[host] || _tnode(host, ""));
  const terminal = (host, path) => {
    let node = root(host), acc = "";
    for (const seg of path.split("/").filter(x => x !== "")) {
      acc += "/" + seg;
      if (!node.children.has(seg)) node.children.set(seg, _tnode(seg, acc));
      node = node.children.get(seg);
    }
    return node;
  };
  for (const s of (scans || [])) { const { host, path } = _epParts(s); terminal(host, path).scans.push(s); }
  if (current && current.host && current.path) {          // synthetic "目前" node
    const node = terminal(current.host, current.path);
    if (!node.scans.length) node.synthetic = true;
  }
  return hosts;
}
function subtreeState(node) {
  const states = [aggState(node.scans)];
  for (const c of node.children.values()) states.push(subtreeState(c));
  return worstOf(states);
}
function compactChain(node) {
  // merge a run of single-child, non-terminal nodes -> "api/system/front"
  let label = node.seg, cur = node;
  while (cur.children.size === 1 && cur.scans.length === 0 && !cur.synthetic) {
    const only = cur.children.values().next().value;
    label += "/" + only.seg; cur = only;
  }
  return { label, node: cur };
}
function scanLeaf(s) {
  const t = new Date(s.started_at || s.created_at).toLocaleString();
  const method = s.method ? `<span class="method-chip">${esc(s.method)}</span>` : "";
  return `<div class="tnode"><div class="trow tscan" data-scan="${s.id}"><span class="status-chip ${s.status}">${s.status}</span>${method}<span class="scan-tool">${esc(s.tool)}</span><span class="tscan-meta">#${s.id} ${esc(t)}</span>${s.vulnerable ? '<span class="vuln-flag">●</span>' : ""}<button class="tscan-del" data-delscan="${s.id}" title="刪除此掃描紀錄">✕</button></div></div>`;
}
function renderPathNode(host, rawNode, exp, cur) {
  const { label, node } = compactChain(rawNode);
  const key = "p:" + host + "|" + node.path;
  const kids = [...node.children.values()];
  const expandable = node.scans.length > 0 || kids.length > 0;
  const open = expandable && exp.has(key);
  const st = subtreeState(node);
  const isCur = cur && cur.host === host && cur.path === node.path;
  const onPath = cur && cur.host === host && (cur.path === node.path || cur.path.startsWith(node.path + "/"));
  const curChip = node.synthetic ? '<span class="cur-tag">目前(未測)</span>'
                : (isCur ? '<span class="cur-tag">目前</span>' : '');
  const count = node.scans.length ? `<span class="tcount">${node.scans.length}</span>`
              : (kids.length ? `<span class="tcount">${kids.length}</span>` : '');
  let inner = "";
  if (open) {
    let parts = node.scans.slice().sort((a, b) => b.created_at - a.created_at).map(scanLeaf).join("");
    parts += kids.sort((a, b) => a.seg.localeCompare(b.seg)).map(c => renderPathNode(host, c, exp, cur)).join("");
    inner = `<div class="tchildren">${parts}</div>`;
  }
  const caret = expandable ? (open ? "▾" : "▸") : "";
  const dataKey = expandable ? ` data-key="${esc(key)}"` : "";
  return `<div class="tnode${onPath ? " on-path" : ""}"><div class="trow tep st-${st}"${dataKey}><span class="tcaret">${caret}</span><span class="tdot"></span><span class="tep-label">${esc(label)}</span>${curChip}${count}</div>${inner}</div>`;
}
function renderTreeIfChanged(force) {
  const cur = state.currentTarget ? state.currentTarget.host + "|" + state.currentTarget.path : "";
  const key = (state.allScans || []).map(s => s.id + ":" + s.status + ":" + s.vulnerable).join("|") +
    "#" + Array.from(state.treeExpanded || []).join(",") + "@" + cur;
  if (!force && key === state.treeKey) return;
  state.treeKey = key;
  renderTree();
}
function renderTree() {
  if (!state.treeExpanded) state.treeExpanded = loadTreeExpanded();
  const box = $("#treeBox"); const scans = state.allScans || [];
  const cur = state.currentTarget; const exp = state.treeExpanded;
  const hosts = buildPathTree(scans, cur);
  $("#treeEmpty").classList.toggle("hidden", Object.keys(hosts).length > 0);
  box.innerHTML = Object.keys(hosts).sort().map(hn => {
    const rootNode = hosts[hn]; const hkey = "h:" + hn; const hopen = exp.has(hkey);
    const kids = [...rootNode.children.values()];
    const hState = subtreeState(rootNode);
    const hCur = cur && cur.host === hn;
    let inner = "";
    if (hopen) {
      let parts = rootNode.scans.slice().sort((a, b) => b.created_at - a.created_at).map(scanLeaf).join("");
      parts += kids.sort((a, b) => a.seg.localeCompare(b.seg)).map(c => renderPathNode(hn, c, exp, cur)).join("");
      inner = `<div class="tchildren">${parts}</div>`;
    }
    const hCount = kids.length ? `<span class="tcount">${kids.length}</span>`
                 : (rootNode.scans.length ? `<span class="tcount">${rootNode.scans.length}</span>` : '');
    return `<div class="tnode${hCur ? " on-path" : ""}"><div class="trow thost st-${hState}" data-key="${esc(hkey)}"><span class="tcaret">${hopen ? "▾" : "▸"}</span><span class="tdot"></span><span class="thost-name">${esc(hn)}</span>${hCount}</div>${inner}</div>`;
  }).join("");
  $$(".trow[data-key]", box).forEach(el => el.onclick = () => toggleTreeNode(el.dataset.key));
  $$(".tscan[data-scan]", box).forEach(el => el.onclick = () => openScanDetail(parseInt(el.dataset.scan, 10)));
  $$("[data-delscan]", box).forEach(b => b.onclick = (e) => { e.stopPropagation(); deleteScan(parseInt(b.dataset.delscan, 10)); });
}
function toggleTreeNode(key) {
  if (!state.treeExpanded) state.treeExpanded = loadTreeExpanded();
  if (state.treeExpanded.has(key)) state.treeExpanded.delete(key); else state.treeExpanded.add(key);
  saveTreeExpanded(); renderTreeIfChanged(true);
}
function treeExpandAll() {
  const hosts = buildPathTree(state.allScans || [], state.currentTarget);
  const set = new Set();
  const walk = (host, node, isRoot) => {
    set.add(isRoot ? "h:" + host : "p:" + host + "|" + node.path);
    for (const c of node.children.values()) walk(host, c, false);
  };
  for (const hn of Object.keys(hosts)) walk(hn, hosts[hn], true);
  state.treeExpanded = set;
  saveTreeExpanded(); renderTreeIfChanged(true);
}
function treeCollapseAll() { state.treeExpanded = new Set(); saveTreeExpanded(); renderTreeIfChanged(true); }

// ===== scan detail modal ==================================================
function findingsHtml(s) {
  let f = s.result; if (!f && s.result_json) { try { f = JSON.parse(s.result_json); } catch (e) {} }
  const rows = [];
  if (s.error) rows.push(`<div class="kv"><b>錯誤</b><span style="color:var(--danger)">${esc(s.error)}</span></div>`);
  if (f) {
    if (f.dbms) rows.push(`<div class="kv"><b>DBMS</b><span>${esc(f.dbms)}</span></div>`);
    if (f.parameters && f.parameters.length) rows.push(`<div class="kv"><b>可注入參數</b><span>${esc(f.parameters.join(" / "))}</span></div>`);
    if (f.titles && f.titles.length) rows.push(`<div class="kv"><b>類型</b><span>${esc(f.titles.slice(0, 4).join("；"))}</span></div>`);
    if (f.payloads && f.payloads.length) rows.push(`<div class="kv"><b>Payload</b><span class="mono-val">${esc(f.payloads[0])}</span></div>`);
  }
  return rows.join("");
}
function renderScanDetail(s) {
  if (!s) return;
  $("#sdTitle").textContent = `${s.tool} · #${s.id}`;
  const dur = s.duration_ms ? " · " + fmtDur(s.duration_ms) : "";
  $("#sdMeta").innerHTML = ` <span class="status-chip ${s.status}">${s.status}</span> ${esc(s.endpoint || s.url)} · ${esc(fmtTime(s.started_at || s.created_at))}${dur}${s.vulnerable ? ' · <span class="vuln-flag">有漏洞</span>' : ""}`;
  $("#sdFindings").innerHTML = findingsHtml(s);
  const canStop = s.status === "running" || s.status === "queued";
  $("#sdActions").innerHTML = canStop ? `<button class="btn ghost sm danger-btn" id="sdStop">中止此掃描</button>` : "";
  const stop = $("#sdStop"); if (stop) stop.onclick = () => stopScan(s.id);
}
async function openScanDetail(id) {
  state.detailId = id; state.detailOffset = 0; state.detailCache = "";
  $("#sdLog").textContent = "(載入中…)";
  try { renderScanDetail(await api(`/api/scans/${id}`)); } catch (e) {}
  showModal("scanDetailModal");
  await pullDetailLog();
  renderBoardIfChanged(true);
}
async function pullDetailLog() {
  if (state.detailId == null) return;
  try {
    const r = await api(`/api/scans/${state.detailId}/log?offset=${state.detailOffset || 0}`);
    if (r.chunk) {
      state.detailCache += r.chunk; state.detailOffset = r.offset;
      const view = $("#sdLog"); const atBottom = view.scrollHeight - view.scrollTop - view.clientHeight < 40;
      view.textContent = state.detailCache; if (atBottom) view.scrollTop = view.scrollHeight;
    } else if (!state.detailCache) { $("#sdLog").textContent = "(尚無輸出)"; }
  } catch (e) {}
}
async function stopScan(id) {
  try { await api(`/api/scans/${id}/stop`, "POST"); toast("已送出中止(實際殺掉程序後才會標記 killed)", "ok"); }
  catch (e) { toast("中止失敗:" + e.message, "err"); }
}
async function deleteScan(id) {
  const ok = await confirmModal({
    title: "刪除掃描紀錄",
    message: `確定刪除掃描 <b>#${esc(id)}</b>?紀錄與日誌會一併移除,無法復原。`,
    okText: "刪除",
  });
  if (!ok) return;
  try {
    await api(`/api/scans/${id}`, "DELETE");
    if (state.detailId === id) { state.detailId = null; closeModals(); }
    toast("已刪除掃描紀錄", "ok");
    await loadScans();
  } catch (e) { toast("刪除失敗:" + e.message, "err"); }
}

// ===== poll loop ==========================================================
async function tick() {
  await loadScans();
  if (state.detailId != null && !$("#scanDetailModal").classList.contains("hidden")) {
    try { renderScanDetail(await api(`/api/scans/${state.detailId}`)); } catch (e) {}
    await pullDetailLog();
  }
}

// ===== views ==============================================================
let _firstView = true;
function setView(v) {
  const changed = state.view !== v;
  state.view = v;
  $("#dashboardView").classList.toggle("hidden", v !== "dashboard");
  $("#projectsView").classList.toggle("hidden", v !== "projects");
  $("#settingsView").classList.toggle("hidden", v !== "settings");
  syncPanels();
  if (!_firstView && changed) playViewEnter();
  _firstView = false;
}
function playViewEnter() {
  const el = document.querySelector(".main-col:not(.hidden)");
  if (!el) return;
  el.classList.remove("view-enter");
  void el.offsetWidth;          // reflow so the animation restarts each switch
  el.classList.add("view-enter");
}
function showDashboard() { setView("dashboard"); }
function showSettings(tab) {
  if (!requireProject()) return;
  setView("settings");
  window.scrollTo(0, 0);
  switchTab(tab || "general");
}
function switchTab(name) {
  $$("#settingsTabs .tab").forEach(t => t.classList.toggle("active", t.dataset.tab === name));
  $$(".tabpanel").forEach(p => p.classList.toggle("hidden", p.id !== "tab-" + name));
  if (name === "general") loadGeneralSettings();
  else if (name === "rules") setRuleScope(state.ruleScope || "global");
  else if (name === "templates") openTemplateEditor();
  else if (name === "project") loadCurrentProject();
}

// ----- general -----
async function loadGeneralSettings() {
  state.settings = await api("/api/settings");
  $("#setMax").value = state.settings.max_concurrent; $("#setPort").value = state.settings.port;
  $("#setIpRefresh").value = state.settings.ip_refresh_seconds;
  $("#setPublicIp").checked = !!state.settings.public_ip_lookup; $("#setAutoOpen").checked = !!state.settings.auto_open_browser;
}
async function saveGeneralSettings() {
  try {
    state.settings = await api("/api/settings", "POST", {
      max_concurrent: Number($("#setMax").value) || 8, port: Number($("#setPort").value) || 8776,
      ip_refresh_seconds: Number($("#setIpRefresh").value) || 60,
      public_ip_lookup: $("#setPublicIp").checked, auto_open_browser: $("#setAutoOpen").checked,
    });
    setIpSeconds(state.settings.ip_refresh_seconds); doIpRefresh();
    toast("已儲存(併發/埠變更需重啟)", "ok");
  } catch (e) { toast("儲存失敗:" + e.message, "err"); }
}

// ----- rules (split into 全域 / 本專案 sub-tabs) -----
function setRuleScope(scope) {
  state.ruleScope = scope;
  $$("#ruleScopeTabs .subtab").forEach(t => t.classList.toggle("active", t.dataset.scope === scope));
  $("#rAdd").textContent = scope === "global" ? "新增到全域" : "新增到本專案";
  loadRules();
}
async function loadRules() {
  const all = await api("/api/rules?" + (state.projectId != null ? "project_id=" + state.projectId : ""));
  const scope = state.ruleScope || "global";
  const rules = all.filter(r => scope === "global" ? r.project_id == null : r.project_id === state.projectId);
  const tb = $("#rulesTable tbody");
  if (!rules.length) {
    tb.innerHTML = `<tr><td colspan="6" class="rules-empty">${scope === "global" ? "尚無全域規則" : "本專案尚無自訂規則"};用上方欄位新增。</td></tr>`;
    return;
  }
  tb.innerHTML = rules.map(r => `
    <tr>
      <td><input type="checkbox" data-toggle="${r.id}" ${r.enabled ? "checked" : ""}></td>
      <td class="nowrap">${r.kind === "name" ? "名稱" : "值"}</td>
      <td class="nowrap">${esc(r.mode)}</td>
      <td class="pname">${esc(r.pattern)}</td>
      <td>${esc(r.note || "")}</td>
      <td><button class="link-btn del nowrap" data-del="${r.id}">刪除</button></td>
    </tr>`).join("");
  $$("[data-toggle]", tb).forEach(cb => cb.onchange = async () => { await api(`/api/rules/${cb.dataset.toggle}`, "PATCH", { enabled: cb.checked }); });
  $$("[data-del]", tb).forEach(b => b.onclick = async () => {
    const okDel = await confirmModal({ title: "刪除過濾規則", message: "確定刪除這條過濾規則?", okText: "刪除" });
    if (!okDel) return;
    await api(`/api/rules/${b.dataset.del}`, "DELETE"); loadRules();
  });
}
async function addRule() {
  const pattern = $("#rPattern").value.trim();
  if (!pattern) { toast("請填樣式", "err"); return; }
  const scope = state.ruleScope || "global";
  try {
    await api("/api/rules", "POST", { kind: $("#rKind").value, mode: $("#rMode").value, pattern, note: $("#rNote").value.trim(), project_id: scope === "global" ? null : state.projectId });
    $("#rPattern").value = ""; $("#rNote").value = ""; loadRules(); toast("已新增規則", "ok");
  } catch (e) { toast("新增失敗:" + e.message, "err"); }
}

// ----- template editor (shared options component) -----
function teSelectedTool() { const el = $('input[name="teTool"]:checked'); return el ? el.value : ""; }
function teSelectTool(tool) {
  const r = $(`input[name="teTool"][value="${tool}"]`); if (r) r.checked = true;
  renderOptions(tool, "#teOptGrid", "#teOptToggles", "#teToolLabel");
}
async function openTemplateEditor() {
  state.templates = await api("/api/templates");
  applyTplListWidth();
  setTplTool(state.tplTool || "sqlmap");   // per-tool tab; renders list + empty state
}
function setTplTool(tool) {
  state.tplTool = tool;
  $$("#tplToolTabs .subtab").forEach(t => t.classList.toggle("active", t.dataset.tpltool === tool));
  showTplEmpty();   // switching tool clears the right-side form
}
function showTplEmpty() {
  state.editingTplId = null;
  $("#tplForm").classList.add("hidden");
  $("#tplEmpty").classList.remove("hidden");
  renderTemplateList();
}
function renderTemplateList() {
  const box = $("#tplListBox");
  // only this tool's templates; its default is pinned on top (backend orders is_default first)
  const list = (state.templates || []).filter(t => ((t.data && t.data.tool) || t.tool) === (state.tplTool || "sqlmap"));
  if (!list.length) { box.innerHTML = `<div class="empty small">此工具尚無範本,按「＋ 新範本」建立。</div>`; return; }
  box.innerHTML = list.map(t => `
    <div class="tpl-item ${t.id === state.editingTplId ? "active" : ""} ${t.is_default ? "is-default" : ""}" data-tpl="${t.id}">
      <span class="scan-tool">${esc((t.data && t.data.tool) || t.tool || "?")}</span>
      <span class="tpl-name">${esc(t.name)}</span>
      ${t.is_default ? '<span class="badge tested">★ 預設</span>' : ""}
    </div>`).join("");
  $$("[data-tpl]", box).forEach(el => el.onclick = () => teLoadTemplate(Number(el.dataset.tpl)));
}
function applyTplListWidth() {
  try { const w = localStorage.getItem("tplListW"); if (w && $("#tplList")) $("#tplList").style.width = w + "px"; } catch (e) {}
}
function setupTplResizer() {
  const handle = $("#tplResizer"), panel = $("#tplList");
  if (!handle || !panel) return;
  let startX = 0, startW = 0, dragging = false;
  handle.addEventListener("mousedown", e => {
    dragging = true; startX = e.clientX; startW = panel.getBoundingClientRect().width;
    handle.classList.add("dragging"); document.body.style.userSelect = "none"; e.preventDefault();
  });
  window.addEventListener("mousemove", e => {
    if (!dragging) return;
    panel.style.width = Math.max(160, Math.min(520, startW + (e.clientX - startX))) + "px";
  });
  window.addEventListener("mouseup", () => {
    if (!dragging) return; dragging = false;
    handle.classList.remove("dragging"); document.body.style.userSelect = "";
    try { localStorage.setItem("tplListW", String(Math.round(panel.getBoundingClientRect().width))); } catch (e) {}
  });
}
function teNewTemplate() {
  state.editingTplId = null;
  $("#tplEmpty").classList.add("hidden");
  $("#tplForm").classList.remove("hidden");
  $("#teName").value = "";
  $("#teDefault").checked = false;
  teSelectTool(state.tplTool || "sqlmap");
  applyOptions({}, "#teOptGrid", "#teOptToggles");
  $("#teDelete").classList.add("hidden");
  renderTemplateList();
}
function teLoadTemplate(id) {
  const t = state.templates.find(x => x.id === id); if (!t) return;
  state.editingTplId = id;
  $("#tplEmpty").classList.add("hidden");
  $("#tplForm").classList.remove("hidden");
  $("#teName").value = t.name;
  $("#teDefault").checked = !!t.is_default;
  const tool = (t.data && t.data.tool) || "sqlmap";
  teSelectTool(tool);
  applyOptions((t.data && t.data.options) || {}, "#teOptGrid", "#teOptToggles");
  $("#teDelete").classList.remove("hidden");
  renderTemplateList();
}
async function teSave() {
  const name = $("#teName").value.trim(); const tool = teSelectedTool();
  if (!name) { toast("請填範本名稱", "err"); return; }
  if (!tool) { toast("請選擇工具", "err"); return; }
  const payload = { name, tool, is_default: $("#teDefault").checked, data: { tool, options: gatherOptions("#teOptGrid", "#teOptToggles") } };
  try {
    if (state.editingTplId) await api(`/api/templates/${state.editingTplId}`, "PATCH", payload);
    else { const t = await api("/api/templates", "POST", payload); state.editingTplId = t.id; }
    state.templates = await api("/api/templates");
    renderTemplateList();
    const curTool = selectedTool(); if (curTool) populateTemplateDropdown(curTool);
    $("#teDelete").classList.remove("hidden");
    toast("範本已儲存", "ok");
  } catch (e) { toast("儲存失敗:" + e.message, "err"); }
}
async function teDelete() {
  if (!state.editingTplId) return;
  const okDel = await confirmModal({ title: "刪除範本", message: "確定刪除此掃描範本?", okText: "刪除" });
  if (!okDel) return;
  await api(`/api/templates/${state.editingTplId}`, "DELETE");
  state.templates = await api("/api/templates");
  const curTool = selectedTool(); if (curTool) populateTemplateDropdown(curTool);
  showTplEmpty();
  toast("已刪除", "ok");
}

// ----- current project -----
function loadCurrentProject() {
  const p = state.projects.find(x => x.id === state.projectId); if (!p) return;
  $("#cpName").value = p.name; $("#cpNote").value = p.note || ""; $("#cpIp").value = p.restrict_ip || "";
}
async function saveCurrentProject() {
  if (state.projectId == null) return;
  try {
    await api(`/api/projects/${state.projectId}`, "PATCH", { name: $("#cpName").value.trim(), note: $("#cpNote").value.trim(), restrict_ip: $("#cpIp").value.trim() });
    await loadProjects(); toast("已儲存本專案", "ok");
  } catch (e) { toast("儲存失敗:" + e.message, "err"); }
}

// ===== modals + theme =====================================================
function showModal(id) { $("#modalBackdrop").classList.remove("hidden"); $("#" + id).classList.remove("hidden"); }
function closeModals() {
  // A pending confirm takes priority: cancel it without nuking the modal beneath.
  if (_confirmResolve) { resolveConfirm(false); return; }
  $("#modalBackdrop").classList.add("hidden");
  $$(".modal").forEach(m => m.classList.add("hidden"));
  state.detailId = null;
}

// Reusable confirm dialog — every destructive/mutating action routes through
// this instead of window.confirm/alert. Returns a Promise<boolean>.
let _confirmResolve = null;
function confirmModal(opts) {
  opts = opts || {};
  return new Promise(resolve => {
    _confirmResolve = resolve;
    $("#confirmTitle").textContent = opts.title || "請確認";
    // body is built by callers with esc() on any dynamic text, so innerHTML is safe here
    $("#confirmBody").innerHTML = opts.message || "";
    const ok = $("#confirmOk"), cancel = $("#confirmCancel");
    ok.textContent = opts.okText || "確定";
    cancel.textContent = opts.cancelText || "取消";
    ok.classList.toggle("danger-btn", opts.danger !== false);
    ok.classList.toggle("primary", opts.danger === false);
    $("#modalBackdrop").classList.remove("hidden");
    $("#confirmModal").classList.remove("hidden");
    ok.onclick = () => resolveConfirm(true);
    cancel.onclick = () => resolveConfirm(false);
  });
}
function resolveConfirm(val) {
  const r = _confirmResolve; _confirmResolve = null;
  $("#confirmModal").classList.add("hidden");
  if ($$(".modal:not(.hidden)").length === 0) $("#modalBackdrop").classList.add("hidden");
  if (r) r(val);
}
// ===== collapsible + resizable panels (persisted) =========================
function panelCollapsed(side) { try { return localStorage.getItem(side === "left" ? "panelLeft" : "panelRight") === "0"; } catch (e) { return false; } }
function applyPanelWidths() {
  try {
    const sw = localStorage.getItem("panelLeftW"); if (sw) $("#scanSidebar").style.width = sw + "px";
    const tw = localStorage.getItem("panelRightW"); if (tw) $("#treePanel").style.width = tw + "px";
  } catch (e) {}
}
function syncPanels() {
  // Keep the left queue + right record tree on the dashboard AND the settings
  // page (they only disappear on the first-run "projects" entry, which has no
  // project selected yet). Collapse toggles are still respected in both views.
  const keep = state.view === "dashboard" || state.view === "settings";
  const lc = panelCollapsed("left"), rc = panelCollapsed("right");
  const showL = keep && !lc, showR = keep && !rc;
  $("#scanSidebar").classList.toggle("hidden", !keep); $("#scanSidebar").classList.toggle("collapsed", lc);
  $("#treePanel").classList.toggle("hidden", !keep); $("#treePanel").classList.toggle("collapsed", rc);
  $("#resizerLeft").classList.toggle("hidden", !showL);
  $("#resizerRight").classList.toggle("hidden", !showR);
  $("#toggleLeftBtn").classList.toggle("off", lc);
  $("#toggleRightBtn").classList.toggle("off", rc);
  applyPanelWidths();
}
function togglePanel(side) {
  const kkey = side === "left" ? "panelLeft" : "panelRight";
  let cur = "1"; try { cur = localStorage.getItem(kkey) || "1"; } catch (e) {}
  try { localStorage.setItem(kkey, cur === "0" ? "1" : "0"); } catch (e) {}
  syncPanels();
}
function setupResizer(handleSel, panelSel, side, storeKey) {
  const handle = $(handleSel), panel = $(panelSel);
  if (!handle || !panel) return;
  let startX = 0, startW = 0, dragging = false;
  handle.addEventListener("mousedown", e => {
    dragging = true; startX = e.clientX; startW = panel.getBoundingClientRect().width;
    handle.classList.add("dragging"); document.body.style.userSelect = "none";
    e.preventDefault();
  });
  window.addEventListener("mousemove", e => {
    if (!dragging) return;
    const dx = e.clientX - startX;
    let w = side === "left" ? startW + dx : startW - dx;
    w = Math.max(200, Math.min(640, w));
    panel.style.width = w + "px";
  });
  window.addEventListener("mouseup", () => {
    if (!dragging) return; dragging = false;
    handle.classList.remove("dragging"); document.body.style.userSelect = "";
    try { localStorage.setItem(storeKey, String(Math.round(panel.getBoundingClientRect().width))); } catch (e) {}
  });
}

function toggleTheme(e) {
  const cur = document.documentElement.getAttribute("data-theme");
  const next = cur === "light" ? "dark" : (cur === "dark" ? "light" : (matchMedia("(prefers-color-scheme: dark)").matches ? "light" : "dark"));
  const apply = () => {
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("theme", next); } catch (e) {}
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", next === "light" ? "#fbfbfd" : "#000000");
  };
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const root = document.documentElement;
  if (!root.startViewTransition || reduce) { apply(); return; }
  // circular-expand wipe from the click point (owner signature)
  root.style.setProperty("--vt-x", ((e && e.clientX) || window.innerWidth) + "px");
  root.style.setProperty("--vt-y", ((e && e.clientY) || 0) + "px");
  root.classList.add("theme-wipe");
  const t = root.startViewTransition(apply);
  t.finished.finally(() => root.classList.remove("theme-wipe"));
}

// ===== templates preload (for composer default apply) =====================
async function loadTemplates(applyLast) {
  state.templates = await api("/api/templates");
  const tool = selectedTool(); if (tool) populateTemplateDropdown(tool);
  if (applyLast) {
    let last = ""; try { last = localStorage.getItem("lastTool") || ""; } catch (e) {}
    if (last && SCHEMAS[last]) selectTool(last, { autoDefault: true });
  }
}

// ===== init ===============================================================
function init() {
  $("#projectsBtn").onclick = () => showProjectsView(false);
  $("#projectsBackBtn").onclick = () => { if (state.projectId != null) showDashboard(); else toast("請先建立一個專案", "err"); };
  $("#openNewProjectBtn").onclick = openNewProject;
  $("#npCreate").onclick = createProjectEntry;

  $("#parseBtn").onclick = parseRequest;
  $("#pasteBtn").onclick = pasteFromClipboard;
  $("#launchBtn").onclick = launch;
  $("#refreshBtn").onclick = loadScans;
  $("#stopAllBtn").onclick = stopAll;
  $("#treeExpandAll").onclick = treeExpandAll;
  $("#treeCollapseAll").onclick = treeCollapseAll;
  $("#statusFilter").onchange = loadScans;
  $$("[data-sel]").forEach(b => b.onclick = () => selectParams(b.dataset.sel));
  $$('input[name="tool"]').forEach(r => r.onchange = () => selectTool(r.value, { autoDefault: true }));
  $("#applyTplBtn").onclick = applySelectedTemplate;
  $("#templateSelect").onchange = applySelectedTemplate;
  $("#editTplLink").onclick = () => showSettings("templates");

  $("#settingsBtn").onclick = () => showSettings("general");
  $("#settingsBackBtn").onclick = showDashboard;
  $$("#settingsTabs .tab").forEach(t => t.onclick = () => switchTab(t.dataset.tab));
  $("#setSave").onclick = saveGeneralSettings;
  $("#rAdd").onclick = addRule;
  $$("#ruleScopeTabs .subtab").forEach(t => t.onclick = () => setRuleScope(t.dataset.scope));
  $("#cpSave").onclick = saveCurrentProject;

  $$('input[name="teTool"]').forEach(r => r.onchange = () => teSelectTool(r.value));
  $$("#tplToolTabs .subtab").forEach(t => t.onclick = () => setTplTool(t.dataset.tpltool));
  setupTplResizer();
  $("#teNewBtn").onclick = teNewTemplate;
  $("#teSave").onclick = teSave;
  $("#teDelete").onclick = teDelete;

  $("#themeBtn").onclick = toggleTheme;
  $("#toggleLeftBtn").onclick = () => togglePanel("left");
  $("#toggleRightBtn").onclick = () => togglePanel("right");
  $("#ipRefreshBtn").onclick = doIpRefresh;
  setupResizer("#resizerLeft", "#scanSidebar", "left", "panelLeftW");
  setupResizer("#resizerRight", "#treePanel", "right", "panelRightW");
  syncPanels();
  $("#sdDelete").onclick = () => { if (state.detailId != null) deleteScan(state.detailId); };
  $("#modalBackdrop").onclick = closeModals;
  $$("[data-close]").forEach(b => b.onclick = closeModals);
  document.addEventListener("keydown", e => { if (e.key === "Escape") closeModals(); });

  loadProjects().then(ok => { if (ok) { showDashboard(); loadScans(); loadTemplates(true); } });
  // IP: initial fetch + countdown clock, interval from settings
  api("/api/settings").then(s => { state.settings = s; setIpSeconds(s.ip_refresh_seconds); }).catch(() => {});
  doIpRefresh(); refreshHealth();
  setInterval(tick, 1500);
  setInterval(ipTick, 1000);
  setInterval(refreshHealth, 15000);
}
document.addEventListener("DOMContentLoaded", init);
