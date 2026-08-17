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
  treeExpanded: null, treeKey: "", currentTarget: null, scanMode: "advanced",
  detailId: null, detailOffset: 0, detailCache: "",
  logView: null,   // "highlighted" | "original"; null -> fall back to settings.default_log_view
  pureRaw: true,   // 原始輸出 only shows the tool's own output (hide our開始/結束/目標/【判定】 wrappers)
  editingTplId: null,
  skipCollapsed: true,   // auto-skipped params start collapsed at the bottom
  headerCollapsed: true, // Header-location params start collapsed too
  ruleScope: "global",   // filter-rules sub-tab: "global" | "project"
  tplTool: "sqlmap",     // template editor sub-tab: "sqlmap" | "ghauri"
  ipSeconds: 60, ipRemaining: 60,
  tabs: [], activeTabId: null,   // multi-tab composer (each tab = one composition)
};
let _tabSeq = 1;

// ===== multi-tab composer =================================================
// Each tab holds an independent composition. state.parsed/state.params are the
// LIVE (active) tab; we snapshot them into the tab record on switch/close.
function _blankTab() {
  return { id: _tabSeq++, kind: "compose", title: "新分頁", raw: "", parsed: null, params: [], tool: null, options: null, note: "" };
}
function _detailTab(scanId) {
  const s = (state.allScans || state.scans || []).find(x => x.id === scanId);
  return { id: _tabSeq++, kind: "detail", scanId, title: s ? ("#" + scanId + " " + (s.tool || "")) : ("#" + scanId) };
}
function _activeTab() { return (state.tabs || []).find(x => x.id === state.activeTabId); }
function snapshotComposeTab() {
  const t = _activeTab();
  if (!t || t.kind !== "compose") return;   // detail tabs are read-only, nothing to snapshot
  t.raw = ($("#rawInput") && $("#rawInput").value) || "";
  t.parsed = state.parsed;
  t.params = state.params;
  const tool = selectedTool();
  t.tool = tool || null;
  t.options = tool ? gatherOptions("#optGrid", "#optToggles") : null;
  t.scanMode = state.scanMode;
  t.note = ($("#scanNote") && $("#scanNote").value) || "";
  t.title = t.parsed ? (t.parsed.endpoint || (t.parsed.parsed && t.parsed.parsed.url) || "新分頁")
    : (t.raw.trim() ? "未解析請求" : "新分頁");
}
// One-shot center-panel crossfade on a REAL tab/detail switch, keyed so the 2s poll
// re-render of identical content can never replay it. Called only from applyTab.
function animateCenterSwap(key) {
  const compose = $("#composeArea"), detail = $("#detailArea");
  if (!compose || !detail) return;
  const el = detail.classList.contains("hidden") ? compose : detail;   // whichever we switched to
  if (el.dataset.swapKey === key) return;                              // same target -> no re-trigger
  el.dataset.swapKey = key;
  el.classList.remove("swap-anim");
  void el.offsetWidth;                                                 // reflow so the keyframes restart
  el.classList.add("swap-anim");
  el.addEventListener("animationend", function done() { el.classList.remove("swap-anim"); }, { once: true });
}
function applyTab(t) {
  if (state.cmdEditing) _exitCmdEdit();   // never carry command-edit mode across a tab/project switch
  state.activeTabId = t.id;
  if (t.kind === "detail") {                 // read-only scan view: swap composer -> detail
    $("#composeArea").classList.add("hidden");
    $("#detailArea").classList.remove("hidden");
    loadDetailInto(t.scanId);
    renderComposeTabs();
    renderTreeIfChanged(true);
    renderBoardIfChanged();     // drop the "待解析" placeholder (this is a detail tab)
    animateCenterSwap("scan:" + t.scanId);
    saveTabs();
    return;
  }
  state.detailId = null;
  $("#detailArea").classList.add("hidden");
  $("#composeArea").classList.remove("hidden");
  state.parsed = t.parsed || null;
  state.params = t.params || [];
  if ($("#rawInput")) $("#rawInput").value = t.raw || "";
  if ($("#parseWarn")) $("#parseWarn").textContent = "";
  if (t.parsed) {
    renderParseSummary(t.parsed); renderParams(); locateInTree(t.parsed);
    $("#resultCard").classList.remove("hidden");
    $("#toolCard").classList.remove("hidden");
  } else {
    $("#resultCard").classList.add("hidden");
    $("#toolCard").classList.add("hidden");
    $("#modeCard").classList.add("hidden");
    $("#templateCard").classList.add("hidden");
    $("#optionsCard").classList.add("hidden");
    $("#composeFooter").classList.add("hidden");
  }
  if (t.tool) {
    selectTool(t.tool);                                   // renders options + shows mode/options/footer
    applyOptions(t.options || {}, "#optGrid", "#optToggles");
    setScanMode(t.scanMode);                              // per-tab mode (defaults to advanced)
  } else {
    $$('input[name="tool"]').forEach(r => r.checked = false);
    $("#toolOptions").classList.add("hidden");
    $("#modeCard").classList.add("hidden");
    $("#templateCard").classList.add("hidden");
    $("#optionsCard").classList.add("hidden");
    $("#composeFooter").classList.add("hidden");
  }
  if ($("#scanNote")) $("#scanNote").value = t.note || "";
  updateCmdPreview();
  renderComposeTabs();
  renderTreeIfChanged(true);
  renderBoardIfChanged();           // show/hide the left "待解析" placeholder for this tab
  if (!t.parsed) locatePending();   // unparsed compose tab -> flash the "待解析" placeholder
  animateCenterSwap("compose:" + t.id);
  saveTabs();
}
function composeTabNew() {
  snapshotComposeTab();
  const t = _blankTab();
  state.tabs.push(t);
  applyTab(t);
}
function composeTabSwitch(id) {
  if (id === state.activeTabId) return;
  snapshotComposeTab();
  const t = state.tabs.find(x => x.id === id);
  if (t) applyTab(t);
}
async function composeTabClose(id) {
  if (state.tabs.length <= 1) return;
  const t = state.tabs.find(x => x.id === id); if (!t) return;
  if (t.pinned) { toast("此分頁已釘選,先取消釘選(📌)才能關閉", ""); return; }   // pinned = protected
  const live = id === state.activeTabId;
  // always confirm so a stray click on ✕ never loses a tab
  const msg = t.kind === "detail" ? "關閉這個唯讀詳情分頁?"
    : ((live ? ($("#rawInput").value.trim()) : (t.raw && t.raw.trim()))
        ? "這個分頁有內容,關閉會<b>捨棄</b>它。確定?" : "關閉這個分頁?");
  const ok = await confirmModal({ title: "關閉分頁", message: msg, okText: "關閉分頁", cancelText: "取消" });
  if (!ok) return;
  const idx = state.tabs.findIndex(x => x.id === id);
  state.tabs.splice(idx, 1);
  if (live) applyTab(state.tabs[Math.max(0, idx - 1)]);
  else renderComposeTabs();
}
function resetComposeTabs() {
  state.tabs = [_blankTab()];
  applyTab(state.tabs[0]);
}
// persist the whole tab set so F5 / server restart keeps the workspace intact.
// (compose tabs hold the raw request -> stored in this browser's localStorage only.)
// compose tabs are scoped PER PROJECT (they hold that project's raw requests/cookies) --
// a single global key leaked one project's tabs into another. Switching projects saves
// the old project's tabs and restores the new one's (see setProject).
function tabsKey() { return "composeTabs:" + (state.projectId != null ? state.projectId : "none"); }
function _tabsBlob() { return JSON.stringify({ tabs: state.tabs, activeTabId: state.activeTabId, seq: _tabSeq }); }
// localStorage is the fast local cache (per-browser); the DB copy (in data/) is what lets the
// tabs survive a move to another machine. Detail tabs are just a scanId ref, so nothing is
// duplicated -- on restore they re-load their scan from the (moved) DB.
let _tabsDbTimer = null;
function _persistTabsToDb() {
  const pid = state.projectId; if (pid == null) return;
  const blob = _tabsBlob();
  clearTimeout(_tabsDbTimer);
  _tabsDbTimer = setTimeout(() => { api("/api/projects/" + pid + "/tabs", "POST", { tabs_json: blob }).catch(() => {}); }, 800);
}
// flush a SPECIFIC project's current tabs to the DB immediately (not debounced). Used when
// leaving a project -> the shared debounce would otherwise be cancelled by the new project.
function _flushTabsToDbNow(pid) {
  if (pid == null) return;
  clearTimeout(_tabsDbTimer);
  const body = JSON.stringify({ tabs_json: _tabsBlob() });
  try {
    if (navigator.sendBeacon) navigator.sendBeacon("/api/projects/" + pid + "/tabs", new Blob([body], { type: "application/json" }));
    else api("/api/projects/" + pid + "/tabs", "POST", { tabs_json: _tabsBlob() }).catch(() => {});
  } catch (e) {}
}
function saveTabs() {
  try {
    snapshotComposeTab();
    localStorage.setItem(tabsKey(), _tabsBlob());
  } catch (e) {}
  _persistTabsToDb();
}
function restoreTabs() {
  let data = null;
  // Prefer the DB copy: it travels with data/ and is always correct for THIS dataset. localStorage
  // is keyed by a numeric project id that collides across swapped data/ sets, so trusting it first
  // could serve another dataset's tabs (with its cookies) -> only use it as a crash-recovery
  // fallback when the DB copy is empty.
  const proj = (state.projects || []).find(p => p.id === state.projectId);
  if (proj && proj.tabs_json) { try { data = JSON.parse(proj.tabs_json); } catch (e) {} }
  if (!(data && Array.isArray(data.tabs) && data.tabs.length)) {
    try { data = JSON.parse(localStorage.getItem(tabsKey()) || "null"); } catch (e) {}
  }
  if (data && Array.isArray(data.tabs) && data.tabs.length) {
    state.tabs = data.tabs;
    state.tabs.forEach(t => { if (!t.kind) t.kind = "compose"; });
    state.activeTabId = (data.activeTabId != null && state.tabs.some(t => t.id === data.activeTabId))
      ? data.activeTabId : state.tabs[0].id;
    _tabSeq = Math.max(data.seq || 0, ...state.tabs.map(t => t.id || 0)) + 1;
  } else {
    state.tabs = [_blankTab()];
    state.activeTabId = state.tabs[0].id;
  }
}
// drag-to-reorder compose tabs (insertion caret shows the exact drop gap)
let _dragTabId = null;
function _clearDrop(box) { $$(".ctab.drop-before, .ctab.drop-after", box).forEach(x => x.classList.remove("drop-before", "drop-after")); }
function _reorderTab(fromId, toId, after) {
  if (fromId == null || fromId === toId) return;
  const from = state.tabs.findIndex(t => t.id === fromId);
  if (from < 0 || state.tabs.findIndex(t => t.id === toId) < 0) return;
  const [moved] = state.tabs.splice(from, 1);
  const to = state.tabs.findIndex(t => t.id === toId);   // recompute index after removal
  state.tabs.splice(after ? to + 1 : to, 0, moved);
  renderComposeTabs(); saveTabs();
}
function renderComposeTabs() {
  const box = $("#composeTabs"); if (!box) return;
  box.innerHTML = (state.tabs || []).map(t =>
    `<div class="ctab ${t.kind === "detail" ? "ctab-detail" : ""} ${t.id === state.activeTabId ? "active" : ""}" data-ctab="${t.id}" draggable="true" title="${esc(t.title || "新分頁")}">
       <span class="ctab-title">${esc(t.title || "新分頁")}</span>
       <button class="ctab-pin${t.pinned ? " pinned" : ""}" data-ctabpin="${t.id}" title="${t.pinned ? "已釘選 · 點擊取消釘選" : "釘選(避免被關閉)"}">📌</button>
       <button class="ctab-close${(t.pinned || state.tabs.length <= 1) ? " off" : ""}" data-ctabclose="${t.id}" title="關閉分頁">✕</button>
     </div>`).join("") +
    `<button type="button" class="ctab-new" id="ctabNew" title="開新分頁">＋</button>`;
  $$("[data-ctab]", box).forEach(el => {
    el.onclick = (e) => {
      if (e.target.closest("[data-ctabclose]")) return;
      composeTabSwitch(Number(el.dataset.ctab));
    };
    el.onmousedown = (e) => { if (e.button === 1) e.preventDefault(); };            // no middle-click autoscroll
    el.onauxclick = (e) => { if (e.button === 1) { e.preventDefault(); composeTabClose(Number(el.dataset.ctab)); } };   // middle-click = close
    el.ondragstart = (e) => { _dragTabId = Number(el.dataset.ctab); try { e.dataTransfer.effectAllowed = "move"; e.dataTransfer.setData("text/plain", String(_dragTabId)); } catch (x) {} el.classList.add("dragging"); };
    el.ondragend = () => { el.classList.remove("dragging"); _clearDrop(box); _dragTabId = null; };
    el.ondragover = (e) => {
      e.preventDefault(); try { e.dataTransfer.dropEffect = "move"; } catch (x) {}
      _clearDrop(box);
      if (_dragTabId == null || Number(el.dataset.ctab) === _dragTabId) return;
      const r = el.getBoundingClientRect();
      el.classList.add((e.clientX - r.left) > r.width / 2 ? "drop-after" : "drop-before");   // caret before/after by cursor
    };
    el.ondragleave = () => el.classList.remove("drop-before", "drop-after");
    el.ondrop = (e) => {
      e.preventDefault();
      const r = el.getBoundingClientRect();
      const after = (e.clientX - r.left) > r.width / 2;
      _clearDrop(box);
      _reorderTab(_dragTabId, Number(el.dataset.ctab), after);
    };
  });
  $$("[data-ctabclose]", box).forEach(b => b.onclick = (e) => { e.stopPropagation(); composeTabClose(Number(b.dataset.ctabclose)); });
  $$("[data-ctabpin]", box).forEach(b => b.onclick = (e) => { e.stopPropagation(); const t = state.tabs.find(x => x.id === Number(b.dataset.ctabpin)); if (t) { t.pinned = !t.pinned; renderComposeTabs(); saveTabs(); } });
  const nb = $("#ctabNew"); if (nb) nb.onclick = () => composeTabNew();
}
// open (or focus) a READ-ONLY detail tab for a scan (replaces the old modal)
function openScanDetail(scanId) {
  snapshotComposeTab();   // always save current compose edits first (no-op on a detail tab)
  let t = (state.tabs || []).find(x => x.kind === "detail" && x.scanId === scanId);
  if (!t) { t = _detailTab(scanId); state.tabs.push(t); }
  applyTab(t);
}
// load a scan's read-only detail into #detailArea + cross-highlight left & tree
async function loadDetailInto(scanId) {
  // restore THIS scan's cached log instead of blanking -> revisits paint instantly and a
  // switch never shows an empty shell; the full fetch then hydrates IN PLACE (setHTML no-op).
  state.detailId = scanId;
  state.logs = state.logs || {};
  const L = state.logs[scanId] || { cache: "", offset: 0 };
  state.detailCache = L.cache; state.detailOffset = L.offset;
  const cached = (state.allScans || []).find(x => x.id === scanId);
  if (cached) renderScanDetail(cached);
  _renderDetailLog();   // paint the restored log (or empty) -- never a "(載入中…)" blank
  // loader shows ONLY if a cold log hasn't landed within 250ms (fast switches never flash it)
  const _lt = setTimeout(() => { if (state.detailId === scanId && !state.detailCache) { const lv = $("#sdLog"); if (lv) lv.textContent = "載入中…"; } }, 250);
  let s = null;
  try { s = await api(`/api/scans/${scanId}`); } catch (e) {}
  if (state.detailId !== scanId) { clearTimeout(_lt); return; }   // user switched mid-request -> abandon
  if (!s && !cached) {   // scan gone (deleted, or a restored stale detail tab) -> show it, don't leave a stale pane
    clearTimeout(_lt);
    const _t = $("#sdTitle"); if (_t) _t.textContent = "#" + scanId + " 已不存在";
    ["#sdMeta", "#sdActions", "#sdVerdict", "#sdParams", "#sdRequest", "#sdFindings"].forEach(sel => { const el = $(sel); if (el) el.innerHTML = ""; });
    const lv = $("#sdLog"); if (lv) lv.textContent = "此掃描已被刪除或不存在(可關閉此分頁)。";
    return;
  }
  if (s) renderScanDetail(s);
  await pullDetailLog();
  clearTimeout(_lt);
  if (state.detailId !== scanId) return;
  // transient reveal path to THIS scan; replacing it auto-collapses the previous
  // click's reveal (no accumulation), while manual expansions stay untouched.
  state.tempScanPath = _scanRevealKeys(s);
  flashScan(scanId);             // state-derived flash -> survives poll re-renders
  renderTreeIfChanged(true);     // templates now emit .flash-target on this scan's rows
  renderBoardIfChanged(true);
  highlightScan(scanId);         // smooth-scroll both panels so the row slides into view
}
// Cross-panel "reveal & highlight" (brushing-and-linking). Research-backed recipe:
// smooth-scroll the row into view (so it visibly slides in) + an in-place outline/
// glow pulse (Yellow-Fade shape, keeps the row's text legible) -- NOT a flying
// marker (studies rate travelling arrows worst) + a persistent selected state
// (.active/.detail-active). The transient flash is STATE-DERIVED (state.flashScanId
// emitted by the row templates) so a poll re-render can't wipe it mid-pulse.
function _scrollParent(el) {
  let p = el && el.parentElement;
  while (p) {
    const oy = getComputedStyle(p).overflowY;
    if ((oy === "auto" || oy === "scroll") && p.scrollHeight > p.clientHeight + 2) return p;
    p = p.parentElement;
  }
  return null;
}
// eased scroll so the row slides into view (know up vs down). Duration adapts to
// distance (220-360ms, ease-out); skipped only if already centred. Manual rAF tween
// (not CSS scroll-behavior), so it animates even under prefers-reduced-motion -- the
// locate cue is essential "where is it" feedback and is kept on deliberately.
function _animScroll(el) {
  if (!el) return;
  const box = _scrollParent(el);
  if (!box) { try { el.scrollIntoView({ block: "center" }); } catch (e) {} return; }
  const cr = box.getBoundingClientRect(), er = el.getBoundingClientRect();
  const want = box.scrollTop + (er.top - cr.top) - (box.clientHeight / 2) + (el.offsetHeight / 2);
  const start = box.scrollTop;
  const end = Math.max(0, Math.min(box.scrollHeight - box.clientHeight, want));
  const dist = end - start;
  if (Math.abs(dist) < 4) return;
  const dur = Math.max(220, Math.min(360, 160 + Math.abs(dist) * 0.5));
  const t0 = performance.now(), ease = t => 1 - Math.pow(1 - t, 3);
  (function step(now) {
    const t = Math.min(1, (now - t0) / dur);
    box.scrollTop = start + dist * ease(t);
    if (t < 1) requestAnimationFrame(step);
  })(performance.now());
}
// direct pulse for a NON-scan-row element (synthetic node / ancestor node)
function _pulse(el) {
  if (!el) return;
  el.classList.remove("flash-target"); void el.offsetWidth; el.classList.add("flash-target");
  setTimeout(() => { try { el.classList.remove("flash-target"); } catch (e) {} }, 1600);
}
// state-derived transient flash for a scan row: the templates emit .flash-target
// while s.id === state.flashScanId, so re-renders re-apply it; cleared after ~1.6s.
function flashScan(scanId) {
  state.flashScanId = scanId;
  clearTimeout(state._flashTimer);
  state._flashTimer = setTimeout(() => {
    state.flashScanId = null;
    renderBoardIfChanged(true); renderTreeIfChanged(true);
  }, 1600);
}
function highlightScan(scanId) {
  _animScroll(document.querySelector(`.scan-row[data-id="${scanId}"]`));   // left row (flash via state)
  const trow = document.querySelector(`.tscan[data-scan="${scanId}"]`);
  if (trow) { _animScroll(trow); return; }                                // tree row visible (flash via state)
  // collapsed -> scroll + pulse the deepest visible ancestor node
  const sc = (state.allScans || []).find(x => x.id === scanId);
  if (!sc) return;
  const { host, path } = _epParts({ endpoint: sc.endpoint, url: sc.url });
  const target = "p:" + host + "|" + path;
  let best = null, bestLen = -1;
  document.querySelectorAll("#treeBox .trow[data-key]").forEach(el => {
    const k = el.getAttribute("data-key");
    const isAncestor = k === "h:" + host || (k.startsWith("p:" + host + "|") && (k === target || target.startsWith(k + "/")));
    if (isAncestor && k.length > bestLen) { best = el; bestLen = k.length; }
  });
  _animScroll(best); _pulse(best);
}
// the keys needed to reveal a scan's record row (host + every path prefix so the
// endpoint expands and its scans show). Returned as a TRANSIENT set.
function _scanRevealKeys(s) {
  const keys = new Set();
  if (!s || typeof s !== "object") return keys;
  try {
    const { host, path } = _epParts({ endpoint: s.endpoint, url: s.url });
    keys.add("h:" + host);
    let acc = "";
    for (const seg of String(path).split("/").filter(x => x !== "")) { acc += "/" + seg; keys.add("p:" + host + "|" + acc); }
  } catch (e) {}
  return keys;
}

// ===== option schemas (keys = backend driver option names) ================
// Defaults + ranges verified against vendored source:
//   sqlmap-1.10/lib/core/defaults.py  &  ghauri-1.4.3/ghauri/scripts/ghauri.py
// `def` = the tool's own default (shown to the user; leaving a field blank uses it).
// type "slider" renders a range + a synced manual number box.
const COMMON_TOGGLES = [
  { key: "force_ssl", type: "segbool", label: "連線協定", def: true, onLabel: "HTTPS", offLabel: "HTTP",
    desc: "請求用哪種協定送出。兩個工具行為一致(sqlmap 靠 --force-ssl、ghauri 靠改寫 Referer,結果都是同一個協定);憑證兩邊都『不驗證』(自簽/過期也能測)。打 http-only / localhost 選 HTTP。" },
  { key: "random_agent", label: "隨機 User-Agent", desc: "每次用隨機瀏覽器 UA,降低被指紋辨識/擋下。" },
  { key: "text_only", label: "只比對文字", desc: "只比對回應的純文字、忽略 HTML 標籤;頁面雜訊多時較穩(--text-only)。" },
];
const COMMON_FIELDS = [
  { key: "proxy", label: "Proxy", type: "text", placeholder: "http://127.0.0.1:8080",
    presets: [["http://127.0.0.1:8080", "Burp / ZAP / mitmproxy"], ["http://127.0.0.1:8888", "Fiddler / Charles"],
      ["socks5://127.0.0.1:9050", "Tor 服務"], ["socks5://127.0.0.1:9150", "Tor Browser"]],
    desc: "把流量導到代理(常用來接 Burp/ZAP 觀察 payload,或走 Tor)。點下方常用值或自訂。預設不使用。" },
  { key: "headers", label: "額外標頭", type: "headers", wide: true,
    desc: "自訂請求標頭:一組一組填(名稱 + 值),可新增/刪除(--headers)。" },
  { key: "ignore_code", label: "忽略狀態碼", type: "text", placeholder: "401,403",
    chips: ["401", "403", "404", "429", "500", "502", "503"],
    desc: "忽略這些 HTTP 狀態碼(逗號分隔),避免固定錯誤碼中斷判定(--ignore-code)。點下方常用碼加入/移除,或自行輸入。" },
  { key: "test_string", label: "True 標記字串", type: "text",
    desc: "只有注入成功才會出現的字串;頁面內容動態、自動判定不穩時用它鎖定(--string)。" },
  { key: "not_string", label: "False 標記字串", type: "text",
    desc: "只有注入失敗才會出現的字串(--not-string)。" },
  { key: "code", label: "True 狀態碼", type: "number",
    desc: "把某個 HTTP 狀態碼當作 True 判定(--code),如 200。" },
  { key: "extra_flags", label: "額外參數(原樣傳給工具)", type: "text", wide: true, placeholder: "例:--prefix ) --suffix -- -",
    desc: "任何上面沒有的旗標,原封不動接到指令後面(進階)。" },
];
const SCHEMAS = {
  sqlmap: {
    fields: [
      { key: "level", label: "Level", type: "slider", min: 1, max: 5, def: 1,
        desc: "測試深度(1–5)。1=只測 GET/POST;2=加測 Cookie;3=加測 User-Agent/Referer 標頭;4=連平常略過的 CSRF/session 類參數也一起測(較易干擾應用狀態);5=加測 Host 標頭、payload 最多。越高越慢、噪音越大。" },
      { key: "risk", label: "Risk", type: "slider", min: 1, max: 3, def: 1,
        desc: "風險(1–3)。1=安全偵測 payload(無副作用);2=加重負載時間盲注(heavy-query/BENCHMARK,會讓 DB CPU 飆高,慢環境恐影響服務);3=加 OR-based(WHERE 條件對整表每一列成立,注入點若在 UPDATE/DELETE 可能改動多列資料)。日常授權測試用 1。" },
      { key: "technique", label: "Technique(勾選)", type: "checks", join: "", def: "BEUSTQ",
        options: [["B", "B 布林盲注"], ["E", "E 報錯"], ["U", "U 聯合查詢"], ["S", "S 堆疊查詢"], ["T", "T 時間盲注"], ["Q", "Q 內聯"]],
        desc: "勾選要用的技術;全部不勾=用工具預設(全部)。" },
      { key: "threads", label: "Threads", type: "slider", min: 1, max: 10, def: 1,
        desc: "併發 HTTP 請求數:越高越快,但越容易觸發防護或造成漏判。sqlmap 上限 10。" },
      { key: "timeout", label: "Timeout", type: "slider", min: 5, max: 120, step: 5, def: 30,
        desc: "單一連線的逾時秒數。" },
      { key: "time_sec", label: "Time-sec", type: "slider", min: 1, max: 15, def: 5,
        desc: "時間盲注時要求資料庫延遲的秒數。太短易誤判、太長變慢。" },
      { key: "delay", label: "Delay", type: "slider", min: 0, max: 10, def: 0,
        desc: "每個請求之間的延遲秒數,用來避開速率限制。" },
      { key: "retries", label: "Retries", type: "slider", min: 0, max: 10, def: 3,
        desc: "連線逾時時的重試次數。" },
      { key: "dbms", label: "DBMS", type: "select",
        options: [["", "自動偵測(建議)"], ["MySQL", "MySQL"], ["PostgreSQL", "PostgreSQL"],
          ["Microsoft SQL Server", "Microsoft SQL Server"], ["Oracle", "Oracle"], ["SQLite", "SQLite"],
          ["Microsoft Access", "Microsoft Access"], ["IBM DB2", "IBM DB2"], ["Firebird", "Firebird"],
          ["MariaDB", "MariaDB"], ["SAP MaxDB", "SAP MaxDB"], ["Sybase", "Sybase"], ["HSQLDB", "HSQLDB"],
          ["H2", "H2"], ["Informix", "Informix"]],
        desc: "強制指定後端資料庫。手打不支援的值會讓 sqlmap 直接中止,故改用選單。預設自動偵測。" },
      { key: "tamper", label: "Tamper(繞 WAF,可多選)", type: "checks", join: ",",
        options: [
          ["space2comment", "space2comment", "空白換 /**/。WAF 以空白為特徵過濾時首選(比 space2plus 穩)。通用"],
          ["randomcase", "randomcase", "關鍵字大小寫隨機。WAF 用寫死大小寫的簽章時繞過;最泛用、低風險。通用"],
          ["charencode", "charencode", "整段 URL 編碼。WAF 比對前沒先 decode 時有效(現代 WAF 多半無效)。通用"],
          ["equaltolike", "equaltolike", "= 換成 LIKE。WAF 擋 = 時用(注意 % _ 會被當萬用字元)。通用"],
          ["between", "between", "> 換 NOT BETWEEN、= 換 BETWEEN。WAF 擋 > 或 = 運算子時用。通用"],
          ["greatest", "greatest", "> 換成 GREATEST()。WAF 擋 > 時用;⚠ 舊版 MSSQL 無此函式。"],
          ["apostrophemask", "apostrophemask", "單引號換全形。WAF 只看 ASCII ' 、且後端會把全形折回 ASCII 時才有效。"],
          ["base64encode", "base64encode", "整段 Base64。⚠ 僅『該參數應用會自行 base64-decode』時才有意義。"],
          ["space2plus", "space2plus", "空白換 +。⚠ sqlmap 之後會把 + 再編成 %2B 反而讓查詢失效,少用。"],
          ["percentage", "percentage", "每字元前加 %。⚠ 僅 ASP/IIS 平台有效,其他平台會破壞 payload。"],
          ["versionedmorekeywords", "versionedmorekeywords", "關鍵字用 /*!…*/ 版本化註解包起。⚠ 僅 MySQL;WAF 靠關鍵字簽章時強力繞過。"],
          ["modsecurityversioned", "modsecurityversioned", "整段用 /*!…*/ 版本化註解包起。⚠ 僅 MySQL;專打 ModSecurity。"],
        ],
        desc: "繞過 WAF 的 payload 變形腳本,可多選。⚠ 沒有『純利多』的 tamper——每個都是針對特定 WAF/DBMS 改寫 payload,對症才套;亂套可能讓 payload 失效或只對特定資料庫有效。上方大致由『通用/低風險』排到『窄/挑環境』。清單外的可用下方「額外參數」。" },
      { key: "prefix", label: "Prefix", type: "text",
        presets: [["'"], ["\""], ["')"], ["\")"], ["'))"], [")"]],
        desc: "在 payload 前面加固定字串,用來跳出注入情境。點下方常用值或自訂。" },
      { key: "suffix", label: "Suffix", type: "text",
        presets: [["-- -"], ["#"], ["-- "], ["/*"]],
        desc: "在 payload 後面加固定字串,通常用來註解掉其餘查詢。點下方常用值或自訂。" },
      { key: "regexp", label: "True 正則", type: "text",
        desc: "用正則判定 True(--regexp),進階替代 True 標記字串。" },
      { key: "auth_type", label: "HTTP 認證方式", type: "select",
        options: [["", "無"], ["Basic", "Basic"], ["Digest", "Digest"], ["NTLM", "NTLM"]],
        desc: "需 HTTP 認證的站台選這裡(--auth-type),搭配下方帳密。" },
      { key: "auth_cred", label: "HTTP 認證帳密", type: "text", placeholder: "user:pass",
        desc: "HTTP 認證帳密,格式 user:pass(--auth-cred)。" },
      { key: "csrf_token", label: "CSRF token 參數名", type: "text",
        desc: "有 anti-CSRF 的站:token 的參數名稱,sqlmap 每次自動帶最新值(--csrf-token)。" },
      { key: "csrf_url", label: "CSRF token 來源 URL", type: "text",
        desc: "抓 CSRF token 的來源頁(若與目標不同,--csrf-url)。" },
      { key: "sql_query", label: "執行 SQL", type: "text", danger: true, placeholder: "SELECT ...",
        desc: "⚠ 在目標上執行任意 SQL(--sql-query,可讀寫資料)。" },
      { key: "os_cmd", label: "執行 OS 命令", type: "text", danger: true, placeholder: "whoami",
        desc: "⚠ 透過注入在 DB 主機執行系統命令(--os-cmd,等同 RCE)。" },
      { key: "file_read", label: "讀取伺服器檔案", type: "text", danger: true, placeholder: "/etc/passwd",
        desc: "⚠ 讀取目標主機上的檔案(--file-read)。" },
      { key: "file_write", label: "上傳本機檔案", type: "text", danger: true, placeholder: "本機檔案路徑",
        desc: "⚠ 把本機檔案寫到目標(--file-write,常用於植入 webshell);需一併填「寫入目標路徑」。" },
      { key: "file_dest", label: "寫入目標路徑", type: "text", danger: true, placeholder: "/var/www/html/x.php",
        desc: "⚠ --file-write 的目標絕對路徑(--file-dest)。" },
    ],
    toggles: [
      { key: "get_banner", label: "取 banner", desc: "抓資料庫版本橫幅(--banner)。" },
      { key: "get_current_user", label: "目前使用者", desc: "抓目前 DB 連線使用者。" },
      { key: "get_current_db", label: "目前資料庫", desc: "抓目前使用的資料庫名。" },
      { key: "get_hostname", label: "主機名", desc: "抓 DB 伺服器主機名。" },
      { key: "get_dbs", label: "列舉 DB", desc: "列出所有資料庫(較慢)。" },
      { key: "is_dba", label: "是否 DBA", desc: "檢查目前使用者是否為資料庫管理員。" },
      { key: "dump", label: "匯出資料表", danger: true, desc: "⚠ 匯出資料表內容(--dump,會實際讀取並落地目標資料)。" },
      { key: "dump_all", label: "匯出整個 DB", danger: true, desc: "⚠ 匯出所有資料庫全部內容(--dump-all),量大且高度侵入。" },
      { key: "passwords", label: "抓密碼雜湊", danger: true, desc: "⚠ 匯出 DBMS 使用者密碼雜湊(--passwords)。" },
    ],
  },
  ghauri: {
    fields: [
      { key: "level", label: "Level", type: "slider", min: 1, max: 3, def: 1,
        desc: "測試深度(ghauri 1–3)。1=只測 GET/POST;2=加測 Cookie;3=加測 Header。越高越慢、噪音越大。" },
      { key: "technique", label: "Technique(勾選)", type: "checks", join: "", def: "BEST",
        options: [["B", "B 布林盲注"], ["E", "E 報錯"], ["S", "S 堆疊查詢"], ["T", "T 時間盲注"]],
        desc: "勾選要用的技術(ghauri 無 U 聯合);全部不勾=用預設 BEST。" },
      { key: "threads", label: "Threads", type: "slider", min: 1, max: 10, def: 1,
        desc: "併發 HTTP 請求數:越高越快,但越容易觸發防護或漏判。" },
      { key: "timeout", label: "Timeout", type: "slider", min: 5, max: 120, step: 5, def: 30,
        desc: "單一連線的逾時秒數。" },
      { key: "time_sec", label: "Time-sec", type: "slider", min: 1, max: 15, def: 5,
        desc: "時間盲注時要求資料庫延遲的秒數。" },
      { key: "delay", label: "Delay", type: "slider", min: 0, max: 10, def: 0,
        desc: "每個請求之間的延遲秒數,用來避開速率限制。" },
      { key: "retries", label: "Retries", type: "slider", min: 0, max: 10, def: 3,
        desc: "連線逾時時的重試次數。" },
      { key: "dbms", label: "DBMS", type: "select",
        options: [["", "自動偵測(建議)"], ["MySQL", "MySQL"], ["PostgreSQL", "PostgreSQL"],
          ["Microsoft SQL Server", "Microsoft SQL Server"], ["Oracle", "Oracle"]],
        desc: "強制指定後端資料庫。ghauri 支援 MySQL / PostgreSQL / MSSQL / Oracle。預設自動偵測。" },
      { key: "prefix", label: "Prefix", type: "text",
        presets: [["'"], ["\""], ["')"], ["\")"], ["'))"], [")"]],
        desc: "在 payload 前面加固定字串,用來跳出注入情境。點下方常用值或自訂。" },
      { key: "suffix", label: "Suffix", type: "text",
        presets: [["-- -"], ["#"], ["-- "], ["/*"]],
        desc: "在 payload 後面加固定字串,通常用來註解掉其餘查詢。點下方常用值或自訂。" },
    ],
    toggles: [
      { key: "get_banner", label: "取 banner", desc: "抓資料庫版本橫幅(--banner)。" },
      { key: "get_current_user", label: "目前使用者", desc: "抓目前 DB 連線使用者。" },
      { key: "get_current_db", label: "目前資料庫", desc: "抓目前使用的資料庫名。" },
      { key: "get_hostname", label: "主機名", desc: "抓 DB 伺服器主機名。" },
      { key: "get_dbs", label: "列舉 DB", desc: "列出所有資料庫(較慢)。" },
      { key: "dump", label: "匯出資料表", danger: true, desc: "⚠ 匯出資料表內容(--dump,會實際讀取目標資料)。" },
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
let _toastTimer = null;
function toast(msg, kind = "") {
  const t = $("#toast"); t.textContent = msg; t.className = "toast " + kind;
  clearTimeout(_toastTimer);   // don't let a prior toast's timer hide this one early
  _toastTimer = setTimeout(() => t.classList.add("hidden"), kind === "err" ? 6000 : 2800);
}
function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function fmtTime(ms) { return ms ? new Date(ms).toLocaleString() : ""; }
function fmtDur(ms) { if (!ms && ms !== 0) return ""; const s = Math.round(ms / 1000); return s < 60 ? s + "s" : Math.floor(s / 60) + "m" + (s % 60) + "s"; }

// ===== shared options renderer (composer + template editor) ===============
function optHead(f) {
  const def = f.def != null ? `<span class="opt-default">預設 ${esc(String(f.def))}</span>` : "";
  return `<div class="opt-head"><span class="opt-label">${esc(f.label)}</span>${def}</div>`;
}
function optDesc(f) { return f.desc ? `<div class="opt-desc">${esc(f.desc)}</div>` : ""; }
function renderFieldHtml(f) {
  const wide = f.wide ? " wide" : "";
  if (f.type === "segbool") {
    // a two-choice segmented control backed by a boolean option (e.g. HTTPS/HTTP for
    // force_ssl). gatherOptions/applyOptions read/write the active segment. data-defon
    // preserves the "store the boolean explicitly" semantics of a default-on toggle.
    const on = f.def !== false;
    return `<div class="opt-row${wide}"><div class="opt-head"><span class="opt-label">${esc(f.label)}</span></div><div class="opt-control">`
      + `<div class="seg-bool" data-optkey="${f.key}" data-defon="${on ? 1 : 0}">`
      + `<button type="button" class="seg-mini${on ? " active" : ""}" data-on="1">${esc(f.onLabel || "開")}</button>`
      + `<button type="button" class="seg-mini${on ? "" : " active"}" data-on="0">${esc(f.offLabel || "關")}</button>`
      + `</div></div>${optDesc(f)}</div>`;
  }
  if (f.type === "slider") {
    const def = f.def != null ? f.def : f.min;
    return `<div class="opt-row${wide}">${optHead(f)}
      <div class="opt-control slider-control">
        <input type="range" class="opt-slider" min="${f.min}" max="${f.max}" step="${f.step || 1}" data-def="${def}">
        <input type="number" class="opt-num" data-optkey="${f.key}" min="${f.min}" max="${f.max}" step="${f.step || 1}" placeholder="${def}">
      </div>${optDesc(f)}</div>`;
  }
  if (f.type === "select") {
    const opts = f.options.map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join("");
    return `<div class="opt-row${wide}">${optHead(f)}<div class="opt-control"><select data-optkey="${f.key}">${opts}</select></div>${optDesc(f)}</div>`;
  }
  if (f.type === "checks") {
    // checkbox group -> joined string (join="" for technique letters, "," for tamper).
    // options are [value, label] or [value, label, description].
    const join = f.join != null ? f.join : ",";
    const defSet = new Set(f.def ? (join === "" ? f.def.split("") : f.def.split(join)) : []);
    const hasDesc = f.options.some(o => o.length > 2);
    const boxes = f.options.map(o => {
      const v = o[0], l = o[1], desc = o[2] || "";
      return `<label class="opt-check${desc ? " with-desc" : ""}" title="${esc(desc)}">`
        + `<input type="checkbox" value="${esc(v)}"${defSet.has(v) ? " checked" : ""}>`
        + `<span class="oc-name">${esc(l)}</span>`
        + (desc ? `<span class="oc-desc">${esc(desc)}</span>` : "")
        + `</label>`;
    }).join("");
    const defBtn = f.def ? `<button type="button" class="checks-default" title="回到預設(${esc(f.def)})">預設</button>` : "";
    return `<div class="opt-row${wide}">${optHead(f)}<div class="opt-control opt-checks${hasDesc ? " opt-checks-desc" : ""}" data-optkey="${f.key}" data-join="${esc(join)}" data-def="${esc(f.def || "")}">${boxes}${defBtn}</div>${optDesc(f)}</div>`;
  }
  if (f.type === "textarea") {
    return `<div class="opt-row${wide}">${optHead(f)}<div class="opt-control"><textarea data-optkey="${f.key}" class="opt-textarea" rows="${f.rows || 3}" spellcheck="false" placeholder="${esc(f.placeholder || "")}"></textarea></div>${optDesc(f)}</div>`;
  }
  if (f.type === "headers") {
    // dynamic name/value rows (populated by wireHeaders/applyOptions). The rows
    // serialize to "Name: Value\n..." in gatherOptions (the --headers format).
    return `<div class="opt-row${wide}">${optHead(f)}<div class="opt-control opt-headers" data-optkey="${f.key}"><div class="hdr-rows"></div><button type="button" class="hdr-add">＋ 新增標頭</button></div>${optDesc(f)}</div>`;
  }
  // text/number: `presets: [[value,label],...]` renders visible click-to-fill
  // chips below the input, while still allowing the user to type their own value.
  const attrs = [f.min != null ? `min="${f.min}"` : "", f.max != null ? `max="${f.max}"` : "",
    f.placeholder ? `placeholder="${esc(f.placeholder)}"` : ""].join(" ");
  const presetsHtml = f.presets ? `<div class="opt-presets">` + f.presets.map(p => {
    const v = p[0], l = p[1] || p[0];
    return `<button type="button" class="preset-chip" data-fill="${esc(v)}" title="${esc(v)}">${esc(l)}</button>`;
  }).join("") + `<button type="button" class="preset-chip preset-clear" data-fill="" title="清空此欄位">✕ 清空</button></div>` : "";
  // toggle chips (e.g. common status codes): click adds/removes the value in the CSV
  const chipsHtml = f.chips ? `<div class="code-chips">` + f.chips.map(c =>
    `<button type="button" class="code-chip" data-code="${esc(c)}">${esc(c)}</button>`).join("") + `</div>` : "";
  return `<div class="opt-row${wide}">${optHead(f)}<div class="opt-control"><input data-optkey="${f.key}" type="${f.type}" ${attrs}></div>${presetsHtml}${chipsHtml}${optDesc(f)}</div>`;
}
// build one header name/value row (values set as properties to avoid escaping issues)
function _hdrAppendRow(box, name, val) {
  const row = document.createElement("div");
  row.className = "hdr-row";
  row.innerHTML = `<input class="hdr-name" placeholder="標頭名稱,如 X-Forwarded-For"><input class="hdr-val" placeholder="值"><button type="button" class="hdr-del" title="刪除此標頭">✕</button>`;
  row.querySelector(".hdr-name").value = name || "";
  row.querySelector(".hdr-val").value = val || "";
  box.appendChild(row);
}
function renderToggleHtml(t) {
  // `def:true` -> checked by default; data-defon marks it so gather/apply store the
  // explicit boolean (so un-ticking a default-on toggle actually persists).
  const defOn = t.def ? ' checked data-defon="1"' : "";
  return `<label class="check"><input type="checkbox" data-optkey="${t.key}"${defOn}><span class="check-body"><span class="check-name">${esc(t.label)}</span>${t.desc ? `<span class="check-desc">${esc(t.desc)}</span>` : ""}</span></label>`;
}
// keep a range slider and its manual number box in sync (blank number = tool default)
function wireSliders(gridSel) {
  $$(`${gridSel} .slider-control`).forEach(sc => {
    const range = sc.querySelector(".opt-slider"), num = sc.querySelector(".opt-num");
    if (!range || !num) return;
    const def = range.getAttribute("data-def");
    range.oninput = () => { num.value = range.value; };
    num.oninput = () => { range.value = (num.value.trim() === "" ? def : num.value); };
    range.value = (num.value.trim() === "" ? def : num.value);   // initial sync
  });
}
// Progressive disclosure: 常用 (always visible) / 進階 (collapsed, functional
// sub-headers) / 危險 (collapsed, red). Keys not listed fall through to 偵測調校
// so nothing silently disappears. `dump*`/shell/file keys are `danger:true` in
// the schema and are pulled into the 危險 zone regardless of this map.
const OPT_GROUPS = [
  ["common",  "",            ["level", "risk", "technique", "threads", "force_ssl", "random_agent"]],
  ["detect",  "偵測調校",     ["dbms", "tamper", "time_sec", "prefix", "suffix", "test_string", "not_string", "code", "regexp", "text_only"]],
  ["conn",    "連線 / 效能",  ["timeout", "delay", "retries", "proxy"]],
  ["request", "請求控制",     ["headers", "ignore_code"]],
  ["auth",    "認證 / CSRF",  ["auth_type", "auth_cred", "csrf_token", "csrf_url"]],
  ["enum",    "列舉(確認可注入後再開)", ["get_banner", "get_current_user", "get_current_db", "get_hostname", "get_dbs", "is_dba"]],
  ["extra",   "其他",         ["extra_flags"]],
];
function _optGroupKey(key) {
  for (const [g, , keys] of OPT_GROUPS) if (keys.includes(key)) return g;
  return "detect";
}
// 基本掃描 (basic) mode is otherwise "pick a template, everything read-only". But a few
// settings depend on the TARGET, not on the injection strategy — whether to force HTTPS
// (http/localhost targets must untick it) and whether to randomise the UA. Forcing the
// user into 進階 just to flip those is silly, so they stay EDITABLE in basic mode. All of
// them live in the 常用 zone, so they render together in one block (no hunting).
const BASIC_EDITABLE = ["force_ssl", "random_agent"];

// ===== 常用設置 (pinned quick-settings strip above the command preview) =======
// A user-chosen subset of options is lifted OUT of the big options card and rendered
// in a compact strip pinned right above 將執行, so the settings people touch most (the
// "force-ssl tier": per-target essentials) are always one glance away. Which keys appear
// is configurable in 設定. Each key lives in exactly ONE place (strip OR card, never both)
// so gatherOptions never double-reads. danger keys are never pinnable.
// Canonical order for both the strip and the settings chooser:
const PIN_ORDER = [
  "force_ssl", "random_agent", "text_only",
  "level", "risk", "technique", "threads", "dbms", "tamper",
  "time_sec", "timeout", "delay", "retries", "proxy",
  "prefix", "suffix",
  "ignore_code", "headers", "test_string", "not_string", "code", "regexp",
  "auth_type", "auth_cred", "csrf_token", "csrf_url",
  "get_banner", "get_current_user", "get_current_db", "get_hostname", "get_dbs", "is_dba",
];
// default pin set: keep it TINY so the strip stays compact -- just the two per-target
// connection toggles. Everything else is one click away in 設定. Used only when
// settings.pinned_common is absent.
const PINNED_DEFAULT = ["force_ssl", "random_agent"];
function _pinnedKeys() {
  const s = state.settings || {};
  return Array.isArray(s.pinned_common) ? s.pinned_common : PINNED_DEFAULT;
}
// map key -> its schema option object for a tool (non-danger only; danger keys never pin)
function _optCatalog(tool) {
  const schema = SCHEMAS[tool]; if (!schema) return {};
  const byKey = {};
  schema.fields.concat(COMMON_FIELDS, COMMON_TOGGLES, schema.toggles)
    .forEach(o => { if (!o.danger) byKey[o.key] = o; });
  return byKey;
}
// ordered option objects to render in the strip for this tool (pinned ∩ available)
function _pinnedForTool(tool) {
  const byKey = _optCatalog(tool);
  const want = new Set(_pinnedKeys());
  return PIN_ORDER.filter(k => want.has(k) && byKey[k]).map(k => byKey[k]);
}
// every pinnable key across both tools (for the 設定 chooser), in canonical order,
// each tagged with which tools expose it.
function _pinCatalog() {
  const sql = _optCatalog("sqlmap"), gha = _optCatalog("ghauri");
  return PIN_ORDER.filter(k => sql[k] || gha[k]).map(k => {
    const o = sql[k] || gha[k];
    const tools = [sql[k] && "sqlmap", gha[k] && "ghauri"].filter(Boolean);
    return { key: k, label: o.label, tools };
  });
}
// render a mixed list of fields (have .type) + toggles (no .type); toggles sit
// in a .opts-toggles flex row so they read as a group of checkboxes.
function renderOptGroup(opts) {
  const fields = opts.filter(o => o.type);
  const toggles = opts.filter(o => !o.type);
  return fields.map(renderFieldHtml).join("")
    + (toggles.length ? `<div class="opts-toggles">${toggles.map(renderToggleHtml).join("")}</div>` : "");
}
function renderOptions(tool, gridSel, togglesSel, labelSel, pinsSel) {
  const schema = SCHEMAS[tool]; if (!schema) return;
  const all = schema.fields.concat(COMMON_FIELDS, COMMON_TOGGLES, schema.toggles);
  const danger = all.filter(o => o.danger);
  // 常用設置: lift the pinned options OUT of the card into the footer strip. Only when a
  // pins container is wired (composer, not the template editor). Each key lives in exactly
  // one place -> no duplicate data-optkey for gatherOptions to double-read.
  const pins = (pinsSel && $(pinsSel)) ? _pinnedForTool(tool) : [];
  const pinSet = new Set(pins.map(o => o.key));
  const byGroup = {};
  all.filter(o => !o.danger && !pinSet.has(o.key)).forEach(o => {
    const g = _optGroupKey(o.key); (byGroup[g] = byGroup[g] || []).push(o);
  });
  // 常用 — collapsible, default EXPANDED (hidden entirely if every common key got pinned)
  const commonHtml = (byGroup.common && byGroup.common.length) ? `
    <div class="opt-sec opt-sec-common common-zone">
      <button type="button" class="opt-sec-head common-head"><span class="caret">▾</span>常用</button>
      <div class="opt-sec-body common-body">${renderOptGroup(byGroup.common)}</div>
    </div>` : "";
  // 進階 — collapsed, functional sub-headers
  const advBody = OPT_GROUPS.filter(([g]) => g !== "common").map(([g, label]) => {
    const os = byGroup[g]; if (!os || !os.length) return "";
    return `<div class="opt-subhead">${esc(label)}</div>${renderOptGroup(os)}`;
  }).join("");
  const advHtml = advBody ? `
    <div class="opt-sec adv-zone collapsed">
      <button type="button" class="opt-sec-head adv-head"><span class="caret">▸</span>進階選項<span class="sec-hint">偵測調校・連線・請求・認證・列舉</span></button>
      <div class="opt-sec-body adv-body">${advBody}</div>
    </div>` : "";
  // 危險 — collapsed, red; still inside gridSel so gatherOptions/applyOptions pick it up
  const dangerHtml = danger.length ? `
    <div class="opt-sec danger-zone collapsed">
      <button type="button" class="opt-sec-head danger-head"><span class="caret">▸</span>⚠ 危險區<span class="sec-hint">取 shell / 執行 SQL / 讀寫檔案 / 匯出資料 · 高破壞性</span></button>
      <div class="opt-sec-body danger-body">${renderOptGroup(danger)}</div>
    </div>` : "";
  $(gridSel).innerHTML = commonHtml + advHtml + dangerHtml;
  if (togglesSel && $(togglesSel)) $(togglesSel).innerHTML = "";   // everything lives in gridSel now
  // render the pinned 常用設置 strip (real inputs, wired like the grid)
  if (pinsSel && $(pinsSel)) {
    const box = $(pinsSel);
    box.classList.toggle("hidden", !pins.length);
    box.innerHTML = pins.length
      ? `<div class="common-pins-row"><span class="common-pins-head">⚡ 常用設置</span>${renderOptGroup(pins)}<span class="cp-hint">設定可調整</span></div>` : "";
    if (pins.length) { wireSliders(pinsSel); wirePresets(pinsSel); wireChecksDefault(pinsSel); wireHeaders(pinsSel); wireCodeChips(pinsSel); wireSegBool(pinsSel); }
  }
  wireSliders(gridSel);
  wirePresets(gridSel);
  wireChecksDefault(gridSel);
  wireHeaders(gridSel);
  wireCodeChips(gridSel);
  wireSegBool(gridSel);
  $$(`${gridSel} .common-zone, ${gridSel} .adv-zone, ${gridSel} .danger-zone`).forEach(z => {
    const head = z.querySelector(".common-head, .adv-head, .danger-head"); if (!head) return;
    head.onclick = () => {
      const c = z.classList.toggle("collapsed");
      const car = z.querySelector(".caret"); if (car) car.textContent = c ? "▸" : "▾";
    };
  });
  if (labelSel && $(labelSel)) $(labelSel).textContent = tool + " 選項";
}
// click-to-fill preset chips (prefix/suffix/proxy) -> set the sibling input + fire
// an input event so the command preview and risk assessment update live.
function wirePresets(gridSel) {
  $$(`${gridSel} .preset-chip`).forEach(b => b.onclick = () => {
    const row = b.closest(".opt-row"); if (!row) return;
    const input = row.querySelector("input[data-optkey]"); if (!input) return;
    input.value = b.dataset.fill;
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}
// "預設" button on a checkbox-group (technique) -> re-check the tool default set.
function wireChecksDefault(gridSel) {
  $$(`${gridSel} .checks-default`).forEach(b => b.onclick = () => {
    const c = b.closest(".opt-checks"); if (!c) return;
    const join = c.dataset.join != null ? c.dataset.join : ",";
    const def = c.dataset.def || "";
    const set = new Set(join === "" ? def.split("") : def.split(join).map(s => s.trim()).filter(Boolean));
    c.querySelectorAll('input[type=checkbox]').forEach(cb => { cb.checked = set.has(cb.value); });
    c.dispatchEvent(new Event("change", { bubbles: true }));
  });
}
// dynamic header rows: wire the add button + delegate delete clicks; keep >=1 row.
function wireHeaders(gridSel) {
  $$(`${gridSel} .opt-headers`).forEach(box => {
    const rows = box.querySelector(".hdr-rows");
    if (rows && !rows.children.length) _hdrAppendRow(rows, "", "");
    const add = box.querySelector(".hdr-add");
    if (add) add.onclick = () => { _hdrAppendRow(rows, "", ""); box.dispatchEvent(new Event("input", { bubbles: true })); };
    box.addEventListener("click", e => {
      const del = e.target.closest(".hdr-del"); if (!del) return;
      const row = del.closest(".hdr-row"); if (!row) return;
      row.remove();
      if (!rows.children.length) _hdrAppendRow(rows, "", "");
      box.dispatchEvent(new Event("input", { bubbles: true }));
    });
  });
}
// segmented boolean (e.g. HTTPS/HTTP): clicking a segment makes it active + fires a
// change event so the command preview refreshes live (same as a checkbox/select).
function wireSegBool(gridSel) {
  $$(`${gridSel} .seg-bool`).forEach(box => {
    box.querySelectorAll(".seg-mini").forEach(bt => bt.onclick = () => {
      if (bt.disabled || bt.classList.contains("active")) return;
      box.querySelectorAll(".seg-mini").forEach(x => x.classList.toggle("active", x === bt));
      box.dispatchEvent(new Event("change", { bubbles: true }));
    });
  });
}
// status-code chips: click toggles the code in the sibling CSV input.
function wireCodeChips(gridSel) {
  $$(`${gridSel} .code-chips`).forEach(box => {
    const row = box.closest(".opt-row"); const input = row && row.querySelector("input[data-optkey]"); if (!input) return;
    box.querySelectorAll(".code-chip").forEach(ch => ch.onclick = () => {
      const arr = input.value.split(",").map(s => s.trim()).filter(Boolean);
      const i = arr.indexOf(ch.dataset.code);
      if (i >= 0) arr.splice(i, 1); else arr.push(ch.dataset.code);
      input.value = arr.join(",");
      input.dispatchEvent(new Event("input", { bubbles: true }));
      _syncCodeChips(gridSel);
    });
    input.addEventListener("input", () => _syncCodeChips(gridSel));
  });
  _syncCodeChips(gridSel);
}
function _syncCodeChips(gridSel) {
  $$(`${gridSel} .code-chips`).forEach(box => {
    const row = box.closest(".opt-row"); const input = row && row.querySelector("input[data-optkey]"); if (!input) return;
    const set = new Set(input.value.split(",").map(s => s.trim()).filter(Boolean));
    box.querySelectorAll(".code-chip").forEach(ch => ch.classList.toggle("active", set.has(ch.dataset.code)));
  });
}
// composer grid (#optGrid) also has a pinned 常用設置 strip (#commonPins) that hosts
// the REAL inputs for pinned keys -> always read/write it too, so a pinned option is
// never silently dropped from the launch payload. Template editor (#teOptGrid) has none.
function _optRoots(gridSel, togglesSel) {
  const roots = [gridSel, togglesSel];
  if (gridSel === "#optGrid") roots.push("#commonPins");
  return roots.filter(Boolean).map(r => `${r} [data-optkey]`).join(", ");
}
function gatherOptions(gridSel, togglesSel) {
  const o = {};
  $$(_optRoots(gridSel, togglesSel)).forEach(el => {
    const k = el.dataset.optkey;
    if (el.classList.contains("opt-checks")) {
      const join = el.dataset.join != null ? el.dataset.join : ",";
      const vals = Array.from(el.querySelectorAll('input[type=checkbox]'))
        .filter(c => c.checked).map(c => c.value);
      const joined = vals.join(join);
      // symmetric with sliders: none checked OR exactly the tool default -> omit
      // (so an untouched technique isn't sent and doesn't trip a risk warning).
      if (joined && joined !== (el.dataset.def || "")) o[k] = joined;
    } else if (el.classList.contains("opt-headers")) {
      const rows = Array.from(el.querySelectorAll(".hdr-row")).map(r => {
        const n = r.querySelector(".hdr-name").value.trim();
        const v = r.querySelector(".hdr-val").value.trim();
        return n ? (n + ": " + v) : "";
      }).filter(Boolean);
      if (rows.length) o[k] = rows.join("\n");   // "Name: Value\n..." -> driver turns \n into literal
    } else if (el.classList.contains("seg-bool")) {
      const on = el.querySelector(".seg-mini.active");   // segmented boolean -> store explicitly (both states)
      o[k] = on ? on.dataset.on === "1" : (el.dataset.defon === "1");
    } else if (el.type === "checkbox") {
      if (el.dataset.defon === "1") o[k] = el.checked;   // default-on: store true/false explicitly
      else if (el.checked) o[k] = true;
    }
    else { const v = el.value.trim(); if (v !== "") o[k] = el.type === "number" ? Number(v) : v; }
  });
  return o;
}
function applyOptions(o, gridSel, togglesSel) {
  o = o || {};
  $$(_optRoots(gridSel, togglesSel)).forEach(el => {
    const k = el.dataset.optkey;
    if (el.classList.contains("opt-checks")) {
      const join = el.dataset.join != null ? el.dataset.join : ",";
      const src = (k in o && o[k] != null) ? String(o[k]) : (el.dataset.def || "");
      const set = new Set(join === "" ? src.split("") : src.split(join).map(s => s.trim()).filter(Boolean));
      el.querySelectorAll('input[type=checkbox]').forEach(c => { c.checked = set.has(c.value); });
      return;
    }
    if (el.classList.contains("opt-headers")) {
      const box = el.querySelector(".hdr-rows"); box.innerHTML = "";
      const lines = String((k in o && o[k] != null) ? o[k] : "").split(/\r?\n/).map(s => s.trim()).filter(Boolean);
      if (!lines.length) lines.push("");   // always show at least one empty row
      lines.forEach(line => {
        const i = line.indexOf(":");
        _hdrAppendRow(box, i >= 0 ? line.slice(0, i).trim() : line, i >= 0 ? line.slice(i + 1).trim() : "");
      });
      return;
    }
    if (el.classList.contains("seg-bool")) {
      const val = (k in o) ? !!o[k] : (el.dataset.defon === "1");
      el.querySelectorAll(".seg-mini").forEach(bt => bt.classList.toggle("active", (bt.dataset.on === "1") === val));
      return;
    }
    if (el.type === "checkbox") el.checked = (k in o) ? !!o[k] : (el.dataset.defon === "1");
    else el.value = (k in o && o[k] != null) ? o[k] : "";
  });
  wireSliders(gridSel);   // re-sync slider positions after applying values
  _syncCodeChips(gridSel);   // reflect applied status-code values on the chips
  _revealFilledZones(gridSel);   // never hide an applied 進階/危險 value behind a collapse
  if (gridSel === "#optGrid" && $("#commonPins")) {   // pinned strip has its own sliders/chips
    wireSliders("#commonPins"); _syncCodeChips("#commonPins");
  }
}
// expand any collapsed 進階/危險 section that ended up holding a non-default value,
// so options loaded from a template / reconfigure are visible, not silently hidden.
function _revealFilledZones(gridSel) {
  $$(`${gridSel} .adv-zone, ${gridSel} .danger-zone`).forEach(z => {
    const filled = Array.from(z.querySelectorAll("[data-optkey]")).some(el => {
      if (el.classList.contains("opt-checks")) {
        const join = el.dataset.join != null ? el.dataset.join : ",";
        const vals = Array.from(el.querySelectorAll("input[type=checkbox]:checked")).map(c => c.value).join(join);
        return vals && vals !== (el.dataset.def || "");
      }
      if (el.type === "checkbox") return el.checked;
      return el.value != null && el.value.trim() !== "";
    });
    void filled;   // no auto-expand: 進階/危險 stay COLLAPSED by default (basic mode expands only the chosen template's zones -- see _applyModeToGrid)
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
// the green "ready" light was removed (a running page already proves the server is
// up). We keep the ONE genuinely useful signal: warn once if sqlmap isn't installed.
let _sqlmapMissingWarned = false;
async function refreshHealth() {
  try {
    const h = await api("/api/health");
    if (!h.sqlmap_present && !_sqlmapMissingWarned) {
      _sqlmapMissingWarned = true;
      toast("尚未安裝 sqlmap 引擎(請執行 bootstrap.bat)", "err");
    }
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
  if (state.projectId != null && state.projectId !== pid) {
    saveTabs();                        // localStorage + (debounced) DB for the project we're leaving
    _flushTabsToDbNow(state.projectId);   // but flush its DB copy NOW -- the debounce would be cancelled by the new project
  }
  state.projectId = pid;
  state.treeExpanded = null; state.treeKey = ""; state.currentTarget = null;   // reset per project
  updateCurrentProjectLabel();
  try { localStorage.setItem("projectId", String(pid)); } catch (e) {}
  restoreTabs(); renderComposeTabs(); applyTab(_activeTab());   // load THIS project's own tab set
}
function requireProject() { if (state.projectId == null) { toast("請先建立並選擇一個專案", "err"); showProjectsView(true); return false; } return true; }

function showProjectsView(firstRun) {
  void firstRun;   // 專案總覽 no longer has a 返回儀表板 button (it's the top-level entry)
  // remember WHERE we are for this tab session so F5 restores it (a fresh tab has no
  // sessionStorage -> lands on the picker, per "打開首頁 = 選擇專案頁").
  try { sessionStorage.setItem("viewMode", "projects"); } catch (e) {}
  setView("projects");
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
    <div class="project-card" data-enter="${p.id}" role="button" tabindex="0" title="進入此專案">
      <div class="pc-main">
        <div class="pc-top"><span class="pc-name">${esc(p.name)}</span><span class="pc-enter-hint">進入 →</span></div>
        <div class="pc-note">${esc(p.note || "—")}</div>
        <div class="pc-meta">${esc(fmtTime(p.created_at))}</div>
      </div>
      <div class="pc-actions">
        <button class="btn ghost sm danger-btn" data-delp="${p.id}">刪除</button>
      </div>
    </div>`).join("");
  const enterProject = (id) => { setProject(id); showDashboard(); loadScans(); };
  $$("[data-enter]", box).forEach(el => {
    el.onclick = () => enterProject(Number(el.dataset.enter));
    el.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); enterProject(Number(el.dataset.enter)); } };
  });
  $$("[data-delp]", box).forEach(b => b.onclick = async (e) => {
    e.stopPropagation();   // don't let a delete click also enter the project
    const id = Number(b.dataset.delp);
    const proj = state.projects.find(x => x.id === id);
    const ok = await confirmModal({
      title: "刪除專案",
      message: `確定刪除專案 <b>${esc(proj ? proj.name : id)}</b>?此專案的掃描與紀錄將一併移除,無法復原。`,
      okText: "刪除",
    });
    if (!ok) return;
    try {
      await api(`/api/projects/${id}`, "DELETE");
      if (state.projectId === id) { try { localStorage.removeItem("projectId"); } catch (e) {} state.projectId = null; }
      await loadProjects(); renderProjectsList();
      toast("已刪除", "ok");
    } catch (e) { toast("刪除失敗:" + e.message, "err"); }
  });
}
function openNewProject() {
  $("#npName").value = ""; $("#npNote").value = "";
  showModal("newProjectModal");
  setTimeout(() => { const el = $("#npName"); if (el) el.focus(); }, 50);
}
async function createProjectEntry() {
  const name = $("#npName").value.trim();
  if (!name) { toast("請填專案名稱", "err"); return; }
  try {
    const p = await api("/api/projects", "POST", { name, note: $("#npNote").value.trim() });
    $("#npName").value = ""; $("#npNote").value = "";
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
    // send the scheme so the parse SUMMARY matches: a pasted URL's own scheme when present,
    // otherwise the current HTTPS/HTTP toggle (default HTTPS). _syncSchemeFromRaw then aligns the toggle.
    const _urlSch = _rawUrlScheme(raw);
    const _fs = _urlSch != null ? (_urlSch === "https") : _currentForceSsl();
    const r = await api("/api/parse", "POST", { raw, project_id: state.projectId, force_ssl: _fs });
    state.parsed = r; state.params = r.parsed.params.map(p => ({ ...p }));
    const warns = (r.parsed.warnings || []).slice();
    if (!r.parsed.host) warns.push("未解析到 Host — 可能解析錯誤");
    const anomCount = state.params.filter(_paramAnomaly).length;
    if (anomCount) warns.push(`${anomCount} 個參數的名稱/值異常,可能解析錯誤(見表格紅色 ⚠)`);
    $("#parseWarn").textContent = warns.length ? "⚠ " + warns.join("；") : "";
    renderParseSummary(r); renderParams();
    locateInTree(r);
    renderBoardIfChanged();   // update the left "待掃描 · <endpoint>" placeholder now that we're parsed
    $("#resultCard").classList.remove("hidden");
    $("#toolCard").classList.remove("hidden");
    if (!selectedTool()) _applyComposeDefaults();   // auto-select default tool + template + mode
    const _hasTool = !!selectedTool();   // reveal mode/template/options/footer if a tool is already picked
    $("#modeCard").classList.toggle("hidden", !_hasTool);
    $("#templateCard").classList.toggle("hidden", !_hasTool);
    $("#optionsCard").classList.toggle("hidden", !_hasTool);
    $("#composeFooter").classList.toggle("hidden", !_hasTool);
    const _at = (state.tabs || []).find(x => x.id === state.activeTabId);
    if (_at) { _at.title = r.endpoint || (r.parsed && r.parsed.url) || "新分頁"; renderComposeTabs(); }
    if (_hasTool) { _syncSchemeFromRaw(raw); updateCmdPreview(); }   // match the toggle to the pasted URL's scheme, then preview
  } catch (e) { toast("解析失敗:" + e.message, "err"); }
}
// the explicit scheme on the FIRST line (bare URL or absolute request-line target), or null
function _rawUrlScheme(raw) {
  const m = ((raw || "").split(/\r?\n/)[0] || "").match(/\b(https?):\/\//i);
  return m ? m[1].toLowerCase() : null;
}
// the HTTPS/HTTP seg-bool's current value (default HTTPS before it's rendered)
function _currentForceSsl() {
  const seg = $('#optGrid [data-optkey="force_ssl"], #commonPins [data-optkey="force_ssl"]');
  if (!seg) return true;
  const on = seg.querySelector(".seg-mini.active");
  return on ? on.dataset.on === "1" : true;
}
// When the pasted first line carries an explicit scheme, set the HTTPS/HTTP toggle to match it
// -- so it starts correct. The toggle stays clickable (backend uses force_ssl authoritatively),
// so the user can still override the URL's scheme.
function _syncSchemeFromRaw(raw) {
  const sch = _rawUrlScheme(raw);
  if (!sch) return;   // relative request -> leave the toggle as the user set it
  const wantHttps = sch === "https";
  const seg = $('#optGrid [data-optkey="force_ssl"], #commonPins [data-optkey="force_ssl"]');
  if (!seg) return;
  seg.querySelectorAll(".seg-mini").forEach(bt => bt.classList.toggle("active", (bt.dataset.on === "1") === wantHttps));
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
  // flash the synthetic "目前(尚未掃描)" node so it's obvious WHERE a scan would land
  setTimeout(() => { const tag = document.querySelector(".cur-tag"); const row = tag ? tag.closest(".trow") : null; _animScroll(row); _pulse(row); }, 80);
}
// While the ACTIVE tab is an unparsed compose tab, a "待解析(此分頁)" placeholder is
// pinned at the top of the tree so the not-yet-located scan has a visible home. Once
// parsed, state.parsed is set and the real "目前" node takes over (see locateInTree).
function _pendingCompose() {
  const t = _activeTab();
  return state.view === "dashboard" && !!t && t.kind === "compose" && !state.parsed;
}
// left-list placeholder: shows for the active compose tab BEFORE its scan runs -- "待解析"
// while unparsed, then "待掃描 · <endpoint>" once parsed, so you always see where it lands.
function _boardPending() {
  if (state.view !== "dashboard") return null;
  const t = _activeTab();
  if (!t || t.kind !== "compose") return null;
  if (state.parsed) {
    const ep = state.parsed.endpoint || (state.parsed.parsed && state.parsed.parsed.url) || "此請求";
    return { label: "待掃描 · " + ep, parsed: true };
  }
  return { label: "待解析(此分頁)", parsed: false };
}
function locatePending() {
  setTimeout(() => {
    const row = document.querySelector("#treeBox .trow.tpending");
    if (row) { _animScroll(row); _pulse(row); }   // same sweep/glow as a real locate
  }, 80);
}
function renderParseSummary(r) {
  const p = r.parsed;
  const rows = [
    ["方法", p.method], ["Scheme", p.scheme], ["Host", p.host || "—"], ["路徑", p.path],
    ["Content-Type", p.content_type || "—"], ["Header 數", Object.keys(p.headers || {}).length],
    ["Cookie 數", Object.keys(p.cookies || {}).length], ["Body 長度", (p.body || "").length],
    ["端點簽名", r.endpoint],
  ];
  $("#parseSummary").innerHTML = rows.map(([k, v]) => {
    const bad = (k === "Host" && !p.host);   // no Host parsed -> likely a parse error
    return `<div class="kv"><b>${k}</b><span class="${bad ? "bad" : ""}">${esc(v)}</span></div>`;
  }).join("") +
    `<div class="kv wide"><b>URL</b><span class="mono-val">${esc(p.url)}</span></div>` +
    `<div class="hint-line">送給工具的請求會用你貼上的<b>原始請求</b>(僅換行正規化),解析只用來挑參數與去重。</div>`;
  renderReconPanel(r.recon);
}
// "目標情報": backend/framework/CDN/WAF inferred from the REQUEST alone. Heuristic +
// request-only, so it characterizes the submitted request, never proves the server.
const _RECON_CAT = { language: "語言", framework: "框架", server: "伺服器", waf: "WAF/防護",
  cdn: "CDN", lb: "負載平衡", cms: "CMS", auth: "驗證", "info-leak": "資訊洩漏", version: "版本", other: "其他" };
function renderReconPanel(recon) {
  const box = $("#reconPanel"); if (!box) return;
  recon = recon || [];
  if (!recon.length) { box.innerHTML = ""; return; }
  const rows = recon.map(x => {
    const cat = _RECON_CAT[x.category] || x.category || "其他";
    const conf = x.confidence || "low";
    const ev = (x.evidence || []).join("、");
    const tip = [x.note, x.source].filter(Boolean).join("\n");
    return `<div class="recon-row${x.category === "info-leak" ? " leak" : ""}" title="${esc(tip)}">
      <span class="recon-cat">${esc(cat)}</span>
      <span class="recon-reveal">${esc(x.reveals)}</span>
      <span class="recon-conf conf-${esc(conf)}">${esc(conf)}</span>
      <span class="recon-ev" title="命中證據:${esc(ev)}">${esc(ev)}</span>
    </div>`;
  }).join("");
  box.innerHTML = `<div class="recon-head">目標情報 <span class="recon-hint">從請求推斷 · 僅描述此請求 · 可偽造</span></div>${rows}`;
}
function priorBadge(p) {
  let cls, label;
  if (p.prior_vulnerable) { cls = "vuln"; label = `曾有漏洞×${p.prior_test_count}`; }
  else if (p.prior_status === "clean") { cls = "clean"; label = `測過無洞×${p.prior_test_count}`; }
  else if (p.prior_status === "skipped") return `<span class="badge skip" title="解析到但未勾選,未實際測試">已略過</span>`;
  else if (p.prior_status) { cls = "tested"; label = `測過×${p.prior_test_count}`; }
  else return `<span class="badge none">未測</span>`;
  // has history -> clickable, opens this parameter's full test timeline
  return `<button type="button" class="badge ${cls} phist-btn" data-phname="${esc(p.name)}" data-phloc="${esc(p.location)}" title="查看此參數的所有測試紀錄">${label} ⤢</button>`;
}
// Heuristic: does this parsed parameter look mis-parsed? Returns a reason (shown
// in red) or "". Conservative — allows legit JSON names (dots/brackets), only
// flags separators/whitespace/newlines that a real param name never contains.
function _paramAnomaly(p) {
  const name = String(p.name == null ? "" : p.name);
  const val = String(p.value == null ? "" : p.value);
  if (!name.trim()) return "參數名稱空白 — 可能解析錯誤";
  if (/\s/.test(name)) return "名稱含空白 — 可能沒切好";
  if (/[&?#=]/.test(name)) return "名稱含 & ? # = 等分隔符 — 可能沒切好";
  if (/[\r\n]/.test(name) || /[\r\n]/.test(val)) return "含換行 — 可能解析錯誤";
  if (name.length > 96) return "名稱異常長 — 可能整段被當成一個參數";
  return "";
}
// Row colour tracks the CHECKBOX (will-be-tested), NOT the auto-skip flag.
// Auto-skip only sets the INITIAL checked state and moves the param into the
// SEPARATE "已自動略過" region below the table.
// Heuristic "worth another test class" hints for one param (candidate, NOT a
// confirmed finding). Sorted high->low confidence; each chip's tooltip carries the
// why + recommended tool + source.
function adviceCellHtml(p) {
  const adv = p.advice || [];
  if (!adv.length) return "";
  const rank = { high: 0, medium: 1, low: 2 };
  const sorted = adv.slice().sort((a, b) =>
    (rank[a.confidence] == null ? 3 : rank[a.confidence]) - (rank[b.confidence] == null ? 3 : rank[b.confidence]));
  return `<div class="adv-hints">` + sorted.map(a => {
    const conf = a.confidence || "low";
    const tip = [a.why, a.tool ? "工具:" + a.tool : "", a.source || ""].filter(Boolean).join("\n");
    return `<span class="advchip conf-${esc(conf)}" title="${esc(tip)}">${esc(a.vuln_class)}</span>`;
  }).join("") + `</div>`;
}
function paramRowHtml(i) {
  const p = state.params[i];
  const anom = _paramAnomaly(p);
  return `<tr class="prow ${p.selected ? "sel" : "unsel"}${anom ? " anomaly-row" : ""}" data-row="${i}">
    <td><input type="checkbox" data-idx="${i}" ${p.selected ? "checked" : ""}${p.location === "FILE" ? " disabled title=\"檔案上傳欄位不做 SQLi 測試\"" : ""}></td>
    <td class="pname${anom ? " anomaly" : ""}">${esc(p.name)}${anom ? `<span class="anomaly-flag" title="${esc(anom)}">⚠</span>` : ""}</td>
    <td><span class="loc-chip">${esc(p.location)}</span></td>
    <td class="val-cell${anom ? " anomaly" : ""}" title="${anom ? esc(anom) : esc(p.value)}">${esc(p.value)}</td>
    <td>${p.filtered ? `<span class="badge skip" title="${esc(p.filter_reason || "")}">自動略過</span>` : ""}</td>
    <td>${priorBadge(p)}</td>
    <td class="adv-cell">${adviceCellHtml(p)}</td>
  </tr>`;
}
function wireParamRows(root) {
  $$('input[type=checkbox][data-idx]', root).forEach(cb => cb.onchange = () => {
    const i = parseInt(cb.dataset.idx, 10);
    state.params[i].selected = cb.checked;
    const tr = cb.closest("tr");
    if (tr) { tr.classList.toggle("sel", cb.checked); tr.classList.toggle("unsel", !cb.checked); }
    updateCmdPreview();
  });
  // clickable history badge -> this parameter's full test timeline
  $$('.phist-btn', root).forEach(b => b.onclick = (e) => {
    e.preventDefault();
    openParamHistory(b.dataset.phname, b.dataset.phloc);
  });
}
// Drill-down: every recorded test of ONE parameter (newest first), each linking
// back to the scan it came from.
async function openParamHistory(name, location) {
  const sigEp = state.parsed && state.parsed.sig_endpoint;
  if (!sigEp) { toast("請先解析請求", "err"); return; }
  const q = new URLSearchParams({
    project_id: state.projectId, sig_endpoint: sigEp, name, location,
  });
  let rows;
  try { rows = await api(`/api/param-tests?${q.toString()}`); }
  catch (e) { toast("讀取紀錄失敗:" + e.message, "err"); return; }
  $("#phTitle").textContent = `參數測試紀錄:${name}(${location})`;
  const body = $("#phBody");
  if (!rows.length) {
    body.innerHTML = `<div class="ph-empty">這個參數還沒有任何測試紀錄。</div>`;
  } else {
    const vulnN = rows.filter(r => r.vulnerable).length;
    body.innerHTML =
      `<div class="ph-sum">共 <b>${rows.length}</b> 次測試,其中 <b class="${vulnN ? "vuln-txt" : ""}">${vulnN}</b> 次判定有漏洞</div>` +
      `<table class="ph-table"><thead><tr><th>時間</th><th>工具</th><th>結果</th><th>來源掃描</th></tr></thead><tbody>` +
      rows.map(r => `<tr>
        <td class="mono-val nowrap">${esc(fmtTime(r.created_at))}</td>
        <td>${esc(r.tool || "—")}</td>
        <td><span class="badge ${r.vulnerable ? "vuln" : (r.status === "clean" ? "clean" : "tested")}">${r.vulnerable ? "有漏洞" : (r.status === "clean" ? "無洞" : esc(r.status))}</span></td>
        <td><button class="link-btn" data-phscan="${r.scan_id}">#${r.scan_id}${r.scan_status ? " · " + esc(r.scan_status) : ""}</button></td>
      </tr>`).join("") +
      `</tbody></table>`;
  }
  $$("[data-phscan]", body).forEach(b => b.onclick = () => {
    const id = parseInt(b.dataset.phscan, 10);
    closeModals(); openScanDetail(id);   // jump to that scan's full log/detail
  });
  showModal("paramHistModal");
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
         <thead><tr><th></th><th>參數</th><th>位置</th><th>樣本值</th><th>過濾</th><th>過去測試</th><th>建議另測</th></tr></thead>
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
    tb.innerHTML = `<tr><td colspan="7" style="color:var(--fg-dim)">沒有偵測到參數。可在 URL 加 ?id=1 之類再試。</td></tr>`;
    renderParamRegion($("#headerParams"), [], {}); renderParamRegion($("#fileParams"), [], {}); renderParamRegion($("#skipParams"), [], {});
    return;
  }
  const idxs = state.params.map((_, i) => i);
  const isHeader = i => state.params[i].location === "HEADER";
  const isFile = i => state.params[i].location === "FILE";
  const main = idxs.filter(i => !state.params[i].filtered && !isHeader(i) && !isFile(i));
  const headers = idxs.filter(isHeader);
  const files = idxs.filter(isFile);
  const skipped = idxs.filter(i => state.params[i].filtered && !isHeader(i) && !isFile(i));
  // main table: the real test candidates (GET/POST/JSON/COOKIE, not auto-skipped)
  tb.innerHTML = main.length ? main.map(paramRowHtml).join("")
    : `<tr><td colspan="7" style="color:var(--fg-dim)">主要參數都在下方分區(Header / 檔案 / 已略過)。</td></tr>`;
  wireParamRows(tb);
  // Header injection points — their OWN region (uncommon, default unchecked)
  renderParamRegion($("#headerParams"), headers, {
    title: "Header 位置參數(預設不勾)", hint: "較少見的注入點,需要才勾",
    collapsed: state.headerCollapsed, set: v => state.headerCollapsed = v,
  });
  // multipart FILE-upload fields — their OWN region, never SQLi-fuzzed
  renderParamRegion($("#fileParams"), files, {
    title: "檔案上傳欄位(不測 SQLi)", hint: "multipart 檔案欄位,已自動略過;檔案漏洞請另行測試",
    collapsed: state.fileCollapsed, set: v => state.fileCollapsed = v,
  });
  // Rule-matched noise — its OWN region (default unchecked)
  renderParamRegion($("#skipParams"), skipped, {
    title: "已自動略過", hint: "判定為雜訊,預設不勾選",
    collapsed: state.skipCollapsed, set: v => state.skipCollapsed = v,
  });
}
function selectParams(mode) {
  state.params.forEach(p => {
    if (p.location === "FILE") { p.selected = false; return; }   // never SQLi-fuzz a file field
    if (mode === "all") p.selected = true;
    else if (mode === "none") p.selected = false;
    else if (mode === "suggest") p.selected = !p.filtered && p.location !== "HEADER";
  });
  renderParams();
  updateCmdPreview();
}

// ===== composer tool + templates ==========================================
function selectedTool() { const el = $('input[name="tool"]:checked'); return el ? el.value : ""; }
// pre-fill a fresh composer with the user's defaults -- tool + its ★default template
// + default mode -- so they don't have to re-pick every time. Only used when nothing
// is selected yet (never overrides a tool the user already chose in this tab).
function _applyComposeDefaults() {
  const s = state.settings || {};
  let tool = s.default_tool; if (!SCHEMAS[tool]) tool = "sqlmap";
  state.scanMode = (s.default_scan_mode === "basic") ? "basic" : "advanced";
  selectTool(tool, { autoDefault: true });   // selects tool + applies is_default template + setScanMode
}
function selectTool(tool, opts) {
  opts = opts || {};
  const radio = $(`input[name="tool"][value="${tool}"]`); if (radio) radio.checked = true;
  renderOptions(tool, "#optGrid", "#optToggles", "#optToolLabel", "#commonPins");
  const _ot = $("#optionsTitle"); if (_ot) _ot.textContent = "6 · 掃描選項(" + tool + ")";   // tool name in the card title
  $("#toolOptions").classList.remove("hidden");
  const _composed = !!state.parsed;   // mode / template / options / footer only once a request is parsed
  $("#modeCard").classList.toggle("hidden", !_composed);
  $("#templateCard").classList.toggle("hidden", !_composed);
  $("#optionsCard").classList.toggle("hidden", !_composed);
  $("#composeFooter").classList.toggle("hidden", !_composed);
  populateTemplateDropdown(tool);
  try { localStorage.setItem("lastTool", tool); } catch (e) {}
  if (opts.autoDefault) {
    const def = (state.templates || []).find(t => t.is_default && t.data && t.data.tool === tool);
    if (def) applyTemplateById(def.id, true);   // silent: pre-select the default template's options
    else markActiveTplChip(0);                  // no default -> start on 「不使用範本」
  }
  setScanMode(state.scanMode);   // re-apply the mode filter to the freshly rendered grid
  updateCmdPreview();
}
// basic / advanced scan mode. basic = pick a template only; the SHARED option grid is
// filtered to just that template's settings and shown READ-ONLY. gatherOptions still
// reads the DOM either way, so the launch payload is identical -- one component, no drift.
function setScanMode(mode) {
  state.scanMode = (mode === "basic") ? "basic" : "advanced";
  $$("#modeCard .seg-btn").forEach(b => b.classList.toggle("active", b.dataset.mode === state.scanMode));
  const basic = state.scanMode === "basic";
  const oc = $("#optionsCard"); if (oc) oc.classList.toggle("mode-basic", basic);
  const bh = $("#basicHint"); if (bh) bh.classList.toggle("hidden", !basic);
  const mh = $("#modeHint"); if (mh) mh.textContent = basic ? "無腦套用範本" : "自由調整所有掃描選項";
  // 「不使用範本」is an advanced-only escape hatch: basic mode always needs a template
  const noneBtn = $("#templateChips .tpl-none");
  if (noneBtn) noneBtn.classList.toggle("hidden", basic);
  if (basic && !$("#templateChips .tpl-chip.active:not(.tpl-none)")) {
    const list = _sortByTplOrder((state.templates || []).filter(t => t.data && t.data.tool === selectedTool()), selectedTool());
    const def = list.find(t => t.is_default) || list[0];
    if (def) applyTemplateById(def.id, true);   // auto-pick so basic never shows an empty grid
  }
  _applyModeToGrid();
  updateCmdPreview();
}
// effective options for preview/launch (single source: the option controls)
function _composeOpts() {
  return gatherOptions("#optGrid", "#optToggles");
}
function _applyModeToGrid() {
  const basic = state.scanMode === "basic";
  const chip = $("#templateChips .tpl-chip.active");
  const tpl = chip ? (state.templates || []).find(t => t.id === Number(chip.dataset.tpl)) : null;
  const tplOpts = (tpl && tpl.data && tpl.data.options) || {};
  // Which of the template's options are a MEANINGFUL change from the field's default
  // -> those (and only those) are shown in basic mode. Consult the DOM per key so the
  // rule matches what actually gets launched (gatherOptions): a default-ON toggle counts
  // when turned OFF; a checks value counts only when != its tool default.
  const keys = new Set();
  Object.keys(tplOpts).forEach(k => {
    const v = tplOpts[k];
    const el = $(`#optGrid [data-optkey="${k}"], #optToggles [data-optkey="${k}"], #commonPins [data-optkey="${k}"]`);
    if (!el) return;
    if (el.classList.contains("opt-checks")) {
      if (v != null && String(v) !== "" && String(v) !== (el.dataset.def || "")) keys.add(k);
    } else if (el.type === "checkbox" && el.dataset.defon === "1") {
      if (v === false) keys.add(k);           // default-ON (force_ssl): meaningful only when OFF
    } else if (el.type === "checkbox") {
      if (v === true) keys.add(k);             // default-OFF toggle: meaningful when ON
    } else if (v !== "" && v != null && v !== false) {
      keys.add(k);
    }
  });
  $$("#optGrid [data-optkey], #optToggles [data-optkey], #commonPins [data-optkey]").forEach(el => {
    const k = el.dataset.optkey;
    const keepEditable = BASIC_EDITABLE.includes(k);   // stays live even in basic mode
    const row = el.closest(".opt-row") || el.closest(".check") || el;
    if (row.classList) {
      row.classList.toggle("basic-hidden", basic && !keys.has(k) && !keepEditable);
      row.classList.toggle("basic-editable", basic && keepEditable);
    }
    (row.querySelectorAll ? [...row.querySelectorAll("input,select,textarea,button")] : [el]).forEach(i => { i.disabled = basic && !keepEditable; });
  });
  // hide the 進階 sub-headers (請求控制 / 認證·CSRF / 列舉 / 其他 ...) that end up with no
  // visible field. They are FLAT siblings interleaved with the field rows, so walk forward
  // from each sub-header to the next one and hide it if every field between is basic-hidden.
  $$("#optGrid .opt-subhead").forEach(sh => {
    let anyVisible = false;
    for (let n = sh.nextElementSibling; n && !(n.classList && n.classList.contains("opt-subhead")); n = n.nextElementSibling) {
      const fields = (n.matches && n.matches("[data-optkey]")) ? [n] : (n.querySelectorAll ? [...n.querySelectorAll("[data-optkey]")] : []);
      if (fields.some(el => { const r = el.closest(".opt-row") || el.closest(".check") || el; return !(r.classList && r.classList.contains("basic-hidden")); })) { anyVisible = true; break; }
    }
    sh.classList.toggle("basic-hidden", basic && !anyVisible);
  });
  // hide whole group sections that end up with no visible field
  $$("#optGrid .opt-sec").forEach(sec => {
    const anyVisible = [...sec.querySelectorAll("[data-optkey]")].some(el => {
      const r = el.closest(".opt-row") || el.closest(".check") || el;
      return !(r.classList && r.classList.contains("basic-hidden"));
    });
    sec.classList.toggle("basic-hidden", basic && !anyVisible);
    if (basic && anyVisible && sec.classList.contains("collapsed")) {   // expand zones that hold the template's fields
      sec.classList.remove("collapsed");
      const car = sec.querySelector(".caret"); if (car) car.textContent = "▾";
    }
  });
}
function populateTemplateDropdown(tool) {
  // order synced with the template-settings drag order (per tool)
  const list = _sortByTplOrder((state.templates || []).filter(t => t.data && t.data.tool === tool), tool);
  const box = $("#templateChips");
  // preserve the current selection across a rebuild (settings refresh must not reset it)
  const prev = box.querySelector(".tpl-chip.active");
  const prevId = prev ? Number(prev.dataset.tpl) : 0;   // 0 = 「不使用範本」
  // "不使用範本" always first, then click-to-apply chips (no dropdown, no separate 套用 button)
  const noneChip = `<button type="button" class="tpl-chip tpl-none" data-tpl="0" title="不套用任何範本,使用預設值自行調整">不使用範本</button>`;
  box.innerHTML = noneChip + list.map(t => {
    const d = (t.data && t.data.danger) || "normal";
    const dl = d === "high" ? "高風險" : d === "safe" ? "安全" : "一般";
    const desc = (t.data && t.data.desc) || "";
    return `<button type="button" class="tpl-chip danger-${esc(d)}" data-tpl="${t.id}" data-danger="${esc(d)}" title="危險等級:${dl}${desc ? " — " + esc(desc) : ""}">${esc(t.name)}${t.is_default ? " ★" : ""}${d === "high" ? " ⚠" : ""}</button>`;
  }).join("");
  $$(".tpl-chip", box).forEach(b => b.onclick = async () => {
    const id = Number(b.dataset.tpl);
    if (id === 0) { clearTemplate(); return; }   // 「不使用範本」-> reset to defaults, no template
    if (b.dataset.danger === "high") {   // high-risk template -> confirm before applying
      const t = (state.templates || []).find(x => x.id === id);
      const ok = await confirmModal({
        title: "套用高風險範本",
        message: `「<b>${esc(t ? t.name : "")}</b>」是<b>高風險</b>範本${t && t.data && t.data.desc ? ":" + esc(t.data.desc) : ""}。確定要套用它的設定嗎?`,
        okText: "套用", cancelText: "取消", danger: true,
      });
      if (!ok) return;
    }
    applyTemplateById(id);
  });
  markActiveTplChip((prevId && list.some(t => t.id === prevId)) ? prevId : 0);   // also fills #tplHint with the active template's 備註
  const noneBtn = box.querySelector(".tpl-none");
  if (noneBtn) noneBtn.classList.toggle("hidden", state.scanMode === "basic");
  if (!list.length) $("#tplHint").textContent = "此工具尚無範本(可到範本設定建立)";
}
// 「不使用範本」: drop any applied template and start from the tool's default options
function clearTemplate() {
  const tool = selectedTool(); if (!tool) return;
  renderOptions(tool, "#optGrid", "#optToggles", "#optToolLabel", "#commonPins");
  markActiveTplChip(0);
  _applyModeToGrid();
  updateCmdPreview();
}
function markActiveTplChip(id) {
  $$("#templateChips .tpl-chip").forEach(c => c.classList.toggle("active", Number(c.dataset.tpl) === id));
  // show the active template's 備註 (desc) under the chips
  const th = $("#tplHint");
  if (th) {
    if (id === 0) th.textContent = "不套用任何範本,使用工具預設值。";
    else { const t = (state.templates || []).find(x => x.id === id); th.textContent = (t && t.data && t.data.desc) || ""; }
  }
}
function applyTemplateById(id, silent) {
  const t = (state.templates || []).find(x => x.id === id);
  if (!t) return;
  applyOptions(t.data.options || {}, "#optGrid", "#optToggles");
  updateCmdPreview();
  markActiveTplChip(id);
  _applyModeToGrid();   // basic mode: re-filter the grid to just this template's fields
  if (!silent) toast(`已套用範本「${t.name}」`, "ok");
}

// ===== command preview (what will actually run) ===========================
// --- command <-> option cross-highlight ------------------------------------
// map a CLI flag back to the 掃描選項 field it came from, so preview tokens can link
// to the controls (hover option -> glow token; click token -> jump + flash option).
const CMD_FLAG_KEY = {
  "--level": "level", "--risk": "risk", "--technique": "technique", "--dbms": "dbms", "--threads": "threads",
  "--tamper": "tamper", "--timeout": "timeout", "--time-sec": "time_sec", "--delay": "delay", "--retries": "retries",
  "--prefix": "prefix", "--suffix": "suffix", "--proxy": "proxy", "--headers": "headers", "--ignore-code": "ignore_code",
  "--string": "test_string", "--not-string": "not_string", "--regexp": "regexp", "--code": "code",
  "--auth-type": "auth_type", "--auth-cred": "auth_cred", "--csrf-token": "csrf_token", "--csrf-url": "csrf_url",
  "--force-ssl": "force_ssl", "--random-agent": "random_agent", "--text-only": "text_only",
  "--banner": "get_banner", "--current-user": "get_current_user", "--current-db": "get_current_db",
  "--hostname": "get_hostname", "--dbs": "get_dbs", "--is-dba": "is_dba", "--dump": "dump", "--dump-all": "dump_all",
  "--passwords": "passwords", "--sql-query": "sql_query", "--os-cmd": "os_cmd", "--file-read": "file_read",
  "--file-write": "file_write", "--file-dest": "file_dest",
};
// store_true flags carry no value token -> don't swallow the following token
const CMD_BARE = new Set(["--force-ssl", "--random-agent", "--text-only", "--banner", "--current-user",
  "--current-db", "--hostname", "--dbs", "--is-dba", "--dump", "--dump-all", "--passwords"]);
// key -> flag (reverse of CMD_FLAG_KEY), for the grey "ghost" preview of pinned-but-unset options
const KEY_CMD_FLAG = Object.fromEntries(Object.entries(CMD_FLAG_KEY).map(([f, k]) => [k, f]));
function _tokenizeCmd(s) {   // split on spaces, respecting the double-quotes display_cmd emits
  const toks = []; let cur = "", q = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (q) { if (ch === '"') q = false; else cur += ch; }
    else if (ch === '"') q = true;
    else if (ch === " ") { if (cur !== "") { toks.push(cur); cur = ""; } }
    else cur += ch;
  }
  if (cur !== "") toks.push(cur);
  return toks;
}
// ghostFlag (optional): render THAT flag's token greyed -- used on hover to preview where an
// unset option's flag would land. Because the string comes from the real build_args (a what-if
// preview), the ghost sits at the EXACT position the flag will occupy once enabled.
function _cmdHtml(cmd, ghostFlag) {
  const toks = _tokenizeCmd(cmd), out = [];
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    const flag = t.startsWith("--") ? t.split("=")[0] : null;
    const key = flag && CMD_FLAG_KEY[flag];
    if (key) {
      let text = t;
      if (!t.includes("=") && !CMD_BARE.has(flag) && i + 1 < toks.length && !toks[i + 1].startsWith("-")) {
        text = t + " " + toks[i + 1]; i++;   // ghauri space-form: group "--level 3"
      }
      const ghost = flag === ghostFlag ? " cmd-ghost" : "";
      const title = ghost ? "勾選後會加入此參數(此處就是實際插入位置)" : "點我跳到此設定";
      out.push(`<span class="cmd-tok${ghost}" data-optkey="${esc(key)}" title="${title}">${esc(text)}</span>`);
    } else {
      out.push(esc(t));
    }
  }
  return out.join(" ");
}
// scroll a 掃描選項 field into view + briefly highlight it (expand its zone if collapsed)
function flashOption(key) {
  const el = $(`#optGrid [data-optkey="${key}"], #optToggles [data-optkey="${key}"], #commonPins [data-optkey="${key}"]`);
  if (!el) return;
  const sec = el.closest(".opt-sec");
  if (sec && sec.classList.contains("collapsed")) { sec.classList.remove("collapsed"); const car = sec.querySelector(".caret"); if (car) car.textContent = "▾"; }
  const row = el.closest(".opt-row") || el.closest(".check") || el;
  row.scrollIntoView({ block: "center" });
  row.classList.add("opt-flash");
  clearTimeout(row._flashT); row._flashT = setTimeout(() => row.classList.remove("opt-flash"), 1300);
}
// one-time delegated wiring (survives innerHTML re-renders of the tokens/options)
function _wireCmdOptionLink() {
  const cp = $("#cmdPreview");
  if (cp && !cp._linked) {
    cp._linked = true;
    cp.addEventListener("click", e => { const tk = e.target.closest(".cmd-tok"); if (tk) flashOption(tk.dataset.optkey); });
  }
  let _hlKey = null;   // hovering any part of an option row glows its command token(s)
  const setHl = (key) => {
    if (key === _hlKey) return;
    if (_hlKey) $$(`#cmdPreview .cmd-tok[data-optkey="${_hlKey}"]`).forEach(t => t.classList.remove("cmd-tok-hl"));
    _hlKey = key;
    if (key) $$(`#cmdPreview .cmd-tok[data-optkey="${key}"]`).forEach(t => t.classList.add("cmd-tok-hl"));
  };
  // wire the same hover→highlight on both the options card AND the pinned 常用設置 strip
  ["#optGrid", "#commonPins"].forEach(sel => {
    const root = $(sel);
    if (root && !root._linked) {
      root._linked = true;
      root.addEventListener("mouseover", e => {
        const row = e.target.closest(".opt-row, .check"); const el = row && row.querySelector("[data-optkey]");
        const key = el ? el.dataset.optkey : null;
        setHl(key);
        _hoverPreview(key);   // unset toggle -> preview its flag (greyed) at the real position
      });
      root.addEventListener("mouseleave", () => { setHl(null); _clearHoverGhost(); });
    }
  });
}
// SINGLE SOURCE OF TRUTH: the backend builds the command with the SAME build_args()
// the launcher runs (POST /api/preview), so the preview can't drift from the real
// command the way a JS reimplementation would.
async function _fetchPreviewCmd(tool, opts) {
  try {
    const r = await api("/api/preview", "POST", {
      raw: ($("#rawInput").value || "").trim(), tool, options: opts,
      params: state.params || [], extra_flags: opts.extra_flags || "", force_ssl: !!opts.force_ssl,
    });
    return (r && r.ok) ? r.cmd : ("(" + ((r && r.warning) || "無法產生指令") + ")");
  } catch (e) { return "(預覽產生失敗:" + ((e && e.message) || e) + ")"; }
}
let _cmdPreviewTimer = null, _cmdPreviewSeq = 0;
function updateCmdPreview() {
  const el = $("#cmdPreview");
  const tool = selectedTool();
  const opts = tool ? _composeOpts() : {};
  // risk line stays LOCAL + instant; only the command string comes from the backend
  const ri = $("#riskIndicator");
  if (ri) {
    if (!tool) { ri.className = "risk-line hidden"; ri.textContent = ""; }
    else {
      const r = assessRisk(tool, opts);
      if (r.level === "safe") { ri.className = "risk-line risk-safe"; ri.textContent = "風險評估:安全"; }
      else {
        ri.className = "risk-line risk-" + r.level;
        const p = r.level === "danger" ? "⚠⚠ 危險:" : r.level === "high" ? "⚠ 高風險:" : "⚠ 偏高:";
        ri.textContent = p + r.reasons.join(";");
      }
    }
  }
  // Always show which scheme WILL be used, so flipping HTTPS/HTTP has a guaranteed visible
  // effect for BOTH tools -- sqlmap also toggles --force-ssl in the command, but ghauri
  // applies the scheme by rewriting the request (Referer), so its command can't change.
  const note = $("#cmdSchemeNote");
  if (note) {
    if (tool && state.parsed) {
      const https = !!opts.force_ssl;
      note.textContent = https
        ? (tool === "ghauri" ? "🔒 連線協定:HTTPS(ghauri 預設 https,指令不需旗標)"
                             : "🔒 連線協定:HTTPS(指令含 --force-ssl)")
        : (tool === "ghauri" ? "🌐 連線協定:HTTP — ghauri 會在請求注入 Referer: http://…(它沒有 --force-ssl 旗標,靠此降級)"
                             : "🌐 連線協定:HTTP(指令不含 --force-ssl)");
      note.classList.remove("hidden");
    } else { note.classList.add("hidden"); }
  }
  if (!el) return;
  if (!tool || !state.parsed) { el.textContent = "選擇工具後,這裡會顯示實際會跑的指令。"; return; }
  // debounce rapid edits into ONE call; keep showing the last value until it returns
  clearTimeout(_cmdPreviewTimer);
  const seq = ++_cmdPreviewSeq;
  _cmdPreviewTimer = setTimeout(async () => {
    const cmd = await _fetchPreviewCmd(tool, opts);
    if (seq !== _cmdPreviewSeq) return;   // ignore a superseded response
    _lastPreviewCmd = cmd;
    if (_hoverGhostKey) return;            // a hover ghost is showing -> don't clobber it
    if (cmd && cmd[0] !== "(") el.innerHTML = _cmdHtml(cmd);   // real, clickable tokens (no ghosts here)
    else el.textContent = cmd;                                 // error/placeholder -> plain text
  }, 160);
}
// Hover ghost: only while the cursor is on an UNSET toggle option, preview the flag it would
// add -- rendered greyed AT ITS REAL POSITION (we fetch the what-if command from the same
// build_args, so the preview position == the launch position). No always-on clutter.
let _hoverGhostKey = null, _hoverGhostSeq = 0, _lastPreviewCmd = "";
async function _hoverPreview(key) {
  if (key === _hoverGhostKey) return;
  const el = key && $(`#optGrid [data-optkey="${key}"], #commonPins [data-optkey="${key}"]`);
  const flag = key && KEY_CMD_FLAG[key];
  // only bare store_true toggles that are currently OFF get a hover ghost (a value field has
  // nothing to preview without a value; a segbool/HTTPS-HTTP is an explicit choice, not "unset").
  const offToggle = el && el.type === "checkbox" && !el.checked && flag && CMD_BARE.has(flag);
  if (!offToggle) { if (_hoverGhostKey) _clearHoverGhost(); return; }
  _hoverGhostKey = key;
  const seq = ++_hoverGhostSeq;
  const tool = selectedTool(); if (!tool || !state.parsed) return;
  const opts = gatherOptions("#optGrid", "#optToggles");
  const cmd = await _fetchPreviewCmd(tool, { ...opts, [key]: true });
  if (seq !== _hoverGhostSeq || _hoverGhostKey !== key) return;   // moved on / superseded
  const cp = $("#cmdPreview");
  if (cp && cmd && cmd[0] !== "(") cp.innerHTML = _cmdHtml(cmd, flag);
}
function _clearHoverGhost() {
  if (_hoverGhostKey == null) return;
  _hoverGhostKey = null; _hoverGhostSeq++;
  const cp = $("#cmdPreview");   // restore the real command instantly (no refetch)
  if (cp && _lastPreviewCmd && _lastPreviewCmd[0] !== "(") cp.innerHTML = _cmdHtml(_lastPreviewCmd);
  else updateCmdPreview();
}

// ===== 編輯指令 (hand-edit the command, then reverse-parse it back into the options) =====
// The safe two-way flow: entering edit LOCKS the options (text is the source of truth); on
// 套用 we reverse-parse the text back into the controls (recognised flags flash, the rest go
// to 額外參數), then re-generate the command from the options -> never "對不上".
function _lockOptions(locked) {
  ["#optionsCard", "#templateCard", "#modeCard", "#commonPins"].forEach(sel => {
    const el = $(sel); if (el) el.classList.toggle("opts-locked", locked);
  });
  const lb = $("#launchBtn"); if (lb) lb.disabled = locked;   // no launching mid-edit
}
async function enterCmdEdit() {
  const tool = selectedTool(); if (!tool || !state.parsed) return;
  _clearHoverGhost();
  const cmd = await _fetchPreviewCmd(tool, _composeOpts());   // seed with the exact current command
  const ta = $("#cmdEdit"); if (!ta) return;
  ta.value = (cmd && cmd[0] !== "(") ? cmd : "";
  $("#cmdPreview").classList.add("hidden"); ta.classList.remove("hidden");
  $("#cmdEditBtn").classList.add("hidden");
  $("#cmdApplyBtn").classList.remove("hidden"); $("#cmdCancelBtn").classList.remove("hidden");
  _lockOptions(true);
  state.cmdEditing = true;
  ta.focus();
}
function _exitCmdEdit() {
  const ta = $("#cmdEdit"); if (ta) ta.classList.add("hidden");
  $("#cmdPreview").classList.remove("hidden");
  $("#cmdEditBtn").classList.remove("hidden");
  $("#cmdApplyBtn").classList.add("hidden"); $("#cmdCancelBtn").classList.add("hidden");
  _lockOptions(false);
  state.cmdEditing = false;
}
function cancelCmdEdit() { _exitCmdEdit(); updateCmdPreview(); }
function applyCmdEdit() {
  const edited = (($("#cmdEdit") && $("#cmdEdit").value) || "").trim();
  if (state.scanMode !== "advanced") setScanMode("advanced");   // reveal the reflected options to keep editing
  const { opts, recognized, unknownCount } = _reverseParseCmd(edited);
  applyOptions(opts, "#optGrid", "#optToggles");   // absent keys reset to default -> options MATCH the text
  _exitCmdEdit();
  _flashOptions(recognized);
  updateCmdPreview();   // regenerate the command from the now-updated options -> in sync
  toast(recognized.length + " 個選項已回填" + (unknownCount ? (",另 " + unknownCount + " 個未知旗標放進『額外參數』") : ""), "ok");
}
// tokenised command -> { opts, recognized[], unknownCount }. Managed core (-r/--batch/
// --disable-coloring/--output-dir) is skipped; unknown or not-for-this-tool flags -> extra_flags.
function _shellQuote(t) {   // re-quote a token with whitespace/quotes so backend shlex.split keeps it whole
  return /[\s"'\\]/.test(t) ? '"' + String(t).replace(/(["\\])/g, "\\$1") + '"' : t;
}
function _reverseParseCmd(cmd) {
  const toks = _tokenizeCmd(cmd || "");
  const opts = {}, recognized = [], extras = [];
  // a token is a FLAG (not a value) if it's a managed core arg or a mapped option flag
  const isFlag = t => t === "-r" || t === "--batch" || t === "--disable-coloring"
    || t.startsWith("--output-dir") || !!CMD_FLAG_KEY[t.split("=")[0]];
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (i === 0) continue;                                   // tool name
    if (t === "-r") { i++; continue; }                       // managed: -r <request file>
    if (t === "--batch" || t === "--disable-coloring") continue;
    if (t.startsWith("--output-dir")) { if (!t.includes("=")) i++; continue; }
    if (!t.startsWith("-")) { extras.push(t); continue; }
    let flag = t, val = null;
    const eq = t.indexOf("=");
    if (eq >= 0) { flag = t.slice(0, eq); val = t.slice(eq + 1); }
    const key = CMD_FLAG_KEY[flag];
    const el = key && document.querySelector(`#optGrid [data-optkey="${key}"], #commonPins [data-optkey="${key}"]`);
    if (!el) { extras.push(t); continue; }                    // unknown / not-for-this-tool -> keep raw
    if (CMD_BARE.has(flag)) { opts[key] = true; recognized.push(key); continue; }
    if (val === null) {                                       // space-form: next token IS the value...
      if (i + 1 < toks.length && !isFlag(toks[i + 1])) { val = toks[i + 1]; i++; }   // ...even if it starts with '-' (e.g. --suffix "-- -")
      else val = "";
    }
    opts[key] = val; recognized.push(key);
  }
  // scheme: only sqlmap renders --force-ssl in its command; ghauri's command carries no scheme
  // flag, so inferring it would wrongly downgrade -> keep the current seg-bool value instead.
  const tool = selectedTool();
  opts.force_ssl = (tool === "sqlmap")
    ? toks.some(t => t === "--force-ssl")
    : !!gatherOptions("#optGrid", "#optToggles").force_ssl;
  if (tool === "sqlmap" && opts.force_ssl && recognized.indexOf("force_ssl") < 0) recognized.push("force_ssl");
  if (extras.length) opts.extra_flags = extras.map(_shellQuote).join(" ");   // preserve quoted multi-word values
  return { opts, recognized: [...new Set(recognized)], unknownCount: extras.filter(t => t.startsWith("-")).length };
}
function _flashOptions(keys) {
  (keys || []).forEach(key => {
    const el = $(`#optGrid [data-optkey="${key}"], #optToggles [data-optkey="${key}"], #commonPins [data-optkey="${key}"]`);
    if (!el) return;
    const row = el.closest(".opt-row") || el.closest(".check") || el;
    row.classList.add("opt-flash");
    clearTimeout(row._flashT); row._flashT = setTimeout(() => row.classList.remove("opt-flash"), 1600);
  });
}

// ===== launch =============================================================
// Assess how intrusive the CURRENT options are, so the launch confirm can warn.
// "risk 之類的等級設太高" -> high; noisy/heavy settings -> elevated.
function assessRisk(tool, o) {
  const reasons = []; let level = "safe";
  const rank = { safe: 0, elevated: 1, high: 2, danger: 3 };
  const bump = (lv, why) => { if (rank[lv] > rank[level]) level = lv; if (why) reasons.push(why); };
  const risk = Number(o.risk), lvl = Number(o.level), thr = Number(o.threads);
  if (tool === "sqlmap" && risk >= 3) bump("high", "risk=3:啟用 OR-based 等重量級 payload,若注入點落在 UPDATE/DELETE 語句可能『修改或刪除多列資料』(具破壞性)");
  else if (tool === "sqlmap" && risk === 2) bump("elevated", "risk=2:加入 heavy-query/BENCHMARK 時間盲注,會讓目標 DB CPU 飆高(慢環境恐影響服務)");
  // tamper(繞 WAF):payload 變形改寫,較 aggressive -- 之前完全沒評估到
  if (tool === "sqlmap" && String(o.tamper || "").trim())
    bump("elevated", "tamper(繞 WAF):把 payload 變形改寫,較 aggressive,且部分腳本只對特定 WAF/DBMS 有效、亂套可能讓 payload 失效");
  // NOTE: technique 'S' 不再單獨警告 -- 兩工具預設就含 S,gatherOptions 又會省略等於預設的值,
  // 導致「用預設(含 S)不警告、反而縮小選擇時才警告」的反效果;真正危險的寫入/取 shell 由 --sql-query/--os-cmd 涵蓋。
  if (lvl >= 5) bump("elevated", "level=5:測試面最廣、請求量與噪音最大");
  else if (lvl === 4) bump("elevated", "level=4:測試面較廣、較慢");
  if (thr >= 10) bump("elevated", "threads=" + thr + ":高併發,對目標壓力大、較易觸發防護");
  else if (thr >= 8) bump("elevated", "threads=" + thr + ":併發偏高");
  // 危險旗標偵測:取 shell / 執行 SQL / 讀寫檔案 / 匯出資料
  const DANGER = { sql_query: "執行任意 SQL(--sql-query)", os_cmd: "執行 OS 命令(--os-cmd)",
    file_read: "讀取伺服器檔案(--file-read)", file_write: "寫入檔案到伺服器(--file-write)",
    file_dest: "寫檔目標路徑(--file-dest)", dump: "匯出資料表(--dump)",
    dump_all: "匯出整個 DB(--dump-all)", passwords: "抓密碼雜湊(--passwords)" };
  const hit = Object.keys(DANGER).filter(k => o[k]);
  if (hit.length) {
    // code-execution / file-plant is strictly worse than data exfil -> lead with it
    const rce = hit.filter(k => k === "os_cmd" || k === "file_write" || k === "file_dest");
    const other = hit.filter(k => rce.indexOf(k) < 0);
    let msg = "";
    if (rce.length) msg += "⚠⚠⚠ 最高破壞性・遠端代碼執行/植入檔案:" + rce.map(k => DANGER[k]).join("、");
    if (other.length) msg += (rce.length ? ";另含 " : "⚠⚠ 危險操作:") + other.map(k => DANGER[k]).join("、");
    msg += " — 務必確認在授權範圍內(取 shell / 改資料 / 讀寫檔案)";
    bump("danger", msg);
  }
  // 額外參數 / edited commands are free text, so the structured DANGER map above can't see them --
  // scan the raw flag string for the same destructive/aggressive flags (otherwise typed
  // --dump-all/--os-cmd would launch as "safe"). Also covers advanced-mode 額外參數.
  const ef = String(o.extra_flags || "");
  if (ef) {
    const EF_DANGER = [
      [/--os-(cmd|shell|pwn)\b/, "在 DB 主機執行系統命令/取 shell(--os-*)"],
      [/--file-(write|dest)\b/, "寫檔到伺服器(--file-write/--file-dest)"],
      [/--(sql-query|sql-shell)\b/, "在目標執行任意 SQL(--sql-query/--sql-shell)"],
      [/--file-read\b/, "讀取伺服器檔案(--file-read)"],
      [/--dump-all\b/, "匯出整個 DB(--dump-all)"],
      [/--dump\b/, "匯出資料表(--dump)"],
      [/--passwords\b/, "抓密碼雜湊(--passwords)"],
    ];
    const efHit = EF_DANGER.filter(([re]) => re.test(ef)).map(([, m]) => m);
    if (efHit.length) bump("danger", "自訂/額外參數含高破壞性旗標:" + efHit.join("、") + " — 務必確認在授權範圍內");
    if (/--risk[\s=]+3\b/.test(ef)) bump("high", "自訂 --risk 3:重量級 payload,注入點在 UPDATE/DELETE 可能改動多列");
    if (/--(os-shell|sql-shell)\b/.test(ef)) bump("high", "互動式旗標(--os-shell/--sql-shell)在背景執行會卡住(沒有 stdin)");
  }
  return { level, reasons };
}
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
  const opts = _composeOpts();
  const proj = (state.projects || []).find(p => p.id === state.projectId) || {};
  // ALWAYS confirm before running -- never launch on a single click.
  const risk = assessRisk(tool, opts);
  const selCount = state.params.filter(p => p.selected).length;
  const target = state.parsed.endpoint || (state.parsed.parsed && state.parsed.parsed.url) || "";
  const riskHead = risk.level === "danger" ? "⚠⚠ 危險操作(高破壞性)"
    : risk.level === "high" ? "⚠ 高風險設定" : "⚠ 偏高設定";
  const riskHtml = risk.level === "safe" ? "" :
    `<div class="risk-box risk-${risk.level}"><b>${riskHead}</b><ul>${risk.reasons.map(r => `<li>${esc(r)}</li>`).join("")}</ul></div>`;
  const previewCmd = await _fetchPreviewCmd(tool, opts);   // authoritative command (same build_args as the real run)
  const ok = await confirmModal({
    title: "確認開始掃描",
    message: `工具 <b>${esc(tool)}</b> · 勾選 <b>${selCount}</b> 個參數<br>
      <span class="mono-label">目標</span> ${esc(target)}
      <div class="cmd-confirm">${esc(previewCmd)}</div>${riskHtml}`,
    okText: risk.level === "danger" ? "我了解具破壞性,仍要執行"
      : risk.level === "high" ? "我了解風險,仍要開始" : "開始掃描",
    cancelText: "再檢查一下",
    danger: (risk.level === "high" || risk.level === "danger"),
  });
  if (!ok) return;
  const btn = $("#launchBtn"); btn.disabled = true;
  try {
    const r = await api("/api/scans", "POST", {
      raw: $("#rawInput").value.trim(), force_ssl: !!opts.force_ssl, project_id: state.projectId,
      tool, options: opts, params: state.params, extra_flags: opts.extra_flags || "",
      restrict_ip: proj.restrict_ip || "",   // project-level memo, carried onto the scan
      note: ($("#scanNote").value || "").trim(),
    });
    toast(`已加入掃描 #${(r.launched[0] || {}).id || ""}(背景執行中)`, "ok");
    $("#scanNote").value = "";   // fresh note per run
    await loadScans();
  } catch (e) { toast("啟動失敗:" + e.message, "err"); }
  finally { btn.disabled = false; }
}

// ===== sidebar board ======================================================
async function loadScans() {
  if (state.projectId == null) { state.allScans = []; state.scans = []; renderBoardIfChanged(true); renderTreeIfChanged(true); return; }
  const q = new URLSearchParams({ project_id: state.projectId, limit: 500, slim: 1 });
  try { state.allScans = await api("/api/scans?" + q.toString()); } catch (e) { return; }
  applyScanFilter();          // outcome filter -> state.scans + board + chip counts
  renderTreeIfChanged();
}
// filter chips are outcome-based (有漏洞/無洞/掃描中/失敗) so they match the row's
// left-border colour axis, instead of the old raw-status dropdown.
const SCAN_FILTERS = [
  { key: "", label: "全部" },
  { key: "vuln", label: "有漏洞" },
  { key: "inconclusive", label: "測不準" },   // ran but result not trustworthy as 無洞
  { key: "clean", label: "無洞" },
  { key: "running", label: "掃描中" },
  { key: "other", label: "失敗/中止" },   // 'other' = error/stopped(失敗) AND killed(已中止)
];
function applyScanFilter(force) {
  const f = state.scanFilter || "";
  state.scans = f ? (state.allScans || []).filter(s => scanOutcome(s).key === f) : (state.allScans || []);
  renderBoardIfChanged(force);
  renderScanFilterChips();
}
function renderScanFilterChips() {
  const box = $("#scanFilterChips"); if (!box) return;
  const all = state.allScans || [];
  const counts = {};
  all.forEach(s => { const k = scanOutcome(s).key; counts[k] = (counts[k] || 0) + 1; });
  const active = state.scanFilter || "";
  const sig = active + "|" + SCAN_FILTERS.map(f => (f.key === "" ? all.length : (counts[f.key] || 0))).join(",");
  if (box._sig === sig) return;   // counts/active unchanged -> skip (no poll churn / hover flicker)
  box._sig = sig;
  box.innerHTML = SCAN_FILTERS.map(f => {
    const n = f.key === "" ? all.length : (counts[f.key] || 0);
    const dot = f.key ? `<span class="fc-dot st-${f.key}"></span>` : "";
    return `<button class="filter-chip${active === f.key ? " active" : ""}" data-filter="${f.key}">${dot}${f.label}<span class="fc-count">${n}</span></button>`;
  }).join("");
  $$("[data-filter]", box).forEach(el => el.onclick = () => { state.scanFilter = el.dataset.filter; applyScanFilter(true); });
}
function boardSignature() { const bp = _boardPending(); return state.scans.map(s => `${s.id}:${s.status}:${s.vulnerable}`).join("|") + "@" + state.detailId + "|P" + (bp ? bp.label : ""); }
function renderBoardIfChanged(force) {
  const key = boardSignature();
  if (!force && key === state.boardKey) return;
  state.boardKey = key;
  const board = $("#scanBoard");
  const bp = _boardPending();
  $("#boardEmpty").classList.toggle("hidden", state.scans.length > 0 || !!bp);
  const pendHtml = bp
    ? `<div class="scan-pending${bp.parsed ? " parsed" : ""}" title="此分頁掃描後,結果會插入此清單"><span class="sp-dot"></span>${esc(bp.label)}</div>`
    : "";
  board.innerHTML = pendHtml + state.scans.map(renderScanRow).join("");
  $$(".scan-row", board).forEach(el => el.onclick = () => openScanDetail(parseInt(el.dataset.id, 10)));
  $$("[data-rowstop]", board).forEach(b => b.onclick = (e) => { e.stopPropagation(); stopScan(parseInt(b.dataset.rowstop, 10)); });
  $$("[data-rowdel]", board).forEach(b => b.onclick = (e) => { e.stopPropagation(); deleteScan(parseInt(b.dataset.rowdel, 10)); });
  // only refresh composer badges when a RESULT actually changed -- not on merely
  // opening a scan detail (which changes boardSignature via detailId).
  const rKey = state.scans.map(s => `${s.id}:${s.status}:${s.vulnerable}`).join("|");
  if (rKey !== state._resultsKey) { state._resultsKey = rKey; refreshParamBadges(); }
}
// Live-update the composer's per-parameter 測過/無洞/有漏洞 badges when a scan for
// the currently-parsed endpoint finishes -- no need to re-paste + re-parse.
async function refreshParamBadges() {
  if (!state.parsed || state.projectId == null || !(state.params || []).length) return;
  const sigEp = state.parsed.sig_endpoint; if (!sigEp) return;
  let hist;
  try { hist = await api(`/api/param-history?project_id=${state.projectId}&sig_endpoint=${encodeURIComponent(sigEp)}`); }
  catch (e) { return; }
  const by = {}; (hist || []).forEach(h => { by[h.location + "|" + h.name] = h; });
  let changed = false;
  state.params.forEach(p => {
    const h = by[p.location + "|" + p.name];
    const ns = h ? h.status : null, nv = h ? !!h.vulnerable : false, nc = h ? h.test_count : 0;
    if (p.prior_status !== ns || p.prior_vulnerable !== nv || p.prior_test_count !== nc) {
      p.prior_status = ns; p.prior_vulnerable = nv; p.prior_test_count = nc; changed = true;
    }
  });
  if (changed) renderParams();
}
// THE single canonical outcome for a scan -> one label + one colour, used
// everywhere (scan list, tree, detail header, verdict headline). This replaces the
// old separate status badge + result chip so there is ONE colour axis, not three.
function scanOutcome(s) {
  if (s.vulnerable) return { key: "vuln", label: "有漏洞", cls: "st-vuln" };
  if (s.status === "running" || s.status === "queued") return { key: "running", label: "掃描中", cls: "st-running" };
  if (s.status === "inconclusive") return { key: "inconclusive", label: "測不準", cls: "st-inconclusive" };
  if (s.status === "done") return { key: "clean", label: "無洞", cls: "st-clean" };
  if (s.status === "killed") return { key: "other", label: "已中止", cls: "st-other" };
  return { key: "other", label: "失敗", cls: "st-other" };   // error / stopped
}
function stateChip(s) { const o = scanOutcome(s); return `<span class="state-chip ${o.cls}">${o.label}</span>`; }
function renderScanRow(s) {
  const st = scanOutcome(s).key;   // border colour matches the chip -> one axis
  const time = s.started_at ? new Date(s.started_at).toLocaleTimeString() : new Date(s.created_at).toLocaleTimeString();
  const dur = s.duration_ms ? " · " + fmtDur(s.duration_ms) : "";
  const canStop = s.status === "running" || s.status === "queued";
  const pouts = s.pouts || [];   // tested params (skipped omitted); v = has an injection point
  const pchips = pouts.length
    ? `<div class="scan-row-params">${pouts.map(po => { const st = po.st || (po.v ? "vuln" : "unknown"); const m = { vuln: ["pv", "有注入點"], clean: ["pc", "無注入點"], tentative: ["pt", "疑似(待確認)"], unknown: ["pu", "未測(無此參數證據)"] }[st] || ["pu", "未測"]; return `<span class="pchip ${m[0]}" title="${esc(po.n)} · ${m[1]}">${esc(po.n)}</span>`; }).join("")}</div>`
    : "";
  return `<div class="scan-row st-${st} ${s.id === state.detailId ? "active" : ""}${s.id === state.flashScanId ? " flash-target" : ""}" data-id="${s.id}">
    ${stateChip(s)}
    <div class="scan-row-main">
      <div class="scan-row-top"><span class="scan-tool">${esc(s.tool)}</span><span class="scan-id">#${s.id}</span></div>
      <div class="scan-row-bot"><span class="scan-ep" title="${esc(s.endpoint || s.url)}">${esc(s.endpoint || s.url)}</span><span class="scan-meta">${time}${dur}</span></div>
      ${pchips}
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
//   vuln(red) > running(orange) > inconclusive/測不準(violet) > clean/無洞(green) > other:error/killed(grey) > untested(grey)
// This is the single "severity" axis. The current-searched path is shown on a
// SEPARATE axis (the accent connector line) so the two never clash. inconclusive
// ranks ABOVE clean so a node holding any 測不準 scan never shows solid green.
function scanState(s) {
  if (s.vulnerable) return "vuln";
  if (s.status === "running" || s.status === "queued") return "running";
  if (s.status === "inconclusive") return "inconclusive";
  if (s.status === "done") return "clean";
  return "other"; // error / killed / stopped
}
const STATE_RANK = { vuln: 0, running: 1, inconclusive: 2, clean: 3, other: 4, untested: 5 };
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
    const segs = path.split("/").filter(x => x !== "");
    if (!segs.length) {   // site root ("/") -> a dedicated "/" child node, not the host row itself,
      if (!node.children.has("/")) node.children.set("/", _tnode("/", "/"));   // so root scans + the "目前" placeholder have a real home
      return node.children.get("/");
    }
    for (const seg of segs) {
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
  return `<div class="tnode"><div class="trow tscan${s.id === state.detailId ? " detail-active" : ""}${s.id === state.flashScanId ? " flash-target" : ""}" data-scan="${s.id}">${stateChip(s)}${method}<span class="scan-tool">${esc(s.tool)}</span><span class="tscan-meta">#${s.id} ${esc(t)}</span><button class="tscan-del" data-delscan="${s.id}" title="刪除此掃描紀錄">✕</button></div></div>`;
}
function renderPathNode(host, rawNode, exp, cur, depth) {
  const { label, node } = compactChain(rawNode);
  const key = "p:" + host + "|" + node.path;
  const kids = [...node.children.values()];
  const expandable = node.scans.length > 0 || kids.length > 0;
  const open = expandable && exp.has(key);
  const st = subtreeState(node);
  const isCur = cur && cur.host === host && cur.path === node.path;
  const onPath = cur && cur.host === host && (cur.path === node.path || cur.path.startsWith(node.path + "/"));
  const curChip = node.synthetic ? '<span class="cur-tag ghost">目前(尚未掃描)</span>'
                : (isCur ? '<span class="cur-tag">目前</span>' : '');
  const count = node.scans.length ? `<span class="tcount">${node.scans.length}</span>`
              : (kids.length ? `<span class="tcount">${kids.length}</span>` : '');
  let inner = "";
  if (open) {
    let parts = node.scans.slice().sort((a, b) => b.created_at - a.created_at).map(scanLeaf).join("");
    parts += kids.sort((a, b) => a.seg.localeCompare(b.seg)).map(c => renderPathNode(host, c, exp, cur, (depth || 0) + 1)).join("");
    inner = `<div class="tchildren">${parts}</div>`;
  }
  const caret = expandable ? (open ? "▾" : "▸") : "";
  const dataKey = expandable ? ` data-key="${esc(key)}"` : "";
  // at a LAST node (no children), optionally APPEND the full domain+path as grey
  // text after the node's own name, so you don't have to trace it down the tree.
  const isLeaf = node.children.size === 0;
  const fullSuffix = (state.treeFullPath && isLeaf && node.path)
    ? `<span class="tep-full">${esc(host + node.path)}</span>` : "";
  return `<div class="tnode${onPath ? " on-path" : ""}"><div class="trow tep tsticky st-${st}"${dataKey} style="top:calc(var(--th)*${depth || 0})"><span class="tcaret">${caret}</span><span class="tdot"></span><span class="tep-label" title="${esc(host + (node.path || ""))}">${esc(label)}</span>${fullSuffix}${curChip}${count}</div>${inner}</div>`;
}
// the synthetic "目前(尚未掃描)" node is a COMPOSING hint -> only on the dashboard,
// never on settings/projects, so it can't be mistaken for a recorded scan.
function _liveTarget() { return state.view === "dashboard" ? state.currentTarget : null; }
function renderTreeIfChanged(force) {
  renderTreeFilterChips();
  const lt = _liveTarget();
  const cur = lt ? lt.host + "|" + lt.path : "";
  const key = (state.allScans || []).map(s => s.id + ":" + s.status + ":" + s.vulnerable).join("|") +
    "#" + Array.from(state.treeExpanded || []).join(",") + "~" + Array.from(state.tempScanPath || []).join(",") + "@" + cur + "!" + (state.detailId || "") + "|P" + (_pendingCompose() ? 1 : 0) + "|F" + (state.treeFilter || "");
  if (!force && key === state.treeKey) return;
  state.treeKey = key;
  renderTree();
}
// tree outcome filter -- same chips/counts as the queue side (全部/有漏洞/無洞/掃描中/失敗)
function renderTreeFilterChips() {
  const box = $("#treeFilterChips"); if (!box) return;
  const all = state.allScans || [];
  const counts = {};
  all.forEach(s => { const k = scanOutcome(s).key; counts[k] = (counts[k] || 0) + 1; });
  const active = state.treeFilter || "";
  const sig = active + "|" + SCAN_FILTERS.map(f => (f.key === "" ? all.length : (counts[f.key] || 0))).join(",");
  if (box._sig === sig) return;   // unchanged -> skip (no poll churn)
  box._sig = sig;
  box.innerHTML = SCAN_FILTERS.map(f => {
    const n = f.key === "" ? all.length : (counts[f.key] || 0);
    const dot = f.key ? `<span class="fc-dot st-${f.key}"></span>` : "";
    return `<button class="filter-chip${active === f.key ? " active" : ""}" data-filter="${f.key}">${dot}${f.label}<span class="fc-count">${n}</span></button>`;
  }).join("");
  $$("[data-filter]", box).forEach(el => el.onclick = () => { state.treeFilter = el.dataset.filter; renderTreeIfChanged(true); });
}
function renderTree() {
  if (!state.treeExpanded) state.treeExpanded = loadTreeExpanded();
  const box = $("#treeBox");
  const scans = (state.allScans || []).filter(s => !state.treeFilter || scanOutcome(s).key === state.treeFilter);   // tree outcome filter
  const cur = _liveTarget();
  // manual (persisted) expansions unioned with the transient single-scan reveal
  const exp = new Set([...(state.treeExpanded || []), ...(state.tempScanPath || [])]);
  const hosts = buildPathTree(scans, cur);
  const pend = _pendingCompose();
  $("#treeEmpty").classList.toggle("hidden", Object.keys(hosts).length > 0 || pend);
  const pendHtml = pend
    ? `<div class="tnode"><div class="trow tpending"><span class="tcaret"></span><span class="tdot"></span><span class="tep-label">⏳ 待解析(此分頁)</span></div></div>`
    : "";
  box.innerHTML = pendHtml + Object.keys(hosts).sort().map(hn => {
    const rootNode = hosts[hn]; const hkey = "h:" + hn; const hopen = exp.has(hkey);
    const kids = [...rootNode.children.values()];
    const hState = subtreeState(rootNode);
    const hCur = cur && cur.host === hn;
    let inner = "";
    if (hopen) {
      let parts = rootNode.scans.slice().sort((a, b) => b.created_at - a.created_at).map(scanLeaf).join("");
      parts += kids.sort((a, b) => a.seg.localeCompare(b.seg)).map(c => renderPathNode(hn, c, exp, cur, 1)).join("");
      inner = `<div class="tchildren">${parts}</div>`;
    }
    const hCount = kids.length ? `<span class="tcount">${kids.length}</span>`
                 : (rootNode.scans.length ? `<span class="tcount">${rootNode.scans.length}</span>` : '');
    return `<div class="tnode${hCur ? " on-path" : ""}"><div class="trow thost tsticky st-${hState}" data-key="${esc(hkey)}" style="top:0"><span class="tcaret">${hopen ? "▾" : "▸"}</span><span class="tdot"></span><span class="thost-name">${esc(hn)}</span>${hCount}</div>${inner}</div>`;
  }).join("");
  $$(".trow[data-key]", box).forEach(el => el.onclick = () => toggleTreeNode(el.dataset.key));
  $$(".tscan[data-scan]", box).forEach(el => el.onclick = () => openScanDetail(parseInt(el.dataset.scan, 10)));
  $$("[data-delscan]", box).forEach(b => b.onclick = (e) => { e.stopPropagation(); deleteScan(parseInt(b.dataset.delscan, 10)); });
}
// keys of pure record-leaf endpoints (have scans, no child paths) -- the nodes whose
// records the 展開含紀錄 accordion governs
function _recordKeys() {
  const set = new Set();
  const hosts = buildPathTree(state.allScans || [], _liveTarget());
  const walk = (host, node) => {
    if (node.scans && node.scans.length > 0 && node.children.size === 0) set.add("p:" + host + "|" + node.path);
    for (const c of node.children.values()) walk(host, c);
  };
  for (const hn of Object.keys(hosts)) walk(hn, hosts[hn]);
  return set;
}
function toggleTreeNode(key) {
  if (!state.treeExpanded) state.treeExpanded = loadTreeExpanded();
  // a node can be open via the manual set OR the active-scan reveal (tempScanPath);
  // collapsing must clear BOTH so the reveal can't re-open it every render.
  const openNow = state.treeExpanded.has(key) || !!(state.tempScanPath && state.tempScanPath.has(key));
  if (openNow) {
    state.treeExpanded.delete(key);
    if (state.tempScanPath) state.tempScanPath.delete(key);
  } else {
    // 展開含紀錄 OFF -> accordion: only ONE record-leaf's records open at a time
    if (!state.treeFullRecords) {
      const recs = _recordKeys();
      if (recs.has(key)) {
        for (const k of Array.from(state.treeExpanded)) if (k !== key && recs.has(k)) state.treeExpanded.delete(k);
        if (state.tempScanPath) for (const k of Array.from(state.tempScanPath)) if (k !== key && recs.has(k)) state.tempScanPath.delete(k);
      }
    }
    state.treeExpanded.add(key);
  }
  saveTreeExpanded(); renderTreeIfChanged(true);
}
// withRecords=false -> expand path structure down to the LAST nodes only (each
// endpoint's individual scan records stay collapsed). withRecords=true -> expand
// everything including the scan records. Default action is the former.
function treeExpandAll(withRecords) {
  const hosts = buildPathTree(state.allScans || [], _liveTarget());
  const set = new Set();
  const walk = (host, node, isRoot) => {
    const hasKids = node.children.size > 0;
    if (isRoot || hasKids || (withRecords && node.scans.length > 0)) {
      set.add(isRoot ? "h:" + host : "p:" + host + "|" + node.path);
    }
    for (const c of node.children.values()) walk(host, c, false);
  };
  for (const hn of Object.keys(hosts)) walk(hn, hosts[hn], true);
  state.treeExpanded = set; state.tempScanPath = new Set();
  saveTreeExpanded(); renderTreeIfChanged(true);
}
function treeCollapseAll() { state.treeExpanded = new Set(); state.tempScanPath = new Set(); saveTreeExpanded(); renderTreeIfChanged(true); }
// toggling 展開含紀錄 now acts immediately (was: only affected the next 展開 click, which
// felt unresponsive). ON -> expand the whole tree incl. every record; OFF -> hide the
// record leaves (collapse pure record-leaf endpoints) while keeping node expansion.
function applyFullRecordsToggle() {
  if (state.treeFullRecords) { treeExpandAll(true); return; }
  if (!state.treeExpanded) state.treeExpanded = loadTreeExpanded();
  const hosts = buildPathTree(state.allScans || [], _liveTarget());
  const walk = (host, node) => {
    if (node.scans.length > 0 && node.children.size === 0) state.treeExpanded.delete("p:" + host + "|" + node.path);
    for (const c of node.children.values()) walk(host, c);
  };
  for (const hn of Object.keys(hosts)) walk(hn, hosts[hn]);
  saveTreeExpanded(); renderTreeIfChanged(true);
}
// remembered tree UI prefs (global, survive F5 + server restart via localStorage)
function loadTreePrefs() {
  try { state.treeFullPath = localStorage.getItem("treeFullPath") !== "0"; } catch (e) { state.treeFullPath = true; }
  try { state.treeFullRecords = localStorage.getItem("treeFullRecords") === "1"; } catch (e) { state.treeFullRecords = false; }
}
function saveTreeFullPath() { try { localStorage.setItem("treeFullPath", state.treeFullPath ? "1" : "0"); } catch (e) {} }
function saveTreeFullRecords() { try { localStorage.setItem("treeFullRecords", state.treeFullRecords ? "1" : "0"); } catch (e) {} }

// ===== scan detail modal ==================================================
function findingsHtml(s) {
  let f = s.result; if (!f && s.result_json) { try { f = JSON.parse(s.result_json); } catch (e) {} }
  const rows = [];
  const kv = (k, v, cls) => rows.push(`<div class="kv"><b>${k}</b><span${cls ? ` class="${cls}"` : ""}>${esc(v)}</span></div>`);
  if (s.note) rows.push(`<div class="kv wide"><b>備註</b><span>${esc(s.note)}</span></div>`);
  if (s.error) rows.push(`<div class="kv"><b>錯誤</b><span style="color:var(--danger)">${esc(s.error)}</span></div>`);
  if (f) {
    if (f.dbms) kv("DBMS", f.dbms);
    if (f.parameters && f.parameters.length) kv("可注入參數", f.parameters.join(" / "));
    if (f.types && f.types.length) kv("類型", [...new Set(f.types)].join("；"));           // technique classes
    if (f.titles && f.titles.length) kv("標題", f.titles.slice(0, 4).join("；"));            // was mislabelled 類型
    if (f.payloads && f.payloads.length) rows.push(`<div class="kv"><b>Payload</b><span class="mono-val">${esc(f.payloads[0])}${f.payloads.length > 1 ? ` (共 ${f.payloads.length} 個)` : ""}</span></div>`);
    // enumeration (only present when the run asked for --banner/--current-*/--is-dba/--dbs)
    if (f.banner) kv("Banner", f.banner);
    if (f.current_user) kv("目前使用者", f.current_user);
    if (f.is_dba === true) kv("DBA 權限", "是(影響程度高)", "vuln-txt");
    else if (f.is_dba === false) kv("DBA 權限", "否");
    if (f.current_db) kv("目前資料庫", f.current_db);
    if (f.hostname) kv("主機名", f.hostname);
    if (f.databases && f.databases.length) kv("資料庫", f.databases.join(" / "));
    else if (f.databases_count != null) kv("資料庫數", f.databases_count);
    if (f.tables_count != null) kv("資料表數", f.tables_count);
    if (f.table_names && f.table_names.length) kv("資料表", f.table_names.join(" / "));
    if (f.columns_count != null) kv("欄位數", f.columns_count);
    if (f.entries_count != null) kv("匯出列數", f.entries_count);
    if (f.db_users && f.db_users.length) kv("DB 使用者", f.db_users.join(" / "));
    if (f.password_hashes && f.password_hashes.length) kv("密碼雜湊", f.password_hashes.length + " 筆");
    if (f.web_tech) kv("Web 技術", f.web_tech);
    if (f.heuristic_sqli && f.heuristic_sqli.length) kv("heuristic 疑似可注入", f.heuristic_sqli.join(" / "));
    // bonus non-SQLi heuristic findings surfaced during the SQLi run
    if (f.heuristic_xss && f.heuristic_xss.length) kv("附帶・疑似 XSS", f.heuristic_xss.join(" / "));
    if (f.heuristic_fi && f.heuristic_fi.length) kv("附帶・疑似 FI", f.heuristic_fi.join(" / "));
    // reliability caveats explaining a possibly-false result
    if (f.caveats && f.caveats.length) kv("可靠度提醒", f.caveats.map(c => c.note || c.marker).join("；"));
  }
  return rows.join("");
}
// per-parameter outcome (mirrors the backend param-history logic) so the detail
// view can show WHICH params were tested / skipped / vulnerable / clean.
function _paramOutcome(p, f, scanVuln, scanDone) {
  if (!p.selected) return { label: "已略過", cls: "st-skip" };
  const pp = (f && f.per_param) || {};
  const vulnNames = (f && f.parameters) || [];
  if (vulnNames.indexOf(p.name) >= 0 || pp[p.name] === "vulnerable") return { label: "有漏洞", cls: "st-vuln" };
  if (f && f.reliability_ok === false) return { label: "未測", cls: "st-untested" };  // 測不準:baseline 不可信,per-param clean 不採信
  if (pp[p.name] === "clean") return { label: "無洞", cls: "st-clean" };            // tool said clean for THIS param
  if (pp[p.name] === "tentative") return { label: "疑似", cls: "st-tent" };          // tool's tentative, unconfirmed
  // No per-param evidence NAMED this param -> 未測, never a groundless 無洞. Covers a
  // param the tool skipped (cookie at --level 1), the URI '#1*' fallback, and any
  // errored/half-run scan. The scan-level status is deliberately NOT used to infer clean.
  return { label: "未測", cls: "st-untested" };
}
function _reqSummaryHtml(s) {
  const { host, ep } = splitEndpoint(s);
  const sp = ep.indexOf(" ");
  const method = sp >= 0 ? ep.slice(0, sp) : "?";
  const path = sp >= 0 ? ep.slice(sp + 1) : ep;
  let opts = s.options; if (!opts && s.options_json) { try { opts = JSON.parse(s.options_json); } catch (e) {} }
  const okeys = opts ? Object.keys(opts).filter(k => opts[k] !== "" && opts[k] != null && opts[k] !== false) : [];
  const rows = [["方法", method], ["主機", host], ["路徑", path], ["工具", s.tool]];
  let html = rows.map(([k, v]) => `<div class="kv"><b>${k}</b><span>${esc(v)}</span></div>`).join("");
  if (s.note) html += `<div class="kv wide"><b>備註</b><span>${esc(s.note)}</span></div>`;
  if (okeys.length) html += `<div class="kv wide"><b>選項</b><span class="mono-val">${esc(okeys.map(k => opts[k] === true ? k : k + "=" + opts[k]).join("  "))}</span></div>`;
  return html;
}
// evidence keyword(s) the auto-verdict hit in the log (scan-level), e.g. 「is vulnerable」
function _scanEvidence() {
  const { markers } = _parseVerdict(state.detailCache || "");
  return markers.length ? markers.map(m => `「${m}」`).join("、") : "";
}
function _wafNoteHtml() {
  const { items } = _parseVerdict(state.detailCache || "");
  const waf = (items || []).find(it => /WAF|IPS/.test(it.label));
  if (!waf) return "";
  return `<div class="sd-card"><div class="sd-sec-title">判定 · 防護偵測</div>`
    + `<div class="pv-list"><div class="pv-row st-waf"><span class="state-chip st-other">WAF/IPS</span>`
    + `<span class="pv-name">偵測到防護</span>`
    + `<span class="pv-ev">${esc(waf.value)}${waf.note ? " · " + esc(waf.note) : ""}</span></div></div></div>`;
}
// The verdict IS the per-parameter breakdown -- which params were tested and whether
// each has an injection point (red) / is clean (green) / was skipped (grey), ordered
// vuln -> clean -> inconclusive -> skipped, each with its matched-keyword evidence.
function _paramsVerdictHtml(s) {
  let params = s.params; if (!params && s.params_json) { try { params = JSON.parse(s.params_json); } catch (e) {} }
  if (!Array.isArray(params) || !params.length) return `<div class="sd-sec-title">判定 · 參數</div><div class="empty small">此請求沒有解析到參數。</div>`;
  let f = s.result; if (!f && s.result_json) { try { f = JSON.parse(s.result_json); } catch (e) {} }
  const scanVuln = !!s.vulnerable;
  const scanDone = s.status === "done";
  const ev = _scanEvidence();
  const order = { "st-vuln": 0, "st-tent": 1, "st-clean": 2, "st-untested": 3, "st-other": 4, "st-skip": 5 };
  const rows = params.map(p => ({ p, oc: _paramOutcome(p, f, scanVuln, scanDone) }));
  // ghauri often reports an injection WITHOUT naming the parameter; if the scan is
  // vulnerable, nothing got attributed, and exactly one param was tested, that param
  // IS the one -> attribute it (safe single-param inference; multi-param stays as-is).
  const sel = rows.filter(r => r.p.selected);
  if (scanVuln && !rows.some(r => r.oc.cls === "st-vuln") && sel.length === 1) sel[0].oc = { label: "有漏洞", cls: "st-vuln" };
  rows.sort((a, b) => (order[a.oc.cls] == null ? 9 : order[a.oc.cls]) - (order[b.oc.cls] == null ? 9 : order[b.oc.cls]));
  const body = rows.map(({ p, oc }) => {
    let evidence;
    if (oc.cls === "st-vuln") evidence = ev ? "命中 " + ev : "偵測到注入點";
    else if (oc.cls === "st-clean") evidence = "無注入點";
    else if (oc.cls === "st-tent") evidence = "工具暫定疑似,尚未確認";
    else if (oc.cls === "st-skip") evidence = "未勾選,本次未測試";
    else if (oc.cls === "st-untested") evidence = "工具日誌未提及此參數,未取得證據(非無洞)";
    else evidence = "無定論";
    return `<div class="pv-row ${oc.cls}"><span class="state-chip ${oc.cls}">${oc.label}</span>`
      + `<span class="pv-name">${esc(p.name)}</span><span class="loc-chip">${esc(p.location || "?")}</span>`
      + `<span class="pv-val" title="${esc(p.value || "")}">${esc(p.value || "")}</span>`
      + `<span class="pv-ev">${esc(evidence)}</span></div>`;
  }).join("");
  const n = params.length, tested = params.filter(p => p.selected).length;
  return `<div class="sd-sec-title">判定 · 參數 · 測 ${tested} / 略過 ${n - tested}</div><div class="pv-list">${body}</div>`;
}
// write-only-if-changed: hydrating the detail from the full fetch becomes a visual
// no-op when the data matches the cache paint -> no repaint, no flash (stale-while-
// revalidate). el._h / el._t cache the last written value.
function setHTML(el, html) { if (el && el._h !== html) { el.innerHTML = html; el._h = html; } }
function setText(el, txt) { if (el && el._t !== txt) { el.textContent = txt; el._t = txt; } }
function renderScanDetail(s) {
  if (!s) return;
  state.detailScan = s;   // remember the full scan so a log-pull can re-render the param verdict with fresh evidence
  setHTML($("#sdTitle"), `${stateChip(s)}<span class="dt-name">${esc(s.tool)} · #${s.id}</span>`);
  const dur = s.duration_ms ? " · " + fmtDur(s.duration_ms) : "";
  setHTML($("#sdMeta"), `<span class="mono-val">${esc(s.endpoint || s.url)}</span> · ${esc(fmtTime(s.started_at || s.created_at))}${dur}`);
  setHTML($("#sdVerdict"), _wafNoteHtml());          // just the WAF caveat now; the verdict itself is the param list
  setHTML($("#sdParams"), _paramsVerdictHtml(s));
  setHTML($("#sdRequest"), _reqSummaryHtml(s));
  setText($("#sdRaw"), s.raw || "");                 // -r request; space is reserved so filling it later doesn't jump
  setHTML($("#sdFindings"), findingsHtml(s));
  const canStop = s.status === "running" || s.status === "queued";
  const actHtml = (canStop ? `<button class="btn ghost sm danger-btn" id="sdStop">中止此掃描</button>` : "")
    + `<button class="btn ghost sm" id="sdReconfig" title="用這次的請求+工具+選項+勾選,開一個新的可編輯分頁">以此設定重新配置(開新分頁)</button>`
    + `<button class="btn ghost sm danger-btn" id="sdDelete2" title="刪除此掃描紀錄">刪除此掃描紀錄</button>`;
  const actEl = $("#sdActions"); setHTML(actEl, actHtml);
  // always (re)bind so handlers close over the FRESHEST s (raw etc.), even on a no-op write
  const stop = $("#sdStop"); if (stop) stop.onclick = () => stopScan(s.id);
  const recfg = $("#sdReconfig"); if (recfg) recfg.onclick = () => reconfigureFromScan(s);
  const del = $("#sdDelete2"); if (del) del.onclick = () => deleteScan(s.id);
}
// #8: load a past scan's exact request + settings back into the composer so the
// user can tweak and re-run, instead of being stuck on the read-only detail view.
async function reconfigureFromScan(s) {
  closeModals();
  showDashboard();
  composeTabNew();   // open a NEW tab -> never clobbers the current composition
  state.scanMode = "advanced";   // reconfigure is for tweaking -> force an editable form
                                 // (basic mode would load the options into a disabled/filtered grid)
  if (s.raw) {
    $("#rawInput").value = s.raw;
    await parseRequest();   // fresh parse -> current param history badges
  }
  if (s.tool) selectTool(s.tool);
  let opts = s.options; if (!opts && s.options_json) { try { opts = JSON.parse(s.options_json); } catch (e) {} }
  opts = opts || {};
  applyOptions(opts, "#optGrid", "#optToggles");
  markActiveTplChip(-1);   // custom config -> no active template

  // restore per-parameter selections by (location,name); collect any that were
  // to be tested but no longer exist in the freshly-parsed request.
  let saved = s.params; if (!saved && s.params_json) { try { saved = JSON.parse(s.params_json); } catch (e) {} }
  const missingParams = [];
  if (Array.isArray(saved)) {
    const curByKey = {}; (state.params || []).forEach(p => { curByKey[p.location + "|" + p.name] = p; });
    saved.forEach(sp => {
      const key = sp.location + "|" + sp.name;
      if (key in curByKey) curByKey[key].selected = !!sp.selected;
      else if (sp.selected) missingParams.push(`${sp.name}(${sp.location})`);
    });
    renderParams();
  }
  // detect options that didn't fully carry over (schema changed / value no
  // longer valid, e.g. an old free-text DBMS not in the new dropdown).
  const applied = gatherOptions("#optGrid", "#optToggles");
  const droppedOpts = [];
  for (const k in opts) {
    if (k === "restrict_ip") continue;   // no longer a composer option (project memo)
    const el = $(`#optGrid [data-optkey="${k}"]`) || $(`#optToggles [data-optkey="${k}"]`) || $(`#commonPins [data-optkey="${k}"]`);
    let same;
    if (el && el.classList && el.classList.contains("opt-checks")) {
      // checkbox groups: compare as a SET (order/casing of a legacy free-text
      // technique/tamper value differs from the canonical re-gathered string).
      const join = el.dataset.join != null ? el.dataset.join : ",";
      const toSet = v => new Set(join === "" ? String(v == null ? "" : v).split("")
        : String(v == null ? "" : v).split(join).map(s => s.trim()).filter(Boolean));
      const a = toSet(opts[k]), b = toSet(applied[k]);
      same = a.size === b.size && [...a].every(x => b.has(x));
    } else {
      same = JSON.stringify(opts[k]) === JSON.stringify(applied[k]);
    }
    if (!same) droppedOpts.push(`${k}=${opts[k]}`);
  }
  if (s.note != null) $("#scanNote").value = s.note;
  updateCmdPreview();

  // ACTIVELY surface any mismatch -- silent degradation would let you re-run a
  // "same" test that quietly isn't the same.
  const warns = [];
  if (missingParams.length) warns.push(`原本要測、但目前請求裡已無的參數:${missingParams.join("、")}`);
  if (droppedOpts.length) warns.push(`未完整套用的選項:${droppedOpts.join("、")}`);
  if (warns.length) {
    const prev = $("#parseWarn").textContent;
    $("#parseWarn").textContent = (prev ? prev + "  " : "") + "⚠ 帶回落差 — " + warns.join(";");
    toast("已載入,但有設定沒完整帶回(見上方 ⚠,務必檢查)", "err");
  } else {
    toast("已完整載入此掃描的設定,可調整後重新開始", "ok");
  }
}
let _pullingLog = false;
async function pullDetailLog() {
  // guard against tick() and openScanDetail() pulling the same offset at once,
  // which would append the same chunk to detailCache twice
  if (state.detailId == null || _pullingLog) return;
  _pullingLog = true;
  const forId = state.detailId;
  try {
    const r = await api(`/api/scans/${forId}/log?offset=${state.detailOffset || 0}`);
    if (state.detailId !== forId) return;   // user switched scans mid-request
    if (r.chunk) {
      state.detailCache += r.chunk; state.detailOffset = r.offset;
      const st = (state.logs = state.logs || {});
      st[forId] = { cache: state.detailCache, offset: state.detailOffset };   // per-scan cache -> instant revisit
      const ord = (state._logOrder = (state._logOrder || []).filter(x => x !== forId)); ord.push(forId);
      while (ord.length > 8) { const old = ord.shift(); if (old !== state.detailId) delete st[old]; }   // LRU cap -> bounded memory
      _renderDetailLog();
    } else if (!state.detailCache) { const lv = $("#sdLog"); if (lv) lv.textContent = "(尚無輸出)"; }
  } catch (e) {} finally { _pullingLog = false; }
}
// Parse the 【判定】 block from the log into a structured verdict + the set of
// marker keywords it hit, so we can render a pretty panel AND highlight the exact
// evidence lines in the raw log.
function _parseVerdict(text) {
  const items = [], markers = new Set();
  for (const raw of String(text || "").split(/\r?\n/)) {
    const i = raw.indexOf("【判定】");
    if (i < 0) continue;
    const body = raw.slice(i + 4).trim();   // "【判定】" is 4 chars
    if (!body || /^[─-]+/.test(body) || body.startsWith("自動判讀依據") || body.startsWith("結束")) continue;
    (body.match(/[「『](.+?)[」』]/g) || []).forEach(m => markers.add(m.slice(1, -1)));
    if (body.startsWith("依據行")) continue;   // evidence pointer, not a summary row
    const arrow = body.split("←");
    const main = arrow[0].trim(), note = arrow.slice(1).join("←").trim();
    const c = main.search(/[::]/);
    const label = c >= 0 ? main.slice(0, c).trim() : main;
    const value = c >= 0 ? main.slice(c + 1).trim() : "";
    items.push({ label, value, note });
  }
  return { items, markers: [...markers] };
}
// ONE clear conclusion: a big headline (有漏洞/無洞/掃描中/失敗, coloured) with the
// evidence as a sub-line -- NOT a separate 有漏洞 + 狀態 split. DBMS/params live in
// the request+findings sections so they're not duplicated here; WAF stays.
function _verdictPanelHtml(items, scan) {
  if (!scan) return "";
  const oc = scanOutcome(scan);
  const note = (re) => { const it = (items || []).find(x => re.test(x.label)); return it ? (it.note || it.value) : ""; };
  const sub = oc.key === "vuln" ? note(/有漏洞/) : (note(/狀態/) || note(/有漏洞/));
  const waf = (items || []).find(it => /WAF|IPS/.test(it.label));
  const wafRow = waf
    ? `<div class="vd-row vd-waf"><span class="vd-label">${esc(waf.label)}</span><span class="vd-value">${esc(waf.value)}</span>${waf.note ? `<span class="vd-note">${esc(waf.note)}</span>` : ""}</div>`
    : "";
  return `<div class="verdict-panel"><div class="vd-title">🔎 自動判定</div>`
    + `<div class="vd-headline ${oc.cls}"><span class="vd-hl-label">${esc(oc.label)}</span>${sub ? `<span class="vd-hl-note">${esc(sub)}</span>` : ""}</div>${wafRow}</div>`;
}
// is the user currently selecting text inside `el`? (don't clobber an in-progress copy)
function _selectionInside(el) {
  const sel = window.getSelection && window.getSelection();
  if (!sel || sel.isCollapsed || !sel.rangeCount) return false;
  return (sel.anchorNode && el.contains(sel.anchorNode)) || (sel.focusNode && el.contains(sel.focusNode));
}
// render the log with the verdict block + its evidence lines highlighted
// ---- raw-output views: our highlighting vs the tool's own terminal colours ----------
const _ANSI_RE = /\x1b\[[0-9;]*[A-Za-z]/g;   // strip SGR + other CSI escapes (ghauri emits colour)
function _stripAnsi(s) { return (s || "").replace(_ANSI_RE, ""); }
// terminal-style palette (concrete hex so it survives both the DOM view and the PNG raster)
const TERM_HEX = { info: "#4ec9b0", warning: "#e5c07b", error: "#e06c75", critical: "#ff6b6b",
  payload: "#c586c0", debug: "#7f848e", verdict: "#61afef", def: "#d4d4d4" };
const HL_HEX = { hit: "#e5c07b", clean: "#6a9955", enum: "#4ec9b0", verdict: "#61afef", def: "#d4d4d4" };
// key evidence lines BOTH engines print -- highlighted by PATTERN regardless of the
// scan-level marker, so ghauri (whose clean verdict marker is Chinese, never in its
// English log) still lights its own evidence instead of showing no highlight at all.
const _HL_VULN_RE = /(\bis vulnerable\b|\bis injectable\b|appears to be '[^']*' injectable|identified the following injection|injection point on)/i;
const _HL_CLEAN_RE = /(does not seem to be injectable|do not appear to be injectable|might not be injectable)/i;
const _HL_ENUM_RE = /(?:^|[\]\s])(Parameter|Type|Title|Payload):\s/;   // injection summary; needs space before+after so "Content-Type:"/"GET parameter" don't match
function _termKey(line) {
  if (line.includes("【判定】")) return "verdict";
  const m = line.match(/\[(INFO|WARNING|ERROR|CRITICAL|PAYLOAD|DEBUG)\]/);
  return m ? m[1].toLowerCase() : "def";
}
// which raw lines produced a PARSED enumeration value (banner / user / db / ...), so both
// views can light them up. Both tools print these the same way.
function _enumPats(scan) {
  const pats = [];
  try {
    const f = JSON.parse((scan && scan.result_json) || "{}") || {};
    if (f.banner) pats.push("banner:");
    if (f.current_user) pats.push("current user:");
    if (f.current_db) pats.push("current database:", "current db:");
    if (f.hostname) pats.push("hostname:");
    if (f.is_dba != null) pats.push("current user is dba:");
    if (f.databases_count != null) pats.push("available databases [");
  } catch (e) { /* slim scan / no result_json */ }
  return pats;
}
function _hlKey(line, lows, enumPats) {
  if (line.includes("【判定】")) return "verdict";
  const low = line.toLowerCase();
  if (_HL_VULN_RE.test(line) || lows.some(m => low.includes(m))) return "hit";
  if (_HL_CLEAN_RE.test(line)) return "clean";
  if (_HL_ENUM_RE.test(line) || low.includes("the back-end dbms is") || low.includes("back-end dbms:")
      || (enumPats.length && enumPats.some(p => low.includes(p)))) return "enum";
  return "def";
}
function _effectiveLogView() { return state.logView || ((state.settings && state.settings.default_log_view === "original") ? "original" : "highlighted"); }
// "純原始輸出": drop the lines WE add (append_log wrappers + the 【判定】 block) and strip our
// timestamp prefix, so the view is just what the tool itself printed -- but KEEP the 指令 line.
const _OUR_WRAP_RE = /^\[\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\]\s+(?:===.*(?:掃描開始|掃描結束)|目標:|備忘・|==\s*使用者中止)/;
const _OUR_TS_RE = /^\[\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\]\s?/;
function _filterPureRaw(text) {
  const out = [];
  for (const line of (text || "").split(/\r?\n/)) {
    if (line.includes("【判定】自動判讀依據")) break;   // OUR verdict block header (specific, won't match tool output)
    if (_OUR_WRAP_RE.test(line)) continue;         // drop 開始/結束/目標/備忘/中止 wrapper lines
    out.push(line.replace(_OUR_TS_RE, ""));        // strip our timestamp; keep the tool line (incl 指令:)
  }
  while (out.length && out[out.length - 1].trim() === "") out.pop();   // trim trailing blanks
  return out.join("\n");
}
function _syncLogViewUI(mode) {
  $$("#logViewSeg .seg-mini").forEach(b => b.classList.toggle("active", b.dataset.logview === mode));
  // original view paints hardcoded terminal hex -> force a dark ground so it's readable in
  // light theme too (otherwise light-grey-on-light-grey is invisible).
  const lv = $("#sdLog"); if (lv) lv.classList.toggle("log-terminal", mode === "original");
  const lbl = $("#logLabel"); if (lbl) lbl.textContent = mode === "original" ? "工具原始輸出(終端配色)" : "判定依據已高亮";
}
function _renderDetailLog() {
  const full = _stripAnsi(state.detailCache || "");   // drop colour escapes so nothing shows as garbage
  const { items, markers } = _parseVerdict(full);     // markers come from the FULL log (verdict block)
  const text = state.pureRaw ? _filterPureRaw(full) : full;   // but DISPLAY may hide our wrappers
  const scan = state.detailScan || (state.allScans || []).find(x => x.id === state.detailId);
  const vp = $("#sdVerdict"); if (vp) vp.innerHTML = _wafNoteHtml();                       // WAF caveat
  const pv = $("#sdParams"); if (pv && scan) pv.innerHTML = _paramsVerdictHtml(scan);       // verdict = param list, w/ fresh evidence
  const view = $("#sdLog"); if (!view) return;
  // a running scan re-renders the log every ~2s; rebuilding innerHTML wipes any text the
  // user is selecting to copy (payload/evidence). Skip the rebuild while a selection is
  // live inside the log -- the next poll re-renders once they release.
  if (_selectionInside(view)) return;
  const atBottom = view.scrollHeight - view.scrollTop - view.clientHeight < 40;
  const mode = _effectiveLogView();
  _syncLogViewUI(mode);
  const lows = markers.map(m => m.toLowerCase()).filter(Boolean);
  const enumPats = _enumPats(scan);
  view.innerHTML = text.split(/\r?\n/).map(line => {
    const e = esc(line);
    if (mode === "original") {   // terminal-style: colour by log level, no verdict highlighting
      return `<span style="color:${TERM_HEX[_termKey(line)]}">${e}</span>`;
    }
    const k = _hlKey(line, lows, enumPats);
    if (k === "verdict") return `<span class="log-verdict">${e}</span>`;
    if (k === "hit") return `<mark class="log-hit">${e}</mark>`;
    if (k === "clean") return `<mark class="log-clean">${e}</mark>`;
    if (k === "enum") return `<mark class="log-enum">${e}</mark>`;
    return e;
  }).join("\n");
  if (atBottom) view.scrollTop = view.scrollHeight;
}
// ===== 匯出輸出圖片 (screenshot) =========================================
let _shotDrag = false, _shotExcludeTo = false;
function openShotModal() {
  if (!(state.detailCache || "").trim()) { toast("尚無輸出可匯出", "err"); return; }
  const mode = _effectiveLogView();
  $("#shotTitle").textContent = `匯出輸出圖片 · #${state.detailId} · ${mode === "original" ? "原始" : "高亮"}版`;
  _buildShotLines(mode);
  const cap = $("#shotCapture");
  cap.contentEditable = "false"; cap.classList.remove("editing", "no-color");
  $("#shotColor").checked = true; $("#shotEdit").classList.remove("active");
  $("#shotHint").textContent = "拖曳可勾選/取消要放進圖片的行(灰掉的不會進圖片);右下角可拖曳調整寬度";
  showModal("shotModal");
}
function _buildShotLines(mode) {
  const full = _stripAnsi(state.detailCache || "");
  const scan = state.detailScan || (state.allScans || []).find(x => x.id === state.detailId);
  const { markers } = _parseVerdict(full);
  const text = state.pureRaw ? _filterPureRaw(full) : full;   // match what the detail view shows
  const lows = markers.map(m => m.toLowerCase()).filter(Boolean);
  const enumPats = _enumPats(scan);
  $("#shotCapture").innerHTML = text.split(/\r?\n/).map(line => {
    const hex = mode === "original" ? TERM_HEX[_termKey(line)] : HL_HEX[_hlKey(line, lows, enumPats)];
    return `<div class="shot-line" data-color="${hex}" style="color:${hex}">${esc(line) || "&nbsp;"}</div>`;
  }).join("");
}
// render ONE tile (a slice of lines) to an <img>. Tiling matters: a single very tall
// foreignObject silently drops middle content in Chrome, so we paint the log in chunks
// and stack them onto the final canvas -> nothing goes missing however long the log is.
async function _renderTileImg(body, contentWidth, lineStyle) {
  const meas = document.createElement("div");
  meas.style.cssText = `position:absolute;left:-99999px;top:0;width:${contentWidth}px;${lineStyle}`;
  meas.innerHTML = body; document.body.appendChild(meas);
  const h = Math.max(1, Math.ceil(meas.getBoundingClientRect().height)); document.body.removeChild(meas);
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${contentWidth}" height="${h}"><foreignObject x="0" y="0" width="${contentWidth}" height="${h}"><div xmlns="http://www.w3.org/1999/xhtml" style="width:${contentWidth}px;${lineStyle}">${body}</div></foreignObject></svg>`;
  const img = new Image();
  img.src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svg);
  await img.decode();
  return { img, h };
}
async function _shotToPng() {
  const cap = $("#shotCapture");
  const colored = $("#shotColor").checked;
  const kids = [...cap.children].filter(el => !(el.classList && el.classList.contains("shot-excluded")));
  if (!kids.length) { toast("沒有選任何行", "err"); return null; }
  const pad = 16, fs = 12.5, lh = 1.5;
  const width = Math.round(Math.min(Math.max(cap.clientWidth || 640, 320), 2400));   // honours the dragged width
  const contentWidth = width - pad * 2;
  const lineStyle = `box-sizing:border-box;font-family:Consolas,'Courier New',monospace;font-size:${fs}px;line-height:${lh};white-space:pre-wrap;word-break:break-word`;
  const lineHtml = el => {
    const color = colored ? (el.dataset.color || "#d4d4d4") : "#d4d4d4";
    return `<div style="color:${color};white-space:pre-wrap;word-break:break-word;min-height:1.5em">${esc(el.textContent) || "&#160;"}</div>`;
  };
  const CHUNK = 25, tiles = [];
  try {
    for (let i = 0; i < kids.length; i += CHUNK) {
      tiles.push(await _renderTileImg(kids.slice(i, i + CHUNK).map(lineHtml).join(""), contentWidth, lineStyle));
    }
  } catch (e) { toast("圖片產生失敗:" + (e.message || e), "err"); return null; }
  const totalH = tiles.reduce((s, t) => s + t.h, 0) + pad * 2;
  const CAP = 32767;   // per-side canvas dimension limit (Chrome/Firefox); toDataURL fails past it
  if (totalH > CAP || width > CAP) {   // even at 1x it won't fit -> tell the user instead of a blank PNG
    toast("選取內容太長,無法一次匯出;請取消一些行,或分兩次匯出", "err"); return null;
  }
  const scale = (width * 2 <= CAP && totalH * 2 <= CAP) ? 2 : 1;   // 2x for crispness only if it still fits
  const canvas = document.createElement("canvas");
  canvas.width = Math.round(width * scale); canvas.height = Math.round(totalH * scale);
  const ctx = canvas.getContext("2d"); ctx.scale(scale, scale);
  ctx.fillStyle = "#1e1e1e"; ctx.fillRect(0, 0, width, totalH);
  let y = pad;
  for (const t of tiles) { ctx.drawImage(t.img, pad, y, contentWidth, t.h); y += t.h; }
  try { return canvas.toDataURL("image/png"); } catch (e) { toast("圖片轉檔失敗:" + (e.message || e), "err"); return null; }
}
// after editing, contenteditable leaves bare text nodes / untagged <div>s -> re-wrap every
// visual line back into a .shot-line (with a data-color) so colour + drag-exclude keep working.
function _normalizeShotLines() {
  const cap = $("#shotCapture"); if (!cap) return;
  const mkLine = (text, color) => {
    const d = document.createElement("div");
    d.className = "shot-line"; d.dataset.color = color || "#d4d4d4"; d.style.color = color || "#d4d4d4";
    if (text) d.textContent = text; else d.innerHTML = "&nbsp;";
    return d;
  };
  const frag = document.createDocumentFragment();
  [...cap.childNodes].forEach(n => {
    if (n.nodeType === Node.TEXT_NODE) { if (n.textContent !== "") frag.appendChild(mkLine(n.textContent, "#d4d4d4")); }
    else if (n.nodeType === Node.ELEMENT_NODE) {
      if (n.classList && n.classList.contains("shot-line")) frag.appendChild(n);   // keep colour + excluded state
      else frag.appendChild(mkLine(n.textContent, (n.dataset && n.dataset.color) || "#d4d4d4"));
    }
  });
  cap.innerHTML = ""; cap.appendChild(frag);
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
    // close any read-only detail tab that was showing this scan
    const dt = (state.tabs || []).find(x => x.kind === "detail" && x.scanId === id);
    if (dt) {
      const idx = state.tabs.findIndex(x => x.id === dt.id);
      state.tabs.splice(idx, 1);
      if (!state.tabs.length) state.tabs = [_blankTab()];
      if (state.activeTabId === dt.id) applyTab(state.tabs[Math.max(0, idx - 1)] || state.tabs[0]);
      else renderComposeTabs();
    }
    if (state.detailId === id) state.detailId = null;
    if (state.logs) delete state.logs[id];   // drop this scan's cached log
    if (state._logOrder) state._logOrder = state._logOrder.filter(x => x !== id);
    toast("已刪除掃描紀錄", "ok");
    await loadScans();
  } catch (e) { toast("刪除失敗:" + e.message, "err"); }
}

// ===== poll loop ==========================================================
async function tick() {
  await loadScans();
  const at = _activeTab();
  if (at && at.kind === "detail" && state.detailId != null) {   // live-refresh the read-only detail tab
    const forId = state.detailId;
    try { const s = await api(`/api/scans/${forId}`); if (state.detailId === forId) renderScanDetail(s); } catch (e) {}
    await pullDetailLog();
  }
}
// board/tree/log poll interval — configurable in settings, applied live
let _tickTimer = null;
function applyScanRefresh() {
  const sec = (state.settings && Number(state.settings.scan_refresh_seconds)) || 2;
  if (_tickTimer) clearInterval(_tickTimer);
  _tickTimer = setInterval(tick, Math.max(500, sec * 1000));
}

// ===== views ==============================================================
let _firstView = true;
function setView(v) {
  const changed = state.view !== v;
  state.view = v;
  $("#dashboardView").classList.toggle("hidden", v !== "dashboard");
  $("#projectsView").classList.toggle("hidden", v !== "projects");
  $("#settingsView").classList.toggle("hidden", v !== "settings");
  // 專案總覽 is a "you've left the project, re-pick one" lobby -> hide the current-
  // project indicator so it doesn't say where you were.
  const hm = document.querySelector(".header-left"); if (hm) hm.classList.toggle("on-projects", v === "projects");
  syncPanels();
  if (changed) renderTreeIfChanged(true);   // drop/restore the "目前" composing hint per view
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
function showDashboard() {
  setView("dashboard");
  try { sessionStorage.setItem("viewMode", "dashboard"); } catch (e) {}   // F5 stays in the project
  const _t = selectedTool(); if (_t) populateTemplateDropdown(_t);   // refresh chips (order may have changed in settings)
}
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
  $("#setMax").value = state.settings.max_concurrent;
  $("#setScanRefresh").value = state.settings.scan_refresh_seconds || 2;
  $("#setIpRefresh").value = state.settings.ip_refresh_seconds;
  $("#setPublicIp").checked = !!state.settings.public_ip_lookup; $("#setAutoOpen").checked = !!state.settings.auto_open_browser;
  $("#setDefaultTool").value = state.settings.default_tool || "sqlmap";
  $("#setDefaultMode").value = state.settings.default_scan_mode === "basic" ? "basic" : "advanced";
  $("#setDefaultLogView").value = state.settings.default_log_view === "original" ? "original" : "highlighted";
  renderPinChooser();
}
// 常用設置 chooser: one checkbox per pinnable (non-danger) option, tool-tagged.
function renderPinChooser() {
  const box = $("#pinChooser"); if (!box) return;
  const pinned = new Set(_pinnedKeys());
  box.innerHTML = _pinCatalog().map(o => {
    const badge = o.tools.length === 1 ? `<span class="pin-tool-badge">${esc(o.tools[0])}</span>` : "";
    return `<label class="pin-opt"><input type="checkbox" data-pinkey="${esc(o.key)}"${pinned.has(o.key) ? " checked" : ""}><span class="pin-opt-name">${esc(o.label)}</span>${badge}</label>`;
  }).join("");
}
async function saveGeneralSettings() {
  try {
    const checked = new Set(Array.from(document.querySelectorAll("#pinChooser input[data-pinkey]:checked")).map(c => c.dataset.pinkey));
    const pinned_common = PIN_ORDER.filter(k => checked.has(k));   // canonical order
    state.settings = await api("/api/settings", "POST", {
      max_concurrent: Number($("#setMax").value) || 3,
      ip_refresh_seconds: Number($("#setIpRefresh").value) || 60,
      scan_refresh_seconds: Number($("#setScanRefresh").value) || 2,
      public_ip_lookup: $("#setPublicIp").checked, auto_open_browser: $("#setAutoOpen").checked,
      default_tool: $("#setDefaultTool").value,
      default_scan_mode: $("#setDefaultMode").value,
      default_log_view: $("#setDefaultLogView").value,
      pinned_common,
    });
    state.logView = null;   // let the new default take effect next time a detail renders
    setIpSeconds(state.settings.ip_refresh_seconds); doIpRefresh();
    applyScanRefresh();   // takes effect immediately, no restart
    _reflowCommonPins();   // move options between the strip and the card per the new choice
    toast("已儲存(併發數變更需重啟,其餘即時生效)", "ok");
  } catch (e) { toast("儲存失敗:" + e.message, "err"); }
}
// re-lay the composer options for the current pin set, preserving the values already set.
function _reflowCommonPins() {
  const tool = selectedTool(); if (!tool || !$("#optGrid")) return;
  const cur = gatherOptions("#optGrid", "#optToggles");   // reads card + strip
  renderOptions(tool, "#optGrid", "#optToggles", "#optToolLabel", "#commonPins");
  applyOptions(cur, "#optGrid", "#optToggles");           // writes card + strip
  _applyModeToGrid();
  updateCmdPreview();
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
    tb.innerHTML = `<tr><td colspan="8" class="rules-empty">${scope === "global" ? "尚無全域規則" : "本專案尚無自訂規則"};用上方欄位新增。</td></tr>`;
    return;
  }
  tb.innerHTML = rules.map(r => {
    const purposeBadge = r.purpose === "advise" ? `<span class="badge tested">建議</span>`
      : r.purpose === "recon" ? `<span class="badge recon">情報</span>`
      : `<span class="badge skip">過濾</span>`;
    const concl = r.purpose === "recon" ? (r.reveals || "") : (r.vuln_class || "");
    const desc = concl
      ? `${esc(concl)}${r.category ? ` <span class="dim">[${esc(r.category)}]</span>` : ""}${r.note ? " · " + esc(r.note) : ""}`
      : esc(r.note || "");
    return `
    <tr>
      <td><input type="checkbox" data-toggle="${r.id}" ${r.enabled ? "checked" : ""}></td>
      <td class="nowrap">${purposeBadge}</td>
      <td class="nowrap">${r.kind === "name" ? "名稱" : "值"}</td>
      <td class="nowrap">${esc(r.mode)}</td>
      <td class="nowrap">${esc(r.location || "任意")}</td>
      <td class="pname">${esc(r.pattern)}</td>
      <td>${desc}</td>
      <td><button class="link-btn del nowrap" data-del="${r.id}">刪除</button></td>
    </tr>`;
  }).join("");
  $$("[data-toggle]", tb).forEach(cb => cb.onchange = async () => {
    try { await api(`/api/rules/${cb.dataset.toggle}`, "PATCH", { enabled: cb.checked }); }
    catch (e) { cb.checked = !cb.checked; toast("更新失敗:" + e.message, "err"); }  // revert the visual on failure
  });
  $$("[data-del]", tb).forEach(b => b.onclick = async () => {
    const okDel = await confirmModal({ title: "刪除過濾規則", message: "確定刪除這條過濾規則?", okText: "刪除" });
    if (!okDel) return;
    try { await api(`/api/rules/${b.dataset.del}`, "DELETE"); loadRules(); toast("已刪除規則", "ok"); }
    catch (e) { toast("刪除失敗:" + e.message, "err"); }
  });
}
async function addRule() {
  const pattern = $("#rPattern").value.trim();
  if (!pattern) { toast("請填樣式", "err"); return; }
  const scope = state.ruleScope || "global";
  const val = id => { const el = $(id); return el ? el.value.trim() : ""; };
  const purpose = val("#rPurpose") || "filter";
  const concl = val("#rVulnClass");   // the shared "結論" field: advise=類別, recon=揭露
  try {
    await api("/api/rules", "POST", {
      kind: $("#rKind").value, mode: $("#rMode").value, pattern,
      note: $("#rNote").value.trim(),
      purpose,
      location: val("#rLocation"),
      vuln_class: purpose === "advise" ? concl : "",
      reveals: purpose === "recon" ? concl : "",
      project_id: scope === "global" ? null : state.projectId,
    });
    $("#rPattern").value = ""; $("#rNote").value = "";
    if ($("#rVulnClass")) $("#rVulnClass").value = "";
    if ($("#rLocation")) $("#rLocation").value = "";
    loadRules(); toast("已新增規則", "ok");
  } catch (e) { toast("新增失敗:" + e.message, "err"); }
}

// ----- template editor (shared options component) -----
// the template's tool IS the current sub-tab (state.tplTool) -- no separate radio
function teSelectedTool() { return state.tplTool || "sqlmap"; }
function teSelectTool(tool) {
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
// client-side template order (per tool), drag-reordered + persisted in localStorage
let _dragTplId = null;
function _tplOrderKey(tool) { return "tplOrder:" + (tool || state.tplTool || "sqlmap"); }
function _tplOrder(tool) { try { return JSON.parse(localStorage.getItem(_tplOrderKey(tool)) || "[]"); } catch (e) { return []; } }
function _sortByTplOrder(list, tool) {
  const ord = _tplOrder(tool), at = id => { const i = ord.indexOf(id); return i < 0 ? 1e9 : i; };
  return list.slice().sort((a, b) => at(a.id) - at(b.id));   // unknown (new) templates fall to the end
}
function _reorderTpl(fromId, toId, after) {
  if (fromId == null || fromId === toId) return;
  const list = _sortByTplOrder((state.templates || []).filter(t => ((t.data && t.data.tool) || t.tool) === (state.tplTool || "sqlmap")));
  let ids = list.map(t => t.id).filter(id => id !== fromId);
  const ti = ids.indexOf(toId); if (ti < 0) return;
  ids.splice(after ? ti + 1 : ti, 0, fromId);
  try { localStorage.setItem(_tplOrderKey(), JSON.stringify(ids)); } catch (e) {}
  renderTemplateList();
}
function renderTemplateList() {
  const box = $("#tplListBox");
  const list = _sortByTplOrder((state.templates || []).filter(t => ((t.data && t.data.tool) || t.tool) === (state.tplTool || "sqlmap")));
  if (!list.length) { box.innerHTML = `<div class="empty small">此工具尚無範本,按「＋ 新範本」建立。</div>`; return; }
  box.innerHTML = list.map(t => {
    const d = (t.data && t.data.danger) || "normal";
    const dlabel = { safe: "安全", normal: "一般", high: "高風險" }[d] || "一般";
    const desc = (t.data && t.data.desc) || "";
    return `
    <div class="tpl-item ${t.id === state.editingTplId ? "active" : ""} ${t.is_default ? "is-default" : ""}" data-tpl="${t.id}" draggable="true">
      <span class="scan-tool">${esc((t.data && t.data.tool) || t.tool || "?")}</span>
      <span class="tpl-name">${esc(t.name)}</span>
      <span class="badge danger-badge danger-${esc(d)}">${dlabel}</span>
      ${t.is_default ? '<span class="badge tested">★ 預設</span>' : ""}
      ${desc ? `<span class="tpl-desc">${esc(desc)}</span>` : ""}
    </div>`; }).join("");
  const clr = () => $$(".tpl-item.drop-before,.tpl-item.drop-after", box).forEach(x => x.classList.remove("drop-before", "drop-after"));
  $$("[data-tpl]", box).forEach(el => {
    el.onclick = () => teLoadTemplate(Number(el.dataset.tpl));
    el.ondragstart = (e) => { _dragTplId = Number(el.dataset.tpl); try { e.dataTransfer.effectAllowed = "move"; e.dataTransfer.setData("text/plain", String(_dragTplId)); } catch (x) {} el.classList.add("dragging"); };
    el.ondragend = () => { el.classList.remove("dragging"); clr(); _dragTplId = null; };
    el.ondragover = (e) => { e.preventDefault(); clr(); if (_dragTplId == null || Number(el.dataset.tpl) === _dragTplId) return; const r = el.getBoundingClientRect(); el.classList.add((e.clientY - r.top) > r.height / 2 ? "drop-after" : "drop-before"); };
    el.ondrop = (e) => { e.preventDefault(); const r = el.getBoundingClientRect(); _reorderTpl(_dragTplId, Number(el.dataset.tpl), (e.clientY - r.top) > r.height / 2); };
  });
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
  if ($("#teDanger")) $("#teDanger").value = "normal";
  if ($("#teDesc")) $("#teDesc").value = "";
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
  if ($("#teDanger")) $("#teDanger").value = (t.data && t.data.danger) || "normal";
  if ($("#teDesc")) $("#teDesc").value = (t.data && t.data.desc) || "";
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
  const danger = ($("#teDanger") && $("#teDanger").value) || "normal";
  const desc = ($("#teDesc") && $("#teDesc").value.trim()) || "";
  const payload = { name, tool, is_default: $("#teDefault").checked, data: { tool, danger, desc, options: gatherOptions("#teOptGrid", "#teOptToggles") } };
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
  try {
    await api(`/api/templates/${state.editingTplId}`, "DELETE");
    state.templates = await api("/api/templates");
    const curTool = selectedTool(); if (curTool) populateTemplateDropdown(curTool);
    showTplEmpty();
    toast("已刪除", "ok");
  } catch (e) { toast("刪除失敗:" + e.message, "err"); }
}

// ----- current project -----
function loadCurrentProject() {
  const p = state.projects.find(x => x.id === state.projectId); if (!p) return;
  $("#cpName").value = p.name; $("#cpNote").value = p.note || "";
}
async function saveCurrentProject() {
  if (state.projectId == null) return;
  try {
    await api(`/api/projects/${state.projectId}`, "PATCH", { name: $("#cpName").value.trim(), note: $("#cpNote").value.trim() });
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
  // NOTE: do NOT touch state.detailId here -- it's the active detail TAB's scan id,
  // managed by applyTab/loadDetailInto. Nuking it on Esc froze a running scan's live
  // log + row highlight while you stayed on the detail tab.
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
    // pre-select the user's chosen default tool (falls back to last-used, then sqlmap)
    if (!state.settings || !state.settings.default_tool) {
      try { state.settings = await api("/api/settings"); } catch (e) {}
    }
    let pref = (state.settings && state.settings.default_tool) || "";
    if (!SCHEMAS[pref]) { try { pref = localStorage.getItem("lastTool") || ""; } catch (e) {} }
    if (!SCHEMAS[pref]) pref = "sqlmap";
    state.scanMode = (state.settings && state.settings.default_scan_mode === "basic") ? "basic" : "advanced";
    selectTool(pref, { autoDefault: true });
  }
}

// ===== init ===============================================================
function init() {
  restoreTabs(); renderComposeTabs(); applyTab(_activeTab());
  window.addEventListener("beforeunload", () => {
    saveTabs();   // localStorage (synchronous)
    // flush the latest tabs to the DB even mid-debounce: sendBeacon survives page unload
    const pid = state.projectId;
    if (pid != null && navigator.sendBeacon) {
      try {
        const blob = new Blob([JSON.stringify({ tabs_json: _tabsBlob() })], { type: "application/json" });
        navigator.sendBeacon("/api/projects/" + pid + "/tabs", blob);
      } catch (e) {}
    }
  });
  $("#projectsBtn").onclick = () => showProjectsView(false);
  $("#openNewProjectBtn").onclick = openNewProject;
  $("#npCreate").onclick = createProjectEntry;

  $("#parseBtn").onclick = parseRequest;
  $("#pasteBtn").onclick = pasteFromClipboard;
  $("#launchBtn").onclick = launch;
  $("#refreshBtn").onclick = loadScans;
  $("#stopAllBtn").onclick = stopAll;
  loadTreePrefs();
  $("#treeExpandNodes").onclick = () => treeExpandAll(state.treeFullRecords);   // 展開: records included iff the toggle is on
  $("#treeCollapseAll").onclick = treeCollapseAll;
  const _tfp = $("#treeFullPath");
  if (_tfp) { _tfp.checked = state.treeFullPath; _tfp.onchange = () => { state.treeFullPath = _tfp.checked; saveTreeFullPath(); renderTreeIfChanged(true); }; }
  const _tfr = $("#treeFullRecords");
  if (_tfr) { _tfr.checked = state.treeFullRecords; _tfr.onchange = () => { state.treeFullRecords = _tfr.checked; saveTreeFullRecords(); applyFullRecordsToggle(); }; }
  $$("[data-sel]").forEach(b => b.onclick = () => selectParams(b.dataset.sel));
  $$('input[name="tool"]').forEach(r => r.onchange = () => selectTool(r.value, { autoDefault: true }));
  $$("#modeCard .seg-btn").forEach(b => b.onclick = () => setScanMode(b.dataset.mode));
  $("#cmdEditBtn").onclick = enterCmdEdit;      // ✏ 編輯指令 -> reverse-parse-on-套用 flow
  $("#cmdApplyBtn").onclick = applyCmdEdit;
  $("#cmdCancelBtn").onclick = cancelCmdEdit;
  // an option change drops any hover ghost first, so clicking the toggle you're previewing
  // repaints the REAL command immediately (updateCmdPreview otherwise bails while a ghost shows).
  const _onOptChange = () => { _hoverGhostKey = null; updateCmdPreview(); };
  $("#optGrid").addEventListener("input", _onOptChange);      // live command preview
  $("#optGrid").addEventListener("change", _onOptChange);     // selects / checkbox groups
  $("#optToggles").addEventListener("change", _onOptChange);
  $("#optToggles").addEventListener("input", _onOptChange);   // danger-zone text fields live-update
  $("#commonPins").addEventListener("input", _onOptChange);   // 常用設置 strip must ALSO update the command live
  $("#commonPins").addEventListener("change", _onOptChange);  // (else a pinned toggle/select won't reflect until another event fires)
  $("#editTplLink").onclick = () => showSettings("templates");

  $("#settingsBtn").onclick = () => showSettings("general");
  $("#settingsBackBtn").onclick = showDashboard;
  $$("#settingsTabs .tab").forEach(t => t.onclick = () => switchTab(t.dataset.tab));
  $("#setSave").onclick = saveGeneralSettings;
  $("#rAdd").onclick = addRule;
  $$("#ruleScopeTabs .subtab").forEach(t => t.onclick = () => setRuleScope(t.dataset.scope));
  $("#cpSave").onclick = saveCurrentProject;

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
  $("#modalBackdrop").onclick = closeModals;
  $$("[data-close]").forEach(b => b.onclick = closeModals);
  document.addEventListener("keydown", e => { if (e.key === "Escape") closeModals(); });

  // raw-output view toggle (高亮 / 原始) + 純原始輸出 filter + 匯出圖片 modal
  $$("#logViewSeg .seg-mini").forEach(b => b.onclick = () => { state.logView = b.dataset.logview; _renderDetailLog(); });
  const _pure = $("#pureRawChk");
  if (_pure) { _pure.checked = state.pureRaw; _pure.onchange = () => { state.pureRaw = _pure.checked; _renderDetailLog(); }; }
  $("#shotBtn").onclick = openShotModal;
  const _cap = $("#shotCapture");
  if (_cap) {
    _cap.addEventListener("mousedown", e => {
      if (_cap.isContentEditable) return;                 // edit mode -> let text selection work
      const line = e.target.closest(".shot-line"); if (!line) return;
      _shotDrag = true; _shotExcludeTo = !line.classList.contains("shot-excluded");
      line.classList.toggle("shot-excluded", _shotExcludeTo); e.preventDefault();
    });
    _cap.addEventListener("mouseover", e => {
      if (!_shotDrag) return;
      const line = e.target.closest(".shot-line"); if (line) line.classList.toggle("shot-excluded", _shotExcludeTo);
    });
    document.addEventListener("mouseup", () => { _shotDrag = false; });
  }
  $("#shotColor").onchange = () => $("#shotCapture").classList.toggle("no-color", !$("#shotColor").checked);
  $("#shotAll").onclick = () => $$("#shotCapture .shot-line").forEach(l => l.classList.remove("shot-excluded"));
  $("#shotNone").onclick = () => $$("#shotCapture .shot-line").forEach(l => l.classList.add("shot-excluded"));
  $("#shotEdit").onclick = () => {
    const cap = $("#shotCapture"); const on = cap.contentEditable !== "true";
    cap.contentEditable = on ? "true" : "false";
    cap.classList.toggle("editing", on); $("#shotEdit").classList.toggle("active", on);
    $("#shotHint").textContent = on ? "編輯模式:直接改文字;改完可再關閉編輯去選行"
                                    : "拖曳可勾選/取消要放進圖片的行(灰掉的不會進圖片);右下角可拖曳調整寬度";
    if (on) cap.focus();
    else _normalizeShotLines();   // re-tag edited/new content as .shot-line so it stays colourable + excludable
  };
  $("#shotDownload").onclick = async () => {
    const url = await _shotToPng(); if (!url) return;
    const a = document.createElement("a"); a.href = url; a.download = `scan_${state.detailId || "output"}.png`;
    document.body.appendChild(a); a.click(); a.remove(); toast("已下載 PNG", "ok");
  };
  $("#shotCopy").onclick = async () => {
    const url = await _shotToPng(); if (!url) return;
    try {
      const blob = await (await fetch(url)).blob();
      await navigator.clipboard.write([new ClipboardItem({ "image/png": blob })]);
      toast("已複製到剪貼簿", "ok");
    } catch (e) { toast("複製失敗(可改用下載):" + (e.message || e), "err"); }
  };
  _wireCmdOptionLink();   // command <-> option cross-highlight (delegated, one-time)
  // A FRESH tab lands on the PROJECT PICKER (don't auto-enter). But an F5 while working
  // INSIDE a project should stay there -> sessionStorage remembers the view for this tab
  // (survives reload, empty on a brand-new tab). last project id stays in localStorage.
  loadProjects().then(ok => {
    if (!ok) return;   // no projects -> loadProjects already opened the new-project flow
    loadScans(); loadTemplates(true);
    let vm = null; try { vm = sessionStorage.getItem("viewMode"); } catch (e) {}
    if (vm === "dashboard" && state.projectId != null) showDashboard();
    else showProjectsView(false);
  }).catch(e => toast("載入失敗:" + (e && e.message || e) + " — 請確認後端已啟動,重新整理再試", "err"));
  // settings: IP interval + configurable scan-refresh interval
  api("/api/settings").then(s => { state.settings = s; setIpSeconds(s.ip_refresh_seconds); applyScanRefresh(); }).catch(() => {});
  doIpRefresh(); refreshHealth();
  applyScanRefresh();     // start polling now (re-applied with saved value once settings load)
  setInterval(ipTick, 1000);
  setInterval(refreshHealth, 15000);
}
document.addEventListener("DOMContentLoaded", init);
