const state = {
  groups: [],
  jobId: null,
  stage: null,
  logs: [],
  detail: null,
  hfResults: [],
  hfSelected: null,
  localModels: [],
  selectPath: null,
  stats: { duration_ms: null, file_count: null, total_bytes: null },
  timerStarted: null,
  timerId: null,
};

const $ = (id) => document.getElementById(id);

function fmtCount(n) {
  if (n == null) return "";
  const x = Number(n);
  if (Number.isNaN(x)) return "";
  if (x >= 1e6) return (x / 1e6).toFixed(1) + "M";
  if (x >= 1e3) return (x / 1e3).toFixed(1) + "k";
  return String(x);
}

function fmtBytes(n) {
  if (n == null || Number.isNaN(n)) return "";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let x = Number(n);
  while (x >= 1024 && i < units.length - 1) {
    x /= 1024;
    i += 1;
  }
  return (i === 0 ? String(Math.round(x)) : x.toFixed(1)) + " " + units[i];
}

function fmtDuration(ms) {
  if (ms == null || Number.isNaN(ms) || ms < 0) return "";
  const total = Math.floor(ms / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const tenths = Math.floor((ms % 1000) / 100);
  if (h > 0) {
    return `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  }
  return `${m}:${String(s).padStart(2, "0")}.${tenths}`;
}

function evalClass(result) {
  const r = String(result || "").toUpperCase();
  if (r === "FAILED") return "failed";
  if (r === "PASSED") return "passed";
  return "";
}

function evalRank(result) {
  const r = String(result || "").toUpperCase();
  if (r === "FAILED") return 0;
  if (r === "PASSED") return 1;
  return 2;
}

function outcomeClass(outcome) {
  const o = String(outcome || "").toUpperCase();
  if (o === "BLOCKED") return "blocked";
  if (o === "PASSED") return "passed";
  return "other";
}

function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || JSON.stringify(body);
    } catch {
      /* ignore */
    }
    throw new Error(detail);
  }
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) return res.json();
  return res;
}

function setHealth(h) {
  const el = $("health");
  if (!h) {
    el.textContent = "";
    return;
  }
  el.className = "health" + (h.ok ? "" : " bad");
  el.textContent = h.ok ? "Ready" : "Not ready";
}

function renderGroups(data) {
  const sel = $("sg");
  sel.innerHTML = "";
  const groups = data.security_groups || [];
  state.groups = groups;
  if (!groups.length) {
    sel.innerHTML = '<option value="">No LOCAL group</option>';
    return;
  }
  for (const g of groups) {
    const opt = document.createElement("option");
    opt.value = g.uuid;
    opt.textContent = g.name || g.uuid;
    sel.appendChild(opt);
  }
  if (data.default_uuid) sel.value = data.default_uuid;
}

function renderLocalModels() {
  const sel = $("local-model");
  const current = state.selectPath || sel.value;
  sel.innerHTML = "";
  if (!state.localModels.length) {
    sel.innerHTML = '<option value="">No downloaded models</option>';
    return;
  }
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = "Select a downloaded model";
  sel.appendChild(placeholder);
  for (const m of state.localModels) {
    const opt = document.createElement("option");
    opt.value = m.path;
    const size = fmtBytes(m.total_bytes);
    opt.textContent = size ? `${m.name} (${size})` : m.name;
    sel.appendChild(opt);
  }
  if (current && [...sel.options].some((o) => o.value === current)) {
    sel.value = current;
  }
}

function renderHfResults() {
  const root = $("hf-results");
  root.innerHTML = "";
  for (const m of state.hfResults) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "hf-row" + (state.hfSelected?.id === m.id ? " selected" : "");
    const dl = fmtCount(m.downloads);
    btn.innerHTML = `<div class="hf-id"></div><div class="hf-meta"></div>`;
    btn.querySelector(".hf-id").textContent = m.id;
    btn.querySelector(".hf-meta").textContent = [m.pipeline_tag, dl && dl + " downloads"].filter(Boolean).join(" · ");
    btn.addEventListener("click", () => {
      state.hfSelected = m;
      $("hf-q").value = m.id;
      renderHfResults();
    });
    root.appendChild(btn);
  }
}

function renderTerm() {
  const el = $("term");
  if (!state.logs.length) {
    el.innerHTML = '<span class="prompt">$ </span>waiting';
    return;
  }
  el.innerHTML = state.logs
    .map((row) => {
      const cls = row.kind === "prompt" ? "prompt" : row.kind === "fail" ? "fail" : "";
      return cls ? `<span class="${cls}">${esc(row.line)}</span>` : esc(row.line);
    })
    .join("\n");
  el.scrollTop = el.scrollHeight;
}

function setTimer(ms) {
  $("term-timer").textContent = ms == null ? "" : fmtDuration(ms);
}

function setSize(bytes) {
  $("term-size").textContent = bytes == null ? "" : fmtBytes(bytes);
}

function startTimer() {
  stopTimer();
  state.timerStarted = Date.now();
  state.stats.duration_ms = 0;
  setTimer(0);
  state.timerId = setInterval(() => {
    if (state.timerStarted == null) return;
    setTimer(Date.now() - state.timerStarted);
  }, 100);
}

function stopTimer(finalMs) {
  if (state.timerId) {
    clearInterval(state.timerId);
    state.timerId = null;
  }
  if (finalMs != null) {
    state.stats.duration_ms = finalMs;
    setTimer(finalMs);
  } else if (state.timerStarted != null) {
    const elapsed = Date.now() - state.timerStarted;
    state.stats.duration_ms = elapsed;
    setTimer(elapsed);
  }
  state.timerStarted = null;
}

function setStage(stage) {
  state.stage = stage;
  $("term-stage").textContent = stage && stage !== "complete" ? stage : "";
  $("term-title").textContent = stage === "download" ? "hf download" : stage ? "model-security" : "terminal";
}

function appendLog(line, opts = {}) {
  if (line == null) return;
  const kind = opts.kind || "cli";
  if (opts.overwrite && state.logs.length) {
    state.logs[state.logs.length - 1] = { line, kind };
  } else {
    state.logs.push({ line, kind });
  }
  if (state.logs.length > 800) state.logs.splice(0, state.logs.length - 800);
  renderTerm();
}

function renderVerdict() {
  const el = $("verdict");
  const scan = state.detail?.scan;
  if (!scan) {
    el.classList.add("hidden");
    el.innerHTML = "";
    return;
  }
  el.classList.remove("hidden");
  const es = scan.eval_summary || {};
  const evals = (state.detail.evaluations || [])
    .slice()
    .sort((a, b) => evalRank(a.result) - evalRank(b.result) || String(a.rule_name || "").localeCompare(String(b.rule_name || "")));
  const rows = evals
    .map((ev) => {
      const cls = evalClass(ev.result);
      return `<div class="rule ${cls}">
        <div class="name">${esc(ev.rule_name)} · ${esc(ev.result)}</div>
        <div class="desc">${esc(ev.rule_description || "")}</div>
      </div>`;
    })
    .join("");
  const bits = [
    `${es.rules_passed ?? 0} passed`,
    `${es.rules_failed ?? 0} failed`,
    `${es.total_rules ?? evals.length} rules`,
  ];
  const size = fmtBytes(state.stats.total_bytes ?? state.detail.total_bytes);
  if (size) bits.push(size);
  const files = state.stats.file_count ?? state.detail.file_count;
  if (files != null) bits.push(files + " files");
  const dur = fmtDuration(state.stats.duration_ms ?? state.detail.duration_ms);
  if (dur) bits.push(dur);
  el.innerHTML = `
    <div class="head">
      <div class="outcome ${outcomeClass(scan.eval_outcome)}">${esc(scan.eval_outcome || "—")}</div>
      <div class="meta">${bits.join(" · ")}</div>
    </div>
    ${rows}
  `;
}

function setBusy(on) {
  $("btn-hf-download").disabled = on;
  $("btn-hf-search").disabled = on;
  $("btn-scan").disabled = on;
}

function beginJob(stage) {
  state.logs = [];
  state.detail = null;
  state.stats = { duration_ms: null, file_count: null, total_bytes: null };
  setSize(null);
  setStage(stage);
  renderVerdict();
  renderTerm();
  setBusy(true);
  startTimer();
}

function listen(jobId) {
  const es = new EventSource("/api/jobs/" + jobId + "/events");
  es.addEventListener("stage", (e) => setStage(JSON.parse(e.data).stage));
  es.addEventListener("log", (e) => {
    const data = JSON.parse(e.data);
    const kind = data.stream === "prompt" ? "prompt" : "cli";
    appendLog(data.line, { kind, overwrite: Boolean(data.overwrite) });
  });
  es.addEventListener("stats", (e) => {
    const data = JSON.parse(e.data);
    if (data.file_count != null) state.stats.file_count = data.file_count;
    if (data.total_bytes != null) {
      state.stats.total_bytes = data.total_bytes;
      setSize(data.total_bytes);
    }
    if (data.duration_ms != null) {
      state.stats.duration_ms = data.duration_ms;
      stopTimer(data.duration_ms);
    }
    renderVerdict();
  });
  es.addEventListener("downloaded", (e) => {
    const data = JSON.parse(e.data);
    if (data.path) state.selectPath = data.path;
    if (data.file_count != null) state.stats.file_count = data.file_count;
    if (data.total_bytes != null) {
      state.stats.total_bytes = data.total_bytes;
      setSize(data.total_bytes);
    }
  });
  es.addEventListener("scan", (e) => {
    const data = JSON.parse(e.data);
    if (data.scan) {
      state.detail = { scan: data.scan, evaluations: [] };
      renderVerdict();
    }
  });
  es.addEventListener("detail", (e) => {
    const data = JSON.parse(e.data);
    state.detail = data;
    if (data.duration_ms != null) state.stats.duration_ms = data.duration_ms;
    if (data.file_count != null) state.stats.file_count = data.file_count;
    if (data.total_bytes != null) {
      state.stats.total_bytes = data.total_bytes;
      setSize(data.total_bytes);
    }
    renderVerdict();
  });
  es.addEventListener("fail", (e) => {
    try {
      appendLog(JSON.parse(e.data).message || "job error", { kind: "fail" });
    } catch {
      appendLog("job error", { kind: "fail" });
    }
  });
  es.addEventListener("done", () => {
    es.close();
    setBusy(false);
    stopTimer(state.stats.duration_ms);
    setStage(state.stage === "error" ? "error" : "complete");
    loadLocalModels().catch(() => {});
  });
  es.onerror = () => {
    if (state.stage === "complete" || state.stage === "error") es.close();
  };
}

async function loadLocalModels() {
  const data = await api("/api/models");
  state.localModels = data.models || [];
  renderLocalModels();
}

async function searchHf() {
  const q = $("hf-q").value.trim();
  if (!q) return;
  $("btn-hf-search").disabled = true;
  try {
    const data = await api("/api/hf/models?q=" + encodeURIComponent(q));
    state.hfResults = data.models || [];
    if (state.hfResults.length === 1) {
      state.hfSelected = state.hfResults[0];
      $("hf-q").value = state.hfSelected.id;
    }
    renderHfResults();
    if (!state.hfResults.length) appendLog("No public models matched.", { kind: "fail" });
  } catch (err) {
    appendLog(err.message, { kind: "fail" });
  } finally {
    $("btn-hf-search").disabled = false;
  }
}

async function startDownload() {
  const repo = (state.hfSelected?.id || $("hf-q").value).trim();
  if (!repo) {
    appendLog("Pick a Hugging Face model first.", { kind: "fail" });
    return;
  }
  beginJob("download");
  try {
    const job = await api("/api/downloads", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hf_repo: repo }),
    });
    state.jobId = job.job_id;
    listen(job.job_id);
  } catch (err) {
    appendLog(err.message, { kind: "fail" });
    setStage("error");
    setBusy(false);
    stopTimer();
  }
}

async function startScan() {
  const path = $("local-model").value.trim();
  const sg = $("sg").value.trim();
  if (!path) {
    appendLog("Select a downloaded model to scan.", { kind: "fail" });
    return;
  }
  if (!sg) {
    appendLog("Select a LOCAL security group.", { kind: "fail" });
    return;
  }
  beginJob("scan");
  try {
    const job = await api("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path, security_group_uuid: sg }),
    });
    state.jobId = job.job_id;
    listen(job.job_id);
  } catch (err) {
    appendLog(err.message, { kind: "fail" });
    setStage("error");
    setBusy(false);
    stopTimer();
  }
}

async function boot() {
  renderTerm();
  $("btn-hf-search").addEventListener("click", searchHf);
  $("btn-hf-download").addEventListener("click", startDownload);
  $("btn-scan").addEventListener("click", startScan);
  $("hf-q").addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      searchHf();
    }
  });
  try {
    setHealth(await api("/api/health"));
  } catch (err) {
    setHealth({ ok: false });
    $("health").textContent = err.message;
  }
  try {
    renderGroups(await api("/api/security-groups"));
  } catch (err) {
    $("sg").innerHTML = `<option value="">${esc(err.message)}</option>`;
  }
  try {
    await loadLocalModels();
  } catch (err) {
    appendLog(err.message, { kind: "fail" });
  }
}

boot();
