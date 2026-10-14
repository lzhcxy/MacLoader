/* ==========================================================================
   shell.js —— 外壳交互：四视图路由 / 预设分段控件 / 边栏收起 / 日志抽屉同步
   视图：c2（构建主界面） · ws（Webshell 占位） · settings（待规划） · about
   ========================================================================== */
(function () {
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];

  const title = $("#viewTitle");
  const badge = $("#viewBadge");
  const navItems = $$(".navitem");
  const VIEWS = ["c2", "ws", "settings", "about"];

  function setView(view) {
    VIEWS.forEach((v) => document.body.classList.toggle("view-" + v, v === view));

    const btn = navItems.find((b) => b.dataset.view === view) || navItems[0];
    navItems.forEach((b) => b.classList.toggle("active", b === btn));

    title.textContent = btn.dataset.title || "";
    badge.textContent = btn.dataset.badge || "";

    // 非构建视图一律收起日志抽屉（它只服务于 C2 构建流程）
    if (view !== "c2") {
      document.body.classList.remove("log-open");
      const d = $("#drawerBtn");
      if (d) d.classList.remove("is-open");
    }
  }

  navItems.forEach((b) => b.addEventListener("click", () => setView(b.dataset.view)));

  /* ---------- 分段控件 → 派发到隐藏的 #preset ---------- */
  const preset = $("#preset");
  const segWrap = $("#segPreset");
  if (preset && segWrap) {
    segWrap.addEventListener("click", (e) => {
      const seg = e.target.closest(".seg");
      if (!seg) return;
      $$(".seg", segWrap).forEach((s) => s.classList.toggle("active", s === seg));
      preset.value = seg.dataset.preset;
      preset.dispatchEvent(new Event("change")); // 触发原 applyPreset
      $("#segHint span").textContent =
        seg.dataset.preset === "" ? "实测通过组合，一键套用" : `已套用「${seg.textContent}」预设`;
    });
  }

  /* ---------- 侧栏收起 ---------- */
  const collapse = $("#collapseBtn");
  if (collapse) {
    collapse.addEventListener("click", () => {
      const hidden = document.body.classList.toggle("side-hidden");
      collapse.title = hidden ? "展开边栏" : "收起边栏";
    });
    if (location.hash === "#collapsed") {   // 预览锚点：直接看收起后的状态
      document.body.classList.add("side-hidden");
      collapse.title = "展开边栏";
    }
  }

  /* ---------- 日志抽屉 ↔ 视图联动 ---------- */
  const drawerBtn = $("#drawerBtn");
  if (drawerBtn) {
    drawerBtn.addEventListener("click", () => {
      const logNav = $('.navitem[data-view="c2"]');
      // 抽屉只在 C2 模块内有意义；若被擅自打开且不在该视图，切回去
      if (!document.body.classList.contains("view-c2")) setView("c2");
      else if (logNav) title.textContent = logNav.dataset.title;
    });
  }

  /* ---------- 主题：浅色 / 深色 / 跟随系统（默认浅色） ---------- */
  const THEME_KEY = "ml.theme";
  const mq = window.matchMedia("(prefers-color-scheme: dark)");
  let theme = "light"; // 未存过偏好时默认浅色，不跟随系统

  try {
    const saved = localStorage.getItem(THEME_KEY);
    if (saved === "light" || saved === "dark" || saved === "auto") theme = saved;
  } catch (_) {}

  function resolve(t) { return t === "auto" ? (mq.matches ? "dark" : "light") : t; }

  function applyTheme() {
    document.documentElement.setAttribute("data-theme", resolve(theme));
    const sel = $("#themeSel");
    if (sel) sel.value = theme;
  }

  const themeSel = $("#themeSel");
  if (themeSel) {
    themeSel.addEventListener("change", () => {
      theme = themeSel.value;
      try { localStorage.setItem(THEME_KEY, theme); } catch (_) {}
      applyTheme();
    });
  }
  if (mq.addEventListener) mq.addEventListener("change", () => { if (theme === "auto") applyTheme(); });
  else mq.addListener(() => { if (theme === "auto") applyTheme(); }); // 老版 Safari
  applyTheme();

  /* ---------- 预览锚点：#ws / #settings / #about / #logopen ---------- */
  const anchors = { "#ws": "ws", "#settings": "settings", "#about": "about" };
  const target = anchors[location.hash];
  if (target) setView(target);
  if (location.hash === "#logopen") {
    setView("c2");
    const d = $("#drawerBtn");
    if (d) { d.classList.add("is-open"); document.body.classList.add("log-open"); }
  }

  /* ---------- 首次启动：依赖安装引导 ---------- */
  /* 体积是这台机器上 brew info 的实测值：mingw-w64 1.4GB、osslsigncode 310KB(+openssl@4 23.8MB) */
  const DEPS = [
    { pkg: "mingw-w64", name: "mingw-w64",
      desc: "Windows 交叉编译器（含 x64 / x86 / windres）", size: "1.40 GB", fatal: true },
    { pkg: "osslsigncode", name: "osslsigncode",
      desc: "Authenticode 签名与时间戳（含 openssl）", size: "24 MB", fatal: false },
  ];

  const ob = $("#onboard");
  let obMiss = [];
  const badDep = (v) => !v || String(v).includes("未找到");

  async function obMissing() {
    const e = await window.__TAURI__.core.invoke("check_env");
    const miss = [];
    if (badDep(e.x64) || badDep(e.x86) || badDep(e.windres)) miss.push(DEPS[0]);
    if (badDep(e.osslsigncode)) miss.push(DEPS[1]);
    return miss;
  }

  function obRender(miss) {
    $("#obList").innerHTML = miss
      .map(
        (d) => `<li class="ob-item ${d.fatal ? "fatal" : "opt"}">
        <div class="ob-txt">
          <div class="ob-name">${d.name}</div>
          <div class="ob-desc">${d.desc}</div>
        </div>
        <span class="ob-tag">${d.fatal ? "必需" : "可选"}</span>
        <span class="ob-size">${d.size}</span>
      </li>`
      )
      .join("");
    const total = miss.length === 2 ? "1.42 GB" : miss.length === 1 ? miss[0].size : "0";
    $("#obTotal").innerHTML = `共需约 <b>${total}</b> 磁盘空间 · 通过 Homebrew 安装`;
  }

  async function obMaybeShow() {
    if (!ob) return;
    if (location.hash === "#onboard" || location.hash === "#onboard-run") {   // 预览锚点
      obMiss = DEPS.slice();
      obRender(obMiss);
      ob.classList.remove("hidden");
      if (location.hash === "#onboard-run") setTimeout(() => $("#obInstall").click(), 300);
      return;
    }
    try { if (localStorage.getItem("ml.onboarded")) return; } catch (_) {}
    const miss = await obMissing();
    if (!miss.length) { try { localStorage.setItem("ml.onboarded", "1"); } catch (_) {} return; }
    obMiss = miss;
    obRender(miss);
    ob.classList.remove("hidden");
  }

  // Rust 侧 brew 输出事件
  if (window.__TAURI__.event && window.__TAURI__.event.listen) {
    window.__TAURI__.event.listen("dep-install", (e) => {
      const p = e.payload || {};
      $("#obProg").classList.remove("hidden");
      const bar = $("#obBar");
      const st = $("#obStatus");
      const lg = $("#obLog");
      if (p.phase === "start") {
        st.textContent = `正在安装 ${p.pkg}（${p.step}/${p.total}）`;
        bar.style.width = ((p.step - 1) / p.total) * 100 + "%";
      } else if (p.phase === "log") {
        lg.textContent += (lg.textContent ? "\n" : "") + p.line;
        lg.scrollTop = lg.scrollHeight;
      } else if (p.phase === "pkg_done") {
        bar.style.width = (p.step / p.total) * 100 + "%";
        st.textContent = `${p.pkg} 安装完成`;
      } else if (p.phase === "done") {
        bar.style.width = "100%";
        st.textContent = "全部安装完成，正在刷新环境…";
        try { localStorage.setItem("ml.onboarded", "1"); } catch (_) {}
        setTimeout(() => location.reload(), 900);
      } else if (p.phase === "error") {
        st.textContent = `${p.pkg} 安装失败，请看上方输出`;
      }
    });
  }

  const obInstall = $("#obInstall");
  if (obInstall) {
    obInstall.addEventListener("click", async () => {
      const hasBrew = await window.__TAURI__.core.invoke("has_brew");
      if (!hasBrew) {
        $("#obNoBrew").classList.remove("hidden");
        obInstall.textContent = "重新检测";
        return;
      }
      if (obInstall.dataset.busy === "1") return;
      obInstall.dataset.busy = "1";
      obInstall.disabled = true;
      obInstall.textContent = "安装中…";
      $("#obProg").classList.remove("hidden");
      $("#obLog").textContent = "";
      try {
        await window.__TAURI__.core.invoke("install_deps", { pkgs: obMiss.map((d) => d.pkg) });
      } catch (err) {
        $("#obStatus").textContent = "安装出错：" + err;
        obInstall.disabled = false;
        obInstall.dataset.busy = "";
        obInstall.textContent = "重试";
      }
    });
  }

  const obSkip = $("#obSkip");
  if (obSkip) {
    obSkip.addEventListener("click", () => {
      try { localStorage.setItem("ml.onboarded", "1"); } catch (_) {}
      ob.classList.add("hidden");
    });
  }

  obMaybeShow();
})();
