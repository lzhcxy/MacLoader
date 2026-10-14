/* ==========================================================================
   mock.js —— 仅用于「纯浏览器预览」
   在真实 Tauri 构建中不加载本文件（window.__TAURI__ 由 runtime 注入）。
   ========================================================================== */
(function () {
  if (window.__TAURI__) return; // 真实环境直接用 runtime

  const fake = {
    x64: "/usr/local/bin/x86_64-w64-mingw32-g++",
    x86: "/usr/local/bin/i686-w64-mingw32-g++",
    windres: "/usr/local/bin/x86_64-w64-mingw32-windres",
    openssl: "/usr/bin/openssl",
    osslsigncode: "/opt/homebrew/bin/osslsigncode",
  };

  // 简易事件总线（模拟 Rust 侧 app.emit）
  const listeners = {};
  const emit = (name, payload) => {
    (listeners[name] || []).forEach((cb) => cb({ payload }));
  };
  window.__mockEmit = emit;

  window.__TAURI__ = {
    event: {
      listen: async (name, cb) => {
        (listeners[name] = listeners[name] || []).push(cb);
        return () => {};
      },
    },
    core: {
      invoke: async (cmd, args) => {
        switch (cmd) {
          case "check_env":
            return fake;
          case "has_brew":
            return true;
          case "install_deps": {
            const pkgs = (args && args.pkgs) || [];
            const total = pkgs.length;
            for (let i = 0; i < pkgs.length; i++) {
              const pkg = pkgs[i];
              const step = i + 1;
              emit("dep-install", { phase: "start", pkg, line: "", step, total });
              const lines = [
                `==> Downloading https://ghcr.io/v2/homebrew/core/${pkg}/manifests/…`,
                "==> Downloading https://ghcr.io/v2/homebrew/core/…/blobs/sha256:…",
                "############################################################ 100.0%",
                `==> Pouring ${pkg}--14.0.0.arm64_sequoia.bottle.tar.gz`,
                `🍺  /opt/homebrew/Cellar/${pkg}: 8584 files, 1.4GB`,
              ];
              for (const l of lines) {
                await new Promise((r) => setTimeout(r, 260));
                emit("dep-install", { phase: "log", pkg, line: l, step, total });
              }
              emit("dep-install", { phase: "pkg_done", pkg, line: "", step, total });
            }
            emit("dep-install", { phase: "done", pkg: "", line: "", step: total, total });
            return null;
          }
          case "list_icons":
            return ["word", "excel", "ppt", "pdf", "pdf-2", "pdf-3", "notepad"];
          case "list_dir":
            return [
              { name: "loader.exe", size: 412672, mtime: 1760400000, path: "/tmp/loader.exe" },
              { name: "invoice.pdf.exe", size: 421888, mtime: 1760410000, path: "/tmp/invoice.pdf.exe" },
            ];
          case "pick_file":
            return args && args.kind === "dir" ? "/tmp" : "/tmp/payload.bin";
          case "generate":
            return {
              ok: true,
              log: "[1] 读取 payload …\n[2] 分块变密钥编码 OK\n[3] 资源伪装 10/12 项\n[keep] 图标 notepad.ico 已嵌入\n已生成 loader.exe (412672 bytes)\n已签名 · 时间戳 -> tsa.wotrus.com\n[OK] 全部步骤完成",
              output: "/tmp/loader.exe",
              size: 412672,
              key: 65,
              uuid_count: 0,
              time_ts: true,
            };
          case "reveal":
            return null;
          default:
            return null;
        }
      },
    },
  };
})();
