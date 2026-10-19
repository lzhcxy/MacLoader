//! 产物静态自审。
//!
//! 生成完 exe 后立刻自己看一遍，把「一眼就能被判死」的特征挑出来。
//! 这是纯文件层面的检查：不上传样本、不联网、不执行。
//!
//! 每条检查给出：是否命中、观察值、建议。命中不等于一定被杀，
//! 但每一条都是静态引擎真实会看的维度。

use std::fs;
use std::path::Path;

use crate::builder::hash::sha256_hex;
use crate::builder::pe;

#[derive(serde::Serialize, Clone, Debug)]
pub struct Finding {
    /// 维度 id，前端按它分组
    pub id: String,
    pub title: String,
    /// pass | warn | fail
    pub level: String,
    pub detail: String,
    pub hint: String,
}

#[derive(serde::Serialize, Clone, Debug)]
pub struct InspectReport {
    pub ok: bool,
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub machine: String,
    pub bits: u8,
    pub timestamp: String,
    pub signed: bool,
    pub has_resources: bool,
    pub findings: Vec<Finding>,
    pub score: u32,
}

fn find(id: &str, title: &str, level: &str, detail: String, hint: &str) -> Finding {
    Finding {
        id: id.into(),
        title: title.into(),
        level: level.into(),
        detail,
        hint: hint.into(),
    }
}

pub fn inspect(path: &str) -> Result<InspectReport, String> {
    let p = Path::new(path);
    let bytes = fs::read(p).map_err(|e| format!("读取失败: {e}"))?;
    let info = pe::parse(p)?;
    let sha256 = sha256_hex(&bytes);
    let size = bytes.len() as u64;

    let machine = match info.machine {
        0x8664 => "x86-64",
        0x014c => "i386",
        0xaa64 => "ARM64",
        other => return Ok(machine_unknown(other, size, sha256)),
    };
    let bits: u8 = if info.is_pe32_plus { 64 } else { 32 };

    let mut f = Vec::new();

    /* 1. 架构一致性 */
    f.push(find(
        "arch",
        "目标架构",
        "pass",
        format!("{machine} ({bits}-bit)"),
        "",
    ));

    /* 2. 节表熵值 —— 高熵节是「加密/压缩载荷」的经典信号 */
    let high: Vec<String> = info
        .sections
        .iter()
        .filter(|s| s.entropy > 7.2 && s.raw_size > 512)
        .map(|s| format!("{} ({:.2})", s.name, s.entropy))
        .collect();
    if high.is_empty() {
        f.push(find(
            "entropy",
            "节表熵值",
            "pass",
            format!("无高熵节（最高 {:.2}）", max_entropy(&info.sections)),
            "",
        ));
    } else {
        f.push(find(
            "entropy",
            "节表熵值",
            "warn",
            format!("高熵节: {}", high.join(", ")),
            "高熵节会被判定为加密/压缩载荷。可尝试关闭代码随机化，或改用分块编码减小单块体积。",
        ));
    }

    /* 3. 可执行节里的可写标志 —— RWX 节是强特征 */
    let rwx = pe::rwx_sections(&info);
    if rwx.is_empty() {
        f.push(find(
            "rwx",
            "RWX 节",
            "pass",
            "没有同时可写可执行的节".into(),
            "",
        ));
    } else {
        f.push(find(
            "rwx",
            "RWX 节",
            "fail",
            format!("存在 RWX 节: {}", rwx.join(", ")),
            "RWX 节几乎是必杀项。检查是否误开了 protect=rwx。",
        ));
    }

    /* 3b. 节表结构 —— 节数过少或节名异常也是特征 */
    let (nsec, vsize) = pe::section_summary(&info);
    f.push(find(
        "sections",
        "节表结构",
        if nsec >= 3 { "pass" } else { "warn" },
        format!("{} 个节，虚拟总大小 {:.2} MB", nsec, vsize as f64 / 1_048_576.0),
        if nsec >= 3 {
            ""
        } else {
            "节数偏少。mingw 正常产物应有 .text/.data/.rdata/.rsrc 等多个节；             节数过少常见于手工构造的 PE，静态引擎会加分。"
        },
    ));

    /* 4. 资源伪装 */
    f.push(if info.has_resources {
        find(
            "res",
            "资源伪装",
            "pass",
            "存在 .rsrc（图标/版本信息已挂载）".into(),
            "",
        )
    } else {
        find(
            "res",
            "资源伪装",
            "warn",
            "没有资源节".into(),
            "没有图标与版本信息的 exe 在静态特征上很突兀。建议开启「完整资源伪装」并选一个图标。",
        )
    });

    /* 5. 签名 */
    let signed = info.cert_size > 0;
    f.push(if signed {
        find(
            "sign",
            "Authenticode 签名",
            "pass",
            format!("有证书表 ({} bytes)", info.cert_size),
            "",
        )
    } else {
        find(
            "sign",
            "Authenticode 签名",
            "warn",
            "没有签名证书表".into(),
            "未签名 exe 在 SmartScreen 与多数引擎下权重更高。建议开启自签名（哪怕只是自签）。",
        )
    });

    /* 6. PE 时间戳 —— 为 0 或明显是「编译时刻」都可疑 */
    let ts = info.timestamp;
    let ts_txt = pe::fmt_ts(ts as i64);
    if ts == 0 {
        f.push(find(
            "ts",
            "PE 时间戳",
            "warn",
            "TimeDateStamp = 0".into(),
            "时间戳为 0 极少见于正常软件。用「创建时间伪造」给一个合理时间。",
        ));
    } else if ts > 0 && ts < 1_000_000_000 {
        f.push(find(
            "ts",
            "PE 时间戳",
            "warn",
            format!("{ts_txt}（1970-2001 区间，偏异常）"),
            "时间戳过早。建议落在近两年。",
        ));
    } else {
        f.push(find("ts", "PE 时间戳", "pass", ts_txt.clone(), ""));
    }

    /* 7. 体积 —— 静态链接 + 未 strip 的 mingw 产物动辄几 MB，
     *     对「一个打开 PDF 的小工具」来说过大本身就可疑 */
    let level = if size > 3_000_000 {
        "warn"
    } else {
        "pass"
    };
    f.push(find(
        "size",
        "产物体积",
        level,
        format!("{:.2} MB", size as f64 / 1_048_576.0),
        if level == "warn" {
            "体积偏大。mingw 静态链接必然偏大，但可尝试 strip 或去掉代码随机化。"
        } else {
            ""
        },
    ));

    /* 8. 导入表里的敏感 API
     *
     * ⚠ 判定依据必须是**真实导入表（IAT）**，不能全文搜子串。
     * 旧实现用 find_subslice 在整份二进制里搜 "VirtualAlloc" 等名字，
     * 而 loader.cpp 用的是 R(k32, "VirtualAlloc") —— 名字确实是源码里的
     * 明文，但只拿来算 DJB2 哈希，不进 IAT。于是任何产物 100% 命中告警，
     * 提示文案还让用户去检查"是否误加了 harden 项"，指向完全错误的方向。
     * 结果：用户学会忽略这条告警，连真有意义的（RWX 节、高熵节）一起忽略。
     *
     * 现在解析真实 IAT；导入表里没有这些名字就是干净通过。 */
    let iat = pe::imported_names(&bytes);
    let suspect = scan_imports(&bytes, iat.as_deref());
    let builtin = toolchain_hits(iat.as_deref());
    if suspect.is_empty() {
        let mut detail = match &iat {
            Some(n) => format!("导入表 {} 个函数，无注入类 API", n.len()),
            None => "无导入表（全动态解析），导入表层面无特征".into(),
        };
        if !builtin.is_empty() {
            detail.push_str(&format!(
                "（{} 由 mingw CRT 引入，工具链固有）",
                builtin.join(", ")
            ));
        }
        f.push(find("imports", "可疑导入", "pass", detail, ""));
    } else {
        f.push(find(
            "imports",
            "可疑导入",
            "warn",
            format!("导入表出现: {}", suspect.join(", ")),
            "这些 API 出现在真实导入表里，会被静态规则直接命中。\
             loader 默认用 PEB+DJB2 动态解析，不应出现在 IAT；\
             检查是否引入了额外的静态链接依赖。",
        ));
    }

    /* 9. 长连续 base64 / hex 串 */
    let blobs = scan_blobs(&bytes);
    if blobs.is_empty() {
        f.push(find(
            "blobs",
            "长串载荷痕迹",
            "pass",
            "未发现超长连续编码串".into(),
            "",
        ));
    } else {
        f.push(find(
            "blobs",
            "长串载荷痕迹",
            "warn",
            format!("发现 {} 处超长连续串（最长 {} 字节）", blobs.len(), blobs[0]),
            "连续编码串是 shellcode 载荷的典型形态。改用分块编码（chunk）把串切碎。",
        ));
    }

    let score = f.iter().filter(|x| x.level == "pass").count() as u32 * 10;
    let max = f.len() as u32 * 10;

    Ok(InspectReport {
        ok: true,
        path: path.into(),
        size,
        sha256,
        machine: machine.into(),
        bits,
        timestamp: ts_txt,
        signed,
        has_resources: info.has_resources,
        findings: f,
        score: (score * 100 / max.max(1)),
    })
}

fn machine_unknown(other: u16, size: u64, sha256: String) -> InspectReport {
    InspectReport {
        ok: true,
        path: String::new(),
        size,
        sha256,
        machine: format!("unknown (0x{other:04X})"),
        bits: 0,
        timestamp: String::new(),
        signed: false,
        has_resources: false,
        findings: vec![find(
            "arch",
            "目标架构",
            "warn",
            format!("未识别的 machine 值 0x{other:04X}"),
            "确认产物确实是 Windows PE。",
        )],
        score: 0,
    }
}

fn max_entropy(s: &[pe::SectionInfo]) -> f64 {
    s.iter().map(|x| x.entropy).fold(0f64, f64::max)
}

/// 引擎会当特征抓、且**loader 绝不该静态导入**的 API。
/// 出现在 IAT 里说明引入了额外的静态链接依赖，是真问题。
const SUSPECT_IMPORTS: &[&str] = &[
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "QueueUserAPC",
    "RtlCreateUserThread",
];

/// **mingw 工具链固有**的导入：CRT 启动代码（pseudo-reloc 等）必然带进来，
/// 实测任何配置（含 --no-obf / 各编码形态）都恒定存在，用户无法消除。
/// 单列出来是为了不把它们混进"可疑"里 —— 否则告警 100% 触发，
/// 用户学会忽略它，连真有意义的告警一起忽略。
const TOOLCHAIN_IMPORTS: &[&str] = &["VirtualAlloc", "VirtualProtect", "VirtualQuery"];

/// 只查导入表。iat 为 None（无导入表）时直接判定为干净。
fn scan_imports(_d: &[u8], iat: Option<&[String]>) -> Vec<String> {
    let Some(names) = iat else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for n in SUSPECT_IMPORTS {
        if names.iter().any(|x| x == n) {
            out.push((*n).to_string());
        }
    }
    out
}

/// 导入表里属于工具链固有的那些（用于文案说明，不算可疑）
fn toolchain_hits(iat: Option<&[String]>) -> Vec<String> {
    let Some(names) = iat else {
        return Vec::new();
    };
    TOOLCHAIN_IMPORTS
        .iter()
        .filter(|n| names.iter().any(|x| x == *n))
        .map(|s| s.to_string())
        .collect()
}

#[allow(dead_code)]
fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// 找连续长度 >= 200 的「纯 base64 / 纯 hex」可见串
fn scan_blobs(d: &[u8]) -> Vec<usize> {
    let mut lens = Vec::new();
    let mut cur_is_b64 = false;
    let mut run = 0usize;
    for &b in d {
        let is_b64 = b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=';
        if is_b64 {
            if run == 0 {
                cur_is_b64 = true;
            }
            if cur_is_b64 {
                run += 1;
            }
        } else {
            if run > 200 {
                lens.push(run);
            }
            run = 0;
        }
    }
    if run > 200 {
        lens.push(run);
    }
    lens.sort_unstable_by(|a, b| b.cmp(a));
    lens.truncate(5);
    lens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_pe_is_rejected() {
        let p = std::env::temp_dir().join("macloader_insp_notpe");
        fs::write(&p, vec![0u8; 4096]).unwrap();
        let e = inspect(&p.to_string_lossy()).expect_err("非 PE 必须报错");
        assert!(e.contains("PE"), "{e}");
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn missing_file_errors() {
        let e = inspect("/no/such/file.exe").expect_err("缺失文件必须报错");
        assert!(e.contains("读取"), "{e}");
    }

    #[test]
    fn scan_imports_finds_iat_entries() {
        let iat = vec!["GetProcAddress".to_string(), "CreateRemoteThread".to_string()];
        let s = scan_imports(b"", Some(&iat));
        assert!(s.contains(&"CreateRemoteThread".to_string()), "{s:?}");
    }

    #[test]
    fn scan_imports_ignores_hashed_name_strings() {
        // loader.cpp 里 R(k32,"VirtualAlloc") 的源串不进 IAT —— 必须不报警
        let d = b"static const char k[] = \"VirtualAlloc VirtualProtect\";";
        let iat = vec!["GetProcAddress".to_string()];
        assert!(scan_imports(d, Some(&iat)).is_empty());
    }

    #[test]
    fn no_import_table_is_clean() {
        // 全动态解析（无 IAT）-> 导入表层面无特征
        assert!(scan_imports(b"VirtualAlloc all over the place", None).is_empty());
    }

    #[test]
    fn toolchain_imports_are_not_reported_as_suspect() {
        // mingw CRT 必然带入 VirtualProtect/VirtualAlloc —— 不算可疑
        let iat = vec![
            "VirtualProtect".to_string(),
            "VirtualAlloc".to_string(),
            "malloc".to_string(),
        ];
        assert!(scan_imports(b"", Some(&iat)).is_empty());
        assert_eq!(toolchain_hits(Some(&iat)).len(), 2);
    }

    #[test]
    fn real_injection_api_is_still_caught() {
        let iat = vec!["WriteProcessMemory".to_string(), "CreateRemoteThread".to_string()];
        let s = scan_imports(b"", Some(&iat));
        assert_eq!(s.len(), 2, "{s:?}");
    }

    #[test]
    fn scan_blobs_detects_long_run() {
        let mut d = vec![b'\x00'; 16];
        d.extend(std::iter::repeat(b'A').take(300));
        d.push(0);
        let b = scan_blobs(&d);
        assert_eq!(b.first(), Some(&300), "{b:?}");
    }

    #[test]
    fn scan_blobs_ignores_short_runs() {
        let d: Vec<u8> = std::iter::repeat(b'B').take(50).collect();
        assert!(scan_blobs(&d).is_empty());
    }
}
