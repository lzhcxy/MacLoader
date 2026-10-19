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
    let iat_hits = scan_iat_features(iat.as_deref());
    let inject: Vec<&str> = iat_hits
        .iter()
        .filter(|(_, c)| *c == "inject")
        .map(|(n, _)| *n)
        .collect();
    let mem: Vec<&str> = iat_hits
        .iter()
        .filter(|(_, c)| *c == "mem")
        .map(|(n, _)| *n)
        .collect();

    // 特征清单：命中项全部列出，不隐藏。可消除的（inject）判 warn，
    // 工具链固有的（mem）判 pass 但如实写明 —— 引擎会看，只是你改不掉。
    let mut detail = match &iat {
        Some(n) => format!("导入表 {} 个函数", n.len()),
        None => "无导入表（全动态解析）".into(),
    };
    if !inject.is_empty() {
        detail.push_str(&format!(" · 注入类: {}", inject.join(", ")));
    }
    if !mem.is_empty() {
        detail.push_str(&format!(" · 内存类: {}", mem.join(", ")));
    }
    if iat_hits.is_empty() {
        detail.push_str(" · 无特征 API");
    }

    let (level, hint) = if !inject.is_empty() {
        (
            "fail",
            "导入表里出现注入类 API，静态规则会直接命中。loader 默认走 PEB+DJB2 动态解析，\
             这些名字不该进 IAT —— 检查是否引入了额外的静态链接依赖。",
        )
    } else if !mem.is_empty() {
        (
            "warn",
            "内存类由 mingw CRT 的 pseudo-reloc 启动代码引入，实测任何配置都恒定存在，\
             本工具无法消除。引擎会看，但属工具链固有成本。",
        )
    } else {
        ("pass", "")
    };
    f.push(find("imports", "导入表特征", level, detail, hint));

    /* 8b. 明文 API 名（字节层面，与 IAT 无关）
     *
     * loader 用 R(k32, "VirtualAlloc") —— 名字作为源码字符串留在产物里，
     * 只用于算 DJB2 哈希，不进 IAT。但引擎做全文子串匹配时照样命中，
     * 所以这也是特征，必须列进清单。与上一维是两件事。 */
    let plain = scan_plaintext_features(&bytes);
    if plain.is_empty() {
        f.push(find(
            "plaintext",
            "明文 API 名",
            "pass",
            "二进制内无敏感 API 明文".into(),
            "",
        ));
    } else {
        f.push(find(
            "plaintext",
            "明文 API 名",
            "warn",
            format!(
                "二进制内明文出现 {} 个: {}",
                plain.len(),
                plain.join(", ")
            ),
            "这些是 loader.cpp 里用于算 DJB2 哈希的源串（R(k32,\"VirtualAlloc\") 形式），\
             不进 IAT，但静态引擎做全文子串匹配时会命中。\
             要消除需把哈希源串改成编译期计算的常量，而非字面量。",
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

/* ================================================================== *
 *  特征清单                                                           *
 *                                                                     *
 *  自审的定位是「把静态引擎会抓的特征如实列全」，不是「打一个好看的     *
 *  分」。所以这里**不隐藏**任何命中项 —— 包括那些用户无法消除的        *
 *  （mingw CRT 必然带入的导入、loader 自己留在二进制里的哈希源串）。    *
 *  清单给全，来源标清，能不能消除由使用者判断。                        *
 * ================================================================== */

/// 导入表（IAT）里的特征 API。(名字, 类别)
///
/// - `inject`：注入类，loader 用 PEB+DJB2 动态解析，绝不该静态出现在 IAT。
///   命中说明引入了额外静态依赖 —— 真问题，可消除。
/// - `mem`：内存操作类。实测 mingw CRT 的 pseudo-reloc 启动代码必然带入
///   VirtualProtect/VirtualQuery，任何配置（含 --no-obf、各编码形态）恒定
///   存在，不是配置问题，也不是本工具能消除的。仍然列出 —— 因为引擎会看。
const IAT_FEATURES: &[(&str, &str)] = &[
    ("WriteProcessMemory", "inject"),
    ("CreateRemoteThread", "inject"),
    ("NtAllocateVirtualMemory", "inject"),
    ("NtProtectVirtualMemory", "inject"),
    ("QueueUserAPC", "inject"),
    ("RtlCreateUserThread", "inject"),
    ("VirtualAlloc", "mem"),
    ("VirtualProtect", "mem"),
    ("VirtualQuery", "mem"),
];

/// 二进制里以**明文**出现的敏感 API 名。
///
/// loader.cpp 用的是 `R(k32, "VirtualAlloc")` —— 名字确实作为源码字符串
/// 留在产物里，只拿来算 DJB2 哈希，**不进 IAT**。但静态引擎做全文子串
/// 匹配时照样会命中，所以这也是特征，必须列进清单。
/// 与 IAT 那条是两件事：一个看导入表，一个看字节内容。
const PLAINTEXT_FEATURES: &[&[u8]] = &[
    b"VirtualAlloc",
    b"VirtualProtect",
    b"WriteProcessMemory",
    b"CreateRemoteThread",
    b"NtAllocateVirtualMemory",
    b"NtProtectVirtualMemory",
    b"QueueUserAPC",
    b"RtlCreateUserThread",
];

/// 只查导入表，返回 (名字, 类别)。iat 为 None（无导入表）时为空。
fn scan_iat_features(iat: Option<&[String]>) -> Vec<(&'static str, &'static str)> {
    let Some(names) = iat else {
        return Vec::new();
    };
    IAT_FEATURES
        .iter()
        .filter(|(n, _)| names.iter().any(|x| x == n))
        .copied()
        .collect()
}

/// 全文搜明文 API 名（字节层面，与 IAT 无关）
fn scan_plaintext_features(d: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for n in PLAINTEXT_FEATURES {
        if find_subslice(d, n).is_some() {
            out.push(String::from_utf8_lossy(n).to_string());
        }
    }
    out
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
    fn iat_scan_reports_features_with_category() {
        let iat = vec![
            "GetProcAddress".to_string(),
            "WriteProcessMemory".to_string(),
            "VirtualProtect".to_string(),
        ];
        let hits = scan_iat_features(Some(&iat));
        assert!(
            hits.contains(&("WriteProcessMemory", "inject")),
            "{hits:?}"
        );
        assert!(hits.contains(&("VirtualProtect", "mem")), "{hits:?}");
        assert_eq!(hits.len(), 2, "无关函数不应计入: {hits:?}");
    }

    #[test]
    fn no_import_table_has_no_iat_features() {
        // 全动态解析（无 IAT）-> 导入表层面无特征
        assert!(scan_iat_features(None).is_empty());
    }

    #[test]
    fn toolchain_mem_imports_are_still_listed() {
        // 特征清单不隐藏：CRT 固有的内存类也必须列出（类别 mem，不是 inject）
        let iat = vec!["VirtualProtect".to_string(), "malloc".to_string()];
        let hits = scan_iat_features(Some(&iat));
        assert_eq!(hits, vec![("VirtualProtect", "mem")]);
    }

    #[test]
    fn plaintext_scan_is_independent_of_iat() {
        // 明文维度只看字节内容：即便不在 IAT 里也照样报
        let d = b"static const char k[] = \"VirtualAlloc\";";
        let s = scan_plaintext_features(d);
        assert!(s.contains(&"VirtualAlloc".to_string()), "{s:?}");
        assert!(scan_plaintext_features(b"nothing here").is_empty());
    }

    #[test]
    fn injection_api_in_iat_is_categorized_as_inject() {
        let iat = vec!["CreateRemoteThread".to_string(), "QueueUserAPC".to_string()];
        let hits = scan_iat_features(Some(&iat));
        assert!(hits.iter().all(|(_, c)| *c == "inject"), "{hits:?}");
        assert_eq!(hits.len(), 2);
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
