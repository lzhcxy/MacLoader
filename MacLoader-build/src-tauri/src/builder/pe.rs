//! PE 文件处理：时间戳伪造、文件时间、静态自审。
//!
//! 只做「文件层面」的操作：读字节、改字节、算熵。不加载目标、不执行。

use std::fs;
use std::path::Path;

/* ============================ 时间换算 ============================ */

/// 公历 -> 距 1970-01-01 的天数（Howard Hinnant 算法）
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// 解析 "YYYY-MM-DDTHH:MM" / "YYYY-MM-DD HH:MM" / "YYYY-MM-DD" -> unix 秒
pub fn parse_datetime(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (date, time) = s
        .split_once('T')
        .or_else(|| s.split_once(' '))
        .unwrap_or((s, "00:00"));
    let mut dp = date.split('-');
    let y: i64 = dp.next()?.parse().ok()?;
    let mo: i64 = dp.next()?.parse().ok()?;
    let d: i64 = dp.next()?.parse().ok()?;
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    let mut tp = time.split(':');
    let hh: i64 = tp.next().unwrap_or("0").trim().parse().ok()?;
    let mi: i64 = tp.next().unwrap_or("0").trim().parse().ok()?;
    Some(days_from_civil(y, mo, d) * 86400 + hh * 3600 + mi * 60)
}

/// unix 秒 -> "YYYY-MM-DD HH:MM:SS UTC"
pub fn fmt_ts(ts: i64) -> String {
    let days = ts.div_euclid(86400);
    let secs = ts.rem_euclid(86400);
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        y,
        m,
        d,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/* ============================ PE 结构 ============================ */

#[derive(Debug)]
pub struct PeInfo {
    pub machine: u16,
    pub is_pe32_plus: bool,
    pub timestamp: u32,
    pub nsec: usize,
    pub sections: Vec<SectionInfo>,
    /// 资源目录是否存在（有 .rsrc 说明挂了图标/版本信息）
    pub has_resources: bool,
    /// Authenticode 证书表（DataDirectory[4] = SECURITY）
    pub cert_size: u32,
}

#[derive(Debug)]
pub struct SectionInfo {
    pub name: String,
    pub vsize: u32,
    pub raw_size: u32,
    pub entropy: f64,
    /// 是否可执行（IMAGE_SCN_MEM_EXECUTE）
    pub exec: bool,
    /// 是否可写（IMAGE_SCN_MEM_WRITE）—— RWX 节是强特征，自审要用
    pub write: bool,
}

/// 最小 PE 解析：读到节表为止。够用即可，不追求完整覆盖。
pub fn parse(path: &Path) -> Result<PeInfo, String> {
    let d = fs::read(path).map_err(|e| e.to_string())?;
    if d.len() < 0x40 {
        return Err("文件过小，不像 PE".into());
    }
    let e = u32::from_le_bytes([d[0x3c], d[0x3d], d[0x3e], d[0x3f]]) as usize;
    if e + 0x18 + 0x80 > d.len() {
        return Err("PE 头越界".into());
    }
    if &d[e..e + 4] != b"PE\0\0" {
        return Err("不是 PE 文件（缺少 PE\\0\\0 签名）".into());
    }
    let machine = u16::from_le_bytes([d[e + 4], d[e + 5]]);
    let nsec = u16::from_le_bytes([d[e + 6], d[e + 7]]) as usize;
    let timestamp = u32::from_le_bytes([d[e + 8], d[e + 9], d[e + 10], d[e + 11]]);
    let opt_size = u16::from_le_bytes([d[e + 0x14], d[e + 0x15]]) as usize;
    let magic = u16::from_le_bytes([d[e + 0x18], d[e + 0x19]]);
    let is_pe32_plus = magic == 0x20b;

    let dd = e + 0x18 + if is_pe32_plus { 0x70 } else { 0x60 };
    let res = dd + 2 * 8; // DataDirectory[2] = RESOURCE
    let sec = dd + 4 * 8; // DataDirectory[4] = SECURITY
    let has_resources = res + 8 <= d.len()
        && u32::from_le_bytes([d[res], d[res + 1], d[res + 2], d[res + 3]]) != 0;
    // ⚠ SECURITY 目录的语义与其它目录不同：Authenticode 的证书表不在虚拟内存里，
    //   所以它的 VirtualAddress 字段存的是**文件偏移**，Size 才是证书表长度。
    //   旧实现读的是前 4 字节（文件偏移），于是自审 UI 显示「有证书表 (245760 bytes)」
    //   ——数字其实是偏移量。判断 signed = cert_size > 0 之所以没报错，只是因为
    //   偏移恰好非 0。这里改读 Size。
    let cert_size = if sec + 8 <= d.len() {
        u32::from_le_bytes([d[sec + 4], d[sec + 5], d[sec + 6], d[sec + 7]])
    } else {
        0
    };

    let sh = e + 0x18 + opt_size;
    let mut sections = Vec::new();
    for i in 0..nsec {
        let s = sh + i * 40;
        if s + 40 > d.len() {
            break;
        }
        let name = String::from_utf8_lossy(&d[s..s + 8])
            .trim_end_matches('\0')
            .trim()
            .to_string();
        let vsize = u32::from_le_bytes([d[s + 8], d[s + 9], d[s + 10], d[s + 11]]);
        let va = u32::from_le_bytes([d[s + 12], d[s + 13], d[s + 14], d[s + 15]]) as usize;
        let raw_size = u32::from_le_bytes([d[s + 16], d[s + 17], d[s + 18], d[s + 19]]);
        let praw = u32::from_le_bytes([d[s + 20], d[s + 21], d[s + 22], d[s + 23]]) as usize;
        let chars = u32::from_le_bytes([d[s + 36], d[s + 37], d[s + 38], d[s + 39]]);
        let exec = chars & 0x2000_0000 != 0; // IMAGE_SCN_MEM_EXECUTE
        let write = chars & 0x8000_0000 != 0; // IMAGE_SCN_MEM_WRITE
        let take = (raw_size as usize).min(d.len().saturating_sub(praw));
        let entropy = if take > 0 && praw < d.len() {
            entropy(&d[praw..praw + take])
        } else {
            entropy(&d[va.min(d.len())..])
        };
        sections.push(SectionInfo {
            name,
            vsize,
            raw_size,
            entropy,
            exec,
            write,
        });
    }

    Ok(PeInfo {
        machine,
        is_pe32_plus,
        timestamp,
        nsec,
        sections,
        has_resources,
        cert_size,
    })
}

/// 同时可写可执行的节（RWX）—— 静态引擎几乎必看的强特征
pub fn rwx_sections(info: &PeInfo) -> Vec<String> {
    info.sections
        .iter()
        .filter(|s| s.exec && s.write)
        .map(|s| s.name.clone())
        .collect()
}

/// 节数量与总虚拟大小，用于自审报告里的「结构是否正常」
pub fn section_summary(info: &PeInfo) -> (usize, u64) {
    (info.nsec, info.sections.iter().map(|s| s.vsize as u64).sum())
}

/// 从真实导入表（IAT）里取出被引用的函数名集合。
///
/// 这是「可疑导入」检测的正确依据：静态引擎看的是**导入表**里有没有
/// VirtualAlloc / CreateRemoteThread 这类名字。全文搜子串会把「源码里用来
/// 算 DJB2 哈希的字符串」也算进去 —— 而那些名字根本不进 IAT，是设计使然，
/// 于是告警 100% 触发，用户学会忽略它，连真正有意义的告警一起忽略掉。
///
/// 返回 None 表示该文件没有可解析的导入表（未导入任何函数，或结构异常）。
pub fn imported_names(d: &[u8]) -> Option<Vec<String>> {
    if d.len() < 0x40 {
        return None;
    }
    let e = u32::from_le_bytes([d[0x3c], d[0x3d], d[0x3e], d[0x3f]]) as usize;
    if e + 0x18 + 0x60 > d.len() || &d.get(e..e + 4)? != b"PE\0\0" {
        return None;
    }
    let magic = u16::from_le_bytes([d[e + 0x18], d[e + 0x19]]);
    let is_pp = magic == 0x20b;
    let dd = e + 0x18 + if is_pp { 0x70 } else { 0x60 };
    let imp = dd + 1 * 8; // DataDirectory[1] = IMPORT
    if imp + 8 > d.len() {
        return None;
    }
    let rva = u32::from_le_bytes([d[imp], d[imp + 1], d[imp + 2], d[imp + 3]]) as usize;
    if rva == 0 {
        return None;
    }

    // 节表：用于 RVA -> 文件偏移
    let nsec = u16::from_le_bytes([d[e + 6], d[e + 7]]) as usize;
    let opt_size = u16::from_le_bytes([d[e + 0x14], d[e + 0x15]]) as usize;
    let sh = e + 0x18 + opt_size;
    let mut spans: Vec<(usize, usize, usize)> = Vec::new(); // (va, vsize, praw)
    for i in 0..nsec {
        let s = sh + i * 40;
        if s + 40 > d.len() {
            break;
        }
        let vsz = u32::from_le_bytes([d[s + 8], d[s + 9], d[s + 10], d[s + 11]]) as usize;
        let va = u32::from_le_bytes([d[s + 12], d[s + 13], d[s + 14], d[s + 15]]) as usize;
        let rsz = u32::from_le_bytes([d[s + 16], d[s + 17], d[s + 18], d[s + 19]]) as usize;
        let praw = u32::from_le_bytes([d[s + 20], d[s + 21], d[s + 22], d[s + 23]]) as usize;
        spans.push((va, vsz.max(rsz), praw));
    }
    let rva2off = |r: usize| -> Option<usize> {
        for &(va, sz, praw) in &spans {
            if r >= va && r < va + sz {
                let o = praw + (r - va);
                if o < d.len() {
                    return Some(o);
                }
            }
        }
        None
    };

    let mut names: Vec<String> = Vec::new();
    let mut cur = rva2off(rva)?;
    for _ in 0..256 {
        // 每个 IMAGE_IMPORT_DESCRIPTOR 20 字节；全零表示结束
        if cur + 20 > d.len() {
            break;
        }
        if d[cur..cur + 20].iter().all(|&b| b == 0) {
            break;
        }
        let name_rva = u32::from_le_bytes([d[cur + 12], d[cur + 13], d[cur + 14], d[cur + 15]]) as usize;
        let thunk_rva = u32::from_le_bytes([d[cur], d[cur + 1], d[cur + 2], d[cur + 3]]) as usize;
        let _ = name_rva;
        if let Some(mut t) = rva2off(thunk_rva) {
            // 逐项读 Hint/Name 或 Ordinal
            let step = if is_pp { 8 } else { 4 };
            for _ in 0..4096 {
                if t + step > d.len() {
                    break;
                }
                let v = if is_pp {
                    u64::from_le_bytes([
                        d[t], d[t + 1], d[t + 2], d[t + 3], d[t + 4], d[t + 5], d[t + 6], d[t + 7],
                    ])
                } else {
                    u32::from_le_bytes([d[t], d[t + 1], d[t + 2], d[t + 3]]) as u64
                };
                if v == 0 {
                    break;
                }
                // 高位为 1 表示按序号导入（没有名字）
                let hi_bit: u64 = if is_pp { 1u64 << 63 } else { 1u64 << 31 };
                if v & hi_bit == 0 {
                    if let Some(no) = rva2off(v as usize) {
                        if no + 2 <= d.len() {
                            // Hint(2) + Name(NUL-terminated)
                            let mut end = no + 2;
                            while end < d.len() && d[end] != 0 {
                                end += 1;
                            }
                            if end > no + 2 {
                                names.push(String::from_utf8_lossy(&d[no + 2..end]).to_string());
                            }
                        }
                    }
                }
                t += step;
            }
        }
        cur += 20;
    }
    if names.is_empty() {
        None
    } else {
        Some(names)
    }
}

/// 香农熵（0..8）。>7.2 基本可以判定是加密/压缩内容。
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut hist = [0u64; 256];
    for &b in data {
        hist[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut h = 0f64;
    for c in hist {
        if c == 0 {
            continue;
        }
        let p = c as f64 / n;
        h -= p * p.log2();
    }
    h
}

/* ============================ 时间戳伪造 ============================ */

/// 改写 PE 头 TimeDateStamp + Debug Directory 里的时间戳。
/// 只改头部签名前的字段，不影响 Authenticode 覆盖的范围（签名由 sign.rs 处理）。
pub fn patch_timestamp(path: &Path, ts: u32) -> Result<usize, String> {
    let mut d = fs::read(path).map_err(|e| e.to_string())?;
    if d.len() < 0x40 {
        return Err("文件过小".into());
    }
    let e = u32::from_le_bytes([d[0x3c], d[0x3d], d[0x3e], d[0x3f]]) as usize;
    if e + 0x18 + 0x80 > d.len() {
        return Err("PE 头越界".into());
    }
    // IMAGE_FILE_HEADER.TimeDateStamp
    d[e + 8..e + 12].copy_from_slice(&ts.to_le_bytes());
    let mut patched = 1usize;

    let magic = u16::from_le_bytes([d[e + 0x18], d[e + 0x19]]);
    let dd = e + 0x18 + if magic == 0x20b { 0x70 } else { 0x60 };
    let dbg = dd + 6 * 8; // DataDirectory[6] = DEBUG
    if dbg + 8 > d.len() {
        fs::write(path, d).map_err(|x| x.to_string())?;
        return Ok(patched);
    }
    let rva = u32::from_le_bytes([d[dbg], d[dbg + 1], d[dbg + 2], d[dbg + 3]]) as usize;
    let size = u32::from_le_bytes([d[dbg + 4], d[dbg + 5], d[dbg + 6], d[dbg + 7]]) as usize;
    if rva == 0 || size < 28 {
        fs::write(path, d).map_err(|x| x.to_string())?;
        return Ok(patched);
    }
    // RVA -> 文件偏移
    let nsec = u16::from_le_bytes([d[e + 6], d[e + 7]]) as usize;
    let opt_size = u16::from_le_bytes([d[e + 0x14], d[e + 0x15]]) as usize;
    let sh = e + 0x18 + opt_size;
    for i in 0..nsec {
        let s = sh + i * 40;
        if s + 40 > d.len() {
            break;
        }
        let vsz = u32::from_le_bytes([d[s + 8], d[s + 9], d[s + 10], d[s + 11]]) as usize;
        let va = u32::from_le_bytes([d[s + 12], d[s + 13], d[s + 14], d[s + 15]]) as usize;
        let rsz = u32::from_le_bytes([d[s + 16], d[s + 17], d[s + 18], d[s + 19]]) as usize;
        let praw = u32::from_le_bytes([d[s + 20], d[s + 21], d[s + 22], d[s + 23]]) as usize;
        let span = vsz.max(rsz);
        if rva >= va && rva < va + span {
            let foff = praw + (rva - va);
            let end = (foff + size).min(d.len());
            let mut p = foff;
            while p + 28 <= end {
                // IMAGE_DEBUG_DIRECTORY.TimeDateStamp
                d[p + 4..p + 8].copy_from_slice(&ts.to_le_bytes());
                patched += 1;
                p += 28;
            }
            break;
        }
    }
    fs::write(path, d).map_err(|x| x.to_string())?;
    Ok(patched)
}

/// 把 PE 可选头的 CheckSum 归零。
///
/// 为什么要归零：mingw 的链接器按输出文件布局算 CheckSum，而布局依赖
/// 绝对输出路径等因素，不受 `MACLOADER_SEED` 控制。结果是固定种子的两次
/// 构建仍然产出不同字节（实测同种子跑 3 次得到 3 个不同 sha256，唯一差异
/// 就在 CheckSum 字段）—— README 承诺的「同配置逐字节相同」失效，
/// 变体矩阵的归因实验也就失去了可信度。
///
/// PE 规范允许 CheckSum = 0（表示未计算）；Windows 加载器对非驱动映像
/// 不校验该字段，且 Authenticode 签名本身也不覆盖 CheckSum。
/// 因此归零既安全，又能让种子复现真正成立。
///
/// 必须在 patch_timestamp 之后、签名之前调用。
pub fn clear_checksum(path: &Path) -> Result<(), String> {
    let mut d = fs::read(path).map_err(|e| e.to_string())?;
    if d.len() < 0x40 {
        return Err("文件过小".into());
    }
    let e = u32::from_le_bytes([d[0x3c], d[0x3d], d[0x3e], d[0x3f]]) as usize;
    if e + 0x18 + 0x60 > d.len() {
        return Err("PE 头越界".into());
    }
    if &d[e..e + 4] != b"PE\0\0" {
        return Err("不是 PE 文件（缺少 PE\\0\\0 签名）".into());
    }
    let magic = u16::from_le_bytes([d[e + 0x18], d[e + 0x19]]);
    // OptionalHeader.CheckSum：PE32+ 在 +0x40，PE32 在 +0x30
    let off = e + 0x18 + if magic == 0x20b { 0x40 } else { 0x30 };
    if off + 4 > d.len() {
        return Err("CheckSum 字段越界".into());
    }
    d[off..off + 4].copy_from_slice(&0u32.to_le_bytes());
    fs::write(path, d).map_err(|e| e.to_string())
}

/* ============================ 文件时间 ============================ */

/// 设置文件 mtime/atime
pub fn set_file_time(path: &Path, ts: i64) -> Result<(), String> {
    use std::fs::{File, FileTimes};
    use std::time::{Duration, SystemTime};
    let f = File::options().write(true).open(path).map_err(|e| e.to_string())?;
    let t = SystemTime::UNIX_EPOCH + Duration::from_secs(ts.max(0) as u64);
    f.set_times(FileTimes::new().set_modified(t).set_accessed(t))
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datetime_roundtrip() {
        let cases = [
            ("2024-11-15T08:30", "2024-11-15 08:30:00 UTC"),
            ("2024-03-01T10:30", "2024-03-01 10:30:00 UTC"),
            ("2024-01-01T00:00", "2024-01-01 00:00:00 UTC"),
            ("2024-12-31 23:59", "2024-12-31 23:59:00 UTC"),
            ("2024-06-15", "2024-06-15 00:00:00 UTC"),
        ];
        for (input, want) in cases {
            let ts = parse_datetime(input).unwrap_or_else(|| panic!("解析失败: {input}"));
            assert_eq!(fmt_ts(ts), want);
        }
    }

    #[test]
    fn rejects_bad_datetime() {
        for bad in ["", "  ", "abcd", "2024-13-01T00:00", "2024-00-01T00:00", "2024-01-32T00:00"] {
            assert!(parse_datetime(bad).is_none(), "{bad} 不应被解析");
        }
    }

    #[test]
    fn epoch_boundary() {
        assert_eq!(parse_datetime("1970-01-01T00:00").unwrap(), 0);
        assert_eq!(fmt_ts(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(parse_datetime("1970-01-02T00:00").unwrap(), 86400);
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(&[]), 0.0);
        // 全同字节 -> 0
        assert!(entropy(&vec![7u8; 1000]) < 0.001);
        // 均匀随机 -> 接近 8
        let mut v = Vec::new();
        for i in 0..4096u32 {
            v.push((i.wrapping_mul(2654435761) >> 16) as u8);
        }
        assert!(entropy(&v) > 6.5, "随机数据熵值应偏高: {}", entropy(&v));
        assert!(entropy(&v) <= 8.0);
    }

    #[test]
    fn non_pe_file_is_rejected() {
        let p = std::env::temp_dir().join("macloader_test_notpe.bin");
        fs::write(&p, vec![0u8; 4096]).unwrap();
        let e = parse(&p).expect_err("非 PE 必须报错");
        assert!(e.contains("PE"), "{e}");
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn tiny_file_is_rejected() {
        let p = std::env::temp_dir().join("macloader_test_tiny.bin");
        fs::write(&p, vec![0u8; 8]).unwrap();
        assert!(parse(&p).is_err());
        let _ = fs::remove_file(&p);
    }

    /* ---- P1-3 回归：SECURITY 目录要读 Size，不是 VirtualAddress ---- */

    /// 手工拼一个最小 PE，SECURITY 目录里 VirtualAddress=文件偏移、Size=长度。
    /// 断言 parse().cert_size 等于 Size（1664），而不是偏移（245760）。
    #[test]
    fn cert_size_reads_the_size_field() {
        let mut d = vec![0u8; 0x200];
        d[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew = 0x80
        d[0x80..0x84].copy_from_slice(b"PE\0\0");
        // COFF: machine=x86-64, nsec=0, optSize=0xF0, magic=PE32+
        d[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        d[0x86..0x88].copy_from_slice(&0u16.to_le_bytes());
        d[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes()); // SizeOfOptionalHeader
        d[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes()); // magic
        // OptionalHeader 起点 0x98；PE32+ 的 DataDirectory 在 +0x70 = 0x108
        let dd = 0x98 + 0x70;
        let sec = dd + 4 * 8; // DataDirectory[4] = SECURITY
        d[sec..sec + 4].copy_from_slice(&0x3c000u32.to_le_bytes()); // 文件偏移
        d[sec + 4..sec + 8].copy_from_slice(&1664u32.to_le_bytes()); // 真实长度

        let p = std::env::temp_dir().join("macloader_test_sec.bin");
        fs::write(&p, &d).unwrap();
        let info = parse(&p).expect("应解析成功");
        assert_eq!(
            info.cert_size, 1664,
            "cert_size 必须读 Size 字段，而不是 VirtualAddress(0x3c000)"
        );
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn imported_names_returns_none_without_imports() {
        // 无 DataDirectory[1] -> 无导入表
        let mut d = vec![0u8; 0x200];
        d[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        d[0x80..0x84].copy_from_slice(b"PE\0\0");
        d[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        d[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
        d[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        assert!(imported_names(&d).is_none());
    }
}
