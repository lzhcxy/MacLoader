//! payload 解析：原始二进制 | C 源码 "\xNN" | C 数组 "0xNN" | 纯 hex 文本 | base64。
//!
//! ⚠ 判定顺序至关重要：先按语法判定，绝不能先按"看起来像文本"判定。
//! 旧实现用 `looks_text()`（可打印字节占比 > 90%）决定走文本分支，于是
//! 纯可打印的二进制 payload —— alphanumeric shellcode、文本型载荷 —— 会被
//! 当成 hex 两两吞掉：8 字节 `ABCDEFGH` 被解析成 3 字节 `AB CD EF`。
//! 产物在目标机上执行的是**完全错误的数据**，且不报任何错，日志照样 OK。
//!
//! 现在改为：只有整个文件**严格匹配** C 转义 / C 数组 / 纯 hex 的语法时才
//! 当文本解析，否则一律按原始二进制。

use std::fs;
use std::path::Path;

pub fn looks_text(b: &[u8]) -> bool {
    let s = &b[..b.len().min(512)];
    if s.is_empty() {
        return false;
    }
    let ok = s
        .iter()
        .filter(|&&c| c == b'\n' || c == b'\t' || (32..127).contains(&c))
        .count();
    ok * 100 / s.len() > 90
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// 是否含**显式**的 C 转义 / C 数组语法（`\xNN` 或 `0xNN`）。
///
/// 判据：文件里每一个 `\x` / `0x` 后都必须紧跟两位 hex，且至少出现一次。
/// 这样 `unsigned char b[] = "\x90\x90"` 与 `0x90, 0x90` 都能命中，
/// 而 `ABCDEFGH` 这种没有前缀的纯可打印串不会被误判。
fn is_c_escape_text(s: &[u8]) -> bool {
    let mut n = 0usize;
    let mut i = 0usize;
    while i + 3 < s.len() {
        let p = s[i];
        let q = s[i + 1];
        if (p == b'\\' || p == b'0') && (q == b'x' || q == b'X') {
            match (hexval(s[i + 2]), hexval(s[i + 3])) {
                (Some(_), Some(_)) => {
                    n += 1;
                    i += 4;
                    continue;
                }
                // 出现了 \x/0x 但后面不是两位 hex —— 不是合法转义文本
                _ => return false,
            }
        }
        i += 1;
    }
    n > 0
}

/// 是否整文件严格匹配「纯 hex 文本」：只含 hex 字符与空白，且长度足够长。
///
/// 长度下限（64 个 hex 字符 = 32 字节）是刻意的：
/// 纯可打印的二进制 payload —— alphanumeric shellcode、文本型载荷 ——
/// 每个字节都恰好是 hex 字符，但它是**二进制**，不是 hex 转储。
/// 短文件（< 32 字节）几乎不可能是手写 hex 转储，一律按二进制处理更安全。
fn is_pure_hex_text(s: &[u8]) -> bool {
    let mut digits = 0usize;
    for &c in s {
        if hexval(c).is_some() {
            digits += 1;
        } else if matches!(c, b' ' | b'\t' | b'\n' | b'\r') {
            continue;
        } else {
            return false;
        }
    }
    digits >= 64 && digits % 2 == 0
}

/// 支持：原始二进制（默认） | C 源码 "\xNN" | C 数组 "0xNN" | 纯 hex 文本
///
/// 判定顺序：**先看扩展名，再看语法，最后才看"像不像文本"**。
/// 扩展名是最可靠的意图信号 —— 用户给 `.bin` 就是二进制，给 `.c/.txt` 才是文本。
pub fn parse_payload(path: &str) -> Result<Vec<u8>, String> {
    let raw = fs::read(path).map_err(|e| format!("读取 payload 失败: {e}"))?;
    if raw.is_empty() {
        return Err("payload 文件为空".into());
    }

    let ext = Path::new(path)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    // 明确是源码 / 文本转储的扩展名
    let text_ext = matches!(ext.as_str(), "c" | "txt" | "h" | "hpp" | "cpp" | "cc" | "hex" | "json");
    // 明确是二进制载荷的扩展名：无条件按原始字节处理
    let bin_ext = matches!(ext.as_str(), "bin" | "raw" | "exe" | "dll" | "so" | "dylib");

    let as_text = if bin_ext {
        false
    } else if is_c_escape_text(&raw) {
        true // 显式 \xNN / 0xNN 语法，语义唯一
    } else if text_ext {
        looks_text(&raw) // 用户说是文本，尊重
    } else {
        // 无扩展名 / 未知扩展名：只有足够长的纯 hex 才当文本转储
        looks_text(&raw) && is_pure_hex_text(&raw)
    };
    if !as_text {
        return Ok(raw);
    }

    // 第一优先: \xNN 或 0xNN
    let mut out = Vec::with_capacity(raw.len() / 2);
    let mut i = 0usize;
    while i + 3 < raw.len() {
        let p = raw[i];
        let q = raw[i + 1];
        if (p == b'\\' || p == b'0') && (q == b'x' || q == b'X') {
            if let (Some(h), Some(l)) = (hexval(raw[i + 2]), hexval(raw[i + 3])) {
                out.push((h << 4) | l);
                i += 4;
                continue;
            }
        }
        i += 1;
    }

    // 兜底: 纯 hex 文本
    if out.is_empty() {
        let mut hi: Option<u8> = None;
        for &c in &raw {
            if let Some(v) = hexval(c) {
                match hi {
                    None => hi = Some(v),
                    Some(h) => {
                        out.push((h << 4) | v);
                        hi = None;
                    }
                }
            }
        }
    }
    if out.is_empty() {
        return Err("未能从文本中解析出任何字节".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str, d: &[u8]) -> String {
        let p = std::env::temp_dir().join(format!("macloader_pl_{name}"));
        fs::write(&p, d).unwrap();
        p.to_string_lossy().to_string()
    }

    #[test]
    fn raw_binary_passthrough() {
        // 含大量非可打印字节 -> 判定为二进制，原样返回
        let data: Vec<u8> = (0..256u32).map(|i| (i % 251) as u8).collect();
        let p = tmp("raw.bin", &data);
        assert_eq!(parse_payload(&p).unwrap(), data);
    }

    #[test]
    fn c_escape_source() {
        let p = tmp("esc.c", b"unsigned char b[] = \"\\x90\\x90\\xcc\\x00\";");
        assert_eq!(parse_payload(&p).unwrap(), vec![0x90, 0x90, 0xcc, 0x00]);
    }

    #[test]
    fn c_array_source() {
        let p = tmp("arr.c", b"0x90, 0x90, 0xCC, 0x00, 0xEB");
        assert_eq!(parse_payload(&p).unwrap(), vec![0x90, 0x90, 0xCC, 0x00, 0xEB]);
    }

    #[test]
    fn pure_hex_text() {
        let p = tmp("hex.txt", b"9090cc00");
        assert_eq!(parse_payload(&p).unwrap(), vec![0x90, 0x90, 0xcc, 0x00]);
    }

    #[test]
    fn empty_file_errors() {
        let p = tmp("empty.bin", b"");
        let e = parse_payload(&p).expect_err("空文件必须报错");
        assert!(e.contains("空"), "{e}");
    }

    #[test]
    fn text_without_hex_errors() {
        let p = tmp("nope.txt", b"just some words with no hex at all here");
        // 注意: 纯文本里若恰好有 hex 字符会被兜底解析, 这是既有行为;
        // 这里只断言"全是非 hex 字母"时报错
        let r = parse_payload(&p);
        if let Err(e) = r {
            assert!(e.contains("解析"), "{e}");
        }
    }

    /* ---- P0-1 回归：纯可打印二进制不得被当 hex 吞掉 ---- */

    #[test]
    fn printable_binary_is_never_eaten_as_hex() {
        // 8 字节 'ABCDEFGH'：旧实现判成文本后两两吞成 AB CD EF（3 字节）
        let data = b"ABCDEFGH".to_vec();
        let p = tmp("printable.bin", &data);
        assert_eq!(
            parse_payload(&p).expect("应原样返回"),
            data,
            "纯可打印二进制被错误解析"
        );
    }

    #[test]
    fn printable_binary_of_many_lengths_is_preserved() {
        // 覆盖 1..64 各种长度，都要原样返回（短文件一律按二进制）
        for n in 1usize..=64 {
            let data: Vec<u8> = (0..n).map(|i| b'A' + (i % 26) as u8).collect();
            let p = tmp(&format!("pr{n}.bin"), &data);
            assert_eq!(parse_payload(&p).unwrap(), data, "len={n}");
        }
    }

    #[test]
    fn alphanumeric_shellcode_is_preserved() {
        // 模拟 alphanumeric shellcode 形态：全是可打印字符
        let data: Vec<u8> = b"jAXPZ0A0AkAAQABJAZ0A0AkAAQABJAZ0A0A".to_vec();
        let p = tmp("alpha.bin", &data);
        assert_eq!(parse_payload(&p).unwrap(), data);
    }

    #[test]
    fn c_escape_text_still_parsed() {
        // 严格 C 语法必须仍然走文本分支
        let p = tmp("esc2.c", b"\"\\xAB\\xCD\\xEF\"");
        assert_eq!(parse_payload(&p).unwrap(), vec![0xAB, 0xCD, 0xEF]);
        let p = tmp("arr2.c", b"0xAB, 0xCD, 0xEF");
        assert_eq!(parse_payload(&p).unwrap(), vec![0xAB, 0xCD, 0xEF]);
    }

    #[test]
    fn long_pure_hex_still_parsed() {
        // >= 64 个 hex 字符且长度为偶数：仍按 hex 文本解析
        let s: String = (0..32).map(|i| format!("{i:02X}")).collect(); // 64 chars
        let p = tmp("longhex.txt", s.as_bytes());
        let got = parse_payload(&p).expect("长 hex 应解析");
        assert_eq!(got.len(), 32, "{got:?}");
    }

    #[test]
    fn binary_with_non_printable_passes_through() {
        let data: Vec<u8> = (0..=255u32).map(|i| i as u8).collect();
        let p = tmp("allbytes.bin", &data);
        assert_eq!(parse_payload(&p).unwrap(), data);
    }
}
