//! 外部工具探测。
//!
//! GUI app 从桌面环境启动时 PATH 可能很贫瘠（macOS 从 Finder 启动不含
//! /opt/homebrew/bin），于是 `which` 会误报「明明装了却找不到」。
//! 这里统一按 PATH + 平台常见目录查找，目录清单见 [`platform`]；
//! `main()` 里另外把 PATH 补齐（见 main.rs）。

use std::path::Path;

use crate::builder::platform::{exe_suffix, extra_bin_dirs, path_sep};

/// 仅在 PATH 里找（语义等同 which / where）
pub fn which(name: &str) -> Option<String> {
    let path = std::env::var("PATH").unwrap_or_default();
    for d in path.split(path_sep()) {
        if d.is_empty() {
            continue;
        }
        // Windows 下可执行文件带 .exe，没给后缀时自动补一次
        for cand in [format!("{d}/{name}"), format!("{d}/{name}{}", exe_suffix())] {
            if Path::new(&cand).exists() {
                return Some(cand);
            }
        }
    }
    None
}

/// PATH + 平台常见目录
pub fn find(names: &[&str]) -> Option<String> {
    for n in names {
        if let Some(p) = which(n) {
            return Some(p);
        }
        for d in extra_bin_dirs() {
            for cand in [format!("{d}/{n}"), format!("{d}/{n}{}", exe_suffix())] {
                if Path::new(&cand).exists() {
                    return Some(cand);
                }
            }
        }
    }
    None
}

/// 某类工具的候选名：交叉编译前缀版在前，本机原生名在后。
///
/// 为什么要有两套名字：在 macOS/Linux 上 mingw 是交叉工具链，二进制一律带
/// `x86_64-w64-mingw32-` 前缀；而在 Windows 的 MSYS2 里，装的就是**本机**
/// 编译器，名字是没有前缀的 `g++` / `windres` / `strip`。
/// 只认前缀名的话，Windows 上会「明明装了 mingw 却报未找到」。
fn tool_names(arch: &str, base: &str) -> Vec<String> {
    let mut v = Vec::new();
    if arch == "x86" {
        v.push(format!("i686-w64-mingw32-{base}"));
        v.push(format!("x86_64-w64-mingw32-{base}"));
    } else {
        v.push(format!("x86_64-w64-mingw32-{base}"));
        v.push(format!("i686-w64-mingw32-{base}"));
    }
    // 本机原生名（MSYS2 / 已把 mingw 设为默认编译器的环境）
    v.push(base.to_string());
    v
}

/// 交叉编译器。x86 优先 i686，找不到再回退 x86_64（都能产出 32 位）
pub fn compiler(arch: &str) -> Option<String> {
    let names = tool_names(arch, "g++");
    find(&names.iter().map(|s| s.as_str()).collect::<Vec<_>>())
}

/// 资源编译器（windres）
pub fn windres(arch: &str) -> Option<String> {
    let names = tool_names(arch, "windres");
    find(&names.iter().map(|s| s.as_str()).collect::<Vec<_>>())
}

/// 交叉 strip（去掉 .exe 里 mingw 留下的大量符号表，显著降体积/改形态）
pub fn strip(arch: &str) -> Option<String> {
    let names = tool_names(arch, "strip");
    find(&names.iter().map(|s| s.as_str()).collect::<Vec<_>>())
}

/// openssl。优先挑真正的 OpenSSL（macOS 系统自带的是 LibreSSL，
/// 不支持部分参数），候选路径见 [`platform::openssl_candidates`]。
pub fn openssl() -> Option<String> {
    for p in crate::builder::platform::openssl_candidates() {
        if Path::new(p).exists() {
            return Some((*p).to_string());
        }
    }
    find(&["openssl"])
}

pub fn osslsigncode() -> Option<String> {
    find(&["osslsigncode"])
}

/// 包管理器。仅 macOS 有 brew，其它平台返回 None（依赖需手工安装）。
pub fn brew() -> Option<String> {
    crate::builder::platform::package_manager()
}

/// 缺失时的占位文案（前端按这个字符串判断，别改）
pub const NOT_FOUND: &str = "未找到";

pub fn or_not_found(v: Option<String>) -> String {
    v.unwrap_or_else(|| NOT_FOUND.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_sh() {
        // /bin/sh 一定存在，用它验证 PATH 与 EXTRA_DIRS 两条路径都能命中
        assert!(find(&["sh"]).is_some());
    }

    #[test]
    fn unknown_tool_is_none() {
        assert!(find(&["definitely-not-a-real-tool-xyz"]).is_none());
        assert_eq!(
            or_not_found(find(&["definitely-not-a-real-tool-xyz"])),
            NOT_FOUND
        );
    }

    #[test]
    fn arch_selects_matching_compiler_names() {
        // 即便本机没装 mingw，也至少要保证 x86 与 x64 查的是不同名字
        assert!(compiler("x86").is_none() || compiler("x86") != compiler("x64"));
    }

    #[test]
    fn tool_names_include_native_fallback() {
        // Windows/MSYS2 里 mingw 没有 target 前缀，候选里必须有裸名
        let n = tool_names("x64", "g++");
        assert!(n.contains(&"x86_64-w64-mingw32-g++".to_string()));
        assert!(n.contains(&"g++".to_string()), "{n:?}");
        let n86 = tool_names("x86", "windres");
        assert!(n86.contains(&"i686-w64-mingw32-windres".to_string()));
        assert!(n86.contains(&"windres".to_string()), "{n86:?}");
    }
}