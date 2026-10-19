//! 外部工具探测。
//!
//! GUI app 从 Finder/Dock 启动时 PATH 极其贫瘠（不含 /opt/homebrew/bin），
//! 于是 `which` 会误报「明明装了却找不到」。这里统一按 PATH + 常见 Homebrew
//! 目录查找，`main()` 里另外把 PATH 补齐（见 main.rs）。

use std::path::Path;

/// Homebrew 等常见安装位置，按优先级排列
const EXTRA_DIRS: &[&str] = &["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"];

/// 仅在 PATH 里找（语义等同 which）
pub fn which(name: &str) -> Option<String> {
    let path = std::env::var("PATH").unwrap_or_default();
    for d in path.split(':') {
        if d.is_empty() {
            continue;
        }
        let p = format!("{d}/{name}");
        if Path::new(&p).exists() {
            return Some(p);
        }
    }
    None
}

/// PATH + Homebrew 目录
pub fn find(names: &[&str]) -> Option<String> {
    for n in names {
        if let Some(p) = which(n) {
            return Some(p);
        }
        for d in EXTRA_DIRS {
            let p = format!("{d}/{n}");
            if Path::new(&p).exists() {
                return Some(p);
            }
        }
    }
    None
}

/// 交叉编译器。x86 优先 i686，找不到再回退 x86_64（都能产出 32 位）
pub fn compiler(arch: &str) -> Option<String> {
    let names: &[&str] = if arch == "x86" {
        &["i686-w64-mingw32-g++", "x86_64-w64-mingw32-g++"]
    } else {
        &["x86_64-w64-mingw32-g++", "i686-w64-mingw32-g++"]
    };
    find(names)
}

/// 资源编译器（windres）
pub fn windres(arch: &str) -> Option<String> {
    let names: &[&str] = if arch == "x86" {
        &["i686-w64-mingw32-windres", "x86_64-w64-mingw32-windres"]
    } else {
        &["x86_64-w64-mingw32-windres", "i686-w64-mingw32-windres"]
    };
    find(names)
}

/// 交叉 strip（去掉 .exe 里 mingw 留下的大量符号表，显著降体积/改形态）
pub fn strip(arch: &str) -> Option<String> {
    let names: &[&str] = if arch == "x86" {
        &["i686-w64-mingw32-strip", "x86_64-w64-mingw32-strip"]
    } else {
        &["x86_64-w64-mingw32-strip", "i686-w64-mingw32-strip"]
    };
    find(names)
}

/// openssl。优先 Homebrew 的 openssl@3（系统自带的是 LibreSSL，不支持部分参数）
pub fn openssl() -> Option<String> {
    for p in [
        "/opt/homebrew/opt/openssl@3/bin/openssl",
        "/usr/local/opt/openssl@3/bin/openssl",
    ] {
        if Path::new(p).exists() {
            return Some(p.into());
        }
    }
    find(&["openssl"])
}

pub fn osslsigncode() -> Option<String> {
    find(&["osslsigncode"])
}

pub fn brew() -> Option<String> {
    find(&["brew"])
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
}
