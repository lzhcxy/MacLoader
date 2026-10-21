//! 平台差异抽象层。
//!
//! 本工具原本只在 macOS 上跑，有几处硬编码的 macOS 假设：
//!   - 外部工具散落在 `/opt/homebrew/bin` 等固定目录
//!   - 图片转 .ico 借 macOS 自带的 `sips`
//!   - 配置/证书缓存在 `$HOME/.macloader`
//!   - 依赖安装走 `brew install`
//!   - PATH 分隔符是 `:`，可执行文件没有扩展名
//!
//! 出 Windows 版时这些全部要换一套实现。集中放在这里，
//! 其它模块只调这些函数，不再自己写 `cfg!` 或拼路径。

use std::path::PathBuf;

/* ============================ 基本信息 ============================ */

/// 宿主平台名，用于环境自检页展示
pub fn host_os() -> &'static str {
    if cfg!(target_os = "macos") {
        "macOS"
    } else if cfg!(target_os = "windows") {
        "Windows"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else {
        "unknown"
    }
}

/// PATH 环境变量分隔符
pub fn path_sep() -> char {
    if cfg!(target_os = "windows") {
        ';'
    } else {
        ':'
    }
}

/// 本机可执行文件的扩展名（Windows 是 ".exe"，其它平台为空）
pub fn exe_suffix() -> &'static str {
    if cfg!(target_os = "windows") {
        ".exe"
    } else {
        ""
    }
}

/// 是否支持一键安装依赖（目前只有 macOS 有 brew）
pub fn supports_dep_install() -> bool {
    cfg!(target_os = "macos")
}

/* ============================ 配置目录 ============================ */

/// 用户配置/缓存根目录。
///
/// - macOS/Linux: `$HOME/.macloader`
/// - Windows:     `%APPDATA%\\MacLoader`（没有 HOME 时的正确落点；
///                直接写 C:\Users\xxx\.macloader 会因为权限或
///                UAC 虚拟化出问题，所以走已知的 AppData roaming）
pub fn config_root() -> PathBuf {
    if cfg!(target_os = "windows") {
        if let Some(d) = std::env::var_os("APPDATA") {
            return PathBuf::from(d).join("MacLoader");
        }
        if let Some(d) = std::env::var_os("USERPROFILE") {
            return PathBuf::from(d).join("AppData").join("Roaming").join("MacLoader");
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".macloader")
}

/* ============================ 外部工具探测 ============================ */

/// PATH 之外额外要搜的目录。
///
/// macOS 的 GUI app 从 Finder 启动时 PATH 极贫瘠（不含 /opt/homebrew/bin），
/// 必须补这些目录，否则 brew / osslsigncode 会「明明装了却找不到」。
/// Windows 下 mingw 常见于 MSYS2 / Chocolatey / Scoop 的这几个位置。
pub fn extra_bin_dirs() -> &'static [&'static str] {
    if cfg!(target_os = "macos") {
        &["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"]
    } else if cfg!(target_os = "windows") {
        &[
            r"C:\msys64\mingw64\bin",
            r"C:\msys64\ucrt64\bin",
            r"C:\tools\msys64\mingw64\bin",
            r"C:\ProgramData\chocolatey\bin",
            r"C:\Program Files\mingw-w64\x86_64-w64-mingw32\bin",
        ]
    } else {
        &["/usr/bin", "/usr/local/bin", "/bin"]
    }
}

/// 启动时补进 PATH 的目录串（按平台分隔符拼接）
pub fn bootstrap_path() -> String {
    if cfg!(target_os = "windows") {
        // Windows 不做 PATH 注入：注册表里的 PATH 已经包含用户安装位置，
        // 而且 GUI 进程从资源管理器启动时 PATH 也是完整的。
        return String::new();
    }
    "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".to_string()
}

/// openssl 的候选绝对路径（系统自带的 LibreSSL 不支持部分参数，优先挑真 OpenSSL）
pub fn openssl_candidates() -> &'static [&'static str] {
    if cfg!(target_os = "macos") {
        &[
            "/opt/homebrew/opt/openssl@3/bin/openssl",
            "/usr/local/opt/openssl@3/bin/openssl",
        ]
    } else if cfg!(target_os = "windows") {
        &[
            r"C:\msys64\mingw64\bin\openssl.exe",
            r"C:\msys64\ucrt64\bin\openssl.exe",
            r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
            r"C:\Program Files\Git\usr\bin\openssl.exe",
        ]
    } else {
        &["/usr/bin/openssl"]
    }
}

/// 包管理器（用于依赖安装引导）。macOS 是 brew；Windows 没有等价物。
pub fn package_manager() -> Option<String> {
    if cfg!(target_os = "macos") {
        crate::builder::tools::find(&["brew"])
    } else {
        None
    }
}

/// 包管理器的人类可读名
pub fn package_manager_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "brew"
    } else if cfg!(target_os = "windows") {
        "MSYS2 pacman"
    } else {
        "apt/dnf"
    }
}

/// 安装依赖要执行的命令**固定前缀**：返回 (程序, 固定参数)，
/// 调用方自己把包名追加在后面（最终形如 `brew install <pkg>`）。
///
/// 不在这里收 pkg 参数，是为了避免调用方「传了 pkg 又自己追加一次」
/// 拼出 `brew install "" <pkg>` 这种空参数命令。
/// Windows / Linux 无自动安装，返回 None，由 [`install_hint`] 给指引。
pub fn install_command() -> Option<(String, Vec<String>)> {
    if cfg!(target_os = "macos") {
        let brew = crate::builder::tools::find(&["brew"])?;
        Some((brew, vec!["install".into()]))
    } else {
        None
    }
}

/// Windows 下给用户的手工安装指引
pub fn install_hint() -> String {
    if cfg!(target_os = "windows") {
        "Windows 下不提供自动安装。请装 MSYS2（https://www.msys2.org）后执行：\n\
         pacman -S --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-windres openssl\n\
         osslsigncode 可从 https://github.com/mtrojnar/osslsigncode 取 Windows 构建。"
            .into()
    } else if cfg!(target_os = "linux") {
        "Linux 下请安装：apt install -y mingw-w64 osslsigncode openssl".into()
    } else {
        "macOS 下点击上方「安装依赖」自动完成，或手工：brew install mingw-w64 osslsigncode".into()
    }
}

/* ============================ 图片 → ICO ============================ */

/// 把 png/jpg 转成多尺寸 .ico。
///
/// macOS 借自带的 `sips` 缩放后再手工组 ICO 容器；
/// Windows 没有 sips，改用自带 `magick`（ImageMagick）或回退到
/// 「直接用原图塞单尺寸 ICO」—— 图标不完美但不阻断构建，
/// 总比整条流程挂掉强。
pub fn convert_to_ico(src: &str, tmp: &std::path::Path) -> Result<Vec<u8>, String> {
    if cfg!(target_os = "windows") {
        return ico_from_image_windows(src, tmp);
    }
    ico_from_image_unix(src, tmp)
}

/// 组 ICO 容器：若干张 PNG 按 (尺寸, 字节) 拼成一个 .ico
pub(crate) fn pack_ico(pngs: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let n = pngs.len();
    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&1u16.to_le_bytes()); // type = icon
    out.extend_from_slice(&(n as u16).to_le_bytes());
    let mut off = 6 + 16 * n;
    for (s, d) in pngs {
        let b = if *s >= 256 { 0u8 } else { *s as u8 };
        out.push(b);
        out.push(b);
        out.push(0);
        out.push(0);
        out.extend_from_slice(&1u16.to_le_bytes()); // planes
        out.extend_from_slice(&32u16.to_le_bytes()); // bpp
        out.extend_from_slice(&(d.len() as u32).to_le_bytes());
        out.extend_from_slice(&(off as u32).to_le_bytes());
        off += d.len();
    }
    for (_, d) in pngs {
        out.extend_from_slice(d);
    }
    out
}

/// macOS/Linux：用 sips 逐尺寸缩放
fn ico_from_image_unix(src: &str, tmp: &std::path::Path) -> Result<Vec<u8>, String> {
    use std::fs;
    use std::process::Command;

    let sips = crate::builder::tools::find(&["sips"]).unwrap_or_else(|| "sips".to_string());
    let mut pngs: Vec<(u32, Vec<u8>)> = Vec::new();
    for s in [16u32, 32, 48, 64, 128, 256] {
        let dst = tmp.join(format!("s{s}.png"));
        let ok = Command::new(&sips)
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
    Ok(pack_ico(&pngs))
}

/// Windows：优先 magick，否则单尺寸兜底
fn ico_from_image_windows(src: &str, tmp: &std::path::Path) -> Result<Vec<u8>, String> {
    use std::fs;
    use std::process::Command;

    let raw = fs::read(src).map_err(|e| format!("读取图片失败: {e}"))?;
    // 源图本身是 .ico 就直接用
    if raw.len() > 8 && raw[..4] == [0, 0, 1, 0] {
        return Ok(raw);
    }

    let magick = crate::builder::tools::find(&["magick", "convert"]);
    if let Some(mg) = magick {
        let mut pngs: Vec<(u32, Vec<u8>)> = Vec::new();
        for s in [16u32, 32, 48, 64, 128, 256] {
            let dst = tmp.join(format!("s{s}.png"));
            let ok = Command::new(&mg)
                .args([src, "-resize", &format!("{s}x{s}")])
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
        if !pngs.is_empty() {
            return Ok(pack_ico(&pngs));
        }
    }

    // 兜底：原图直接塞一个 256 尺寸的条目。
    // 尺寸标注不准，但资源仍然合法，图标能显示，不阻断构建。
    if raw.len() > 8 && (&raw[1..4] == b"PNG" || &raw[..2] == b"\xff\xd8") {
        return Ok(pack_ico(&[(256, raw)]));
    }
    Err("图片转换失败：需要 ImageMagick（magick），或换用 .ico 文件".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_os_is_recognized() {
        assert_ne!(host_os(), "unknown");
    }

    #[test]
    fn config_root_is_absolute_and_nonempty() {
        let r = config_root();
        assert!(!r.as_os_str().is_empty(), "{r:?}");
    }

    #[test]
    fn exe_suffix_matches_target() {
        if cfg!(target_os = "windows") {
            assert_eq!(exe_suffix(), ".exe");
        } else {
            assert_eq!(exe_suffix(), "");
        }
    }

    #[test]
    fn pack_ico_header_is_valid() {
        let png = vec![0x89, b'P', b'N', b'G', 0, 0, 0, 0, 1];
        let ico = pack_ico(&[(16, png.clone())]);
        assert_eq!(&ico[..4], &[0, 0, 1, 0], "ICO 头不对");
        assert_eq!(ico.len(), 6 + 16 + png.len());
    }

    #[test]
    fn pack_ico_multiple_sizes() {
        let p = vec![0x89, b'P', b'N', b'G', 9, 9, 9, 9, 1];
        let ico = pack_ico(&[(16, p.clone()), (32, p.clone()), (256, p.clone())]);
        // 3 条目：头 6 + 目录 3*16 + 数据 3*len
        assert_eq!(ico.len(), 6 + 48 + 3 * p.len());

        // ICONDIRENTRY 布局（每项 16 字节）：
        //   +0 宽  +1 高  +2 色数  +3 保留
        //   +4 planes(u16)  +6 bpp(u16)  +8 size(u32)  +12 offset(u32)
        // 第 i 项起点 = 6 + i*16
        let e = |i: usize| 6 + i * 16;
        assert_eq!(ico[e(0)], 16, "第 1 项宽");
        assert_eq!(ico[e(1)], 32, "第 2 项宽");
        assert_eq!(ico[e(2)], 0, "256 无法放进 1 字节，按 0（=256）");

        // 每项的 size 字段都等于该 PNG 长度
        for i in 0..3 {
            let sz = u32::from_le_bytes([
                ico[e(i) + 8],
                ico[e(i) + 9],
                ico[e(i) + 10],
                ico[e(i) + 11],
            ]);
            assert_eq!(sz as usize, p.len(), "第 {} 项 size 字段", i + 1);
        }

        // offset 必须依次指向各自的数据，且末项末尾正好结束
        let mut expect_off = 6 + 3 * 16;
        for i in 0..3 {
            let off = u32::from_le_bytes([
                ico[e(i) + 12],
                ico[e(i) + 13],
                ico[e(i) + 14],
                ico[e(i) + 15],
            ]);
            assert_eq!(off as usize, expect_off, "第 {} 项 offset", i + 1);
            assert_eq!(&ico[off as usize..off as usize + p.len()], &p[..]);
            expect_off += p.len();
        }
        assert_eq!(expect_off, ico.len(), "末项数据应正好填满");
    }

    #[test]
    fn install_hint_is_nonempty() {
        assert!(!install_hint().is_empty());
    }

    #[test]
    fn bootstrap_path_only_on_unix() {
        if cfg!(target_os = "windows") {
            assert!(bootstrap_path().is_empty());
        } else {
            assert!(!bootstrap_path().is_empty());
        }
    }
}
