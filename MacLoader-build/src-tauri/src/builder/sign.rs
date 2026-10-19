//! Authenticode 自签名。
//!
//! 关键点：证书必须按 subject 缓存。
//! 旧实现固定用 `codesign.pfx`，于是「换图标 → 版本信息变 Adobe → 签名者仍是
//! Microsoft」这种矛盾会一直保留。现在把 subject 摘要进文件名。

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::builder::hash::short;
use crate::builder::tools::{osslsigncode, openssl};

/// 证书缓存位置：$HOME/.macloader/
pub fn cert_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".macloader")
}

/// 确保存在与 subject 对应的自签代码签名证书 + PFX，返回（pfx 路径，密码）
pub fn ensure_cert(subject: &str) -> Result<(PathBuf, String), String> {
    let dir = cert_dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let tag = short(subject.as_bytes());
    let safe: String = subject
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .take(48)
        .collect();
    let stem = format!("codesign-{safe}-{tag}");
    let pfx = dir.join(format!("{stem}.pfx"));
    let key = dir.join(format!("{stem}.key"));
    let crt = dir.join(format!("{stem}.crt"));
    let pass = "macloader".to_string();

    if pfx.exists() && key.exists() {
        return Ok((pfx, pass));
    }
    let ossl = openssl().ok_or("未找到 openssl")?;

    // OpenSSL 3 要求 -subj 用 "/CN=.." 形式；这里把逗号形式自动转过来
    let mut subj = subject.trim().to_string();
    if subj.is_empty() {
        subj = crate::builder::resource::d_subj();
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
    let _ = fs::remove_file(&pfx);

    let o = Command::new(&ossl)
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            key.to_str().unwrap_or("k.pem"),
            "-out",
            crt.to_str().unwrap_or("c.pem"),
            "-days",
            "3650",
            "-subj",
            &subj,
            "-addext",
            "keyUsage=critical,digitalSignature",
            "-addext",
            "extendedKeyUsage=codeSigning",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
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
            "pkcs12",
            "-export",
            "-out",
            pfx.to_str().unwrap_or("c.pfx"),
            "-inkey",
            key.to_str().unwrap_or("k.pem"),
            "-in",
            crt.to_str().unwrap_or("c.pem"),
            "-passout",
            &format!("pass:{pass}"),
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if !o.status.success() {
        return Err(format!("PFX 打包失败: {}", String::from_utf8_lossy(&o.stderr)));
    }
    Ok((pfx, pass))
}

/// 用 osslsigncode 签名；tsa 为空则不打时间戳
pub fn sign_exe(path: &Path, pfx: &Path, pass: &str, name: &str, tsa: &str) -> Result<(), String> {
    let osslsc = osslsigncode().ok_or_else(|| "未找到 osslsigncode".to_string())?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::resource::preset_subject;

    #[test]
    fn different_subjects_get_different_cache_files() {
        // 这是本次修的核心缺陷：subject 变了必须换证书文件。
        let a = preset_subject("lib:notepad");
        let b = preset_subject("lib:pdf");
        assert_ne!(short(a.as_bytes()), short(b.as_bytes()));
        assert_ne!(a, b);
    }

    #[test]
    fn cache_stem_is_filesystem_safe() {
        // subject 里含 / 与空格，不能直接进文件名
        let s = preset_subject("lib:word");
        let safe: String = s
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .take(48)
            .collect();
        assert!(!safe.contains('/'), "{safe}");
        assert!(!safe.contains(' '), "{safe}");
        assert!(safe.len() <= 48);
    }

    #[test]
    fn comma_subject_is_converted() {
        let mut subj = "C=US, O=Acme".to_string();
        if !subj.starts_with('/') {
            subj = subj
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| format!("/{s}"))
                .collect();
        }
        assert_eq!(subj, "/C=US/O=Acme");
    }
}
