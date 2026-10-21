//! 配置持久化：命名方案（profile）与「上次配置」记忆。
//!
//! 存在 `$HOME/.macloader/profiles/*.json` 与 `last.json`。
//! 只写 JSON，不写可执行内容。

use std::fs;
use std::path::PathBuf;

use crate::builder::GenOpts;

const CONFIG_DIR_ENV: &str = "MACLOADER_CONFIG_DIR";

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Profile {
    pub name: String,
    pub opts: GenOpts,
    /// 保存时间（unix 秒）
    pub saved_at: u64,
}

pub fn dir() -> PathBuf {
    if let Some(path) = std::env::var_os(CONFIG_DIR_ENV) {
        return PathBuf::from(path);
    }
    crate::builder::platform::config_root().join("profiles")
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 文件名安全化：只允许字母数字、下划线、连字符与 CJK。
fn safe_name(name: &str) -> String {
    let s: String = name
        .trim()
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .take(64)
        .collect();
    if s.is_empty() {
        "default".to_string()
    } else {
        s
    }
}

pub fn save(name: &str, opts: &GenOpts) -> Result<String, String> {
    let d = dir();
    fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    let p = d.join(format!("{}.json", safe_name(name)));
    let prof = Profile {
        name: name.trim().to_string(),
        opts: opts.clone(),
        saved_at: now(),
    };
    let s = serde_json::to_string_pretty(&prof).map_err(|e| e.to_string())?;
    fs::write(&p, s).map_err(|e| e.to_string())?;
    Ok(p.to_string_lossy().to_string())
}

pub fn load(name: &str) -> Result<GenOpts, String> {
    let p = dir().join(format!("{}.json", safe_name(name)));
    let s = fs::read_to_string(&p).map_err(|e| format!("读取方案失败: {e}"))?;
    let prof: Profile = serde_json::from_str(&s).map_err(|e| format!("方案解析失败: {e}"))?;
    Ok(prof.opts)
}

pub fn list() -> Vec<Profile> {
    let d = dir();
    let Ok(rd) = fs::read_dir(&d) else {
        return vec![];
    };
    let mut out: Vec<Profile> = rd
        .flatten()
        .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
        .filter_map(|e| fs::read_to_string(e.path()).ok())
        .filter_map(|s| serde_json::from_str::<Profile>(&s).ok())
        .collect();
    out.sort_by(|a, b| b.saved_at.cmp(&a.saved_at));
    out
}

pub fn delete(name: &str) -> Result<(), String> {
    let p = dir().join(format!("{}.json", safe_name(name)));
    if !p.exists() {
        return Err("方案不存在".into());
    }
    fs::remove_file(p).map_err(|e| e.to_string())
}

/// 记忆「上次的配置」，下次启动自动恢复
pub fn save_last(opts: &GenOpts) -> Result<(), String> {
    let d = dir();
    fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    let p = d.join("last.json");
    let s = serde_json::to_string_pretty(opts).map_err(|e| e.to_string())?;
    fs::write(p, s).map_err(|e| e.to_string())
}

pub fn load_last() -> Option<GenOpts> {
    let p = dir().join("last.json");
    let s = fs::read_to_string(p).ok()?;
    serde_json::from_str(&s).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct TestEnv {
        path: PathBuf,
        _guard: MutexGuard<'static, ()>,
    }

    impl TestEnv {
        fn new() -> Self {
            let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let path = std::env::temp_dir().join(format!(
                "macloader-profile-test-{}-{}",
                std::process::id(),
                now()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("创建测试配置目录失败");
            std::env::set_var(CONFIG_DIR_ENV, &path);
            Self {
                path,
                _guard: guard,
            }
        }
    }

    impl Drop for TestEnv {
        fn drop(&mut self) {
            std::env::remove_var(CONFIG_DIR_ENV);
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn safe_name_filters_path_chars() {
        assert_eq!(safe_name("a/b"), "ab");
        assert_eq!(safe_name("../../etc"), "etc");
        assert_eq!(safe_name("   "), "default");
        assert_eq!(safe_name(""), "default");
        assert_eq!(safe_name("我的 方案"), "我的方案");
    }

    #[test]
    fn save_then_load_roundtrip() {
        let _env = TestEnv::new();
        let mut o = GenOpts::default();
        o.arch = "x86".into();
        o.encoding = "b32".into();
        o.icon = "lib:pdf".into();
        o.out_name = "rt.exe".into();
        save("unittest-rt", &o).expect("保存失败");
        let back = load("unittest-rt").expect("读取失败");
        assert_eq!(back.arch, "x86");
        assert_eq!(back.encoding, "b32");
        assert_eq!(back.icon, "lib:pdf");
        assert_eq!(back.out_name, "rt.exe");
        let _ = delete("unittest-rt");
    }

    #[test]
    fn load_missing_profile_errors() {
        let _env = TestEnv::new();
        assert!(load("definitely-not-saved-xyz").is_err());
    }

    #[test]
    fn list_includes_saved() {
        let _env = TestEnv::new();
        let o = GenOpts::default();
        save("unittest-list", &o).unwrap();
        let names: Vec<String> = list().into_iter().map(|p| p.name).collect();
        assert!(names.iter().any(|n| n == "unittest-list"), "{names:?}");
        let _ = delete("unittest-list");
    }

    #[test]
    fn delete_missing_errors() {
        let _env = TestEnv::new();
        assert!(delete("definitely-not-saved-xyz").is_err());
    }

    #[test]
    fn last_roundtrip() {
        let _env = TestEnv::new();
        let mut o = GenOpts::default();
        o.encoding = "uuid".into();
        save_last(&o).unwrap();
        let back = load_last().expect("读取 last 失败");
        assert_eq!(back.encoding, "uuid");
    }
}
