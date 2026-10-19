//! 有状态 PRNG（xorshift64*）。
//!
//! 为什么不直接用 rand crate：这里需要「可复现」。
//! `MACLOADER_SEED=<n>` 固定随机序列，让同一配置两次构建产出逐字节相同。
//! 不固定时每次都随机化块数/块长/密钥/垃圾代码 —— 于是「同一配置」的两次
//! 产物哈希不同，无法判断某个变体被杀到底是因为配置项，还是纯粹运气。
//! 做对照实验前必须先固定种子。

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// 兜底常量：种子解析失败 / 时钟不可用时用它。
const GOLDEN: u64 = 0x9E37_79B9_7F4A_7C15;

static STATE: AtomicU64 = AtomicU64::new(0);

/// 当前是否处于「固定种子」模式。
pub fn seeded() -> bool {
    std::env::var("MACLOADER_SEED").is_ok()
}

fn init_value() -> u64 {
    let n = match std::env::var("MACLOADER_SEED") {
        Ok(v) => v.parse::<u64>().unwrap_or(GOLDEN),
        Err(_) => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(GOLDEN),
    };
    if seeded() {
        // 固定种子时去掉 pid 熵，保证真正可复现
        n ^ GOLDEN
    } else {
        n ^ (std::process::id() as u64).wrapping_mul(0x2545_F491_4F6C_DD1D) ^ GOLDEN
    }
}

pub fn rand_u64() -> u64 {
    let mut s = STATE.load(Ordering::Relaxed);
    if s == 0 {
        s = init_value();
        if s == 0 {
            s = GOLDEN;
        }
    }
    let mut x = s;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    STATE.store(x, Ordering::Relaxed);
    x.wrapping_mul(0x2545_F491_4F6C_DD1D)
}

/// 1..=254，刻意避开 0：XOR 密钥为 0 等于没加密。
pub fn rand_byte() -> u8 {
    ((rand_u64() % 254) + 1) as u8
}

/// [0, n)
pub fn rand_below(n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    (rand_u64() % n as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_returns_zero_key() {
        for _ in 0..4096 {
            let b = rand_byte();
            assert!(b >= 1 && b <= 254, "{b}");
        }
    }

    #[test]
    fn consecutive_values_differ() {
        let mut same = 0;
        let mut prev = rand_u64();
        for _ in 0..10_000 {
            let v = rand_u64();
            if v == prev {
                same += 1;
            }
            prev = v;
        }
        assert_eq!(same, 0, "xorshift64* 不应出现连续重复值");
    }

    #[test]
    fn rand_below_stays_in_range() {
        for n in [1usize, 2, 3, 17, 256] {
            for _ in 0..512 {
                assert!(rand_below(n) < n);
            }
        }
        assert_eq!(rand_below(0), 0);
    }
}
