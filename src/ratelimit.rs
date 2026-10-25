//! CC（Challenge Collapsar）限速：固定 60 秒窗口的每 IP 请求计数。
//!
//! 计数引擎已下沉 [`dhrust::ratelimit`]（与接口级限流 [`crate::throttle`] 共用）；
//! 本模块保留 WAF 的 CC 语义：每个 key **首次命中起 60 秒**固定上限，超限返回 429。
//! 与旧实现（自然分钟边界）的差异：跨整点不再集中重置，避免整点突发；
//! 窗口锚点从“自然分钟”改为“每 IP 首次命中”，与 dhrust 引擎/C# `DH.RateLimter` 口径一致。

use std::time::Duration;

use dhrust::ratelimit::{Decision, WindowLimiter};

/// 固定窗口限速器（每 key 每 60 秒 N 次；0 = 关闭由调用方判断）。
pub struct RateLimiter {
    inner: WindowLimiter,
}

impl RateLimiter {
    /// 新建空限速器。
    pub fn new() -> Self {
        Self {
            inner: WindowLimiter::new(),
        }
    }

    /// 记一次请求并返回判定（含窗口剩余时间，可直接用于 `Retry-After`）。
    pub fn check(&self, key: &str, per_minute: u32) -> Decision {
        if per_minute == 0 {
            return Decision {
                allowed: true,
                count: 0,
                limit: 0,
                reset_in: Duration::ZERO,
            };
        }
        self.inner
            .hit(key, u64::from(per_minute), Duration::from_secs(60))
    }

    /// 记一次请求；超限返回 `false`。
    pub fn allow(&self, key: &str, per_minute: u32) -> bool {
        self.check(key, per_minute).allowed
    }

    /// 清空全部计数（热重载时调用）。
    pub fn clear(&self) {
        self.inner.clear();
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_limit_works() {
        let limiter = RateLimiter::new();
        for _ in 0..3 {
            assert!(limiter.allow("1.2.3.4", 3));
        }
        assert!(!limiter.allow("1.2.3.4", 3));
        // 不同 key 独立
        assert!(limiter.allow("5.6.7.8", 3));
        // 0 = 关闭
        assert!(limiter.allow("1.2.3.4", 0));
        // 清理
        limiter.clear();
        assert!(limiter.allow("1.2.3.4", 3));
    }

    #[test]
    fn check_exposes_reset_in() {
        let limiter = RateLimiter::new();
        let d = limiter.check("1.2.3.4", 1);
        assert!(d.allowed);
        assert!(d.reset_in > Duration::ZERO && d.reset_in <= Duration::from_secs(60));
        let d = limiter.check("1.2.3.4", 1);
        assert!(!d.allowed);
        assert!(d.reset_in > Duration::ZERO);
        let d = limiter.check("1.2.3.4", 0);
        assert!(d.allowed && d.count == 0 && d.reset_in.is_zero());
    }
}
