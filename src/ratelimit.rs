//! CC（Challenge Collapsar）限速：固定 60 秒窗口的每 IP 请求计数。
//!
//! 计数引擎已下沉 [`dhrust::ratelimit`]（与接口级限流 [`crate::throttle`] 共用）；
//! 本模块只保留 WAF 的 CC 语义：每个 IP 每分钟固定上限，超限返回 429。

use std::time::Duration;

use dhrust::ratelimit::WindowLimiter;

/// 固定窗口限速器（每 key 每分钟 N 次；0 = 关闭由调用方判断）。
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

    /// 记一次请求；超限返回 `false`。
    pub fn allow(&self, key: &str, per_minute: u32) -> bool {
        if per_minute == 0 {
            return true;
        }
        self.inner
            .hit(key, u64::from(per_minute), Duration::from_secs(60))
            .allowed
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
}
