//! CC（Challenge Collapsar）限速：固定 60 秒窗口的每 IP 请求计数。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// 固定窗口限速器（每 key 每分钟 N 次；0 = 关闭由调用方判断）。
pub struct RateLimiter {
    inner: Mutex<HashMap<String, (i64, u32)>>,
}

impl RateLimiter {
    /// 新建空限速器。
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// 记一次请求；超限返回 `false`。
    pub fn allow(&self, key: &str, per_minute: u32) -> bool {
        if per_minute == 0 {
            return true;
        }
        let window = now_secs() / 60;
        let mut map = match self.inner.lock() {
            Ok(m) => m,
            Err(poisoned) => poisoned.into_inner(),
        };
        // 防泄漏：键过多时清理过期窗口
        if map.len() > 4096 {
            map.retain(|_, (w, _)| *w == window);
        }
        match map.get_mut(key) {
            Some((w, count)) => {
                if *w != window {
                    *w = window;
                    *count = 1;
                    true
                } else {
                    *count += 1;
                    *count <= per_minute
                }
            }
            None => {
                map.insert(key.to_string(), (window, 1));
                true
            }
        }
    }

    /// 清空全部计数（热重载时调用）。
    pub fn clear(&self) {
        if let Ok(mut m) = self.inner.lock() {
            m.clear();
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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
