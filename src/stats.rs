//! WAF 运行统计：**只累加被拦请求**（放行路径几乎零开销），用于「当前是否正在被攻击」的判定。
//!
//! 设计约束（对齐「资源与带宽惯例」）：
//! - 全原子计数（`Relaxed`）：每次检查 1 次递增；被拦时再按原因 / IP 各 1 次，无锁竞争路径；
//! - **固定容量** Top 表（IP 16 个、原因 8 类）：不会随攻击流量膨胀内存，满了按最小计数替换；
//! - 分钟窗口只保留 **6 个桶**（近 6 分钟），`O(1)` 累加、`O(6)` 汇总；
//! - 快照 `WafStatsSnapshot` 由面板 / `-status` 读取，**不写盘、不发网络、不产生后台线程**。

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Top 表容量（来源 IP 数）。
const TOP_IP_CAPACITY: usize = 16;
/// Top 表容量（拦截原因分类数）。
const TOP_REASON_CAPACITY: usize = 8;
/// 分钟窗口桶数（近 6 分钟）。
const WINDOW_BUCKETS: usize = 6;

/// 拦截原因分类（用于聚合，不参与判定）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockKind {
    /// SQL 注入
    SqlInjection,
    /// XSS
    Xss,
    /// 路径穿越 / 敏感路径探测
    PathTraversal,
    /// 命令注入
    CommandInjection,
    /// 恶意爬虫 / 扫描器 UA
    Bot,
    /// IP 黑名单
    IpBlacklist,
    /// 自定义 UA / 空 UA / 自定义规则
    CustomRule,
    /// CSRF（跨站来源）
    Csrf,
    /// CC 限流（429）
    RateLimit,
}

impl BlockKind {
    /// 稳定标识（写日志 / 前端展示 / 聚合键）。
    pub fn as_str(self) -> &'static str {
        match self {
            BlockKind::SqlInjection => "sqli",
            BlockKind::Xss => "xss",
            BlockKind::PathTraversal => "path",
            BlockKind::CommandInjection => "cmd",
            BlockKind::Bot => "bot",
            BlockKind::IpBlacklist => "ip",
            BlockKind::CustomRule => "rule",
            BlockKind::Csrf => "csrf",
            BlockKind::RateLimit => "cc",
        }
    }

    /// 中文名。
    pub fn label(self) -> &'static str {
        match self {
            BlockKind::SqlInjection => "SQL 注入",
            BlockKind::Xss => "XSS",
            BlockKind::PathTraversal => "路径穿越",
            BlockKind::CommandInjection => "命令注入",
            BlockKind::Bot => "恶意爬虫/扫描器",
            BlockKind::IpBlacklist => "IP 黑名单",
            BlockKind::CustomRule => "自定义规则",
            BlockKind::Csrf => "跨站请求",
            BlockKind::RateLimit => "CC 限流",
        }
    }

    fn index(self) -> usize {
        match self {
            BlockKind::SqlInjection => 0,
            BlockKind::Xss => 1,
            BlockKind::PathTraversal => 2,
            BlockKind::CommandInjection => 3,
            BlockKind::Bot => 4,
            BlockKind::IpBlacklist => 5,
            BlockKind::CustomRule => 6,
            BlockKind::Csrf => 7,
            BlockKind::RateLimit => 8,
        }
    }
}

/// 分钟窗口桶。
#[derive(Clone, Default)]
struct Bucket {
    minute: u64,
    count: u64,
}

/// 固定容量 Top 表项。
#[derive(Clone, Default)]
struct TopItem {
    key: String,
    count: u64,
}

/// 运行统计（进程内、重置即清零）。
pub struct WafStats {
    /// 启动时刻（Unix 秒）
    since: u64,
    /// 经过 WAF 的请求数
    total: AtomicU64,
    /// 被拦请求数
    blocked: AtomicU64,
    /// 按原因分类
    by_kind: [AtomicU64; 9],
    /// 分钟窗口（近 6 分钟）
    window: Mutex<[Bucket; WINDOW_BUCKETS]>,
    /// Top 来源 IP
    top_ips: Mutex<Vec<TopItem>>,
}

impl Default for WafStats {
    fn default() -> Self {
        Self {
            since: now_secs(),
            total: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            by_kind: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
            window: Mutex::new(
                [const {
                    Bucket {
                        minute: 0,
                        count: 0,
                    }
                }; WINDOW_BUCKETS],
            ),
            top_ips: Mutex::new(Vec::with_capacity(TOP_IP_CAPACITY)),
        }
    }
}

impl WafStats {
    /// 新建。
    pub fn new() -> WafStats {
        WafStats::default()
    }

    /// 记录一次请求（放行也算；1 次原子递增）。
    #[inline]
    pub fn record_request(&self) {
        self.total.fetch_add(1, Ordering::Relaxed);
    }

    /// 记录一次拦截：总量 + 原因 + 分钟窗口 + Top IP。
    pub fn record_block(&self, kind: BlockKind, ip: &str) {
        self.blocked.fetch_add(1, Ordering::Relaxed);
        self.by_kind[kind.index()].fetch_add(1, Ordering::Relaxed);

        let minute = now_secs() / 60;
        {
            let mut window = lock(&self.window);
            // 找当前分钟桶；没有则用「最旧」的那个桶覆盖（环形）
            let mut target = 0usize;
            for (i, b) in window.iter().enumerate() {
                if b.minute == minute {
                    target = i;
                    break;
                }
                if b.minute < window[target].minute {
                    target = i;
                }
            }
            if window[target].minute != minute {
                window[target].minute = minute;
                window[target].count = 0;
            }
            window[target].count += 1;
        }

        if ip.is_empty() {
            return;
        }
        let mut top = lock(&self.top_ips);
        if let Some(item) = top.iter_mut().find(|i| i.key == ip) {
            item.count += 1;
            return;
        }
        if top.len() < TOP_IP_CAPACITY {
            top.push(TopItem {
                key: ip.to_string(),
                count: 1,
            });
            return;
        }
        // 满了：替换计数最小的（固定容量，内存不随攻击流量增长）
        if let Some(idx) = top
            .iter()
            .enumerate()
            .min_by_key(|(_, i)| i.count)
            .map(|(idx, _)| idx)
            && top[idx].count <= 1
        {
            top[idx].key = ip.to_string();
            top[idx].count = 1;
        }
    }

    /// 快照（面板 / `-status` 读取；只做一次原子读 + 两个短锁）。
    pub fn snapshot(&self) -> WafStatsSnapshot {
        let minute = now_secs() / 60;
        let (last_minute, last_5_minutes) = {
            let window = lock(&self.window);
            let one = window
                .iter()
                .filter(|b| b.minute == minute)
                .map(|b| b.count)
                .sum::<u64>();
            let five = window
                .iter()
                .filter(|b| b.minute + 5 >= minute && b.minute <= minute)
                .map(|b| b.count)
                .sum::<u64>();
            (one, five)
        };
        let mut by_reason: Vec<(String, String, u64)> = Vec::with_capacity(TOP_REASON_CAPACITY);
        for kind in [
            BlockKind::SqlInjection,
            BlockKind::Xss,
            BlockKind::PathTraversal,
            BlockKind::CommandInjection,
            BlockKind::Bot,
            BlockKind::IpBlacklist,
            BlockKind::CustomRule,
            BlockKind::Csrf,
            BlockKind::RateLimit,
        ] {
            let count = self.by_kind[kind.index()].load(Ordering::Relaxed);
            if count > 0 {
                by_reason.push((kind.as_str().to_string(), kind.label().to_string(), count));
            }
        }
        by_reason.sort_by_key(|item| std::cmp::Reverse(item.2));
        by_reason.truncate(TOP_REASON_CAPACITY);

        let mut top_ips: Vec<(String, u64)> = lock(&self.top_ips)
            .iter()
            .filter(|i| !i.key.is_empty())
            .map(|i| (i.key.clone(), i.count))
            .collect();
        top_ips.sort_by_key(|item| std::cmp::Reverse(item.1));
        top_ips.truncate(TOP_IP_CAPACITY);

        let total = self.total.load(Ordering::Relaxed);
        let blocked = self.blocked.load(Ordering::Relaxed);
        WafStatsSnapshot {
            since: self.since,
            uptime_seconds: now_secs().saturating_sub(self.since),
            total,
            blocked,
            blocked_ratio: if total == 0 {
                0.0
            } else {
                blocked as f64 / total as f64
            },
            last_minute,
            last_5_minutes,
            by_reason,
            top_ips,
        }
    }
}

/// 统计快照。
#[derive(Clone, Debug, Default)]
pub struct WafStatsSnapshot {
    /// 启动时刻（Unix 秒）
    pub since: u64,
    /// 已运行秒数
    pub uptime_seconds: u64,
    /// 经过 WAF 的请求数
    pub total: u64,
    /// 被拦请求数
    pub blocked: u64,
    /// 拦截率（0.0~1.0）
    pub blocked_ratio: f64,
    /// 最近 1 分钟拦截数
    pub last_minute: u64,
    /// 最近 5 分钟拦截数
    pub last_5_minutes: u64,
    /// 按原因（`(code, label, count)`，按次数降序，最多 8 项）
    pub by_reason: Vec<(String, String, u64)>,
    /// Top 来源 IP（按次数降序，最多 16 项）
    pub top_ips: Vec<(String, u64)>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match m.lock() {
        Ok(v) => v,
        Err(e) => e.into_inner(),
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_requests_blocks_and_reasons() {
        let stats = WafStats::new();
        for _ in 0..10 {
            stats.record_request();
        }
        stats.record_block(BlockKind::Bot, "1.1.1.1");
        stats.record_block(BlockKind::Bot, "1.1.1.1");
        stats.record_block(BlockKind::SqlInjection, "2.2.2.2");

        let s = stats.snapshot();
        assert_eq!(s.total, 10);
        assert_eq!(s.blocked, 3);
        assert!((s.blocked_ratio - 0.3).abs() < 1e-9);
        assert_eq!(s.last_minute, 3, "同一分钟窗口内应累计");
        assert_eq!(s.last_5_minutes, 3);
        assert_eq!(s.by_reason[0].0, "bot", "按次数降序：{s:?}");
        assert_eq!(s.by_reason[0].2, 2);
        assert_eq!(s.top_ips[0], ("1.1.1.1".to_string(), 2));
    }

    #[test]
    fn top_ips_is_fixed_capacity() {
        let stats = WafStats::new();
        for i in 0..200 {
            stats.record_block(BlockKind::Bot, &format!("10.0.0.{i}"));
        }
        let s = stats.snapshot();
        assert!(s.top_ips.len() <= TOP_IP_CAPACITY, "Top 表必须有上限");
        assert_eq!(s.blocked, 200, "总量仍然准确");
    }

    #[test]
    fn empty_ip_is_not_tracked() {
        let stats = WafStats::new();
        stats.record_block(BlockKind::Csrf, "");
        let s = stats.snapshot();
        assert_eq!(s.blocked, 1);
        assert!(s.top_ips.is_empty());
    }

    #[test]
    fn zero_requests_does_not_divide_by_zero() {
        let s = WafStats::new().snapshot();
        assert_eq!(s.total, 0);
        assert_eq!(s.blocked_ratio, 0.0);
    }
}
