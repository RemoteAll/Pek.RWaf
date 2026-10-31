//! Pek.RWaf（Rust 版 Web 防火墙）：**对齐 C# `Pek.WAF`（规则引擎 + IP 名单 + UA 过滤 + 频率监控 + 日志），
//! 并按用户需求扩展**：
//!
//! - **爬虫分级管理**（[`bots`]）：放行正常搜索引擎蜘蛛（Googlebot/Baiduspider/Bingbot…）与
//!   **GEO 正常抓取**（GPTBot/ClaudeBot/PerplexityBot 等官方 AI 抓取器，供站点被生成式引擎引用），
//!   拦截恶意爬虫/扫描器（MJ12bot/SemrushBot/curl/python-requests/sqlmap…）；管理区可全禁 bot；
//! - **SQL 注入防护**（[`attack`]）：对路径/查询串/表单体做 URL 解码后特征检测（union select、`or 1=1`、
//!   sleep()/benchmark()、information_schema、xp_cmdshell 等）；与「数据访问统一走 Pek.RCode 参数化 ORM」
//!   形成纵深防御（外围 WAF + 内层 ORM）；
//! - **CC 防护**（[`ratelimit`]）：按 IP 固定窗口限速（搜索引擎/GEO 白名单如常爬行不受限）；
//! - **接口级限流**（[`throttle`]）：对齐 C# `DH.RateLimter`——按「方法 + 路径」声明规则，
//!   支持 IP/用户/Header/Query/Path/Cookie/Form 七种策略、多阀门优先级、`WhenNull`、
//!   429 多种返回格式；计数引擎下沉 [`dhrust::ratelimit`]（可替换 Redis 共享计数）；
//! - **自定义规则**（[`rules`]）：JSON 规则集，**与 C# Pek.WAF 的 Ruleset 格式兼容**（同一份规则文件可双端共用），
//!   在 C# 操作符全集之上新增 `IsBotKind`（按爬虫分类命中）；
//! - **dhrust 接入**（[`middleware`]）：`router.use_middleware(waf.middleware())` 一行接入洋葱链；
//!   配置 `Config/Waf.toml` 首启自动生成、改动热重载（mtime 节流检查）；回环地址默认豁免。
//!
//! ## 快速接入（dhrust 服务）
//!
//! ```no_run
//! # use std::sync::Arc;
//! use dhrust::net::router::Router;
//! use pek_rwaf::{Waf, WafConfig};
//!
//! let waf = Waf::new(WafConfig::admin_api());     // 或 WafConfig::public_site() / Waf::load(dir)
//! let mut router = Router::new();
//! router.use_middleware(waf.middleware());        // WAF 放最外层：最先检查请求、最后观察响应
//! ```

pub mod attack;
pub mod bots;
pub mod config;
pub mod middleware;
pub mod ratelimit;
pub mod rules;
pub mod stats;
pub mod throttle;
pub mod wafreq;

pub use config::{WafConfig, WafMode};
pub use middleware::{Verdict, Waf};
pub use stats::{BlockKind, WafStats, WafStatsSnapshot};
pub use throttle::{RateValve, Throttle, ThrottleConfig, ThrottleRule, ThrottleVerdict, WhenNull};
pub use wafreq::WafRequest;
