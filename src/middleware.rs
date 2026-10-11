//! WAF 核心：`Waf` 门面（决策链）、dhrust 中间件装配、`Config/Waf.json` 热重载。
//!
//! 检查顺序（首个命中短路）：
//! 1. 总开关 → 回环豁免 → IP 黑名单 → IP 白名单
//! 2. 自定义拦截 UA → 空 UA → 爬虫分类（恶意拦 / 敏感前缀全禁机器人 / 放行类豁免限速）
//! 3. 攻击特征（SQL 注入 / 路径探测 / 命令注入 / XSS——按各自动作，敏感前缀下 Monitor 升级为 Block）
//! 4. 自定义规则集（命中即拦）
//! 5. CC 限速（每 IP 每分钟；放行类机器人豁免；静态资源不计数）
//!
//! 接入方式（dhrust Router）：
//! ```ignore
//! let waf = pek_rwaf::Waf::load(&base);          // 读 {base}/Config/Waf.json（首启生成）
//! router.use_middleware(waf.middleware());        // 首行注册，全部路由生效
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use dhrust::net::http::{HttpOutcome, HttpResponse};
use dhrust::net::router::{Middleware, middleware};

use crate::attack::{self, AttackKind};
use crate::bots::{self, BotKind};
use crate::config::{Action, WafConfig};
use crate::ratelimit::RateLimiter;
use crate::rules::{self, Compiled};
use crate::wafreq::{WafRequest, ip_in_list};

/// 热重载检查间隔（毫秒）。
const RELOAD_CHECK_INTERVAL_MS: i64 = 10_000;

/// 静态资源扩展名（CC 限速不计数）。
const STATIC_EXTS: &[&str] = &[
    "js", "css", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "avif", "bmp", "woff", "woff2",
    "ttf", "otf", "eot", "map", "mp4", "webm", "mp3", "ogg",
];

/// 判定结果。
#[derive(Debug, Clone)]
pub enum Verdict {
    /// 放行
    Allow,
    /// 拦截（`status`：403 常规拦截 / 429 限速）
    Blocked {
        /// HTTP 状态码
        status: u16,
        /// 原因（日志/测试用；响应体不含细节）
        reason: String,
    },
}

impl Verdict {
    /// 是否放行。
    pub fn is_allow(&self) -> bool {
        matches!(self, Verdict::Allow)
    }

    /// 拦截时的状态码。
    pub fn blocked_status(&self) -> Option<u16> {
        match self {
            Verdict::Allow => None,
            Verdict::Blocked { status, .. } => Some(*status),
        }
    }

    /// 拦截原因。
    pub fn reason(&self) -> Option<&str> {
        match self {
            Verdict::Allow => None,
            Verdict::Blocked { reason, .. } => Some(reason),
        }
    }
}

/// WAF 门面（线程安全；内部缓存规则编译结果与限速计数）。
pub struct Waf {
    config: RwLock<WafConfig>,
    compiled_rules: RwLock<Vec<Compiled>>,
    limiter: RateLimiter,
    file: Option<PathBuf>,
    base_dir: PathBuf,
    last_check: AtomicI64,
    last_mtime: AtomicU64,
}

impl Waf {
    /// 以内存配置构建（无文件热重载）。
    pub fn new(config: WafConfig) -> Arc<Self> {
        let waf = Self {
            config: RwLock::new(config),
            compiled_rules: RwLock::new(Vec::new()),
            limiter: RateLimiter::new(),
            file: None,
            base_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            last_check: AtomicI64::new(0),
            last_mtime: AtomicU64::new(0),
        };
        waf.recompile();
        Arc::new(waf)
    }

    /// 从项目基础目录加载（`{base}/Config/Waf.json`；文件不存在时自动生成默认模板）。
    pub fn load(base: &Path) -> Arc<Self> {
        Self::load_with_default(base, WafConfig::default())
    }

    /// 同 [`Waf::load`]，但首启生成的模板使用指定预设（如前台站点用 [`WafConfig::public_site`]）。
    pub fn load_with_default(base: &Path, default: WafConfig) -> Arc<Self> {
        let file = base.join("Config").join("Waf.json");
        let config = if !file.exists() {
            let _ = default.save(&file);
            default
        } else {
            match WafConfig::load_or_create(&file) {
                Ok(c) => c,
                Err(e) => {
                    dhrust::logs::log().warn(&format!("[WAF] 配置加载失败，使用默认策略：{e}"));
                    default
                }
            }
        };
        let waf = Self {
            config: RwLock::new(config),
            compiled_rules: RwLock::new(Vec::new()),
            limiter: RateLimiter::new(),
            file: Some(file),
            base_dir: base.to_path_buf(),
            last_check: AtomicI64::new(0),
            last_mtime: AtomicU64::new(0),
        };
        waf.recompile();
        Arc::new(waf)
    }

    /// 当前配置副本（面板展示用）。
    pub fn config(&self) -> WafConfig {
        match self.config.read() {
            Ok(c) => c.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// 手动重载配置与规则（校验失败保留旧配置）。
    pub fn reload(&self) {
        let Some(file) = self.file.clone() else {
            return;
        };
        // 文件被删除：以当前内存配置重建（预设可能为 public_site 等非库默认，不能落回 admin_api）
        if !file.exists() {
            let current = self.config();
            let _ = current.save(&file);
            return;
        }
        match WafConfig::load_or_create(&file) {
            Ok(cfg) => {
                match self.config.write() {
                    Ok(mut w) => *w = cfg,
                    Err(p) => *p.into_inner() = cfg,
                }
                self.recompile();
                self.limiter.clear();
                if let Ok(meta) = std::fs::metadata(&file)
                    && let Ok(t) = meta.modified()
                    && let Ok(d) = t.duration_since(std::time::UNIX_EPOCH)
                {
                    self.last_mtime.store(d.as_millis() as u64, Ordering::Relaxed);
                }
            }
            Err(e) => {
                dhrust::logs::log().warn(&format!("[WAF] 配置热重载失败（保留旧配置）：{e}"));
            }
        }
    }

    fn recompile(&self) {
        let ruleset = match self.config.read() {
            Ok(c) => c.ruleset.clone(),
            Err(p) => p.into_inner().ruleset.clone(),
        };
        let compiled: Vec<Compiled> = match &ruleset {
            Some(rule) => match rules::compile(rule, &self.base_dir) {
                Ok(c) => vec![c],
                Err(e) => {
                    dhrust::logs::log().warn(&format!("[WAF] {e}"));
                    Vec::new()
                }
            },
            None => Vec::new(),
        };
        match self.compiled_rules.write() {
            Ok(mut w) => *w = compiled,
            Err(p) => *p.into_inner() = compiled,
        }
    }

    fn maybe_reload(&self) {
        let Some(file) = &self.file else {
            return;
        };
        let now = now_ms();
        let last = self.last_check.load(Ordering::Relaxed);
        if now - last < RELOAD_CHECK_INTERVAL_MS {
            return;
        }
        // 单飞：CAS 成功者执行检查
        if self
            .last_check
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let Ok(meta) = std::fs::metadata(file) else {
            // 文件被删除：经 reload 以当前配置重建（保持项目预设）
            self.reload();
            return;
        };
        let Ok(t) = meta.modified() else { return };
        let Ok(d) = t.duration_since(std::time::UNIX_EPOCH) else {
            return;
        };
        let mtime = d.as_millis() as u64;
        if mtime == self.last_mtime.load(Ordering::Relaxed) {
            return;
        }
        self.reload();
    }

    /// 对原始 HTTP 请求执行检查（中间件入口）。
    pub fn check_http(&self, req: &dhrust::net::http::HttpRequest) -> Verdict {
        let wreq = WafRequest::from_http(req);
        self.check(&wreq)
    }

    /// 对规范化请求执行检查。
    pub fn check(&self, req: &WafRequest) -> Verdict {
        // 先做（10s 节流的）配置热重载检查——被拦截的请求也参与，保证改配置后及时生效
        self.maybe_reload();
        let cfg = match self.config.read() {
            Ok(c) => c,
            Err(p) => p.into_inner(),
        };
        if !cfg.enable {
            return Verdict::Allow;
        }
        let ip = req.remote_ip.trim();

        // —— 回环豁免（保护本地工具/冒烟脚本）——
        if cfg.loopback_bypass && is_loopback(ip) {
            return Verdict::Allow;
        }
        // —— IP 白名单（显式信任，优先于黑名单与全部检查）→ IP 黑名单 ——
        if !cfg.ip_whitelist.is_empty() && ip_in_list(ip, &cfg.ip_whitelist.join(",")) {
            return Verdict::Allow;
        }
        if !cfg.ip_blacklist.is_empty() && ip_in_list(ip, &cfg.ip_blacklist.join(",")) {
            return self.blocked(&cfg, 403, format!("IP 黑名单：{ip}"), req);
        }

        let ua_lower = req.user_agent.trim().to_ascii_lowercase();

        // —— 自定义 UA 规则 ——
        if !cfg.extra_block_bots.is_empty()
            && cfg.extra_block_bots.iter().any(|k| ua_lower.contains(&k.to_ascii_lowercase()))
        {
            return self.blocked(&cfg, 403, "自定义拦截 UA".to_string(), req);
        }
        if cfg.block_empty_ua && ua_lower.is_empty() {
            return self.blocked(&cfg, 403, "空 User-Agent".to_string(), req);
        }

        let extra_allowed = !cfg.extra_allow_bots.is_empty()
            && cfg.extra_allow_bots.iter().any(|k| ua_lower.contains(&k.to_ascii_lowercase()));
        let sensitive = !cfg.sensitive_prefixes.is_empty()
            && cfg.sensitive_prefixes.iter().any(|p| req.path.starts_with(p.as_str()));

        // —— 爬虫分类 ——
        let mut friendly_bot = false;
        if !extra_allowed
            && let Some(kind) = bots::classify(&req.user_agent)
        {
            match kind {
                BotKind::Malicious => {
                    if cfg.block_malicious_bots {
                        return self.blocked(
                            &cfg,
                            403,
                            format!("恶意爬虫/扫描器：{}", brief(&req.user_agent)),
                            req,
                        );
                    }
                }
                BotKind::SearchEngine | BotKind::AiCrawler | BotKind::SocialPreview => {
                    if sensitive {
                        return self.blocked(
                            &cfg,
                            403,
                            format!("敏感路径禁止机器人（{}）", kind.name_cn()),
                            req,
                        );
                    }
                    let allowed = match kind {
                        BotKind::SearchEngine => cfg.allow_search_bots,
                        BotKind::AiCrawler => cfg.allow_ai_bots,
                        _ => cfg.allow_social_previews,
                    };
                    if allowed {
                        friendly_bot = true;
                        if cfg.verbose {
                            dhrust::logs::log().info(&format!(
                                "[WAF] 放行 {}：{} {}（{}）",
                                kind.name_cn(),
                                req.method,
                                req.path,
                                brief(&req.user_agent)
                            ));
                        }
                    } else {
                        return self.blocked(
                            &cfg,
                            403,
                            format!("未放行的机器人：{}", kind.name_cn()),
                            req,
                        );
                    }
                }
                BotKind::Monitor | BotKind::Unknown => {
                    if sensitive {
                        return self.blocked(
                            &cfg,
                            403,
                            format!("敏感路径禁止机器人（{}）", kind.name_cn()),
                            req,
                        );
                    }
                    if cfg.verbose {
                        dhrust::logs::log().info(&format!(
                            "[WAF] {}：{} {}（{}）",
                            kind.name_cn(),
                            req.method,
                            req.path,
                            brief(&req.user_agent)
                        ));
                    }
                }
            }
        }

        // —— 攻击特征（skipAttackPrefixes 下的管理端点跳过——如在线 SQL/文件管理，由业务层护栏负责）——
        let skip_attack = !cfg.skip_attack_prefixes.is_empty()
            && cfg.skip_attack_prefixes.iter().any(|p| req.path.starts_with(p.as_str()));
        if !skip_attack {
            for kind in attack::scan_all(&req.path, &req.query, &req.body_text) {
                let mut action = match kind {
                    AttackKind::SqlInjection => cfg.sqli_action,
                    AttackKind::Xss => cfg.xss_action,
                    AttackKind::PathTraversal => cfg.path_action,
                    AttackKind::CommandInjection => cfg.cmd_action,
                };
                if sensitive && action == Action::Monitor {
                    action = Action::Block; // 敏感前缀下 Monitor 升级
                }
                match action {
                    Action::Off => {}
                    Action::Monitor => {
                        if cfg.verbose {
                            dhrust::logs::log().info(&format!(
                                "[WAF] 监控命中 {}：{} {}",
                                kind.name_cn(),
                                req.method,
                                req.path
                            ));
                        }
                    }
                    Action::Block => {
                        return self.blocked(
                            &cfg,
                            403,
                            format!("{} 特征：{}", kind.name_cn(), brief(&req.path)),
                            req,
                        );
                    }
                }
            }
        }

        // —— 自定义规则集（命中即拦）——
        {
            let rules = match self.compiled_rules.read() {
                Ok(r) => r,
                Err(p) => p.into_inner(),
            };
            for rule in rules.iter() {
                if rules::eval(rule, req) {
                    return self.blocked(&cfg, 403, format!("自定义规则：{}", rule.label()), req);
                }
            }
        }

        // —— CC 限速（放行类机器人豁免；静态资源不计数）——
        if cfg.rate_limit_per_min > 0
            && !friendly_bot
            && !is_static_asset(&req.path)
            && !self.limiter.allow(ip, cfg.rate_limit_per_min)
        {
            return self.blocked(
                &cfg,
                429,
                format!("请求频率超限（{} 次/分钟）", cfg.rate_limit_per_min),
                req,
            );
        }

        Verdict::Allow
    }

    fn blocked(&self, cfg: &WafConfig, status: u16, reason: String, req: &WafRequest) -> Verdict {
        if cfg.log_blocked {
            dhrust::logs::log().warn(&format!(
                "[WAF] 拦截 {} {} 状态={} IP={} UA={} 原因={}",
                req.method,
                req.path,
                status,
                req.remote_ip,
                brief(&req.user_agent),
                reason
            ));
        }
        Verdict::Blocked { status, reason }
    }

    /// 生成 dhrust 中间件（`router.use_middleware(waf.middleware())`）。
    pub fn middleware(self: &Arc<Self>) -> Middleware {
        let waf = Arc::clone(self);
        middleware(move |ctx, next| {
            let waf = Arc::clone(&waf);
            async move {
                match waf.check_http(&ctx.req) {
                    Verdict::Allow => next(ctx).await,
                    Verdict::Blocked { status, .. } => {
                        let body = if status == 429 {
                            "请求过于频繁，请稍后再试"
                        } else {
                            "请求被安全策略拦截"
                        };
                        let mut resp = HttpResponse::text(status, body)
                            .with_header("X-WAF-Blocked", "1")
                            .with_header("Cache-Control", "no-store");
                        if status == 429 {
                            resp = resp.with_header("Retry-After", "60");
                        }
                        HttpOutcome::Response(resp)
                    }
                }
            }
        })
    }
}

/// 是否回环地址。
pub fn is_loopback(ip: &str) -> bool {
    let ip = ip.trim();
    ip == "::1"
        || ip == "0:0:0:0:0:0:0:1"
        || ip.eq_ignore_ascii_case("localhost")
        || ip.starts_with("127.")
}

/// 是否静态资源（限速跳过）。
fn is_static_asset(path: &str) -> bool {
    let p = path.split(['?', '#']).next().unwrap_or(path);
    let last = p.rsplit('/').next().unwrap_or("");
    match last.rsplit_once('.') {
        Some((_, ext)) => STATIC_EXTS.contains(&ext.to_ascii_lowercase().as_str()),
        None => false,
    }
}

fn brief(s: &str) -> String {
    let t: String = s.chars().take(80).collect();
    if s.chars().count() > 80 { format!("{t}…") } else { t }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wreq(path: &str) -> WafRequest {
        WafRequest {
            path: path.to_string(),
            method: "GET".to_string(),
            query: String::new(),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0".to_string(),
            remote_ip: "8.8.8.8".to_string(),
            content_type: String::new(),
            body_text: String::new(),
        }
    }

    #[test]
    fn public_site_allows_friendly_and_blocks_malicious() {
        let waf = Waf::new(WafConfig::public_site());
        // 正常浏览器
        assert!(waf.check(&wreq("/")).is_allow());
        // 搜索引擎 / GEO-AI / 社交预览放行
        let mut r = wreq("/cards");
        r.user_agent = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)".into();
        assert!(waf.check(&r).is_allow());
        r.user_agent = "Mozilla/5.0 AppleWebKit/537.36; compatible; GPTBot/1.2; +https://openai.com/gptbot".into();
        assert!(waf.check(&r).is_allow());
        r.user_agent = "ClaudeBot/1.0".into();
        assert!(waf.check(&r).is_allow());
        r.user_agent = "facebookexternalhit/1.1".into();
        assert!(waf.check(&r).is_allow());
        // 恶意爬虫/扫描器拦截
        r.user_agent = "Mozilla/5.0 (compatible; MJ12bot/v1.4.8)".into();
        assert_eq!(waf.check(&r).blocked_status(), Some(403));
        r.user_agent = "sqlmap/1.7".into();
        assert_eq!(waf.check(&r).blocked_status(), Some(403));
        // 正常移动端/App Dart UA 不误伤
        r.user_agent = "Dart/3.11 (dart:io)".into();
        assert!(waf.check(&r).is_allow());
    }

    #[test]
    fn sensitive_prefix_blocks_all_bots() {
        let waf = Waf::new(WafConfig::public_site());
        let mut r = wreq("/admin/");
        r.user_agent = "Mozilla/5.0 (compatible; Googlebot/2.1)".into();
        assert_eq!(waf.check(&r).blocked_status(), Some(403), "敏感路径禁止搜索引擎");
        r.user_agent = "SomeRandomBot/0.1".into();
        assert_eq!(waf.check(&r).blocked_status(), Some(403), "敏感路径禁止未知 bot");
        // 普通浏览器可访问管理页（登录保护由业务层负责）
        r.user_agent = "Mozilla/5.0 Chrome/126.0".into();
        assert!(waf.check(&r).is_allow());
    }

    #[test]
    fn attack_detection_and_sensitive_upgrade() {
        let waf = Waf::new(WafConfig::public_site());
        let mut r = wreq("/api/cards");
        r.query = "q=1' or 1=1--".into();
        assert_eq!(waf.check(&r).blocked_status(), Some(403), "SQL 注入拦截");
        // 路径探测
        let r = wreq("/wp-login.php");
        assert_eq!(waf.check(&r).blocked_status(), Some(403), "敏感路径探测拦截");
        // XSS 默认仅记录（放行）
        let mut r = wreq("/search");
        r.query = "q=<script>alert(1)</script>".into();
        assert!(waf.check(&r).is_allow(), "XSS 默认 monitor");
        // 敏感前缀下 Monitor → Block
        let mut r = wreq("/admin/x");
        r.query = "q=<script>alert(1)</script>".into();
        assert_eq!(waf.check(&r).blocked_status(), Some(403), "敏感前缀 XSS 升级拦截");
        // 正常中文搜索不误报
        let mut r = wreq("/cards");
        r.query = "q=%E6%8B%9B%E5%95%86%E9%93%B6%E8%A1%8C&page=1".into();
        assert!(waf.check(&r).is_allow());
    }

    #[test]
    fn admin_api_strictness_and_loopback_bypass() {
        let waf = Waf::new(WafConfig::admin_api());
        // 空 UA 默认放行（服务器间调用常无 UA，如 .NET HttpClient / dhrust 本客户端）；显式开启后拦截
        let mut r = wreq("/api/status");
        r.user_agent = String::new();
        assert!(waf.check(&r).is_allow(), "空 UA 默认放行");
        let mut strict = WafConfig::admin_api();
        strict.block_empty_ua = true;
        let waf_strict = Waf::new(strict);
        assert_eq!(waf_strict.check(&r).blocked_status(), Some(403), "开启后空 UA 拦截");
        // 搜索引擎也拦（管理端不放行 bot）
        let mut r = wreq("/api/status");
        r.user_agent = "Googlebot/2.1".into();
        assert_eq!(waf.check(&r).blocked_status(), Some(403));
        // 回环豁免（本地工具/冒烟）
        let mut r = wreq("/api/status");
        r.user_agent = "curl/8.4.0".into();
        r.remote_ip = "127.0.0.1".into();
        assert!(waf.check(&r).is_allow(), "回环豁免");
        // 非回环同样 UA 拦截
        r.remote_ip = "8.8.8.8".into();
        assert_eq!(waf.check(&r).blocked_status(), Some(403));
    }

    #[test]
    fn rate_limit_and_static_skip() {
        let mut cfg = WafConfig::admin_api();
        cfg.rate_limit_per_min = 3;
        let waf = Waf::new(cfg);
        // 静态资源不计数
        for _ in 0..5 {
            assert!(waf.check(&wreq("/assets/app.js")).is_allow());
        }
        // API 正常计数：3 次放行，第 4 次 429
        assert!(waf.check(&wreq("/api/a")).is_allow());
        assert!(waf.check(&wreq("/api/a")).is_allow());
        assert!(waf.check(&wreq("/api/a")).is_allow());
        assert_eq!(waf.check(&wreq("/api/a")).blocked_status(), Some(429));
        // 放行类机器人豁免（前台模式下 Googlebot 不限速）
        let mut cfg = WafConfig::public_site();
        cfg.rate_limit_per_min = 2;
        let waf = Waf::new(cfg);
        for _ in 0..10 {
            let mut r = wreq("/cards");
            r.user_agent = "Googlebot/2.1".into();
            assert!(waf.check(&r).is_allow(), "搜索引擎豁免限速");
        }
    }

    #[test]
    fn ip_lists_and_config_reload() {
        let dir = std::env::temp_dir().join(format!("pek-waf-mw-{}", std::process::id()));
        let file = dir.join("Config").join("Waf.json");
        {
            let mut cfg = WafConfig::public_site();
            cfg.ip_blacklist = vec!["8.8.8.0/24".to_string()];
            cfg.save(&file).unwrap();
        }
        let waf = Waf::load(&dir);
        // 黑名单 IP 拦截
        assert_eq!(waf.check(&wreq("/")).blocked_status(), Some(403));
        // 白名单（重新写配置 + 手动 reload）
        {
            let mut cfg = WafConfig::public_site();
            cfg.ip_blacklist = vec!["8.8.8.0/24".to_string()];
            cfg.ip_whitelist = vec!["8.8.8.8".to_string()];
            cfg.save(&file).unwrap();
        }
        waf.reload();
        assert!(waf.check(&wreq("/")).is_allow(), "白名单优先放行");
        // 黑名单内的其它 IP 仍拦
        let mut r = wreq("/");
        r.remote_ip = "8.8.8.9".into();
        assert_eq!(waf.check(&r).blocked_status(), Some(403));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn skip_attack_prefixes_for_admin_endpoints() {
        let mut cfg = WafConfig::admin_api();
        cfg.skip_attack_prefixes = vec!["/api/db".to_string()];
        let waf = Waf::new(cfg);
        // 普通路径：SQL 特征拦截
        let mut r = wreq("/api/cards");
        r.query = "q=1' or 1=1--".into();
        assert_eq!(waf.check(&r).blocked_status(), Some(403));
        // 管理端点：跳过攻击检测（只读 SQL 护栏由业务层负责）
        let mut r = wreq("/api/dbQuery");
        r.query = "x=select * from t".into();
        assert!(waf.check(&r).is_allow(), "skip 前缀跳过攻击检测");
        // URL 层扫描不受影响：非 skip 前缀的路径探测照拦
        let r2 = wreq("/.env");
        assert_eq!(waf.check(&r2).blocked_status(), Some(403));
    }

    #[test]
    fn reload_recreates_missing_file_with_current_preset() {
        let dir = std::env::temp_dir().join(format!("pek-waf-reload-{}", std::process::id()));
        let file = dir.join("Config").join("Waf.json");
        let waf = Waf::load_with_default(&dir, WafConfig::public_site());
        assert_eq!(waf.config().mode, crate::config::WafMode::PublicSite);
        std::fs::remove_file(&file).unwrap();
        waf.reload();
        assert!(file.exists(), "文件被删除后应重建");
        assert_eq!(
            waf.config().mode,
            crate::config::WafMode::PublicSite,
            "重建应保持前台预设而非库默认（admin_api）"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn custom_ruleset_blocks() {
        let mut cfg = WafConfig::admin_api();
        cfg.ruleset = Some(serde_json::from_str(r#"{
            "Operator": "OrElse",
            "Rules": [
                { "MemberName": "Path", "Operator": "EndsWith", "Inputs": [".php"] },
                { "MemberName": "UserAgent", "Operator": "IsBotKind", "TargetValue": "Malicious" }
            ]
        }"#).unwrap());
        let waf = Waf::new(cfg);
        assert_eq!(waf.check(&wreq("/x.php")).blocked_status(), Some(403));
        let mut r = wreq("/api/x");
        r.user_agent = "scrapy/2.11".into();
        // scrapy 属灰色（Monitor）不命中 Malicious 规则——但走攻击/其它检查仍放行
        assert!(waf.check(&r).is_allow());
        let mut r = wreq("/api/x");
        r.user_agent = "Nikto/2.5.0".into();
        // 已被恶意名单直接拦（先于规则）
        assert_eq!(waf.check(&r).blocked_status(), Some(403));
    }
}
