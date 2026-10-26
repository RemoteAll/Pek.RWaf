//! WAF 核心：`Waf` 门面（决策链）、dhrust 中间件装配、`Config/Waf.toml` 热重载。
//!
//! 检查顺序（首个命中短路）：
//! 1. 总开关 → 回环豁免 → IP 黑名单 → IP 白名单
//! 2. 自定义拦截 UA → 空 UA → 爬虫分类（恶意拦 / 敏感前缀全禁机器人 / 放行类豁免限速）
//! 3. 攻击特征（SQL 注入 / 路径探测 / 命令注入 / XSS——按各自动作，敏感前缀下 Monitor 升级为 Block）
//! 4. 自定义规则集（命中即拦）
//! 5. CC 限速（每 IP 首次命中起 60 秒窗口；放行类机器人豁免；静态资源不计数）
//!
//! 接入方式（dhrust Router）：
//! ```ignore
//! let waf = pek_rwaf::Waf::load(&base);          // 读 {base}/Config/Waf.toml（首启生成）
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
    /// 可信业务请求签名密钥（DHDeploy 的 TimeStamp/Nonce/Signature 头；只存内存，
    /// 不落 Config/Waf.toml，面板保存配置不会把它清掉）
    trusted_secret: RwLock<Option<String>>,
    /// 强制跳过机器人拦截的路径前缀（内存态：不落配置文件、面板保存也不会清掉）
    forced_skip_bot: RwLock<Vec<String>>,
    /// 强制跳过攻击特征检测的路径前缀（同上）
    forced_skip_attack: RwLock<Vec<String>>,
    /// 是否在「直连对端是回环」时采纳 `X-Forwarded-For`（反向代理后取真实 IP；
    /// 内存态——与项目自己的 `client_ip` 口径保持一致，避免 WAF 看到的全是 127.0.0.1）
    trust_forwarded_for: RwLock<bool>,
    file: Option<PathBuf>,
    /// 创建时的预设配置（部分键缺失的旧文件/面板提交用其补齐）
    preset: WafConfig,
    base_dir: PathBuf,
    last_check: AtomicI64,
    last_mtime: AtomicU64,
    /// 运行统计（只累加被拦 + 请求总数；原子计数，几乎零开销）
    stats: crate::stats::WafStats,
    /// 拦截日志去重（同 IP + 同原因 1 秒内只记一条）：防攻击洪峰把日志 IO 放大
    log_throttle: LogThrottle,
}

impl Waf {
    /// 以内存配置构建（无文件热重载）。
    pub fn new(config: WafConfig) -> Arc<Self> {
        let waf = Self {
            config: RwLock::new(config.clone()),
            compiled_rules: RwLock::new(Vec::new()),
            limiter: RateLimiter::new(),
            trusted_secret: RwLock::new(None),
            forced_skip_bot: RwLock::new(Vec::new()),
            forced_skip_attack: RwLock::new(Vec::new()),
            trust_forwarded_for: RwLock::new(false),
            file: None,
            preset: config,
            base_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            last_check: AtomicI64::new(0),
            last_mtime: AtomicU64::new(0),
            stats: crate::stats::WafStats::new(),
            log_throttle: LogThrottle::new(),
        };
        waf.recompile();
        Arc::new(waf)
    }

    /// 从项目基础目录加载（`{base}/Config/Waf.toml`；文件不存在时自动生成默认模板）。
    pub fn load(base: &Path) -> Arc<Self> {
        Self::load_with_default(base, WafConfig::default())
    }

    /// 同 [`Waf::load`]，但首启生成的模板使用指定预设（如前台站点用 [`WafConfig::public_site`]）。
    ///
    /// 升级场景（旧版 `Config/Waf.json` 存在）：由 `dhrust::config::TomlConfig` 自动迁移，
    /// 旧文件缺失的键继承本预设，不需要本库写迁移代码。
    pub fn load_with_default(base: &Path, default: WafConfig) -> Arc<Self> {
        let file = base.join(crate::config::CONFIG_REL);
        if !file.exists() && !file.with_extension("json").exists() {
            let _ = default.save(&file);
        }
        let config = match WafConfig::load_merging(&file, &default) {
            Ok(c) => c,
            Err(e) => {
                dhrust::logs::log().warn(&format!("[WAF] 配置加载失败，使用默认策略：{e}"));
                default.clone()
            }
        };
        let waf = Self {
            config: RwLock::new(config),
            compiled_rules: RwLock::new(Vec::new()),
            limiter: RateLimiter::new(),
            trusted_secret: RwLock::new(None),
            forced_skip_bot: RwLock::new(Vec::new()),
            forced_skip_attack: RwLock::new(Vec::new()),
            trust_forwarded_for: RwLock::new(false),
            file: Some(file),
            preset: default,
            base_dir: base.to_path_buf(),
            last_check: AtomicI64::new(0),
            last_mtime: AtomicU64::new(0),
            stats: crate::stats::WafStats::new(),
            log_throttle: LogThrottle::new(),
        };
        waf.recompile();
        Arc::new(waf)
    }

    /// 运行统计快照（「当前是否正在被攻击」的判定入口；零磁盘/零网络）。
    ///
    /// - `total`：经过 WAF 的请求数；`blocked`：被拦数；
    /// - `last_minute` / `last_5_minutes`：分钟窗口拦截数（突增即扫描/攻击特征）；
    /// - `by_reason`：按原因分类（多类同时出现常见于工具扫描）；
    /// - `top_ips`：Top 来源 IP（固定 16 容量，不会随攻击流量膨胀）。
    pub fn stats(&self) -> crate::stats::WafStatsSnapshot {
        self.stats.snapshot()
    }

    /// 设置可信业务请求签名密钥（内存态，不写配置文件；空串=关闭）。
    ///
    /// 请求携带 `TimeStamp`/`Nonce`/`Signature` 三头且签名复验通过时直接放行 WAF
    /// （业务层仍会做时间窗/重放/权限校验）；签名不过的请求仍按原有规则拦截。
    pub fn set_trusted_signature_secret(&self, secret: impl Into<String>) {
        let secret = secret.into();
        let value = if secret.trim().is_empty() {
            None
        } else {
            Some(secret.trim().to_string())
        };
        match self.trusted_secret.write() {
            Ok(mut w) => *w = value,
            Err(p) => *p.into_inner() = value,
        }
    }

    /// 强制跳过机器人（爬虫/扫描器 UA）拦截的路径前缀——**内存态**，不落配置文件、
    /// 面板保存配置（会写全字段，可能把 `skipBotPrefixes` 写成空数组）也不会清掉。
    ///
    /// 机器对机器 API（如 DHDeploy Agent 的 `/api/*`）应使用本方法注册，
    /// 避免客户端 UA（RestSharp/HttpClient/python-requests…）被误判为扫描器。
    pub fn set_forced_skip_bot_prefixes(&self, prefixes: Vec<String>) {
        match self.forced_skip_bot.write() {
            Ok(mut w) => *w = prefixes,
            Err(p) => *p.into_inner() = prefixes,
        }
    }

    /// 强制跳过攻击特征检测的路径前缀（内存态；同上）。
    ///
    /// 用于「本体即执行 SQL / 传文件 / 跑命令」的管理端点——安全由业务层护栏负责。
    pub fn set_forced_skip_attack_prefixes(&self, prefixes: Vec<String>) {
        match self.forced_skip_attack.write() {
            Ok(mut w) => *w = prefixes,
            Err(p) => *p.into_inner() = prefixes,
        }
    }

    /// 当前生效的强制豁免前缀（诊断用：(bot, attack)）。
    pub fn forced_skip_prefixes(&self) -> (Vec<String>, Vec<String>) {
        let bot = self
            .forced_skip_bot
            .read()
            .map(|v| v.clone())
            .unwrap_or_default();
        let attack = self
            .forced_skip_attack
            .read()
            .map(|v| v.clone())
            .unwrap_or_default();
        (bot, attack)
    }

    /// 是否在「直连对端是回环」时采纳 `X-Forwarded-For`（**内存态**）。
    ///
    /// 反向代理之后，TCP 对端恒为 `127.0.0.1`——若不开这个，WAF 会把所有请求都当成回环：
    /// 一旦 `loopback_bypass = true` 就是**整体放行**，IP 黑名单与 Top IP 也全失效。
    /// 只在对端确为回环时才采纳 XFF，避免客户端伪造头部绕过。
    pub fn set_trust_forwarded_for(&self, trust: bool) {
        match self.trust_forwarded_for.write() {
            Ok(mut w) => *w = trust,
            Err(p) => *p.into_inner() = trust,
        }
    }

    /// 当前是否信任转发头（诊断用）。
    pub fn trust_forwarded_for(&self) -> bool {
        match self.trust_forwarded_for.read() {
            Ok(g) => *g,
            Err(p) => *p.into_inner(),
        }
    }

    /// 解析真实客户端 IP：`(TCP 对端, X-Forwarded-For)` → 纯 IP 串。
    ///
    /// 与项目业务层的 `client_ip` 口径一致：**仅当对端是回环**时才采纳 XFF 的第一段。
    fn resolve_ip(&self, peer: Option<&str>, xff: Option<&str>) -> String {
        let peer_ip = crate::wafreq::strip_port(peer.unwrap_or(""));
        if self.trust_forwarded_for()
            && is_loopback(&peer_ip)
            && let Some(xff) = xff
        {
            let first = xff.split(',').next().unwrap_or("").trim();
            if !first.is_empty() {
                return crate::wafreq::strip_port(first);
            }
        }
        peer_ip
    }

    /// 请求签名是否为当前可信业务请求（SHA1(排序后的 timestamp+nonce+secret)）。
    fn trusted_signed(&self, req: &dhrust::net::http::HttpRequest) -> bool {
        self.trusted_signed_by(|name| req.header(name))
    }

    /// 同 [`trusted_signed`]，但头部取值由调用方提供（完整请求 / 头快照共用）。
    fn trusted_signed_by<'a>(
        &self,
        header: impl Fn(&str) -> Option<&'a str>,
    ) -> bool {
        let secret = match self.trusted_secret.read() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        };
        let Some(secret) = secret else {
            return false;
        };
        let timestamp = header("TimeStamp").unwrap_or("").trim();
        let nonce = header("Nonce").unwrap_or("").trim();
        let signature = header("Signature").unwrap_or("").trim();
        if timestamp.is_empty() || nonce.is_empty() || signature.is_empty() {
            return false;
        }
        let expect = dhrust::sign::create_signature(
            timestamp.to_string(),
            nonce.to_string(),
            secret,
        );
        if expect.is_empty() {
            return false;
        }
        // 定时攻击防护：等长逐字节比较
        let (a, b) = (expect.as_bytes(), signature.as_bytes());
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }

    /// 当前配置副本（面板展示用）。
    pub fn config(&self) -> WafConfig {
        match self.config.read() {
            Ok(c) => c.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// 面板保存入口：覆盖配置——先写配置文件（存在路径时），再立即生效（规则重编译、限速计数清零）。
    ///
    /// 写文件失败时不应用（避免“内存已改、重启丢失”的不一致）。
    pub fn apply_config(&self, cfg: WafConfig) -> Result<(), String> {
        if let Some(file) = &self.file {
            cfg.save(file)?;
        }
        match self.config.write() {
            Ok(mut w) => *w = cfg,
            Err(p) => *p.into_inner() = cfg,
        }
        self.recompile();
        self.limiter.clear();
        if let Some(file) = &self.file {
            self.stamp_mtime(file);
        }
        Ok(())
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
        match WafConfig::load_merging(&file, &self.preset) {
            Ok(cfg) => {
                match self.config.write() {
                    Ok(mut w) => *w = cfg,
                    Err(p) => *p.into_inner() = cfg,
                }
                self.recompile();
                self.limiter.clear();
                self.stamp_mtime(&file);
            }
            Err(e) => {
                dhrust::logs::log().warn(&format!("[WAF] 配置热重载失败（保留旧配置）：{e}"));
            }
        }
    }

    /// 记录配置文件 mtime 基线（避免下一轮热重载对同内容重复处理）。
    fn stamp_mtime(&self, file: &Path) {
        if let Ok(meta) = std::fs::metadata(file)
            && let Ok(t) = meta.modified()
            && let Ok(d) = t.duration_since(std::time::UNIX_EPOCH)
        {
            self.last_mtime.store(d.as_millis() as u64, Ordering::Relaxed);
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
        // 可信业务请求（DHDeploy 客户端等）按共享密钥签名放行；不依赖 UA，避免 RestSharp/
        // python-requests 等正常机器客户端被当成扫描器；签名不通过仍走原规则。
        if self.trusted_signed(req) {
            return Verdict::Allow;
        }
        let mut wreq = WafRequest::from_http(req);
        // body 扫描范围按配置：默认只扫文本类的前 16 KB；`body_scan_all_types` 打开后
        // 连 `application/octet-stream` 也扫（防「改个 Content-Type 就绕过 body 检测」），
        // 上限由 `body_scan_limit` 控制（防大 body 造成 CPU 开销）。
        let (limit, all_types) = match self.config.read() {
            Ok(c) => (c.body_scan_limit, c.body_scan_all_types),
            Err(p) => {
                let c = p.into_inner();
                (c.body_scan_limit, c.body_scan_all_types)
            }
        };
        let limit = if limit == 0 { 16 * 1024 } else { limit };
        if !req.body.is_empty()
            && (all_types || crate::wafreq::is_text_content_type(&wreq.content_type))
        {
            let cap = req.body.len().min(limit);
            wreq.body_text = String::from_utf8_lossy(&req.body[..cap]).to_string();
        }
        // 真实 IP：反代后对端恒为回环，开了 `set_trust_forwarded_for` 才采纳 XFF
        // （否则 WAF 会把所有请求当回环，配合 loopback_bypass 就是整体放行）
        wreq.remote_ip = self.resolve_ip(req.remote_addr.as_deref(), req.header("x-forwarded-for"));
        // CSRF/跨站来源校验先于回环豁免：浏览器跨站请求的源 IP 恰是回环（localhost/面板免登录场景防护）。
        // 无 Sec-Fetch-Site 与 Origin 的请求（curl / 服务间调用 / 旧客户端）不进此分支。
        if let Some(reason) = csrf_check(req) {
            let cfg = match self.config.read() {
                Ok(c) => c,
                Err(p) => p.into_inner(),
            };
            if cfg.enable && cfg.csrf_guard {
                return self.blocked(&cfg, 403, reason, &wreq, crate::stats::BlockKind::Csrf);
            }
        }
        self.check(&wreq)
    }

    /// 对规范化请求执行检查。
    pub fn check(&self, req: &WafRequest) -> Verdict {
        // 统计：每请求一次原子递增（放行路径也只有这一次）
        self.stats.record_request();
        self.check_inner(req)
    }

    /// **头阶段**检查（还没读 body 时调）：与 [`check`] 同规则，但
    /// - **不**累加请求计数（避免与之后的 [`check`] 重复计数）；拦截仍正常计入统计；
    /// - 攻击扫描只能看 `path`/`query`（`body_text` 为空）——正好是「不需 body 就能判断」那部分。
    ///
    /// 用于 HTTP 层的早拒钩子：UA/IP/路径/查询串特征命中时，**不用收完 body 就能拒绝**。
    ///
    /// 注意：只能看头部不包含的东西（body），因此不含 body 级规则；
    /// 需要「签名 / CSRF」也提前判时用 [`check_head_http`](Self::check_head_http)。
    pub fn check_head(&self, req: &WafRequest) -> Verdict {
        self.check_inner(req)
    }

    /// **头阶段**检查（完整形态）：从 [`HttpRequestHead`] 构造，除 [`check_head`] 的规则外，
    /// 还会：① 先认可信业务签名（已签名请求不应被 UA 规则误拦）；
    /// ② 跑 CSRF/跨站来源校验（纯头判断，无需 body）；③ 用真实 IP（回环时采纳 XFF）。
    ///
    /// 用于 `HttpServerOptions.early_guard`：全部判断都不需要 body。
    pub fn check_head_http(&self, head: &dhrust::net::http::HttpRequestHead) -> Verdict {
        if self.trusted_signed_by(|name| head.header(name)) {
            return Verdict::Allow;
        }
        let mut wreq = WafRequest::from_head(head);
        wreq.remote_ip = self.resolve_ip(head.remote_addr.as_deref(), head.header("x-forwarded-for"));
        if let Some(reason) = csrf_reason(
            &head.method,
            head.header("sec-fetch-site").unwrap_or(""),
            head.header("origin").unwrap_or(""),
            head.header("host").unwrap_or(""),
        ) {
            let cfg = match self.config.read() {
                Ok(c) => c,
                Err(p) => p.into_inner(),
            };
            if cfg.enable && cfg.csrf_guard {
                return self.blocked(&cfg, 403, reason, &wreq, crate::stats::BlockKind::Csrf);
            }
        }
        self.check_inner(&wreq)
    }

    fn check_inner(&self, req: &WafRequest) -> Verdict {
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
            return self.blocked(
                &cfg,
                403,
                format!("IP 黑名单：{ip}"),
                req,
                crate::stats::BlockKind::IpBlacklist,
            );
        }

        let ua_lower = req.user_agent.trim().to_ascii_lowercase();

        // —— 自定义 UA 规则 ——
        if !cfg.extra_block_bots.is_empty()
            && cfg.extra_block_bots.iter().any(|k| ua_lower.contains(&k.to_ascii_lowercase()))
        {
            return self.blocked(&cfg, 403, "自定义拦截 UA".to_string(), req, crate::stats::BlockKind::CustomRule);
        }
        if cfg.block_empty_ua && ua_lower.is_empty() {
            return self.blocked(&cfg, 403, "空 User-Agent".to_string(), req, crate::stats::BlockKind::CustomRule);
        }

        let extra_allowed = !cfg.extra_allow_bots.is_empty()
            && cfg.extra_allow_bots.iter().any(|k| ua_lower.contains(&k.to_ascii_lowercase()));
        let sensitive = !cfg.sensitive_prefixes.is_empty()
            && cfg.sensitive_prefixes.iter().any(|p| req.path.starts_with(p.as_str()));
        // 跳过机器人拦截的路径前缀（机器对机器 API；攻击检测/CC 不受影响）
        // skip_bot_prefixes 来自配置文件（面板保存会写全字段，可能被显式写成空数组），
        // 因此另支持「强制豁免」（内存态，进程内设定后不可被配置覆盖）。
        let skip_bot = (!cfg.skip_bot_prefixes.is_empty()
            && cfg
                .skip_bot_prefixes
                .iter()
                .any(|p| req.path.starts_with(p.as_str())))
            || self
                .forced_skip_bot
                .read()
                .map(|v| v.iter().any(|p| req.path.starts_with(p.as_str())))
                .unwrap_or(false);

        // —— 爬虫分类 ——
        let mut friendly_bot = false;
        if !extra_allowed
            && !skip_bot
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
                            crate::stats::BlockKind::Bot,
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
                            crate::stats::BlockKind::Bot,
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
                            crate::stats::BlockKind::Bot,
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
                            crate::stats::BlockKind::Bot,
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
        let skip_attack = (!cfg.skip_attack_prefixes.is_empty()
            && cfg
                .skip_attack_prefixes
                .iter()
                .any(|p| req.path.starts_with(p.as_str())))
            || self
                .forced_skip_attack
                .read()
                .map(|v| v.iter().any(|p| req.path.starts_with(p.as_str())))
                .unwrap_or(false);
        if !skip_attack {
            // 静态资源（js/css/图片/字体）只做「路径穿越 / 敏感路径」检测：
            // 这些文件内容天然含 `' or `、`<script` 之类片段，跑全量特征是误报高发区，
            // 且面板每次加载都要重复扫 N 个文件——省掉这部分每请求的字符串分配。
            let kinds = if is_static_asset(&req.path) {
                attack::scan_path(&req.path, &req.query)
            } else {
                attack::scan_all(&req.path, &req.query, &req.body_text)
            };
            for kind in kinds {
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
                        let block_kind = match kind {
                            AttackKind::SqlInjection => crate::stats::BlockKind::SqlInjection,
                            AttackKind::Xss => crate::stats::BlockKind::Xss,
                            AttackKind::PathTraversal => crate::stats::BlockKind::PathTraversal,
                            AttackKind::CommandInjection => crate::stats::BlockKind::CommandInjection,
                        };
                        return self.blocked(
                            &cfg,
                            403,
                            format!("{} 特征：{}", kind.name_cn(), brief(&req.path)),
                            req,
                            block_kind,
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
                    return self.blocked(
                        &cfg,
                        403,
                        format!("自定义规则：{}", rule.label()),
                        req,
                        crate::stats::BlockKind::CustomRule,
                    );
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
                crate::stats::BlockKind::RateLimit,
            );
        }

        Verdict::Allow
    }

    fn blocked(
        &self,
        cfg: &WafConfig,
        status: u16,
        reason: String,
        req: &WafRequest,
        kind: crate::stats::BlockKind,
    ) -> Verdict {
        // 统计（只累加被拦请求：原因分类 + 分钟窗口 + Top IP）
        self.stats.record_block(kind, &req.remote_ip);
        if cfg.log_blocked && self.log_throttle.allow(&req.remote_ip, &reason) {
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

/// 是否回环地址（含 IPv4 映射：`::ffff:127.0.0.1`——双栈监听时对端常见此形态）。
pub fn is_loopback(ip: &str) -> bool {
    let ip = ip.trim();
    let ip = ip.strip_prefix("::ffff:").unwrap_or(ip);
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

/// 拦截日志去重器：同「IP + 原因」在 1 秒窗口内只放行一条日志。
///
/// 目的：攻击洪峰时 `blocked()` 每个请求写一条 warn 会把日志 IO 放大成瓶颈；
/// 计数与统计不受影响（统计是原子计数，与日志无关）。
struct LogThrottle {
    inner: std::sync::Mutex<std::collections::HashMap<u64, std::time::Instant>>,
}

impl LogThrottle {
    fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn allow(&self, ip: &str, reason: &str) -> bool {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        ip.hash(&mut h);
        reason.hash(&mut h);
        let key = h.finish();

        let now = std::time::Instant::now();
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        // 容量保护：条目过多时清掉 60 秒前的旧记录（Top 攻击源数量有界，不会无限涨）
        if map.len() > 512 {
            map.retain(|_, t| now.duration_since(*t) < std::time::Duration::from_secs(60));
        }
        if let Some(t) = map.get(&key)
            && now.duration_since(*t) < std::time::Duration::from_secs(1)
        {
            return false;
        }
        map.insert(key, now);
        true
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 跨站来源校验（CSRF）：返回拦截原因（None = 放行）。
///
/// 判定顺序（仅非安全方法）：
/// 1. `Sec-Fetch-Site: cross-site` → 拒绝（现代浏览器）；
/// 2. 无 Sec-Fetch-Site 但有 `Origin`：与请求 `Host` 同源才放行（`null` 视作跨站拒绝）；
/// 3. 两类头均无（curl / .NET HttpClient / 服务间调用）→ 放行。
fn csrf_check(req: &dhrust::net::http::HttpRequest) -> Option<String> {
    csrf_reason(
        &req.method,
        req.header("sec-fetch-site").unwrap_or(""),
        req.header("origin").unwrap_or(""),
        req.header("host").unwrap_or(""),
    )
}

/// 同 [`csrf_check`]，但参数化（完整请求 / 头快照共用）。
fn csrf_reason(method: &str, sec_fetch_site: &str, origin: &str, host: &str) -> Option<String> {
    let m = method.to_ascii_uppercase();
    if !matches!(m.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") {
        return None;
    }
    let site = sec_fetch_site.trim().to_ascii_lowercase();
    if !site.is_empty() {
        return if site == "cross-site" {
            Some("跨站请求（Sec-Fetch-Site: cross-site）".to_string())
        } else {
            None
        };
    }
    let origin = origin.trim();
    if origin.is_empty() {
        return None;
    }
    if origin == "null" {
        return Some("跨站来源（Origin: null——file:// 或沙盒页面）".to_string());
    }
    let host = host.trim();
    let origin_host = origin.split("://").nth(1).unwrap_or(origin);
    if !host.is_empty() && !origin_host.eq_ignore_ascii_case(host) {
        return Some(format!("跨站来源（Origin: {origin} ≠ Host: {host}）"));
    }
    None
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

    /// 构造原始 HTTP 请求（CSRF 用例）。
    fn hreq(method: &str, headers: Vec<(&str, &str)>) -> dhrust::net::http::HttpRequest {
        dhrust::net::http::HttpRequest {
            method: method.to_string(),
            path: "/api/action".to_string(),
            query: String::new(),
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: bytes::Bytes::new(),
            remote_addr: Some("127.0.0.1:5000".to_string()),
        }
    }

    #[test]
    fn trusted_signature_bypasses_bot_block() {
        let mut cfg = WafConfig::admin_api();
        cfg.loopback_bypass = false; // 测试用 hreq 是回环地址，关掉豁免才能验证 bot 拦截
        let waf = Waf::new(cfg);
        waf.set_trusted_signature_secret("s3cret");

        let ts = dhrust::times::getmilltimestamp().to_string();
        let nonce = "n-123456";
        let sig = dhrust::sign::create_signature(ts.clone(), nonce.to_string(), "s3cret".to_string());
        let signed = hreq(
            "POST",
            vec![
                ("User-Agent", "RestSharp/114.0.0.0"),
                ("TimeStamp", &ts),
                ("Nonce", nonce),
                ("Signature", &sig),
            ],
        );
        assert_eq!(waf.check_http(&signed).blocked_status(), None);

        let unsigned = hreq("POST", vec![("User-Agent", "RestSharp/114.0.0.0")]);
        assert_eq!(waf.check_http(&unsigned).blocked_status(), Some(403));
    }

    #[test]
    fn csrf_guard_blocks_cross_site_writes() {
        let waf = Waf::new(WafConfig::admin_api());
        // 跨站 POST（哪怕源 IP 是回环——先于回环豁免）→ 403
        let v = waf.check_http(&hreq(
            "POST",
            vec![("Sec-Fetch-Site", "cross-site"), ("Host", "127.0.0.1:5501")],
        ));
        assert_eq!(v.blocked_status(), Some(403));
        // 跨源 Origin → 403
        let v = waf.check_http(&hreq(
            "POST",
            vec![("Origin", "https://evil.example"), ("Host", "127.0.0.1:5501")],
        ));
        assert_eq!(v.blocked_status(), Some(403));
        // Origin: null（file:// / 沙盒）→ 403
        let v = waf.check_http(&hreq(
            "POST",
            vec![("Origin", "null"), ("Host", "127.0.0.1:5501")],
        ));
        assert_eq!(v.blocked_status(), Some(403));
        // 同源 Origin → 放行
        let v = waf.check_http(&hreq(
            "POST",
            vec![
                ("Origin", "http://127.0.0.1:5501"),
                ("Host", "127.0.0.1:5501"),
            ],
        ));
        assert!(v.is_allow());
        // 无来源头（curl / .NET HttpClient / 服务间）→ 放行
        let v = waf.check_http(&hreq("POST", vec![]));
        assert!(v.is_allow());
        // GET 跨站 → 无副作用，放行
        let v = waf.check_http(&hreq("GET", vec![("Sec-Fetch-Site", "cross-site")]));
        assert!(v.is_allow());
        // 关闭 csrf_guard → 放行
        let mut cfg = WafConfig::admin_api();
        cfg.csrf_guard = false;
        let waf2 = Waf::new(cfg);
        let v = waf2.check_http(&hreq("POST", vec![("Sec-Fetch-Site", "cross-site")]));
        assert!(v.is_allow());
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
        let file = dir.join(crate::config::CONFIG_REL);
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
    fn apply_config_takes_effect_and_persists() {
        let dir = std::env::temp_dir().join(format!("pek-waf-apply-{}", std::process::id()));
        let file = dir.join(crate::config::CONFIG_REL);
        let waf = Waf::load_with_default(&dir, WafConfig::public_site());
        // 关闭 → 恶意 UA 也放行
        let mut cfg = waf.config();
        cfg.enable = false;
        waf.apply_config(cfg).unwrap();
        let mut r = wreq("/");
        r.user_agent = "sqlmap/1.7".into();
        assert!(waf.check(&r).is_allow(), "关闭后应全放行");
        // 已持久化到文件
        let reloaded = WafConfig::load_or_create(&file).unwrap();
        assert!(!reloaded.enable);
        // 重新开启 + 下调限速 → 生效
        let mut cfg = waf.config();
        cfg.enable = true;
        cfg.rate_limit_per_min = 2;
        waf.apply_config(cfg).unwrap();
        assert_eq!(waf.check(&r).blocked_status(), Some(403), "恢复后恶意 UA 拦截");
        let s = wreq("/x");
        assert!(waf.check(&s).is_allow());
        assert!(waf.check(&s).is_allow());
        assert_eq!(waf.check(&s).blocked_status(), Some(429));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_with_default_migrates_legacy_json() {
        let dir = std::env::temp_dir().join(format!("pek-waf-migrate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let legacy = dir.join(crate::config::LEGACY_CONFIG_REL);
        std::fs::create_dir_all(legacy.parent().expect("父目录")).expect("建目录");
        std::fs::write(&legacy, r#"{ "enable": true, "rateLimitPerMin": 42 }"#).expect("写旧配置");

        let waf = Waf::load_with_default(&dir, WafConfig::public_site());
        assert_eq!(waf.config().rate_limit_per_min, 42, "旧配置的值应生效");
        assert_eq!(
            waf.config().mode,
            crate::config::WafMode::PublicSite,
            "旧文件未写的键应继承调用方预设"
        );
        let file = dir.join(crate::config::CONFIG_REL);
        assert!(file.is_file(), "应生成 Waf.toml");
        assert!(!legacy.exists(), "旧 JSON 应改名");
        assert!(legacy.with_extension("json.bak").is_file(), "旧文件应备份");
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn reload_recreates_missing_file_with_current_preset() {
        let dir = std::env::temp_dir().join(format!("pek-waf-reload-{}", std::process::id()));
        let file = dir.join(crate::config::CONFIG_REL);
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
    fn skip_bot_prefixes_for_machine_api() {
        let mut cfg = WafConfig::admin_api();
        cfg.skip_bot_prefixes = vec!["/api".to_string()];
        let waf = Waf::new(cfg);
        // skip 前缀下：恶意默认 UA（自家工具）不拦
        let mut r = wreq("/api/getAvailableSn");
        r.user_agent = "python-requests/2.31".into();
        assert!(waf.check(&r).is_allow(), "skip 前缀不拦 bot");
        // 攻击检测仍生效（skipAttackPrefixes 未设：路径探测照拦）
        let r2 = wreq("/api/x.php");
        assert_eq!(waf.check(&r2).blocked_status(), Some(403));
        // 其余路径仍拦
        let mut r3 = wreq("/");
        r3.user_agent = "python-requests/2.31".into();
        assert_eq!(waf.check(&r3).blocked_status(), Some(403));
    }

    #[test]
    fn forced_skip_bot_overrides_explicit_empty_config() {
        // 线上故障场景：配置文件被面板保存后写成 "skipBotPrefixes": []（显式空）
        let mut cfg = WafConfig::admin_api();
        cfg.skip_bot_prefixes = Vec::new();
        let waf = Waf::new(cfg);
        let mut r = wreq("/api/v1/DirectFileManager/List");
        r.user_agent = "RestSharp/114.0.0.0".into();
        // 未注册强制豁免：仍按配置拦（复现线上日志）
        assert_eq!(waf.check(&r).blocked_status(), Some(403));

        // 注册强制豁免后：即便配置显式空也放行
        waf.set_forced_skip_bot_prefixes(vec!["/api".to_string()]);
        assert!(waf.check(&r).is_allow(), "强制豁免应覆盖配置文件的显式空数组");
        assert_eq!(waf.forced_skip_prefixes().0, vec!["/api".to_string()]);

        // 前缀之外不受影响
        let mut r2 = wreq("/other");
        r2.user_agent = "RestSharp/114.0.0.0".into();
        assert_eq!(waf.check(&r2).blocked_status(), Some(403));
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

    /// 反向代理场景：只有「对端是回环」且开启信任时才采纳 `X-Forwarded-For`。
    #[test]
    fn forwarded_for_used_only_for_loopback_peer() {
        let mut cfg = WafConfig::admin_api();
        cfg.loopback_bypass = false;
        cfg.ip_blacklist = vec!["6.6.6.6".to_string()];
        let waf = Waf::new(cfg);

        // 未开信任：无论 XFF 是什么，都按对端 IP（回环）处理
        let mut req = hreq("GET", vec![("X-Forwarded-For", "6.6.6.6")]);
        assert_eq!(waf.check_http(&req).blocked_status(), None);

        // 开信任 + 对端回环 → 采用 XFF 首段，命中黑名单
        waf.set_trust_forwarded_for(true);
        assert!(waf.trust_forwarded_for());
        assert_eq!(waf.check_http(&req).blocked_status(), Some(403));

        // 对端不是回环 → 忽略 XFF（防伪造）
        req.remote_addr = Some("10.1.2.3:5000".to_string());
        assert_eq!(waf.check_http(&req).blocked_status(), None);
    }

    #[test]
    fn ipv4_mapped_loopback_is_loopback() {
        assert!(is_loopback("::ffff:127.0.0.1"));
        assert!(is_loopback("::1"));
        assert!(!is_loopback("::ffff:8.8.8.8"));
    }

    /// 静态资源只做路径穿越检测：内容型关键字不误报，但穿越仍要拦。
    #[test]
    fn static_asset_scans_path_only() {
        let mut cfg = WafConfig::admin_api();
        cfg.loopback_bypass = false;
        let waf = Waf::new(cfg);

        // JS 文件路径 + 查询串里带 XSS/SQLi 关键字 → 静态资源跳过内容型特征
        let mut r = wreq("/panel/app.js");
        r.query = "v=<script>alert(1)</script>".to_string();
        assert!(waf.check(&r).is_allow(), "静态资源不应因内容型特征被拦");

        // 同一路径带路径穿越 → 仍必须拦
        let mut r = wreq("/panel/app.js");
        r.query = "f=../../etc/passwd".to_string();
        assert_eq!(waf.check(&r).blocked_status(), Some(403));

        // 非静态路径带同样关键字 → 照常拦
        let mut r = wreq("/panel/api/save");
        r.query = "v=<script>alert(1)</script>".to_string();
        assert_eq!(waf.check(&r).blocked_status(), Some(403));
    }

    /// 日志去重不改变统计口径：连续拦截仍逐条计数。
    #[test]
    fn log_throttle_does_not_affect_stats() {
        let mut cfg = WafConfig::admin_api();
        cfg.loopback_bypass = false;
        let waf = Waf::new(cfg);
        let mut r = wreq("/api/x");
        r.query = "a=' or 1=1".to_string();
        for _ in 0..3 {
            assert_eq!(waf.check(&r).blocked_status(), Some(403));
        }
        let snap = waf.stats();
        assert_eq!(snap.blocked, 3, "去重只影响日志，不影响计数：{snap:?}");
    }

    /// 改个 Content-Type 不应能绕过 body 检测（开启 `body_scan_all_types` 后）。
    #[test]
    fn body_scan_all_types_catches_octet_stream_payload() {
        let mut cfg = WafConfig::admin_api();
        cfg.loopback_bypass = false;
        cfg.body_scan_all_types = false;
        cfg.body_scan_limit = 64 * 1024;
        let waf = Waf::new(cfg);

        let mut req = hreq("POST", vec![("Content-Type", "application/octet-stream")]);
        req.body = bytes::Bytes::from_static(b"AppId=wx' or 1=1--");
        // 默认：非文本不扫 → 放行（旧行为，保留为可配）
        assert!(waf.check_http(&req).is_allow());

        // 打开全类型扫描 → 同一请求被拦
        let mut cfg = waf.config();
        cfg.body_scan_all_types = true;
        waf.apply_config(cfg).unwrap();
        assert_eq!(waf.check_http(&req).blocked_status(), Some(403));

        // 扫描上限生效：payload 放到上限之后则不扫到（证明上限可配）
        let mut cfg = waf.config();
        cfg.body_scan_limit = 4;
        waf.apply_config(cfg).unwrap();
        assert!(waf.check_http(&req).is_allow());
    }

    /// 头阶段检查也要认可信签名（否则已签名业务请求会被 UA 规则早拒）。
    #[test]
    fn head_stage_respects_trusted_signature_and_csrf() {
        let mut cfg = WafConfig::admin_api();
        cfg.loopback_bypass = false;
        let waf = Waf::new(cfg);
        waf.set_trusted_signature_secret("s3cret");

        let ts = dhrust::times::getmilltimestamp().to_string();
        let nonce = "n-abcdefgh";
        let sig =
            dhrust::sign::create_signature(ts.clone(), nonce.to_string(), "s3cret".to_string());
        let head = |extra: Vec<(&str, &str)>| {
            let mut headers: Vec<(String, String)> = vec![
                ("user-agent".to_string(), "RestSharp/114.0.0.0".to_string()),
                ("host".to_string(), "127.0.0.1:5501".to_string()),
            ];
            headers.extend(extra.into_iter().map(|(k, v)| (k.to_string(), v.to_string())));
            dhrust::net::http::HttpRequestHead {
                method: "POST".to_string(),
                path: "/api/action".to_string(),
                query: String::new(),
                headers,
                remote_addr: Some("127.0.0.1:5000".to_string()),
                content_length: None,
            }
        };

        // 未签名 + RestSharp UA（恶意爬虫名单）→ 头阶段 403
        assert_eq!(waf.check_head_http(&head(vec![])).blocked_status(), Some(403));
        // 带有效签名 → 头阶段放行
        let signed = head(vec![
            ("TimeStamp", &ts),
            ("Nonce", nonce),
            ("Signature", &sig),
        ]);
        assert_eq!(waf.check_head_http(&signed).blocked_status(), None);
        // 跨站写操作 → 头阶段即拦（无需 body）
        let cross = head(vec![("Sec-Fetch-Site", "cross-site")]);
        assert_eq!(waf.check_head_http(&cross).blocked_status(), Some(403));
    }
}

