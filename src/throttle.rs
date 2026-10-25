//! 接口级限流（对齐 C# `DH.RateLimter`）：按「方法 + 路径」声明规则，每条规则可挂多个阀门。
//!
//! # 与 C# 版的能力对应
//!
//! | C# `DH.RateLimter` | 本模块 |
//! | --- | --- |
//! | `[RateValve]` 特性（可多个，`Priority` 从高到低） | [`ThrottleRule::valves`]（按 `priority` 降序检查） |
//! | `Policy`：Ip / UserIdentity / Header / Query / RequestPath / Cookie / Form | [`Policy`]（同名七种） |
//! | `WhenNull.Pass` / `Intercept` | [`WhenNull`]（空值跳过规则 / 按客户端 IP 生成空值标识继续限流） |
//! | `Limit` + `Duration`（秒） | [`RateValve::limit`] + [`RateValve::duration`] |
//! | `IRateLimitStore<T>.IncrementAsync`（Redis/内存） | [`dhrust::ratelimit::CounterStore`]（默认进程内，可注入 Redis） |
//! | `ReturnType`：`Json_DGResult` / `Json_DResult` / `Text` | [`ThrottleReturnType`]（429 + 对应响应体） |
//! | 请求头 `Api-Throttle-Status: 1/0` | 同名请求头（并回写到响应头） |
//! | `AllowRateLimter` 全局开关 | [`ThrottleConfig::enable`] |
//! | `RateLimterOptions.OnUserIdentity/OnIpAddress/onIntercepted` | [`Throttle::set_user_identity`] / [`Throttle::set_client_ip`] / [`Throttle::set_limited_response`] |
//!
//! **差异（有意为之）**：
//! - C# 用 MVC 特性声明，Rust 没有运行时反射——改为 `Config/Throttle.toml` 规则表，
//!   或在路由注册处用 [`Throttle::guard`] 包裹单个处理器；
//! - C# 的 MD5 / IP 转换有 5 分钟内存缓存（`MemoryCache`）；Rust 的 `md5_hex` / `ip_to_num`
//!   单次成本在百纳秒级，直接计算，**不引入会无界增长的缓存**；
//! - C# 的黑白名单功能未实现（源码注释明确“暂未实现”），本模块同样不做——IP 名单由
//!   [`crate::Waf`] 负责；
//! - C# 的 `Timestamp` 仅用于结果对象；本模块用 [`LimitInfo::retry_after`] 直接给出
//!   `Retry-After` 所需秒数。
//!
//! # 接入方式
//!
//! ```no_run
//! # use std::path::Path;
//! # use dhrust::net::router::Router;
//! # let mut router = Router::new();
//! // 方式一：全局中间件 + Config/Throttle.toml（推荐；规则热重载）
//! let throttle = pek_rwaf::throttle::Throttle::load(Path::new("."));
//! router.use_middleware(throttle.middleware());
//!
//! // 方式二：按路由包裹（规则写在代码里，无需配置文件）
//! # use pek_rwaf::throttle::{RateValve, ThrottleRule};
//! # use dhrust::net::router::route;
//! # use dhrust::net::http::{HttpOutcome, HttpResponse};
//! let rule = ThrottleRule::new("POST", "/api/login", vec![RateValve::ip(5, 60)]);
//! let handler = route(|_ctx| async { HttpOutcome::Response(HttpResponse::text(200, "ok")) });
//! router.map_post("/api/login", throttle.guard(rule, handler));
//! ```
//!
//! 与 [`crate::Waf`] 的关系：WAF 的 `rateLimitPerMin` 是**全站每 IP** 的 CC 防护；本模块是
//! **按接口/多策略** 的业务限流。两者可同时启用（WAF 中间件放最外层），计数引擎共用
//! [`dhrust::ratelimit`]。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use dhrust::net::http::{DGResult, HttpOutcome, HttpRequest, HttpResponse, state};
use dhrust::net::router::{Ctx, Middleware, RouteHandler, middleware, route};
use dhrust::ratelimit::{CounterStore, WindowLimiter};

/// 限流状态请求/响应头（对齐 C# `Common.HeaderStatusKey`）。
pub const HEADER_STATUS: &str = "Api-Throttle-Status";
/// 全局 API 标识（对齐 C# `Common.GlobalApiKey`；规则既无 `name` 也无 `path` 时使用）。
pub const GLOBAL_API_KEY: &str = "global";
/// 配置文件相对基础目录的路径。
pub const CONFIG_REL: &str = "Config/Throttle.toml";
/// 旧版 JSON 配置（存在时由 `TomlConfig` 自动迁移）。
pub const LEGACY_CONFIG_REL: &str = "Config/Throttle.json";

/// 热重载检查间隔（毫秒）。
const RELOAD_CHECK_INTERVAL_MS: i64 = 10_000;

/// 识别策略（对齐 C# `Policy`；数值仅作文档参考：Ip=1…Form=7）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Policy {
    /// IP 地址（转为十进制数字后哈希）
    #[serde(alias = "Ip", alias = "IP")]
    Ip,
    /// 用户身份（默认取 `Ctx.state` 的 `user_id`/`userId`/`userid`/`user`/`username`/`sub`，
    /// 可用 [`Throttle::set_user_identity`] 覆盖）
    #[serde(alias = "UserIdentity")]
    UserIdentity,
    /// 请求头（`policyKey` 为头名，大小写不敏感）
    #[serde(alias = "Header")]
    Header,
    /// 查询参数（`policyKey` 为参数名）
    #[serde(alias = "Query")]
    Query,
    /// 请求路径（`policyKey` 忽略）
    #[serde(alias = "RequestPath")]
    RequestPath,
    /// Cookie（`policyKey` 为 Cookie 名；精确优先，其次大小写不敏感）
    #[serde(alias = "Cookie")]
    Cookie,
    /// urlencoded 表单字段（`policyKey` 为字段名；multipart 未解析）
    #[serde(alias = "Form")]
    Form,
}

impl Policy {
    /// 计数键中的策略名（对齐 C# `Policy.ToString().ToLower()`）。
    pub fn as_key(self) -> &'static str {
        match self {
            Policy::Ip => "ip",
            Policy::UserIdentity => "useridentity",
            Policy::Header => "header",
            Policy::Query => "query",
            Policy::RequestPath => "requestpath",
            Policy::Cookie => "cookie",
            Policy::Form => "form",
        }
    }
}

/// 识别值为空时的处理方式（对齐 C# `WhenNull`）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WhenNull {
    /// 跳过当前阀门（同一规则的其他阀门仍继续执行）
    #[serde(alias = "Pass")]
    Pass,
    /// 用客户端 IP 生成空值标识，继续参与限流
    #[serde(alias = "Intercept")]
    Intercept,
}

/// 超限返回格式（对齐 C# `ReturnType`）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum ThrottleReturnType {
    /// `DGResult` 信封（`Code/Message/...`，`Code = state::BUSY`）
    #[serde(alias = "Json_DGResult", alias = "JsonDgResult", alias = "JsonDGResult")]
    JsonDgResult,
    /// `{"code":99,"msg":"..."}`（对齐 C# `DResult`）
    #[serde(alias = "Json_DResult", alias = "JsonDResult")]
    #[default]
    JsonDResult,
    /// 纯文本
    #[serde(alias = "Text")]
    Text,
}

/// 频率阀门（对齐 C# `RateValve`）。
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct RateValve {
    /// 识别策略
    pub policy: Policy,
    /// 策略键（Header/Query/Cookie/Form 的键名；其它策略忽略）
    pub policy_key: String,
    /// 窗口内允许次数（0 = 本阀门关闭）
    pub limit: u64,
    /// 窗口长度（秒；0 = 本阀门关闭）
    pub duration: u64,
    /// 识别值为空时的处理方式
    pub when_null: WhenNull,
    /// 优先级（同一规则内按降序检查）
    pub priority: i32,
    /// 超限返回格式
    pub return_type: ThrottleReturnType,
}

impl Default for RateValve {
    fn default() -> Self {
        Self {
            policy: Policy::Ip,
            policy_key: String::new(),
            limit: 1,
            duration: 60,
            when_null: WhenNull::Pass,
            priority: 0,
            return_type: ThrottleReturnType::JsonDResult,
        }
    }
}

impl RateValve {
    /// IP 策略阀门。
    pub fn ip(limit: u64, duration_seconds: u64) -> Self {
        Self {
            policy: Policy::Ip,
            limit,
            duration: duration_seconds,
            ..Self::default()
        }
    }

    /// 用户身份策略阀门。
    pub fn user_identity(limit: u64, duration_seconds: u64) -> Self {
        Self {
            policy: Policy::UserIdentity,
            limit,
            duration: duration_seconds,
            ..Self::default()
        }
    }

    /// Header 策略阀门（`key` 为请求头名）。
    pub fn header(key: impl Into<String>, limit: u64, duration_seconds: u64) -> Self {
        Self {
            policy: Policy::Header,
            policy_key: key.into(),
            limit,
            duration: duration_seconds,
            ..Self::default()
        }
    }

    /// Query 策略阀门（`key` 为查询参数名）。
    pub fn query(key: impl Into<String>, limit: u64, duration_seconds: u64) -> Self {
        Self {
            policy: Policy::Query,
            policy_key: key.into(),
            limit,
            duration: duration_seconds,
            ..Self::default()
        }
    }

    /// RequestPath 策略阀门。
    pub fn request_path(limit: u64, duration_seconds: u64) -> Self {
        Self {
            policy: Policy::RequestPath,
            limit,
            duration: duration_seconds,
            ..Self::default()
        }
    }

    /// Cookie 策略阀门（`key` 为 Cookie 名）。
    pub fn cookie(key: impl Into<String>, limit: u64, duration_seconds: u64) -> Self {
        Self {
            policy: Policy::Cookie,
            policy_key: key.into(),
            limit,
            duration: duration_seconds,
            ..Self::default()
        }
    }

    /// Form 策略阀门（`key` 为 urlencoded 字段名）。
    pub fn form(key: impl Into<String>, limit: u64, duration_seconds: u64) -> Self {
        Self {
            policy: Policy::Form,
            policy_key: key.into(),
            limit,
            duration: duration_seconds,
            ..Self::default()
        }
    }

    /// 设置优先级（越大越先检查）。
    pub fn priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// 设置识别值为空时的处理方式。
    pub fn when_null(mut self, when_null: WhenNull) -> Self {
        self.when_null = when_null;
        self
    }

    /// 设置超限返回格式。
    pub fn return_type(mut self, return_type: ThrottleReturnType) -> Self {
        self.return_type = return_type;
        self
    }

    /// 设置策略键。
    pub fn policy_key(mut self, key: impl Into<String>) -> Self {
        self.policy_key = key.into();
        self
    }

    /// 是否生效（`limit > 0 && duration > 0`，对齐 C# 过滤条件）。
    pub fn is_effective(&self) -> bool {
        self.limit > 0 && self.duration > 0
    }
}

/// 单条限流规则（对齐 C# 一个 Action 上的一组 `[RateValve]`）。
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ThrottleRule {
    /// 规则名（用于计数键/日志；缺省用 `方法 路径`）
    pub name: String,
    /// HTTP 方法（空或 `*` = 任意）
    pub method: String,
    /// 路径匹配：精确、尾部 `*` 前缀、`{param}` 段占位（大小写不敏感）
    pub path: String,
    /// 是否启用
    pub enable: bool,
    /// 阀门列表（检查时按 `priority` 降序）
    pub valves: Vec<RateValve>,
}

impl Default for ThrottleRule {
    fn default() -> Self {
        Self {
            name: String::new(),
            method: String::new(),
            path: String::new(),
            enable: true,
            valves: Vec::new(),
        }
    }
}

impl ThrottleRule {
    /// 新建规则（`method` 空/`*` = 任意方法；`path` 空/`*` = 任意路径）。
    pub fn new(
        method: impl Into<String>,
        path: impl Into<String>,
        valves: Vec<RateValve>,
    ) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            valves,
            ..Self::default()
        }
    }

    /// 设置规则名。
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// 设置是否启用。
    pub fn enabled(mut self, enable: bool) -> Self {
        self.enable = enable;
        self
    }

    /// 追加一个阀门。
    pub fn with_valve(mut self, valve: RateValve) -> Self {
        self.valves.push(valve);
        self
    }
}

/// 限流配置（`Config/Throttle.toml`）。
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ThrottleConfig {
    /// 总开关（对齐 C# `AllowRateLimter`）
    pub enable: bool,
    /// 计数键前缀（默认 `dh`）
    pub key_prefix: String,
    /// 超限是否写告警日志
    pub log_blocked: bool,
    /// 是否信任 `X-Forwarded-For` / `X-Real-IP`（默认 **否**——防止客户端伪造；
    /// 只有在反向代理会覆盖这两个头时才开启）
    pub trust_forwarded_for: bool,
    /// 跳过限流的路径前缀（如静态资源；大小写不敏感）
    pub skip_paths: Vec<String>,
    /// 规则列表（多个规则可同时匹配，各自独立计数）
    pub rules: Vec<ThrottleRule>,
}

impl Default for ThrottleConfig {
    fn default() -> Self {
        Self {
            enable: true,
            key_prefix: "dh".to_string(),
            log_blocked: true,
            trust_forwarded_for: false,
            skip_paths: Vec::new(),
            rules: Vec::new(),
        }
    }
}

/// 配置模板头（带注释；`TomlConfig` 以此补齐缺失键）。
const CONFIG_HEADER: &str = "\
# Pek.RWaf 接口级限流配置（TOML；保存后 ≤10 秒自动生效）
# 规则按「方法 + 路径」匹配，可多条同时生效；每条规则可声明多个阀门（priority 越大越先检查）。
#
# policy: ip / userIdentity / header / query / requestPath / cookie / form
# whenNull: pass（识别值为空 → 跳过该阀门）/ intercept（用客户端 IP 生成空值标识继续限流）
# returnType: jsonDResult（{code,msg}）/ jsonDgResult（DGResult）/ text
#
# 示例：
# [[rules]]
# name = \"POST /api/auth/login\"
# method = \"POST\"
# path = \"/api/auth/login\"
# [[rules.valves]]
# policy = \"ip\"
# limit = 5
# duration = 60
# whenNull = \"pass\"
# priority = 1
# returnType = \"jsonDResult\"
";

/// 配置模板中标量字段（`rules` 由 `save_with_arrays` 单独维护）。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScalarTemplate<'a> {
    enable: bool,
    key_prefix: &'a str,
    log_blocked: bool,
    trust_forwarded_for: bool,
    skip_paths: &'a [String],
}

impl ThrottleConfig {
    /// 从 `path` 加载；文件不存在时写入默认模板并返回默认值。
    pub fn load_or_create(path: &Path) -> Result<Self, String> {
        if !path.exists() && !path.with_extension("json").exists() {
            let cfg = Self::default();
            let _ = cfg.save(path); // 写失败不致命（只读目录等）
            return Ok(cfg);
        }
        Self::load_file(path, &Self::default())
    }

    /// 从 `path` 加载；文件中缺失的字段用 `default` 补齐（文件优先；旧版 JSON 自动迁移）。
    pub fn load_merging(path: &Path, default: &Self) -> Result<Self, String> {
        if !path.exists() && !path.with_extension("json").exists() {
            return Err(format!("配置文件不存在：{}", path.display()));
        }
        Self::load_file(path, default)
    }

    fn load_file(path: &Path, default: &Self) -> Result<Self, String> {
        let template = Self::template_of(default)?;
        let opts = dhrust::config::ConfigOptions {
            create_on_missing: false, // 由调用方决定是否创建
            repair_corrupt: false,    // 热加载/报错场景不改动用户文件
        };
        let cfg = dhrust::config::TomlConfig::<Self>::try_load_with(path, &template, opts)
            .map_err(|e| e.to_string())?;
        Ok(cfg.into_value())
    }

    /// 保存到 `path`（自动建目录；标量保留注释，`rules` 按数组表同步）。
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let template = Self::template_of(self)?;
        let mut cfg = dhrust::config::TomlConfig::from_value(path, &template, self.clone());
        let rules = serde_json::to_value(&self.rules)
            .map_err(|e| format!("序列化限流规则失败：{e}"))?;
        let empty = Vec::new();
        let entries = rules.as_array().unwrap_or(&empty);
        cfg.save_with_arrays(&[("rules", entries)])
            .map_err(|e| e.to_string())
    }

    fn template_of(cfg: &Self) -> Result<String, String> {
        let scalars = ScalarTemplate {
            enable: cfg.enable,
            key_prefix: &cfg.key_prefix,
            log_blocked: cfg.log_blocked,
            trust_forwarded_for: cfg.trust_forwarded_for,
            skip_paths: &cfg.skip_paths,
        };
        let body = toml::to_string_pretty(&scalars)
            .map_err(|e| format!("序列化限流配置失败：{e}"))?;
        let mut out = String::with_capacity(CONFIG_HEADER.len() + body.len() + 16);
        out.push_str(CONFIG_HEADER);
        out.push('\n');
        out.push_str(&body);
        if !body.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("rules = []\n");
        Ok(out)
    }
}

/// 超限信息（日志/自定义响应/诊断）。
#[derive(Clone, Debug)]
pub struct LimitInfo {
    /// 规则显示名
    pub rule: String,
    /// 请求方法
    pub method: String,
    /// 请求路径
    pub path: String,
    /// 命中的策略
    pub policy: Policy,
    /// 策略键
    pub policy_key: String,
    /// 窗口内允许次数
    pub limit: u64,
    /// 窗口长度（秒）
    pub duration: u64,
    /// 当前窗口计数（含本次）
    pub count: u64,
    /// 距窗口结束的剩余时间（用于 `Retry-After`）
    pub retry_after: Duration,
    /// 返回格式
    pub return_type: ThrottleReturnType,
    /// 客户端 IP
    pub client_ip: String,
}

/// 限流判定结果。
#[derive(Clone, Debug)]
pub enum ThrottleVerdict {
    /// 放行
    Allow,
    /// 超限
    Limited(LimitInfo),
}

impl ThrottleVerdict {
    /// 是否放行。
    pub fn is_allow(&self) -> bool {
        matches!(self, ThrottleVerdict::Allow)
    }

    /// 超限信息（放行时为 `None`）。
    pub fn limited(&self) -> Option<&LimitInfo> {
        match self {
            ThrottleVerdict::Limited(info) => Some(info),
            ThrottleVerdict::Allow => None,
        }
    }
}

type UserIdentityFn = dyn Fn(&Ctx) -> Option<String> + Send + Sync;
type ClientIpFn = dyn Fn(&Ctx) -> String + Send + Sync;
type LimitedResponseFn = dyn Fn(&LimitInfo) -> HttpResponse + Send + Sync;

/// 接口级限流引擎（线程安全；配置热重载、计数引擎可替换）。
pub struct Throttle {
    config: RwLock<Arc<ThrottleConfig>>,
    limiter: WindowLimiter,
    user_identity: RwLock<Option<Arc<UserIdentityFn>>>,
    client_ip: RwLock<Option<Arc<ClientIpFn>>>,
    response: RwLock<Option<Arc<LimitedResponseFn>>>,
    file: Option<PathBuf>,
    preset: ThrottleConfig,
    base_dir: PathBuf,
    last_check: AtomicI64,
    last_mtime: AtomicU64,
}

impl Throttle {
    /// 以默认配置构建（无规则 = 不放行任何限流，便于随后 [`Throttle::add_rule`]）。
    pub fn new() -> Arc<Self> {
        Self::with_config(ThrottleConfig::default())
    }

    /// 以内存配置构建（无文件热重载）。
    pub fn with_config(config: ThrottleConfig) -> Arc<Self> {
        Self::with_config_and_limiter(config, WindowLimiter::new())
    }

    /// 以内存配置 + 自定义计数存储构建（如 Redis 共享计数）。
    pub fn with_store(config: ThrottleConfig, store: Arc<dyn CounterStore>) -> Arc<Self> {
        Self::with_config_and_limiter(config, WindowLimiter::with_store(store))
    }

    /// 以内存配置 + 自定义计数引擎构建。
    pub fn with_config_and_limiter(
        config: ThrottleConfig,
        limiter: WindowLimiter,
    ) -> Arc<Self> {
        let mut config = config;
        normalize_config(&mut config);
        let base_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        Arc::new(Self {
            config: RwLock::new(Arc::new(config.clone())),
            limiter,
            user_identity: RwLock::new(None),
            client_ip: RwLock::new(None),
            response: RwLock::new(None),
            file: None,
            preset: config,
            base_dir,
            last_check: AtomicI64::new(0),
            last_mtime: AtomicU64::new(0),
        })
    }

    /// 便捷构建：使用给定规则集（无配置文件）。
    pub fn with_rules(rules: Vec<ThrottleRule>) -> Arc<Self> {
        Self::with_config(ThrottleConfig {
            rules,
            ..ThrottleConfig::default()
        })
    }

    /// 从项目基础目录加载（`{base}/Config/Throttle.toml`；文件不存在时自动生成默认模板）。
    pub fn load(base: &Path) -> Arc<Self> {
        Self::load_with_default(base, ThrottleConfig::default())
    }

    /// 同 [`Throttle::load`]，但首启生成的模板使用指定预设。
    pub fn load_with_default(base: &Path, default: ThrottleConfig) -> Arc<Self> {
        Self::load_with_default_and_limiter(base, default, WindowLimiter::new())
    }

    /// 从文件加载并使用自定义计数存储（如 Redis 共享计数）。
    pub fn load_with_store(base: &Path, store: Arc<dyn CounterStore>) -> Arc<Self> {
        Self::load_with_default_and_limiter(
            base,
            ThrottleConfig::default(),
            WindowLimiter::with_store(store),
        )
    }

    fn load_with_default_and_limiter(
        base: &Path,
        default: ThrottleConfig,
        limiter: WindowLimiter,
    ) -> Arc<Self> {
        let file = base.join(CONFIG_REL);
        if !file.exists() && !file.with_extension("json").exists() {
            let _ = default.save(&file);
        }
        let mut config = match ThrottleConfig::load_merging(&file, &default) {
            Ok(c) => c,
            Err(e) => {
                dhrust::logs::log().warn(&format!(
                    "[RateLimiter] 配置加载失败，使用默认策略（无限流规则）：{e}"
                ));
                default.clone()
            }
        };
        normalize_config(&mut config);
        let throttle = Arc::new(Self {
            config: RwLock::new(Arc::new(config)),
            limiter,
            user_identity: RwLock::new(None),
            client_ip: RwLock::new(None),
            response: RwLock::new(None),
            file: Some(file),
            preset: default,
            base_dir: base.to_path_buf(),
            last_check: AtomicI64::new(0),
            last_mtime: AtomicU64::new(0),
        });
        throttle.stamp_mtime(&base.join(CONFIG_REL));
        throttle
    }

    /// 当前配置副本（面板展示/诊断）。
    pub fn config(&self) -> ThrottleConfig {
        self.snapshot().as_ref().clone()
    }

    /// 基础目录。
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    fn snapshot(&self) -> Arc<ThrottleConfig> {
        match self.config.read() {
            Ok(g) => Arc::clone(&g),
            Err(p) => Arc::clone(&p.into_inner()),
        }
    }

    fn set_config(&self, mut config: ThrottleConfig) {
        normalize_config(&mut config);
        let config = Arc::new(config);
        match self.config.write() {
            Ok(mut w) => *w = config,
            Err(p) => *p.into_inner() = config,
        }
    }

    /// 面板保存入口：覆盖配置——先写文件（存在路径时），再立即生效并清零计数。
    pub fn apply_config(&self, config: ThrottleConfig) -> Result<(), String> {
        let mut config = config;
        normalize_config(&mut config);
        if let Some(file) = &self.file {
            config.save(file)?;
        }
        self.set_config(config);
        self.limiter.clear();
        if let Some(file) = &self.file {
            self.stamp_mtime(file);
        }
        Ok(())
    }

    /// 追加一条规则并立即生效（无配置文件时仅内存生效）。
    pub fn add_rule(&self, rule: ThrottleRule) -> Result<(), String> {
        let mut config = self.config();
        config.rules.push(rule);
        self.apply_config(config)
    }

    /// 手动重载配置（校验失败保留旧配置）。
    pub fn reload(&self) {
        let Some(file) = self.file.clone() else {
            return;
        };
        if !file.exists() {
            let current = self.config();
            let _ = current.save(&file);
            return;
        }
        match ThrottleConfig::load_merging(&file, &self.preset) {
            Ok(config) => {
                self.set_config(config);
                self.limiter.clear();
                self.stamp_mtime(&file);
            }
            Err(e) => {
                dhrust::logs::log().warn(&format!(
                    "[RateLimiter] 配置热重载失败（保留旧配置）：{e}"
                ));
            }
        }
    }

    /// 清零全部计数（配置重载后自动调用）。
    pub fn clear_counters(&self) {
        self.limiter.clear();
    }

    /// 自定义用户身份提取（默认读取 `Ctx.state` 的常用用户键）。
    pub fn set_user_identity(
        &self,
        f: impl Fn(&Ctx) -> Option<String> + Send + Sync + 'static,
    ) {
        set_hook(&self.user_identity, Arc::new(f));
    }

    /// 自定义客户端 IP 提取（默认 `RemoteAddr` 去端口；`trustForwardedFor` 开启时读代理头）。
    pub fn set_client_ip(&self, f: impl Fn(&Ctx) -> String + Send + Sync + 'static) {
        set_hook(&self.client_ip, Arc::new(f));
    }

    /// 自定义超限响应（默认 429 + 配置的返回格式）。
    pub fn set_limited_response(
        &self,
        f: impl Fn(&LimitInfo) -> HttpResponse + Send + Sync + 'static,
    ) {
        set_hook(&self.response, Arc::new(f));
    }

    fn stamp_mtime(&self, file: &Path) {
        if let Ok(meta) = std::fs::metadata(file)
            && let Ok(t) = meta.modified()
            && let Ok(d) = t.duration_since(std::time::UNIX_EPOCH)
        {
            self.last_mtime.store(d.as_millis() as u64, Ordering::Relaxed);
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
        if self
            .last_check
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let Ok(meta) = std::fs::metadata(file) else {
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

    /// 对请求上下文执行限流检查（同步；中间件/guard 内部使用）。
    pub fn check(&self, ctx: &Ctx) -> ThrottleVerdict {
        self.maybe_reload();
        let cfg = self.snapshot();
        if !cfg.enable {
            return ThrottleVerdict::Allow;
        }
        let path_lower = ctx.req.path.to_ascii_lowercase();
        if is_skipped(&cfg, &path_lower) {
            return ThrottleVerdict::Allow;
        }
        let ip = self.client_ip(ctx);
        for rule in &cfg.rules {
            if !rule_matches(rule, &ctx.req.method, &path_lower) {
                continue;
            }
            if let Some(info) = self.check_rule(&cfg, rule, ctx, &ip) {
                return ThrottleVerdict::Limited(info);
            }
        }
        ThrottleVerdict::Allow
    }

    /// 对原始 HTTP 请求执行限流检查（便捷入口；内部构造 [`Ctx`]）。
    pub fn check_http(&self, req: &HttpRequest) -> ThrottleVerdict {
        self.check(&Ctx::build(req.clone()))
    }

    fn check_rule(
        &self,
        cfg: &ThrottleConfig,
        rule: &ThrottleRule,
        ctx: &Ctx,
        ip: &str,
    ) -> Option<LimitInfo> {
        for valve in &rule.valves {
            if !valve.is_effective() {
                continue;
            }
            let Some(value) = self.effective_value(ctx, valve, ip) else {
                continue; // WhenNull::Pass：跳过当前阀门
            };
            let key = counter_key(cfg, rule, valve, &value);
            let decision = self
                .limiter
                .hit(&key, valve.limit, Duration::from_secs(valve.duration));
            if decision.allowed {
                continue;
            }
            let info = LimitInfo {
                rule: display_rule(rule),
                method: ctx.req.method.clone(),
                path: ctx.req.path.clone(),
                policy: valve.policy,
                policy_key: valve.policy_key.clone(),
                limit: valve.limit,
                duration: valve.duration,
                count: decision.count,
                retry_after: decision.reset_in,
                return_type: valve.return_type,
                client_ip: ip.to_string(),
            };
            if cfg.log_blocked {
                dhrust::logs::log().warn(&format!(
                    "[RateLimiter] 触发限流! API={} Policy={} IP={} Count={} Limit={} Duration={}s",
                    info.rule,
                    valve.policy.as_key(),
                    ip,
                    info.count,
                    info.limit,
                    info.duration
                ));
            }
            return Some(info);
        }
        None
    }

    fn client_ip(&self, ctx: &Ctx) -> String {
        if let Some(f) = get_hook(&self.client_ip) {
            return f(ctx);
        }
        if self.snapshot().trust_forwarded_for
            && let Some(xff) = ctx
                .header("x-forwarded-for")
                .or_else(|| ctx.header("x-real-ip"))
            && let Some(first) = xff.split(',').next()
        {
            let ip = first.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
        dhrust::net::panel_auth::client_ip(ctx)
    }

    fn user_identity(&self, ctx: &Ctx) -> Option<String> {
        if let Some(f) = get_hook(&self.user_identity) {
            return f(ctx);
        }
        // 鉴权中间件把用户写入 Ctx.state（键名按生态既有约定依次尝试）
        const KEYS: &[&str] = &["user_id", "userId", "userid", "user", "username", "sub"];
        for key in KEYS {
            if let Some(value) = ctx.state.get(*key)
                && !value.is_empty()
            {
                return Some(value.clone());
            }
        }
        None
    }

    fn policy_value(&self, ctx: &Ctx, valve: &RateValve, ip: &str) -> Option<String> {
        let value = match valve.policy {
            Policy::Ip => {
                if ip.is_empty() || ip.eq_ignore_ascii_case("unknown") {
                    None
                } else {
                    // 对齐 C#：IP 无效（无法转数字）视为空值，交给 WhenNull 处理
                    dhrust::net::ip_to_num(ip)
                }
            }
            Policy::UserIdentity => self.user_identity(ctx),
            Policy::Header => ctx.header(&valve.policy_key).map(str::to_string),
            Policy::Query => ctx.query_value(&valve.policy_key).map(str::to_string),
            Policy::RequestPath => Some(ctx.req.path.clone()),
            Policy::Cookie => cookie_value(ctx, &valve.policy_key),
            Policy::Form => ctx.form_value(&valve.policy_key).map(str::to_string),
        };
        value.filter(|v| !v.is_empty())
    }

    fn effective_value(&self, ctx: &Ctx, valve: &RateValve, ip: &str) -> Option<String> {
        if let Some(value) = self.policy_value(ctx, valve, ip) {
            return Some(value);
        }
        match valve.when_null {
            WhenNull::Pass => None,
            WhenNull::Intercept => Some(format!(
                "empty_value_{}",
                dhrust::sign::md5_short(if ip.is_empty() { "unknown" } else { ip })
            )),
        }
    }

    /// 生成超限响应（默认 429；可经 [`Throttle::set_limited_response`] 覆盖）。
    pub fn limited_response(&self, info: &LimitInfo) -> HttpResponse {
        if let Some(f) = get_hook(&self.response) {
            return f(info);
        }
        const MESSAGE: &str = "访问过于频繁，请稍后重试！";
        let mut resp = match info.return_type {
            ThrottleReturnType::Text => HttpResponse::text(429, MESSAGE),
            ThrottleReturnType::JsonDResult => HttpResponse::json(
                429,
                format!(
                    "{{\"code\":{},\"msg\":{}}}",
                    state::BUSY,
                    dhrust::net::http::json_escape(MESSAGE)
                ),
            ),
            ThrottleReturnType::JsonDgResult => {
                HttpResponse::json(429, DGResult::error(state::BUSY, MESSAGE).to_json())
            }
        };
        let retry_after = info.retry_after.as_secs().max(1).to_string();
        resp = resp
            .with_header(HEADER_STATUS, "0")
            .with_header("Retry-After", &retry_after)
            .with_header("X-RateLimit-Limit", &info.limit.to_string())
            .with_header("X-RateLimit-Remaining", "0")
            .with_header("Cache-Control", "no-store");
        resp
    }

    /// 生成 dhrust 中间件（`router.use_middleware(throttle.middleware())`）。
    pub fn middleware(self: &Arc<Self>) -> Middleware {
        let engine = Arc::clone(self);
        middleware(move |mut ctx, next| {
            let engine = Arc::clone(&engine);
            async move {
                match engine.check(&ctx) {
                    ThrottleVerdict::Allow => {
                        set_header(&mut ctx.req.headers, HEADER_STATUS, "1");
                        let mut outcome = next(ctx).await;
                        if let HttpOutcome::Response(resp) = &mut outcome {
                            set_header(&mut resp.headers, HEADER_STATUS, "1");
                        }
                        outcome
                    }
                    ThrottleVerdict::Limited(info) => {
                        set_header(&mut ctx.req.headers, HEADER_STATUS, "0");
                        HttpOutcome::Response(engine.limited_response(&info))
                    }
                }
            }
        })
    }

    /// 包裹单个路由处理器（规则写在代码里；不必进配置文件）。
    ///
    /// 与 [`Throttle::middleware`] 同时使用时，同一路由会被配置规则与本规则**各计一次**
    /// （如需叠加多策略，建议全部写进一条规则的多阀门，避免重复计数）。
    pub fn guard(
        self: &Arc<Self>,
        rule: ThrottleRule,
        handler: RouteHandler,
    ) -> RouteHandler {
        let engine = Arc::clone(self);
        let mut rule = rule;
        normalize_rule(&mut rule);
        route(move |mut ctx: Ctx| {
            let engine = Arc::clone(&engine);
            let rule = rule.clone();
            let handler = Arc::clone(&handler);
            async move {
                engine.maybe_reload();
                let cfg = engine.snapshot();
                let path_lower = ctx.req.path.to_ascii_lowercase();
                let skip = !cfg.enable
                    || !rule.enable
                    || !rule_matches(&rule, &ctx.req.method, &path_lower)
                    || is_skipped(&cfg, &path_lower);
                if skip {
                    return handler(ctx).await;
                }
                let ip = engine.client_ip(&ctx);
                match engine.check_rule(&cfg, &rule, &ctx, &ip) {
                    None => {
                        set_header(&mut ctx.req.headers, HEADER_STATUS, "1");
                        let mut outcome = handler(ctx).await;
                        if let HttpOutcome::Response(resp) = &mut outcome {
                            set_header(&mut resp.headers, HEADER_STATUS, "1");
                        }
                        outcome
                    }
                    Some(info) => {
                        set_header(&mut ctx.req.headers, HEADER_STATUS, "0");
                        HttpOutcome::Response(engine.limited_response(&info))
                    }
                }
            }
        })
    }
}

impl Default for Throttle {
    fn default() -> Self {
        // `Throttle` 通常以 `Arc` 使用；这里只提供无文件的内存实例
        let mut config = ThrottleConfig::default();
        normalize_config(&mut config);
        Self {
            config: RwLock::new(Arc::new(config.clone())),
            limiter: WindowLimiter::new(),
            user_identity: RwLock::new(None),
            client_ip: RwLock::new(None),
            response: RwLock::new(None),
            file: None,
            preset: config,
            base_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            last_check: AtomicI64::new(0),
            last_mtime: AtomicU64::new(0),
        }
    }
}

fn normalize_config(config: &mut ThrottleConfig) {
    for rule in &mut config.rules {
        normalize_rule(rule);
    }
}

fn normalize_rule(rule: &mut ThrottleRule) {
    // 稳定排序：同优先级保持声明顺序
    rule.valves
        .sort_by_key(|valve| std::cmp::Reverse(valve.priority));
}

fn is_skipped(cfg: &ThrottleConfig, path_lower: &str) -> bool {
    cfg.skip_paths.iter().any(|p| {
        let p = p.trim();
        !p.is_empty() && path_lower.starts_with(&p.to_ascii_lowercase())
    })
}

fn rule_matches(rule: &ThrottleRule, method: &str, path_lower: &str) -> bool {
    if !rule.enable {
        return false;
    }
    let rule_method = rule.method.trim();
    if !rule_method.is_empty()
        && rule_method != "*"
        && !rule_method.eq_ignore_ascii_case(method)
    {
        return false;
    }
    path_matches(&rule.path, path_lower)
}

fn path_matches(pattern: &str, path_lower: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() || pattern == "*" {
        return true;
    }
    let pattern = pattern.to_ascii_lowercase();
    if let Some(prefix) = pattern.strip_suffix('*') {
        return path_lower.starts_with(prefix);
    }
    if pattern.contains('{') {
        let pats: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
        let segs: Vec<&str> = path_lower.split('/').filter(|s| !s.is_empty()).collect();
        if pats.len() != segs.len() {
            return false;
        }
        return pats
            .iter()
            .zip(segs.iter())
            .all(|(pat, seg)| is_param(pat) || pat == seg);
    }
    pattern == path_lower
}

fn is_param(segment: &str) -> bool {
    segment.starts_with('{') && segment.ends_with('}') && segment.len() > 2
}

fn display_rule(rule: &ThrottleRule) -> String {
    if !rule.name.trim().is_empty() {
        return rule.name.trim().to_string();
    }
    if !rule.path.trim().is_empty() {
        return format!("{} {}", rule.method.trim(), rule.path.trim())
            .trim()
            .to_string();
    }
    GLOBAL_API_KEY.to_string()
}

fn counter_key(
    cfg: &ThrottleConfig,
    rule: &ThrottleRule,
    valve: &RateValve,
    value: &str,
) -> String {
    let api = if !rule.name.trim().is_empty() {
        rule.name.trim().to_ascii_lowercase()
    } else if !rule.path.trim().is_empty() {
        format!("{} {}", rule.method.trim(), rule.path.trim())
            .trim()
            .to_ascii_lowercase()
    } else {
        GLOBAL_API_KEY.to_string()
    };
    let prefix = if cfg.key_prefix.trim().is_empty() {
        "dh"
    } else {
        cfg.key_prefix.trim()
    };
    let policy = valve.policy.as_key();
    let key_hash = if valve.policy_key.trim().is_empty() {
        None
    } else {
        Some(dhrust::sign::md5_short(&valve.policy_key))
    };
    let value_hash = if value.is_empty() {
        None
    } else {
        Some(dhrust::sign::md5_short(value))
    };
    match (key_hash, value_hash) {
        (Some(k), Some(v)) => format!("{prefix}:rl:{policy}:{k}:{v}:{api}"),
        (None, Some(v)) => format!("{prefix}:rl:{policy}:{v}:{api}"),
        _ => format!("{prefix}:rl:{policy}:{api}"),
    }
}

fn cookie_value(ctx: &Ctx, name: &str) -> Option<String> {
    if name.is_empty() {
        return None;
    }
    let raw = ctx.header("cookie")?;
    let mut ci_match = None;
    for part in raw.split(';') {
        let part = part.trim();
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        // 精确优先；找不到再退化为大小写不敏感（对齐 ASP.NET Core 的常见行为）
        if k == name {
            return Some(v.trim().to_string());
        }
        if ci_match.is_none() && k.eq_ignore_ascii_case(name) {
            ci_match = Some(v.trim().to_string());
        }
    }
    ci_match
}

fn set_header(headers: &mut Vec<(String, String)>, name: &str, value: &str) {
    if let Some((_, slot)) = headers
        .iter_mut()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
    {
        *slot = value.to_string();
    } else {
        headers.push((name.to_string(), value.to_string()));
    }
}

fn set_hook<T: ?Sized>(slot: &RwLock<Option<Arc<T>>>, hook: Arc<T>) {
    match slot.write() {
        Ok(mut w) => *w = Some(hook),
        Err(p) => *p.into_inner() = Some(hook),
    }
}

fn get_hook<T: ?Sized>(slot: &RwLock<Option<Arc<T>>>) -> Option<Arc<T>> {
    match slot.read() {
        Ok(g) => g.clone(),
        Err(p) => p.into_inner().clone(),
    }
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
    use dhrust::net::router::Router;

    fn make_ctx(
        method: &str,
        path_with_query: &str,
        headers: &[(&str, &str)],
        body: &str,
        remote_ip: &str,
    ) -> Ctx {
        let (path, query) = match path_with_query.split_once('?') {
            Some((p, q)) => (p.to_string(), q.to_string()),
            None => (path_with_query.to_string(), String::new()),
        };
        let mut hs: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        if !body.is_empty()
            && !hs
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        {
            hs.push((
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ));
        }
        Ctx::build(HttpRequest {
            method: method.to_string(),
            path,
            query,
            headers: hs,
            body: bytes::Bytes::from(body.to_string()),
            remote_addr: Some(format!("{remote_ip}:54321")),
        })
    }

    fn req(method: &str, path: &str, remote_ip: &str) -> HttpRequest {
        HttpRequest {
            method: method.to_string(),
            path: path.to_string(),
            query: String::new(),
            headers: Vec::new(),
            body: bytes::Bytes::new(),
            remote_addr: Some(format!("{remote_ip}:54321")),
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pek-rwaf-throttle-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("建目录");
        dir
    }

    #[test]
    fn ip_policy_limits_and_isolates() {
        let throttle = Throttle::with_rules(vec![ThrottleRule::new(
            "GET",
            "/api/ip",
            vec![RateValve::ip(2, 60)],
        )]);
        for _ in 0..2 {
            assert!(throttle.check(&make_ctx("GET", "/api/ip", &[], "", "8.8.8.8")).is_allow());
        }
        let info = throttle
            .check(&make_ctx("GET", "/api/ip", &[], "", "8.8.8.8"))
            .limited()
            .expect("第三次应超限")
            .clone();
        assert_eq!(info.policy, Policy::Ip);
        assert_eq!(info.count, 3);
        assert_eq!(info.limit, 2);
        assert!(info.retry_after <= Duration::from_secs(60));
        // 不同 IP 独立
        assert!(throttle.check(&make_ctx("GET", "/api/ip", &[], "", "9.9.9.9")).is_allow());
    }

    #[test]
    fn method_and_path_matching() {
        assert!(path_matches("/api/login", "/api/login"));
        assert!(!path_matches("/api/login", "/api/login2"));
        assert!(path_matches("/api/admin/*", "/api/admin/logs"));
        assert!(!path_matches("/api/admin/*", "/api/admin"));
        assert!(path_matches("/api/users/{id}", "/api/users/42"));
        assert!(!path_matches("/api/users/{id}", "/api/users/42/orders"));
        assert!(path_matches("", "/anything"));
        assert!(path_matches("*", "/anything"));

        let rule = ThrottleRule::new("POST", "/api/login", vec![RateValve::ip(1, 60)]);
        assert!(!rule_matches(&rule, "GET", "/api/login"));
        assert!(rule_matches(&rule, "post", "/api/login"));
        assert!(!rule_matches(&rule, "POST", "/api/logout"));
        assert!(!rule_matches(&rule.clone().enabled(false), "POST", "/api/login"));
    }

    #[test]
    fn when_null_pass_skips_valve() {
        let throttle = Throttle::with_rules(vec![ThrottleRule::new(
            "GET",
            "/api/pass",
            vec![RateValve::header("X-Key", 1, 60).when_null(WhenNull::Pass)],
        )]);
        for _ in 0..5 {
            assert!(
                throttle
                    .check(&make_ctx("GET", "/api/pass", &[], "", "1.1.1.1"))
                    .is_allow(),
                "WhenNull::Pass 时识别值为空应跳过该阀门"
            );
        }
        // 有值时正常限流
        let with_key = make_ctx("GET", "/api/pass", &[("X-Key", "v")], "", "2.2.2.2");
        assert!(throttle.check(&with_key).is_allow());
        let with_key = make_ctx("GET", "/api/pass", &[("X-Key", "v")], "", "2.2.2.2");
        assert!(!throttle.check(&with_key).is_allow());
    }

    #[test]
    fn when_null_intercept_counts_by_client_ip() {
        let throttle = Throttle::with_rules(vec![ThrottleRule::new(
            "GET",
            "/api/intercept",
            vec![
                RateValve::header("X-Key", 1, 60).when_null(WhenNull::Intercept),
            ],
        )]);
        assert!(
            throttle
                .check(&make_ctx("GET", "/api/intercept", &[], "", "3.3.3.3"))
                .is_allow()
        );
        let info = throttle
            .check(&make_ctx("GET", "/api/intercept", &[], "", "3.3.3.3"))
            .limited()
            .expect("同 IP 无值应共享计数")
            .clone();
        assert_eq!(info.policy, Policy::Header);
        // 不同 IP 的空值标识不同
        assert!(
            throttle
                .check(&make_ctx("GET", "/api/intercept", &[], "", "4.4.4.4"))
                .is_allow()
        );
    }

    #[test]
    fn multiple_valves_follow_priority() {
        let throttle = Throttle::with_rules(vec![ThrottleRule::new(
            "GET",
            "/api/priority",
            vec![
                RateValve::ip(100, 60).priority(1),
                RateValve::header("X-Token", 1, 60).priority(10),
            ],
        )]);
        let with_token = || {
            make_ctx(
                "GET",
                "/api/priority",
                &[("X-Token", "token")],
                "",
                "5.5.5.5",
            )
        };
        assert!(throttle.check(&with_token()).is_allow());
        let info = throttle
            .check(&with_token())
            .limited()
            .expect("高优先级 Header 阀门应先命中")
            .clone();
        assert_eq!(info.policy, Policy::Header);
        assert_eq!(info.limit, 1);
    }

    #[test]
    fn query_cookie_form_and_path_policies() {
        // Query
        let query = Throttle::with_rules(vec![ThrottleRule::new(
            "GET",
            "/api/query",
            vec![RateValve::query("api_key", 1, 60)],
        )]);
        assert!(
            query
                .check(&make_ctx("GET", "/api/query?api_key=a", &[], "", "6.6.6.6"))
                .is_allow()
        );
        assert!(
            !query
                .check(&make_ctx("GET", "/api/query?api_key=a", &[], "", "6.6.6.6"))
                .is_allow()
        );
        assert!(
            query
                .check(&make_ctx("GET", "/api/query?api_key=b", &[], "", "6.6.6.6"))
                .is_allow(),
            "不同查询值应独立计数"
        );

        // Cookie（大小写不敏感兜底）
        let cookie = Throttle::with_rules(vec![ThrottleRule::new(
            "GET",
            "/api/cookie",
            vec![RateValve::cookie("sid", 1, 60)],
        )]);
        assert!(
            cookie
                .check(&make_ctx(
                    "GET",
                    "/api/cookie",
                    &[("Cookie", "SID=abc; theme=dark")],
                    "",
                    "6.6.6.6"
                ))
                .is_allow()
        );
        assert!(
            !cookie
                .check(&make_ctx(
                    "GET",
                    "/api/cookie",
                    &[("Cookie", "SID=abc")],
                    "",
                    "6.6.6.6"
                ))
                .is_allow()
        );

        // Form（urlencoded）
        let form = Throttle::with_rules(vec![ThrottleRule::new(
            "POST",
            "/api/form",
            vec![RateValve::form("uid", 1, 60)],
        )]);
        assert!(
            form.check(&make_ctx(
                "POST",
                "/api/form",
                &[],
                "uid=u1&x=1",
                "7.7.7.7"
            ))
            .is_allow()
        );
        assert!(
            !form
                .check(&make_ctx("POST", "/api/form", &[], "uid=u1", "7.7.7.7"))
                .is_allow()
        );

        // RequestPath：规则路径用前缀匹配多个路径，计数按实际路径区分
        let path = Throttle::with_rules(vec![ThrottleRule::new(
            "GET",
            "/api/path/*",
            vec![RateValve::request_path(1, 60)],
        )]);
        assert!(
            path.check(&make_ctx("GET", "/api/path/a", &[], "", "8.8.8.8"))
                .is_allow()
        );
        assert!(
            path.check(&make_ctx("GET", "/api/path/b", &[], "", "8.8.8.8"))
                .is_allow()
        );
        assert!(
            !path
                .check(&make_ctx("GET", "/api/path/a", &[], "", "8.8.8.8"))
                .is_allow()
        );
    }

    #[test]
    fn user_identity_policy_reads_ctx_state_and_hook() {
        let throttle = Throttle::with_rules(vec![ThrottleRule::new(
            "GET",
            "/api/user",
            vec![RateValve::user_identity(1, 60)],
        )]);
        let mut ctx = make_ctx("GET", "/api/user", &[], "", "9.9.9.9");
        ctx.set_state("user_id", "u1");
        assert!(throttle.check(&ctx).is_allow());
        let mut ctx = make_ctx("GET", "/api/user", &[], "", "9.9.9.9");
        ctx.set_state("user_id", "u1");
        assert!(!throttle.check(&ctx).is_allow());
        let mut ctx = make_ctx("GET", "/api/user", &[], "", "9.9.9.9");
        ctx.set_state("user_id", "u2");
        assert!(throttle.check(&ctx).is_allow(), "不同用户应独立计数");

        // 自定义提取器优先于 state
        let custom = Throttle::with_rules(vec![ThrottleRule::new(
            "GET",
            "/api/user",
            vec![RateValve::user_identity(1, 60)],
        )]);
        custom.set_user_identity(|ctx| ctx.header("X-User").map(str::to_string));
        let h = |user: &str| {
            make_ctx(
                "GET",
                "/api/user",
                &[("X-User", user)],
                "",
                "9.9.9.9",
            )
        };
        assert!(custom.check(&h("alice")).is_allow());
        assert!(!custom.check(&h("alice")).is_allow());
        assert!(custom.check(&h("bob")).is_allow());
    }

    #[test]
    fn response_formats_and_headers() {
        let throttle = Throttle::with_rules(vec![ThrottleRule::new(
            "GET",
            "/api/resp",
            vec![RateValve::ip(1, 60)],
        )]);
        assert!(
            throttle
                .check(&make_ctx("GET", "/api/resp", &[], "", "1.1.1.1"))
                .is_allow()
        );
        let info = throttle
            .check(&make_ctx("GET", "/api/resp", &[], "", "1.1.1.1"))
            .limited()
            .expect("应超限")
            .clone();
        let resp = throttle.limited_response(&info);
        assert_eq!(resp.status, 429);
        let body = String::from_utf8_lossy(&resp.body);
        assert!(body.contains("\"code\":99"), "DResult 响应体：{body}");
        // 对齐 .NET `JavaScriptEncoder.Default`：非 ASCII 转义为 \uXXXX
        assert!(body.contains("\\u8BBF"), "DResult 响应体：{body}");
        assert!(header_value(&resp.headers, "Retry-After").is_some());
        assert_eq!(
            header_value(&resp.headers, HEADER_STATUS),
            Some("0".to_string())
        );
        assert_eq!(
            header_value(&resp.headers, "X-RateLimit-Limit"),
            Some("1".to_string())
        );

        // 文本与 DGResult
        let text_info = LimitInfo {
            return_type: ThrottleReturnType::Text,
            ..info.clone()
        };
        let resp = throttle.limited_response(&text_info);
        assert!(String::from_utf8_lossy(&resp.body).contains("访问过于频繁"));
        let dg_info = LimitInfo {
            return_type: ThrottleReturnType::JsonDgResult,
            ..info.clone()
        };
        let resp = throttle.limited_response(&dg_info);
        let body = String::from_utf8_lossy(&resp.body);
        assert!(body.contains("\"Code\":99"), "DGResult 响应体：{body}");

        // 自定义响应
        let custom = Throttle::with_rules(vec![ThrottleRule::new(
            "GET",
            "/api/resp",
            vec![RateValve::ip(1, 60)],
        )]);
        custom.set_limited_response(|_info| HttpResponse::text(429, "custom"));
        assert!(
            custom
                .check(&make_ctx("GET", "/api/resp", &[], "", "1.1.1.1"))
                .is_allow()
        );
        let info = custom
            .check(&make_ctx("GET", "/api/resp", &[], "", "1.1.1.1"))
            .limited()
            .unwrap()
            .clone();
        assert_eq!(&custom.limited_response(&info).body[..], b"custom");
    }

    fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }

    #[test]
    fn config_roundtrip_and_reload() {
        let dir = temp_dir("config");
        let file = dir.join(CONFIG_REL);
        let cfg = ThrottleConfig {
            key_prefix: "test".to_string(),
            rules: vec![ThrottleRule::new(
                "POST",
                "/api/login",
                vec![RateValve::ip(3, 120).priority(2)],
            )],
            ..ThrottleConfig::default()
        };
        cfg.save(&file).expect("保存配置");
        let text = std::fs::read_to_string(&file).expect("读配置");
        assert!(text.contains("keyPrefix = \"test\""), "配置内容：{text}");
        assert!(text.contains("rules"), "规则数组应落盘：{text}");

        let loaded =
            ThrottleConfig::load_merging(&file, &ThrottleConfig::default()).expect("加载配置");
        assert_eq!(loaded.key_prefix, "test");
        assert_eq!(loaded.rules.len(), 1);
        assert_eq!(loaded.rules[0].valves[0].limit, 3);
        assert_eq!(loaded.rules[0].valves[0].duration, 120);

        let throttle = Throttle::load(&dir);
        let c = || make_ctx("POST", "/api/login", &[], "", "2.2.2.2");
        for _ in 0..3 {
            assert!(throttle.check(&c()).is_allow());
        }
        assert!(!throttle.check(&c()).is_allow());

        // 外部改小 limit → reload 后立即生效，且计数清零
        let mut changed = loaded.clone();
        changed.rules[0].valves[0].limit = 1;
        changed.save(&file).expect("改配置");
        throttle.reload();
        assert!(throttle.check(&c()).is_allow(), "重载后计数应清零");
        assert!(!throttle.check(&c()).is_allow(), "新 limit=1 应生效");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_config_clears_counters_and_skip_paths() {
        let throttle = Throttle::with_rules(vec![ThrottleRule::new(
            "GET",
            "/api/apply",
            vec![RateValve::ip(1, 60)],
        )]);
        let c = || make_ctx("GET", "/api/apply", &[], "", "3.3.3.3");
        assert!(throttle.check(&c()).is_allow());
        assert!(!throttle.check(&c()).is_allow());

        let cfg = throttle.config();
        throttle.apply_config(cfg).expect("应用配置");
        assert!(throttle.check(&c()).is_allow(), "应用配置后计数应清零");

        let mut cfg = throttle.config();
        cfg.skip_paths = vec!["/api/apply".to_string()];
        throttle.apply_config(cfg).expect("应用跳过配置");
        for _ in 0..5 {
            assert!(throttle.check(&c()).is_allow(), "skipPaths 应跳过");
        }
    }

    #[test]
    fn legacy_json_is_migrated_to_toml() {
        let dir = temp_dir("legacy");
        let legacy = dir.join(LEGACY_CONFIG_REL);
        std::fs::create_dir_all(legacy.parent().expect("父目录")).expect("建目录");
        std::fs::write(
            &legacy,
            r#"{"enable":true,"keyPrefix":"old","rules":[{"method":"GET","path":"/x","valves":[{"policy":"ip","limit":7,"duration":30}]}]}"#,
        )
        .expect("写旧配置");
        let file = dir.join(CONFIG_REL);
        let cfg = ThrottleConfig::load_or_create(&file).expect("迁移");
        assert_eq!(cfg.key_prefix, "old");
        assert_eq!(cfg.rules.len(), 1);
        assert_eq!(cfg.rules[0].valves[0].limit, 7);
        assert!(file.is_file(), "应生成 TOML");
        assert!(!legacy.exists(), "旧 JSON 应改名");
        assert!(legacy.with_extension("json.bak").is_file(), "旧文件应备份");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disabled_switch_allows_everything() {
        let cfg = ThrottleConfig {
            enable: false,
            rules: vec![ThrottleRule::new(
                "GET",
                "/api/off",
                vec![RateValve::ip(1, 60)],
            )],
            ..ThrottleConfig::default()
        };
        let throttle = Throttle::with_config(cfg);
        for _ in 0..5 {
            assert!(
                throttle
                    .check(&make_ctx("GET", "/api/off", &[], "", "4.4.4.4"))
                    .is_allow()
            );
        }
    }

    #[tokio::test]
    async fn middleware_enforces_and_sets_status_headers() {
        let throttle = Throttle::with_rules(vec![ThrottleRule::new(
            "GET",
            "/api/ping",
            vec![RateValve::ip(1, 60)],
        )]);
        let mut router = Router::new();
        router.use_middleware(throttle.middleware());
        router.map_get(
            "/api/ping",
            route(|_ctx| async { HttpOutcome::Response(HttpResponse::text(200, "pong")) }),
        );
        let handler = router.into_handler();

        let first = handler(req("GET", "/api/ping", "9.9.9.9")).await;
        match first {
            HttpOutcome::Response(resp) => {
                assert_eq!(resp.status, 200);
                assert_eq!(
                    header_value(&resp.headers, HEADER_STATUS),
                    Some("1".to_string())
                );
            }
            _ => panic!("应为普通响应"),
        }

        let second = handler(req("GET", "/api/ping", "9.9.9.9")).await;
        match second {
            HttpOutcome::Response(resp) => {
                assert_eq!(resp.status, 429);
                assert_eq!(
                    header_value(&resp.headers, HEADER_STATUS),
                    Some("0".to_string())
                );
                assert!(header_value(&resp.headers, "Retry-After").is_some());
            }
            _ => panic!("应为普通响应"),
        }
    }

    #[tokio::test]
    async fn guard_wraps_single_handler() {
        let throttle = Throttle::new();
        let rule = ThrottleRule::new("GET", "/api/one", vec![RateValve::ip(1, 60)]);
        let guarded = throttle.guard(
            rule,
            route(|_ctx| async { HttpOutcome::Response(HttpResponse::text(200, "ok")) }),
        );
        let mut router = Router::new();
        router.map_get("/api/one", guarded);
        let handler = router.into_handler();

        let first = handler(req("GET", "/api/one", "6.6.6.6")).await;
        match first {
            HttpOutcome::Response(resp) => {
                assert_eq!(resp.status, 200);
                assert_eq!(
                    header_value(&resp.headers, HEADER_STATUS),
                    Some("1".to_string())
                );
            }
            _ => panic!("应为普通响应"),
        }
        let second = handler(req("GET", "/api/one", "6.6.6.6")).await;
        match second {
            HttpOutcome::Response(resp) => {
                assert_eq!(resp.status, 429);
                assert_eq!(
                    header_value(&resp.headers, HEADER_STATUS),
                    Some("0".to_string())
                );
            }
            _ => panic!("应为普通响应"),
        }
    }
}
