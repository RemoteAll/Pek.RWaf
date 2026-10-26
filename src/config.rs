//! WAF 配置：`Config/Waf.toml`（首启自动生成模板；mtime 变化热重载）。
//!
//! # 格式
//! **TOML**（可写注释，运维可直接改文件）；读写统一走 `dhrust::config::TomlConfig`
//! （= `Config<T>` 的 TOML 版：缺失生成、缺键带注释补齐、类型容错、损坏备份重建），
//! 本库**不重复实现配置管线**。
//!
//! 旧版 `Config/Waf.json` 仍会被读取：首次加载时自动迁移为 TOML、原文件备份为 `Waf.json.bak`。

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::rules::Rule;

/// 配置文件相对基础目录的路径。
pub const CONFIG_REL: &str = "Config/Waf.toml";
/// 旧版 JSON 配置（存在时自动迁移）。
pub const LEGACY_CONFIG_REL: &str = "Config/Waf.json";

/// 站点模式（决定默认策略组合与文档语义）。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WafMode {
    /// 前台公开站点：放行搜索引擎 / GEO-AI 抓取 / 社交预览；`/admin` 等敏感前缀内全禁。
    PublicSite,
    /// 管理端 / API 站点：一律不放行机器人；全站从严。
    AdminApi,
}

/// 单项防护动作。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Action {
    /// 关闭
    Off,
    /// 仅记录（放行）
    Monitor,
    /// 拦截（403）
    Block,
}

/// WAF 配置（`Config/Waf.toml`；缺省字段自动补默认值）。
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct WafConfig {
    /// 总开关
    pub enable: bool,
    /// 模式（仅语义标记；策略由下列具体开关决定）
    pub mode: WafMode,
    /// 拦截空 User-Agent（默认关：服务器间调用（如 .NET HttpClient / dhrust 本客户端）常无 UA，
    /// 开启前请确认没有内部调用链路）
    pub block_empty_ua: bool,
    /// 回环地址（127.0.0.1/::1）豁免全部检查（保护本地工具/冒烟脚本；生产可关）
    pub loopback_bypass: bool,
    /// IP 白名单（精确 / CIDR / 通配符 `192.168.*.*`；逗号或分号分隔）
    pub ip_whitelist: Vec<String>,
    /// IP 黑名单
    pub ip_blacklist: Vec<String>,
    /// 自定义放行 UA 子串（优先于全部恶意判定）
    pub extra_allow_bots: Vec<String>,
    /// 自定义拦截 UA 子串（先于名单分类）
    pub extra_block_bots: Vec<String>,
    /// 放行搜索引擎蜘蛛
    pub allow_search_bots: bool,
    /// 放行 GEO / AI 抓取器（GPTBot/ClaudeBot/PerplexityBot…）
    pub allow_ai_bots: bool,
    /// 放行社交平台链接预览
    pub allow_social_previews: bool,
    /// 拦截恶意爬虫 / 扫描器（MJ12bot/sqlmap/python-requests/curl…）
    pub block_malicious_bots: bool,
    /// 敏感前缀（如 `/admin`）：命中后禁止一切机器人、攻击特征强制拦截
    pub sensitive_prefixes: Vec<String>,
    /// 跳过攻击特征检测的路径前缀（本体即“执行 SQL / 传文件”的管理端点；
    /// 这些端点的安全由业务层护栏（只读 SQL 校验、权限、审计）负责；bot/IP/CC 检查不受影响）
    pub skip_attack_prefixes: Vec<String>,    /// 跳过机器人拦截的路径前缀（机器对机器 API——如产测工具调用接口；
    /// 攻击检测/IP 名单/CC 限速不受影响）
    pub skip_bot_prefixes: Vec<String>,
    /// 跨站来源校验（CSRF 防护）：浏览器发起的**非安全方法**请求（POST/PUT/PATCH/DELETE）校验
    /// `Sec-Fetch-Site` / `Origin`——跨站拒绝（含 `Origin: null`），同源与无来源头（curl / 服务间调用）放行。
    /// **该检查先于回环豁免**：浏览器跨站请求的源 IP 恰为回环（localhost/面板免登录场景防护）。
    pub csrf_guard: bool,
    /// SQL 注入动作（默认拦截）
    pub sqli_action: Action,
    /// XSS 动作（默认仅记录——表单富文本场景易误报）
    pub xss_action: Action,
    /// 路径穿越 / 敏感路径探测动作（默认拦截）
    pub path_action: Action,
    /// 命令注入动作（默认仅记录）
    pub cmd_action: Action,
    /// CC 限速（每 IP 首次命中起 60 秒窗口内的请求数；0 = 关闭；放行类机器人豁免；静态资源不计数）
    pub rate_limit_per_min: u32,
    /// 拦截日志
    pub log_blocked: bool,
    /// 详细日志（记录放行/监控命中）
    pub verbose: bool,
    /// 请求体扫描上限（字节；默认 64 KB）：只扫前 N 字节，防大 body 造成 CPU 开销；
    /// 设为 0 时回退到 16 KB 保守值
    pub body_scan_limit: usize,
    /// 对**非文本** Content-Type 的请求体也做扫描（lossy 转文本）。
    /// 默认关（图片/二进制上传易误报）；本项目这类「只有 JSON/表单」的服务应打开，
    /// 否则攻击者改个 `Content-Type: application/octet-stream` 就能绕过 body 检测
    pub body_scan_all_types: bool,
    /// 自定义规则集（C# Pek.WAF 兼容 JSON；命中即拦截）
    pub ruleset: Option<Rule>,
}

impl Default for WafConfig {
    /// 默认 = [`WafConfig::admin_api`]（安全从严）。
    fn default() -> Self {
        Self::admin_api()
    }
}

impl WafConfig {
    /// 前台公开站点预设：正常搜索引擎 / GEO-AI / 社交预览放行；恶意爬虫拦截；`/admin` 从严。
    pub fn public_site() -> Self {
        Self {
            enable: true,
            mode: WafMode::PublicSite,
            block_empty_ua: false,
            loopback_bypass: true,
            ip_whitelist: Vec::new(),
            ip_blacklist: Vec::new(),
            extra_allow_bots: Vec::new(),
            extra_block_bots: Vec::new(),
            allow_search_bots: true,
            allow_ai_bots: true,
            allow_social_previews: true,
            block_malicious_bots: true,
            sensitive_prefixes: vec!["/admin".to_string()],
            skip_attack_prefixes: Vec::new(),
            skip_bot_prefixes: Vec::new(),
            csrf_guard: true,
            sqli_action: Action::Block,
            xss_action: Action::Monitor,
            path_action: Action::Block,
            cmd_action: Action::Monitor,
            rate_limit_per_min: 600,
            log_blocked: true,
            verbose: false,
            body_scan_limit: 64 * 1024,
            body_scan_all_types: false,
            ruleset: None,
        }
    }

    /// 管理端 / API 预设：不放行任何机器人；全站从严（XSS/命令注入也拦截）。
    pub fn admin_api() -> Self {
        Self {
            enable: true,
            mode: WafMode::AdminApi,
            block_empty_ua: false,
            loopback_bypass: true,
            ip_whitelist: Vec::new(),
            ip_blacklist: Vec::new(),
            extra_allow_bots: Vec::new(),
            extra_block_bots: Vec::new(),
            allow_search_bots: false,
            allow_ai_bots: false,
            allow_social_previews: false,
            block_malicious_bots: true,
            sensitive_prefixes: Vec::new(),
            skip_attack_prefixes: Vec::new(),
            skip_bot_prefixes: Vec::new(),
            csrf_guard: true,
            sqli_action: Action::Block,
            xss_action: Action::Block,
            path_action: Action::Block,
            cmd_action: Action::Block,
            rate_limit_per_min: 300,
            log_blocked: true,
            verbose: false,
            body_scan_limit: 64 * 1024,
            body_scan_all_types: true,
            ruleset: None,
        }
    }

    /// 从 `path` 加载；文件不存在时写入默认模板并返回默认。
    ///
    /// `path` 指向 `Config/Waf.toml`；若它不存在但同目录的 `Waf.json` 存在，
    /// **由 `dhrust::config::TomlConfig` 自动迁移**（写 TOML、旧文件备份为 `.json.bak`，
    /// 缺失键继承本调用预设）——本库不写迁移代码。
    pub fn load_or_create(path: &Path) -> Result<Self, String> {
        if !path.exists() && !path.with_extension("json").exists() {
            let cfg = Self::default();
            let _ = cfg.save(path); // 写失败不致命（如只读目录）
            return Ok(cfg);
        }
        Self::load_file(path, &Self::default())
    }

    /// 从 `path` 加载；文件中缺失的字段用 `default` 补齐（文件优先；旧版 JSON 自动迁移）。
    ///
    /// 与 [`Self::load_or_create`] 的差别：后者缺失字段落回 `WafConfig::default()`，
    /// 会丢掉调用方预设（例如 DHDeploy Agent 的 `skipBotPrefixes=["/api"]`）——
    /// 旧版本生成的配置文件不含新字段时，预设被静默清空
    /// （2026-10-21 直连 `RestSharp` UA 被误拦即此原因）。
    pub fn load_merging(path: &Path, default: &Self) -> Result<Self, String> {
        if !path.exists() && !path.with_extension("json").exists() {
            return Err(format!("配置文件不存在：{}", path.display()));
        }
        Self::load_file(path, default)
    }

    /// 以 `default` 为模板/类型基准读取 TOML（缺键补齐、类型容错；解析失败返回错误）。
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

    /// 保存到 `path`（自动建目录；以当前值为模板，保留已有注释）。
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let template = Self::template_of(self)?;
        let mut cfg = dhrust::config::TomlConfig::from_value(path, &template, self.clone());
        cfg.save().map_err(|e| e.to_string())
    }

    /// 生成带注释头的 TOML 模板（内容 = 给定配置；字段齐全）。
    fn template_of(cfg: &Self) -> Result<String, String> {
        let body = toml::to_string_pretty(cfg).map_err(|e| format!("序列化 WAF 配置失败：{e}"))?;
        Ok(format!(
            "# Pek.WAF 配置（TOML；保存后自动热生效）\n\
             # 字段含义见 Pek.RWaf 文档 / 宿主后台「安全」页；可手工修改后保存。\n\
             # 旧版 Config/Waf.json 会在首次启动时自动迁移为本文件（并备份为 .json.bak）。\n\n{body}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_defaults() {
        let dir = std::env::temp_dir().join(format!("pek-waf-cfg-{}", std::process::id()));
        let file = dir.join(CONFIG_REL);
        let cfg = WafConfig::public_site();
        cfg.save(&file).unwrap();
        let loaded = WafConfig::load_or_create(&file).unwrap();
        assert_eq!(loaded.mode, WafMode::PublicSite);
        assert!(loaded.allow_search_bots);
        assert!(loaded.allow_ai_bots);
        assert_eq!(loaded.sqli_action, Action::Block);
        assert_eq!(loaded.xss_action, Action::Monitor);
        assert_eq!(loaded.sensitive_prefixes, vec!["/admin".to_string()]);
        // 缺省字段容错（旧文件缺新字段）
        std::fs::write(&file, "enable = true\n").unwrap();
        let partial = WafConfig::load_or_create(&file).unwrap();
        assert_eq!(partial.mode, WafMode::AdminApi); // 落回默认（admin_api）
        assert_eq!(partial.rate_limit_per_min, 300);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_missing_keys_inherit_preset() {
        let dir = std::env::temp_dir().join(format!("pek-waf-merge-{}", std::process::id()));
        let file = dir.join("Waf.toml");
        std::fs::create_dir_all(&dir).unwrap();
        // 旧文件：不含 skipBotPrefixes（模拟升级前生成）
        std::fs::write(&file, "enable = true\nblockMaliciousBots = true\n").unwrap();

        let mut preset = WafConfig::admin_api();
        preset.skip_bot_prefixes = vec!["/api".to_string()];
        preset.skip_attack_prefixes = vec!["/api".to_string()];

        let merged = WafConfig::load_merging(&file, &preset).unwrap();
        // 文件里的值优先
        assert!(merged.enable);
        assert!(merged.block_malicious_bots);
        // 文件缺失的键继承预设
        assert_eq!(merged.skip_bot_prefixes, vec!["/api".to_string()]);
        assert_eq!(merged.skip_attack_prefixes, vec!["/api".to_string()]);

        // 文件里显式给出空数组时尊重文件（不继承预设）
        std::fs::write(&file, "skipBotPrefixes = []\n").unwrap();
        let merged2 = WafConfig::load_merging(&file, &preset).unwrap();
        assert!(merged2.skip_bot_prefixes.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ruleset_survives_toml_roundtrip() {
        let dir = std::env::temp_dir().join(format!("pek-waf-rules-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let file = dir.join(CONFIG_REL);
        let mut cfg = WafConfig::admin_api();
        cfg.ruleset = Some(serde_json::from_str(r#"{
            "Operator": "OrElse",
            "Rules": [
                { "MemberName": "Path", "Operator": "EndsWith", "Inputs": [".php", 42, true] }
            ]
        }"#).unwrap());
        cfg.save(&file).expect("保存 TOML（含规则集）");
        let loaded = WafConfig::load_merging(&file, &WafConfig::default()).expect("读回");
        assert!(loaded.ruleset.is_some(), "规则集不能丢");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_json_is_migrated_to_toml() {
        let dir = std::env::temp_dir().join(format!("pek-waf-mig-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let legacy = dir.join(LEGACY_CONFIG_REL);
        std::fs::create_dir_all(legacy.parent().expect("父目录")).expect("建目录");
        std::fs::write(&legacy, r#"{ "enable": true, "rateLimitPerMin": 42 }"#).expect("写旧配置");
        let file = dir.join(CONFIG_REL);
        let cfg = WafConfig::load_or_create(&file).expect("加载/迁移");
        assert!(cfg.enable);
        assert_eq!(cfg.rate_limit_per_min, 42);
        assert!(file.is_file(), "应生成 TOML");
        assert!(!legacy.exists(), "旧 JSON 应改名");
        assert!(legacy.with_extension("json.bak").is_file(), "旧文件应备份");
        // 新文件能被再次读回（确认是合法 TOML）
        let again = WafConfig::load_merging(&file, &WafConfig::default()).expect("读回 TOML");
        assert_eq!(again.rate_limit_per_min, 42);
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn bad_json_reports_error() {
        let dir = std::env::temp_dir().join(format!("pek-waf-bad-{}", std::process::id()));
        let file = dir.join("Waf.toml");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&file, "enable = = broken\n").unwrap();
        assert!(WafConfig::load_or_create(&file).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

