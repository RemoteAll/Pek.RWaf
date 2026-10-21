//! WAF 配置：`Config/Waf.json`（首启自动生成模板；mtime 变化热重载）。

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::rules::Rule;

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

/// WAF 配置（`Config/Waf.json`；缺省字段自动补默认值）。
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
    /// CC 限速（每 IP 每分钟请求数；0 = 关闭；放行类机器人豁免；静态资源不计数）
    pub rate_limit_per_min: u32,
    /// 拦截日志
    pub log_blocked: bool,
    /// 详细日志（记录放行/监控命中）
    pub verbose: bool,
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
            ruleset: None,
        }
    }

    /// 从 `path` 加载；文件不存在时写入默认模板并返回默认。
    pub fn load_or_create(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            let cfg = Self::default();
            let _ = cfg.save(path); // 写失败不致命（如只读目录）
            return Ok(cfg);
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("读取 {} 失败：{e}", path.display()))?;
        serde_json::from_str::<Self>(&text)
            .map_err(|e| format!("解析 {} 失败：{e}", path.display()))
    }

    /// 从 `path` 加载；文件中缺失的字段用 `default` 补齐（文件优先）。
    ///
    /// 与 [`Self::load_or_create`] 的差别：后者缺失字段落回 `WafConfig::default()`，
    /// 会丢掉调用方预设（例如 DHDeploy Agent 的 `skipBotPrefixes=["/api"]`）——
    /// 旧版本生成的配置文件不含新字段时，预设被静默清空
    /// （2026-10-21 直连 `RestSharp` UA 被误拦即此原因）。
    pub fn load_merging(path: &Path, default: &Self) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("读取 {} 失败：{e}", path.display()))?;
        let mut base = serde_json::to_value(default)
            .map_err(|e| format!("序列化预设配置失败：{e}"))?;
        let over: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| format!("解析 {} 失败：{e}", path.display()))?;
        merge_missing(&mut base, &over);
        serde_json::from_value(base).map_err(|e| format!("解析 {} 失败：{e}", path.display()))
    }

    /// 保存到 `path`（自动建目录）。
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let text = serde_json::to_string_pretty(self).map_err(|e| format!("序列化失败：{e}"))?;
        std::fs::write(path, text).map_err(|e| format!("写入 {} 失败：{e}", path.display()))
    }
}

/// 把 `over` 合并进 `base`：对象递归合并，`over` 中缺失的键保留 `base` 的值。
fn merge_missing(base: &mut serde_json::Value, over: &serde_json::Value) {
    match (base, over) {
        (serde_json::Value::Object(b), serde_json::Value::Object(o)) => {
            for (k, v) in o {
                match b.get_mut(k) {
                    Some(slot) => merge_missing(slot, v),
                    None => {
                        b.insert(k.clone(), v.clone());
                    }
                }
            }
        }
        (slot, v) => *slot = v.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_defaults() {
        let dir = std::env::temp_dir().join(format!("pek-waf-cfg-{}", std::process::id()));
        let file = dir.join("Config/Waf.json");
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
        std::fs::write(&file, r#"{ "enable": true }"#).unwrap();
        let partial = WafConfig::load_or_create(&file).unwrap();
        assert_eq!(partial.mode, WafMode::AdminApi); // 落回默认（admin_api）
        assert_eq!(partial.rate_limit_per_min, 300);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_missing_keys_inherit_preset() {
        let dir = std::env::temp_dir().join(format!("pek-waf-merge-{}", std::process::id()));
        let file = dir.join("Waf.json");
        std::fs::create_dir_all(&dir).unwrap();
        // 旧文件：不含 skipBotPrefixes（模拟升级前生成）
        std::fs::write(&file, r#"{ "enable": true, "blockMaliciousBots": true }"#).unwrap();

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
        std::fs::write(&file, r#"{ "skipBotPrefixes": [] }"#).unwrap();
        let merged2 = WafConfig::load_merging(&file, &preset).unwrap();
        assert!(merged2.skip_bot_prefixes.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bad_json_reports_error() {
        let dir = std::env::temp_dir().join(format!("pek-waf-bad-{}", std::process::id()));
        let file = dir.join("Waf.json");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&file, "{ not json").unwrap();
        assert!(WafConfig::load_or_create(&file).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
