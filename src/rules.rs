//! 自定义规则引擎：**与 C# `Pek.WAF` 的 Ruleset JSON 格式兼容**（同一份规则文件可双端共用），
//! 并在 C# 操作符全集之上新增 `IsBotKind`（按爬虫分类命中）。
//!
//! 规则 JSON（根/逻辑节点/叶节点一体，`OrElse` 任一命中、`AndAlso` 全部命中；命中即拦截）：
//! ```json
//! { "Operator": "OrElse", "Rules": [
//!   { "MemberName": "Path", "Operator": "EndsWith", "Inputs": [".php"] },
//!   { "MemberName": "UserAgent", "Operator": "IsBotKind", "TargetValue": "Malicious" }
//! ] }
//! ```
//! 支持成员：`Path` / `Method` / `UserAgent` / `RemoteIp`(`IpAddress`) / `QueryString` / `ContentType`；
//! 操作符：`EndsWith`/`StartsWith`/`Contains`/`Equals`/`IsMatch`(正则)/`IsInInput`/`IsInteger`/`IsDouble`/
//! `IsInIpList`/`IsNotInIpList`/`InSubnet`/`IpInFile`/`Equal`/`ContainsUserAgent`/`NotContainsUserAgent`/
//! `IsInUserAgentList`/`IsNotInUserAgentList`/`UserAgentStartsWith`/`UserAgentIsEmpty`/`UserAgentIsNotEmpty`/
//! `IsBotKind`；`Negate: true` 可取反；`IpCountry` 需外部 GeoIP 数据（未内置，恒不命中）。

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::bots::{self, BotKind};
use crate::wafreq::{WafRequest, ip_in_list, load_ip_file};

/// 规则节点（C# 兼容 JSON 形态）。
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct Rule {
    /// 叶节点：成员名（逻辑节点为空）
    #[serde(default)]
    pub member_name: Option<String>,
    /// 操作符（叶=条件操作符；节点=OrElse/AndAlso）
    #[serde(default)]
    pub operator: Option<String>,
    /// 输入值列表（字符串/数字混合）
    #[serde(default)]
    pub inputs: Vec<Value>,
    /// 目标值（部分操作符使用）
    #[serde(default)]
    pub target_value: Option<String>,
    /// 取反
    #[serde(default)]
    pub negate: bool,
    /// 子规则（逻辑节点）
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// 编译后的规则节点。
#[derive(Debug)]
pub enum Compiled {
    /// 逻辑组合（`and = true` 为 AndAlso）
    Logical {
        and: bool,
        children: Vec<Compiled>,
    },
    /// 叶子条件
    Leaf {
        /// 人类可读描述（日志）
        label: String,
        /// 成员名（原样，求值时大小写不敏感匹配）
        member: String,
        /// 操作符（原样，小写比较）
        op: String,
        /// 输入值（字符串化；IpInFile 已展开为文件内容）
        inputs: Vec<String>,
        /// 目标值
        target: String,
        /// 取反
        negate: bool,
        /// 预编译正则（IsMatch）
        regex: Option<Regex>,
    },
}

/// 编译规则树（`base_dir` 用于 `IpInFile` 相对路径）。
pub fn compile(rule: &Rule, base_dir: &std::path::Path) -> Result<Compiled, String> {
    compile_inner(rule, base_dir).map_err(|e| format!("规则编译失败：{e}"))
}

fn compile_inner(rule: &Rule, base_dir: &std::path::Path) -> Result<Compiled, String> {
    if !rule.rules.is_empty() {
        let and = rule
            .operator
            .as_deref()
            .map(|o| o.eq_ignore_ascii_case("AndAlso"))
            .unwrap_or(false);
        let mut children = Vec::with_capacity(rule.rules.len());
        for r in &rule.rules {
            children.push(compile_inner(r, base_dir)?);
        }
        return Ok(Compiled::Logical { and, children });
    }

    let member = rule.member_name.clone().unwrap_or_default();
    let op = rule.operator.clone().unwrap_or_default();
    let op_lower = op.to_ascii_lowercase();
    let mut inputs: Vec<String> = rule
        .inputs
        .iter()
        .map(|v| match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .collect();
    let target = rule.target_value.clone().unwrap_or_default();

    // IpInFile：编译期加载文件内容（热重载时重新编译 → 自动重读）
    if op_lower == "ipinfile"
        && let Some(file) = inputs.first().cloned()
    {
        let path = base_dir.join(&file);
        inputs = load_ip_file(&path);
        if inputs.is_empty() {
            return Err(format!("IpInFile 为空或不可读：{}", path.display()));
        }
    }

    // IsMatch：预编译正则
    let regex = if op_lower == "ismatch" {
        let pattern = if !target.is_empty() {
            target.clone()
        } else {
            inputs.first().cloned().unwrap_or_default()
        };
        Some(Regex::new(&pattern).map_err(|e| format!("IsMatch 正则无效（{pattern}）：{e}"))?)
    } else {
        None
    };

    let label = format!("{member}/{op}{}", if target.is_empty() { String::new() } else { format!("({target})") });
    Ok(Compiled::Leaf {
        label,
        member,
        op: op_lower,
        inputs,
        target,
        negate: rule.negate,
        regex,
    })
}

/// 求值：命中返回 `true`（语义与 C# 一致——true = 拦截）。
pub fn eval(node: &Compiled, req: &WafRequest) -> bool {
    match node {
        Compiled::Logical { and, children } => {
            if *and {
                children.iter().all(|c| eval(c, req))
            } else {
                children.iter().any(|c| eval(c, req))
            }
        }
        Compiled::Leaf {
            member,
            op,
            inputs,
            target,
            negate,
            regex,
            ..
        } => {
            let value = req.member(member);
            let mut result = eval_leaf(op, inputs, target, regex, value, &req.user_agent);
            if *negate {
                result = !result;
            }
            result
        }
    }
}

fn eval_leaf(
    op: &str,
    inputs: &[String],
    target: &str,
    regex: &Option<Regex>,
    value: &str,
    user_agent: &str,
) -> bool {
    let lower = value.to_ascii_lowercase();
    let ua_lower = user_agent.to_ascii_lowercase();
    let eq_i = |a: &str, b: &str| a.eq_ignore_ascii_case(b);
    match op {
        "endswith" => inputs.iter().any(|i| lower.ends_with(&i.to_ascii_lowercase())),
        "startswith" => inputs.iter().any(|i| lower.starts_with(&i.to_ascii_lowercase())),
        "contains" => inputs.iter().any(|i| lower.contains(&i.to_ascii_lowercase())),
        "equals" | "equal" => inputs.iter().any(|i| eq_i(value, i)) || (!target.is_empty() && eq_i(value, target)),
        "ismatch" => regex.as_ref().map(|r| r.is_match(value)).unwrap_or(false),
        "isinput" => inputs.iter().any(|i| eq_i(value, i)),
        "isinteger" => value.trim().parse::<i64>().is_ok(),
        "isdouble" | "issingle" | "isdecimal" => value.trim().parse::<f64>().is_ok(),
        _ => eval_ext(op, inputs, target, value, &ua_lower),
    }
}

fn eval_ext(
    op: &str,
    inputs: &[String],
    target: &str,
    value: &str,
    ua_lower: &str,
) -> bool {
    match op {
        // —— IP 系（成员为 RemoteIp/IpAddress 时）——
        "isiniplist" => ip_in_list(value, &inputs.join(",")),
        "isnotiniplist" => !ip_in_list(value, &inputs.join(",")),
        "insubnet" => {
            let net = inputs.first().cloned().unwrap_or_default();
            let mask = inputs.get(1).cloned().unwrap_or_default();
            crate::wafreq::ip_match(value, &format!("{net}/{mask}"))
        }
        "ipinfile" => ip_in_list(value, &inputs.join(",")),
        // —— UA 系（对 UserAgent 成员操作，忽略大小写）——
        "containsuseragent" => inputs.iter().any(|i| ua_lower.contains(&i.to_ascii_lowercase())),
        "notcontainsuseragent" => !inputs.iter().any(|i| ua_lower.contains(&i.to_ascii_lowercase())),
        "isinuseragentlist" => inputs.iter().any(|i| ua_lower == i.to_ascii_lowercase()),
        "isnotinuseragentlist" => !inputs.iter().any(|i| ua_lower == i.to_ascii_lowercase()),
        "useragentstartswith" => inputs.iter().any(|i| ua_lower.starts_with(&i.to_ascii_lowercase())),
        "useragentisempty" => ua_lower.trim().is_empty(),
        "useragentisnotempty" => !ua_lower.trim().is_empty(),
        // —— 扩展：按爬虫分类命中 ——
        "isbotkind" => {
            let wanted = if !target.is_empty() {
                target.to_ascii_lowercase()
            } else {
                inputs.first().map(|i| i.to_ascii_lowercase()).unwrap_or_default()
            };
            match bots::classify(value) {
                Some(k) => match wanted.as_str() {
                    "any" => true,
                    "friendly" => k.is_friendly(),
                    "searchengine" => k == BotKind::SearchEngine,
                    "aicrawler" => k == BotKind::AiCrawler,
                    "socialpreview" => k == BotKind::SocialPreview,
                    "monitor" => k == BotKind::Monitor,
                    "malicious" => k == BotKind::Malicious,
                    "unknown" => k == BotKind::Unknown,
                    _ => false,
                },
                None => false,
            }
        }
        // 未知操作符：不命中（宽容，避免误拦）
        _ => false,
    }
}

impl Compiled {
    /// 人类可读描述（日志）。
    pub fn label(&self) -> String {
        match self {
            Compiled::Logical { and, children } => {
                let op = if *and { "AndAlso" } else { "OrElse" };
                let parts: Vec<String> = children.iter().map(|c| c.label()).collect();
                format!("{op}({})", parts.join(", "))
            }
            Compiled::Leaf { label, negate, .. } => {
                if *negate {
                    format!("NOT {label}")
                } else {
                    label.clone()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(ua: &str) -> WafRequest {
        WafRequest {
            path: "/x.php".to_string(),
            method: "GET".to_string(),
            query: String::new(),
            user_agent: ua.to_string(),
            remote_ip: "8.8.8.8".to_string(),
            content_type: String::new(),
            body_text: String::new(),
        }
    }

    #[test]
    fn csharp_readme_ruleset_works() {
        // C# Pek.WAF README 的示例规则（原样 JSON）
        let json = r#"{
            "Operator": "OrElse",
            "Rules": [
                { "MemberName": "Path", "Operator": "EndsWith", "Inputs": [".php"] },
                { "MemberName": "Path", "Operator": "EndsWith", "Inputs": [".env"] },
                { "MemberName": "Path", "Operator": "EndsWith", "Inputs": [".git"] }
            ]
        }"#;
        let rule: Rule = serde_json::from_str(json).unwrap();
        let compiled = compile(&rule, std::path::Path::new(".")).unwrap();
        assert!(eval(&compiled, &req("Mozilla/5.0")));
        let mut r2 = req("Mozilla/5.0");
        r2.path = "/index.html".to_string();
        assert!(!eval(&compiled, &r2));
    }

    #[test]
    fn ip_and_ua_operators() {
        let json = r#"{ "MemberName": "RemoteIp", "Operator": "IsInIpList", "Inputs": ["10.0.0.0/8, 192.168.*.*"] }"#;
        let rule: Rule = serde_json::from_str(json).unwrap();
        let c = compile(&rule, std::path::Path::new(".")).unwrap();
        let mut r = req("Mozilla/5.0");
        r.remote_ip = "10.1.2.3".to_string();
        assert!(eval(&c, &r));
        r.remote_ip = "8.8.8.8".to_string();
        assert!(!eval(&c, &r));

        let json = r#"{ "MemberName": "UserAgent", "Operator": "IsBotKind", "TargetValue": "Malicious" }"#;
        let rule: Rule = serde_json::from_str(json).unwrap();
        let c = compile(&rule, std::path::Path::new(".")).unwrap();
        assert!(eval(&c, &req("MJ12bot/v1.4")));
        assert!(!eval(&c, &req("Googlebot/2.1")));

        // Negate 取反
        let json = r#"{ "MemberName": "UserAgent", "Operator": "IsBotKind", "TargetValue": "friendly", "Negate": true }"#;
        let rule: Rule = serde_json::from_str(json).unwrap();
        let c = compile(&rule, std::path::Path::new(".")).unwrap();
        assert!(!eval(&c, &req("Googlebot/2.1")));
        assert!(eval(&c, &req("curl/8.0")));
    }

    #[test]
    fn regex_and_andalso() {
        let json = r#"{ "Operator": "AndAlso", "Rules": [
            { "MemberName": "Path", "Operator": "StartsWith", "Inputs": ["/admin"] },
            { "MemberName": "UserAgent", "Operator": "IsMatch", "TargetValue": "^(curl|python)" }
        ] }"#;
        let rule: Rule = serde_json::from_str(json).unwrap();
        let c = compile(&rule, std::path::Path::new(".")).unwrap();
        let mut r = req("python-requests/2.31");
        r.path = "/admin/".to_string();
        assert!(eval(&c, &r));
        r.user_agent = "Mozilla/5.0".to_string();
        assert!(!eval(&c, &r));
    }
}
