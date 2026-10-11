//! 请求视图与 IP 匹配工具（CIDR / 通配符 / 列表 / 文件）。

use dhrust::net::http::HttpRequest;

/// WAF 请求视图（从 [`HttpRequest`] 提取；字段均为小写归一化前的原文）。
#[derive(Debug, Clone, Default)]
pub struct WafRequest {
    /// 请求路径（不含查询串）
    pub path: String,
    /// HTTP 方法
    pub method: String,
    /// 查询串（原始形态）
    pub query: String,
    /// User-Agent（缺省为空串）
    pub user_agent: String,
    /// 客户端 IP（已剥离端口；未知为空串）
    pub remote_ip: String,
    /// Content-Type（缺省为空串）
    pub content_type: String,
    /// 请求体文本预览（文本类且 ≤16KB；二进制为空）
    pub body_text: String,
}

impl WafRequest {
    /// 从 dhrust 请求构建。
    pub fn from_http(req: &HttpRequest) -> Self {
        let user_agent = req.header("user-agent").unwrap_or("").to_string();
        let content_type = req.header("content-type").unwrap_or("").to_string();
        let body_text = if content_type.starts_with("text/")
            || content_type.contains("json")
            || content_type.contains("x-www-form-urlencoded")
            || content_type.contains("xml")
        {
            let cap = req.body.len().min(16 * 1024);
            String::from_utf8_lossy(&req.body[..cap]).to_string()
        } else {
            String::new()
        };
        Self {
            path: req.path.clone(),
            method: req.method.clone(),
            query: req.query.clone(),
            user_agent,
            remote_ip: strip_port(req.remote_addr.as_deref().unwrap_or("")),
            content_type,
            body_text,
        }
    }

    /// 供规则引擎读取的成员值（对齐 C# `WebRequest` 常用属性；未知成员返回空串）。
    pub fn member(&self, name: &str) -> &str {
        match name {
            "Path" => &self.path,
            "Method" => &self.method,
            "UserAgent" => &self.user_agent,
            "RemoteIp" | "IpAddress" | "RemoteIpAddress" => &self.remote_ip,
            "QueryString" => &self.query,
            "ContentType" => &self.content_type,
            // IpCountry 需外部 GeoIP 数据（未内置）；Headers 仅支持整体模糊匹配
            _ => "",
        }
    }
}

/// 剥离 `IP:Port` 中的端口（兼容 `[::1]:123` 形态；无端口原样返回）。
pub fn strip_port(addr: &str) -> String {
    let addr = addr.trim();
    if addr.is_empty() {
        return String::new();
    }
    if let Some(rest) = addr.strip_prefix('[') {
        // [v6]:port 或 [v6]
        if let Some((host, _)) = rest.split_once(']') {
            return host.to_string();
        }
        return addr.to_string();
    }
    // v4:port（恰一个冒号）——多个冒号视为裸 IPv6
    if addr.matches(':').count() == 1
        && let Some((host, port)) = addr.rsplit_once(':')
        && port.chars().all(|c| c.is_ascii_digit())
    {
        return host.to_string();
    }
    addr.to_string()
}

/// 判断 IP 是否命中单条规则（精确 / CIDR（v4）/ 通配符（v4 分段））。
pub fn ip_match(ip: &str, rule: &str) -> bool {
    let rule = rule.trim();
    if rule.is_empty() || ip.is_empty() {
        return false;
    }
    if rule == "*" {
        return true;
    }
    if let Some((net, mask)) = rule.split_once('/') {
        return cidr_match(ip, net, mask);
    }
    if rule.contains('*') {
        return wildcard_match(ip, rule);
    }
    ip.eq_ignore_ascii_case(rule)
}

/// 判断 IP 是否命中列表（分隔符：`,` `;` 空白与换行均可混合）。
pub fn ip_in_list(ip: &str, list: &str) -> bool {
    list.split([';', ',', ' ', '\t', '\r', '\n'])
        .filter(|s| !s.trim().is_empty())
        .any(|rule| ip_match(ip, rule))
}

/// 从黑名单文件加载（逐行；忽略空行与 `#` 注释）。
pub fn load_ip_file(path: &std::path::Path) -> Vec<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => text
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.to_string())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// IPv4 CIDR 匹配（IPv6 仅精确：`::1/128` 之类按精确处理）。
fn cidr_match(ip: &str, net: &str, mask: &str) -> bool {
    let Ok(bits) = mask.trim().parse::<u32>() else {
        return ip.eq_ignore_ascii_case(net);
    };
    let (Some(ipv4), Some(netv4)) = (parse_v4(ip), parse_v4(net)) else {
        // 非 v4：退化为精确（IPv6 前缀匹配暂不内置）
        return ip.eq_ignore_ascii_case(net);
    };
    if bits == 0 {
        return true;
    }
    if bits > 32 {
        return false;
    }
    let m = u32::MAX << (32 - bits);
    (ipv4 & m) == (netv4 & m)
}

/// IPv4 通配符匹配（如 `192.168.*.*`）。
fn wildcard_match(ip: &str, pattern: &str) -> bool {
    let ip_segs: Vec<&str> = ip.split('.').collect();
    let pat_segs: Vec<&str> = pattern.split('.').collect();
    if ip_segs.len() != 4 || pat_segs.len() != 4 {
        return false;
    }
    ip_segs
        .iter()
        .zip(pat_segs.iter())
        .all(|(a, b)| *b == "*" || a == b)
}

fn parse_v4(ip: &str) -> Option<u32> {
    let segs: Vec<&str> = ip.split('.').collect();
    if segs.len() != 4 {
        return None;
    }
    let mut v: u32 = 0;
    for s in segs {
        let b: u32 = s.parse().ok()?;
        if b > 255 {
            return None;
        }
        v = (v << 8) | b;
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_port_cases() {
        assert_eq!(strip_port("192.168.1.5:51234"), "192.168.1.5");
        assert_eq!(strip_port("127.0.0.1"), "127.0.0.1");
        assert_eq!(strip_port("[::1]:8080"), "::1");
        assert_eq!(strip_port("::1"), "::1");
        assert_eq!(strip_port(""), "");
    }

    #[test]
    fn ip_match_cases() {
        assert!(ip_match("192.168.1.100", "192.168.1.100"));
        assert!(!ip_match("192.168.1.101", "192.168.1.100"));
        assert!(ip_match("10.1.2.3", "10.0.0.0/8"));
        assert!(!ip_match("11.1.2.3", "10.0.0.0/8"));
        assert!(ip_match("192.168.1.5", "192.168.*.*"));
        assert!(!ip_match("192.169.1.5", "192.168.*.*"));
        assert!(ip_match("192.168.1.5", "0.0.0.0/0"));
        assert!(ip_match("::1", "::1"));
    }

    #[test]
    fn ip_in_list_mixed_separators() {
        let list = "192.168.1.100, 10.0.0.0/8; 172.16.*.*\n203.0.113.9";
        assert!(ip_in_list("10.5.5.5", list));
        assert!(ip_in_list("172.16.9.9", list));
        assert!(ip_in_list("203.0.113.9", list));
        assert!(!ip_in_list("8.8.8.8", list));
    }

    #[test]
    fn waf_request_from_http() {
        let req = dhrust::net::http::HttpRequest {
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            query: "q=1".to_string(),
            headers: vec![("User-Agent".to_string(), "curl/8.0".to_string())],
            body: bytes::Bytes::new(),
            remote_addr: Some("127.0.0.1:9999".to_string()),
        };
        let wr = WafRequest::from_http(&req);
        assert_eq!(wr.remote_ip, "127.0.0.1");
        assert_eq!(wr.user_agent, "curl/8.0");
        assert_eq!(wr.member("Path"), "/api/test");
        assert_eq!(wr.member("RemoteIp"), "127.0.0.1");
    }
}
