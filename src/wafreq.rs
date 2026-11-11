//! 请求视图与 IP 匹配工具（CIDR / 通配符 / 列表 / 文件）。

use dhrust::net::http::{HttpRequest, HttpRequestHead};

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
    /// 用 dhrust 请求**覆写**自身（复用已有容量，首次之后零分配）。
    ///
    /// 与旧版 `from_http()` 的差别：不再 `clone()` 路径/查询串、不再为每个字段新建 `String`。
    /// **旧的所有权构造已删除**（用户 2026-11-11：「不要留这种，要不然永远都不会使用最新的」）——
    /// 一律用「持有实例 + 覆写」的形态，从 API 层面就避免在热路径上分配。
    ///
    /// **不填 `body_text`**（这是故意的，不是遗漏）：
    /// ① 命中 `skip_attack_prefixes` 的请求（聊天/API 接口）根本不扫 body，
    ///    白拷一份 16 KB 实测要 ~24 µs（复制 + UTF-8 校验，且在中间件里被拷了两遍）；
    /// ② 扫描上限来自配置（`body_scan_limit`），不该由视图自己拍。
    /// 需要 body 时由调用方调 [`fill_body_preview`](Self::fill_body_preview)。
    pub fn fill_from_http(&mut self, req: &HttpRequest) {
        self.clear();
        self.path.push_str(&req.path);
        self.method.push_str(&req.method);
        self.query.push_str(&req.query);
        self.user_agent
            .push_str(req.header("user-agent").unwrap_or(""));
        strip_port_into(req.remote_addr.as_deref().unwrap_or(""), &mut self.remote_ip);
        self.content_type
            .push_str(req.header("content-type").unwrap_or(""));
    }

    /// 填写 body 预览（只取前 `limit` 字节）。
    ///
    /// 与 [`fill_from_http`](Self::fill_from_http) 拆开是为了「不扫 body 就不复制」：
    /// 合法 UTF-8 时直接借校验通过的切片写进复用缓冲（容量保留）。
    /// 「是不是文本类」由调用方判断（配置 `body_scan_all_types` 会改变结论）。
    pub fn fill_body_preview(&mut self, body: &[u8], limit: usize) {
        self.body_text.clear();
        if body.is_empty() || limit == 0 {
            return;
        }
        let cap = body.len().min(limit);
        match std::str::from_utf8(&body[..cap]) {
            Ok(text) => self.body_text.push_str(text),
            Err(_) => self
                .body_text
                .push_str(&String::from_utf8_lossy(&body[..cap])),
        }
    }

    /// 用 **请求头快照**覆写自身（还没读 body 时；`body_text` 恒为空）。
    ///
    /// 用于 HTTP 层的早拒钩子：UA / IP / 路径 / 查询串命中特征即可拒绝，
    /// **不让对方把大 body 传上来**（省带宽）。body 级规则由之后的 [`Waf::check`](crate::Waf::check) 补齐。
    pub fn fill_from_head(&mut self, head: &HttpRequestHead) {
        self.fill_head(
            &head.path,
            &head.method,
            &head.query,
            head.header("user-agent").unwrap_or(""),
            head.remote_addr.as_deref().unwrap_or(""),
            head.header("content-type").unwrap_or(""),
        );
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

    /// 清空全部字段（**保留容量**）。
    ///
    /// 配合 [`WafRequest::fill_head`] 使用：调用方持有**一个**实例、每请求覆写字段，
    /// 首次之后就不再分配 —— 热路径上省掉每请求 6 次 `String` 分配。
    ///
    /// 实测（`rustc -O`，200 万次取均，单线程/8 线程一致）：每请求 6 个 owned `String`
    /// 约 150~190 ns CPU，换成复用填充后接近 0；8 线程下也未出现分配器竞争放大。
    pub fn clear(&mut self) {
        self.path.clear();
        self.method.clear();
        self.query.clear();
        self.user_agent.clear();
        self.remote_ip.clear();
        self.content_type.clear();
        self.body_text.clear();
    }

    /// 用**请求头**字段覆写自身（复用已有容量）。
    ///
    /// 不再为每个字段分配新 `String`，而是在已分配的缓冲上 `push_str`。
    pub fn fill_head(
        &mut self,
        path: &str,
        method: &str,
        query: &str,
        user_agent: &str,
        remote_ip: &str,
        content_type: &str,
    ) {
        self.clear();
        self.path.push_str(path);
        self.method.push_str(method);
        self.query.push_str(query);
        self.user_agent.push_str(user_agent);
        // 与 `from_head` 同口径：剥掉端口（`1.2.3.4:5678` → `1.2.3.4`）
        // 用 `strip_port_into` 而不是 `strip_port`：后者会多一次 String 分配，白忙一场
        strip_port_into(remote_ip, &mut self.remote_ip);
        self.content_type.push_str(content_type);
    }
}

/// 请求体是否为「文本类」内容（可安全按 UTF-8 扫描）。
pub fn is_text_content_type(content_type: &str) -> bool {
    content_type.starts_with("text/")
        || content_type.contains("json")
        || content_type.contains("x-www-form-urlencoded")
        || content_type.contains("xml")
}

/// 剥离 `IP:Port` 中的端口（兼容 `[::1]:123` 形态；无端口原样返回）。
pub fn strip_port(addr: &str) -> String {
    // 返回「去掉端口的那个切片」/「整体」，由 `strip_port_into` 统一实现
    let (host, _) = strip_port_parts(addr);
    host.to_string()
}

/// 剥离端口并**追加**到已有缓冲（不额外分配）。
///
/// 热路径用：`WafRequest::fill_head` 复用实例时靠它把 `IP:Port` 写进已有容量。
pub fn strip_port_into(addr: &str, out: &mut String) {
    let (host, _) = strip_port_parts(addr);
    out.push_str(host);
}

/// 拆出（去掉端口的 host 切片, 原串），供 `strip_port` / `strip_port_into` 共用。
fn strip_port_parts(addr: &str) -> (&str, ()) {
    let addr = addr.trim();
    if addr.is_empty() {
        return ("", ());
    }
    if let Some(rest) = addr.strip_prefix('[') {
        // [v6]:port 或 [v6]
        if let Some((host, _)) = rest.split_once(']') {
            return (host, ());
        }
        return (addr, ());
    }
    // v4:port（恰一个冒号）——多个冒号视为裸 IPv6
    if addr.matches(':').count() == 1
        && let Some((host, port)) = addr.rsplit_once(':')
        && port.chars().all(|c| c.is_ascii_digit())
    {
        return (host, ());
    }
    (addr, ())
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
        let mut wr = WafRequest::default();
        wr.fill_from_http(&req);
        assert_eq!(wr.remote_ip, "127.0.0.1");
        assert_eq!(wr.user_agent, "curl/8.0");
        assert_eq!(wr.member("Path"), "/api/test");
        assert_eq!(wr.member("RemoteIp"), "127.0.0.1");

        // 复用同一实例覆写：不能残留上一次的字段（body 尤其容易漏）
        wr.fill_from_http(&req);
        assert_eq!(wr.path, "/api/test");
        assert_eq!(wr.body_text, "");
    }

    /// body 预览是**单独一步**（`fill_from_http` 故意不填）：
    /// 这样「不扫 body 的请求」根本不会白拷一份大正文。
    #[test]
    fn fill_body_preview_is_opt_in_and_clears() {
        let req = dhrust::net::http::HttpRequest {
            method: "POST".to_string(),
            path: "/v1/chat/completions".to_string(),
            query: String::new(),
            headers: vec![(
                "Content-Type".to_string(),
                "application/json".to_string(),
            )],
            body: bytes::Bytes::from_static(b"{\"q\":\"1' or 1=1--\"}"),
            remote_addr: Some("127.0.0.1:9999".to_string()),
        };
        let mut wr = WafRequest::default();
        wr.fill_from_http(&req);
        assert_eq!(wr.body_text, "", "fill_from_http 不再复制 body");

        wr.fill_body_preview(&req.body, 1024);
        assert_eq!(wr.body_text, "{\"q\":\"1' or 1=1--\"}");

        // 上限生效 + 再次填充分明先清空（不残留上一次的长 body）
        wr.fill_body_preview(&req.body, 4);
        assert_eq!(wr.body_text, "{\"q\"");
        wr.fill_body_preview(&[], 1024);
        assert_eq!(wr.body_text, "");
    }
}
