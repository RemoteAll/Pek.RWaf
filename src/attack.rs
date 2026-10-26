//! 攻击特征检测：SQL 注入 / XSS / 路径穿越与探测 / 命令注入。
//!
//! 检测对象为「路径 + 查询串 + 表单/JSON 体」经 `percent_decode`（含一次双重解码）后的规范化文本。
//! 与「数据访问统一走 Pek.RCode 参数化 ORM」形成纵深防御：本模块为外围第一道，
//! ORM 参数化为内层根本防线。

/// 攻击类型。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AttackKind {
    /// SQL 注入
    SqlInjection,
    /// XSS
    Xss,
    /// 路径穿越 / 敏感路径探测（含 `.php`/`.env`/`.git` 等默认拦截项）
    PathTraversal,
    /// 命令注入
    CommandInjection,
}

impl AttackKind {
    /// 中文名（日志用）。
    pub fn name_cn(self) -> &'static str {
        match self {
            AttackKind::SqlInjection => "SQL 注入",
            AttackKind::Xss => "XSS",
            AttackKind::PathTraversal => "路径穿透/敏感路径探测",
            AttackKind::CommandInjection => "命令注入",
        }
    }
}

/// SQL 注入特征（规范化后 `contains` 匹配）。
pub const SQLI_PATTERNS: &[&str] = &[
    "' or ",
    "\" or ",
    "'or'",
    "\"or\"",
    " or 1=1",
    " or '1'='1",
    "' or 1=1",
    ") or (",
    "' or (",
    "union select",
    "union all select",
    "select * from",
    "select count(*) from",
    "information_schema",
    "sleep(",
    "benchmark(",
    "waitfor delay",
    "pg_sleep(",
    "dbms_pipe.receive_message",
    "xp_cmdshell",
    "into outfile",
    "load_file(",
    "drop table",
    "truncate table",
    "@@version",
    "convert(int,",
    "'--",
    "';--",
    "\" --",
    "order by 1--",
]

;

/// XSS 特征。
pub const XSS_PATTERNS: &[&str] = &[
    "<script",
    "</script",
    "javascript:",
    "onerror=",
    "onload=",
    "onmouseover=",
    "onfocus=",
    "srcdoc=",
    "<iframe",
    "<svg",
    "document.cookie",
    "eval(",
    "alert(",
];

/// 路径穿越 / 敏感路径探测特征。
pub const PATH_PATTERNS: &[&str] = &[
    "../",
    "..\\",
    "%2e%2e",
    "..%2f",
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self",
    "web.config",
    "phpmyadmin",
    "wp-admin",
    "wp-login",
    "/.env",
    "/.git/",
    "/.svn/",
    "/.aws/",
    "/.ssh/",
    "/actuator/",
    "cgi-bin/",
    "phpunit",
    "phpinfo",
    ".php",
    ".jsp",
    ".asp",
    ".cgi",
    ".env",
    ".git",
    ".sql",
    "/vendor/",
];

/// 命令注入特征（宽松，建议默认 monitor）。
pub const CMD_PATTERNS: &[&str] = &[
    ";cat ",
    "|cat ",
    "&&cat",
    "$(",
    "`cat",
    ";/bin/",
    "&/bin/",
    "wget http",
    "curl http",
    "%0acat",
    "\ncat ",
];

/// URL 百分号解码（`+` 视作空格；非法序列保留原样；UTF-8 边界安全）。
pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = hex_val(bytes[i + 1]);
                let lo = hex_val(bytes[i + 2]);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h << 4) | l);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// 规范化：解码（两次，覆盖双重编码）+ 小写 + 空白折叠。
///
/// 优化：解码一次后已不含 `%` 时**不再做第二次解码**（正常请求省一次分配与拷贝）。
pub fn normalize(text: &str) -> String {
    let once = percent_decode(text);
    let twice = if once.contains('%') {
        percent_decode(&once)
    } else {
        String::new()
    };
    let mut out = String::with_capacity(once.len() + twice.len() + 1);
    let mut last_space = true; // 起始不加多余空格
    for (i, seg) in [once.as_str(), twice.as_str()].into_iter().enumerate() {
        if seg.is_empty() {
            continue;
        }
        // 两段之间保证至少一个空格（与旧实现 `"{once} {twice}"` 等价）
        if i > 0 && !last_space {
            out.push(' ');
            last_space = true;
        }
        for c in seg.chars() {
            let c = c.to_ascii_lowercase();
            if c.is_whitespace() {
                if !last_space {
                    out.push(' ');
                    last_space = true;
                }
            } else {
                out.push(c);
                last_space = false;
            }
        }
    }
    out
}

fn hit(text: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|p| text.contains(p))
}

/// 只做「路径穿越 / 敏感路径」检测。
///
/// 静态资源（js/css/图片/字体）专用：这些文件的**内容**天然含有 `' or `、`<script`
/// 之类片段，跑全量扫描是误报高发区；但路径穿越仍然必须拦。
pub fn scan_path(path: &str, query: &str) -> Vec<AttackKind> {
    let text = normalize(&format!("{path}?{query}"));
    if hit(&text, PATH_PATTERNS) {
        vec![AttackKind::PathTraversal]
    } else {
        Vec::new()
    }
}

/// 综合扫描（规范化一次，返回全部命中的类别——便于按策略分别处理）。
pub fn scan_all(path: &str, query: &str, body: &str) -> Vec<AttackKind> {
    let text = normalize(&format!("{path}?{query} {body}"));
    let mut kinds = Vec::new();
    if hit(&text, SQLI_PATTERNS) {
        kinds.push(AttackKind::SqlInjection);
    }
    if hit(&text, PATH_PATTERNS) {
        kinds.push(AttackKind::PathTraversal);
    }
    if hit(&text, CMD_PATTERNS) {
        kinds.push(AttackKind::CommandInjection);
    }
    if hit(&text, XSS_PATTERNS) {
        kinds.push(AttackKind::Xss);
    }
    kinds
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_cases() {
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("%2e%2e%2f"), "../");
        assert_eq!(percent_decode("%E4%B8%AD"), "中");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[test]
    fn sqli_detected() {
        let v = scan_all("/api/cards", "q=1' or 1=1--", "");
        assert!(v.contains(&AttackKind::SqlInjection));
        let v = scan_all("/api/x", "id=1 union select password from users", "");
        assert!(v.contains(&AttackKind::SqlInjection));
        let v = scan_all("/api/x", "name=admin'; select sleep(5)--", "");
        assert!(v.contains(&AttackKind::SqlInjection));
        // 双重编码绕过
        let v = scan_all("/api/x", "q=1%2527%20or%201=1", "");
        assert!(v.contains(&AttackKind::SqlInjection));
    }

    #[test]
    fn normal_input_not_flagged() {
        // 中文搜索 / 正常卡名 / 尾号
        let v = scan_all("/cards", "q=%E6%8B%9B%E5%95%86%E7%BB%8F%E5%85%B8%E7%99%BD%E9%87%91%E5%8D%A1&page=1", "");
        assert!(v.is_empty(), "正常搜索不应误报：{v:?}");
        let v = scan_all("/api/my/cardSave", "", "{\"cardTail\":\"8888\",\"alias\":\"我的卡\"}");
        assert!(v.is_empty(), "正常表单不应误报：{v:?}");
    }

    #[test]
    fn path_probes_detected() {
        assert!(scan_all("/wp-login.php", "", "").contains(&AttackKind::PathTraversal));
        assert!(scan_all("/.env", "", "").contains(&AttackKind::PathTraversal));
        assert!(scan_all("/.git/config", "", "").contains(&AttackKind::PathTraversal));
        assert!(scan_all("/static/../../etc/passwd", "", "").contains(&AttackKind::PathTraversal));
        assert!(scan_all("/assets/%2e%2e%2fsecret", "", "").contains(&AttackKind::PathTraversal));
    }

    #[test]
    fn xss_and_cmd_detected() {
        assert!(scan_all("/search", "q=<script>alert(1)</script>", "").contains(&AttackKind::Xss));
        assert!(scan_all("/api/x", "file=;cat /etc/hosts", "").contains(&AttackKind::CommandInjection));
    }
}
