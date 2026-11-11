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
];

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
///
/// 优化：不含 `%`/`+` 时直接返回原串（最常见）；否则解码到 `Vec<u8>` 后
/// `String::from_utf8` **直接接管缓冲**（合法 UTF-8 时零额外分配）。
pub fn percent_decode(input: &str) -> String {
    if !input.as_bytes().iter().any(|b| *b == b'%' || *b == b'+') {
        return input.to_string();
    }
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    decode_bytes_into(input.as_bytes(), &mut out);
    match String::from_utf8(out) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    }
}

/// 按字节解码百分号编码（非法序列原样保留），结果追加到 `out`。
///
/// 内部复用：`normalize` 系列一次解码到底，省掉「先建 String 再拷一次」。
fn decode_bytes_into(input: &[u8], out: &mut Vec<u8>) {
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'%' if i + 2 < input.len() => {
                let hi = hex_val(input[i + 1]);
                let lo = hex_val(input[i + 2]);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h << 4) | l);
                    i += 3;
                    continue;
                }
                out.push(input[i]);
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
    normalize_parts(&[text])
}

/// 多段文本规范化（**零拼接分配**）：各段按顺序视为直接相连（分隔符由调用方作为独立段给出），
/// 语义与 `normalize(&format!("{a}{b}{c}"))` 完全一致，但不再为拼接多分配一个 String。
///
/// 快路径（绝大多数请求）：全文不含 `%` → 只做一趟「`+`/空白折叠 + 小写」直接产出结果；
/// 慢路径（含 `%`）：先解码到字节缓冲，仍需二次解码时追加「解码一次 + 空格 + 解码两次」，
/// 与旧实现 `"{once} {twice}"` 等价。
pub fn normalize_parts(parts: &[&str]) -> String {
    let capacity = parts.iter().map(|p| p.len()).sum();
    if !parts.iter().any(|p| p.contains('%')) {
        return collapse_lower(parts.iter().copied(), capacity);
    }
    let mut raw: Vec<u8> = Vec::with_capacity(capacity);
    for p in parts {
        decode_bytes_into(p.as_bytes(), &mut raw);
    }
    if raw.contains(&b'%') {
        // 覆盖双重编码：保留「解一次」形态，再追加「解两次」形态
        let mut twice: Vec<u8> = Vec::with_capacity(raw.len() + 1);
        decode_bytes_into(&raw, &mut twice);
        raw.push(b' ');
        raw.extend_from_slice(&twice);
    }
    let text = String::from_utf8_lossy(&raw);
    collapse_lower(std::iter::once(text.as_ref()), text.len())
}

/// 把多段文本「折叠空白 + 小写」直接写进结果串（各段之间不额外插空格）。
///
/// 两个要点（都是实测出来的）：
/// 1. **必须预分配 `capacity`** —— 否则长 body 会因 `String` 反复扩容重拷，比旧实现还慢；
/// 2. 全 ASCII 时走**字节**快路径（不逐 `char` 解码再编码），中文等非 ASCII 才回落字符路径。
///
/// 入参要求 `Clone` 是为了「先判是否纯 ASCII、再正式跑一遍」两趟遍历**不额外分配**。
fn collapse_lower<'a, I>(parts: I, capacity: usize) -> String
where
    I: Iterator<Item = &'a str> + Clone,
{
    if parts.clone().all(|s| s.is_ascii()) {
        let mut out: Vec<u8> = Vec::with_capacity(capacity);
        let mut last_space = true; // 起始不加多余空格
        for seg in parts {
            for &b in seg.as_bytes() {
                // `+` 与百分号解码里的「`+` → 空格」保持同口径
                if b == b'+' || b.is_ascii_whitespace() {
                    if !last_space {
                        out.push(b' ');
                        last_space = true;
                    }
                } else {
                    out.push(b.to_ascii_lowercase());
                    last_space = false;
                }
            }
        }
        return String::from_utf8(out).expect("纯 ASCII 缓冲必定是合法 UTF-8");
    }
    let mut out = String::with_capacity(capacity);
    let mut last_space = true;
    for seg in parts {
        for c in seg.chars() {
            if c == '+' || c.is_whitespace() {
                if !last_space {
                    out.push(' ');
                    last_space = true;
                }
            } else {
                out.push(c.to_ascii_lowercase());
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
    // 分隔符作为独立段给出：等价 `{path}?{query}`，但不再多分配一个拼接串
    let text = normalize_parts(&[path, "?", query]);
    if hit(&text, PATH_PATTERNS) {
        vec![AttackKind::PathTraversal]
    } else {
        Vec::new()
    }
}

/// 综合扫描（规范化一次，返回全部命中的类别——便于按策略分别处理）。
///
/// 注：曾试过「首字节分桶 + 单趟多名单匹配」，实测**不划算**并已回退——
/// 真实中文 JSON（16 KB）只快 17%，而「全 `a` 填充」这类病态输入因每字节都要
/// 尝试全部候选反而慢 67%（36.9 µs → 61.6 µs）。真正能在单趟内完成的只有
/// Aho-Corasick 自动机，收益约 20 µs/16 KB，暂不引入。
pub fn scan_all(path: &str, query: &str, body: &str) -> Vec<AttackKind> {
    let text = normalize_parts(&[path, "?", query, " ", body]);
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
        let v = scan_all(
            "/cards",
            "q=%E6%8B%9B%E5%95%86%E7%BB%8F%E5%85%B8%E7%99%BD%E9%87%91%E5%8D%A1&page=1",
            "",
        );
        assert!(v.is_empty(), "正常搜索不应误报：{v:?}");
        let v = scan_all(
            "/api/my/cardSave",
            "",
            "{\"cardTail\":\"8888\",\"alias\":\"我的卡\"}",
        );
        assert!(v.is_empty(), "正常表单不应误报：{v:?}");
    }

    /// 基准：`scan_all` 端到端 + 分项耗时（规范化 / 名单匹配）
    ///
    /// 手动跑：`cargo test --release --lib bench_scan_all_join_vs_parts -- --ignored --nocapture`
    ///
    /// 计时口径：每项跑 3 轮各 `N` 次，**取最小值**（排除调度抖动），`black_box` 防优化掉。
    /// 正文取两种：真实中文 JSON（典型）与全 `a` 填充（最坏——每个位置都像模式首字节）。
    #[test]
    #[ignore = "bench（手动运行）"]
    fn bench_scan_all_join_vs_parts() {
        use std::hint::black_box;
        use std::time::Instant;

        const N: usize = 20_000;
        const ROUNDS: usize = 3;

        let path = "/v1/chat/completions";
        let query = "stream=true";
        let tiny = "{\"model\":\"deepseek-chat\",\"messages\":[{\"role\":\"user\"}]}";
        // 真实形态：中文说明 + 英文混排，凑到 16 KB
        let unit = "{\"role\":\"user\",\"content\":\"请帮我总结这份招标文件里的技术要求与评分办法，注意工期和质保条款。\"},";
        let real_16k = {
            let mut s = String::from("{\"messages\":[");
            while s.len() < 16 * 1024 {
                s.push_str(unit);
            }
            s.push_str("]}");
            s
        };
        let worst_16k = "{\"msg\":\"".to_string() + &"a".repeat(16 * 1024) + "\"}";

        // 跑 `ROUNDS × N` 次取最小值（ns/次）
        let measure = |mut f: Box<dyn FnMut()>| -> f64 {
            let mut best = f64::MAX;
            for _ in 0..ROUNDS {
                let started = Instant::now();
                for _ in 0..N {
                    f();
                }
                let ns = started.elapsed().as_nanos() as f64 / N as f64;
                best = best.min(ns);
            }
            best
        };

        let bench = |label: &str, body: &str| {
            // 旧链路：format! 拼整串 → normalize → 四个名单各扫一遍
            let old_scan = {
                let body = body.to_string();
                move || {
                    let text = normalize(&format!("{path}?{query} {body}"));
                    black_box((
                        hit(&text, SQLI_PATTERNS),
                        hit(&text, PATH_PATTERNS),
                        hit(&text, CMD_PATTERNS),
                        hit(&text, XSS_PATTERNS),
                    ));
                }
            };
            // 新链路：分段 normalize（零拼接）→ 单趟多名单匹配
            let new_scan = {
                let body = body.to_string();
                move || {
                    black_box(scan_all(path, query, &body));
                }
            };
            // 分项：只做规范化（新旧各一次合并语义，这里只比新实现口径）
            let only_norm = {
                let body = body.to_string();
                move || {
                    black_box(normalize_parts(&[path, "?", query, " ", &body]));
                }
            };

            let old_ns = measure(Box::new(old_scan));
            let new_ns = measure(Box::new(new_scan));
            let norm_ns = measure(Box::new(only_norm));

            // 单趟匹配候选（已回退，仅保留对比口径：四趟 matches 与端到端一致）
            let pre = normalize_parts(&[path, "?", query, " ", body]);
            let four_pass = {
                let pre = pre.clone();
                move || {
                    black_box((
                        hit(&pre, SQLI_PATTERNS),
                        hit(&pre, PATH_PATTERNS),
                        hit(&pre, CMD_PATTERNS),
                        hit(&pre, XSS_PATTERNS),
                    ));
                }
            };
            let four_ns = measure(Box::new(four_pass));

            println!(
                "[{label}] 端到端 旧 {old_ns:>8.0} ns → 新 {new_ns:>8.0} ns（{:+.1}%）\
                 ｜规范化 {norm_ns:>8.0} ns｜名单匹配（四趟）{four_ns:>8.0} ns",
                (new_ns - old_ns) / old_ns * 100.0
            );

            assert_eq!(
                normalize(&format!("{path}?{query} {body}")),
                normalize_parts(&[path, "?", query, " ", body]),
                "分段规范化结果必须与拼接实现完全一致"
            );
            assert!(
                scan_all(path, query, body).is_empty(),
                "该正文不含攻击特征"
            );
        };
        bench("无 body", "");
        bench("小 JSON body", tiny);
        bench("16KB 真实中文 JSON", &real_16k);
        bench("16KB 最坏全 a 填充", &worst_16k);
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
        assert!(
            scan_all("/api/x", "file=;cat /etc/hosts", "").contains(&AttackKind::CommandInjection)
        );
    }
}
