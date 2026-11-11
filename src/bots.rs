//! 爬虫分级管理：放行正常搜索引擎与 GEO-AI 抓取，拦截恶意爬虫/扫描器。
//!
//! 分级（[`BotKind`]）：
//! - [`BotKind::SearchEngine`]：主流搜索引擎蜘蛛（Googlebot/Bingbot/Baiduspider/Sogou/Applebot…）；
//! - [`BotKind::AiCrawler`]：**正常 GEO 抓取**——官方 AI/生成式引擎抓取器（GPTBot/ClaudeBot/PerplexityBot/
//!   Google-Extended/CCBot 等），用于站点被生成式引擎收录引用；
//! - [`BotKind::SocialPreview`]：社交平台链接预览（facebookexternalhit/Twitterbot/Slackbot…）；
//! - [`BotKind::Monitor`]：灰色（合法但非官方，如 Bytespider/Scrapy/axios 等库默认 UA）——记录并限速，不默认拦截；
//! - [`BotKind::Malicious`]：恶意爬虫与扫描器（MJ12bot/SemrushBot/AhrefsBot/sqlmap/nikto/python-requests/curl…）；
//! - [`BotKind::Unknown`]：疑似机器人（UA 含 bot/spider/crawl 等词但不在名单）。
//!
//! 名单可按项目在 [`crate::WafConfig`] 里追加（`extra_allow_bots` / `extra_block_bots`）。

/// 爬虫分类。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BotKind {
    /// 正常搜索引擎蜘蛛（放行）
    SearchEngine,
    /// 正常 GEO / AI 抓取器（放行）
    AiCrawler,
    /// 社交平台链接预览（放行）
    SocialPreview,
    /// 灰色（记录 + 限速；默认不拦）
    Monitor,
    /// 恶意爬虫 / 扫描器（默认拦截）
    Malicious,
    /// 疑似机器人（UA 含机器人关键词但未识别）
    Unknown,
}

impl BotKind {
    /// 是否属于默认放行的正常抓取器（搜索引擎 / AI-GEO / 社交预览）。
    pub fn is_friendly(self) -> bool {
        matches!(
            self,
            BotKind::SearchEngine | BotKind::AiCrawler | BotKind::SocialPreview
        )
    }

    /// 中文类别名（日志用）。
    pub fn name_cn(self) -> &'static str {
        match self {
            BotKind::SearchEngine => "搜索引擎",
            BotKind::AiCrawler => "AI/GEO 抓取",
            BotKind::SocialPreview => "社交预览",
            BotKind::Monitor => "灰色爬虫",
            BotKind::Malicious => "恶意爬虫/扫描器",
            BotKind::Unknown => "疑似机器人",
        }
    }
}

/// 搜索引擎蜘蛛（官方 UA 子串，小写匹配）。
pub const SEARCH_ENGINES: &[&str] = &[
    "googlebot",
    "google-inspectiontool",
    "storebot-google",
    "googleother",
    "bingbot",
    "bingpreview",
    "adidxbot",
    "msnbot",
    "baiduspider",
    "yandex",
    "duckduckbot",
    "duckduckgo-favicons-bot",
    "sogou",
    "360spider",
    "haosouspider",
    "applebot",
    "petalbot",
    "yisouspider",
    "shenmaspider",
    "slurp",
    "exabot",
    "qwantify",
    "seznam",
    "mojeek",
    "ia_archiver",
    "archive.org_bot",
    "tineye",
];

/// 正常 GEO / AI 抓取器（生成式引擎官方 UA 子串）。
pub const AI_CRAWLERS: &[&str] = &[
    "gptbot",
    "chatgpt-user",
    "oai-searchbot",
    "claudebot",
    "claude-web",
    "claude-user",
    "anthropic-ai",
    "perplexitybot",
    "perplexity-user",
    "google-extended",
    "applebot-extended",
    "ccbot",
    "commoncrawl",
    "meta-externalagent",
    "facebookbot",
    "amazonbot",
    "cohere-ai",
    "youbot",
];

/// 社交平台链接预览。
pub const SOCIAL_PREVIEWS: &[&str] = &[
    "facebookexternalhit",
    "twitterbot",
    "linkedinbot",
    "slackbot",
    "telegrambot",
    "discordbot",
    "skypeuripreview",
    "whatsapp",
    "pinterestbot",
    "redditbot",
    "embedly",
    "quora link preview",
    "outbrain",
];

/// 灰色爬虫（记录 + 限速；默认不拦）。
pub const MONITOR_BOTS: &[&str] = &[
    "bytespider",
    "scrapy",
    "nutch",
    "axios/",
    "node-fetch",
    "okhttp",
    "java/",
    "php/",
    "gigabot",
    "diffbot",
    "dataprovider",
    "seekport",
];

/// 恶意爬虫 / 扫描器（默认拦截）。
pub const MALICIOUS_BOTS: &[&str] = &[
    // 商业 SEO/采集爬虫（不等 robots，普遍滥用）
    "mj12bot",
    "dotbot",
    "semrushbot",
    "ahrefsbot",
    "megaindex",
    "blexbot",
    "dataforseo",
    "serpstat",
    "zoominfobot",
    "maui bot",
    "turnitinbot",
    "majestic",
    "rogerbot",
    "screaming frog",
    // 脚本/库默认 UA（扫描与采集最常见载体；自家工具请走 IP 白名单或回环）
    "python-requests",
    "python-urllib",
    "aiohttp",
    "curl/",
    "wget/",
    "go-http-client",
    "libwww-perl",
    "lwp::simple",
    "pycurl",
    "winhttp",
    "guzzle",
    "restsharp",
    "apachebench",
    "ab/",
    // 漏洞扫描器 / 安全探测
    "sqlmap",
    "nikto",
    "nmap",
    "zgrab",
    "masscan",
    "dirbuster",
    "gobuster",
    "wfuzz",
    "hydra",
    "nessus",
    "acunetix",
    "nuclei",
    "whatweb",
    "wpscan",
    "httrack",
    "w3af",
    "xray",
    "goby",
    "netsparker",
    // 网络空间测绘（持续扫描全网）
    "censys",
    "shodan",
    "internet-measurement",
    "leakix",
    "binaryedge",
    "netsystemsresearch",
    "expanse",
    "palo alto networks",
    "driftnet",
    "binaryedge",
];

/// 疑似机器人关键词（UA 含其一且不在任何名单 → [`BotKind::Unknown`]）。
pub const BOT_KEYWORDS: &[&str] = &[
    "bot",
    "spider",
    "crawl",
    "slurp",
    "scan",
    "spider",
    "fetcher",
    "harvest",
    "headless",
    "phantom",
    "selenium",
    "puppeteer",
    "playwright",
    "lighthouse",
];

/// 分类 UA（空 UA 返回 `None`——由 [`crate::Waf`] 按 `block_empty_ua` 策略处理）。
///
/// 实现取舍（实测）：这里**整体小写一次**再逐名单 `contains`，比「不分配、逐模式
/// `contains_ignore_ascii_case`」快得多——后者在 100+ 个模式、UA 不命中任何名单时
/// 会退化成「每个模式都全串扫一遍」，实测 700 ns → 6.3 µs（慢 9 倍）。
/// 名单里即便有大写（`Censys`/`Expanse`）也已随 UA 一起折叠，不影响命中。
pub fn classify(ua: &str) -> Option<BotKind> {
    let ua = ua.trim();
    if ua.is_empty() {
        return None;
    }
    let lower = ua.to_ascii_lowercase();
    let hit = |list: &[&str]| list.iter().any(|k| lower.contains(k));
    if hit(MALICIOUS_BOTS) {
        return Some(BotKind::Malicious);
    }
    if hit(SEARCH_ENGINES) {
        return Some(BotKind::SearchEngine);
    }
    if hit(AI_CRAWLERS) {
        return Some(BotKind::AiCrawler);
    }
    if hit(SOCIAL_PREVIEWS) {
        return Some(BotKind::SocialPreview);
    }
    if hit(MONITOR_BOTS) {
        return Some(BotKind::Monitor);
    }
    if hit(BOT_KEYWORDS) {
        return Some(BotKind::Unknown);
    }
    None
}

/// 每线程 UA 分类缓存槽数（实际流量里不同 UA 通常只有个位数）。
const UA_CACHE_SLOTS: usize = 8;

/// 缓存条目：`(折叠大小写后的两路哈希, UA 长度, 分类结果)`。
type UaCacheEntry = (u64, u64, u32, Option<BotKind>);

thread_local! {
    /// 每线程的「UA → 分类」小缓存。
    ///
    /// 为什么需要：`classify` 要在 6 个名单、130+ 个关键词上逐个 `contains`，
    /// UA 不命中任何名单时是**最坏情况**（每次都全表扫完），实测约 1.2 µs；
    /// 而真实流量里 UA 高度重复（浏览器 / SDK / 探活脚本），缓存后重复 UA 只需
    /// 一次哈希（~20 ns）。
    ///
    /// 键用**折叠大小写后**的两路 64 位哈希 + 长度：比对不依赖原始大小写，
    /// 也不需要保存 UA 副本（零分配）。两路独立哈希让碰撞概率低到可忽略。
    static UA_CACHE: std::cell::RefCell<([Option<UaCacheEntry>; UA_CACHE_SLOTS], usize)> =
        const { std::cell::RefCell::new(([None; UA_CACHE_SLOTS], 0)) };
}

/// 折叠大小写后的双路 64 位哈希（`len` 已并入，避免不同长度撞同一槽）。
#[inline]
fn ua_hash(ua: &[u8]) -> (u64, u64) {
    let mut h1: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a
    let mut h2: u64 = 0x9e37_79b9_7f4a_7c15; // 另一随机种子
    for &b in ua {
        let b = b.to_ascii_lowercase();
        h1 = (h1 ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3);
        h2 = (h2 ^ b as u64).wrapping_mul(0xff51_afd7_ed55_8ccd);
        h2 = h2.rotate_left(17) ^ (h2 >> 29);
    }
    (h1 ^ (ua.len() as u64).wrapping_mul(0x27d4_eb2d), h2)
}

/// 带缓存的 [`classify`]：热路径请用这个。
///
/// 语义与 [`classify`] 完全一致（同一 UA 必得同一结果）；缓存只影响耗时，
/// 不改变判定，配置里的额外名单变化时会自然失效（不同 UA 才走慢路径，
/// 同一 UA 的判定不随配置变化——名单是编译期常量）。
pub fn classify_cached(ua: &str) -> Option<BotKind> {
    let ua = ua.trim();
    let (h1, h2) = ua_hash(ua.as_bytes());
    let len = ua.len() as u32;
    if let Some(hit) = UA_CACHE.with(|c| {
        let c = c.borrow();
        c.0.iter()
            .flatten()
            .find(|e| e.0 == h1 && e.1 == h2 && e.2 == len)
            .map(|e| e.3)
    }) {
        return hit;
    }
    let kind = classify(ua);
    UA_CACHE.with(|c| {
        let mut c = c.borrow_mut();
        let idx = c.1;
        c.1 = (c.1 + 1) % UA_CACHE_SLOTS;
        c.0[idx] = Some((h1, h2, len, kind));
    });
    kind
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_major_bots() {
        // 正常搜索引擎（含常见完整 UA）
        assert_eq!(
            classify("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
            Some(BotKind::SearchEngine)
        );
        assert_eq!(
            classify("Mozilla/5.0 (compatible; Baiduspider/2.0)"),
            Some(BotKind::SearchEngine)
        );
        assert_eq!(classify("bingbot/2.0"), Some(BotKind::SearchEngine));
        // GEO / AI
        assert_eq!(
            classify(
                "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot"
            ),
            Some(BotKind::AiCrawler)
        );
        assert_eq!(classify("ClaudeBot/1.0"), Some(BotKind::AiCrawler));
        assert_eq!(classify("PerplexityBot/1.0"), Some(BotKind::AiCrawler));
        // 社交预览
        assert_eq!(
            classify("facebookexternalhit/1.1"),
            Some(BotKind::SocialPreview)
        );
        // 恶意
        assert_eq!(
            classify("Mozilla/5.0 (compatible; MJ12bot/v1.4.8)"),
            Some(BotKind::Malicious)
        );
        assert_eq!(classify("python-requests/2.31.0"), Some(BotKind::Malicious));
        assert_eq!(classify("curl/8.4.0"), Some(BotKind::Malicious));
        assert_eq!(classify("sqlmap/1.7"), Some(BotKind::Malicious));
        // 灰色
        assert_eq!(
            classify("Mozilla/5.0 (compatible; Bytespider)"),
            Some(BotKind::Monitor)
        );
        // 未知 bot
        assert_eq!(classify("SomeRandomBot/0.1"), Some(BotKind::Unknown));
        // 普通浏览器 / 移动端 / Dart（App）→ 非 bot
        assert_eq!(
            classify("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0"),
            None
        );
        assert_eq!(classify("Dart/3.11 (dart:io)"), None);
        assert_eq!(classify(""), None);
        assert_eq!(classify("   "), None);
    }

    #[test]
    fn friendly_flags() {
        assert!(BotKind::SearchEngine.is_friendly());
        assert!(BotKind::AiCrawler.is_friendly());
        assert!(BotKind::SocialPreview.is_friendly());
        assert!(!BotKind::Malicious.is_friendly());
        assert!(!BotKind::Monitor.is_friendly());
    }

    #[test]
    fn cached_classify_matches_plain() {
        let cases = [
            "",
            "   ",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "sqlmap/1.7",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) chrome/126.0", // 仅大小写不同
            "GPTBot/1.2",
            "Why-Tracking-Online/1.0",
            "some-random-crawler",
            "curl/8.4.0",
        ];
        // 命中/大小写/空 UA 都必须与不带缓存的实现一致；重复调用走缓存分支也一样
        for _ in 0..3 {
            for ua in cases {
                assert_eq!(
                    classify_cached(ua),
                    classify(ua.trim()),
                    "缓存版与直算版不一致：{ua}"
                );
            }
        }
        // 超出槽数（8）后仍不能串味
        for i in 0..40 {
            let ua = format!("Agent-{i}/1.0");
            assert_eq!(classify_cached(&ua), classify(&ua), "轮换后不一致：{ua}");
        }
        assert_eq!(classify_cached("sqlmap/1.7"), Some(BotKind::Malicious));
    }
}
