# Pek.RWaf

Pek 系列 Web 应用防火墙（Rust 公共库，crate `pek-rwaf`）——对齐 C# [`Pek.WAF`](../Pek.FrameWork/Pek.WAF) 的功能并扩展
「爬虫分级治理」与「CC 限速」，以 [dhrust](../DH.RustBase) 中间件形式接入任意 HTTP 服务。

消费方：**Pek.RCard**（前台公开站点）、**Pek.RAgent / Pek.RPanlServer / DHDeploy.Agent.Rust**（管理端）。

## 能力总览

| 能力 | 说明 |
| --- | --- |
| 🤖 爬虫分级 | 6 级分类：搜索引擎 / GEO-AI 抓取 / 社交预览（**放行**）；灰色 / 未知（记录+限速）；恶意爬虫与扫描器（**拦截**） |
| 🧱 注入检测 | SQL 注入 / XSS / 路径穿越与敏感路径探测 / 命令注入；逐项动作（关/监控/拦截），双重 URL 解码防绕过 |
| ⏱️ CC 限速 | 固定 60 秒窗口每 IP 计数；放行类机器人豁免；静态资源不计数 |
| 🌐 跨站来源校验 | 浏览器**非安全方法**（POST/PUT/PATCH/DELETE）校验 `Sec-Fetch-Site`/`Origin`（CSRF 防护；**先于回环豁免**——localhost 面板免登录场景防恶意网页盲发）；无来源头（curl/服务间调用）放行 |
| 📜 规则引擎 | **与 C# Pek.WAF 的 Ruleset JSON 格式兼容**（同一份规则可双端共用）+ 新增 `IsBotKind` |
| 🚫 IP 名单 | 白名单（优先放行）/ 黑名单；精确、CIDR（`10.0.0.0/8`）、通配符（`192.168.*.*`）、文件 |
| ♻️ 热重载 | `Config/Waf.json` 修改后 ≤10 秒自动生效（mtime 检查）；校验失败保留旧配置 |
| 🔓 回环豁免 | `127.0.0.1`/`::1` 默认豁免（保护本地工具与冒烟脚本；生产可关） |

> 与数据库安全的关系：本库是**外围第一道防线**；数据访问统一走 Pek.RCode 参数化 ORM 是**根本防线**，两者纵深配合。

## 快速接入（三步）

```rust
// 1. Cargo.toml
// pek-rwaf = { path = "../Pek.RWaf" }

// 2. 启动时加载（读 {base}/Config/Waf.json；首启自动生成模板）
let waf = pek_rwaf::Waf::load(&base);

// 3. 路由装配首行挂中间件（全部路由生效）
router.use_middleware(waf.middleware());
```

被拦截的请求返回 `403`（限速为 `429`，带 `Retry-After: 60`），响应体为简短提示、头部带 `X-WAF-Blocked: 1`；
拦截原因（含 IP / UA / 路径）写入 dhrust 日志（`[WAF] 拦截 ...`）。

## 站点模式预设

| 配置项 | `public_site()`（前台） | `admin_api()`（管理端，默认） |
| --- | --- | --- |
| 搜索引擎 / GEO-AI / 社交预览 | 放行 | 全部拦截 |
| 空 User-Agent | 不拦 | 不拦（`blockEmptyUa` 可开启） |
| `/admin` 等敏感前缀 | 禁止一切机器人、攻击监控项升级为拦截 | —（全站从严） |
| SQL 注入 / 路径探测 | 拦截 | 拦截 |
| XSS / 命令注入 | 仅记录（表单易误报） | 拦截 |
| CC 限速 | 600 次/分钟 | 300 次/分钟 |

首启生成的 `Config/Waf.json` 使用 `admin_api()` 默认值；前台项目在配置里改用如下组合即可：

```json
{ "mode": "publicSite", "allowSearchBots": true, "allowAiBots": true,
  "allowSocialPreviews": true, "sensitivePrefixes": ["/admin"] }
```

## 爬虫分级（核心）

**放行**（正常收录与 GEO 引用）：`Googlebot` `Bingbot` `Baiduspider` `Sogou` `Applebot` `Yandex`…（27 项）；
`GPTBot` `ChatGPT-User` `ClaudeBot` `PerplexityBot` `Google-Extended` `CCBot` `Meta-ExternalAgent`…（18 项，AI/GEO 抓取）；
`facebookexternalhit` `Twitterbot` `Slackbot`…（社交预览）。

**拦截**（恶意爬虫与扫描器）：`MJ12bot` `SemrushBot` `AhrefsBot` `DotBot` 等 SEO 采集；
`sqlmap` `nikto` `nmap` `dirbuster` `wpscan` `acunetix` 等扫描器；`Censys` `Shodan` 等测绘；
`python-requests` `curl` `wget` `go-http-client` 等脚本默认 UA（**自家工具请走 IP 白名单或回环**）。

**记录并限速**（灰色，不默认拦）：`Bytespider` `Scrapy` `axios` `okhttp` `node-fetch`…

**自定义**：`extraAllowBots` / `extraBlockBots`（UA 子串，大小写不敏感；放行优先）。

普通浏览器、移动端与 Flutter/Dart App（`Dart/x.x (dart:io)`）不命中任何名单，不受影响。

## 可信业务请求（不新增密钥）

机器对机器调用不应由“User-Agent 是否像爬虫”来决定放行，WAF 提供两种**无新增密钥**的方式：

1. **复用项目已有的签名头**（推荐，若项目已有 HMAC 签名）：
   - `Waf::set_trusted_signature_secret(secret)`（内存态，不写 `Config/Waf.json`，面板保存配置不会清掉）；
   - 请求带 `TimeStamp` / `Nonce` / `Signature` 三头，且按现有算法（`SHA1(排序后的 timestamp+nonce+secret)`）复验通过 → 放行 WAF；
   - 密钥由项目已有的共享密钥提供（如 DHDeploy 的 `AgentSecret`），**不需要额外配置**；业务层仍做时间窗/重放/权限校验。
2. **按 API 路径跳过“爬虫 UA 判定”**（通用，适用于没有签名的项目）：
   - `skipBotPrefixes: ["/api"]`；
   - 只跳过 bot 分类，**攻击特征、IP 名单、CC 限速仍然生效**；
   - 真正的鉴权仍由业务层（JWT / API Token / 签名 / 会话）负责——**WAF 的 bot 判定不是鉴权层**。

> 不要为 WAF 再引入一个静态“可信头密钥”：那是新增凭据、需要轮换，且静态值同样可能被窃取；优先复用项目已有的签名/令牌体系，或使用 `skipBotPrefixes` + 业务鉴权。

## 规则引擎（C# 兼容）

`Config/Waf.json` 的 `ruleset` 字段与 C# `Pek.WAF` 的 Ruleset JSON **同格式**（PascalCase），命中即拦截：

```json
{
  "Operator": "OrElse",
  "Rules": [
    { "MemberName": "Path", "Operator": "EndsWith", "Inputs": [".php", ".env", ".git"] },
    { "MemberName": "UserAgent", "Operator": "IsBotKind", "TargetValue": "Malicious" },
    { "MemberName": "RemoteIp", "Operator": "InSubnet", "Inputs": ["10.0.0.0", 8] },
    { "MemberName": "Path", "Operator": "IsMatch", "TargetValue": "^/admin" , "Negate": true }
  ]
}
```

- **逻辑**：`OrElse`（任一命中）/ `AndAlso`（全部命中）；节点可任意嵌套；`Negate` 取反。
- **成员**：`Path` / `Method` / `UserAgent` / `RemoteIp`(`IpAddress`) / `QueryString` / `ContentType`。
- **操作符**：`EndsWith` `StartsWith` `Contains` `Equals`/`Equal` `IsMatch`(正则) `IsInInput` `IsInteger` `IsDouble`/`IsSingle`/`IsDecimal`；
  IP 系 `IsInIpList` `IsNotInIpList` `InSubnet` `IpInFile`；UA 系 `ContainsUserAgent` `NotContainsUserAgent` `IsInUserAgentList`
  `IsNotInUserAgentList` `UserAgentStartsWith` `UserAgentIsEmpty` `UserAgentIsNotEmpty`；**新增** `IsBotKind`。
- `IsBotKind` 目标值：`SearchEngine` / `AiCrawler` / `SocialPreview` / `Monitor` / `Malicious` / `Unknown` / `Any` / `friendly`。
- 说明：`IpCountry` 需外部 GeoIP 数据（未内置，恒不命中）；`IpInFile` 相对 `Config/` 所属基础目录解析。

## 配置参考（`Config/Waf.json`，camelCase）

| 字段 | 默认（admin_api） | 说明 |
| --- | --- | --- |
| `enable` | `true` | 总开关 |
| `mode` | `"adminApi"` | 语义标记（`publicSite` / `adminApi`） |
| `blockEmptyUa` | `false` | 拦截空 User-Agent（服务器间调用常无 UA，默认关） |
| `loopbackBypass` | `true` | 回环地址全豁免 |
| `ipWhitelist` / `ipBlacklist` | `[]` | IP 名单（白名单优先） |
| `extraAllowBots` / `extraBlockBots` | `[]` | 自定义 UA 子串 |
| `allowSearchBots` / `allowAiBots` / `allowSocialPreviews` | `false` | 放行三类正常抓取 |
| `blockMaliciousBots` | `true` | 拦截恶意爬虫 |
| `sensitivePrefixes` | `[]` | 敏感前缀（禁一切机器人 + 攻击监控升级拦截） |
| `skipAttackPrefixes` | `[]` | 跳过攻击检测的路径前缀（如项目自带的在线 SQL / 文件管理端点，安全由业务层护栏负责；bot/IP/CC 不受影响） || `skipBotPrefixes` | `[]` | 跳过机器人拦截的路径前缀（机器对机器 API——如产测工具调用接口；攻击检测/IP 名单/CC 不受影响） |
| `csrfGuard` | `true` | 跨站来源校验（CSRF）：浏览器非安全方法校验 `Sec-Fetch-Site`/`Origin`，跨站（含 `Origin: null`）拒绝；先于回环豁免 || `sqliAction` / `xssAction` / `pathAction` / `cmdAction` | `"block"` | 逐项动作：`off` / `monitor` / `block` |
| `rateLimitPerMin` | `300` | CC 限速（0=关） |
| `logBlocked` / `verbose` | `true` / `false` | 拦截日志 / 详细日志 |
| `ruleset` | `null` | C# 兼容规则树 |

## 落地记录

- 2026-10-11 建库：24 单测 + 1 文档测试全绿、clippy 零警告。
