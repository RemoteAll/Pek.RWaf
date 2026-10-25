# Pek.RWaf · 项目指令

> 全项目通用规则见用户级《跨项目接续协议》（本机 `%APPDATA%\Code\User\prompts\跨项目接续协议.instructions.md`；模板在 `tools/continuity/templates/`）。
> **开工先读（存在则读，按序）**：`.github/copilot-instructions.md` → `docs/项目接续指南.md` → `docs/用户档案.md` → `docs/项目记忆.md` → `docs/决策记录.md` 最新节。

## 每轮收尾（务必）

① `docs/决策记录.md` 新增一节（**含用户原话**）；② `tools/continuity/sync-memory.ps1` 同步记忆；③ 跑回归验证并如实汇报。

## 本项目要点（补充）

- **本仓库是库 crate（lib），无独立二进制**：对外只暴露 `pek_rwaf::{Waf, WafConfig, ...}`，由宿主服务以中间件方式接入。
- 兼容口径：规则集与 C# `Pek.WAF` 的 `Ruleset` 格式互通（同一份规则文件可双端共用），在此之上新增 `IsBotKind` 操作符。
- **限流只有一套引擎**：WAF CC（`ratelimit.rs`）与接口级限流（`throttle.rs`，对齐 C# `DH.RateLimter`）都复用 `dhrust::ratelimit`；
  不要在库内再新增 `Mutex<HashMap>` 计数实现；需要共享计数时实现 `CounterStore`（如 Redis）并注入。
- 改动后必须覆盖三端：`Pek.RPanlServer`、`HLZX.EIP`（以及任何 `route.use_middleware(waf.middleware())` 的宿主）。
- 构建/测试用 `cargo check` / `cargo test`；本机日常编译用 `cargo build --profile fast`，发版才用 `--release`（thin LTO）。
