---
name: '认证与授权绕过分析'
icon: '🛂'
description: '当请求涉及鉴权/会话/权限判断时启用。典型信号：URL 路径含 admin/manage/console/config/internal/private、请求方法为 POST/PUT/DELETE、Authorization / Cookie / X-Token 头存在、Referer / Origin 涉及受保护域、URL 含数字 id 或 uuid 类资源标识符。不适用：纯公开页面的 GET（无权限语义）、纯静态资源、未携带任何身份凭证的探测请求。'
findingType: 'auth-bypass'
---

本技能专注于认证与授权绕过风险的分析。在你识别到鉴权/越权迹象时，按以下流程处理：
1. 识别访问控制面：URL 路径（/admin、/api/v1/users/{id}）、HTTP 方法（GET 仅读 / POST 写 / DELETE 删）、Header（X-User-Id、X-Role、Authorization）、Cookie（session=、token=）。
2. 推断当前请求需要的权限层级：未登录 / 普通用户 / VIP / 管理员。
3. 给出越权/绕过复现思路：水平越权（改 id 访问他人资源）、垂直越权（普通用户改 role 调管理接口）、未授权访问（去掉 Authorization / Cookie 仍 200）、参数绕过（X-Original-URL、X-Rewrite-URL、路径 ../ 穿越）、方法绕过（GET 改 POST/PUT 后未鉴权）。
4. 给出修复建议：服务端统一鉴权中间件、不可信客户端 claim（不要从 X-User-Id 直接 trust）、资源级 ACL 而非角色级菜单、id 用不可枚举 token（UUIDv4）替代自增、登录态与权限独立校验。
所有由本技能产出的 finding 必须设置 type=auth-bypass。多个技能可能同时被激活，本技能不负责 SQL 注入 / XSS / SSRF / JWT 本身签名等类型的发现——JWT 签名层面的风险交给 JWT 技能。
【重放建议】鉴权类问题几乎都需要"对比两次响应"才能 100% 确认，建议用 replay_request 验证：
- 拿到原始请求后，先去掉 Authorization / Cookie / session 头重放一次，看是否仍返回 200（未授权访问）；
- 改 URL 路径里的 id（自增 → 改大一位、UUID → 改同格式他人值），重放看是否越权读到他人资源（水平越权）；
- 改 X-User-Id / X-Role 等客户端可控 claim（普通用户值 → 管理员值），重放看后端是否信任（垂直越权）；
- 对疑似有"路径白名单绕过"的接口，追加 X-Original-URL / X-Rewrite-URL 头，或在路径里插入 ;xxx、%2e%2e/、// 等变体重放；
- 改方法（GET ↔ POST/PUT/DELETE），重放看是否只对部分方法鉴权。
如果两次响应在状态码、Content-Length、关键字段上一致，可直接给结论；存在差异时再针对性追加 1～2 次重放定位最小复现链路。
重放预算由 orchestrator 统一管控（3 次硬上限），不必每次都跑满。本技能是"分析建议"而非"硬性规则"，最终判断权交给模型。
- 【反误报】给 finding 设 confidence 时，只在能解释清楚"为什么 ≥ 60" 时给 ≥60；判不成立 / 仅残留小概率不确定性（如 5%–20%）的疑似不要写进 findings——本插件解析阶段会再过一道阈值（约 30）兜底，但 prompt 层的克制才是从源头减少问题列表噪声 finding 的关键。
