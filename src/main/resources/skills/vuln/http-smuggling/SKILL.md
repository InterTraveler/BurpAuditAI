---
name: 'HTTP 请求走私分析'
icon: '🪤'
description: '当请求通过反向代理（nginx / apache / CDN / WAF）转发到上游应用服务器，且请求使用了非标准 Content-Length / Transfer-Encoding、或同一连接复用了多个请求时启用。典型信号：Transfer-Encoding: chunked 与 Content-Length 同时存在、Transfer-Encoding 值大小写变体（Chunked / chUnked）、同一 socket 上连续多个请求、目标站点使用代理 + 后端语言不一致（如 nginx + Tomcat）、请求头里出现 CL.TE / TE.CL 模糊地带。不适用：纯单请求浏览器交互（无代理场景）、纯静态资源 CDN 回源。'
findingType: 'http-smuggling'
---

本技能专注于 HTTP 请求走私（HTTP Request Smuggling）风险的分析。在你识别到走私迹象时，按以下流程处理：
1. 识别协议歧义点：Content-Length 与 Transfer-Encoding 同时存在、Transfer-Encoding 值大小写或额外空格（Transfer-Encoding: chunked\r\n vs \tchunked）、同一连接下一个请求可能被错位解析。
2. 推断前后端解析差异：CL.TE（前端看 CL、后端看 TE）、TE.CL（前端看 TE、后端看 CL）、TE.TE（前后端都接受 TE 但对变体容忍度不同）。
3. 给出复现 payload：用一个"前缀请求"消耗预期 CL，剩余字节作为"后缀请求"的起始——后缀请求将被下一个真实用户继承，从而窃取会话 / 投毒缓存。
4. 给出修复建议：使用 HTTP/2 终结歧义、前后端统一解析库（禁用 TE 或强制禁用 CL 二选一）、拒绝同时带 CL 和 TE 的请求、对 TE 头严格校验格式。
所有由本技能产出的 finding 必须设置 type=http-smuggling。多个技能可能同时被激活，本技能不负责 SQL 注入 / XSS / SSRF / 鉴权等类型的发现。
【重放建议】走私的"前缀请求+后缀请求"模式无法靠单条 replay_request 完整复现（需要同连接上的二次请求），但仍可借重放拿到"前后端解析差异"的初步证据：
- 同一目标分别发"只带 CL" / "只带 TE: chunked" / "同时带 CL 和 TE" 三条请求，比对响应状态与 Content-Length 是否有反常（被前后端错位消费）；
- 对 TE 头加大小写 / 空格变体（Transfer-Encoding: chunked\r\n → \tchunked / Chunked / chunKed）重放，看是否被前端接受、后端拒绝（TE.TE）；
- 复现后缀请求窃取会话的"二次请求"必须用 raw socket 在 Burp Repeater 手动操作，**本技能默认不要求**通过 replay_request 完成——只做"协议歧义点"层面的判定就够。
如果只是"协议歧义存在"但没复现后缀请求继承，给 medium；完整复现了再给 high。预算 3 次上限（orchestrator 管控）。本技能是"分析建议"而非"硬性规则"，最终判断权交给模型。
- 【反误报】给 finding 设 confidence 时，只在能解释清楚"为什么 ≥ 60" 时给 ≥60；判不成立 / 仅残留小概率不确定性（如 5%–20%）的疑似不要写进 findings——本插件解析阶段会再过一道阈值（约 30）兜底，但 prompt 层的克制才是从源头减少问题列表噪声 finding 的关键。
