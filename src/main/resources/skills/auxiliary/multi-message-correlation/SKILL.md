---
name: '多报文协同分析'
icon: '🔗'
description: '把同域名近期 HTTP 请求（method/URL/状态码/headers/极简 body）附加到 user 段，便于模型结合历史行为分析当前请求。当本技能被激活时，无需任何 URL/方法前提——它本身只是"上下文注入器"；是否启用本技能由调用方按需决定，一般用于发现"当前请求是否偏离历史行为模式"的场景。'
findingType: 'behavior-anomaly'
userContext: |
  以下是同域名近期 {summaryCount} 条历史请求摘要（按时间倒序，每条含 method/URL/状态码/headers/极简 body）：
  {related}
summaryCount: 5
---

本技能专注于"当前请求与同域历史行为的偏离检测"。在你拿到附加的历史请求摘要时，按以下流程处理：
1. 维度对照：URL 路径、HTTP method、状态码、关键 Header（Authorization / Cookie / Content-Type / User-Agent / Referer）、响应体量（Content-Length）。
2. 异常信号识别：同一会话突现新 IP / UA、状态码从 200 变 403/500、参数突然带 SQL/HTML/路径穿越字符、Content-Length 异常放大、出现未授权访问的路径前缀（/admin、/internal）。
3. 推断风险：偏离既可能是正常业务演进，也可能是会话劫持、CSRF 跨会话触发、探测扫描、撞库。需结合路径与参数语义判断。
4. 输出：仅当偏离指向"潜在攻击 / 异常行为"时给出 finding，type=behavior-anomaly；纯正常演进不报。
5. 不要把历史请求当作"分析目标"——历史只用于"判断当前请求是否异常"。当历史与当前矛盾时，以当前请求的报文为准。
所有由本技能产出的 finding 必须设置 type=behavior-anomaly。多个技能可能同时被激活，本技能不负责 SQL 注入 / XSS / SSRF / 鉴权 / 命令注入 / 业务逻辑等具体漏洞类型的发现——本技能专管"行为偏离"维度。
本技能是"分析建议"而非"硬性规则"，最终判断权交给模型。
