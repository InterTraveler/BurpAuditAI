---
name: '敏感数据泄露分析'
icon: '🔐'
description: '当响应体或响应头中可能包含本不应该返回的敏感信息时启用。典型信号：响应体为 JSON / XML / 文本，字段名含 password / token / secret / api_key / private_key / ssn / id_card / phone / email；响应头含 Server / X-Powered-By / X-AspNet-Version 等版本指纹；状态码 500 触发了堆栈回显。不适用：纯静态二进制资源（图片/视频/CDN）、明确已脱敏的接口（响应只含公开字段）。'
findingType: 'sensitive-data'
---

本技能专注于敏感数据泄露风险的分析。在你识别到敏感数据迹象时，按以下流程处理：
1. 扫描响应体关键字段：password、passwd、pwd、secret、token、access_token、refresh_token、api_key、apikey、private_key、session_id、cookie、authorization、ssn、id_card、phone、email、address、credit_card、cvv。
2. 扫描响应头指纹：Server、X-Powered-By、X-AspNet-Version、X-AspNetMvc-Version、Trace-Id（带堆栈的版本）、Set-Cookie 缺 HttpOnly/SameSite/Secure。
3. 扫描错误响应：500 状态码下响应体含堆栈、异常类名、SQL 语句、文件绝对路径。
4. 判断敏感度：账户密码 / 私钥 / 身份证为高危；内部 IP / 用户邮箱 / 业务字段为中危；版本指纹为低危。
5. 给出修复建议：响应字段白名单 / 字段脱敏（手机号中间四位、身份证生日）、关闭详细错误回显、Set-Cookie 加 HttpOnly + Secure + SameSite、敏感字段 HTTP-only 缓存控制（Cache-Control: no-store）。
所有由本技能产出的 finding 必须设置 type=sensitive-data。多个技能可能同时被激活，本技能不负责 SQL 注入 / XSS / SSRF / 鉴权等类型的发现。
【重放建议】敏感数据泄露主要靠"看响应"判断，但有几种典型场景重放能拿到更多证据：
- 故意发"非法输入"重放（如 id=99999999、id=-1、id=abc），逼出 500 错误页看是否带堆栈 / 异常类名 / SQL 语句 / 绝对路径（错误回显型信息泄露）；
- 把 Authorization / Cookie 头去掉重放，看未授权路径是否仍返回带敏感字段的响应（结合 auth-bypass 判断时尤其有用）；
- 在响应头里只看到 Server / X-Powered-By 这类指纹时，**不**建议重放（结果不会变），直接给低危 finding 即可；
- 对 Set-Cookie 缺 HttpOnly / Secure / SameSite 的情况，看原始请求的 context（是不是 HTTPS、是不是敏感操作）再判断；不用重放。
如果 500 响应里出现堆栈 / SQL / 路径，可直接给 high 结论；指纹类只给 low。重放预算 3 次硬上限（orchestrator 管控），多数情况下本技能不需要重放。本技能是"分析建议"而非"硬性规则"，最终判断权交给模型。
- 【反误报】给 finding 设 confidence 时，只在能解释清楚"为什么 ≥ 60" 时给 ≥60；判不成立 / 仅残留小概率不确定性（如 5%–20%）的疑似不要写进 findings——本插件解析阶段会再过一道阈值（约 30）兜底，但 prompt 层的克制才是从源头减少问题列表噪声 finding 的关键。
