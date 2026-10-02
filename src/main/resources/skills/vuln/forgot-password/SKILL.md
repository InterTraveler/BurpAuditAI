---
name: '密码重置与账户恢复漏洞分析'
icon: '🔑'
description: '当请求涉及账户恢复 / 密码重置 / 邮箱验证 / 手机验证流程时启用。典型信号：URL 含 forgot / reset / recover / verify / confirm / activate / invite / accept-invitation / change-email / change-password / set-password / first-login；请求方法为 POST 且 body 含 email / token / code / otp；响应里出现 reset_token / verification_code；多步骤流程（请求重置→收邮件→点击链接→设新密码）。**本技能只覆盖"HTTP 报文层能直接看到的证据"**——邮件正文 / 短信内容 / SMTP 客户端行为不在 Burp 被动分析范围，相关节点交由人工验证。不适用：纯登录接口（那是 auth-bypass 技能）、纯注册接口。'
findingType: 'forgot-password'
---

本技能专注于密码重置与账户恢复流程的漏洞。**本插件只能看到 HTTP 报文，看不到邮件 / 短信正文 / SMTP 客户端行为——下面的节点按"Burp 能否从请求/响应中直接拿到证据"分级**：
1. 枚举重置链路的 5 个关键节点：
   - 触发节点（POST /forgot 提交 email/手机号）→ 服务端发邮件 / 短信；
   - 凭证生成（token / 验证码）→ 写入 DB / 缓存；
   - 凭证传输（邮件 / 短信 / push）→ 用户接收；
   - 凭证校验（GET /reset?token=xxx 或 POST /verify code=123456）→ 校验有效性；
   - 重置生效（POST /reset-password 设新密码）→ 改写 DB。
2. **Burp 能直接拿到的证据**（重点分析）：
   - 触发节点：用户名枚举（合法 email 返回 200 + 消息，非法 email 返回 404 + 错误消息，响应时间差）。这条 Burp 完全能验。
   - 凭证生成：可预测 token（连续请求看 token 是不是顺序递增 / 时间戳 + 用户 ID + 简单 MD5 / base64 解码后含明文 user_id）、短验证码（4 位数字可暴力，由 sms-bombing 技能接手；本技能只负责"是否存在短验证码"的事实判断，不具体跑爆破）、一次性 token 重复使用可成功。
   - 凭证校验：响应体直接返回 token / code（前端逻辑问题，Burp 100% 能看到）、Referer 头泄露 token 给第三方资源、日志接口 / debug 端点回显 token。
   - 重置生效：改他人 token 仍生效（attacker 自己的 token 重置 victim 账户，旧密码仍能登录等）、改完密码后旧 session 未失效。
3. **需要邮件 / 客户端配合才能验证的节点**（**不**做主动重放，finding 里只列风险点 + 让人工复现）：
   - 邮件正文 HTML 注入（XSS 视角，归 xss-detector 技能）；
   - Host 头投毒（Host: evil.com 是否让重置链接投到 evil.com）—— Burp 只能"看 Host 头是否被原样拼到响应 Location"或"重放触发后看响应里是否暴露了完整链接"，完整邮件正文需要人工验证；
   - SMTP 注入（CRLF 改收件人 / 抄送）—— Burp 看不到 SMTP 对话，归人工复现。
   - 这三类不要消耗 orchestrator 的重放预算，发现可疑迹象时在 finding 里写"建议人工登录邮箱核对邮件正文 / 链接 Host"即可。
4. 给出修复建议：token 长度 ≥ 128 bit 随机、显式过期（15-30 分钟）、一次性且绑定用户（用后即失效）、不返回 token 到响应体、邮件链接生成用白名单 Host（不要直接拼接 Host 头）、改密码后失效所有现存 session。
所有由本技能产出的 finding 必须设置 type=forgot-password。多个技能可能同时被激活，本技能不负责鉴权（拿现有密码绕过登录，那是 auth-bypass 技能）/ 短信 / 邮件轰炸（OTP 可被无限发送，那是 sms-bombing 技能）/ OAuth 流程（OAuth 接管是 oauth 技能）/ XSS（邮件 HTML 注入是 XSS 视角）等类型的发现。
【重放建议】密码重置 3 次硬上限（orchestrator 管控）按：
- 第 1 次：触发节点测用户名枚举（发 attacker@target.com vs victim@target.com 对比响应体 / 时间差）；
- 第 2 次：拿到自己的 reset_token，看 token 长度 / 格式（base64？hex？时间戳？可预测？），试同一 token 重放 2 次（一次性校验？）；
- 第 3 次：精调用 attacker 的 token 改 victim 的密码（跨用户 token 复用，response 里看是否 200/302 成功）。
**不要**用重放来验证 Host 头投毒 / 邮件 HTML 注入 / SMTP 注入——这些 Burp 看不到证据，浪费预算。
response 里出现不同响应 / token 重复使用成功 / 跨用户 token 复用成功，可给 high。本技能是"分析建议"而非"硬性规则"，最终判断权交给模型。
- 【反误报】给 finding 设 confidence 时，只在能解释清楚"为什么 ≥ 60" 时给 ≥60；判不成立 / 仅残留小概率不确定性（如 5%–20%）的疑似不要写进 findings——本插件解析阶段会再过一道阈值（约 30）兜底，但 prompt 层的克制才是从源头减少问题列表噪声 finding 的关键。
