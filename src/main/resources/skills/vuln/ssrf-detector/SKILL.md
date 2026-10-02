---
name: 'SSRF 服务端请求伪造分析'
icon: '🌐'
description: '当请求中的参数可能被服务端用来发起二次请求时启用。典型信号：参数名含 url/uri/host/endpoint/feed/proxy/callback/redirect/image/src/avatar/link、Content-Type 含 application/json 或 application/xml、URL 出现在图片代理、网页抓取、文件预览、OAuth callback、RSS 订阅、头像下载、短链服务等场景。不适用：客户端 JS 发起的纯前端跨域请求（无服务端中转）、纯静态资源。'
findingType: 'ssrf'
---

本技能专注于 SSRF 风险的分析。在你识别到 SSRF 迹象时，按以下流程处理：
1. 识别"可被服务端消费的 URL/主机/端口输入"：query 参数、body 字段、Referer、X-Forwarded-*、XML 外部实体、URL 协议头（gopher / file / dict / ldap）。
2. 推断内网可达性：是否会触发对 127.0.0.1 / 10.0.0.0/8 / 172.16.0.0/12 / 192.168.0.0/16 / 169.254.0.0/16 / 云元数据 169.254.169.254 的访问。
3. 给出探测 payload：http://127.0.0.1:port/、http://[::1]/、http://169.254.169.254/latest/meta-data/、DNS rebinding 思路、协议头 gopher://。
4. 给出修复建议：URL 白名单（scheme + host + port）、DNS 解析后再校验 IP 是否在黑名单段、关闭 30x 自动跟随到内网、剥离 file/gopher/ldap 等危险协议。
所有由本技能产出的 finding 必须设置 type=ssrf。多个技能可能同时被激活，本技能不负责 SQL 注入 / XSS / 鉴权等类型的发现。
【重放建议】SSRF 的本质是"用服务端发请求"，所以重放时把可控 URL 字段改成内网/危险地址，看响应即可验证：
- 把 URL 参数改成 http://127.0.0.1:port/ 或 http://[::1]/，重放看响应里是否出现本机服务的内容（内网探测）；
- 改成 http://169.254.169.254/latest/meta-data/ 或 http://169.254.169.254/computeMetadata/v1/，看是否返回云元数据（云租户凭证泄漏）；
- 改成 file:///etc/passwd、file:///c:/windows/win.ini，看是否回显本地文件（file 协议）；
- 改成 gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a 等协议头，验证是否允许非 http(s) 协议；
- 域名换成 DNS rebinding 测试域（如 1u.ms / rebind.network），看后端是否先解析后请求（DNS rebinding）；
- 对回显型场景，重点看响应体/响应头是否带内网内容；对盲打型，重点看响应时间（time-based）与服务端日志（如果可观测）。
如果响应里出现内网/云元数据/本地文件内容，可直接给结论；盲打场景可结合时间差异判断。重放预算 3 次硬上限（orchestrator 管控）。本技能是"分析建议"而非"硬性规则"，最终判断权交给模型。
- 【反误报】给 finding 设 confidence 时，只在能解释清楚"为什么 ≥ 60" 时给 ≥60；判不成立 / 仅残留小概率不确定性（如 5%–20%）的疑似不要写进 findings——本插件解析阶段会再过一道阈值（约 30）兜底，但 prompt 层的克制才是从源头减少问题列表噪声 finding 的关键。
