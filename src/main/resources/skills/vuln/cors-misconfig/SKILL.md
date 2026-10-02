---
name: 'CORS 跨域配置审计'
icon: '🚧'
description: '当响应头中携带 Access-Control-Allow-* 系列时启用。典型信号：响应含 Access-Control-Allow-Origin 头、Access-Control-Allow-Credentials: true、Origin 头携带跨域来源、请求方法为 application/json 的跨域 fetch / XHR。不适用：无任何 CORS 头的纯同源请求 / 纯静态资源 / 纯服务端 API 调用（浏览器外环境）。'
findingType: 'cors-misconfig'
---

本技能专注于 CORS 配置风险的分析。在你识别到 CORS 相关迹象时，按以下流程处理：
1. 提取响应头关键字段：Access-Control-Allow-Origin、Access-Control-Allow-Credentials、Access-Control-Allow-Methods、Access-Control-Allow-Headers、Access-Control-Expose-Headers、Vary: Origin。
2. 判断危险组合：Allow-Origin: * 与 Allow-Credentials: true 同时存在（浏览器其实会拒绝，但服务端配置意图错误）、Allow-Origin 反射 Origin 头且 Allow-Credentials: true、Allow-Methods 含危险方法、Allow-Headers 含 Authorization 且 Allow-Origin 反射任意来源。
3. 给出复现思路：用 attacker.com 域名发请求 + withCredentials=true，看响应是否设置 cookie 后回包可被读取。
4. 给出修复建议：白名单子域（不要反射）、Allow-Credentials 时严格匹配、敏感接口不返回 Access-Control-Allow-Origin、用 Vary: Origin 防缓存串扰。
所有由本技能产出的 finding 必须设置 type=cors-misconfig。多个技能可能同时被激活，本技能不负责 SQL 注入 / XSS / SSRF / 鉴权等类型的发现。
【重放建议】CORS 风险几乎都需要"换 Origin 重放"才能确认服务端策略，建议用 replay_request 验证：
- 把请求的 Origin 头换成 https://attacker.example，重放看 Access-Control-Allow-Origin 是否反射任意来源且 Allow-Credentials: true（最危险的组合）；
- 把 Origin 换成同站子域（如 https://evil.target.com vs https://target.com），看是否在白名单但又允许带凭证；
- 把 Origin 换成 null（Origin: null）或同源不同大小写（https://TARGET.com），看是否有绕过；
- 重点关注三个头组合：Access-Control-Allow-Origin / Access-Control-Allow-Credentials / Vary: Origin。后两个任一缺失，Allow-Origin 反射即可被中间缓存 / CDN 串扰放大；
- 复现时是浏览器场景，工具无法直接体现 withCredentials 行为；以"响应头"为唯一判断依据即可。
如果响应里出现 Access-Control-Allow-Origin 反射了攻击者可控的 Origin 且 Allow-Credentials: true，可直接给 critical 结论。重放预算 3 次硬上限（orchestrator 管控）。本技能是"分析建议"而非"硬性规则"，最终判断权交给模型。
- 【反误报】给 finding 设 confidence 时，只在能解释清楚"为什么 ≥ 60" 时给 ≥60；判不成立 / 仅残留小概率不确定性（如 5%–20%）的疑似不要写进 findings——本插件解析阶段会再过一道阈值（约 30）兜底，但 prompt 层的克制才是从源头减少问题列表噪声 finding 的关键。
