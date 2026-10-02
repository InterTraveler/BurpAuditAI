---
name: 'JWT 令牌分析'
icon: '🪙'
description: '当请求头 Authorization 携带 Bearer token 且 token 形态为三段 Base64URL（header.payload.signature）时启用。典型信号：Authorization 头以 Bearer eyJ 开头、Cookie 含 access_token= / token=、URL 参数含 jwt=。不适用：非 JWT 形态的 token（自签名的十六进制串、纯 opaque session id）、未携带 token 的请求。'
findingType: 'jwt'
---

本技能专注于 JWT 风险的分析。在你识别到 JWT 迹象时，按以下流程处理：
1. 拆分三段并解码：header（alg / typ / kid）、payload（sub / iss / aud / exp / iat / jti / 自定义 claim）。
2. 检查签名机制风险：alg=none 接受、HS256 公钥误用为对称密钥（secret 即公钥 PEM）、RS256 切换到 HS256 密钥混淆、未校验签名直接 trust payload。
3. 检查 claim 风险：exp 缺失或为 0、iat 异常、aud 错配、iss 未校验、role / permissions / scope 等特权 claim 是否在客户端可改。
4. 给出复现思路：去掉签名、alg 切换、kid 注入、jku/jwk 头替换、jti 重放。
5. 给出修复建议：强制校验 alg 白名单、密钥按用途分离且长度足够（HS256 ≥ 256 bit）、exp/aud/iss 显式校验、token 绑定指纹（避免泄漏给第三方）。
所有由本技能产出的 finding 必须设置 type=jwt。多个技能可能同时被激活，本技能不负责 SQL 注入 / XSS / SSRF / 鉴权流程等类型的发现。
【重放建议】JWT 类问题通常需要"篡改 token 后看服务端是否仍认账"，强烈建议用 replay_request 验证：
- 把 alg 改成 "none"（或 "None"/"NONE"）并去掉 signature 段，重放看是否仍返回 200/业务数据（alg=none 接受）；
- 保留原 token 的 payload 但用对称密钥签名（HS256 + 公钥 PEM 当 secret 试），重放看后端是否走错路径（RS256→HS256 密钥混淆）；
- 篡改 payload 里 role / permissions / scope / sub 等特权 claim（如 "user" → "admin"），重放看是否影响响应内容或状态码（claim 越权）；
- 篡改 kid 头（kid SQL 注入 / 路径穿越 kid → 引用外部密钥），用空签名 / 已知弱 secret 重新签，重放看是否能验签通过；
- 在 jku / jwk 头里塞自己控制的公钥 URL，重放看后端是否按 URL 去拉公钥验签（jku/jwk 头替换）；
- 拿到 token 后不清退，重放到其它接口或一段时间后重放，看 jti / exp 是否真在校验。
如果响应内容/状态码与原请求一致，可直接给结论；否则按差异聚焦"是哪个字段被校验 / 哪个没被校验"。重放预算 3 次硬上限（orchestrator 管控），按假设优先级用。本技能是"分析建议"而非"硬性规则"，最终判断权交给模型。
- 【反误报】给 finding 设 confidence 时，只在能解释清楚"为什么 ≥ 60" 时给 ≥60；判不成立 / 仅残留小概率不确定性（如 5%–20%）的疑似不要写进 findings——本插件解析阶段会再过一道阈值（约 30）兜底，但 prompt 层的克制才是从源头减少问题列表噪声 finding 的关键。
