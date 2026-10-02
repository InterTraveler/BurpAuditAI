---
name: 'OAuth 与 OIDC 流程漏洞分析'
icon: '🪪'
description: '当请求涉及 OAuth 2.0 / OIDC / SAML 流程时启用。典型信号：URL 含 oauth / authorize / token / callback / redirect_uri / client_id / response_type / scope / state / code / id_token / saml / assertion / acs / sso / connect / federate / well-known；响应头含 Bearer；Cookie / Authorization 头含 access_token / id_token / JWT 形态的字符串（且 3 段 Base64URL）；URL 出现在 /oauth / /auth / /login/oauth / /sso / /saml2 / .well-known/openid-configuration。不适用：纯自有账号体系（用户名 + 密码直接登录）、纯 API Bearer Token 调用（JWT 本身签名问题归 jwt-analyzer 技能）。'
findingType: 'oauth'
---

本技能专注于 OAuth 2.0 / OIDC / SAML 流程漏洞（authorization code 拦截、redirect_uri 绕过、PKCE 缺失、open redirect 串联 token 窃取、scope 越权、SSO 接管）。在你识别到 OAuth / OIDC / SAML 入口时，按以下流程处理：
1. 识别流程类型：Authorization Code（带 code 回调）/ Implicit（已淘汰，token 直接在 URL 段）/ Client Credentials（服务端对服务端，无用户）/ Password Grant（已淘汰）；OIDC 叠加 id_token 验签流程；SAML 是 XML 断言非 JSON。
2. 枚举 OAuth 关键攻击面：
   - redirect_uri 绕过：精确匹配 vs 路径前缀匹配 vs 域名匹配 vs 协议匹配 vs 大小写；尝试 https://attacker.com/cb vs https://target.com.attacker.com/cb vs https://target.com/cb/../cb vs https://target.com/cb?x=evil.com vs https://target.com/cb#@attacker.com vs https://target.com@attacker.com；
   - state 缺失：CSRF 登录（攻击者用自己 code 强制受害者绑攻击者账号）；state 不绑会话（可重放）；
   - PKCE 缺失：authorization code interception（公共客户端无 PKCE，攻击者拦截 code 直接换 token）；
   - scope 越权：客户端请求的 scope 与用户实际授权的 scope 是否一致；refresh_token scope 是否包含额外权限；
   - 客户端密钥泄露：JS bundle / 移动 app / 桌面 app 反编译出 client_secret；
   - 隐式流（Implicit）token 在 URL 段：Referer 头 / 日志 / 浏览器历史 / 跨页面 JS 变量均可泄露。
3. 给出 OIDC 特有攻击面：
   - id_token 验签缺失：直接 trust payload 改 sub / email / role 接管他人；
   - nonce 缺失：id_token 重放；
   - iss / aud 校验缺失：跨租户 token 接受（任意用户 token 都信）。
4. 给出 SAML 攻击面（专项，XSW 在 hunt-saml，但本技能视角先覆盖常见）：
   - 签名剥离：去掉 Signature 节点，部分旧解析器接受；
   - 注释注入：NameID 里塞 <!-- 分隔，被前端正则截断成 admin@target.com；
   - 接收方（ACS URL）可控。
5. 给出修复建议：redirect_uri 精确匹配（白名单字符级）；强制 PKCE（公共客户端必须）；state 必填 + 绑 session；scope 最小化；client_secret 永远不出现在前端 / 移动端；id_token 强验签 + 校验 iss/aud/exp/nonce。
所有由本技能产出的 finding 必须设置 type=oauth。多个技能可能同时被激活，本技能不负责 JWT 本身签名问题（alg=none / RS256→HS256 密钥混淆，那是 jwt-analyzer 技能）/ 开放重定向（仅当串联 OAuth 才归本技能，单独立 open redirect 归其他视角）/ XSS（OAuth 回调页 XSS）/ SSRF（SAML XXE）等类型的发现。
【重放建议】OAuth 漏洞 3 次硬上限（orchestrator 管控）按：
- 第 1 次：抓 authorization 请求，把 redirect_uri 改成 https://attacker.com/cb（精确匹配）或 https://target.com.attacker.com/cb（子域攻击）看是否接受；
- 第 2 次：抓回调请求，看 response 里 code 是否在 URL 段（拦截风险）/ state 是否绑定会话（CSRF 风险）；
- 第 3 次：拿到 code 后用自己 client_secret 换 token（验证 PKCE 缺失时直接换成功）。
redirect_uri 反射任意域且能换到 token = critical（ATO）；code 拦截换 token = high；state 缺失 = high（CSRF 登录）。本技能是"分析建议"而非"硬性规则"，最终判断权交给模型。
- 【反误报】给 finding 设 confidence 时，只在能解释清楚"为什么 ≥ 60" 时给 ≥60；判不成立 / 仅残留小概率不确定性（如 5%–20%）的疑似不要写进 findings——本插件解析阶段会再过一道阈值（约 30）兜底，但 prompt 层的克制才是从源头减少问题列表噪声 finding 的关键。
