---
name: '云凭证与 API Key 泄露分析'
icon: '🔑'
description: '当响应体 / 响应头 / JS bundle / HTML 注释 / 错误堆栈中出现云厂商凭证、第三方 API Key、SSH 私钥、数据库连接串、加密钱包助记词等高危凭据时启用。典型信号：响应体含 AK / SK 字符串（如 LTAI、AKID、AIza、ghp_、sk-、xoxb-、glpat-）、Token 字样；JS bundle 里硬编码的第三方 API（Map / GA / 推送 / 支付 / 短信 / OSS）；HTML 注释里的邮箱 / 密码；错误堆栈里含 jdbc:mysql / redis:// / mongodb:// 完整连接串；404 / 静态目录暴露 .env / config.json / application.yml / .git/HEAD；移动 App 反编译后看到的硬编码密钥。不适用：纯业务字段（账号 / 业务 token 都是后端自签）、已经在后端审计中明确合法的占位 API key（如 OAuth client_id 本来就是公开的）。'
findingType: 'cloud-credential-leak'
---

本技能专注于"高危凭据在 HTTP 响应中泄漏"的发现。这是 SRC / 红队里"一次拿到 = 直接接管整账号"的致命漏洞，赏金通常很高。在你识别到凭据模式时，按以下流程处理：
1. 扫描响应里的凭据指纹（按厂商分类）：
   - 阿里云：AccessKeyId 以 LTAI / STS 开头，长度 16-30；AccessKeySecret 长度 30+；完整格式 AKID:secret 一对。
   - 腾讯云：SecretId 以 AKID 开头（与阿里云有重叠，看前缀字段更准）；SecretKey 长度 40+。
   - AWS：AccessKeyId 以 AKIA / ASIA 开头 20 位；SecretAccessKey 长度 40+；SessionToken 三段 base64 拼接；账号 ID 12 位。
   - GCP：API key 以 AIzaSy 开头 39 位；Service Account JSON 含 private_key（PEM 格式 "-----BEGIN PRIVATE KEY-----"）。
   - Azure：ClientId / ClientSecret / TenantId 三元组；Storage Account Key 88 位 base64（含 / + 字符）。
   - Google API（独立）：AIzaSy 开头 39 位；Maps API key 39 位；reCAPTCHA secret 40 位。
   - GitHub Token：ghp_ / gho_ / ghu_ / ghs_ / ghr_ 开头 36 位；ghp_ 拿到 = 整个账号读写仓库权限。
   - Slack Token：xoxb- / xoxa- / xoxp- / xoxr- / xoxs- 开头；Bot User OAuth Token = 接管频道。
   - Stripe Live Key：sk_live_ 开头（不能放前端）；pk_live_ / rk_live_ 也算敏感；webhook secret（whsec_）拿到 = 伪造支付回调。
   - OpenAI / Anthropic / DeepSeek / Cohere：sk-... 开头（这些在企业内部代码里出现 = 内部计费账号被偷）。
   - 微信小程序 / 公众号 AppSecret 32 位：拿到 = 接管公众号 / 小程序。
   - 钉钉 / 飞书 / 企业微信：corpid / corpsecret / agentid。
   - JWT 签名密钥泄露：HS256 共享密钥 / RSA 私钥 → 直接伪造 token（这是 jwt-analyzer 之外的另个维度）。
   - 数据库连接串：jdbc:mysql://user:password@host:port/db、redis://:password@host:port、mongodb://user:password@host。
   - SSH / TLS 私钥：-----BEGIN OPENSSH PRIVATE KEY----- / -----BEGIN RSA PRIVATE KEY----- 出现在响应里。
   - 加密货币：mnemonic（12 / 24 个英文单词，固定 BIP39 词库）、Keystore JSON（{"address":"...","crypto":{...}}）。
   - 内网 / VPN：WireGuard 配置含 PrivateKey、OpenVPN .ovpn 含 <key> 标签、frpc / frps token。
   - 短信平台 / 推送 / 邮件 SMTP：ApiKey / AppSecret / 完整 SMTP 密码。
   - JWT 公私钥对：kid → jku / x5u 可被指；以及 jwk 明文出现。
2. 验证凭据是否仍可用（这是 finding 等级的关键）：
   - 阿里云：用 sts GetCallerIdentity 接口（无需授权，但 AK 配错会 403）。
   - AWS：sts:GetCallerIdentity（同样不需要授权调用）。
   - GCP：tokeninfo API 验 token 是否有效。
   - GitHub：GET /user（ghp_ 拿到 = 直接读 user）。
   - Slack：auth.test（xoxb- 拿到 = 直接读 bot 身份）。
   - 数据库连接串：拿到 = 直接连（如果网络可达）。
   - SMTP / 短信：拿到 = 直接发（成本可控，测一条就够）。
   - 注：**绝对不要尝试对生产目标做"登录验证"**，仅做"是否存在"+"权限范围"两步最小验证；任何发现写到 finding 里留人工复核。
3. 判断危害等级（按可接管范围）：
   - critical：阿里云 / AWS / GCP 顶级 AK 拿到 + GetCallerIdentity 返回有权限账号；GitHub ghp_ 拿到 + /user 返回 200；数据库连接串 / SSH 私钥 / Keystore 拿到。
   - high：Stripe live sk_、企业微信 corpsecret、Slack Bot Token、OpenAI/Anthropic sk- 拿到。
   - medium：微信公众号 AppSecret、Google API key（无 scope 限制的）、短信平台 ApiKey。
   - low：仅 pk_live_ 前端可见 key、OAuth client_id 本就公开的。
4. 给出修复建议：所有凭据移到服务端，客户端通过自建后端代理访问；用临时 STS / AssumeRole 替代长时 AK；GitHub 用 Fine-grained PAT 而非 ghp_；用 Secret Manager / KMS；前端 key 必须配 HTTP referer / IP 白名单 scope；response body 走脱敏中间件；错误堆栈 production 关闭；CI / 静态资源目录禁止放 .env / config.json / .git。
所有由本技能产出的 finding 必须设置 type=cloud-credential-leak。多个技能可能同时被激活，本技能不负责 JWT 签名算法本身（HS256 vs RS256 vs none，那是 jwt-analyzer）/ OAuth 流程漏洞（OAuth state 缺失、redirect_uri 不校验，那是 oauth）/ 数据库 / SSH 本身的暴露（那是 exposed-endpoints）。
【重放建议】凭据验证重放有 3 次硬上限（orchestrator 管控），按：
- 第 1 次：调用云厂商的"匿名可达"接口（GetCallerIdentity / tokeninfo / auth.test），确认是否仍可用；
- 第 2 次：如果第 1 次确认可用，立即停止进一步操作（避免触发风控），finding 写明凭据已确认有效，留人工处理；
- 第 3 次（仅在凭据失效的情况下）：用 grep / 字典在其它 endpoint / 备份文件里扫同源凭据（这是"扩散面"评估）。
仅凭指纹可见 = medium；指纹 + 云厂商匿名接口确认有效 = critical（同时立刻停止后续重放，避免触发风控）。本技能是"分析建议"而非"硬性规则"，最终判断权交给模型。
- 【反误报】给 finding 设 confidence 时，只在能解释清楚"为什么 ≥ 60" 时给 ≥60；判不成立 / 仅残留小概率不确定性（如 5%–20%）的疑似不要写进 findings——本插件解析阶段会再过一道阈值（约 30）兜底，但 prompt 层的克制才是从源头减少问题列表噪声 finding 的关键。
