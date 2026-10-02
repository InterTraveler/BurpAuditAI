---
name: 'Spring Boot 漏洞分析'
icon: '🌱'
description: '当目标技术栈为 Java Spring / Spring Boot 时启用，无论请求是哪个端点都应激活本技能做主动发现。典型信号：响应头含 X-Application-Context / Server: Netty（WebFlux）/ 错误页含 "Whitelabel Error Page" / "Spring" 字样、404/500 报错栈里有 org.springframework.web / org.springframework.boot / org.apache.catalina；URL 含 /actuator / /env / /heapdump / /trace / /jolokia / /h2-console / /swagger-ui / /v3/api-docs；JS bundle 里出现 spring / springframework 字样；目标用 .jar 部署（jar 启动脚本中含 spring-boot）。**本技能覆盖"Burp 被动分析 + 主动重放"两层能直接拿到证据的入口，heapdump / 离线 OQL 之类需要外部工具的环节归人工复现**。不适用：纯前端 SPA、Node/PHP/Go/Python 栈、非 Spring Java 框架（Struts/JSF 走对应专项）。'
findingType: 'spring-boot'
---

本技能专注于 Spring Boot 生态漏洞（Actuator 未授权信息泄露、SpEL 注入、Spring4Shell、Spring Cloud Function SPEL、H2 console RCE、Jolokia JMX、Swagger UI 信息暴露）。在你识别到 Spring Boot 技术栈时，按以下流程处理：
1. Actuator 端点枚举（默认 13 个 + 自定义）：
   - 高危：/actuator/env（环境变量含数据库密码 / 密钥）、/actuator/configprops（@ConfigurationProperties 全量）、/actuator/beans、/actuator/mappings（全 URL 映射）、/actuator/trace（最近 100 个 HTTP 请求含 header / cookie）、/actuator/loggers、/actuator/shutdown（POST 关服务）；
   - 中危：/actuator/health、/actuator/info、/actuator/metrics、/actuator/conditions；
   - 默认暴露：management.endpoints.web.exposure.include 决定哪些可访问。
   - **/actuator/heapdump 是高危但 Burp 拿不到完整证据**（堆转储是 GB 级二进制，本插件只看到响应头 Content-Type / Content-Length 跟状态码 200，无法解析 .h2o 找密码）—— 发现可访问时**不**做主动重放，在 finding 里标 critical 并写"建议用户下载后用 VisualVM / EclipseMAT 离线 OQL 查 password / secret / key 关键字"即可，**不要**消耗 orchestrator 重放预算。
2. 探测命令（Burp 重放能直接验证的）：
   ```
   /actuator /actuator/env /actuator/health /actuator/mappings
   /actuator/beans /actuator/configprops /actuator/trace /actuator/loggers
   /actuator/conditions /actuator/info /actuator/metrics /actuator/shutdown
   /env /jolokia /h2-console /swagger-ui.html
   /v3/api-docs /v2/api-docs /swagger-resources
   ```
   **/actuator/heapdump 不要列进 Burp 重放清单**——拿不到解析结果，浪费预算。
3. **Burp 响应里能直接拿到的凭证类证据**（重点看 /actuator/env 响应体）：
   - 含 jdbc:mysql / jdbc:postgresql / redis:// 等连接串 + 跟 username / password 同 key；
   - 含 jwt.secret / signing-key / encryption-key 等密钥字段；
   - 含 AKID / SK / api_key / access_secret 等云厂商凭据；
   - 含 spring.datasource.password / spring.redis.password 明文。
   这类直接看 JSON 文本即可，**不**需要下载 heapdump。
4. SpEL 注入：payload `${7*7}` / `${T(java.lang.Runtime).getRuntime().exec('id')}`；常见触发点：
   - Spring 表达式（@Value("${user.input}")）
   - Spring Cloud Function SPEL（CVE-2022-22963）：通过 spring.cloud.function.routing-expression 头注入
   - Spring Data Commons（CVE-2018-1273）：@Repository 排序参数
   - ViewManipulator / Whitelabel error page
5. Spring4Shell（CVE-2022-22965）：JDK 9+ + Spring 5.3.x < 5.3.18 / 5.2.x < 5.2.20，class.module.classLoader.DefaultAssertionStatus 等字段触发 RCE，参数 class.module.classLoader.resources.context.parent.pipeline.first.pattern 写入 webshell。
6. H2 console：若开发环境 H2 数据库 console 暴露在公网，可执行 SQL：CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException { ... }$$; CALL SHELLEXEC('id')。
7. 给出修复建议：Actuator 端点 management.endpoints.web.exposure.include 只暴露 health/info；加 spring.security.user.* 鉴权或独立管理端口（management.server.port 区分公网）；heapdump 仅内网；升级 Spring 到最新（覆盖 Spring4Shell / Spring Cloud Function / CVE-2024-）；H2 console 禁用或仅 localhost；Jolokia 加认证。
所有由本技能产出的 finding 必须设置 type=spring-boot。多个技能可能同时被激活，本技能不负责通用 SSRF（Actuator env 走 SSRF 视角归 ssrf）/ 命令注入（SpEL RCE 拿到执行也归 command-injection）/ 反序列化 / SSTI（Freemarker 模板 RCE 走 ssti 技能）等类型的发现。本技能专管"发现 Spring Boot 入口 + 已知 CVE"。
【重放建议】Spring Boot 漏洞 3 次硬上限（orchestrator 管控）按：
- 第 1 次：批量跑 /actuator/* 端点枚举（一次发 10+ 个请求快速探明哪些 200），同时在响应里 grep 出 jdbc / password / secret / key 等关键字（这就是 critical 凭证泄露证据，不需要 heapdump）；
- 第 2 次：对最可疑的端点（如 /actuator/env）做"删 Authorization / Cookie 头重放"，看是否未授权可访问（结合 auth-bypass 技能判定）；
- 第 3 次：试 SpEL 注入（${7*7} 验证回显 49 → 进一步 RCE payload）或 Spring4Shell payload。
**不要**对 /actuator/heapdump 做主动重放——响应是 GB 级二进制本插件处理不了。在 finding 里标 critical 即可。
/actuator/env 含明文数据库密码 / Spring4Shell 写 webshell 成功 / SpEL RCE 命中 = critical（数据库密码是直接 P0）；actuator 全部 404 但仍识别到 Spring 框架 = info；heapdump 200 但本插件无法解析 = critical（已暴露面但需用户离线取证）。本技能是"分析建议"而非"硬性规则"，最终判断权交给模型。
- 【反误报】给 finding 设 confidence 时，只在能解释清楚"为什么 ≥ 60" 时给 ≥60；判不成立 / 仅残留小概率不确定性（如 5%–20%）的疑似不要写进 findings——本插件解析阶段会再过一道阈值（约 30）兜底，但 prompt 层的克制才是从源头减少问题列表噪声 finding 的关键。
