---
name: 'GraphQL 注入与接口漏洞分析'
icon: '◆'
description: '当请求端点暴露 GraphQL API 时启用。典型信号：URL 含 /graphql / /gql / /query / /api/graphql；Content-Type 是 application/json 且 body 含 query / mutation / variables / operationName 关键字；POST body 是 GraphQL 查询语句；响应里出现 __schema / __type / data / errors 关键字；JS bundle 包含 apollo-client / relay / urql / graphql-request；目标返回 application/json 错误格式 {"errors": [{"message": "..."}, ...]}。不适用：纯 REST API、纯 SOAP（那是 http-smuggling 视角）、普通 JSON SQL 注入。'
findingType: 'graphql'
---

本技能专注于 GraphQL 注入与接口漏洞（introspection 信息泄露、IDOR via node() / GID、mutation 越权、批量攻击 / DoS、深度查询耗资源、SQL 注入穿透 ORM、auth bypass via unscoped mutations、二次注入）。在你识别到 GraphQL 端点时，按以下流程处理：
1. 识别 GraphQL 端点：
   - 探活：POST /graphql body {"query": "{__schema{types{name}}}"} 看是否返回 200 + types 列表；
   - 常见路径：/graphql、/api/graphql、/query、/gql、/v1/graphql、/graphql/v1、/api/v1/graphql；
   - 探 introspection：{"query": "{__schema{queryType{name}mutationType{name}types{name,kind,fields{name,type{name,kind,ofType{name,kind}}}}}"} }，如果返回完整 schema 可走自动化（clairvoyance / GraphQL Cop / InQL）。
2. introspection 利用：
   - schema 暴露 → 看所有 query / mutation 名称 → 找 admin_xxx / delete_xxx / reset_password 之类的 mutation；
   - 找 type 字段里的 sensitive_field（email / phone / ssn / password / isAdmin / role）；
   - 看 enum 里的可枚举值（status: [ACTIVE, BANNED, PENDING_VERIFICATION]）。
3. 常见攻击面：
   - **IDOR via node(id) / GID**（全局对象 ID 是 base64 编码的 type+id）：{"query":"{node(id:\"VXNlck5vZGU6MjM=\"){...on User{email,role,isAdmin}}"}"，遍历改 ID 可读任意用户；
   - **mutation 越权**：mutation 内部缺 auth 校验，普通用户调 admin_createUser / deleteUser；
   - **未授权 mutations**：mutation 不需登录即可调用，调用 changePassword(input: ...) 直接改密码；
   - **批量查询 / DoS**：[__typename, user, user, user, ...] × 1000 重复查询；
   - **深度嵌套 DoS**：{a{a{a{a{a{...}}}}}} × 1000 层；
   - **aliases 批量攻击**：{"query":"{a:user(id:1){email} b:user(id:2){email} ... × 1000}"};
   - **field duplication DoS**：__typename × 100000 字段复制；
   - **SQL 注入穿透 ORM**：search(query: "1' OR '1'='1") 拼进 ORM 的 raw SQL；
   - **二次注入**：mutation 创建 → 另一个 query 渲染时 SQL 触发；
   - **introspection DoS**：反复查 __schema 烧 CPU。
4. 给出修复建议：生产环境关 introspection（Apollo: introspection: false）；mutation 内部强制 auth 校验（不是中间件统一，每个 mutation 内部 assertAuth()）；IDOR 用数据库自增 ID 替代 GID（不要暴露）；rate limit 按 query 复杂度计算（graphql-query-complexity）；query depth limit（graphql-depth-limit 中间件，max 5-10）；alias 数量限制；SQL 走 ORM parameterized query，不要拼字符串。
所有由本技能产出的 finding 必须设置 type=graphql。多个技能可能同时被激活，本技能不负责 SQL 注入（GraphQL 内部 SQL 注入归 sql-injection）/ NoSQL 注入 / SSRF（GraphQL 内部参数 SSRF 归 ssrf）/ 鉴权（GraphQL mutation 缺 auth 归 auth-bypass 技能）等类型的发现。本技能专管"GraphQL 协议层漏洞"。
【重放建议】GraphQL 注入 3 次硬上限（orchestrator 管控）按：
- 第 1 次：introspection 探活（POST /graphql body 简单 query），拿 schema 摘要；
- 第 2 次：找 1 个最像 IDOR 的 query（user / node / me）改 ID 测越权（atkr token 换 victim ID）；
- 第 3 次：测 mutation 越权（用普通用户 token 调 admin 类 mutation，看是否被服务端拒）。
introspection 开放 = info / low（除非 schema 含敏感 mutation 名称）；mutation 越权 = critical；IDOR via GID = high（直接读到他人 PII）。本技能是"分析建议"而非"硬性规则"，最终判断权交给模型。
- 【反误报】给 finding 设 confidence 时，只在能解释清楚"为什么 ≥ 60" 时给 ≥60；判不成立 / 仅残留小概率不确定性（如 5%–20%）的疑似不要写进 findings——本插件解析阶段会再过一道阈值（约 30）兜底，但 prompt 层的克制才是从源头减少问题列表噪声 finding 的关键。
