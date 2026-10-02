---
name: 'NoSQL 注入分析'
icon: '🍃'
description: '当请求参数可能被拼进 MongoDB / CouchDB / Redis / Cassandra 查询，且后端是 Node.js / Python / Java 时启用。典型信号：Content-Type 是 application/json 且 body 含复杂嵌套对象；参数名含 id / user / name / email / search / query / filter / where / find / $where / $gt / $ne / $regex；响应错误含 MongoError / BSON / ObjectId 字样；JS bundle / 抓包里看到 mongoose / mongodb / couchdb / redis 关键字；目标用 Express / Koa / Hapi / NestJS / Django + Mongo / Spring Data MongoDB。不适用：纯 SQL 注入（那是 sql-injection 技能）、纯 Elasticsearch（部分相似但 SQL 视角归 sql-injection）。'
findingType: 'nosql-injection'
---

本技能专注于 NoSQL 注入（MongoDB / CouchDB / Redis / Cassandra），重点是 MongoDB 因为最常见。在你识别到 NoSQL 入口时，按以下流程处理：
1. 识别 NoSQL 入口：
   - 关键指纹：mongoose.connect / mongodb:// 协议 / MongoError 错误类 / 响应里有 _id / ObjectId 字样；
   - 关键 payload 形态：JSON body 可传对象（不是字符串）{"$gt": ""} / {"$ne": null} / {"$regex": ".*"} / {"$where": "sleep(5000)"}；
   - query 字符串也可被后端解析为对象（Express 默认 qs 解析）：user[$ne]=xxx 等价 {"user": {"$ne": "xxx"}}。
2. MongoDB 注入分型：
   - **判活**：{"$gt": ""} 替代 username，看是否能绕过（任意 username 都返回 → 注入成功）；
   - **认证绕过**：POST /login body {"username": {"$ne": ""}, "password": {"$ne": ""}} 直接登录任意用户；
   - **数据提取**：{"$regex": "^a.*"} 配合盲注逐字符猜字段值（响应长度差 / 时间差 / 错误差）；
   - **时间盲注**：{"$where": "function(){if(this.username=='admin'){sleep(5000)} return true}"}；
   - **$where JS 执行**：{"$where": "function(){return this.username=='admin' || eval('...') }"}（MongoDB 4.x 之前支持）；
   - **serverStatus() 等函数**：{"$where": "function(){var s=db.serverStatus(); return s.host=='target' || eval('...') }"}。
3. CouchDB 注入：通过 _design 视图 / Mango 查询语法；不常见。
4. Redis 注入：CLI 命令注入（CONFIG SET dir / SAVE 等）通过 SSRF + gopher 协议，或者 Lua 脚本注入 EVAL。
5. 给出修复建议：参数类型严格校验（username 必须是字符串，不是对象）；用 mongoose Schema 类型校验；用 sanitize-html / mongo-sanitize 中间件过滤 $ 开头 key；不要把 user 输入直接当 MongoDB 查询条件（强制类型转换 toString）；用 parameterized query builder（mongoose 7+ 已部分修复）；Express 禁用 qs extended 模式（用 querystring）。
所有由本技能产出的 finding 必须设置 type=nosql-injection。多个技能可能同时被激活，本技能不负责 SQL 注入 / SSRF（Redis SSRF 走 gopher 协议归 ssrf 技能）/ 命令注入（$where 拿到 JS RCE 走 command-injection 视角）等类型的发现。本技能专管"NoSQL 查询被注入"层。
【重放建议】NoSQL 注入 3 次硬上限（orchestrator 管控）按：
- 第 1 次：把 username 字段从字符串改成 {"$ne": ""}，看是否绕过登录（判活 + 认证绕过一击）；
- 第 2 次：盲注猜字段值 {"$regex": "^a.*"} 配合响应长度差 / 时间差；
- 第 3 次：$where JS 执行 {"$where": "function(){return eval('1+1')==2}"} 探 JS 执行能力（4.x 之前）。
认证绕过直接登录 = critical；数据盲注拿到密码 hash = critical；$where 拿到 RCE = critical。本技能是"分析建议"而非"硬性规则"，最终判断权交给模型。
- 【反误报】给 finding 设 confidence 时，只在能解释清楚"为什么 ≥ 60" 时给 ≥60；判不成立 / 仅残留小概率不确定性（如 5%–20%）的疑似不要写进 findings——本插件解析阶段会再过一道阈值（约 30）兜底，但 prompt 层的克制才是从源头减少问题列表噪声 finding 的关键。
