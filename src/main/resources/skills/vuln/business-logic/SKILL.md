---
name: '业务逻辑漏洞分析'
icon: '💼'
description: '当请求涉及金额、数量、优惠券、积分、库存、状态流转、支付、订单、退款、提现等业务字段时启用。典型信号：URL 含 order/pay/refund/coupon/withdraw/transfer/balance/price/amount/quantity 关键字；请求方法为 POST/PUT/DELETE 且 body 含数值字段；响应里出现总价、折扣、余额变化；多步骤流程（创建订单→支付→发货→退款）任一节点。不适用：纯查询接口（无状态变更）、纯静态资源、无业务语义字段的 CRUD。'
findingType: 'business-logic'
---

本技能专注于业务逻辑漏洞（价格篡改、负数量、优惠券重复用、并发抢兑、支付绕过、状态机错位等）。在你识别到业务字段时，按以下流程处理：
1. 识别业务流程的所有状态机：创建→支付→发货→确认→退款 / 提现→审核→到账。每个状态之间的转换条件是什么，前置状态能否被绕过直接跳到后置。
2. 推断数值字段的信任边界：哪些字段是服务端最终计算、哪些是客户端可改（price=、amount=、quantity=、discount=、balance=）。如果客户端传了 price 而服务端又重算，只看"重算是否被绕过"。
3. 给出常见攻击面：负数量（-1 件 × 单价 = 退款）、0 元/极小金额（price=0.01）、金额单位混淆（元 vs 分）、数量为小数（0.001 比特币）、价格覆盖（POST 里多塞一个 price= 字段）、优惠券重复使用（同一 code 多次 redeem）、状态跳过（从 created 直接跳到 delivered）、并发抢兑（limit=1 但 N 个请求同时进）。
4. 给出修复建议：服务端是单一权威价，所有客户端传的 price/amount/quantity 必须重算或忽略；状态机用 token/signature 校验不可跳；优惠券 / 积分 / 库存用原子操作（SELECT FOR UPDATE / Redis 锁 / 数据库唯一约束）；金额一律用最小单位整数（分）传输。
所有由本技能产出的 finding 必须设置 type=business-logic。多个技能可能同时被激活，本技能不负责 SQL 注入 / XSS / SSRF / 鉴权流程 / 越权（id 改他人）/ JWT 本身签名等类型的发现——那些交给对应专项技能。
【重放建议】业务逻辑漏洞几乎都要"对比修改前后的状态变化"才能确认，建议用 replay_request 验证：
- 把 price=1000 改成 price=1 或 price=0.01 重放，看下单时是否真的以 1 元成交（金额覆盖）；
- 把 quantity=1 改成 quantity=-1 重放，看是否生成退款（负数漏洞）；
- 同一优惠券 code 在 3 次硬预算内（orchestrator 管控）连续 redeem，看是否被多次使用（重放用券）；
- 用 HTTP/1.1 keep-alive 或 Burp Repeater 的"send group in sequence (single connection)"发 5-10 个并发支付请求，看库存 / 余额是否被双扣（竞态双花，业务逻辑与 hunt-race-condition 重叠时可双技能并发）；
- 跳过中间状态：从 created 直接 PUT 到 /order/{id}/delivered 重放，看是否真能跳过支付。
如果响应里出现"金额与请求不一致仍成功"、"状态机被跳过"、"同一券被多次使用"的证据，可直接给 high/critical 结论。本技能是"分析建议"而非"硬性规则"，最终判断权交给模型。
- 【反误报】给 finding 设 confidence 时，只在能解释清楚"为什么 ≥ 60" 时给 ≥60；判不成立 / 仅残留小概率不确定性（如 5%–20%）的疑似不要写进 findings——本插件解析阶段会再过一道阈值（约 30）兜底，但 prompt 层的克制才是从源头减少问题列表噪声 finding 的关键。
