---
name: '竞态条件分析'
icon: '⏱️'
description: '当请求涉及可能被并发访问的临界资源，且能从已观察到的多条历史请求摘要里看出"时序 / 复用 / 并发"线索时启用。典型信号：单条记录有数值/状态字段（balance / stock / coupon_count / invite_quota / vote_count / rate_limit_counter）、流程是 check-then-act（先查再改）、同域名历史摘要里出现 N 条几乎同一时间打同一端点的请求 / 同一 X-Request-ID 被复用 / 同一 token 短时间多次提交、目标有支付 / 提现 / 抢购 / 投票 / 邀请奖励 / 兑换码 / 限速计数等业务。不适用：纯幂等 GET、无状态变更的接口、单条记录只读操作、单条请求且历史摘要里找不到任何并发 / 复用线索。'
findingType: 'race-condition'
---

本技能专注于竞态条件（TOCTOU、双花、限速计数绕过、邀请奖励刷量、兑换码并发抢）。**本插件的视角是"被动分析已观察到的 HTTP 流量"，不是"主动并发攻击"——绝大多数竞态需要主动打 N 个并发请求才能复现，单条 replay_request 几乎无法验证**。在识别到 check-then-act 模式时，按以下流程处理：
1. 识别临界资源：单条数据库记录的数值字段（balance / stock / invite_count / coupon_status='unused'）、Redis 计数、内存里的限速计数器。
2. 推断窗口期：服务端在哪个瞬间做 check、下一个瞬间做 act。两个瞬间之间是否能被并发请求挤进去。
3. **优先利用历史摘要**（multi-message-correlation 注入的同域名近期请求列表）寻找已有线索：
   - 同秒 / 亚秒级出现 N 条相同 method+URL+body 的请求（用户主动连点 / 自动化脚本 / 已发生的并发刷量）；
   - 同一 X-Request-ID / Idempotency-Key / 业务流水号被多条请求共用；
   - 同一 session cookie / token 短时间在 N 个不同 IP / UA 出现（撞库 / 凭证复用）；
   - 状态字段在历史响应里出现矛盾（如前一条显示 coupon=unused，后一条已 used 但中间没有 redeem 记录）。
4. 给出常见攻击面：单条记录数值字段双花（提现 / 转账 / 支付）、优惠券 / 兑换码并发抢同一未使用记录、限速计数器未原子自增（先 GET 再 INCR，N 个请求共用同一旧值）、邀请奖励 count 自增未加锁、投票计数被刷、登录失败计数被绕过、注册时间戳竞态。
5. 给出修复建议：所有 check-then-act 改原子操作（SQL 用 UPDATE ... WHERE balance >= amount / SELECT ... FOR UPDATE / 数据库唯一约束 / 乐观锁 version 字段）；Redis 用 INCR / DECR 而非 GET+SET；限速计数用滑动窗口或令牌桶且必须原子。
所有由本技能产出的 finding 必须设置 type=race-condition。多个技能可能同时被激活，本技能不负责 SQL 注入 / XSS / SSRF / 鉴权 / 业务逻辑的价格覆盖（price=1，那是 business-logic）/ JWT 等类型的发现——那些交给对应专项技能。
【重放建议】**默认不发 replay_request**——竞态靠单次重放无法验证，3 次硬预算浪费在这里不划算。只在以下条件同时满足时才发 1 次：① 历史摘要里已找到 ≥2 条可作为"并发证据"的请求；② 用这条 replay 是想看"同端点同 body 是否仍能成功 2 次"作为旁证；③ orchestrator 明确允许。Burp Repeater 的"send group in sequence (single connection)"是用户在 Burp UI 里手动复现的最终手段，不在本插件自动重放范围内——本插件只在 finding 里说明"建议用户在 Repeater 里跑 single-packet attack / 连续 10-20 发"作为人工复现路径。
如果历史摘要里有"已发生并发的间接证据"（同秒 N 条相同请求、同一 token 复用、状态字段矛盾）即可给 medium；只有"理论上的竞态可能"无任何旁证，给 low / info，不浪费重放预算。本技能是"分析建议"而非"硬性规则"，最终判断权交给模型。
- 【反误报】给 finding 设 confidence 时，只在能解释清楚"为什么 ≥ 60" 时给 ≥60；判不成立 / 仅残留小概率不确定性（如 5%–20%）的疑似不要写进 findings——本插件解析阶段会再过一道阈值（约 30）兜底，但 prompt 层的克制才是从源头减少问题列表噪声 finding 的关键。
