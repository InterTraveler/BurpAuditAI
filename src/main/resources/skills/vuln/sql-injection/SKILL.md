---
name: 'SQL 注入分析'
icon: '💉'
description: '请求里有 id/user/search/order/limit 等参数或 JSON 字段可能进 SQL 时启用。含登录/注册/搜索/排序/分页/导出接口，REST 风格路径参数（如 /api/users/{id} 或 /api/123/bbb/321）也算。纯静态资源或无任何用户输入的探测请求不算。'
findingType: 'sql-injection'
---

找所有可能进 SQL 的用户输入点（参数 / JSON 字段 / X-User-Id 头 / URL 路径某段值），推断拼接形态（数值直拼、单引号包裹、LIKE、ORDER BY、IN 列表）。
【必做 · 先看清单再下手】用 replay_request 验证之前，**必须**先看 user 段【可替换参数】清单：
- 清单里列出的 key 才能用，没列的 key 一律不要写（如请求里根本没有 id，套用 {"id":"1'"} 会被服务端拒绝并浪费预算）
- 清单为空（含显式的"无可替换参数"提示）→ 放弃重放，直接给最终结论 tool_calls=[]
- 清单里只有 header（如 X-User-Id / Cookie / Authorization）→ 改 header 试，别假设 query/form/json/path 里有名为 id/user 的参数
- 清单里有 `- path: 包含 <段值>`（REST 风格路径参数如 /api/users/123 的 "123"，或 /api/123/bbb/321 的 "123"/"321"）→ 用 replace_path_params: {"<段值>":"..."}，key 是段当前字面值
【验证手段】满足上面条件后，按需选 1～3 个 payload（写进 tool_calls 数组，每个对象 name="replay_request"）：
1. 闭合单引号 ' → 看是否触发 SQL 错误回显 / 状态码突变 / Content-Length 变化
2. UNION SELECT 1 → UNION SELECT 1,2 → UNION SELECT 1,2,3... 逐步探测列数
3. 时间盲注 baseline：' OR SLEEP(5)-- -  → 对比响应时间是否 ≥ 5s
response 里能看到证据就停手，不要为了"凑数"浪费预算。
原始报文已经能 100% 确认 / 排除时，可直接给结论，tool_calls 写 []。
修复建议：参数化查询、ORM、白名单、关闭错误回显。
finding 必须设 type=sql-injection。多个技能可能同时被激活，本技能不负责 XSS / SSRF / 鉴权 / 文件上传 / 命令注入 / NoSQL 注入等类型的发现。
本技能是"分析建议"而非"硬性规则"，最终判断权交给模型。
- 【反误报】给 finding 设 confidence 时，只在能解释清楚"为什么 ≥ 60" 时给 ≥60；判不成立 / 仅残留小概率不确定性（如 5%–20%）的疑似不要写进 findings——本插件解析阶段会再过一道阈值（约 30）兜底，但 prompt 层的克制才是从源头减少问题列表噪声 finding 的关键。
