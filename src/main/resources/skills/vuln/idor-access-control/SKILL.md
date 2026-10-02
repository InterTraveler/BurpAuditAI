---
name: 'IDOR 与水平越权分析'
icon: '🪪'
description: '当请求 URL / body 中包含资源 ID（数字、UUID、自增主键、外键），且能从前置请求里推断出"当前用户应该只能访问自己拥有的资源"时启用。典型信号：URL 路径形如 /api/users/{id} / /orders/{uuid} / /files/{fid}；body / query 含 owner_id / user_id / order_id / tenant_id；同一接口出现 A 用户 token 改 ID 后访问他人资源的现象。不适用：完全无 ID 概念的纯查询接口、管理后台全员可见的列表接口、未登录的公开页面。'
findingType: 'idor-access-control'
---

本技能专注于 IDOR（Insecure Direct Object Reference）与水平越权（Horizontal Privilege Escalation）的发现。这是 SRC 实测排名第一的高频漏洞，远比"垂直越权 / 鉴权绕过"常见。在你识别到资源型 ID 模式时，按以下流程处理：
1. 提取请求里的"资源定位符"：URL 路径段（/api/users/{id}）、query 参数（?file_id=12345）、body 字段（{"order_id": "abc"}）、Header（X-Project-Id）、cookie（PHPSESSID 之外的业务 id cookie）。
2. 推断"该 ID 应该归谁所有"：从以下线索拼接所有权——
   - 当前 token / session 解出的 user_id（看 Authorization 头、JWT payload、cookie）；
   - 历史报文里出现过的"我的 ID"（用户改自己资料时的 ID、改头像时的 file_id）；
   - 多报文协同（multi-message-correlation）注入的同域历史请求列表里，能看到该用户正常访问过的 ID 集合。
3. 判定越权维度：
   - 水平越权：相同角色的用户 A 改 ID 访问用户 B 的资源（最常见、SRC 赏金最高）；
   - 垂直越权：低权限用户改 ID / 改 role 访问管理资源（这通常是 auth-bypass 的范畴，本技能只在有明显 ID 模式时覆盖）；
   - 未授权访问：完全去掉 Authorization 后 ID 接口仍返回他人数据（同时落到 auth-bypass，本技能负责给出"具体能拿到哪些他人数据"）。
4. 给出可重放的修改方式（不一定要现在重放，给出最小复现路径）：
   - 自增整数 ID：+/-1、+/-1000、改为明显属于他人的 ID；
   - UUIDv4：无法暴力，但可以从历史报文里抓出他人用过的同接口 UUID 来替换（这就是为什么 multi-message-correlation 技能重要）；
   - 外键 ID：换成另一个已知存在的外键；
   - 路径 ID 段：替换为 admin / root / 1 / 0 等"特权值"。
5. 给出修复建议：服务端必须按"当前会话身份 + 资源所有者"双重校验，不能信任客户端传的 ID；用 UUIDv4 而非自增主键作为对外 ID（缓解而非解决）；批量接口加 ACL 过滤（WHERE owner_id = current_user）；导出 / 列表接口加分页 + 权限过滤。
所有由本技能产出的 finding 必须设置 type=idor-access-control。多个技能可能同时被激活，本技能不负责垂直越权 / 鉴权本身的缺失（那是 auth-bypass）/ 权限模型设计缺陷（那是 business-logic）/ 文件越权读（那是 lfi 视角，URL 形如 /files/{id}/download）等类型的发现。
【重放建议】IDOR 重放有 3 次硬上限（orchestrator 管控），按：
- 第 1 次：去掉 Authorization / Cookie 重放，确认接口本身是否需要登录（若 200 = 未授权访问 + IDOR 双高危）；
- 第 2 次：用当前用户 token + 修改 ID 到"明显属于他人"的值（自增 ID 改 +/-1；从历史抓出来的他人 UUID），看响应是否泄漏他人资源；
- 第 3 次（精调）：如果第 2 次返回 403 / 404，看是否有"内部错误码泄漏"（403 vs 404 区别 = IDOR 弱证据，证明服务端区分了"无权"与"不存在"）。
两次响应在状态码 / Content-Length / 关键字段上一致 = IDOR 确认。本技能是"分析建议"而非"硬性规则"，最终判断权交给模型。
- 【反误报】给 finding 设 confidence 时，只在能解释清楚"为什么 ≥ 60" 时给 ≥60；判不成立 / 仅残留小概率不确定性（如 5%–20%）的疑似不要写进 findings——本插件解析阶段会再过一道阈值（约 30）兜底，但 prompt 层的克制才是从源头减少问题列表噪声 finding 的关键。
