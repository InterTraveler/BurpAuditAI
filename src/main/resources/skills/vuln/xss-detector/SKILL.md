---
name: 'XSS 跨站脚本分析'
icon: '🧨'
description: '当请求中任意参数可能拼入 HTML / JavaScript / URL / CSS 上下文并由浏览器渲染时启用。典型信号：参数名含 q/search/comment/title/name/email/content/body/callback/redirect/url/next、Content-Type 含 text/html、响应 Content-Type 为 text/html、URL 出现在搜索/留言/个人资料/反馈/上传文件名/OAuth callback 等可输入场景。不适用：纯 API JSON 接口（无浏览器渲染）、纯静态资源、二进制下载（application/octet-stream）。'
findingType: 'xss'
---

本技能专注于 XSS（反射型 / 存储型 / DOM 型）风险的分析。在你识别到 XSS 迹象时，按以下流程处理：
1. 识别反射点：哪些参数最终会拼进 HTML 标签、属性、URL、script 块、CSS 块、JSON 字符串、HTTP header。
2. 判断上下文，决定绕过手段：
   - HTML 文本上下文：用 < > 编码绕过或新标签注入（<svg onload=...>、<img src=x onerror=...>）。
   - HTML 属性上下文：闭合引号 + 事件处理器（"><img src=x onerror=alert(1)>）。
   - script 块上下文：闭合 </script> 或用 \u003c 注入 JSON 字符串。
   - URL/href/src 上下文：javascript: 协议 + URL 编码绕过。
   - CSS 上下文：expression() / url(javascript:)。
   - JSON / JSONP 上下文：闭合 JSON 字符串后用 </script><img> 跳出，或把 Content-Type 改成 text/html 触发浏览器降级解析。
3. 给出最小复现 payload：基础向量 + 针对上下文调整后的绕过；并标注反射位置是"显式回显（响应体内）"还是"通过 DOM API 间接触发（前端 JS sink）"。
4. 给出修复建议：HTML 编码 + 白名单标签、CSP header（Content-Security-Policy: default-src 'self'）、HttpOnly/SameSite Cookie、对用户可控 URL 做协议白名单、关闭 inline JS。
所有由本技能产出的 finding 必须设置 type=xss。多个技能可能同时被激活，本技能不负责 SQL 注入 / SSRF / 鉴权等类型的发现。
【重放策略】XSS 必须靠"塞 payload 重放响应"才能确认。重放时按"三型 × 上下文"矩阵选 payload，不要每个点都硬试：
一、反射型 XSS（payload 在请求参数里、响应里原样回显）
- HTML 文本上下文：q=<svg/onload=alert(1)>  或  q=<img src=x onerror=alert(1)>
- HTML 属性上下文：q="><img src=x onerror=alert(1)> （先闭合双引号）
- 闭合 <script> 后再注：q=</script><img src=x onerror=alert(1)>
- JSON / JSONP 上下文：先看响应 Content-Type 是不是 application/json；如果是，复制请求把 Content-Type 改 text/html 重放，看浏览器是否被诱导降级解析（很多 JSONP 接口就是这样挂的）；同时试 q=<\\/script><img src=x onerror=alert(1)> 跳出 JSON 字符串。
- URL 上下文：q=javascript:alert(1)  （适用于 href/src/action/formaction）
- 编码绕过：服务端只过滤小写时试 q=<Svg/OnLoAd=alert(1)> ；只过滤 < > 时试 q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E 或 HTML 实体 &#60;img...&#62;。
二、存储型 XSS（payload 已经被存进库，二次访问触发）
- 提交 payload 后，**换会话/匿名/爬虫身份**再访问同一个资源（评论、商品、昵称），看响应里 payload 是否落地。
- 重点看"作者本人能改 → 其他用户/管理员能看"的链路（后台审核页、订单备注、用户名、头像文件名）。
- 存储型的反射点往往不在原请求的响应里，而在另一条 GET 的响应里——重放预算要留给那条 GET。
三、DOM 型 XSS（sink 在前端 JS，原始报文里看不到）
- 仅靠抓包和重放**无法验证**。重放只能确认"参数在响应里"+"后端没过滤"，但能否执行取决于前端 .innerHTML / document.write / eval / location 跳转。
- 结论应保守：只标"潜在 DOM XSS，建议人工确认 sink"，别直接下"已确认 XSS"。
- 给出"如果有人会做下一步"的具体路径：找到引用该参数的 .js 文件、定位 sink、给出 PoC。
四、判定准则（避免误报）
- "响应里出现 payload 字符串" ≠ "XSS"。必须落在可执行上下文里才算：
  ✓ 出现在 <script>...</script> 块里
  ✓ 出现在事件处理器属性（onclick/onerror/onload/onmouseover/...）
  ✓ 出现在 href=javascript: / src=javascript: / action=javascript: / formaction=javascript:
  ✓ 出现在 <style> 里的 expression() / url(javascript:)
  ✓ 注入到 JSON 字符串后用 </script> 跳出且 Content-Type 可被诱导为 text/html
  ✗ 只出现在普通 HTML 文本里、已经被 HTML 编码（&lt; &gt; &amp; &quot;）、被白名单标签剔除
  ✗ 只出现在响应头（X- 开头 / 自定义头）——反射型 XSS 在响应头能弹，但需要靠 fetch + 自定义 URL 构造，常规浏览器不渲染
五、重放预算与流程
- 总预算 3 次硬上限（orchestrator 管控），按"反射/存储"分配：
  - 反射型：先用 1 次 SVG 通用向量探反射点，命中后再用 1-2 次按上下文换 payload。
  - 存储型：1 次提交 + 1-2 次匿名访问确认。
  - DOM 型：1 次抓包取证即可，把预算留给别的发现。
- 每次重放改完 payload 必须**完整读响应体**，看 payload 落点、是否被编码、是否在 <script> 块内。
- 重放后如果被 WAF / 过滤器拦下，从响应里提取拦截规则的特征，绕过思路（如双写 s<scriptcript>、大小写 <ScRiPt>、注释隔开 <scr<!-- -->ipt>）写进 finding，不死磕。
六、对响应头的额外利用
- 如果反射点在响应头（Location / Set-Cookie / User-Agent 回显 / X-Forwarded-For 回显），可写 finding 提示"反射型 XSS via response header splitting / CRLF injection"，但能否弹窗要靠前端 JS 用 fetch + 自定义 URL 触发——标注为"理论可利用，需前端条件"。
本技能是"分析建议 + 重放剧本"而非"硬性规则"，最终判断权交给模型。XSS 的特点是"看着像但经常不是"——编码过了、白名单滤了、Content-Type 兜底了，都会让 payload 在响应里"原样回显但不执行"。重放的目的是**确认落点 + 确认上下文**，不是单纯看 payload 字符串是否出现。
- 【反误报】给 finding 设 confidence 时，只在能解释清楚"为什么 ≥ 60" 时给 ≥60；判不成立 / 仅残留小概率不确定性（如 5%–20%）的疑似不要写进 findings——本插件解析阶段会再过一道阈值（约 30）兜底，但 prompt 层的克制才是从源头减少问题列表噪声 finding 的关键。
