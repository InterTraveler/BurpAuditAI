---
name: '文件上传漏洞分析'
icon: '📤'
description: '当请求体含 multipart/form-data 上传文件、且服务端会对上传内容做存储 / 解析 / 渲染时启用。典型信号：Content-Type 是 multipart/form-data、含 filename= / Content-Disposition: form-data 头、URL 在头像上传 / 附件上传 / 文件导入 / 富文本编辑器 / 文档转换 / PDF 预览 / SVG 上传 / 文档解析等场景。不适用：纯表单文本提交、纯 JSON 接口、客户端只读下载。'
findingType: 'file-upload'
---

本技能专注于文件上传漏洞（webshell、SVG XSS、HTML XSS、DOCX XXE、文件名路径穿越、Content-Type 绕过、二次渲染 RCE）。在你识别到文件上传入口时，按以下流程处理：
1. 识别上传链路：上传点（头像 / 附件 / 文档）→ 存储路径（本地 / 对象存储 / OSS）→ 访问方式（直链 / CDN / 重命名 / Content-Disposition: attachment）→ 解析执行（哪些 MIME / 扩展名会被解析）。
2. 推断可利用的扩展名 / MIME：
   - 直链访问 + 解析：php / jsp / asp / aspx / py（看后端语言）；war（Tomcat）；html / htm（可能 XSS 但也可能是 RCE 如果有 include）；
   - 二次渲染：svg（XSS / XXE）、html / htm（XSS）、docx/xlsx/pptx（XXE）；
   - 仅存储 + Content-Type 嗅探：gif89a 头 + PHP 代码（部分老旧 Apache 解析漏洞）；
   - 路径穿越：filename=../../shell.php（看存储路径是否拼接用户输入）。
3. 给出 bypass 思路（按服务端校验顺序）：
   - 扩展名校验在后：shell.php.jpg / shell.jpg.php / shell.php%00.jpg / shell.phtml / shell.php5 / shell.PhP；
   - Content-Type 校验在前：把 Content-Type 改成 image/jpeg 但实际是 PHP 文件；
   - 黑名单不全：.phtml / .php3 / .php4 / .php5 / .pht / .phps（看 Apache 配置）；
   - Windows 特性：shell.php. / shell.php::DATA / shell.php. .（NTFS ADS）；
   - 大小写：shell.PhP / shell.pHp；
   - 双写：shell.pphphp（中间 ph 被去）；
   - .htaccess 上传：上传 .htaccess 改变同目录解析规则（AddType application/x-httpd-php .jpg）。
4. 给出修复建议：
   - 白名单扩展名（不要黑名单）；
   - 重命名文件（UUID.扩展名）+ Content-Disposition: attachment 强制下载；
   - 存储与 Web 根目录分离（用户上传到 /uploads，Web 根在 /var/www，文件无法被解释执行）；
   - 二次渲染场景（SVG / DOCX）做内容消毒；
   - 服务端二次校验 Content-Type（MIME sniff，magic bytes）。
所有由本技能产出的 finding 必须设置 type=file-upload。多个技能可能同时被激活，本技能不负责 XSS（仅限 SVG/HTML 文件内容 XSS）/ XXE（DOCX/PPTX 内 XXE）/ 路径穿越（仅 filename 字段，纯路径穿越归 lfi 技能）/ 业务逻辑（头像上传后审核绕过，那是 business-logic）等类型的发现。
【重放建议】上传漏洞 3 次硬上限（orchestrator 管控）按：
- 第 1 次：探后端语言（尝试 .php / .jsp / .aspx 看哪个返回 200 还是被拦）；
- 第 2 次：按后端选 1 个最小 webshell（<?php echo md5(1);?> / <%@page import="java.util.*"%><%=new java.util.Date()%>）试 1-2 个 bypass（双扩展名 / Content-Type 改）；
- 第 3 次：拿到执行后写一个稳定一句话 + 文件管理（注意：仅证明漏洞立即停手，**不要**在目标上写很多文件留痕）。
上传成功 + 能访问 + 看到 echo 输出，给 critical；上传成功但访问不到（被重命名 / Content-Disposition 拦截）给 high；扩展名被严格白名单拦下但发现 filename 字段可注入 ../ 给 medium。本技能是"分析建议"而非"硬性规则"，最终判断权交给模型。
- 【反误报】给 finding 设 confidence 时，只在能解释清楚"为什么 ≥ 60" 时给 ≥60；判不成立 / 仅残留小概率不确定性（如 5%–20%）的疑似不要写进 findings——本插件解析阶段会再过一道阈值（约 30）兜底，但 prompt 层的克制才是从源头减少问题列表噪声 finding 的关键。
