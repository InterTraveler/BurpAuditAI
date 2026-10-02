---
name: '反序列化漏洞分析'
icon: '📦'
description: '当请求体或响应体使用二进制 / 编码序列化格式，且服务端语言会反序列化该格式执行代码或调用方法时启用。典型信号：Content-Type 为 application/x-java-serialized-object、application/x-shockwave-flash、application/x-php-serialized、Content-Type 含 avro/protobuf/thrift/binary 字样；body 是 base64 开头 (rO0AB / O:8: 开头)；请求里带 type=JavaObject / format=binary 字段；Cookie 含 rememberMe= 字段（Shiro 反序列化指纹）。不适用：纯 JSON / 纯 form-urlencoded / 纯 multipart 请求（那些是注入类，不是反序列化）。'
findingType: 'deserialization'
---

本技能专注于反序列化漏洞（Java ObjectInputStream、PHP unserialize、Python pickle、.NET BinaryFormatter、Ruby Marshal）。在你识别到序列化格式时，按以下流程处理：
1. 识别序列化格式指纹：
   - Java：rO0AB 开头（base64 后的 ObjectInputStream），触发点常见于 RMI / JMX / 自定义协议 / Shiro rememberMe cookie（aes key 已知时）/ Spring 旧版 RCE；
   - PHP：O:8:\"stdClass\":... 形式，或 serialize() 输出；
   - Python：\x80\x04 或 \x80\x05 开头（pickle 协议 4/5）；
   - .NET：FF FE ... 或 BinaryFormatter 输出；
   - Ruby：\x04\x08 开头 Marshal.dump。
2. 推断 Gadget 链：Java 用 ysoserial 的 CommonsCollections / CommonsBeanutils / Jdk7u21 等；PHP 用 PHPGGC（laravel / thinkphp / guzzle 等链）；Python pickle 直接 __reduce__ 即可 RCE。
3. 给出最小复现 payload：用 ysoserial 生成 rO0ABXNy...，用 PHPGGC 生成 O:... ，用 pickle 脚本生成 b'\x80\x05...'；先选无害探测（如执行 whoami 写文件 / DNS 回调）再 RCE。
4. 给出修复建议：拒绝反序列化不可信输入（首选）；白名单允许的类（SerializationFilter / ObjectInputFilter）；用 Jackson / Gson / MessagePack / protobuf 替代 Java 原生序列化；PHP 用 json_decode 替代 unserialize；Shiro 升级并改 AES key。
所有由本技能产出的 finding 必须设置 type=deserialization。多个技能可能同时被激活，本技能不负责 SQL 注入 / XSS / SSRF / 鉴权 / 命令注入（拿到 RCE 后那是 command-injection 视角发现）。本技能专管"反序列化入口"。
【重放建议】反序列化一旦命中就是 critical，但触发需要 1-2 次硬探测，建议：
- 看请求里有 rO0AB / O:8: / \x80\x04 / Marshal 等指纹时，直接用对应 ysoserial / PHPGGC / pickle 脚本生成 payload 重放一次；
- Java 反序列化 payload 通常较大（>1KB），注意 Content-Length 是否被截断；
- 优先用 DNS / HTTP 回调探测（interactsh / dnslog）确认反序列化是否真执行了，避免在目标机器上直接写文件留下证据；
- 如果是 Shiro rememberMe cookie，先看是否需要 AES key（公开 key / 默认 key / 泄露的 key），再用 shiro-exploit / ysoserial 工具链；
- response 里看不到回显时（盲打），靠时间差或 OOB 回调判断。重放预算 3 次硬上限（orchestrator 管控）。
如果 OOB 回调命中或目标机器上能执行命令（写文件 / DNS 查询），直接给 critical 结论。本技能是"分析建议"而非"硬性规则"，最终判断权交给模型。
- 【反误报】给 finding 设 confidence 时，只在能解释清楚"为什么 ≥ 60" 时给 ≥60；判不成立 / 仅残留小概率不确定性（如 5%–20%）的疑似不要写进 findings——本插件解析阶段会再过一道阈值（约 30）兜底，但 prompt 层的克制才是从源头减少问题列表噪声 finding 的关键。
