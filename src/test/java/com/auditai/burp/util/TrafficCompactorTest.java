package com.auditai.burp.util;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link TrafficCompactor} 单元测试。
 *
 * <p>所有用例在断言前都用 {@link System#out} 打印"输入 / 输出 / 长度"，方便在
 * mvn test 输出中直观看到压缩效果。所有 {@code assertTrue} 都带 "actual=..." 消息，
 * 失败时能直接看到真实输出。</p>
 *
 * <p>测试策略：</p>
 * <ul>
 *   <li><b>底层方法</b>（{@code formatHeaderLine / compactBody / looksLikeJson} 等）
 *       —— 不依赖 Montoya，直接调 package-private 静态方法；</li>
 *   <li><b>原始字节入口</b>（{@code compactRawRequest/Response/Pair}）—— 面向"调用方只持
 *       raw bytes、没有 Montoya 句柄"的场景，直接喂原始 HTTP 字节断言压缩行为。</li>
 * </ul>
 */
class TrafficCompactorTest {

    @BeforeAll
    static void banner() {
        System.out.println("==================== TrafficCompactorTest ====================");
        System.out.println("阈值速览：");
        System.out.println("  HEADER_VALUE_KEEP_CHARS  = " + readInt("HEADER_VALUE_KEEP_CHARS")
                + "    // 非敏感头 value 保留的前缀字符数（超出部分省略为 \"...\"）");
        System.out.println("  MAX_JSON_STRING_CHARS    = " + readInt("MAX_JSON_STRING_CHARS")
                + "    // JSON 中单个 key / value 字符串最大字符数（超长截断并附 \"...（已截断）\"）");
        System.out.println("  MAX_JSON_OBJECT_KEYS     = " + readInt("MAX_JSON_OBJECT_KEYS")
                + "    // JSON 对象最多保留的键数（超出以\"共 N 元素\"占位）");
        System.out.println("  MAX_JSON_ARRAY_ITEMS     = " + readInt("MAX_JSON_ARRAY_ITEMS")
                + "    // JSON 数组最多保留的元素数（超出以\"共 N 元素\"占位）");
        System.out.println("  MAX_JSON_DEPTH           = " + readInt("MAX_JSON_DEPTH")
                + "    // JSON 嵌套深度上限（最外层 0，达到上限的对象/数组用 {...} / [...] 占位）");
        System.out.println("  MAX_JSON_OUTPUT_BYTES    = " + readInt("MAX_JSON_OUTPUT_BYTES")
                + "    // 整个 JSON 序列化后体积硬上限（字节，超出截断）");
        System.out.println("  MAX_OTHER_BODY_CHARS     = " + readInt("MAX_OTHER_BODY_CHARS")
                + "    // 非 JSON / 非二进制纯文本 body 截断阈值（字符数）");
        System.out.println("=============================================================");
    }

    // ============================ header 格式化 ============================

    /** 普通头（Content-Type）：value 长度 > 5 字符时截断到前 5 字符 + "..." */
    @Test
    void formatHeaderLine_normalHeader_truncatesValue() {
        String name = "Content-Type";
        String value = "application/json; charset=utf-8";
        System.out.println("\n[用例] 普通头截断");
        System.out.println("  输入  name  = " + name);
        System.out.println("  输入  value = " + value + " (" + value.length() + " 字符)");
        String result = TrafficCompactor.formatHeaderLine(name, value);
        System.out.println("  输出         = " + result);
        assertEquals("Content-Type: appli...", result);
    }

    /** 普通头：value 长度 ≤ 5 字符时原样保留，不截断 */
    @Test
    void formatHeaderLine_shortValue_keepsFull() {
        String name = "Host";
        String value = "a.b";
        System.out.println("\n[用例] 短 value 不截断");
        System.out.println("  输入  name  = " + name);
        System.out.println("  输入  value = " + value + " (" + value.length() + " 字符)");
        String result = TrafficCompactor.formatHeaderLine(name, value);
        System.out.println("  输出         = " + result);
        assertEquals("Host: a.b", result);
    }

    /** 敏感头（Authorization）：value 整体替换为"（已脱敏）"，原文（token）不得出现 */
    @Test
    void formatHeaderLine_sensitiveHeader_redacts() {
        String name = "Authorization";
        String value = "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature";
        System.out.println("\n[用例] 敏感头脱敏");
        System.out.println("  输入  name  = " + name);
        System.out.println("  输入  value = " + value);
        String result = TrafficCompactor.formatHeaderLine(name, value);
        System.out.println("  输出         = " + result);
        assertTrue(result.contains("（已脱敏）"), "actual=" + result);
        assertFalse(result.contains("eyJhbGciOiJIUzI1NiJ9"), "actual=" + result);
    }

    // ============================ body：空 / 二进制 / 纯文本 ============================

    /** body 为 null 或空数组时返回"（空）"占位 */
    @Test
    void compactBody_nullAndEmpty() {
        System.out.println("\n[用例] body 为 null / 空数组");
        System.out.println("  null   → '" + TrafficCompactor.compactBody(null, "text/plain") + "'");
        System.out.println("  []     → '" + TrafficCompactor.compactBody(new byte[0], "text/plain") + "'");
        assertEquals("（空）", TrafficCompactor.compactBody(null, "text/plain"));
        assertEquals("（空）", TrafficCompactor.compactBody(new byte[0], "text/plain"));
    }

    /** PNG 字节流被识别为二进制，返回"（二进制内容已省略，N 字节）"占位 */
    @Test
    void compactBody_binary_detected() {
        System.out.println("\n[用例] 二进制 body");
        byte[] png = new byte[]{(byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0};
        String result = TrafficCompactor.compactBody(png, "image/png");
        System.out.println("  输入字节数    = " + png.length);
        System.out.println("  Content-Type  = image/png");
        System.out.println("  输出          = " + result);
        assertTrue(result.contains("二进制内容已省略"), "actual=" + result);
        assertTrue(result.contains(png.length + " 字节"), "actual=" + result);
    }

    /** 纯文本 body 长度 > 50 字符时截断并附"共 N 字符"占位 */
    @Test
    void compactBody_plainText_truncates() {
        System.out.println("\n[用例] 纯文本 body 截断（>50 字符）");
        String longText = "a".repeat(120);
        String result = TrafficCompactor.compactBody(longText.getBytes(StandardCharsets.UTF_8), "text/plain");
        System.out.println("  输入长度    = " + longText.length() + " 字符");
        System.out.println("  输出        = " + result);
        assertTrue(result.startsWith("a".repeat(50)), "actual=" + result);
        assertTrue(result.contains("共 120 字符"), "actual=" + result);
    }

    // ============================ body：JSON 各分支 ============================

    /** JSON value 字符串长度 > 20 字符时截断并把 "...（已截断）" marker 放进引号内，
     *  避免 "...截断" + ...（已截断）这种两个 `...` 让人分不清哪个是 marker、哪个是 JSON 闭合引号。 */
    @Test
    void compactBody_jsonObject_truncatesLongString() {
        System.out.println("\n[用例] JSON value 字符串超长截断（>20 字符）");
        String json = "{\"name\":\"alice\",\"bio\":\"这是一段超长的个人简介用于测试字符串截断行为\"}";
        String result = TrafficCompactor.compactBody(json.getBytes(StandardCharsets.UTF_8), "application/json");
        System.out.println("  输入  = " + json);
        System.out.println("  输出  = " + result);
        // marker 整体在引号内：`"原文...（已截断）"`
        assertTrue(result.contains("...（已截断）\""), "actual=" + result);
        // 截断点之后的内容（"行为"二字）不应出现
        assertFalse(result.contains("用于测试字符串截断行为"), "actual=" + result);
    }

    /** JSON 嵌套深度达到 MAX_JSON_DEPTH=2 时，深层位置用 {...} 替代不再递归 */
    @Test
    void compactBody_jsonDeepNesting_cappedByDepth() {
        System.out.println("\n[用例] JSON 嵌套深度上限（MAX_JSON_DEPTH=2）");
        // a.b.c.d.e：5 层嵌套，depth=2 时进入字段值会立即被打成 {...}
        String json = "{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":\"deep\"}}}}}";
        String result = TrafficCompactor.compactBody(json.getBytes(StandardCharsets.UTF_8), "application/json");
        System.out.println("  输入  = " + json);
        System.out.println("  输出  = " + result);
        assertTrue(result.contains("{...}"), "深度超限应被打成 {...}, actual=" + result);
    }

    /** Content-Type 声明是 JSON 但 body 解析失败时，回退到纯文本截断而不是抛异常 */
    @Test
    void compactBody_malformedJson_fallsBackToPlainText() {
        System.out.println("\n[用例] 非法 JSON 回退到纯文本截断");
        String broken = "{not valid json at all, just text broken broken broken broken";
        String result = TrafficCompactor.compactBody(broken.getBytes(StandardCharsets.UTF_8), "application/json");
        System.out.println("  输入  = " + broken);
        System.out.println("  输出  = " + result);
        assertTrue(result.startsWith("{not valid json at all, just text broken"),
                "actual=" + result);
        assertTrue(result.contains("共 " + broken.length() + " 字符"),
                "actual=" + result);
    }

    // ============================ 不依赖 Montoya 的原始字节入口 ============================
    //
    // compactRawRequest/Response/Pair 三个公共方法，专门服务"多报文协同分析"
    // 等"调用方只持 raw bytes、没有 Montoya 句柄"的场景（典型：AnalysisHistoryStore
    // 存的就是 gzip 压缩的原始 HTTP 字节）。这一组用例直接喂原始字节断言行为。

    /** compactRawRequest：完整 HTTP 请求字节 → 解析首行 / headers / body 后压缩 */
    @Test
    void compactRawRequest_fullHttpRequest_parsesAndCompresses() {
        System.out.println("\n[用例] compactRawRequest 完整请求字节解析");
        String raw = "POST /api/login HTTP/1.1\r\n"
                + "Host: api.example.com\r\n"
                + "Content-Type: application/json\r\n"
                + "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig\r\n"
                + "X-Custom-Token: aabbccdd-eeff-0011-2233-445566778899\r\n"
                + "\r\n"
                + "{\"user\":\"alice\",\"password\":\"super-secret-very-long-password-1234567890\"}";
        String result = TrafficCompactor.compactRawRequest(raw.getBytes(StandardCharsets.UTF_8));
        System.out.println("  输出 = \n" + result);
        // 首行：METHOD + URL（HTTP 版本不出现）
        assertTrue(result.startsWith("【请求】POST /api/login"), "actual=" + result);
        // Host 长度 19 > 5，截到 "api.e..."
        assertTrue(result.contains("Host: api.e..."), "actual=" + result);
        // Content-Type 截断到前 5 字符
        assertTrue(result.contains("Content-Type: appli..."), "actual=" + result);
        // 敏感头脱敏
        assertTrue(result.contains("Authorization: （已脱敏）"), "actual=" + result);
        assertFalse(result.contains("eyJhbGciOiJIUzI1NiJ9"), "敏感 token 不得泄漏, actual=" + result);
        // X-Custom-Token 因名字含 "token" 关键字被判定为敏感头 → 整体脱敏
        assertTrue(result.contains("X-Custom-Token: （已脱敏）"), "actual=" + result);
        // JSON body 被识别 + 极简压缩（value 截到 20 字符，password 整段被截）
        assertTrue(result.contains("[Body"), "actual=" + result);
        assertTrue(result.contains("\"user\":\"alice\""), "actual=" + result);
        assertFalse(result.contains("super-secret-very-long-password-1234567890"),
                "超长 password 不应完整出现, actual=" + result);
    }

    /** compactRawResponse：完整 HTTP 响应字节 → 状态行 + headers + body */
    @Test
    void compactRawResponse_fullHttpResponse_parsesAndCompresses() {
        System.out.println("\n[用例] compactRawResponse 完整响应字节解析");
        String raw = "HTTP/1.1 200 OK\r\n"
                + "Content-Type: application/json; charset=utf-8\r\n"
                + "Set-Cookie: session=abcd1234efgh5678ijkl; HttpOnly; Path=/\r\n"
                + "\r\n"
                + "{\"id\":1,\"name\":\"alice\",\"email\":\"alice@example.com\",\"role\":\"admin\"}";
        String result = TrafficCompactor.compactRawResponse(raw.getBytes(StandardCharsets.UTF_8));
        System.out.println("  输出 = \n" + result);
        // 状态行
        assertTrue(result.startsWith("【响应 200】"), "actual=" + result);
        // 头截断
        assertTrue(result.contains("Content-Type: appli..."), "actual=" + result);
        // Set-Cookie 含 "cookie" 关键字 → 敏感头脱敏
        assertTrue(result.contains("Set-Cookie: （已脱敏）"), "actual=" + result);
        // JSON body
        assertTrue(result.contains("\"id\":1"), "actual=" + result);
        assertTrue(result.contains("\"role\":\"admin\""), "actual=" + result);
    }

    /** compactRawPair：请求 + 响应配对，任一为空走占位 */
    @Test
    void compactRawPair_handlesEmptyInputs() {
        System.out.println("\n[用例] compactRawPair 空入参走占位文本");
        String onlyReq = TrafficCompactor.compactRawPair(
                "GET / HTTP/1.1\r\nHost: a.b\r\n\r\n".getBytes(StandardCharsets.UTF_8),
                null);
        System.out.println("  仅请求 = \n" + onlyReq);
        assertTrue(onlyReq.contains("【请求】GET /"), "actual=" + onlyReq);
        assertTrue(onlyReq.contains("【响应】（暂无响应）"), "actual=" + onlyReq);
        // 双 null：请求也走占位
        String both = TrafficCompactor.compactRawPair(null, null);
        System.out.println("  双 null = \n" + both);
        assertTrue(both.contains("【请求】（无原始请求字节）"), "actual=" + both);
        assertTrue(both.contains("【响应】（暂无响应）"), "actual=" + both);
    }

    /** compactRawRequest：只有 headers 没有 body（不抛 NPE） */
    @Test
    void compactRawRequest_headerOnlyNoBody() {
        System.out.println("\n[用例] compactRawRequest 仅 headers 无 body");
        String raw = "GET /health HTTP/1.1\r\nHost: api.test\r\n\r\n";
        String result = TrafficCompactor.compactRawRequest(raw.getBytes(StandardCharsets.UTF_8));
        System.out.println("  输出 = \n" + result);
        assertTrue(result.contains("【请求】GET /health"), "actual=" + result);
        // Host 长度 9 > 5，截到 "api.t..."
        assertTrue(result.contains("Host: api.t..."), "actual=" + result);
        assertFalse(result.contains("[Body"), "无 body 时不应输出 Body 段, actual=" + result);
    }

    /** compactRawRequest：空字节数组 → 返回空串（早期返回） */
    @Test
    void compactRawRequest_emptyOrNull_returnsEmpty() {
        System.out.println("\n[用例] compactRawRequest 空 / null 早期返回空串");
        assertEquals("", TrafficCompactor.compactRawRequest(null));
        assertEquals("", TrafficCompactor.compactRawRequest(new byte[0]));
        assertEquals("", TrafficCompactor.compactRawResponse(null));
        assertEquals("", TrafficCompactor.compactRawResponse(new byte[0]));
    }

    /** compactRawRequest：LF-only 行尾（无 \r）也要正确切分 */
    @Test
    void compactRawRequest_lfOnlyLineEndings_tolerated() {
        System.out.println("\n[用例] compactRawRequest LF-only 行尾兼容");
        String raw = "GET /x HTTP/1.1\nHost: a.b\n\nbody";
        String result = TrafficCompactor.compactRawRequest(raw.getBytes(StandardCharsets.UTF_8));
        System.out.println("  输出 = \n" + result);
        assertTrue(result.contains("【请求】GET /x"), "actual=" + result);
        assertTrue(result.contains("Host: a.b"), "actual=" + result);
        assertTrue(result.contains("[Body 4 字节]"), "actual=" + result);
        assertTrue(result.contains("body"), "actual=" + result);
    }

    /** compactRawRequest：畸形行（没有 ':'）不抛异常，安静跳过 */
    @Test
    void compactRawRequest_malformedHeaders_skipQuietly() {
        System.out.println("\n[用例] compactRawRequest 畸形 header 行安静跳过");
        String raw = "GET /x HTTP/1.1\r\nHost: a.b\r\nbad-line-without-colon\r\n\r\nok";
        String result = TrafficCompactor.compactRawRequest(raw.getBytes(StandardCharsets.UTF_8));
        System.out.println("  输出 = \n" + result);
        assertTrue(result.contains("【请求】GET /x"), "actual=" + result);
        assertTrue(result.contains("Host: a.b"), "actual=" + result);
        // 畸形行本身不出现，但其它部分正常输出
        assertTrue(result.contains("ok"), "actual=" + result);
    }

    /**
     * 头部以 LF 结束、body 里含 CRLFCRLF 时，必须按"第一个空行"切分。
     *
     * <p>回归用例：历史实现先全局搜 {@code \r\n\r\n}、找不到才兜底 {@code \n\n}，
     * 于是这种报文会命中 body 内部的 {@code \r\n\r\n}——headerBlock 混进 body 前缀、
     * body 起点错位（压缩结果里会出现莫名字节）。</p>
     */
    @Test
    void compactRawRequest_lfHeadersWithCrlfCrlfInBody_splitsAtFirstBlankLine() {
        System.out.println("\n[用例] compactRawRequest LF 头部 + body 内含 CRLFCRLF");
        // 头部以 \n\n 结束；body = "AAA\r\n\r\nBBB"（内含 CRLFCRLF）
        String raw = "GET /x HTTP/1.1\nHost: a.b\n\nAAA\r\n\r\nBBB";
        String result = TrafficCompactor.compactRawRequest(raw.getBytes(StandardCharsets.UTF_8));
        System.out.println("  输出 = \n" + result);
        assertTrue(result.contains("【请求】GET /x"), "actual=" + result);
        assertTrue(result.contains("Host: a.b"), "actual=" + result);
        // body 必须完整包含 AAA 与 BBB（若切错点，AAA 会被当成"头部内容"吞掉）
        assertTrue(result.contains("AAA"), "body 应以第一个空行为起点，actual=" + result);
        assertTrue(result.contains("BBB"), "actual=" + result);
        assertTrue(result.contains("[Body 10 字节]"),
                "body 长度应为 3 + 4 + 3 = 10 字节，actual=" + result);
    }

    // ============================ 辅助 ============================

    private static int readInt(String name) {
        try {
            Field f = TrafficCompactor.class.getDeclaredField(name);
            f.setAccessible(true);
            return f.getInt(null);
        } catch (Exception e) {
            return -1;
        }
    }

    // ============================ compactMessageText：消息文本里的 HTTP 块压缩 ============================
    //
    // 给 ToolLoopOrchestrator 的 DEBUG 日志用：把整条 user / tool 消息里的
    // 【HTTP 请求】/【HTTP 响应】/【重放结果】块压缩为"几行占位"，方便核对流程编排。

    @Test
    void compactMessageText_fullRequestAndResponse() {
        String text = "【HTTP 请求】\n"
                + "POST http://192.168.253.128/dvwa/xx\n"
                + "Host: 192.168.253.128\n"
                + "Content-Type: application/x-www-form-urlencoded\n"
                + "Cookie: session=abc\n"
                + "\n"
                + "请求体（共 5 字节）：\n"
                + "id=1\n"
                + "\n"
                + "【HTTP 响应】\n"
                + "HTTP/1.1 200 OK\n"
                + "Content-Type: text/html\n"
                + "\n"
                + "响应体（共 4757 字节）：\n"
                + "<html>...very long...</html>\n";
        String out = TrafficCompactor.compactMessageText(text);
        // METHOD URL 行保留
        assertTrue(out.contains("POST http://192.168.253.128/dvwa/xx"),
                "应保留 METHOD URL 行，实际：" + out);
        // headers 折叠
        assertTrue(out.contains("（请求头：略...）"), "请求头应折叠为占位");
        // body 字节数保留
        assertTrue(out.contains("（请求体：5字节）"), "请求体字节数应保留，实际：" + out);
        // 响应头折叠
        assertTrue(out.contains("（响应头：略...）"), "响应头应折叠为占位");
        // 响应体字节数保留
        assertTrue(out.contains("（响应体：4757字节）"), "响应体字节数应保留，实际：" + out);
        // 原始 body 不应泄漏
        assertFalse(out.contains("<html>"), "原 HTML 正文不应出现在输出，实际：" + out);
        assertFalse(out.contains("id=1\n"), "原请求体正文不应出现在输出");
        assertFalse(out.contains("Cookie: session=abc"), "原 Cookie 不应出现");
        assertFalse(out.contains("状态码：200"), "状态码行应被压掉");
    }

    @Test
    void compactMessageText_replayResultBlock() {
        String text = "【重放结果（tool_call_id=tc-1-abc12345，reason=闭合单引号，耗时 100ms）】\n"
                + "\n"
                + "[响应]\n"
                + "HTTP/1.1 500 Internal Server Error\n"
                + "Content-Type: text/html\n"
                + "\n"
                + "响应体（共 1234 字节）：\n"
                + "<html>SQL error: near 1' syntax error</html>\n";
        String out = TrafficCompactor.compactMessageText(text);
        // 外层重放结果元信息应保留
        assertTrue(out.contains("【重放结果（tool_call_id=tc-1-abc12345"),
                "外层重放结果元信息应保留，实际：" + out);
        // headers 折叠
        assertTrue(out.contains("（响应头：略...）"), "响应头应折叠为占位");
        // body 字节数保留
        assertTrue(out.contains("（响应体：1234字节）"), "响应体字节数应保留，实际：" + out);
        // 原始 body 不应泄漏
        assertFalse(out.contains("SQL error"), "原响应体不应泄漏");
        assertFalse(out.contains("状态码=500"), "状态码行应被压掉");
    }

    @Test
    void compactMessageText_replayResultBlock_bracketedBodyFormat() {
        // 复现 bug：buildReplayResultUserPrompt 实际用 "[响应体 N 字节]" 方括号格式，
        // 不是 buildUserPrompt 的 "响应体（共 N 字节）：" 圆括号格式。
        // 旧版只匹配圆括号 → 整个响应体原样泄漏到 DEBUG 日志。
        String text = "【重放结果（tool_call_id=rc-1-xyz, reason=闭合单引号, 耗时 100ms）】\n"
                + "\n"
                + "[响应]\n"
                + "HTTP/1.1 500 Internal Server Error\n"
                + "Content-Type: text/html\n"
                + "\n"
                + "[响应体 1234 字节]\n"
                + "<html>SQL error: near 1' syntax error... very long body content here "
                + "that should NEVER appear in compressed debug output "
                + "no matter how many lines it spans "
                + "line 4 of body "
                + "line 5 of body </html>\n";
        String out = TrafficCompactor.compactMessageText(text);
        // body 字节数应保留
        assertTrue(out.contains("（响应体：1234字节）"),
                "方括号格式 [响应体 N 字节] 也应被识别并压缩，实际：" + out);
        // body 正文任何片段都不能出现
        assertFalse(out.contains("SQL error"), "原响应体正文不应泄漏（bug 回归测试）");
        assertFalse(out.contains("very long body content"), "原响应体正文不应泄漏（bug 回归测试）");
        assertFalse(out.contains("line 4 of body"), "原响应体正文多行都不应泄漏");
        assertFalse(out.contains("near 1'"), "原响应体里的 SQL 报错不应泄漏");
    }

    @Test
    void compactMessageText_addressableParamsList_preserved() {
        // 可替换参数清单不在 HTTP 块里，应该原样保留
        String text = "【HTTP 请求】\n"
                + "GET /api?id=1 HTTP/1.1\n"
                + "Host: x.com\n"
                + "\n"
                + "【HTTP 响应】\n"
                + "HTTP/1.1 200 OK\n"
                + "\n"
                + "【可替换参数】\n"
                + "- query: id\n"
                + "- header: X-Token\n";
        String out = TrafficCompactor.compactMessageText(text);
        assertTrue(out.contains("【可替换参数】"), "可替换参数清单应保留");
        assertTrue(out.contains("- query: id"), "query 清单应保留");
        assertTrue(out.contains("- header: X-Token"), "header 清单应保留");
    }

    @Test
    void compactMessageText_noMarkers_returnsAsIs() {
        String text = "{\"analysis\":\"普通 JSON 响应\",\"tool_calls\":[],\"risk\":\"none\",\"findings\":[]}";
        assertEquals(text, TrafficCompactor.compactMessageText(text));
    }

    @Test
    void compactMessageText_emptyAndNull() {
        assertEquals("", TrafficCompactor.compactMessageText(null));
        assertEquals("", TrafficCompactor.compactMessageText(""));
    }

    @Test
    void compactMessageText_requestWithoutBody() {
        // GET 请求没有 body 块
        String text = "【HTTP 请求】\n"
                + "GET /api?id=1 HTTP/1.1\n"
                + "Host: x.com\n"
                + "\n"
                + "【HTTP 响应】\n"
                + "HTTP/1.1 200 OK\n";
        String out = TrafficCompactor.compactMessageText(text);
        assertTrue(out.contains("GET /api?id=1 HTTP/1.1"), "METHOD URL 应保留");
        assertTrue(out.contains("（请求头：略...）"), "请求头应折叠");
        // 没有 body 块就不应输出 body 行
        assertFalse(out.contains("（请求体："), "无 body 时不应输出 body 行");
        assertTrue(out.contains("（响应头：略...）"), "响应头应折叠");
    }
}
