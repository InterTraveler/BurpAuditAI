package com.auditai.burp.http;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link BodyStorage} 单元测试：覆盖"小报文直通 / binary 截断 / JSON 字符串裁剪 /
 * JSON 数组/对象元素上限 / SHA-256 稳定性 + ThreadLocal 释放"等边界。
 *
 * <p>纯函数测试，不依赖 Burp 运行时。</p>
 */
final class BodyStorageTest {

    private static final Pattern HEX_64 = Pattern.compile("^[0-9a-f]{64}$");

    /** 小报文（body < 256KiB）保持原样，不被替换。 */
    @Test
    void prepareStoredMessage_smallMessageKeepsRaw() {
        byte[] raw = ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello world")
                .getBytes(StandardCharsets.UTF_8);
        byte[] result = BodyStorage.prepareStoredMessage(raw);
        assertEquals(raw.length, result.length, "小报文应原样返回，不复制替换占位符");
        assertEquals(new String(raw, StandardCharsets.UTF_8),
                new String(result, StandardCharsets.UTF_8));
    }

    /** binary body 超阈值被占位符替换；header 部分保留。 */
    @Test
    void prepareStoredMessage_largeBinaryBodyIsReplacedWithPlaceholder() {
        byte[] hugeBinary = new byte[BodyStorage.MAX_BINARY_BODY_BYTES + 16];
        for (int i = 0; i < hugeBinary.length; i++) {
            hugeBinary[i] = (byte) (i & 0xFF); // 非 UTF-8 序列，TextUtil.isLikelyBinary 应判为 binary
        }
        byte[] header = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\n\n"
                .getBytes(StandardCharsets.UTF_8);
        byte[] rawFull = new byte[header.length + hugeBinary.length];
        System.arraycopy(header, 0, rawFull, 0, header.length);
        System.arraycopy(hugeBinary, 0, rawFull, header.length, hugeBinary.length);

        byte[] result = BodyStorage.prepareStoredMessage(rawFull);
        // header 完整保留
        for (int i = 0; i < header.length; i++) {
            assertEquals(header[i], result[i], "header 字节必须保留");
        }
        // body 部分被替换为占位符，体积远小于原始
        assertTrue(result.length < rawFull.length,
                "binary body 被占位符替换后总长度应小于原始");
        String replaced = new String(result, header.length,
                result.length - header.length, StandardCharsets.UTF_8);
        assertTrue(replaced.contains("binary body omitted"),
                "占位符文本应包含 'binary body omitted'");
    }

    /** JSON 文本 body 超阈值时优先尝试结构化裁剪：对象过大时保留 key 列表语义。 */
    @Test
    void prepareStoredMessage_largeJsonBodyGetsStructuredTrim() {
        StringBuilder sb = new StringBuilder("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n");
        sb.append('{');
        // 触发"对象键超限 → 结构化裁剪 → 结果仍 < 1MiB"的场景：
        //   - 写 3 × MAX_JSON_OBJECT_KEYS 个键（约 30k），让原始 body 超过 1MiB
        //     触发结构化裁剪路径。
        //   - value 短（50 字节），让裁剪到 10000 键后的 body 约 500KB，< 1MiB——
        //     clipJson 才能保留结构（返回非 null），否则回退到文本占位符，
        //     断言不到 _auditai_truncated 标记。
        String value = "v".repeat(50);
        int totalKeys = BodyStorage.MAX_JSON_OBJECT_KEYS * 3;
        for (int i = 0; i < totalKeys; i++) {
            if (i > 0) sb.append(',');
            sb.append("\"k").append(i).append("\":\"").append(value).append('"');
        }
        sb.append('}');
        byte[] raw = sb.toString().getBytes(StandardCharsets.UTF_8);
        assertTrue(raw.length > BodyStorage.MAX_TEXT_BODY_BYTES,
                "测试前置：raw 必须超过文本上限，实际=" + raw.length);
        byte[] result = BodyStorage.prepareStoredMessage(raw);
        String bodyText = new String(result, StandardCharsets.UTF_8);
        // 裁剪后 JSON 仍然合法（结尾是 }）—— 证明走的是结构化裁剪而不是文本占位符
        assertTrue(bodyText.endsWith("}"), "裁剪后必须仍是合法 JSON 对象");
        assertTrue(bodyText.contains("_auditai_truncated"),
                "对象超限时应添加 _auditai_truncated 标记");
    }

    /** JSON 字符串字段超长时被截断并带占位。 */
    @Test
    void prepareStoredMessage_largeJsonStringFieldIsClipped() {
        StringBuilder sb = new StringBuilder("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n");
        sb.append("{\"longField\":\"");
        // 写一个远超 MAX_TEXT_BODY_BYTES 的 JSON 字符串：1.5MiB
        for (int i = 0; i < 1_500_000; i++) {
            sb.append('a');
        }
        sb.append("\"}");
        byte[] raw = sb.toString().getBytes(StandardCharsets.UTF_8);
        assertTrue(raw.length > BodyStorage.MAX_TEXT_BODY_BYTES,
                "测试前置：raw 必须超过文本上限，实际=" + raw.length);
        byte[] result = BodyStorage.prepareStoredMessage(raw);
        String bodyText = new String(result, StandardCharsets.UTF_8);
        assertTrue(bodyText.contains("AuditAI clipped"),
                "超长 JSON 字符串字段应带 clipped 标记");
    }

    /** SHA-256 对同一输入产出相同 64 字符小写十六进制。 */
    @Test
    void sha256_isDeterministicAndHex64() {
        byte[] input = "audit-ai-test".getBytes(StandardCharsets.UTF_8);
        String first = BodyStorage.sha256(input);
        String second = BodyStorage.sha256(input);
        assertEquals(first, second, "同一输入应两次结果相同");
        assertTrue(HEX_64.matcher(first).matches(),
                "SHA-256 必须是 64 位小写十六进制，实际=" + first);
        // 与 PowerShell (New-Object SHA256Managed + UTF8.GetBytes) 已知值交叉对照
        assertEquals("9a6df853544e9e28dfb63e1d9c35695b91fa9af5c44c05efe5ea817d33278f4f",
                first, "交叉对照：SHA-256('audit-ai-test')");
    }

    /** 不同输入产出不同 SHA-256。 */
    @Test
    void sha256_differentInputsProduceDifferentDigests() {
        String a = BodyStorage.sha256("alpha".getBytes(StandardCharsets.UTF_8));
        String b = BodyStorage.sha256("beta".getBytes(StandardCharsets.UTF_8));
        assertNotEquals(a, b);
        assertFalse(a.isEmpty());
        assertFalse(b.isEmpty());
    }

    /** ThreadLocal 释放后同线程再次调用 SHA-256 不抛异常。 */
    @Test
    void releaseForCurrentThread_isIdempotentAndSafe() {
        // 先触发 ThreadLocal 初始化
        BodyStorage.sha256("warm-up".getBytes(StandardCharsets.UTF_8));
        // 释放
        BodyStorage.releaseForCurrentThread();
        // 再次调用应自动重建 ThreadLocal，行为正常
        String after = BodyStorage.sha256("after-release".getBytes(StandardCharsets.UTF_8));
        assertTrue(HEX_64.matcher(after).matches(),
                "释放 ThreadLocal 后再次调用 SHA-256 必须仍能产出合法摘要");
        // 再次 release 也安全（幂等）
        BodyStorage.releaseForCurrentThread();
        BodyStorage.releaseForCurrentThread();
    }

    /** readCompressed 对 null 返回空数组。 */
    @Test
    void readCompressed_nullPathReturnsEmpty() throws Exception {
        byte[] result = BodyStorage.readCompressed(null);
        assertEquals(0, result.length, "null path 必须返回空数组而不是抛 NPE");
    }

    /**
     * 多字节字符（中文）的 JSON 字符串超限时必须真的被截短。
     *
     * <p>回归用例：阈值 {@code MAX_JSON_STRING_BYTES} 是 UTF-8 <b>字节</b>数，而历史实现
     * 用 {@code MAX_JSON_STRING_BYTES / 2} 当<b>字符</b>数上限——中文 1 字符 3 字节，
     * 一个 40KB 字符的中文串已达 120KB 字节（超限），但字符数远小于 32K，
     * {@code Math.min(len, 32K)} 取到全长，结果"裁剪"一个字符没删、反而追加了标记，
     * body 变得更大且上限失效。</p>
     */
    @Test
    void prepareStoredMessage_largeCjkJsonStringIsActuallyClipped() {
        StringBuilder sb = new StringBuilder("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n");
        sb.append("{\"longField\":\"");
        // 30000 个中文字符 = 90000 字节 > MAX_JSON_STRING_BYTES(64KiB)，
        // 但字符数 30000 < 64KiB/2 = 32768 —— 旧实现用"字符数上限"就会一个字符都截不掉。
        sb.append("中".repeat(30_000));
        sb.append("\",\"pad\":\"");
        // 另一个大 ASCII 字段，把整体 body 推过 MAX_TEXT_BODY_BYTES(1MiB)，从而进入结构化裁剪分支
        sb.append("a".repeat(1_100_000));
        sb.append("\"}");
        byte[] raw = sb.toString().getBytes(StandardCharsets.UTF_8);
        // 前置：body 需超过文本上限，才会走结构化裁剪
        assertTrue(raw.length > BodyStorage.MAX_TEXT_BODY_BYTES,
                "测试前置：raw 必须超过文本上限，实际=" + raw.length);

        byte[] result = BodyStorage.prepareStoredMessage(raw);
        String bodyText = new String(result, StandardCharsets.UTF_8);
        assertTrue(bodyText.contains("AuditAI clipped"), "应带裁剪标记，实际长度=" + bodyText.length());
        int fieldStart = bodyText.indexOf("longField\":\"") + "longField\":\"".length();
        // 裁剪标记紧跟被截断的文本（闭合引号在标记之后），所以只找标记本身
        int fieldEnd = bodyText.indexOf("...[AuditAI clipped]", fieldStart);
        assertTrue(fieldEnd > fieldStart, "字段应被截断并紧跟裁剪标记");
        int clippedBytes = bodyText.substring(fieldStart, fieldEnd).getBytes(StandardCharsets.UTF_8).length;
        assertTrue(clippedBytes <= BodyStorage.MAX_JSON_STRING_BYTES,
                "裁剪后字段不得再超过字节上限（旧实现会留下 90000 字节），实际=" + clippedBytes);
        assertFalse(bodyText.contains("\uFFFD"), "截断不得切断多字节字符（不产生替换字符）");
    }

    /** truncateToUtf8Bytes：不切断多字节字符，且不超字节上限。 */
    @Test
    void truncateToUtf8Bytes_neverSplitsMultiByteChars() {
        // 每个 emoji 占 4 字节（代理对），maxBytes 落在第 2 个 emoji 内部
        String value = "😀😀😀";
        String truncated = BodyStorage.truncateToUtf8Bytes(value, 6);
        assertEquals("😀", truncated, "6 字节处必须回退到第 1 个 emoji 的边界");
        assertEquals(4, truncated.getBytes(StandardCharsets.UTF_8).length);
        // 中文：3 字节/字符
        String cjk = "中文测试";
        assertEquals("中", BodyStorage.truncateToUtf8Bytes(cjk, 4));
        assertEquals("中文", BodyStorage.truncateToUtf8Bytes(cjk, 6));
        // 未超限时原样返回
        assertEquals(cjk, BodyStorage.truncateToUtf8Bytes(cjk, 100));
    }
}