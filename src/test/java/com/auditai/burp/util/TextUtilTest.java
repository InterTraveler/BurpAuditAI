package com.auditai.burp.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link TextUtil} 单元测试。
 *
 * <p>测试全部为纯函数测试，不依赖 Burp 运行时，可在 mvn test 阶段独立执行。</p>
 */
class TextUtilTest {

    /** 超长文本应被截断并附带说明。 */
    @Test
    void truncate_cutsLongText() {
        String longText = "a".repeat(5000);
        String result = TextUtil.truncate(longText, 100);
        assertTrue(result.startsWith("a".repeat(100)));
        assertTrue(result.contains("已截断"));
    }

    /** null 按空串处理，不应抛异常。 */
    @Test
    void truncate_handlesNull() {
        assertEquals("", TextUtil.truncate(null, 10));
    }

    /**
     * 截断点恰好落在代理对中间（maxChars=1，文本首字符是 emoji）时，
     * 必须回退到 emoji 之前，结果不得以孤立高代理结尾。
     *
     * <p>回归用例：历史实现判定的是"保留区内部的 cut-2/cut-1 是完整代理对"，
     * 方向写反——真正被切开的代理对反而没被处理。</p>
     */
    @Test
    void truncate_neverSplitsSurrogatePair() {
        // "😀x" = [高代理, 低代理, 'x']，cut=1 正好把代理对切成两半
        String result = TextUtil.truncate("😀x", 1);
        assertTrue(result.startsWith("\n……（已截断"),
                "应回退到 emoji 之前（正文为空，只剩截断说明），实际：" + result);
        assertFalse(endsWithLoneHighSurrogate(result), "结果不得以孤立高代理结尾");
    }

    /**
     * 保留区正好落在完整代理对之后（maxChars=4，文本是两个 emoji）时，
     * 两个 emoji 都应被完整保留（不能被"回退一个 code unit"砍掉一半）。
     *
     * <p>回归用例：历史实现会把这种情况误判成"落在代理对中间"，
     * 于是把第二个 emoji 的低代理砍掉，产出孤立高代理。</p>
     */
    @Test
    void truncate_keepsCompleteSurrogatePair() {
        String result = TextUtil.truncate("😀😀x", 4);
        assertTrue(result.startsWith("😀😀"), "完整的两个 emoji 都应保留，实际：" + result);
        assertFalse(endsWithLoneHighSurrogate(result), "结果不得以孤立高代理结尾");
    }

    /** 三个 emoji + 半途截断：仍不允许出现孤立代理。 */
    @Test
    void truncate_multiEmojiWithOddCut() {
        for (int max = 1; max <= 6; max++) {
            String result = TextUtil.truncate("😀😀😀", max);
            assertFalse(endsWithLoneHighSurrogate(result),
                    "maxChars=" + max + " 时出现了孤立高代理：" + result);
        }
    }

    /** 结果末尾是否是"孤立高代理"（即最后一个 char 是高代理、它后面没有低代理跟随）。 */
    private static boolean endsWithLoneHighSurrogate(String text) {
        // 只看截断出来的正文（不含 "……（已截断…" 后缀）
        int suffixStart = text.indexOf('\n');
        String body = suffixStart >= 0 ? text.substring(0, suffixStart) : text;
        if (body.isEmpty()) {
            return false;
        }
        char last = body.charAt(body.length() - 1);
        return Character.isHighSurrogate(last);
    }

    /** 敏感头（Authorization）的值应被整体打码。 */
    @Test
    void redactHeaderValue_masksSensitiveHeader() {
        String masked = TextUtil.redactHeaderValue("Authorization", "Bearer secret-key-123");
        assertTrue(masked.contains("脱敏"));
        assertFalse(masked.contains("secret-key-123"));
    }

    /** 普通头原样返回。 */
    @Test
    void redactHeaderValue_keepsNormalHeader() {
        assertEquals("text/html", TextUtil.redactHeaderValue("Content-Type", "text/html"));
    }

    /** 带前缀的常见敏感头也应被打码（如 X-Authorization / Proxy-Authorization）。 */
    @Test
    void redactHeaderValue_masksPrefixedSensitiveHeader() {
        assertTrue(TextUtil.redactHeaderValue("X-Authorization", "secret").contains("脱敏"));
        assertTrue(TextUtil.redactHeaderValue("Proxy-Authorization", "secret").contains("脱敏"));
        assertTrue(TextUtil.redactHeaderValue("X-Auth-Token", "secret").contains("脱敏"));
        assertTrue(TextUtil.redactHeaderValue("X-CSRF-Token", "secret").contains("脱敏"));
    }

    /** 大小写不敏感地匹配敏感关键字。 */
    @Test
    void redactHeaderValue_isCaseInsensitive() {
        assertTrue(TextUtil.redactHeaderValue("AUTHORIZATION", "secret").contains("脱敏"));
        assertTrue(TextUtil.redactHeaderValue("x-api-key", "secret").contains("脱敏"));
    }

    /** 二进制 body 应返回占位描述而不是乱码。 */
    @Test
    void safeBody_detectsBinary() {
        byte[] pngHeader = {(byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
        String result = TextUtil.safeBody(pngHeader);
        assertTrue(result.contains("二进制"));
    }

    /** 文本 body 应正常解码。 */
    @Test
    void safeBody_decodesText() {
        String result = TextUtil.safeBody("{\"name\":\"test\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        assertTrue(result.contains("name"));
    }

    /** 合法 JSON 应被美化为多行；保持原有字段顺序。 */
    @Test
    void prettyJson_formatsObject() {
        String raw = "{\"active_skill_ids\":[\"sql-injection\"],\"analysis\":\"\",\"risk\":\"none\"}";
        String pretty = TextUtil.prettyJson(raw);
        // 美化后必须包含换行 + 2 空格缩进
        assertTrue(pretty.contains("\n"));
        assertTrue(pretty.contains("  \"active_skill_ids\""));
        // 关键字段值必须保留
        assertTrue(pretty.contains("\"sql-injection\""));
        assertTrue(pretty.contains("\"none\""));
    }

    /** 中文/HTML 符号不应被转义成 \\uXXXX（关掉 htmlEscaping 的关键回归点）。 */
    @Test
    void prettyJson_doesNotHtmlEscape() {
        String raw = "{\"a\":\"<script>x</script>\",\"b\":\"中文\"}";
        String pretty = TextUtil.prettyJson(raw);
        assertFalse(pretty.contains("\\u003c"));
        assertFalse(pretty.contains("\\u4e2d"));
        assertTrue(pretty.contains("<script>"));
        assertTrue(pretty.contains("中文"));
    }

    /** 非 JSON 输入应原样回退，绝不抛异常（DEBUG 日志容错的关键）。 */
    @Test
    void prettyJson_fallsBackOnInvalidJson() {
        String raw = "this is not json {";
        assertEquals(raw, TextUtil.prettyJson(raw));
    }

    /** null / 空串都按安全语义处理。 */
    @Test
    void prettyJson_handlesNullAndEmpty() {
        assertEquals("", TextUtil.prettyJson(null));
        assertEquals("", TextUtil.prettyJson(""));
    }
}
