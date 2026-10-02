package com.auditai.burp.tools.replay;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * {@link MultipartBodyParser#extractBoundary(String)} 单元测试：覆盖 quoted /
 * unquoted / 大小写 / 多参数 / null 等边界。
 *
 * <p>该方法是 package-private 的纯字符串解析函数，便于在不带 Burp 运行时的环境下单测。
 * 完整 multipart 解析（parse / serialize）依赖 Montoya 的 HttpRequest，本测试不覆盖。</p>
 */
final class MultipartBodyParserTest {

    @Test
    void extractBoundary_quoted_returnsValueWithoutQuotes() {
        assertEquals("AaB03x",
                MultipartBodyParser.extractBoundary(
                        "multipart/form-data; boundary=\"AaB03x\""));
    }

    @Test
    void extractBoundary_unquoted_returnsValue() {
        assertEquals("AaB03x",
                MultipartBodyParser.extractBoundary(
                        "multipart/form-data; boundary=AaB03x"));
    }

    @Test
    void extractBoundary_caseInsensitive() {
        assertEquals("AaB03x",
                MultipartBodyParser.extractBoundary(
                        "multipart/form-data; BOUNDARY=AaB03x"));
    }

    @Test
    void extractBoundary_withCharsetThenBoundary_ignoresCharset() {
        assertEquals("xyz",
                MultipartBodyParser.extractBoundary(
                        "multipart/form-data; charset=utf-8; boundary=xyz"));
    }

    @Test
    void extractBoundary_withExtraWhitespace_trimsValue() {
        assertEquals("xyz",
                MultipartBodyParser.extractBoundary(
                        "multipart/form-data; boundary=\t xyz \t"));
    }

    @Test
    void extractBoundary_missing_returnsNull() {
        assertNull(MultipartBodyParser.extractBoundary("multipart/form-data; charset=utf-8"));
        assertNull(MultipartBodyParser.extractBoundary("application/json"));
        assertNull(MultipartBodyParser.extractBoundary(""));
    }

    @Test
    void extractBoundary_null_returnsNull() {
        assertNull(MultipartBodyParser.extractBoundary(null));
    }

    @Test
    void extractBoundary_emptyQuoted_returnsEmpty() {
        // 极端：boundary="" 应返回空串，调用方据此判定不是 multipart（见 parse 第 74 行）
        assertEquals("", MultipartBodyParser.extractBoundary(
                "multipart/form-data; boundary=\"\""));
    }
}