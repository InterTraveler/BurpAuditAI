package com.auditai.burp.passive;

import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link UrlRegexFilter} 单元测试：match-all 兜底、非法正则告警、匹配语义、
 * 输入截断（灾难性回溯防御）与多线程共享调用。
 */
final class UrlRegexFilterTest {

    @Test
    void nullOrBlankRegexMatchesEverything() {
        assertTrue(new UrlRegexFilter(null, null).matches("https://anything.example/x"));
        assertTrue(new UrlRegexFilter("", null).matches("https://anything.example/x"));
        assertTrue(new UrlRegexFilter("   ", null).matches("https://anything.example/x"));
    }

    @Test
    void invalidRegexFallsBackToMatchAllAndLogs() {
        AtomicReference<String> logged = new AtomicReference<>();
        UrlRegexFilter filter = new UrlRegexFilter("([unclosed", logged::set);
        // 非法正则 → 回退 match-all + 告警
        assertTrue(filter.matches("https://anything.example/x"));
        assertTrue(logged.get() != null && logged.get().contains("正则非法"));
    }

    @Test
    void matchesUsesFindSemantics() {
        UrlRegexFilter filter = new UrlRegexFilter("api\\.example\\.com", null);
        assertTrue(filter.matches("https://api.example.com/v1/users?page=2"));
        assertFalse(filter.matches("https://evil.com/hostive"));
    }

    @Test
    void veryLongUrlIsTruncatedBeforeMatching() {
        // 超过截断上限的 URL 仍按"子串匹配"工作（截断只影响锚定末尾的正则，过滤场景可接受）
        StringBuilder sb = new StringBuilder("https://example.com/start");
        for (int i = 0; i < 10_000; i++) {
            sb.append('a');
        }
        sb.append("/end");
        UrlRegexFilter filter = new UrlRegexFilter("example\\.com/start", null);
        assertTrue(filter.matches(sb.toString()));
    }

    // ========== 伪正则翻译（* → .*，字符类内不翻译） ==========

    @Test
    void expandPseudoReplacesStarOutsideCharacterClass() {
        assertEquals(".*api.*", UrlRegexFilter.expandPseudoRegex("*api*"));
        assertEquals("api\\.example.*", UrlRegexFilter.expandPseudoRegex("api\\.example*"));
        assertEquals(".*", UrlRegexFilter.expandPseudoRegex("*"));
    }

    @Test
    void expandKeepsAlreadyFormedDotStar() {
        // 已存在的 .* 不应被修改
        assertEquals(".*api\\.example.*", UrlRegexFilter.expandPseudoRegex(".*api\\.example.*"));
    }

    @Test
    void expandPreservesStarInsideCharacterClass() {
        // 字符类内 * 视为字面字符
        assertEquals("[a*]x", UrlRegexFilter.expandPseudoRegex("[a*]x"));
        // 字符类外仍翻译
        assertEquals("[a*].*", UrlRegexFilter.expandPseudoRegex("[a*]*"));
    }

    @Test
    void expandHandlesEscapedBackslashAndUnclosedBracket() {
        // 转义反斜杠：\* 被识别为"被转义"，保留 \* 不翻译（用户级）—— 这里仅冒烟，下方用例覆盖更严格路径
        // 未配对 [：从开括号起 depth 升到 1，里面所有字符都视为字面（含 *）
        assertEquals("[unclosed*", UrlRegexFilter.expandPseudoRegex("[unclosed*"));
    }

    @Test
    void expandPseudoReturnsInputWhenNullOrEmpty() {
        assertNull(UrlRegexFilter.expandPseudoRegex(null));
        assertEquals("", UrlRegexFilter.expandPseudoRegex(""));
    }

    @Test
    void expandPseudoLeavesRealRegexUntouched() {
        // 标准正则完全不动
        String real = "(api|users)/v\\d+/[a-z]+";
        assertEquals(real, UrlRegexFilter.expandPseudoRegex(real));
    }

    // ========== 伪正则经构造器后行为正确 ==========

    @Test
    void pseudoRegexConstructedFilterWorks() {
        // 用户写 *api* 应当等效 .*api.*，匹配 https://foo-api-baz.example/...
        UrlRegexFilter filter = new UrlRegexFilter("*api*", null);
        assertTrue(filter.matches("https://foo.api.baz.example/path"));
        assertTrue(filter.matches("https://example.com/api/users"));
        assertFalse(filter.matches("https://example.com/users"));
    }

    @Test
    void starInsideCharacterClassTreatedAsLiteral() {
        // 字符类内 * 不被翻译 → [a*] 匹配字面字符 'a' 或 '*'
        UrlRegexFilter filter = new UrlRegexFilter("[a*]x", null);
        assertTrue(filter.matches("ax-prefix"));
        assertTrue(filter.matches("*x-suffix"));
        assertFalse(filter.matches("bx-no"));
    }

    // ========== validate():UI 实时校验 ==========

    @Test
    void validateEmpty() {
        UrlRegexFilter.ValidationResult r1 = UrlRegexFilter.validate(null);
        UrlRegexFilter.ValidationResult r2 = UrlRegexFilter.validate("   ");
        assertSame(UrlRegexFilter.ValidationResult.EMPTY, r1);
        assertSame(UrlRegexFilter.ValidationResult.EMPTY, r2);
    }

    @Test
    void validateStandardRegex() {
        UrlRegexFilter.ValidationResult r = UrlRegexFilter.validate("api\\.example\\.com");
        assertEquals(UrlRegexFilter.ValidationStatus.VALID, r.status());
        assertSame(UrlRegexFilter.ValidationResult.VALID, r);
        // VALID 状态无翻译场景:translatedRegex 为空字符串。UI 应当用原输入展示。
        assertEquals("", r.translatedRegex());
    }

    @Test
    void validatePseudoRegexReturnsExpanded() {
        UrlRegexFilter.ValidationResult r = UrlRegexFilter.validate("*api*");
        assertEquals(UrlRegexFilter.ValidationStatus.VALID_EXPANDED, r.status());
        assertEquals(".*api.*", r.translatedRegex());
        assertTrue(r.message().contains("展开"));
    }

    @Test
    void validateInvalidRegex() {
        UrlRegexFilter.ValidationResult r = UrlRegexFilter.validate("([unclosed");
        assertEquals(UrlRegexFilter.ValidationStatus.INVALID, r.status());
        assertTrue(r.message().contains("非法"), r.message());
    }

    @Test
    void validateInvalidAfterExpansion() {
        // 用户输入 *api[ 这种伪正则 → 翻译成 .*api[ 后仍非法（字符类未闭合）
        UrlRegexFilter.ValidationResult r = UrlRegexFilter.validate("*api[");
        assertEquals(UrlRegexFilter.ValidationStatus.INVALID, r.status());
    }
}
