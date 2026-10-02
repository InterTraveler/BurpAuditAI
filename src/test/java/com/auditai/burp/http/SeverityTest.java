package com.auditai.burp.http;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

/** {@link Severity} 解析与排序权重的单元测试。 */
class SeverityTest {

    @Test
    void parseEnglishKeywords() {
        assertSame(Severity.CRITICAL, Severity.parse("critical"));
        assertSame(Severity.CRITICAL, Severity.parse("CRITICAL"));
        assertSame(Severity.HIGH, Severity.parse("high"));
        assertSame(Severity.MEDIUM, Severity.parse("medium"));
        assertSame(Severity.LOW, Severity.parse("low"));
        assertSame(Severity.INFO, Severity.parse("info"));
    }

    @Test
    void parseChineseKeywords() {
        assertSame(Severity.CRITICAL, Severity.parse("严重"));
        assertSame(Severity.CRITICAL, Severity.parse("危急"));
        assertSame(Severity.HIGH, Severity.parse("高危"));
        assertSame(Severity.HIGH, Severity.parse("高级"));
        assertSame(Severity.MEDIUM, Severity.parse("中危"));
        assertSame(Severity.LOW, Severity.parse("低"));
        assertSame(Severity.INFO, Severity.parse("信息"));
    }

    @Test
    void parseFallsBackToInfo() {
        assertSame(Severity.INFO, Severity.parse(null));
        assertSame(Severity.INFO, Severity.parse(""));
        assertSame(Severity.INFO, Severity.parse("   "));
        assertSame(Severity.INFO, Severity.parse("garbage"));
    }

    @Test
    void rankOrdering() {
        // 排序时 rank 越大越靠前
        assertNotEquals(0, Severity.CRITICAL.rank);
        assertEquals(true, Severity.CRITICAL.rank > Severity.HIGH.rank);
        assertEquals(true, Severity.HIGH.rank > Severity.MEDIUM.rank);
        assertEquals(true, Severity.MEDIUM.rank > Severity.LOW.rank);
        assertEquals(true, Severity.LOW.rank > Severity.INFO.rank);
    }
}
