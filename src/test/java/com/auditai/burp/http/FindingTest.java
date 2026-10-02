package com.auditai.burp.http;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@link Finding} 工厂方法与字段容错的单元测试。 */
class FindingTest {

    @Test
    void createReplacesBlankFields() {
        Finding f = Finding.create("  ", null, null, "", null, null,
                100L, 50L);
        assertEquals("未分类", f.getType());
        assertEquals(0, f.getConfidence());
        assertSame(Severity.INFO, f.getSeverity());
        assertEquals("", f.getDescription());
        assertEquals("", f.getMethod());
        assertEquals("", f.getUrl());
        assertEquals(100L, f.getCapturedAtMillis());
        assertEquals(50L, f.getAnalysisTimestamp());
        assertFalse(f.isPlaceholder());
    }

    @Test
    void createClampsConfidence() {
        Finding high = Finding.create("x", 200, "high", "d", "GET", "http://x",
                0L, 0L);
        assertEquals(100, high.getConfidence());
        Finding low = Finding.create("x", -50, "low", "d", "GET", "http://x",
                0L, 0L);
        assertEquals(0, low.getConfidence());
    }

    @Test
    void findingIdIsUniquePerCall() {
        Finding a = Finding.create("x", 50, "info", "d", "GET", "http://x", 0L, 0L);
        Finding b = Finding.create("x", 50, "info", "d", "GET", "http://x", 0L, 0L);
        assertNotNull(a.getFindingId());
        assertNotNull(b.getFindingId());
        assertNotEquals(a.getFindingId(), b.getFindingId());
    }

    @Test
    void placeholderMarksAsPlaceholder() {
        Finding f = Finding.placeholder("分析摘要", Severity.HIGH,
                "GET", "http://x", 0L, 0L);
        assertTrue(f.isPlaceholder());
        assertEquals("需关注", f.getType());
        assertSame(Severity.HIGH, f.getSeverity());
        assertEquals("分析摘要", f.getDescription());
        // 占位 finding 用 severity 推一个默认可信度（high→65），让排序时仍占合理位置
        assertTrue(f.getConfidence() > 0);
    }

    @Test
    void placeholderConfidenceMappingBySeverity() {
        assertEquals(75, Finding.placeholder("a", Severity.CRITICAL, "GET", "u", 0L, 0L).getConfidence());
        assertEquals(65, Finding.placeholder("a", Severity.HIGH, "GET", "u", 0L, 0L).getConfidence());
        assertEquals(50, Finding.placeholder("a", Severity.MEDIUM, "GET", "u", 0L, 0L).getConfidence());
        assertEquals(35, Finding.placeholder("a", Severity.LOW, "GET", "u", 0L, 0L).getConfidence());
        assertEquals(20, Finding.placeholder("a", Severity.INFO, "GET", "u", 0L, 0L).getConfidence());
    }
}
