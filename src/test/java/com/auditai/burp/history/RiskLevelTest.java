package com.auditai.burp.history;

import com.auditai.burp.http.AnalysisResult;
import com.auditai.burp.http.Finding;
import com.auditai.burp.http.Severity;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * {@link RiskLevel} 单元测试：
 * <ul>
 *   <li>枚举常量值稳定（rank/label 与 Severity 一一对应 + NONE 兜底）；</li>
 *   <li>{@link RiskLevel#derive} 从 findings 推导最高严重度，失败/无 findings 时为 NONE。</li>
 * </ul>
 */
class RiskLevelTest {

    @Test
    void enumValues_haveExpectedRankAndLabel() {
        assertEquals(5, RiskLevel.CRITICAL.rank);
        assertEquals("严重", RiskLevel.CRITICAL.label);
        assertEquals(0, RiskLevel.NONE.rank);
        assertEquals("—", RiskLevel.NONE.label);
    }

    @Test
    void derive_nullResult_returnsNone() {
        assertSame(RiskLevel.NONE, RiskLevel.derive(null));
    }

    @Test
    void derive_errorResult_returnsNone() {
        AnalysisResult result = AnalysisResult.error(0L, "GET", "http://x", 200, "boom", 100L);
        assertSame(RiskLevel.NONE, RiskLevel.derive(result));
    }

    @Test
    void derive_emptyFindings_returnsNone() {
        AnalysisResult result = AnalysisResult.success(0L, "GET", "http://x", 200, "ok", 100L);
        assertSame(RiskLevel.NONE, RiskLevel.derive(result));
    }

    @Test
    void derive_blankSummary_returnsNone() {
        Finding f = Finding.create("x", 80, "high", "desc", "GET", "http://x", 0L, 0L);
        AnalysisResult result = AnalysisResult.success(0L, "GET", "http://x", 200, "  ", 100L,
                List.of(f));
        assertSame(RiskLevel.NONE, RiskLevel.derive(result));
    }

    @Test
    void derive_singleFinding_returnsThatRisk() {
        Finding f = Finding.create("x", 80, "high", "desc", "GET", "http://x", 0L, 0L);
        AnalysisResult result = AnalysisResult.success(0L, "GET", "http://x", 200, "ok", 100L,
                List.of(f));
        assertSame(RiskLevel.HIGH, RiskLevel.derive(result));
    }

    @Test
    void derive_multipleFindings_picksHighestRank() {
        Finding low = Finding.create("a", 50, "low", "d1", "GET", "http://x", 0L, 0L);
        Finding high = Finding.create("b", 90, "high", "d2", "GET", "http://x", 0L, 0L);
        Finding critical = Finding.create("c", 99, "critical", "d3", "GET", "http://x", 0L, 0L);
        AnalysisResult result = AnalysisResult.success(0L, "GET", "http://x", 200, "ok", 100L,
                List.of(low, high, critical));
        assertSame(RiskLevel.CRITICAL, RiskLevel.derive(result));
    }

    @Test
    void derive_nullElementsInFindings_areSkipped() {
        Finding high = Finding.create("a", 90, "high", "d1", "GET", "http://x", 0L, 0L);
        // 含 null 时跳过（不抛 NPE），结果取非 null 中最高
        java.util.List<Finding> mixed = new java.util.ArrayList<>();
        mixed.add(null);
        mixed.add(high);
        mixed.add(null);
        AnalysisResult result = AnalysisResult.success(0L, "GET", "http://x", 200, "ok", 100L,
                java.util.Collections.unmodifiableList(mixed));
        assertSame(RiskLevel.HIGH, RiskLevel.derive(result));
    }

    @Test
    void severityMapping_isOneToOne() {
        // RiskLevel 的 5 档（除 NONE）应与 Severity 的 5 档一一对应：rank 字段值必须相等。
        assertEquals(Severity.CRITICAL.rank, RiskLevel.CRITICAL.rank);
        assertEquals(Severity.HIGH.rank, RiskLevel.HIGH.rank);
        assertEquals(Severity.MEDIUM.rank, RiskLevel.MEDIUM.rank);
        assertEquals(Severity.LOW.rank, RiskLevel.LOW.rank);
        assertEquals(Severity.INFO.rank, RiskLevel.INFO.rank);
    }
}
