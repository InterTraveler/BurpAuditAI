package com.auditai.burp.http;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link AnalysisResponseParser#extractFindings} + {@link AnalysisResponseParser#resolveFindings}
 * 的容错解析 + 决策表单元测试。
 */
class TrafficAnalyzerFindingsTest {

    /** 阈值减 1，confidence 低于此值应被过滤。 */
    private static final int BELOW_THRESHOLD = AnalysisResponseParser.DEFAULT_MIN_CONFIDENCE - 1;

    /** 等于阈值，应被保留。 */
    private static final int AT_THRESHOLD = AnalysisResponseParser.DEFAULT_MIN_CONFIDENCE;

    @Test
    void parsesWellFormedFindings() {
        String raw = "{\"analysis\":\"...\",\"risk\":\"high\","
                + "\"findings\":[{\"type\":\"SQL 注入\",\"confidence\":85,\"description\":\"id 存在注入\"}]}";
        AnalysisResponseParser.ExtractedFindings extracted = AnalysisResponseParser.extractFindings(raw,
                "GET", "http://x.test/api?id=1", 1000L, 999L);
        assertTrue(extracted.hasIssue());
        assertSame(Severity.HIGH, extracted.riskLevel());
        List<Finding> finalFindings = AnalysisResponseParser.resolveFindings(extracted, "...", "GET", "http://x", 1000L, 999L);
        assertEquals(1, finalFindings.size());
        Finding f = finalFindings.get(0);
        assertEquals("SQL 注入", f.getType());
        assertEquals(85, f.getConfidence());
        assertSame(Severity.HIGH, f.getSeverity());
        assertEquals("id 存在注入", f.getDescription());
        assertFalse(f.isPlaceholder());
    }

    @Test
    void emptyFindingsWithRiskNoneProducesEmptyList() {
        String raw = "{\"analysis\":\"...\",\"risk\":\"none\",\"findings\":[]}";
        AnalysisResponseParser.ExtractedFindings extracted = AnalysisResponseParser.extractFindings(raw,
                "GET", "http://x", 0L, 0L);
        assertFalse(extracted.hasIssue());
        assertSame(Severity.INFO, extracted.riskLevel());
        List<Finding> finalFindings = AnalysisResponseParser.resolveFindings(extracted, "...", "GET", "http://x", 0L, 0L);
        assertTrue(finalFindings.isEmpty());
    }

    @Test
    void emptyFindingsWithRiskHighProducesPlaceholder() {
        String raw = "{\"analysis\":\"...\",\"risk\":\"high\",\"findings\":[]}";
        AnalysisResponseParser.ExtractedFindings extracted = AnalysisResponseParser.extractFindings(raw,
                "GET", "http://x", 0L, 0L);
        assertTrue(extracted.hasIssue());
        assertSame(Severity.HIGH, extracted.riskLevel());
        String analysis = "本次分析认为存在风险，问题位于参数 id 附近";
        List<Finding> finalFindings = AnalysisResponseParser.resolveFindings(extracted, analysis,
                "GET", "http://x", 0L, 0L);
        // 兜底：1 条占位 finding
        assertEquals(1, finalFindings.size());
        Finding placeholder = finalFindings.get(0);
        assertTrue(placeholder.isPlaceholder());
        assertEquals("需关注", placeholder.getType());
        assertSame(Severity.HIGH, placeholder.getSeverity());
        // description 取自 analysis 截取
        assertTrue(placeholder.getDescription().contains("问题位于参数 id 附近"));
    }

    @Test
    void missingRiskFieldWithEmptyFindingsProducesEmpty() {
        // 完全没 risk 字段 + 没 findings → 视为无问题（保守）
        String raw = "{\"analysis\":\"...\"}";
        AnalysisResponseParser.ExtractedFindings extracted = AnalysisResponseParser.extractFindings(raw,
                "GET", "http://x", 0L, 0L);
        assertFalse(extracted.hasIssue());
        List<Finding> finalFindings = AnalysisResponseParser.resolveFindings(extracted, "...", "GET", "http://x", 0L, 0L);
        assertTrue(finalFindings.isEmpty());
    }

    @Test
    void missingRiskWithFindingsKeepsThem() {
        // 兼容旧模型：没 risk 字段但给了 findings → 当有问题，findings 全部入库
        String raw = "{\"findings\":[{\"type\":\"XSS\",\"confidence\":70,\"description\":\"d\"}]}";
        AnalysisResponseParser.ExtractedFindings extracted = AnalysisResponseParser.extractFindings(raw,
                "GET", "http://x", 0L, 0L);
        // 没 risk 字段时 hasIssue=false（保守默认），但 findings 非空 → resolveFindings 仍保留
        assertFalse(extracted.hasIssue());
        assertTrue(extracted.findings().isEmpty() == false);
        List<Finding> finalFindings = AnalysisResponseParser.resolveFindings(extracted, "...", "GET", "http://x", 0L, 0L);
        assertEquals(1, finalFindings.size());
        assertEquals("XSS", finalFindings.get(0).getType());
    }

    @Test
    void nonJsonProducesEmpty() {
        String raw = "not a json at all";
        AnalysisResponseParser.ExtractedFindings extracted = AnalysisResponseParser.extractFindings(raw,
                "GET", "http://x", 0L, 0L);
        assertFalse(extracted.hasIssue());
        List<Finding> finalFindings = AnalysisResponseParser.resolveFindings(extracted, "...", "GET", "http://x", 0L, 0L);
        assertTrue(finalFindings.isEmpty());
    }

    @Test
    void nullAndEmptyProduceEmpty() {
        AnalysisResponseParser.ExtractedFindings e1 =
                AnalysisResponseParser.extractFindings(null, "GET", "http://x", 0L, 0L);
        assertFalse(e1.hasIssue());
        AnalysisResponseParser.ExtractedFindings e2 =
                AnalysisResponseParser.extractFindings("", "GET", "http://x", 0L, 0L);
        assertFalse(e2.hasIssue());
    }

    @Test
    void partiallyBadEntrySkippedButOthersKept() {
        // 第一条是字符串（非对象），第二条是合法对象；解析应保留第二条
        String raw = "{\"risk\":\"high\",\"findings\":[\"garbage\","
                + "{\"type\":\"XSS\",\"confidence\":70,\"description\":\"d\"}]}";
        AnalysisResponseParser.ExtractedFindings extracted = AnalysisResponseParser.extractFindings(raw,
                "GET", "http://x", 0L, 0L);
        assertEquals(1, extracted.findings().size());
        assertEquals("XSS", extracted.findings().get(0).getType());
    }

    @Test
    void severityInheritedFromTopLevelRisk() {
        // finding 元素的 severity 一律继承顶层 risk 字段
        String raw = "{\"risk\":\"critical\",\"findings\":["
                + "{\"type\":\"SQL\",\"confidence\":90,\"description\":\"d\"}]}";
        AnalysisResponseParser.ExtractedFindings extracted = AnalysisResponseParser.extractFindings(raw,
                "GET", "http://x", 0L, 0L);
        assertEquals(1, extracted.findings().size());
        assertSame(Severity.CRITICAL, extracted.findings().get(0).getSeverity());
    }

    @Test
    void riskCaseInsensitive() {
        // "NONE" / "High" 都能解析
        assertFalse(AnalysisResponseParser.extractFindings("{\"risk\":\"NONE\"}", "GET", "u", 0L, 0L).hasIssue());
        assertTrue(AnalysisResponseParser.extractFindings("{\"risk\":\"High\"}", "GET", "u", 0L, 0L).hasIssue());
    }

    @Test
    void unknownRiskValueFallsBackToInfoAndHasIssueFalse() {
        // 解析不出来的 risk 字符串降级为 INFO；INFO + 空 findings → hasIssue=false。
        String raw = "{\"risk\":\"haha\",\"findings\":[]}";
        AnalysisResponseParser.ExtractedFindings extracted = AnalysisResponseParser.extractFindings(raw,
                "GET", "http://x", 0L, 0L);
        assertFalse(extracted.hasIssue());
        assertSame(Severity.INFO, extracted.riskLevel());
    }

    @Test
    void lowConfidenceFindingIsDropped() {
        // confidence=8 < 阈值，应不入库。
        String raw = "{\"analysis\":\"...\",\"risk\":\"high\",\"findings\":["
                + "{\"type\":\"SQL 注入\",\"confidence\":8,\"description\":\"残留不确定性\"}]}";
        AnalysisResponseParser.ExtractedFindings extracted = AnalysisResponseParser.extractFindings(raw,
                "GET", "http://x/?ind=1", 0L, 0L);
        assertTrue(extracted.findings().isEmpty(),
                "confidence=8 应被阈值过滤掉，不能出现在 findings 列表里");
    }

    @Test
    void lowConfidenceFindingIsDroppedEvenWhenMixedWithHighConfidence() {
        // 混合场景：一条 90% 的真问题 + 一条 5% 的噪声 → 90% 必须保留、5% 必须丢弃，
        // 不能因为整批里掺了噪声就把好 finding 一起丢掉，反之亦然。
        String raw = "{\"risk\":\"high\",\"findings\":["
                + "{\"type\":\"XSS\",\"confidence\":85,\"description\":\"真问题\"},"
                + "{\"type\":\"SQL 注入\",\"confidence\":5,\"description\":\"噪声\"}]}";
        AnalysisResponseParser.ExtractedFindings extracted = AnalysisResponseParser.extractFindings(raw,
                "GET", "http://x", 0L, 0L);
        assertEquals(1, extracted.findings().size());
        assertEquals("XSS", extracted.findings().get(0).getType());
        assertEquals(85, extracted.findings().get(0).getConfidence());
    }

    @Test
    void confidenceExactlyAtThresholdIsKept() {
        // confidence 等于阈值，应被保留。
        String raw = "{\"risk\":\"medium\",\"findings\":["
                + "{\"type\":\"SQL 注入\",\"confidence\":" + AT_THRESHOLD + ",\"description\":\"边界\"}]}";
        AnalysisResponseParser.ExtractedFindings extracted = AnalysisResponseParser.extractFindings(raw,
                "GET", "http://x", 0L, 0L);
        assertEquals(1, extracted.findings().size());
        assertEquals(AT_THRESHOLD, extracted.findings().get(0).getConfidence());
    }

    @Test
    void confidenceOneBelowThresholdIsDropped() {
        // confidence 等于阈值减 1，应被丢弃。
        String raw = "{\"risk\":\"medium\",\"findings\":["
                + "{\"type\":\"SQL 注入\",\"confidence\":" + BELOW_THRESHOLD + ",\"description\":\"边界噪声\"}]}";
        AnalysisResponseParser.ExtractedFindings extracted = AnalysisResponseParser.extractFindings(raw,
                "GET", "http://x", 0L, 0L);
        assertTrue(extracted.findings().isEmpty(),
                "confidence=" + BELOW_THRESHOLD + " 应被阈值过滤");
    }

    @Test
    void nullConfidenceIsDropped() {
        // confidence 字段缺失等同 0，低于阈值必被丢弃。
        String raw = "{\"risk\":\"high\",\"findings\":["
                + "{\"type\":\"XSS\",\"description\":\"没填 confidence\"}]}";
        AnalysisResponseParser.ExtractedFindings extracted = AnalysisResponseParser.extractFindings(raw,
                "GET", "http://x", 0L, 0L);
        assertTrue(extracted.findings().isEmpty(),
                "confidence 缺失应等同 0，低于阈值必然丢弃");
    }

    @Test
    void allFindingsFilteredOutAndRiskInfoDemotesHasIssue() {
        // 把"全部 finding 被阈值过滤 + 整次 risk 仅为 INFO"的请求统一降级为 hasIssue=false——
        // 让 resolveFindings 不再造占位 finding 冲进 UI 列表。
        String raw = "{\"analysis\":\"...\",\"risk\":\"info\",\"findings\":["
                + "{\"type\":\"SQL 注入\",\"confidence\":5,\"description\":\"噪声\"}]}";
        AnalysisResponseParser.ExtractedFindings extracted = AnalysisResponseParser.extractFindings(raw,
                "GET", "http://x", 0L, 0L);
        assertTrue(extracted.findings().isEmpty());
        assertFalse(extracted.hasIssue(),
                "findings 已被过滤为空 + risk=INFO，必须同步把 hasIssue 降为 false");
    }

    @Test
    void emptyFindingsWithRiskInfoProducesEmptyFinalList() {
        // INFO 档位不造占位 finding。
        String raw = "{\"analysis\":\"...\",\"risk\":\"info\",\"findings\":[]}";
        AnalysisResponseParser.ExtractedFindings extracted = AnalysisResponseParser.extractFindings(raw,
                "GET", "http://x", 0L, 0L);
        List<Finding> finalFindings = AnalysisResponseParser.resolveFindings(extracted, "...", "GET", "http://x", 0L, 0L);
        assertTrue(finalFindings.isEmpty(),
                "findings 空 + risk=INFO 不应造占位 finding");
    }

    @Test
    void highRiskStillProducesPlaceholderEvenAfterFiltering() {
        // findings 空 + risk=high 仍必须造占位 finding。
        // 阈值过滤只作用于结构化 findings，占位 finding 由 Severity 等级映射 confidence，与阈值无关。
        String raw = "{\"analysis\":\"未发现结构化 findings 但 risk=high\",\"risk\":\"high\",\"findings\":[]}";
        AnalysisResponseParser.ExtractedFindings extracted = AnalysisResponseParser.extractFindings(raw,
                "GET", "http://x", 0L, 0L);
        assertTrue(extracted.hasIssue());
        List<Finding> finalFindings = AnalysisResponseParser.resolveFindings(extracted,
                "未发现结构化 findings 但 risk=high", "GET", "http://x", 0L, 0L);
        assertEquals(1, finalFindings.size());
        assertTrue(finalFindings.get(0).isPlaceholder());
        assertSame(Severity.HIGH, finalFindings.get(0).getSeverity());
    }

    @Test
    void customMinConfidenceZeroKeepsAllFindings() {
        // minConfidence=0 等价于不过滤，仅单测用于排查边界。
        String raw = "{\"risk\":\"low\",\"findings\":["
                + "{\"type\":\"XSS\",\"confidence\":1,\"description\":\"边缘案例\"}]}";
        AnalysisResponseParser.ExtractedFindings extracted = AnalysisResponseParser.extractFindings(raw,
                "GET", "http://x", 0L, 0L, 0);
        assertEquals(1, extracted.findings().size(),
                "minConfidence=0 时应保留全部 finding（包括 1% 这类极低置信度）");
    }

}
