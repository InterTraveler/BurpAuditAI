package com.auditai.burp.http;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link AnalysisResult} 单元测试：工厂方法的语义、不可变性、findings 列表防御性拷贝。
 */
final class AnalysisResultTest {

    @Test
    void successWithoutFindingsProducesEmptyList() {
        AnalysisResult r = AnalysisResult.success(1000L, "GET", "http://x", 200, "ok", 50L);
        assertEquals(1000L, r.getTimestampMillis());
        assertEquals("GET", r.getMethod());
        assertEquals("http://x", r.getUrl());
        assertEquals(200, r.getStatusCode());
        assertEquals("ok", r.getSummary());
        assertNull(r.getError());
        assertEquals(50L, r.getDurationMillis());
        assertNotNull(r.getFindings());
        assertTrue(r.getFindings().isEmpty());
    }

    @Test
    void successWithFindingsKeepsThem() {
        List<Finding> findings = List.of(Finding.create("SQLi", 80, "high",
                "参数 id 存在注入", "GET", "http://x", 0L, 0L));
        AnalysisResult r = AnalysisResult.success(0L, "GET", "http://x", 200, "ok", 0L, findings);
        assertEquals(1, r.getFindings().size());
        assertEquals("SQLi", r.getFindings().get(0).getType());
    }

    @Test
    void errorResultHasErrorMessage() {
        AnalysisResult r = AnalysisResult.error(0L, "GET", "http://x", -1, "boom", 30L);
        assertEquals("boom", r.getError());
        assertEquals("boom", r.getSummary(), "error 路径下 summary 与 error 同源（前端展示用 summary）");
        assertTrue(r.getFindings().isEmpty());
    }

    @Test
    void findingsListIsImmutable() {
        List<Finding> mutable = new ArrayList<>();
        mutable.add(Finding.create("X", 50, "low", "d", "GET", "http://x", 0L, 0L));
        AnalysisResult r = AnalysisResult.success(0L, "GET", "http://x", 200, "ok", 0L, mutable);
        // 调用方再改原列表，不应影响 AnalysisResult
        mutable.clear();
        assertEquals(1, r.getFindings().size());
        // 直接改返回的列表应抛 UnsupportedOperationException
        assertThrows(UnsupportedOperationException.class, () -> r.getFindings().clear());
    }

}
