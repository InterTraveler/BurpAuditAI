package com.auditai.burp.http;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * 单条流量分析的不可变结果对象。TrafficAnalyzer 在分析线程构造，UI 线程读取；字段在构造时确定后不再修改。
 *
 * analysisId 是本次分析在 AnalysisHistoryEntry / Finding / 审计轨迹之间共享的全局唯一字符串。
 */
public final class AnalysisResult {

    /** 本次分析在 entry / finding / audit-trail 之间共享的全局唯一 ID。 */
    private final String analysisId;

    /** 分析开始的时间戳（毫秒），用于表格"时间"列。 */
    private final long timestampMillis;

    /** HTTP 方法（GET / POST / …）。 */
    private final String method;

    /** 完整请求 URL。 */
    private final String url;

    /** 响应状态码；无响应时为 -1。 */
    private final int statusCode;

    /** AI 分析摘要（成功时）或错误描述（失败时）。 */
    private final String summary;

    /** 错误信息；成功时为 null。 */
    private final String error;

    /** 分析耗时（毫秒），含 AI 接口往返时间。 */
    private final long durationMillis;

    /**
     * 模型识别出的"问题 / 可疑点"列表（成功时可能为空但极少情况；失败时通常为空）。
     *
     * 每个 {@link Finding} 绑定同一对 {@code (method, url)}，可独立展示在
     * "问题列表"页签中，由 {@link FindingStore} 进一步汇聚成跨请求的全局问题集合。
     */
    private final List<Finding> findings;

    /** 构造器不对外暴露，统一通过 success / error 工厂方法创建。 */
    private AnalysisResult(String analysisId, long timestampMillis, String method, String url,
                           int statusCode, String summary, String error, long durationMillis,
                           List<Finding> findings) {
        this.analysisId = Objects.requireNonNull(analysisId, "analysisId");
        this.timestampMillis = timestampMillis;
        this.method = method;
        this.url = url;
        this.statusCode = statusCode;
        this.summary = summary;
        this.error = error;
        this.durationMillis = durationMillis;
        // 深拷贝 + 过滤 null:断开原 list 与本对象的引用关系;过滤 null 避免 List.copyOf 直接抛 NPE。
        if (findings == null) {
            this.findings = List.of();
        } else {
            List<Finding> nonNull = new java.util.ArrayList<>(findings.size());
            for (Finding f : findings) {
                if (f != null) {
                    nonNull.add(f);
                }
            }
            this.findings = List.copyOf(nonNull);
        }
    }

    /**
     * 工厂方法：分析成功，无结构化 findings。
     *
     * @param analysisId 本次分析跨 entry / finding 共享的 ID,业务路径必传。
     */
    public static AnalysisResult success(String analysisId, long timestampMillis, String method, String url,
                                         int statusCode, String summary, long durationMillis) {
        return new AnalysisResult(analysisId, timestampMillis, method, url, statusCode, summary, null,
                durationMillis, List.of());
    }

    /** 工厂方法:分析成功,携带模型识别出的 findings。 */
    public static AnalysisResult success(String analysisId, long timestampMillis, String method, String url,
                                         int statusCode, String summary, long durationMillis,
                                         List<Finding> findings) {
        return new AnalysisResult(analysisId, timestampMillis, method, url, statusCode, summary, null,
                durationMillis, findings);
    }

    /** 工厂方法:分析失败。error 为 null / 空白时用"分析失败（异常无详细消息）"占位,避免 summary 列空字符串。 */
    public static AnalysisResult error(String analysisId, long timestampMillis, String method, String url,
                                       int statusCode, String error, long durationMillis) {
        String safeError = (error == null || error.isBlank()) ? "分析失败（异常无详细消息）" : error;
        return new AnalysisResult(analysisId, timestampMillis, method, url, statusCode, safeError, safeError,
                durationMillis, List.of());
    }

    /** 本次分析的共享 ID。 */
    public String getAnalysisId() {
        return analysisId;
    }

    public long getTimestampMillis() {
        return timestampMillis;
    }

    public String getMethod() {
        return method;
    }

    public String getUrl() {
        return url;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getSummary() {
        return summary;
    }

    public String getError() {
        return error;
    }

    public long getDurationMillis() {
        return durationMillis;
    }

    /**
     * 返回模型识别出的问题列表（永远非 null，可能为空）。
     *
     * UI 拿到结果后应通过 {@link FindingStore#addFindings(AnalysisResult)}
     * 把非空列表合并到全局问题库里。
     */
    public List<Finding> getFindings() {
        return findings;
    }
}
