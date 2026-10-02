package com.auditai.burp.http;

import java.util.List;

/**
 * 单条流量分析的不可变结果对象。
 *
 * <p>由 {@link TrafficAnalyzer} 在分析线程中构造，交给 UI 线程展示；
 * 字段全部在构造时确定，之后不再修改，天然线程安全。</p>
 */
public final class AnalysisResult {

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
     * <p>每个 {@link Finding} 绑定同一对 {@code (method, url)}，可独立展示在
     * "问题列表"页签中，由 {@link FindingStore} 进一步汇聚成跨请求的全局问题集合。</p>
     */
    private final List<Finding> findings;

    /** 构造器不对外暴露，统一通过 success / error 工厂方法创建。 */
    private AnalysisResult(long timestampMillis, String method, String url, int statusCode,
                           String summary, String error, long durationMillis,
                           List<Finding> findings) {
        this.timestampMillis = timestampMillis;
        this.method = method;
        this.url = url;
        this.statusCode = statusCode;
        this.summary = summary;
        this.error = error;
        this.durationMillis = durationMillis;
        // 深拷贝：{@code List.copyOf} 断开原 list 与本对象的引用关系，
        // 防止外部后续修改原 list 时穿透到 AnalysisResult 的 findings。
        // 顺带过滤掉 null 元素：与 {@code RiskLevel.derive} 的"null 元素跳过"语义对齐，
        // 避免 {@code List.copyOf} 自身在含 null 时直接抛 NPE。
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
     * 工厂方法：分析成功（无结构化 findings 的旧调用方使用）。
     */
    public static AnalysisResult success(long timestampMillis, String method, String url,
                                         int statusCode, String summary, long durationMillis) {
        return new AnalysisResult(timestampMillis, method, url, statusCode, summary, null,
                durationMillis, List.of());
    }

    /**
     * 工厂方法：分析成功（携带模型识别出的 findings）。
     */
    public static AnalysisResult success(long timestampMillis, String method, String url,
                                         int statusCode, String summary, long durationMillis,
                                         List<Finding> findings) {
        return new AnalysisResult(timestampMillis, method, url, statusCode, summary, null,
                durationMillis, findings);
    }

    /** 工厂方法：分析失败（网络错误、未配置 Key、模型报错等）。 */
    public static AnalysisResult error(long timestampMillis, String method, String url,
                                       int statusCode, String error, long durationMillis) {
        // 兜底：上层（TrafficAnalyzer 等）有时会把原始异常的 getMessage() 透传过来，
        // 部分异常（NullPointerException / IllegalStateException 不带 msg / JDK 抛的
        // 内部 IOException 等）的 message 为 null —— 之前直接传给构造器会让 summary / error
        // 同时为 null，UI 上"摘要"列显示成空字符串，用户无法判断分析是否真的跑过。
        // 这里把 null 统一替换成"未知错误"占位，至少让用户能看到"这条分析失败了"。
        String safeError = (error == null || error.isBlank()) ? "分析失败（异常无详细消息）" : error;
        return new AnalysisResult(timestampMillis, method, url, statusCode, safeError, safeError,
                durationMillis, List.of());
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
     * <p>UI 拿到结果后应通过 {@link FindingStore#addFindings(AnalysisResult)}
     * 把非空列表合并到全局问题库里。</p>
     */
    public List<Finding> getFindings() {
        return findings;
    }
}
