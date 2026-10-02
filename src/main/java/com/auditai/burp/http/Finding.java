package com.auditai.burp.http;

import java.util.Objects;
import java.util.UUID;

/**
 * 单条"经模型分析后认为发现的问题（或者可疑点）"的不可变记录。
 *
 * <p>由 {@link TrafficAnalyzer} 在分析线程解析模型输出得到，提交到 {@link FindingStore}
 * 供"问题列表"页签展示。一条问题绑定一对 {@code (method, url)}，可携带模型对问题
 * 的可信度（{@code confidence}）、严重程度（{@link Severity}）、详细描述
 * （{@code description}）。</p>
 *
 * <p>所有字段都在构造时确定，之后不再修改——天然线程安全，可被 EDT 之外的工作线程
 * 读访问。"完整分析报告"和"关联 requestId"等上下文由 {@link FindingStore} 通过
 * {@code analysisTimestamp} 关联，不直接放在 Finding 上（避免重复存储多份
 * 同一份 summary）。</p>
 */
public final class Finding {

    /** 全局唯一 ID（用于 FindingStore 的去重与持久化）。 */
    private final String findingId;

    /** HTTP 方法（GET / POST / …），便于和 {@code AnalysisHistoryStore} 里的同一条记录关联。 */
    private final String method;

    /** 完整请求 URL。 */
    private final String url;

    /** 漏洞 / 风险类型标签（如 "SQL 注入" / "XSS" / "鉴权绕过"），由模型给定。 */
    private final String type;

    /**
     * 可信度（0–100 整数，值越大代表模型越确信）。
     *
     * <p>取值语义：80+ 高置信，60–80 中等，<60 偏可疑。UI 列表按该值降序，
     * 配合 {@link Severity} 共同决定排序权重。</p>
     */
    private final int confidence;

    /** 严重程度（critical / high / medium / low / info）。 */
    private final Severity severity;

    /**
     * 详细描述（多行中文）。模型在 {@code findings[].description} 字段直接给；
     * 占位 finding 时由 UI 兜底从整段 analysis 截取。
     */
    private final String description;

    /** 问题被识别出来的时间戳（毫秒）。 */
    private final long capturedAtMillis;

    /**
     * 所属分析任务的时间戳（毫秒），与 {@link AnalysisResult#getTimestampMillis()} 一致。
     *
     * <p>用于在 {@link FindingStore} 内关联到该次分析的完整 report 和 requestId。</p>
     */
    private final long analysisTimestamp;

    /**
     * 是否为"占位 finding"：模型明确表态 {@code risk != "none"}、但没给出结构化
     * findings 数组时由 UI 兜底生成（让"本次分析明明说有风险、却没结构化细节"
     * 的情况不至于完全丢失）。
     *
     * <p>UI 列表会对占位 finding 做视觉标识（斜体 + 灰色 + "(占位)" 后缀），
     * 让用户清楚这是兜底结果、不是模型给出的结构化结论。</p>
     */
    private final boolean placeholder;

    /**
     * 完整构造器（仅本包内可见，统一通过 {@link #create} / {@link #placeholder} 工厂创建）。
     */
    private Finding(String findingId, String method, String url, String type,
                    int confidence, Severity severity, String description,
                    long capturedAtMillis, long analysisTimestamp, boolean placeholder) {
        this.findingId = findingId;
        this.method = method;
        this.url = url;
        this.type = type;
        this.confidence = confidence;
        this.severity = severity;
        this.description = description == null ? "" : description;
        this.capturedAtMillis = capturedAtMillis;
        this.analysisTimestamp = analysisTimestamp;
        this.placeholder = placeholder;
    }

    /**
     * 工厂方法：把模型给出的一条原始 finding 包装成不可变 {@link Finding}（正常 finding）。
     *
     * <p>任何字段为 null / 空白时使用安全占位：</p>
     * <ul>
     *   <li>{@code method} / {@code url} 强制使用调用方传入的 fallback（来自请求本身）；</li>
     *   <li>{@code type} 为空时记为 "未分类"；</li>
     *   <li>{@code description} 为空时记为空串（UI 上视为"无"）；</li>
     *   <li>{@code confidence} 越界时夹到 [0, 100]。</li>
     * </ul>
     *
     * @param fallbackMethod    模型未给出 method 时使用的 HTTP 方法（来自被分析请求）。
     * @param fallbackUrl       模型未给出 url 时使用的 URL（来自被分析请求）。
     * @param capturedAtMillis  问题被识别出来的时间戳（毫秒）。
     * @param analysisTimestamp 所属分析任务的时间戳（毫秒），与 {@link AnalysisResult#getTimestampMillis()} 一致。
     */
    public static Finding create(String type, Integer confidence, String severityText,
                                 String description, String fallbackMethod, String fallbackUrl,
                                 long capturedAtMillis, long analysisTimestamp) {
        String safeMethod = fallbackMethod == null || fallbackMethod.isBlank() ? "" : fallbackMethod;
        String safeUrl = fallbackUrl == null || fallbackUrl.isBlank() ? "" : fallbackUrl;
        String safeType = type == null || type.isBlank() ? "未分类" : type;
        int safeConfidence = confidence == null ? 0 : Math.max(0, Math.min(100, confidence));
        Severity safeSeverity = Severity.parse(severityText);
        String safeDescription = description == null ? "" : description;
        return new Finding(UUID.randomUUID().toString(), safeMethod, safeUrl, safeType,
                safeConfidence, safeSeverity, safeDescription,
                capturedAtMillis, analysisTimestamp, false);
    }

    /**
     * 工厂方法：构造"占位 finding"——模型表态 {@code risk != "none"} 但 findings 数组为空时
     * 兜底生成，避免漏报。
     *
     * <p>占位 finding 用 {@link Severity} 体现本次整体风险等级；{@code type} 固定为
     * "需关注"；{@code description} 由调用方传入（通常是整段 analysis 的前若干字），
     * UI 上会做斜体 + "(占位)" 视觉标识。</p>
     */
    public static Finding placeholder(String description, Severity severity,
                                      String fallbackMethod, String fallbackUrl,
                                      long capturedAtMillis, long analysisTimestamp) {
        String safeMethod = fallbackMethod == null || fallbackMethod.isBlank() ? "" : fallbackMethod;
        String safeUrl = fallbackUrl == null || fallbackUrl.isBlank() ? "" : fallbackUrl;
        String safeType = "需关注";
        Severity safeSeverity = severity == null ? Severity.INFO : severity;
        int placeholderConfidence = severityConfidence(safeSeverity);
        String safeDescription = description == null ? "" : description;
        return new Finding(UUID.randomUUID().toString(), safeMethod, safeUrl, safeType,
                placeholderConfidence, safeSeverity, safeDescription,
                capturedAtMillis, analysisTimestamp, true);
    }

    /**
     * 工厂方法：磁盘恢复用，把所有字段（包含 placeholder 标记）一次性塞回去。
     *
     * <p>仅 {@link FindingStore} 反序列化时使用——业务路径都应走 {@link #create} /
     * {@link #placeholder}。</p>
     */
    static Finding restore(String findingId, String method, String url, String type,
                           int confidence, Severity severity, String description,
                           long capturedAtMillis, long analysisTimestamp, boolean placeholder) {
        String safeId = (findingId == null || findingId.isBlank()) ? UUID.randomUUID().toString() : findingId;
        return new Finding(safeId, method, url, type, confidence, severity, description,
                capturedAtMillis, analysisTimestamp, placeholder);
    }

    /** 把严重程度映射成占位 finding 的默认可信度（让占位 finding 也能在表格里有合理排序）。 */
    private static int severityConfidence(Severity severity) {
        return switch (severity) {
            case CRITICAL -> 75;
            case HIGH -> 65;
            case MEDIUM -> 50;
            case LOW -> 35;
            case INFO -> 20;
            default -> 0;
        };
    }

    public String getFindingId() {
        return findingId;
    }

    public String getMethod() {
        return method;
    }

    public String getUrl() {
        return url;
    }

    public String getType() {
        return type;
    }

    public int getConfidence() {
        return confidence;
    }

    public Severity getSeverity() {
        return severity;
    }

    public String getDescription() {
        return description;
    }

    public long getCapturedAtMillis() {
        return capturedAtMillis;
    }

    public long getAnalysisTimestamp() {
        return analysisTimestamp;
    }

    public boolean isPlaceholder() {
        return placeholder;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof Finding)) {
            return false;
        }
        Finding that = (Finding) other;
        return Objects.equals(findingId, that.findingId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(findingId);
    }
}
