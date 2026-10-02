package com.auditai.burp.history;

import com.auditai.burp.http.AnalysisResult;
import com.auditai.burp.http.Finding;
import com.auditai.burp.http.Severity;

import java.util.List;

/**
 * "历史"页签里"风险等级"列的取值。
 *
 * <p>与 {@link Severity}（用在 finding 严重程度上）一对一映射 + 多一个 {@link #NONE}
 * 兜底档：分析失败、没有任何 finding、或者模型整体表态 risk=none 时显示。</p>
 *
 * <p>排序权重：{@link #rank} 越大越严重。"历史"页签默认按时间倒序展示，UI 也可
 * 让用户手动按风险等级降序排。</p>
 */
public enum RiskLevel {

    /** 严重：与 Severity.CRITICAL 对应。 */
    CRITICAL(5, "严重"),
    /** 高危：与 Severity.HIGH 对应。 */
    HIGH(4, "高危"),
    /** 中危：与 Severity.MEDIUM 对应。 */
    MEDIUM(3, "中危"),
    /** 低危：与 Severity.LOW 对应。 */
    LOW(2, "低危"),
    /** 信息：与 Severity.INFO 对应。 */
    INFO(1, "信息"),
    /**
     * 无风险 / 失败 / 未知：
     * <ul>
     *   <li>分析失败（{@link AnalysisResult#getError()} 非 null）；</li>
     *   <li>分析成功但 finding 列表为空；</li>
     *   <li>summary 为 null / 空白。</li>
     * </ul>
     */
    NONE(0, "—");

    /** 排序权重（越大越靠前）。 */
    public final int rank;

    /** 中文显示名（用于表格列）。 */
    public final String label;

    RiskLevel(int rank, String label) {
        this.rank = rank;
        this.label = label;
    }

    /**
     * UI 显示词在 i18n 资源里的 key。
     *
     * <p>{@link #label} 保留中文作为数据层的规范化显示名；表格/报告里需要跟随界面
     * 语言时，由 UI 层调用 {@code I18n.t(risk.displayKey())} 取词。</p>
     */
    public String displayKey() {
        return switch (this) {
            case CRITICAL -> "ui.level.critical";
            case HIGH -> "ui.level.high";
            case MEDIUM -> "ui.level.medium";
            case LOW -> "ui.level.low";
            case INFO -> "ui.level.info";
            case NONE -> "ui.level.none";
        };
    }

    /**
     * 从分析结果推导风险等级：取 findings 里最大 {@link Severity#rank}；
     * 失败 / findings 为空 / summary 为空时回退为 {@link #NONE}。
     *
     * @param result 一次完整分析的不可变结果对象；为 null 时直接返回 NONE。
     * @return 推导出的风险等级，永远非 null。
     */
    public static RiskLevel derive(AnalysisResult result) {
        if (result == null) {
            return NONE;
        }
        if (result.getError() != null) {
            // 分析失败：风险未定档为 NONE（UI 用"分析结论"列的失败描述 + "风险"列的"—"配合）
            return NONE;
        }
        String summary = result.getSummary();
        if (summary == null || summary.isBlank()) {
            return NONE;
        }
        List<Finding> findings = result.getFindings();
        if (findings == null || findings.isEmpty()) {
            return NONE;
        }
        int maxRank = 0;
        for (Finding finding : findings) {
            if (finding == null) {
                continue;
            }
            Severity severity = finding.getSeverity();
            if (severity != null && severity.rank > maxRank) {
                maxRank = severity.rank;
            }
        }
        return fromSeverityRank(maxRank);
    }

    /** 由 Severity.rank 数值（0-5）映射到 RiskLevel；越界回退为 NONE。 */
    private static RiskLevel fromSeverityRank(int rank) {
        return switch (rank) {
            case 5 -> CRITICAL;
            case 4 -> HIGH;
            case 3 -> MEDIUM;
            case 2 -> LOW;
            case 1 -> INFO;
            default -> NONE;
        };
    }
}
