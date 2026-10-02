package com.auditai.burp.http;

import java.util.Locale;

/**
 * 问题严重程度等级。
 *
 * <p>排序权重：{@link #rank} 越大越严重。UI 上"问题列表"按 (severity 降序, confidence 降序)
 * 展示，让最值得关注的条目排在最前面。</p>
 */
public enum Severity {

    /** 严重：可直接被利用、影响核心数据 / 资产安全（如 RCE、SQL 注入、全账户接管）。 */
    CRITICAL(5, "严重"),
    /** 高危：在常规路径上可复现、影响范围较大（如越权读取敏感数据、SSRF 内网穿透）。 */
    HIGH(4, "高危"),
    /** 中危：受一定条件限制或影响有限（如特定输入下的 XSS、CSRF）。 */
    MEDIUM(3, "中危"),
    /** 低危：影响较小或复现成本高（如信息泄露、缺失安全头）。 */
    LOW(2, "低危"),
    /** 信息：仅作为可疑点 / 安全建议，并无直接危害。 */
    INFO(1, "信息");

    /** 排序权重（越大越靠前）。 */
    public final int rank;

    /** 中文显示名（用于表格列）。 */
    public final String label;

    Severity(int rank, String label) {
        this.rank = rank;
        this.label = label;
    }

    /**
     * UI 显示词在 i18n 资源里的 key。
     *
     * <p>{@link #label} 保留中文作为数据层的规范化显示名；需要跟随界面语言时，
     * 由 UI 层调用 {@code I18n.t(severity.displayKey())} 取词，避免枚举持有单一语言文案。</p>
     */
    public String displayKey() {
        return switch (this) {
            case CRITICAL -> "ui.level.critical";
            case HIGH -> "ui.level.high";
            case MEDIUM -> "ui.level.medium";
            case LOW -> "ui.level.low";
            case INFO -> "ui.level.info";
        };
    }

    /**
     * 解析模型返回的严重程度字符串（大小写、空格、常见别名都尽量容错）。
     *
     * @param text 模型原始 severity 字段；为空或无法识别时回退为 {@link #INFO}。
     * @return 对应严重程度枚举，永远非 null。
     */
    public static Severity parse(String text) {
        if (text == null) {
            return INFO;
        }
        String normalized = text.trim().toLowerCase(Locale.ROOT);
        if (normalized.isEmpty()) {
            return INFO;
        }
        // 常见中英文 / 简写
        return switch (normalized) {
            case "critical", "crit", "严重", "危急" -> CRITICAL;
            case "high", "高", "高危", "高级" -> HIGH;
            case "medium", "med", "moderate", "中", "中危", "中级" -> MEDIUM;
            case "low", "低", "低危", "低级" -> LOW;
            default -> INFO;
        };
    }
}
