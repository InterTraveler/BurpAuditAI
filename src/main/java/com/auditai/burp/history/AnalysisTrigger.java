package com.auditai.burp.history;

/**
 * 触发一次 AI 分析的来源。
 *
 * <p>用于"历史"页签的"分析类型"列：让用户一眼区分这条记录是手动点 Analyze 触发的
 * 还是被动流量分析自动触发的。</p>
 */
public enum AnalysisTrigger {

    /** 用户在分析页主动点 "Analyze" 按钮触发的分析。 */
    MANUAL("手动"),

    /** 被动流量分析（Proxy 流量经规则 + 指纹去重后自动触发的分析）。 */
    PASSIVE("被动");

    /** 中文显示名。 */
    public final String label;

    AnalysisTrigger(String label) {
        this.label = label;
    }

    /** UI 显示词在 i18n 资源里的 key（手动 / 被动，随界面语言取词）。 */
    public String displayKey() {
        return switch (this) {
            case MANUAL -> "ui.trigger.manual";
            case PASSIVE -> "ui.trigger.passive";
        };
    }
}
