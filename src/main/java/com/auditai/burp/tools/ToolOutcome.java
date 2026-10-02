package com.auditai.burp.tools;

import java.util.Objects;

/**
 * 一次工具调用的执行结果（不可变）。
 *
 * <p>两条来源：</p>
 * <ul>
 *   <li><b>成功</b>：构造时传非空 {@link #userPromptFragment}；{@link #error} 为 {@code null}；</li>
 *   <li><b>失败</b>：构造时传非空 {@link #error}；{@link #userPromptFragment} 是给模型看的
 *       "工具调用失败说明"占位文本（让模型能看到失败原因决定下一步是重试还是收尾）。</li>
 * </ul>
 *
 * <p>{@link #userPromptFragment} 是 orchestrator 直接追加到 user 段的"原始片段"——
 * 工具实现负责按统一格式渲染（含脱敏、截断、占位符等），orchestrator 不做二次加工。
 * 这与 OpenAI Function Calling 里"tool result 是一段 message string"的设计一致。</p>
 *
 * @param success             是否执行成功
 * @param userPromptFragment  成功：要回填给模型的描述；失败：给模型的失败说明
 * @param error               错误描述（成功时为 null）；用于日志 / UI / 测试断言
 */
public record ToolOutcome(boolean success, String userPromptFragment, String error) {

    public ToolOutcome {
        Objects.requireNonNull(userPromptFragment, "userPromptFragment");
        if (success && error != null) {
            throw new IllegalArgumentException("成功时 error 必须为 null");
        }
        if (!success && (error == null || error.isEmpty())) {
            throw new IllegalArgumentException("失败时 error 必须非空");
        }
    }

    /**
     * 成功结果：含回填到 user 段的描述。
     */
    public static ToolOutcome success(String userPromptFragment) {
        return new ToolOutcome(true, userPromptFragment, null);
    }

    /**
     * 失败结果：含错误描述 + 给模型看的失败说明。
     */
    public static ToolOutcome failure(String error, String userPromptFragment) {
        return new ToolOutcome(false, Objects.requireNonNull(userPromptFragment, "userPromptFragment"),
                Objects.requireNonNull(error, "error"));
    }
}
