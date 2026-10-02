package com.auditai.burp.tools;

import java.util.Objects;

/**
 * 一次工具调用的不可变快照：模型在 JSON {@code tool_calls} 数组里的某一项。
 *
 * <p>设计成"只承载 name + arguments JSON + reason"——具体参数结构由各
 * {@link Tool} 实现自己解析，orchestrator 不关心（避免"通用调度器"被
 * 各工具的私有协议绑架）。</p>
 *
 * @param toolName 模型写的工具名（与 {@link Tool#name()} 完全一致）
 * @param reason   模型给的"为什么要调用"说明；可空
 * @param argumentsJson 模型提交的参数原文 JSON；orchestrator 不会解析它
 */
public record ToolCall(String toolName, String reason, String argumentsJson) {

    public ToolCall {
        Objects.requireNonNull(toolName, "toolName");
        // reason / argumentsJson 允许为空
    }
}
