package com.auditai.burp.tools;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * 把模型在最终 JSON 里输出的 {@code tool_calls} 数组解析成强类型
 * {@link ToolCall} 列表（不可变）。
 *
 * <p>输出协议（与各工具的提示词描述对齐）：</p>
 * <pre>
 * {
 *   "analysis": "...",                  // 可选，模型当前对最终结论的"中间草稿"
 *   "tool_calls": [                     // 可选，0 ~ N 个工具调用
 *     {
 *       "name": "&lt;tool-name&gt;",         // 必填，必须与 Tool#name() 一致
 *       "arguments": {                  // 必填，工具私有 JSON schema
 *         "reason": "...",              // 可选
 *         // 其它字段由各 Tool 自己定义
 *       }
 *     }
 *   ]
 * }
 * </pre>
 *
 * <p>本解析器是<b>宽容</b>的：模型输出带 markdown 代码块、夹杂前后空白、单引号误用等
 * 都能兜底；只在完全没有合法 JSON 时才返回 empty。详见同款思路的
 * {@code AnalysisResponseParser#tryParseObject}。</p>
 */
public final class ToolCallParser {

    private ToolCallParser() {
    }

    /**
     * 模型"中间 analysis 草稿"字段的兜底字段名（按优先级排列）。
     *
     * <p>与 {@code AnalysisResponseParser.ANALYSIS_FALLBACK_KEYS} 对齐：兼容推理模型
     * （o1 / o3 / DeepSeek-R1 / Gemini Thinking 等）习惯用
     * {@code {"thoughts": "...", "response": "..."}} 表达"思考 + 回答"，
     * 而不是协议字段 {@code analysis}。</p>
     */
    private static final List<String> ANALYSIS_FALLBACK_KEYS =
            List.of("response", "text", "content", "output");

    /**
     * 解析模型原始输出，抽出 {@code tool_calls} 数组里所有合法项。
     *
     * <p>返回的 {@link Parsed} 携带：</p>
     * <ul>
     *   <li>{@link Parsed#toolCalls}：解析出的 {@link ToolCall} 列表；</li>
     *   <li>{@link Parsed#analysis}：模型同步输出的"中间分析草稿"（可能为 null），用于
     *       多轮上下文拼接时展示"模型此时在想什么"；</li>
     *   <li>{@link Parsed#errors}：解析过程中的非致命错误（缺 name / arguments 不是对象等），
     *       由调用方决定是降级还是写入日志。</li>
     * </ul>
     *
     * <p>本方法不抛异常——模型返回的脏数据应被尽可能兜底处理。</p>
     */
    public static Parsed parse(String rawModelOutput) {
        if (rawModelOutput == null || rawModelOutput.isBlank()) {
            return new Parsed(List.of(), null, List.of("模型输出为空"));
        }
        JsonObject root;
        try {
            Optional<JsonObject> parsed = tryParseObject(rawModelOutput);
            if (parsed.isEmpty()) {
                return new Parsed(List.of(), null, List.of("无法解析为 JSON 对象"));
            }
            root = parsed.get();
        } catch (RuntimeException e) {
            return new Parsed(List.of(), null, List.of("JSON 解析异常：" + e.getMessage()));
        }
        String analysis = readAnalysisField(root);
        List<String> errors = new ArrayList<>();
        List<ToolCall> toolCalls = new ArrayList<>();
        if (!root.has("tool_calls") || root.get("tool_calls").isJsonNull()) {
            return new Parsed(toolCalls, analysis, errors);
        }
        JsonElement tcEl = root.get("tool_calls");
        if (!tcEl.isJsonArray()) {
            errors.add("tool_calls 不是数组，已忽略");
            return new Parsed(toolCalls, analysis, errors);
        }
        JsonArray array = tcEl.getAsJsonArray();
        for (int i = 0; i < array.size(); i++) {
            JsonElement item = array.get(i);
            if (item == null || item.isJsonNull() || !item.isJsonObject()) {
                errors.add("tool_calls[" + i + "] 不是对象，已跳过");
                continue;
            }
            JsonObject call = item.getAsJsonObject();
            // 必须用 readString（判 isJsonPrimitive）：模型写 "name": {...} / [...] 时
            // JsonObject#getAsString() 会抛 UnsupportedOperationException，一路冒到
            // ToolLoopOrchestrator 把整轮分析打断——违反本方法"不抛异常"的契约。
            String name = readString(call, "name");
            if (name == null || name.isEmpty()) {
                errors.add("tool_calls[" + i + "] 缺少 name，已跳过");
                continue;
            }
            if (!call.has("arguments") || call.get("arguments").isJsonNull()
                    || !call.get("arguments").isJsonObject()) {
                errors.add("tool_calls[" + i + "] 缺 arguments 对象，已跳过");
                continue;
            }
            JsonObject args = call.get("arguments").getAsJsonObject();
            String reason = readString(args, "reason");
            // 把 arguments 原样作为 JSON 字符串传给工具——工具实现自己解析。
            String argumentsJson = args.toString();
            toolCalls.add(new ToolCall(name, reason, argumentsJson));
        }
        return new Parsed(List.copyOf(toolCalls), analysis, List.copyOf(errors));
    }

    /**
     * 与 {@code AnalysisResponseParser} 同款的"宽容 JSON 对象解析"：去掉 markdown 围栏、
     * 截取首尾花括号、喂给 gson。
     */
    private static Optional<JsonObject> tryParseObject(String raw) {
        String trimmed = raw.trim();
        // 去掉 ```json ... ``` 围栏
        if (trimmed.startsWith("```")) {
            int firstNewline = trimmed.indexOf('\n');
            if (firstNewline > 0) {
                trimmed = trimmed.substring(firstNewline + 1);
            }
            if (trimmed.endsWith("```")) {
                trimmed = trimmed.substring(0, trimmed.length() - 3);
            }
            trimmed = trimmed.trim();
        }
        // 截取顶层 { ... }（容错：模型在 JSON 前后偶尔带解释文本）
        int firstBrace = trimmed.indexOf('{');
        int lastBrace = trimmed.lastIndexOf('}');
        if (firstBrace < 0 || lastBrace <= firstBrace) {
            return Optional.empty();
        }
        String candidate = trimmed.substring(firstBrace, lastBrace + 1);
        try {
            JsonElement el = JsonParser.parseString(candidate);
            if (el != null && el.isJsonObject()) {
                return Optional.of(el.getAsJsonObject());
            }
        } catch (RuntimeException ignored) {
            // 解析失败 → 视为"无 JSON"
        }
        return Optional.empty();
    }

    /**
     * 从 JSON 对象里按"analysis → response → text → content → output"的优先级
     * 取一个非空字符串字段。返回 null 表示没有任何字段可用。
     */
    private static String readAnalysisField(JsonObject obj) {
        if (obj == null) {
            return null;
        }
        JsonElement primary = obj.get("analysis");
        String value = readNonBlankString(primary);
        if (value != null) {
            return value;
        }
        for (String key : ANALYSIS_FALLBACK_KEYS) {
            String candidate = readNonBlankString(obj.get(key));
            if (candidate != null) {
                return candidate;
            }
        }
        return null;
    }

    /** 读 JSON 元素的非空字符串值。非字符串 / null / 空白字符串都返回 null。 */
    private static String readNonBlankString(JsonElement elem) {
        if (elem == null || elem.isJsonNull() || !elem.isJsonPrimitive()) {
            return null;
        }
        String value = elem.getAsString();
        if (value == null || value.isBlank()) {
            return null;
        }
        return value;
    }

    /**
     * 读 JSON 对象的字符串字段：只接受 JSON 原始值（字符串/数字/布尔），
     * 对象、数组、null 一律返回 null。
     *
     * <p>{@code JsonObject#getAsString()} 对非原始值会抛 {@link UnsupportedOperationException}，
     * 因此本方法必须做类型判定——这是"脏数据不抛异常"契约的实现细节。</p>
     */
    private static String readString(JsonObject obj, String key) {
        JsonElement elem = obj.get(key);
        if (elem == null || elem.isJsonNull() || !elem.isJsonPrimitive()) {
            return null;
        }
        return elem.getAsString();
    }

    /**
     * 解析结果：模型一轮输出里所有可执行的工具调用 + 中间 analysis 草稿 + 错误列表。
     */
    public record Parsed(List<ToolCall> toolCalls, String analysis, List<String> errors) {
        public Parsed {
            Objects.requireNonNull(toolCalls, "toolCalls");
            Objects.requireNonNull(errors, "errors");
        }

        /** 是否包含至少一个可执行工具调用。 */
        public boolean hasToolCalls() {
            return !toolCalls.isEmpty();
        }

        public boolean isEmpty() {
            return toolCalls.isEmpty() && (analysis == null || analysis.isEmpty());
        }
    }
}
