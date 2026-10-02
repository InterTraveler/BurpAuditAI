package com.auditai.burp.tools.replay;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.auditai.burp.ai.PromptBuilder;
import com.auditai.burp.tools.Tool;
import com.auditai.burp.tools.ToolCall;
import com.auditai.burp.tools.ToolOutcome;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * "重放请求"工具的 {@link Tool} 适配器：把通用的工具调用协议翻译成具体的"重放"动作。
 *
 * <p>本类是"能力实现"的代表——它把"replay"这个常驻分析能力包装成标准 {@link Tool}
 * 接口，让 {@link com.auditai.burp.tools.ToolLoopOrchestrator} 通过
 * {@code Map<String, Tool>} 路由调用，无需知道"replay"的具体协议细节。</p>
 *
 * <p><b>v3 协议：按位置分类的参数替换</b></p>
 *
 * <p>模型在 {@code arguments} 里提交 6 类参数，每类一个 map：</p>
 * <pre>{@code
 * {
 *   "reason": "闭合单引号",
 *   "replace_query_params":       { "id": "1'" },          // URL 上的 ?k=v 参数
 *   "replace_form_params":        { "username": "admin'" }, // application/x-www-form-urlencoded
 *   "replace_header_params":      { "X-User-Id": "admin" },// 请求头
 *   "replace_json_params":        { "user.id": "1'" },     // JSON body 字段（支持点号路径）
 *   "replace_path_params":        { "123": "1'" },         // URL 路径段（key = 段当前字面值）
 *   "replace_multipart_params":   { "file": "shell.php" }  // multipart/form-data 的 part
 * }
 * }</pre>
 *
 * <p>本类负责：</p>
 * <ol>
 *   <li>把 JSON 反序列化成 {@link ReplayRequest}（6 个 map 各自解析）；</li>
 *   <li>调 {@link ReplayService#execute} 真实发送；</li>
 *   <li>用 {@link PromptBuilder#buildReplayResultUserPrompt} 把结果渲染成 user 段文本，
 *       并在末尾追加"key=old → key=new"diff——让模型下一轮能直接看到"我刚才到底改了哪几处"。</li>
 * </ol>
 *
 * <p><b>为什么需要这个适配层？</b>{@link ReplayService} 本身做的是"执行单次 HTTP 重放"，
 * 接受强类型 {@link ReplayRequest}；而 orchestrator 给到的是
 * {@link ToolCall}{@code (name, reason, argumentsJson)}，需要把 JSON 反序列化成
 * {@code ReplayRequest} 然后调 {@code ReplayService}。本类负责这道"协议转换"。</p>
 */
public final class ReplayTool implements Tool {

    /** 与提示词中"工具名"严格一致的标识——拼写错误会让模型发起的调用全部失败。 */
    public static final String NAME = "replay_request";

    private final PromptBuilder promptBuilder;
    /** 直接持有一个 ReplayService 实例——它负责"发 HTTP"这层，本类负责"参数解析 + 结果渲染"。 */
    private final ReplayService replayService;
    private final Gson gson = new Gson();

    /**
     * 完整构造器：注入 Montoya API、PromptBuilder（用于把响应渲染成 user 段文本）
     * 和原请求（用于锁定 host:port:scheme）。后两者仅用于初始化 {@link ReplayService}，
     * 本类自己不再持有——持有 {@code api}/{@code originalRequest} 既占内存又无意义。
     */
    public ReplayTool(MontoyaApi api, PromptBuilder promptBuilder, HttpRequest originalRequest) {
        this.promptBuilder = promptBuilder;
        this.replayService = new ReplayService(api, originalRequest);
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public ToolOutcome execute(ToolCall call) {
        if (!NAME.equals(call.toolName())) {
            return ToolOutcome.failure("内部错误：路由到 ReplayTool 但 toolName=" + call.toolName(),
                    "[重放失败] 工具路由错误：期望 " + NAME + "，实际 " + call.toolName());
        }
        // 1. 解析 arguments JSON
        ReplayRequest replayReq;
        try {
            JsonObject args = gson.fromJson(call.argumentsJson(), JsonObject.class);
            replayReq = parseArgs(args);
        } catch (JsonSyntaxException | IllegalArgumentException e) {
            return ToolOutcome.failure("参数解析失败：" + e.getMessage(),
                    "[重放失败] 参数解析失败：" + e.getMessage());
        }
        if (!replayReq.hasReplacements()) {
            return ToolOutcome.failure("6 类替换参数全部为空——必须至少填一个分类下的 key=value 才值得发请求",
                    "[重放失败] replace_query_params / replace_form_params / "
                            + "replace_header_params / replace_json_params / "
                            + "replace_path_params / replace_multipart_params "
                            + "至少要有一个非空");
        }
        // 2. 真正执行重放
        long t0 = System.currentTimeMillis();
        ReplayResult result = replayService.execute(replayReq);
        long elapsed = System.currentTimeMillis() - t0;
        // 3. 用 PromptBuilder 渲染成 user 段文本
        String callId = "rc-" + System.nanoTime();
        String fragment = promptBuilder.buildReplayResultUserPrompt(
                callId, result, summarizeRequest(replayReq, result), elapsed);
        return result.isSuccess() ? ToolOutcome.success(fragment)
                : ToolOutcome.failure(result.error(), fragment);
    }

    /**
     * 把 {@code arguments} JSON 解析为强类型 {@link ReplayRequest}。
     */
    private ReplayRequest parseArgs(JsonObject args) {
        if (args == null) {
            throw new IllegalArgumentException("arguments 是空");
        }
        String reason = optString(args, "reason");
        Map<String, String> queryParams    = parseStringMap(args, "replace_query_params");
        Map<String, String> formParams     = parseStringMap(args, "replace_form_params");
        Map<String, String> headerParams   = parseStringMap(args, "replace_header_params");
        Map<String, String> jsonParams     = parseStringMap(args, "replace_json_params");
        Map<String, String> pathParams     = parseStringMap(args, "replace_path_params");
        Map<String, String> multipartParams = parseStringMap(args, "replace_multipart_params");
        return ReplayRequest.builder()
                .reason(reason)
                .queryParams(queryParams)
                .formParams(formParams)
                .headerParams(headerParams)
                .jsonParams(jsonParams)
                .pathParams(pathParams)
                .multipartParams(multipartParams)
                .build();
    }

    /**
     * 解析 6 类参数中的任一类（{@code replace_query_params} / {@code replace_form_params} /
     * {@code replace_header_params} / {@code replace_json_params} / {@code replace_path_params} /
     * {@code replace_multipart_params}）。
     *
     * <p>必须是"对象"形式（{@code {"k":"v", ...}}）；缺失或非对象都视为空 Map
     * （由 {@link #execute} 后续判"空"报错）。value 强制转 String——避免模型写
     * 数字 / 布尔 / 数组 时被默默接受、产生歧义。</p>
     */
    private static Map<String, String> parseStringMap(JsonObject args, String fieldName) {
        if (args == null || !args.has(fieldName) || args.get(fieldName).isJsonNull()) {
            return Map.of();
        }
        if (!args.get(fieldName).isJsonObject()) {
            throw new IllegalArgumentException(
                    fieldName + " 必须是 JSON 对象 {key:value}，实际类型：" + args.get(fieldName));
        }
        JsonObject obj = args.getAsJsonObject(fieldName);
        Map<String, String> map = new LinkedHashMap<>();
        for (var entry : obj.entrySet()) {
            String k = entry.getKey();
            var v = entry.getValue();
            if (v == null || v.isJsonNull()) {
                map.put(k, "");
            } else if (v.isJsonPrimitive()) {
                map.put(k, v.getAsString());
            } else {
                // 对象/数组 → 不接受（避免把 "nested" JSON 塞进 header）
                throw new IllegalArgumentException(
                        fieldName + "." + k + " 必须是字符串，实际：" + v);
            }
        }
        return map;
    }

    /**
     * 读一个可选字符串字段：非原始值（对象/数组）返回 null 而不是抛异常。
     *
     * <p>{@code JsonObject#getAsString()} 对对象/数组会抛 {@link UnsupportedOperationException}，
     * 而 {@link Tool#execute} 的契约是"绝对不能抛异常"——模型把 {@code "reason"} 写成对象时
     * 必须降级成"无 reason"，不能让整轮工具循环崩掉。</p>
     */
    private static String optString(JsonObject obj, String key) {
        if (obj == null || !obj.has(key) || obj.get(key).isJsonNull()
                || !obj.get(key).isJsonPrimitive()) {
            return null;
        }
        return obj.get(key).getAsString();
    }

    /**
     * 给 user 段用的小摘要：本次重放改了哪几个 key、每个 key 的位置和原值→新值。
     *
     * <p>没有 changes（空 Map 重发或失败前没改）时，回退到 reason。</p>
     */
    private static String summarizeRequest(ReplayRequest req, ReplayResult result) {
        List<ReplayRequest.ParamChange> changes = result.changesOrEmpty();
        if (changes.isEmpty()) {
            // 失败且没有已应用的改动 → 显示 reason 让模型知道"我刚才想干嘛"
            return req.reason() != null ? req.reason() : "（无 reason）";
        }
        StringBuilder sb = new StringBuilder(128);
        for (int i = 0; i < changes.size(); i++) {
            if (i > 0) sb.append('\n');
            sb.append(changes.get(i).shortSummary());
        }
        return sb.toString();
    }

    // —— 故意不暴露 ReplayService，避免本类与"实际发送 HTTP"的职责耦合 ——
}
