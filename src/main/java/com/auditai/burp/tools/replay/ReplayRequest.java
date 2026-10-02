package com.auditai.burp.tools.replay;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * 模型在单次重放工具调用中提交的"要重放的请求"参数（不可变）。
 *
 * <p>对应 {@code replay.skill} 中描述的 {@code replay_request.arguments} 字段。</p>
 *
 * <p><b>协议设计（v3：按位置分类的参数替换）</b></p>
 *
 * <p>从 v3 开始，模型不再用单个扁平的 {@code replace_params}，而是按 HTTP 报文中
 * "参数所在的位置"分六个独立字段提交：</p>
 *
 * <pre>{@code
 * {
 *   "name": "replay_request",
 *   "arguments": {
 *     "reason": "闭合单引号",
 *     "replace_query_params":       { "id": "1'" },          // URL 上的 ?k=v 参数
 *     "replace_form_params":        { "username": "admin'" }, // application/x-www-form-urlencoded
 *     "replace_header_params":      { "X-User-Id": "admin" },// 请求头
 *     "replace_json_params":        { "user.id": "1'" },     // JSON body 字段（支持点号路径）
 *     "replace_path_params":        { "123": "1'" },         // URL 路径段（key = 段当前字面值）
 *     "replace_multipart_params":   { "file": "shell.php" }  // multipart/form-data 的 part（key=part name）
 *   }
 * }
 * }</pre>
 *
 * <p><b>为什么这样设计？</b></p>
 * <ul>
 *   <li><b>容错率高</b>：每个字段只在自己所属的位置查找，不再用"key 撞名 → 优先级兜底"
 *       的隐式约定。模型写错位置会立刻报错，而不是静默命中了一个不在预期位置的同名 key；</li>
 *   <li><b>意图清晰</b>：模型声明"我要改 query 上的 id" vs "我要改 header 里的 id" 是
 *       显式分开的，日志和审计也能直接看到"我到底改了哪几处、各自属于哪一类"；</li>
 *   <li><b>大小可控</b>：模型输出从"整段 HTTP 报文"降到"几个键值对"，节省 token；</li>
 *   <li><b>无引号边界问题</b>：键值都是普通 JSON 字符串，不再需要模型在 JSON 字符串里
 *       转义 HTTP 报文里的引号 / 反斜杠 / 控制字符（SQL 注入 payload 经常带这些）；</li>
 *   <li><b>编码/转义交给 Burp</b>：用 Montoya 的 {@code withParameter} / {@code withUpdatedHeader}
 *       改值，URL 编码、JSON 编码、Content-Length 重算等都让 Burp 自己处理，模型只负责
 *       "写值"——避免模型在 payload 里手动加 {@code %27} 之类容易出错。</li>
 * </ul>
 *
 * <p><b>查找规则</b>（在 {@code ReplayService} 实现）：</p>
 * <ol>
 *   <li>{@code replace_query_params} 的 key 只在 URL 参数（{@code HttpParameterType.URL}）中查；</li>
 *   <li>{@code replace_form_params} 的 key 只在 form body 参数（{@code HttpParameterType.BODY}）中查；</li>
 *   <li>{@code replace_header_params} 的 key 只在请求头中查（大小写不敏感）；</li>
 *   <li>{@code replace_json_params} 的 key 在 JSON body 参数（{@code HttpParameterType.JSON}）中查，
 *       支持点号路径（如 {@code user.id}）；</li>
 *   <li>{@code replace_path_params} 的 key = URL 路径中某一<b>段的当前字面值</b>
 *       （不限于最后一段，如 {@code /api/users/123} 可用 key {@code "users"} 或 {@code "123"}），
 *       该段整体替换为新值；支持单段路径（{@code /users}）；要求 URL 不含查询参数
 *       （"path-only" 场景），按字面比较、不做 URL 解码；</li>
 *   <li>{@code replace_multipart_params} 的 key 只在 {@code multipart/form-data} body 的 part
 *       里查（key=part 的 {@code Content-Disposition} 里的 name 属性）；请求不是 multipart
 *       → 该分类视为空、模型提交的 key 全部 notFound → 整体拒绝。</li>
 *   <li>任何 key 在自己所属位置找不到 → 整个重放拒绝，错误信息里明确指出"哪个分类的哪个 key 没找到"。</li>
 * </ol>
 *
 * <p>同位置多值参数（如 {@code ?id=1&id=2}）会全部替换为同一新值；如果只想改某一个，目前协议不支持——
 * 这在安全审计里也是罕见诉求。</p>
 */
public final class ReplayRequest {

    private final String reason;
    /** URL 上的 ?k=v 参数；key 只在 URL 参数里查。 */
    private final Map<String, String> queryParams;
    /** form body 参数（Content-Type: application/x-www-form-urlencoded）；key 只在 BODY 参数里查。 */
    private final Map<String, String> formParams;
    /** 请求头；key 在 headers 里查，大小写不敏感。 */
    private final Map<String, String> headerParams;
    /** JSON body 字段；key 在 JSON 参数里查，支持点号路径（user.id）。 */
    private final Map<String, String> jsonParams;
    /** URL 路径段；key = 某段当前的字面值（不限于最后一段），该段整体替换。空 Map 表示"不改 path"。 */
    private final Map<String, String> pathParams;
    /** multipart/form-data body 的 part；key=part 的 Content-Disposition.name。空 Map 表示"不改 multipart"。 */
    private final Map<String, String> multipartParams;

    private ReplayRequest(String reason,
                          Map<String, String> queryParams,
                          Map<String, String> formParams,
                          Map<String, String> headerParams,
                          Map<String, String> jsonParams,
                          Map<String, String> pathParams,
                          Map<String, String> multipartParams) {
        this.reason = reason;
        this.queryParams = queryParams;
        this.formParams = formParams;
        this.headerParams = headerParams;
        this.jsonParams = jsonParams;
        this.pathParams = pathParams;
        this.multipartParams = multipartParams;
    }

    /**
     * 模型"为什么这次重放，期望看到什么变化"的简短说明；可能为 {@code null} 或空。
     * 用于在最终审计记录里留痕——为什么模型当初决定再发一次。
     */
    public String reason() {
        return reason;
    }

    /** URL 上的 ?k=v 参数；key 只在 URL 参数里查。空 Map 表示"不改 query"。 */
    public Map<String, String> queryParams() {
        return queryParams;
    }

    /** form body 参数（application/x-www-form-urlencoded）；key 只在 BODY 参数里查。空 Map 表示"不改 form"。 */
    public Map<String, String> formParams() {
        return formParams;
    }

    /** 请求头；key 在 headers 里查，大小写不敏感。空 Map 表示"不改 header"。 */
    public Map<String, String> headerParams() {
        return headerParams;
    }

    /** JSON body 字段；key 在 JSON 参数里查，支持点号路径（user.id）。空 Map 表示"不改 json"。 */
    public Map<String, String> jsonParams() {
        return jsonParams;
    }

    /**
     * URL 路径段；key = 某段当前的字面值（不限于最后一段，支持单段路径），该段整体替换为新值。
     * 空 Map 表示"不改 path"。
     */
    public Map<String, String> pathParams() {
        return pathParams;
    }

    /**
     * multipart/form-data body 的 part 替换；key=part 的 {@code Content-Disposition} 里的
     * {@code name} 属性。原请求不是 multipart → 所有 key 都 notFound → 整体拒绝。
     * 空 Map 表示"不改 multipart"。
     */
    public Map<String, String> multipartParams() {
        return multipartParams;
    }

    /**
     * 是否有任何要替换的参数（用于判断"是否值得发"）。
     * 六个分类里只要有一个非空就算有。
     */
    public boolean hasReplacements() {
        return !queryParams.isEmpty() || !formParams.isEmpty()
                || !headerParams.isEmpty() || !jsonParams.isEmpty()
                || !pathParams.isEmpty() || !multipartParams.isEmpty();
    }

    public static Builder builder() {
        return new Builder();
    }

    /** 简单 builder：避免一堆多参构造器。 */
    public static final class Builder {
        private String reason;
        private Map<String, String> queryParams;
        private Map<String, String> formParams;
        private Map<String, String> headerParams;
        private Map<String, String> jsonParams;
        private Map<String, String> pathParams;
        private Map<String, String> multipartParams;

        public Builder reason(String reason) {
            this.reason = reason;
            return this;
        }

        public Builder queryParams(Map<String, String> queryParams) {
            this.queryParams = queryParams;
            return this;
        }

        public Builder formParams(Map<String, String> formParams) {
            this.formParams = formParams;
            return this;
        }

        public Builder headerParams(Map<String, String> headerParams) {
            this.headerParams = headerParams;
            return this;
        }

        public Builder jsonParams(Map<String, String> jsonParams) {
            this.jsonParams = jsonParams;
            return this;
        }

        public Builder pathParams(Map<String, String> pathParams) {
            this.pathParams = pathParams;
            return this;
        }

        public Builder multipartParams(Map<String, String> multipartParams) {
            this.multipartParams = multipartParams;
            return this;
        }

        public ReplayRequest build() {
            return new ReplayRequest(
                    reason,
                    immutable(queryParams),
                    immutable(formParams),
                    immutable(headerParams),
                    immutable(jsonParams),
                    immutable(pathParams),
                    immutable(multipartParams));
        }

        private static Map<String, String> immutable(Map<String, String> m) {
            return m == null ? Map.of()
                    : Collections.unmodifiableMap(new LinkedHashMap<>(m));
        }
    }

    /**
     * 一对"原值 → 新值"的描述，给用户/日志看用。不参与请求构造。
     */
    public record ParamChange(String key, String originalValue, String newValue,
                              String location) {
        public ParamChange {
            Objects.requireNonNull(key, "key");
            Objects.requireNonNull(location, "location");
        }

        /**
         * 简洁展示：用于 DEBUG 日志 / 摘要。
         *
         * <p>格式 {@code - location[ key ]: old → new}，每个改动一行。{@code [ ]} 把 location
         * 与 key 绑在一起，避免行尾括号歧义；{@code key} 只写一次，省 token。
         * 原值为 null 时显示 {@code (无)}——区分"原本就没有"和"原值是空串"。</p>
         */
        public String shortSummary() {
            return "- " + location + "[ " + key + " ]: "
                    + formatValue(originalValue) + " → " + formatValue(newValue);
        }

        /** null → {@code (无)}；超长截断；否则原样。 */
        private static String formatValue(String s) {
            if (s == null) {
                return "(无)";
            }
            if (s.length() <= 40) {
                return s;
            }
            return s.substring(0, 40) + "...";
        }
    }
}
