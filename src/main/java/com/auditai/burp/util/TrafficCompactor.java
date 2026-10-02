package com.auditai.burp.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Burp 报文极致压缩器：把请求/响应压缩为适合批量喂给大模型的极简文本。
 *
 * <p>与 {@link TextUtil} 的定位差异：</p>
 * <ul>
 *   <li>{@code TextUtil} 服务"单报文 + 可读"（供 {@code PromptBuilder} 做单次分析），保留头名+少量值；</li>
 *   <li>{@code TrafficCompactor} 服务"批量报文 + 极致压缩"（上下文紧张时同时塞多条记录），
 *       非敏感头 value 仅保留前 5 字符，JSON 进一步裁剪到 key/value/数组/深度多维度阈值。</li>
 * </ul>
 *
 * <p><b>共享复用：</b>敏感头判定直接复用 {@link TextUtil#isSensitiveHeader(String)}，
 * 二进制嗅探直接复用 {@link TextUtil#isLikelyBinary(byte[])}，
 * 避免策略在两处独立维护导致漂移。</p>
 *
 * <p><b>设计原则：</b></p>
 * <ul>
 *   <li>解析失败一律回退到"截断纯文本"路径，单条坏数据不能拖垮整批；</li>
 *   <li>JSON 重新序列化时关闭 HTML 转义（{@code disableHtmlEscaping}），
 *       避免 {@code =}、{@code <}、{@code >} 被转成 {@code \u003d} 等冗长形式；</li>
 *   <li>嵌套深度硬上限，防止恶意超深 JSON 爆栈；</li>
 *   <li>输出整体走"两行缩进 + 段落分隔"风格，模型解析时结构清晰。</li>
 * </ul>
 */
public final class TrafficCompactor {

    // ============================ 阈值常量（极致压缩档） ============================

    /** 非敏感头 value 保留的前缀字符数。 */
    static final int HEADER_VALUE_KEEP_CHARS = 5;

    /** JSON 中单个 key / value 字符串最大字符数。超长截断并附标记。 */
    static final int MAX_JSON_STRING_CHARS = 20;

    /** JSON 对象最多保留的键数量。超出的键以"省略"占位符表示。 */
    static final int MAX_JSON_OBJECT_KEYS = 6;

    /** JSON 数组最多保留的元素数量。超出的元素以"省略"占位符表示。 */
    static final int MAX_JSON_ARRAY_ITEMS = 8;

    /**
     * JSON 嵌套深度上限（最外层为 0）。
     * 达到上限的对象/数组统一用 {@code {...}} / {@code [...]} 占位，不再递归。
     * 设置很小（如 2）是为了对付"深层嵌套攻击 payload"导致模型上下文爆掉。
     */
    static final int MAX_JSON_DEPTH = 2;

    /** 整个 JSON 序列化后体积硬上限（字节）。 */
    static final int MAX_JSON_OUTPUT_BYTES = 2 * 1024;

    /** 非 JSON / 非二进制的纯文本 body 截断阈值（字符数）。 */
    static final int MAX_OTHER_BODY_CHARS = 50;

    // ============================ 输出占位文本 ============================

    /** 敏感头 value 脱敏后的占位。 */
    private static final String REDACTED_PLACEHOLDER = "（已脱敏）";

    /** 二进制 body 占位（参数：原始字节数）。 */
    private static final String BINARY_PLACEHOLDER_FMT = "（二进制内容已省略，%d 字节）";

    /** JSON key 字符串超长截断后追加。 */
    private static final String JSON_KEY_TRUNCATED_SUFFIX = "...";

    /** JSON value 字符串超长截断后追加。 */
    private static final String JSON_VALUE_TRUNCATED_SUFFIX = "...（已截断）";

    /** 数组 / 对象元素超出上限时的占位（参数：原始总元素数）。 */
    private static final String JSON_ITEMS_TRUNCATED_FMT = "（后面内容已省略，共 %d 元素）";

    /** JSON 整体超体积上限的占位（参数：原始字节数）。 */
    private static final String JSON_OUTPUT_BYTES_TRUNCATED_FMT = "...（JSON 整体超 %d 字节上限已截断）";

    /** 非 JSON 纯文本 body 截断占位（参数：原始字符数）。 */
    private static final String OTHER_TRUNCATED_FMT = "...（后面内容已省略，共 %d 字符）";

    /** 空 body 占位。 */
    private static final String EMPTY_BODY_PLACEHOLDER = "（空）";

    // ============================ 共享实例 ============================

    /**
     * 紧凑、无 HTML 转义的 Gson：避免 {@code =}/{@code <}/{@code >} 等被转义成
     * {@code \u003d} 这类冗长 Unicode 形式（占 token 还没可读性）。
     */
    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();

    private TrafficCompactor() {
    }

    // ============================ 公共入口 ============================

    /**
     * 底层入口：按 content-type 自适应处理字节 body，供单元测试与非 Montoya 场景复用。
     *
     * @param body        原始 body 字节（可为 null/空）。
     * @param contentType 对应的 Content-Type 头值（可为 null）。
     * @return 压缩后的可读字符串。
     */
    public static String compactBody(byte[] body, String contentType) {
        if (body == null || body.length == 0) {
            return EMPTY_BODY_PLACEHOLDER;
        }
        if (TextUtil.isLikelyBinary(body)) {
            return BINARY_PLACEHOLDER_FMT.formatted(body.length);
        }
        String text = new String(body, StandardCharsets.UTF_8);
        if (looksLikeJson(contentType, text)) {
            return compactJsonString(text);
        }
        return truncateOther(text);
    }

    /**
     * 压缩"完整 HTTP 请求"原始字节（含请求行 + headers + 可选 body）。
     *
     * <p>用途：不依赖 Montoya 的"完整报文 → 极致压缩"入口——调用方持有可能来自磁盘 /
     * 网络抓包的纯字节（典型场景：{@code ProxyTrafficStore.StoredTraffic#readRequest()}），
     * 由本方法自行解析请求行、headers、body，再走统一的"极致压缩"策略。</p>
     *
     * <p>输出格式：
     * <pre>
     * 【请求】METHOD URL
     *   Header-Name: value（前 5 字符；敏感头显示"（已脱敏）"）
     *   [Body N 字节]
     *   {compactBody 输出}
     * </pre>
     *
     * @param rawRequest 完整 HTTP 请求字节（可为 null/空；为 null/空时返回空串）。
     * @return 压缩后的可读字符串。
     */
    public static String compactRawRequest(byte[] rawRequest) {
        if (rawRequest == null || rawRequest.length == 0) {
            return "";
        }
        return compactRawMessage(rawRequest, true);
    }

    /**
     * 压缩"完整 HTTP 响应"原始字节（含状态行 + headers + 可选 body）。
     *
     * <p>解析策略、压缩策略、输出格式与请求版本完全对齐——把首行视为
     * {@code HTTP/1.1 STATUS REASON} 拆出 STATUS 单独展示。</p>
     *
     * @param rawResponse 完整 HTTP 响应字节（可为 null/空；为 null/空时返回空串）。
     * @return 压缩后的可读字符串。
     */
    public static String compactRawResponse(byte[] rawResponse) {
        if (rawResponse == null || rawResponse.length == 0) {
            return "";
        }
        return compactRawMessage(rawResponse, false);
    }

    /**
     * 压缩"完整 HTTP 请求 + 响应"原始字节对：多报文协同分析（多报文摘要）
     * 的核心入口。任一为空时输出对应占位提示，仍保持输出结构稳定。
     *
     * <p>典型调用方：{@code TrafficAnalyzer} 在同域历史摘要阶段，遍历
     * {@code ProxyTrafficStore} 取到的多条历史记录，逐一调用本方法把每条
     * 历史的"完整请求 + 响应"压缩为"几百字节级别的可读摘要"，再拼到
     * 阶段 2 的 user 段里供模型参考。</p>
     */
    public static String compactRawPair(byte[] rawRequest, byte[] rawResponse) {
        StringBuilder sb = new StringBuilder(1024);
        if (rawRequest == null || rawRequest.length == 0) {
            sb.append("【请求】（无原始请求字节）\n");
        } else {
            sb.append(compactRawRequest(rawRequest));
        }
        sb.append('\n');
        if (rawResponse == null || rawResponse.length == 0) {
            sb.append("【响应】（暂无响应）\n");
        } else {
            sb.append(compactRawResponse(rawResponse));
        }
        return sb.toString();
    }

    /**
     * 共享入口：把整段原始 HTTP 字节按"首行 / headers / body"切分后压缩。
     * 请求与响应共用，仅首行渲染策略不同。
     */
    private static String compactRawMessage(byte[] raw, boolean isRequest) {
        // 1. 找 \r\n\r\n 或 \n\n 分隔 headers / body；返回值包含"分隔符实际占用的字节数"，
        //    避免把 \n\n 当成 \r\n\r\n 跳 4 字节导致 body 起始位置错位（少读 2 字节）
        int[] sep = findHeaderBodySeparator(raw);
        byte[] headerBlock;
        byte[] bodyBytes;
        if (sep[0] < 0) {
            headerBlock = raw;
            bodyBytes = new byte[0];
        } else {
            headerBlock = Arrays.copyOfRange(raw, 0, sep[0]);
            bodyBytes = Arrays.copyOfRange(raw, sep[0] + sep[1], raw.length);
        }
        // 2. 把 header 块按行切（兼容 \r\n 与 \n）；首行是 status line / request line
        String headerText = new String(headerBlock, StandardCharsets.UTF_8);
        String[] lines = headerText.split("\\r?\\n");
        if (lines.length == 0 || (lines.length == 1 && lines[0].isEmpty())) {
            return "（空）";
        }
        StringBuilder sb = new StringBuilder(headerBlock.length + 64);
        // 3. 首行：请求行 / 状态行
        String firstLine = lines[0];
        if (isRequest) {
            String method = firstPart(firstLine);
            String url = secondPart(firstLine);
            sb.append("【请求】").append(method).append(' ').append(url).append('\n');
        } else {
            int status = parseStatusCode(firstLine);
            sb.append("【响应 ").append(status).append("】\n");
        }
        // 4. headers + 沿途抓取 Content-Type
        String contentType = null;
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            if (line.isEmpty()) {
                continue;
            }
            int colon = line.indexOf(':');
            if (colon < 0) {
                // 无 ":" 的畸形行：当作 continuation / 异常行，跳过避免抛错
                continue;
            }
            String name = line.substring(0, colon).trim();
            String value = line.substring(colon + 1).trim();
            sb.append("  ").append(formatHeaderLine(name, value)).append('\n');
            // HTTP header 名按 RFC 7230 是 ASCII 不区分大小写,用 Locale.ROOT 比对
            // 避免土耳其语 locale 把 "I"/"İ" 当成同字母
            if (contentType == null && "content-type".equals(name.toLowerCase(java.util.Locale.ROOT))) {
                contentType = value;
            }
        }
        // 5. body：复用 appendBodySection 的格式契约
        appendBodySection(sb, bodyBytes, contentType);
        return sb.toString();
    }

    /**
     * 在整段原始 HTTP 字节中寻找 header / body 分隔符：优先 {@code \r\n\r\n}，
     * 兜底 {@code \n\n}。返回 {@code int[2]}：
     * <ul>
     *   <li>{@code [0]} = 分隔符起始位置（-1 表示未找到）；</li>
     *   <li>{@code [1]} = 分隔符自身占用的字节数（{@code \r\n\r\n}=4，{@code \n\n}=2），
     *       配合 {@code [0]} 即可算出 body 起始位置（{@code [0]+[1]}），
     *       避免把两种分隔符都按 4 字节跳导致 {@code \n\n} 时多丢 2 字节 body。</li>
     * </ul>
     */
    private static int[] findHeaderBodySeparator(byte[] raw) {
        int crlfCrlf = -1;
        for (int i = 0; i <= raw.length - 4; i++) {
            if (raw[i] == '\r' && raw[i + 1] == '\n' && raw[i + 2] == '\r' && raw[i + 3] == '\n') {
                crlfCrlf = i;
                break;
            }
        }
        int lfLf = -1;
        for (int i = 0; i <= raw.length - 2; i++) {
            if (raw[i] == '\n' && raw[i + 1] == '\n') {
                lfLf = i;
                break;
            }
        }
        // 取"最早出现"的那个空行：HTTP 头部在第一个空行处结束。
        // 不能像历史实现那样"先全局搜 \r\n\r\n、找不到再兜底 \n\n"——若头部以 \n\n 结束
        // 而 body 内部含 \r\n\r\n（二进制 / 多段文本 body 很常见），就会命中 body 里的分隔符，
        // 导致 headerBlock 混入 body 前缀、body 起点整体错位。
        if (crlfCrlf >= 0 && (lfLf < 0 || crlfCrlf < lfLf)) {
            return new int[]{crlfCrlf, 4};
        }
        if (lfLf >= 0) {
            return new int[]{lfLf, 2};
        }
        return new int[]{-1, 0};
    }

    /**
     * 从 "GET /x HTTP/1.1" 这种首行取第一个空格分隔段；没有空格时返回整行。
     */
    private static String firstPart(String line) {
        int idx = line.indexOf(' ');
        return idx < 0 ? line : line.substring(0, idx);
    }

    /**
     * 从 "GET /x HTTP/1.1" 这种首行取第二个空格分隔段；没有时返回空串。
     */
    private static String secondPart(String line) {
        int first = line.indexOf(' ');
        if (first < 0) {
            return "";
        }
        int second = line.indexOf(' ', first + 1);
        if (second < 0) {
            return "";
        }
        return line.substring(first + 1, second);
    }

    /**
     * 从 "HTTP/1.1 200 OK" 状态行里解析 status code；解析失败返回 -1。
     */
    private static int parseStatusCode(String statusLine) {
        int first = statusLine.indexOf(' ');
        if (first < 0) {
            return -1;
        }
        int second = statusLine.indexOf(' ', first + 1);
        String token = second < 0
                ? statusLine.substring(first + 1)
                : statusLine.substring(first + 1, second);
        try {
            return Integer.parseInt(token.trim());
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    // ============================ 内部：报文拼接 ============================

    /**
     * 共享逻辑：拼接 body 段落（带字节数说明 + 调用 {@link #compactBody}）。
     */
    private static void appendBodySection(StringBuilder sb, byte[] body, String contentType) {
        if (body == null || body.length == 0) {
            return;
        }
        sb.append("\n  [Body ").append(body.length).append(" 字节]\n  ")
          .append(compactBody(body, contentType)).append('\n');
    }

    // ============================ 内部：header 格式化 ============================

    /**
     * 单行 header 格式化：敏感头脱敏；普通头保留前 5 字符 + 省略号。
     * package-private 便于单元测试直接覆盖。
     */
    static String formatHeaderLine(String name, String value) {
        String safeName = (name == null) ? "" : name;
        String safeValue = (value == null) ? "" : value;
        if (TextUtil.isSensitiveHeader(safeName)) {
            return safeName + ": " + REDACTED_PLACEHOLDER;
        }
        return safeName + ": " + truncateString(safeValue, HEADER_VALUE_KEEP_CHARS, "...");
    }

    // ============================ 内部：JSON 判定 & 解析 ============================

    /**
     * 判定 body 是否走 JSON 分支。优先看 Content-Type，再兜底看首字符。
     */
    static boolean looksLikeJson(String contentType, String body) {
        if (contentType != null) {
            String lower = contentType.toLowerCase(Locale.ROOT);
            // 覆盖 application/json、application/vnd.api+json 等 "+json" 后缀
            if (lower.contains("json")) {
                return true;
            }
        }
        if (body == null) {
            return false;
        }
        String trimmed = body.trim();
        return !trimmed.isEmpty() && (trimmed.charAt(0) == '{' || trimmed.charAt(0) == '[');
    }

    /**
     * 把 JSON 字符串解析为树、裁剪、再紧凑序列化。解析失败回退到纯文本截断。
     */
    static String compactJsonString(String text) {
        try {
            JsonElement root = JsonParser.parseString(text);
            String serialized = compactJsonElement(root, 0);
            return capJsonOutputBytes(serialized);
        } catch (Exception e) {
            // 解析失败：当作普通文本处理，避免整批流程被一条坏数据拖死
            return truncateOther(text);
        }
    }

    /**
     * 整体 JSON 序列化后字节数硬上限：超了就按字节截断并附占位说明。
     */
    private static String capJsonOutputBytes(String serialized) {
        byte[] bytes = serialized.getBytes(StandardCharsets.UTF_8);
        if (bytes.length <= MAX_JSON_OUTPUT_BYTES) {
            return serialized;
        }
        // 按字节截断要小心不要切到 UTF-8 多字节字符中间 —— 倒退到上一个 ASCII 边界即可
        int cut = MAX_JSON_OUTPUT_BYTES;
        while (cut > 0 && (bytes[cut] & 0xC0) == 0x80) {
            cut--;
        }
        return new String(bytes, 0, cut, StandardCharsets.UTF_8)
                + JSON_OUTPUT_BYTES_TRUNCATED_FMT.formatted(bytes.length);
    }

    // ============================ 内部：JSON 树形裁剪 ============================

    /**
     * 递归裁剪任意 JSON 元素。{@code depth} 表示当前节点所在层级（最外层 0）。
     * package-private 便于单元测试直接覆盖。
     */
    static String compactJsonElement(JsonElement el, int depth) {
        if (el == null || el.isJsonNull()) {
            return "null";
        }
        // 深度上限：达到后对象/数组用紧凑占位，primitive 原样返回
        if (depth >= MAX_JSON_DEPTH) {
            if (el.isJsonObject()) {
                return "{...}";
            }
            if (el.isJsonArray()) {
                return "[...]";
            }
            return renderPrimitive(el);
        }
        if (el.isJsonObject()) {
            return compactJsonObject(el.getAsJsonObject(), depth);
        }
        if (el.isJsonArray()) {
            return compactJsonArray(el.getAsJsonArray(), depth);
        }
        return renderPrimitive(el);
    }

    private static String compactJsonObject(JsonObject obj, int depth) {
        List<Map.Entry<String, JsonElement>> entries = new ArrayList<>(obj.entrySet());
        boolean truncated = entries.size() > MAX_JSON_OBJECT_KEYS;
        int keep = Math.min(entries.size(), MAX_JSON_OBJECT_KEYS);

        StringBuilder sb = new StringBuilder(entries.size() * 16 + 16);
        sb.append('{');
        for (int i = 0; i < keep; i++) {
            Map.Entry<String, JsonElement> e = entries.get(i);
            if (i > 0) {
                sb.append(',');
            }
            sb.append(compactJsonKey(e.getKey())).append(':');
            sb.append(compactJsonValue(e.getValue(), depth + 1));
        }
        if (truncated) {
            sb.append(',').append(JSON_ITEMS_TRUNCATED_FMT.formatted(entries.size()));
        }
        sb.append('}');
        return sb.toString();
    }

    private static String compactJsonArray(JsonArray arr, int depth) {
        int size = arr.size();
        boolean truncated = size > MAX_JSON_ARRAY_ITEMS;
        int keep = Math.min(size, MAX_JSON_ARRAY_ITEMS);

        StringBuilder sb = new StringBuilder(size * 8 + 8);
        sb.append('[');
        for (int i = 0; i < keep; i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(compactJsonValue(arr.get(i), depth + 1));
        }
        if (truncated) {
            sb.append(',').append(JSON_ITEMS_TRUNCATED_FMT.formatted(size));
        }
        sb.append(']');
        return sb.toString();
    }

    private static String compactJsonKey(String key) {
        if (key == null) {
            return "\"\"";
        }
        // key 截断：把 marker 放进引号内（GSON 重新加引号），让 "...marker" 整体作为
        // 一个"内容上的截断提示"，避免与 JSON 字符串的闭合引号混淆
        if (key.length() <= MAX_JSON_STRING_CHARS) {
            return GSON.toJson(key);
        }
        return GSON.toJson(key.substring(0, MAX_JSON_STRING_CHARS) + JSON_KEY_TRUNCATED_SUFFIX);
    }

    private static String compactJsonValue(JsonElement el, int depth) {
        if (el == null || el.isJsonNull()) {
            return "null";
        }
        if (el.isJsonPrimitive()) {
            return compactJsonPrimitive(el.getAsJsonPrimitive());
        }
        return compactJsonElement(el, depth);
    }

    /**
     * 共享逻辑：渲染单个 JSON 原始值——字符串超过 {@link #MAX_JSON_STRING_CHARS} 时
     * 截断并追加截断标记（marker 放进引号内，避免与 JSON 字符串的闭合引号混淆）；
     * 数字 / 布尔 / null 直接渲染，不截断（截了可能改变语义）。
     *
     * <p>{@link #compactJsonValue} 与 {@link #renderPrimitive} 共用，消除重复实现。</p>
     */
    private static String compactJsonPrimitive(JsonPrimitive p) {
        if (p.isString()) {
            String s = p.getAsString();
            if (s.length() <= MAX_JSON_STRING_CHARS) {
                return GSON.toJson(s);
            }
            return GSON.toJson(s.substring(0, MAX_JSON_STRING_CHARS) + JSON_VALUE_TRUNCATED_SUFFIX);
        }
        return p.toString();
    }

    private static String renderPrimitive(JsonElement el) {
        // depth 触顶且 el 是 primitive 时调用：直接渲染
        if (el.isJsonPrimitive()) {
            return compactJsonPrimitive(el.getAsJsonPrimitive());
        }
        return el.toString();
    }

    // ============================ 内部：通用字符串截断 ============================

    /**
     * 共享逻辑：字符串长度 ≤ max 时原样返回；否则保留前 max 字符 + suffix。
     * 用于普通 header 截断、JSON key / value 截断、纯文本 body 截断等多处。
     */
    static String truncateString(String text, int max, String suffix) {
        if (text == null) {
            return "";
        }
        if (text.length() <= max) {
            return text;
        }
        return text.substring(0, max) + suffix;
    }

    /**
     * 非 JSON / 非二进制的纯文本 body 截断：超过 {@link #MAX_OTHER_BODY_CHARS} 字符
     * 时按字节/字符数截断并附占位说明（保留原始长度便于模型判断"是不是返回被截了"）。
     */
    static String truncateOther(String text) {
        if (text == null) {
            return EMPTY_BODY_PLACEHOLDER;
        }
        if (text.length() <= MAX_OTHER_BODY_CHARS) {
            return text;
        }
        return text.substring(0, MAX_OTHER_BODY_CHARS)
                + OTHER_TRUNCATED_FMT.formatted(text.length());
    }

    // ============================ 消息文本里的 HTTP 块压缩 ============================
    //
    // 下面是给 DEBUG 日志用的"消息文本"压缩器：把 {@code PromptBuilder} 拼出来的
    // {@code 【HTTP 请求】...【HTTP 响应】...} 文本块压缩成"几行占位"，避免
    // Burp Output 里刷一堆 header / body 明文。
    //
    // 与 {@link #compactRawRequest} / {@link #compactRawResponse} 的差异：
    // - 那两个是从"原始字节"做完整解析（首行 / headers / body 全要），用于阶段 1
    //   喂给模型的"极致压缩"摘要；
    // - 本方法是从"已经是人类可读的中文文本块"做轻量替换，只把"请求行 / 状态码 /
    //   headers / body 正文"折叠成"略.../N字节"占位，其它结构（marker、可替换参数
    //   清单等）原样保留。

    /**
     * 压缩消息文本里的 HTTP 块，输出形如：
     * <pre>
     * 【HTTP 请求】
     * POST http://192.168.253.128/dvwa/xx
     * （请求头：略...）
     * （请求体：123字节）
     *
     * 【HTTP 响应】
     * （响应头：略...）
     * （响应体：4757字节）
     * </pre>
     *
     * <p>处理三种标记块（中英文都覆盖）：</p>
     * <ul>
     *   <li>{@code 【HTTP 请求】} ... 紧跟的"METHOD URL"行 + 后续 headers + 请求体；
     *       压缩后保留 METHOD URL 行、body 字节数，headers 折叠为占位；</li>
     *   <li>{@code 【HTTP 响应】} ... 状态码 + headers + 响应体；压缩后 headers 折叠为占位，
     *       保留 body 字节数（状态码丢弃——按用户期望的最简形式）；</li>
     *   <li>{@code 【重放结果（...）】 ... [响应] ... [响应体 N 字节]} —— 重放工具回填文本，
     *       整段折叠为占位，只保留外层 "【重放结果（callId=xxx，耗时 Nms）】" 元信息。</li>
     * </ul>
     *
     * <p>识别两种"body 字节数行"格式（项目里两套 prompt 渲染器格式不同）：</p>
     * <ul>
     *   <li>{@code buildUserPrompt} 风格：{@code 请求体（共 123 字节）：} / {@code 响应体（共 N 字节）：}（圆括号）</li>
     *   <li>{@code buildReplayResultUserPrompt} 风格：{@code [响应体 N 字节]} / {@code [Body N bytes]}（方括号）</li>
     * </ul>
     *
     * <p>没有上述标记时，文本原样返回（不抛异常、不报错——保证其它消息 / 错误片段等
     * "非 HTTP" 内容原样通过）。</p>
     *
     * <p><b>两路共用</b>：本方法是工具循环阶段 2 DEBUG 的核心——{@code ToolLoopOrchestrator}
     * 在"已经持有 messages 里的字符串、拿不到原 HttpRequest/HttpResponse 对象"的场景下用它。
     * 阶段 1 DEBUG 走 {@code PromptBuilder.buildUserPromptDebug(req, resp)}；为了避免"两套
     * 压缩逻辑漂移"，那个方法内部也调本方法——先把 {@code buildUserPrompt} 拼成完整版，
     * 再用 {@code compactMessageText} 压成调试版。</p>
     */
    public static String compactMessageText(String text) {
        if (text == null || text.isEmpty()) {
            return text == null ? "" : text;
        }
        // 快速通道：连一个标记都没有 → 原样返回
        if (text.indexOf("【HTTP 请求】") < 0
                && text.indexOf("【HTTP 响应】") < 0
                && text.indexOf("【重放结果") < 0
                && text.indexOf("[重放结果") < 0
                && text.indexOf("[Replay result") < 0) {
            return text;
        }
        String[] lines = text.split("\n", -1);
        StringBuilder out = new StringBuilder(text.length());
        int i = 0;
        while (i < lines.length) {
            String line = lines[i];
            // —— 块 1：用户消息里的【HTTP 请求】——
            if ("【HTTP 请求】".equals(line)) {
                out.append(line).append('\n');
                // 下一行是 METHOD URL
                if (i + 1 < lines.length) {
                    out.append(lines[++i]).append('\n');
                }
                out.append("（请求头：略...）\n");
                // 跳到下一个【xxx】marker 或空行+正文结束；过程中找"请求体（共 N 字节）："
                int bodySize = -1;
                i++;
                while (i < lines.length) {
                    String l = lines[i];
                    if (l.startsWith("【") || l.startsWith("[")) {
                        break;
                    }
                    bodySize = tryExtractBodySize(l, "request");
                    if (bodySize >= 0) {
                        // i 此时指向 body 正文首行；advance 到边界行
                        i = advancePastBody(lines, i);
                        break;
                    }
                    i++;
                }
                if (bodySize >= 0) {
                    out.append("（请求体：").append(bodySize).append("字节）\n");
                }
                continue;
            }
            // —— 块 2：用户消息里的【HTTP 响应】——
            if (line.startsWith("【HTTP 响应】")) {
                out.append(line).append('\n');
                out.append("（响应头：略...）\n");
                int bodySize = -1;
                i++;
                while (i < lines.length) {
                    String l = lines[i];
                    if (l.startsWith("【") || l.startsWith("[")) {
                        break;
                    }
                    bodySize = tryExtractBodySize(l, "response");
                    if (bodySize >= 0) {
                        i = advancePastBody(lines, i);
                        break;
                    }
                    i++;
                }
                if (bodySize >= 0) {
                    out.append("（响应体：").append(bodySize).append("字节）\n");
                }
                continue;
            }
            // —— 块 3：工具结果里的【重放结果（...）】或 [Replay result (...)]——
            if (line.startsWith("【重放结果") || line.startsWith("[重放结果")
                    || line.startsWith("[Replay result")) {
                out.append(line).append('\n');
                i++;
                // 第一段：扫描到 "[响应]" / "[Response]" / "【HTTP 响应】" 为止。
                // 期间经过的"【你提交的请求】" / "【可选】" / summary 行原样输出。
                while (i < lines.length) {
                    String l = lines[i];
                    if (isResponseSectionStart(l)) {
                        break;
                    }
                    out.append(l).append('\n');
                    i++;
                }
                // 第二段：已确定进入 [响应] / [Response] / 【HTTP 响应】 子节。
                // 显式跳过这个内层 marker（不输出，避免重复；也不当节结束处理），
                // 然后输出"响应头：略..."占位，继续往后找 body 字节数标记。
                out.append("（响应头：略...）\n");
                int bodySize = -1;
                while (i < lines.length) {
                    String l = lines[i];
                    if (isResponseSectionStart(l)) {
                        // 跳过 "[响应]" / "[Response]" 这种内层 marker
                        i++;
                        continue;
                    }
                    // 真正的节结束（外层【】标记 / 预算耗尽提示 / EOF）→ 退出
                    if (isOuterSectionEnd(l)) {
                        break;
                    }
                    // 状态行 / header 行 / 空行 / body 标记行
                    bodySize = tryExtractBodySize(l, "response");
                    if (bodySize >= 0) {
                        // i 此时是 body 标记行；i+1 是 body 正文首行
                        i = advancePastBody(lines, i + 1);
                        break;
                    }
                    i++;
                }
                if (bodySize >= 0) {
                    out.append("（响应体：").append(bodySize).append("字节）\n");
                }
                continue;
            }
            out.append(line).append('\n');
            i++;
        }
        // 去掉末尾多余的 \n（split 末尾空字符串带来的）
        if (!out.isEmpty() && out.charAt(out.length() - 1) == '\n' && !text.endsWith("\n")) {
            out.setLength(out.length() - 1);
        }
        return out.toString();
    }

    /**
     * 识别一行是否为"body 字节数标记行"——同时覆盖项目里两套 prompt 渲染器用的两种格式：
     * <ul>
     *   <li>{@code buildUserPrompt} 风格（圆括号）：{@code 请求体（共 123 字节）：}、
     *       {@code 响应体（共 N 字节）：}（中英冒号都接受）</li>
     *   <li>{@code buildReplayResultUserPrompt} 风格（方括号）：{@code [响应体 123 字节]}、
     *       {@code [Body 123 bytes]}</li>
     * </ul>
     *
     * @param line     待检测行
     * @param which    "request" / "response"——用于区分请求/响应的关键字（仅圆括号风格需要）
     * @return 字节数；不匹配返回 -1
     */
    private static int tryExtractBodySize(String line, String which) {
        if (line == null) return -1;
        // 格式 1：[响应体 123 字节] / [Body 123 bytes]（方括号，前缀可有可无"["）
        if (line.startsWith("[响应体 ") || line.startsWith("[请求体 ")
                || line.startsWith("[Body ") || line.startsWith("[Request body ")) {
            int closeBracket = line.indexOf(']');
            if (closeBracket > 0) {
                String num = line.substring(1, closeBracket)
                        .replace("响应体", "")
                        .replace("请求体", "")
                        .replace("Body", "")
                        .replace("Request body", "")
                        .replace("字节", "")
                        .replace("bytes", "")
                        .trim();
                try {
                    return Integer.parseInt(num);
                } catch (NumberFormatException e) {
                    return -1;
                }
            }
        }
        // 格式 2：请求体（共 123 字节）： / 响应体（共 N 字节）：（圆括号）
        String prefix = "request".equals(which) ? "请求体（共" : "响应体（共";
        int p = line.indexOf(prefix);
        if (p < 0) return -1;
        int s = line.indexOf("字节）", p + prefix.length());
        if (s < 0) return -1;
        String num = line.substring(p + prefix.length(), s).trim();
        try {
            return Integer.parseInt(num);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /**
     * 从 body 标记行的下一行（{@code lines[i]} 是 body 正文首行）开始向后扫描，
     * 跳过 body 正文，找到下一个"应终止扫描的边界行"（空行 / 章节标记行 / 数组标记行）
     * 并返回该边界行的索引——调用方在 while 循环里把 {@code i} 设为此值后，
     * 外层 for 循环会自然从边界行的下一行开始（因为 for 末尾有 i++）。
     *
     * <p>关键：返回的 i 是"刚好跳完 body"的索引——外层 for 循环会再 i++ 进入
     * 真正的下一节首行。</p>
     */
    private static int advancePastBody(String[] lines, int i) {
        // i 此时是 body 正文首行；往后扫到第一个"边界行"（空行 / 【/[/<EOF>）
        int j = i;
        while (j < lines.length) {
            String l = lines[j];
            if (l.isEmpty() || l.startsWith("【") || l.startsWith("[")) {
                return j;  // 边界行；外层 for 会 ++j 进入下一节
            }
            j++;
        }
        return j;  // EOF
    }

    /**
     * 是否为"进入响应子节"的内层 marker：{@code [响应]} / {@code [Response]} /
     * {@code 【HTTP 响应】}——是块 3 压缩时唯一需要"跳过但不当节结束"的标记。
     */
    private static boolean isResponseSectionStart(String line) {
        return line.startsWith("[响应]") || line.startsWith("[Response]")
                || line.startsWith("【HTTP 响应】");
    }

    /**
     * 是否为"外层节结束"标记：重放结果块后面的【重放预算已耗尽】/【xx】或
     * [Replay budget...] 类提示。空行不算"节结束"——body 内可能含空行。
     *
     * <p><b>注意</b>：{@code [响应体 N 字节]} / {@code [Body N bytes]} 形如"外层"标题
     * （以 {@code [} 开头）但实际是 body 字节数标记行，<b>不</b>当节结束——它属于本块
     * 内的子节，需要被识别并压缩。</p>
     */
    private static boolean isOuterSectionEnd(String line) {
        if (line == null || line.isEmpty()) {
            return false;
        }
        // 任何【xxx】（中文方括号标题）都算外层节；除【HTTP 响应】外其它都当结束。
        if (line.startsWith("【") && !line.startsWith("【HTTP 响应】")) {
            return true;
        }
        // 方括号标题：[Replay budget...] / [xxx]——但要排除内层 marker
        // （[响应] / [Response]）和 body 字节数行（[响应体 N 字节] / [Body N bytes]），
        // 这两类是块 3 内部的子节标记，不算"外层结束"。
        if (line.startsWith("[") && !isResponseSectionStart(line)
                && !isBodySizeMarker(line)) {
            return true;
        }
        return false;
    }

    /**
     * 是否为 body 字节数标记行：{@code [响应体 N 字节]} / {@code [请求体 N 字节]} /
     * {@code [Body N bytes]} / {@code [Request body N bytes]}。专给 {@link #isOuterSectionEnd}
     * 用——把这类行从"外层节结束"的白名单里排除掉。
     */
    private static boolean isBodySizeMarker(String line) {
        return line.startsWith("[响应体 ") || line.startsWith("[请求体 ")
                || line.startsWith("[Body ") || line.startsWith("[Request body ");
    }
}
