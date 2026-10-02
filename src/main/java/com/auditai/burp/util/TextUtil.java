package com.auditai.burp.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

/**
 * 文本处理工具集。全部为静态方法，禁止实例化。
 *
 * <p>核心目的：控制送进大模型的报文体积与敏感信息暴露面——</p>
 * <ul>
 *   <li>{@link #truncate}：超长文本截断，避免把几 MB 的报文整段发给模型（既烧 token 又易超限）；</li>
 *   <li>{@link #redactHeaderValue}：对 Authorization / Cookie / API Key 等敏感头打码，
 *       防止密钥在分析过程中泄露给第三方模型服务；</li>
 *   <li>{@link #safeBody}：把字节数组转为可读文本；二进制内容（图片、压缩包等）
 *       用占位描述代替，不让乱码污染提示词。</li>
 * </ul>
 */
public final class TextUtil {

    /** 单个报文体送入模型的采样上限（字符数）。 */
    private static final int MAX_BODY_SAMPLE_CHARS = 4096;

    /** 二进制嗅探的采样字节数（取 body 开头这一段做可打印性统计）。 */
    private static final int BINARY_SNIFF_SAMPLE_BYTES = 512;

    /**
     * 用于 DEBUG 日志的"美化 JSON"渲染器：开启 {@code prettyPrinting} 便于肉眼阅读，
     * 并开启 {@code disableHtmlEscaping}（即关闭 Gson 的 HTML 转义），避免
     * {@code =}/{@code <}/{@code >} 被写成 {@code \u003d} 这类冗长 Unicode 形式
     * （占字符又没可读性）。Gson 内部对
     * {@link com.google.gson.JsonObject} 的迭代是按插入序的，所以输出顺序与解析前
     * 保持一致——方便对照"模型原始 JSON 字段顺序"。
     */
    private static final Gson PRETTY_GSON = new GsonBuilder()
            .setPrettyPrinting()
            .disableHtmlEscaping()
            .create();

    /** 判定为二进制的"可疑字节占比"阈值（百分数）。 */
    private static final int BINARY_SUSPICIOUS_THRESHOLD_PERCENT = 5;

    /**
     * 需要打码的敏感头名称（不区分大小写）。
     * 覆盖常见的认证与会话凭据载体；如需扩展可在此追加。
     *
     * <p>被提升为 {@code public} 供 {@code TrafficCompactor} 复用——
     * "哪些头属于敏感"是协议层面的判断，必须只有一份事实，避免两处判定不一致
     * （比如 {@code TrafficCompactor} 把 {@code X-Token} 视为敏感而
     * {@code PromptBuilder} 漏判）。</p>
     */
    public static final Pattern SENSITIVE_HEADER_PATTERN = Pattern.compile(
            "(?i)(authorization|auth|cookie|set-cookie|key|token|session|sid|signature|sign|sig|secret|bearer|jwt|ticket|nonce|otp|passcode|password|passwd|hash|fingerprint|credential|cert)");

    /** 工具类禁止实例化。 */
    private TextUtil() {
    }

    /**
     * 判定指定头名是否属于"敏感头"（需要脱敏）。
     *
     * <p>复用同一份 {@link #SENSITIVE_HEADER_PATTERN}，使脱敏策略只在一处定义。
     * 使用 {@link java.util.regex.Matcher#find()} 而不是 {@code matches()}，
     * 确保像 {@code X-Authorization}、{@code Proxy-Authorization}、
     * {@code X-Auth-Token} 这类带前缀的常见敏感头也能被识别。</p>
     *
     * @param headerName 头名称（可为 null）。
     * @return 命中关键字时返回 true。
     */
    public static boolean isSensitiveHeader(String headerName) {
        return headerName != null && SENSITIVE_HEADER_PATTERN.matcher(headerName).find();
    }

    /**
     * 截断长文本：保留前 maxChars 个字符，并追加说明以提示原文被截断。
     *
     * <p>截断点按 UTF-16 code point 边界对齐：若恰好落在增补字符（emoji 等）的
     * 代理对中间，则回退一个 code unit，避免产生孤立代理导致后续编码出现 U+FFFD。</p>
     *
     * @param text     原文（可为 null，按空串处理）。
     * @param maxChars 保留的最大字符数；小于等于 0 时返回空串（不抛异常）。
     * @return 截断后的文本。
     */
    public static String truncate(String text, int maxChars) {
        if (text == null || maxChars <= 0) {
            return "";
        }
        if (text.length() <= maxChars) {
            return text;
        }
        int cut = maxChars;
        // 若截断点恰好把代理对切成两半（前一个是高代理、cut 处是低代理），回退一个 code unit，
        // 否则 substring 会以孤立高代理结尾，后续 UTF-8 编码会产生 U+FFFD 替换字符。
        // 注意判定必须在 cut 的两侧（cut-1 / cut），而不是保留区内部（cut-2 / cut-1）：
        // 后者会把"完整落在保留区里的代理对"误砍成孤立高代理。
        if (cut < text.length() && Character.isHighSurrogate(text.charAt(cut - 1))
                && Character.isLowSurrogate(text.charAt(cut))) {
            cut -= 1;
        }
        return text.substring(0, cut) + "\n……（已截断，原文共 " + text.length() + " 字符）";
    }

    /**
     * 敏感头脱敏：头名称<b>包含</b> {@link #SENSITIVE_HEADER_PATTERN} 中任一关键字，
     * 其值整体替换为掩码。
     *
     * <p>使用 {@link java.util.regex.Matcher#find()} 而不是 {@code matches()}，确保
     * 像 {@code X-Authorization}、{@code Proxy-Authorization}、{@code X-Auth-Token}
     * 这类带前缀的常见敏感头也能被识别（{@code matches()} 要求整个字符串完全匹配，
     * 会漏掉这类头）。</p>
     *
     * @param headerName  头名称。
     * @param headerValue 头值（可为 null）。
     * @return 脱敏后的头值；非敏感头原样返回。
     */
    public static String redactHeaderValue(String headerName, String headerValue) {
        if (isSensitiveHeader(headerName)) {
            return "******（已脱敏）";
        }
        return headerValue == null ? "" : headerValue;
    }

    /**
     * 报文体安全转换：检测二进制内容，避免把乱码/超大文本直接拼进提示词。
     *
     * <p>检测方法：取前 512 字节样本，统计空字节与不可打印字符占比，
     * 超过阈值即判定为二进制。文本内容则按 UTF-8 解码并截断。</p>
     *
     * @param body 原始报文 body（可为空数组）。
     * @return 可安全放入提示词的文本描述。
     */
    public static String safeBody(byte[] body) {
        if (body == null || body.length == 0) {
            return "（空）";
        }
        if (isLikelyBinary(body)) {
            return "（二进制数据，共 " + body.length + " 字节，已省略内容）";
        }
        String text = new String(body, StandardCharsets.UTF_8);
        return truncate(text, MAX_BODY_SAMPLE_CHARS);
    }

    /**
     * 二进制嗅探：对 body 开头一段字节做可打印性抽样。
     *
     * <p>比较一律按<b>无符号</b>字节进行（{@code b & 0xFF}）：UTF-8 多字节字符的
     * 字节（0x80-0xFF）在 signed 视角下是负数，若按 signed 比较会把中文/日文/emoji
     * 正文误判为二进制。0x80-0xFF 均视为合法 UTF-8 组成部分，只把真正的控制字符
     * （0x00-0x1F，常见空白除外）计为可疑。</p>
     *
     * @param body 要检测的字节数组。
     * @return 如果样本中可疑字节比例超过阈值则返回 true。
     */
    public static boolean isLikelyBinary(byte[] body) {
        if (body == null || body.length == 0) {
            return false;
        }
        int sampleLen = Math.min(body.length, BINARY_SNIFF_SAMPLE_BYTES);
        int suspicious = 0;
        for (int i = 0; i < sampleLen; i++) {
            int ub = body[i] & 0xFF;
            // 不可打印（含 null 字节 0x00，0x00 < 0x20 已被覆盖）且非常见空白字符视为可疑
            if (ub < 0x20 && ub != '\t' && ub != '\n' && ub != '\r') {
                suspicious++;
            }
        }
        // 可疑字节占比超过阈值即判定为二进制内容
        return suspicious * 100 / sampleLen > BINARY_SUSPICIOUS_THRESHOLD_PERCENT;
    }

    /**
     * 把单行 JSON 文本"美化"为多行可读格式，仅供 DEBUG 日志展示。
     *
     * <p>模型在 {@code completeJsonAsyncWithFallback} 阶段已经解析过一次，本方法
     * 在 DEBUG 输出时再 parse 一次 + pretty-print 一次——代价在测试中 < 1ms，
     * 对线上性能无感知；好处是"模型到底回了什么 JSON"一眼看清（默认是大段单行，
     * 关键字段被淹没在长字符串里）。</p>
     *
     * <p>解析失败时<b>原样回退</b>输出，不抛异常——DEBUG 日志绝不能因为美化失败
     * 而把"原始 raw 响应"也一起丢掉（排错时最需要看的恰恰是那个非 JSON 字符串）。</p>
     *
     * @param raw 模型原始 JSON 响应（可能为 null / 空 / 非 JSON）。
     * @return 美化后的 JSON；非 JSON 或空输入时回退为原文。
     */
    public static String prettyJson(String raw) {
        if (raw == null || raw.isEmpty()) {
            return raw == null ? "" : raw;
        }
        try {
            JsonElement root = JsonParser.parseString(raw);
            return PRETTY_GSON.toJson(root);
        } catch (JsonSyntaxException e) {
            return raw;
        }
    }
}
