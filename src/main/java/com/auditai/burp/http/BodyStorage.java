package com.auditai.burp.http;

import com.auditai.burp.util.TextUtil;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;
import java.util.zip.GZIPInputStream;

/**
 * 读盘解压 + 超大 body 有界保护 + JSON 结构化裁剪。
 * 写盘（gzip + SHA-256 文件名去重）由 {@link com.auditai.burp.history.AnalysisHistoryStore} 私有实现负责，
 * 本类不重复造。
 */
public final class BodyStorage {

    /** 超过该大小的二进制消息体被占位符替换。 */
    static final int MAX_BINARY_BODY_BYTES = 256 * 1024;

    /** 超过该大小的文本消息体执行裁剪。 */
    static final int MAX_TEXT_BODY_BYTES = 1024 * 1024;

    /** JSON 中单个字符串字段的最大保留大小。 */
    static final int MAX_JSON_STRING_BYTES = 64 * 1024;

    /** JSON 数组裁剪时最多保留的元素个数。 */
    static final int MAX_JSON_ARRAY_ITEMS = 10_000;

    /** JSON 对象裁剪时最多保留的键个数。 */
    static final int MAX_JSON_OBJECT_KEYS = 10_000;

    private static final byte[] HEADER_SEPARATOR = "\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] FALLBACK_HEADER_SEPARATOR = "\n\n".getBytes(StandardCharsets.US_ASCII);

    // MessageDigest 非线程安全（digest() 会改写内部状态），用 ThreadLocal 每线程一份
    // 复用实例，省掉每次 MessageDigest.getInstance 的 provider 查找开销。
    private static final ThreadLocal<MessageDigest> SHA256 = ThreadLocal.withInitial(() -> {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 是 JDK 必带算法；只在被裁剪过的 JRE 上才会丢。
            throw new IllegalStateException("SHA-256 is not available in this JRE", e);
        }
    });

    private BodyStorage() {}

    /**
     * 对完整 HTTP 报文做有界内容保护：只替换 body，不动 header。
     * 小报文直通；二进制 body > 256 KiB 替换占位符；文本 body > 1 MiB 优先尝试结构化裁剪 JSON，
     * 不行再退到文本占位符。
     */
    public static byte[] prepareStoredMessage(byte[] rawMessage) {
        int bodyOffset = findBodyOffset(rawMessage);
        byte[] messageBody = java.util.Arrays.copyOfRange(rawMessage, bodyOffset, rawMessage.length);
        if (messageBody.length <= MAX_BINARY_BODY_BYTES) {
            return rawMessage;
        }
        if (TextUtil.isLikelyBinary(messageBody)) {
            return replaceBody(rawMessage, bodyOffset, "[AuditAI: binary body omitted; original size="
                    + messageBody.length + " bytes, limit=" + MAX_BINARY_BODY_BYTES + " bytes]");
        }
        if (messageBody.length <= MAX_TEXT_BODY_BYTES) {
            return rawMessage;
        }
        String bodyText = new String(messageBody, StandardCharsets.UTF_8);
        String clippedJson = clipJson(bodyText);
        String replacement = clippedJson != null ? clippedJson
                : "[AuditAI: text body clipped; original size=" + messageBody.length
                + " bytes, limit=" + MAX_TEXT_BODY_BYTES + " bytes]";
        return replaceBody(rawMessage, bodyOffset, replacement);
    }

    /** 头不动，只替换 body 部分。 */
    private static byte[] replaceBody(byte[] rawMessage, int bodyOffset, String replacement) {
        byte[] placeholderBytes = replacement.getBytes(StandardCharsets.UTF_8);
        byte[] result = java.util.Arrays.copyOf(rawMessage, bodyOffset + placeholderBytes.length);
        System.arraycopy(placeholderBytes, 0, result, bodyOffset, placeholderBytes.length);
        return result;
    }

    /**
     * 保持 JSON 有效结构做裁剪（对象保留字段、数组保留前部、字符串截断）并加标记；
     * 裁剪后仍超文本上限返回 null，由调用方回退到文本占位符。
     */
    private static String clipJson(String bodyText) {
        try {
            JsonElement root = JsonParser.parseString(bodyText);
            JsonElement clipped = clipJsonElement(root);
            String result = new Gson().toJson(clipped);
            return result.getBytes(StandardCharsets.UTF_8).length <= MAX_TEXT_BODY_BYTES
                    ? result : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static JsonElement clipJsonElement(JsonElement element) {
        if (element.isJsonPrimitive()) {
            JsonPrimitive primitive = element.getAsJsonPrimitive();
            if (primitive.isString()) {
                String value = primitive.getAsString();
                // 阈值按 UTF-8 字节算，截断也必须按字节算：历史实现用 MAX_JSON_STRING_BYTES / 2
                // 当"字符数"上限，中文/emoji 串（1 字符 = 3~4 字节）字节超限但字符数不足时会
                // 一个字符都截不掉，反而在后面追加标记，body 变得更大、上限形同失效。
                if (value.getBytes(StandardCharsets.UTF_8).length > MAX_JSON_STRING_BYTES) {
                    return new JsonPrimitive(
                            truncateToUtf8Bytes(value, MAX_JSON_STRING_BYTES) + "...[AuditAI clipped]");
                }
            }
            return element;
        }
        if (element.isJsonArray()) {
            JsonArray source = element.getAsJsonArray();
            JsonArray result = new JsonArray();
            int limit = Math.min(source.size(), MAX_JSON_ARRAY_ITEMS);
            for (int index = 0; index < limit; index++) {
                result.add(clipJsonElement(source.get(index)));
            }
            if (source.size() > limit) {
                result.add(new JsonPrimitive("[AuditAI: " + (source.size() - limit)
                        + " array elements clipped]"));
            }
            return result;
        }
        if (element.isJsonObject()) {
            JsonObject source = element.getAsJsonObject();
            JsonObject result = new JsonObject();
            int count = 0;
            for (Map.Entry<String, JsonElement> entry : source.entrySet()) {
                if (count++ >= MAX_JSON_OBJECT_KEYS) {
                    result.addProperty("_auditai_truncated", true);
                    break;
                }
                result.add(entry.getKey(), clipJsonElement(entry.getValue()));
            }
            return result;
        }
        return element;
    }

    /**
     * 按 UTF-8 字节数把字符串截断到不超过 {@code maxBytes}，且不切断多字节字符。
     *
     * <p>实现要点：UTF-8 里"续字节"的高两位是 {@code 10}，出现续字节说明截断点落在
     * 某个多字节字符内部，向前回退到该字符的首字节即可，结果不会产生 U+FFFD。</p>
     */
    static String truncateToUtf8Bytes(String value, int maxBytes) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        if (bytes.length <= maxBytes) {
            return value;
        }
        int end = maxBytes;
        while (end > 0 && (bytes[end] & 0xC0) == 0x80) {
            end--;
        }
        return new String(bytes, 0, end, StandardCharsets.UTF_8);
    }

    /** 找 HTTP 头/body 分隔位置；非 HTTP 数据按整段处理。 */
    private static int findBodyOffset(byte[] message) {
        int offset = indexOf(message, HEADER_SEPARATOR);
        if (offset >= 0) {
            return offset + HEADER_SEPARATOR.length;
        }
        offset = indexOf(message, FALLBACK_HEADER_SEPARATOR);
        return offset >= 0 ? offset + FALLBACK_HEADER_SEPARATOR.length : 0;
    }

    /**
     * {@code target} 在 {@code source} 中首次出现的下标，未找到返回 -1。
     * 委托 {@link java.util.Arrays#mismatch} 走 JDK 9+ 的向量化实现，比手写 O(n·m) 快。
     */
    private static int indexOf(byte[] source, byte[] target) {
        if (target.length == 0) {
            return 0;
        }
        if (source.length < target.length) {
            return -1;
        }
        int end = source.length - target.length;
        for (int i = 0; i <= end; i++) {
            // Arrays.mismatch 找到首个不相等下标；返回 target.length 说明完全匹配
            if (java.util.Arrays.mismatch(source, i, i + target.length, target, 0, target.length) == -1) {
                return i;
            }
        }
        return -1;
    }

    /**
     * 算 SHA-256（小写十六进制），用于正文文件去重。
     * MessageDigest 实例走 ThreadLocal 复用，省掉 provider 查找。
     *
     * @param content 报文字节；null 会抛 NullPointerException（与 {@code MessageDigest.digest} 行为一致）。
     * @return 64 字符小写十六进制。
     */
    public static String sha256(byte[] content) {
        MessageDigest digest = SHA256.get();
        digest.reset();
        return HexFormat.of().formatHex(digest.digest(content));
    }

    /**
     * 释放当前线程缓存的 MessageDigest：插件卸载路径调用。
     * Burp 重载插件会复用线程，"无残留" 更稳。
     */
    public static void releaseForCurrentThread() {
        SHA256.remove();
    }

    /**
     * 读并解压一段 gzip 报文。
     *
     * @param file gzip 文件；null 时返回空字节数组。
     * @return 解压后的字节。
     * @throws IOException 读盘 / 解压失败。
     */
    public static byte[] readCompressed(Path file) throws IOException {
        if (file == null) {
            return new byte[0];
        }
        try (InputStream input = Files.newInputStream(file);
             GZIPInputStream gzip = new GZIPInputStream(input)) {
            return gzip.readAllBytes();
        }
    }
}
