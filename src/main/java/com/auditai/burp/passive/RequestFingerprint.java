package com.auditai.burp.passive;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * 请求指纹 = HTTP方法 + URL(含query) + 请求体 Hash（若有）。
 *
 * <p>用于 {@link FingerprintDedup}：同一指纹只分析一次，避免对同一请求重复调 AI。</p>
 *
 * <p><b>输入语义：</b>本类接受<b>完整原始请求字节</b>（请求行 + headers + body），
 * 内部只取 <code>\r\n\r\n</code> 之后的 body 部分做哈希——指纹严格按需求定义为
 * "请求体 Hash"，动态 header（Cookie / CSRF / 时间戳等）不参与指纹，避免同一
 * URL+body 因 header 变化被重复分析。请求体为空（GET 类无 body 请求）时按
 * "无 body" 处理，hash 部分用 {@code "nobody"} 占位，避免与"有 body 但恰好 hash
 * 为空"边界情况混淆。大 body 只哈希前 {@link #HASH_CAP_BYTES} 字节并附带总长度
 * （去重用启发式，非安全用途），避免超大上传把内存和哈希时间吃掉。</p>
 *
 * <p><b>哈希实现：</b>直接使用 JDK {@link java.security.MessageDigest}（SHA-256）。
 * 每次调用新建实例，无共享可变状态，可在任意线程（包括被动分析工作线程）并发调用。
 * （不用 Montoya 的 {@code cryptoUtils().generateDigest}：Montoya 的
 * {@code ByteArray.byteArray} 依赖 Burp 运行时的对象工厂，单元测试环境不可用；
 * 且纯 JDK 实现去掉对 Burp 运行时工厂的依赖，便于测试与隔离。）</p>
 */
public final class RequestFingerprint {

    /**
     * 参与指纹哈希的请求体长度上限（字节）。超过该长度时只哈希前
     * {@value #HASH_CAP_BYTES} 字节并在摘要后附加总长度，避免大文件上传时
     * 对整段 body 做拷贝与哈希（代价与去重收益不成比例）。
     */
    public static final int HASH_CAP_BYTES = 64 * 1024;

    /**
     * 计算请求指纹。
     *
     * @param method     HTTP 方法（GET / POST / …）；null/空按空串处理。
     * @param url        完整 URL（含 query）；null/空按空串处理。
     * @param rawRequest 完整原始请求字节（请求行 + headers + body）；null 按无 body 处理。
     * @return 形如 {@code "POST|https://x.example/a?b=1|<sha256-hex>"} 的指纹字符串。
     */
    public static String compute(String method, String url, byte[] rawRequest) {
        byte[] body = extractBody(rawRequest);
        String bodyDigest = body.length == 0
                ? "nobody"
                : bodyDigest(body);
        return safe(method) + "|" + safe(url) + "|" + bodyDigest;
    }

    /**
     * 从完整原始请求字节中切出 body：取首个 {@code \r\n\r\n}（或 {@code \n\n}）之后的内容。
     * 找不到分隔符（畸形报文）按无 body 处理。
     */
    static byte[] extractBody(byte[] rawRequest) {
        if (rawRequest == null || rawRequest.length == 0) {
            return new byte[0];
        }
        // 标准 CRLF 分隔
        for (int i = 0; i + 3 < rawRequest.length; i++) {
            if (rawRequest[i] == '\r' && rawRequest[i + 1] == '\n'
                    && rawRequest[i + 2] == '\r' && rawRequest[i + 3] == '\n') {
                return Arrays.copyOfRange(rawRequest, i + 4, rawRequest.length);
            }
        }
        // 容错：仅 LF 分隔
        for (int i = 0; i + 1 < rawRequest.length; i++) {
            if (rawRequest[i] == '\n' && rawRequest[i + 1] == '\n') {
                return Arrays.copyOfRange(rawRequest, i + 2, rawRequest.length);
            }
        }
        return new byte[0];
    }

    /**
     * body → 指纹摘要串：长度不超过 {@link #HASH_CAP_BYTES} 时哈希完整 body；
     * 超过时只哈希前 {@link #HASH_CAP_BYTES} 字节并附加 {@code -<总长度>}，
     * 保证不同长度、或前 64KB 不同的 body 不会互相碰撞（前 64KB 相同且等长的
     * 不同 body 理论上可能碰撞——去重用启发式，可接受）。
     */
    private static String bodyDigest(byte[] body) {
        int length = body.length;
        int hashLength = Math.min(length, HASH_CAP_BYTES);
        byte[] toHash = hashLength == length ? body : Arrays.copyOf(body, hashLength);
        String digest = sha256Hex(toHash);
        return length > HASH_CAP_BYTES ? digest + "-" + length : digest;
    }

    /** 字节数组 → SHA-256 十六进制字符串（无分隔符，全小写）。 */
    private static String sha256Hex(byte[] bytes) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            // JDK 必然提供 SHA-256；走到这里说明运行环境异常，显式失败而不是静默降级。
            throw new IllegalStateException("JVM 不支持 SHA-256", e);
        }
        return toHex(md.digest(bytes));
    }

    /** 字节数组 → 十六进制字符串（无分隔符，全小写）。 */
    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    /** null / 空按空串处理，避免指纹里出现 "null" 字面量。 */
    private static String safe(String s) {
        return s == null ? "" : s;
    }

    // 私有构造器：本类是纯静态工具类，禁止实例化。
    private RequestFingerprint() {
    }
}
