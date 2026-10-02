package com.auditai.burp.passive;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link RequestFingerprint} 单元测试：body 提取、body-only 哈希（header 不参与）、
 * 大 body 截断 + 长度后缀、确定性。
 */
final class RequestFingerprintTest {

    // ---------- extractBody ----------

    @Test
    void extractBodyStandardCrlf() {
        byte[] raw = ("GET /x HTTP/1.1\r\nHost: a\r\n\r\npayload-body").getBytes(StandardCharsets.UTF_8);
        assertArrayEquals("payload-body".getBytes(StandardCharsets.UTF_8), RequestFingerprint.extractBody(raw));
    }

    @Test
    void extractBodyLfOnly() {
        byte[] raw = ("GET /x HTTP/1.1\nHost: a\n\npayload").getBytes(StandardCharsets.UTF_8);
        assertArrayEquals("payload".getBytes(StandardCharsets.UTF_8), RequestFingerprint.extractBody(raw));
    }

    @Test
    void extractBodyNoSeparatorReturnsEmpty() {
        byte[] raw = "no separator here".getBytes(StandardCharsets.UTF_8);
        assertEquals(0, RequestFingerprint.extractBody(raw).length);
    }

    @Test
    void extractBodyNullOrEmptyReturnsEmpty() {
        assertEquals(0, RequestFingerprint.extractBody(null).length);
        assertEquals(0, RequestFingerprint.extractBody(new byte[0]).length);
    }

    // ---------- compute ----------

    @Test
    void getRequestWithoutBodyUsesNobodyMarker() {
        byte[] raw = "GET /api/status HTTP/1.1\r\nHost: a\r\n\r\n".getBytes(StandardCharsets.UTF_8);
        String fp = RequestFingerprint.compute("GET", "https://a.example/api/status", raw);
        assertEquals("GET|https://a.example/api/status|nobody", fp);
    }

    @Test
    void headersDoNotAffectFingerprint() {
        // 同一 method + URL + body，仅 header 不同 → 指纹必须相同（去重不被动态 header 破坏）
        byte[] raw1 = ("POST /api/login HTTP/1.1\r\nHost: a\r\nCookie: s=1\r\n\r\nuser=admin")
                .getBytes(StandardCharsets.UTF_8);
        byte[] raw2 = ("POST /api/login HTTP/1.1\r\nHost: a\r\nCookie: s=999\r\nX-Request-Id: abc\r\n\r\nuser=admin")
                .getBytes(StandardCharsets.UTF_8);
        assertEquals(
                RequestFingerprint.compute("POST", "https://a.example/api/login", raw1),
                RequestFingerprint.compute("POST", "https://a.example/api/login", raw2));
    }

    @Test
    void differentBodyYieldsDifferentFingerprint() {
        byte[] raw1 = "POST /api HTTP/1.1\r\nHost: a\r\n\r\nbody-one".getBytes(StandardCharsets.UTF_8);
        byte[] raw2 = "POST /api HTTP/1.1\r\nHost: a\r\n\r\nbody-two".getBytes(StandardCharsets.UTF_8);
        assertNotEquals(
                RequestFingerprint.compute("POST", "https://a.example/api", raw1),
                RequestFingerprint.compute("POST", "https://a.example/api", raw2));
    }

    @Test
    void deterministicForSameInput() {
        byte[] raw = "POST /api HTTP/1.1\r\nHost: a\r\n\r\nbody".getBytes(StandardCharsets.UTF_8);
        assertEquals(
                RequestFingerprint.compute("POST", "https://a.example/api", raw),
                RequestFingerprint.compute("POST", "https://a.example/api", raw));
    }

    @Test
    void oversizedBodyIsTruncatedWithLengthSuffix() {
        // body 超过 64KB：只哈希前 64KB + 附加总长度 → 指纹含 "-<length>" 后缀
        byte[] bigBody = new byte[RequestFingerprint.HASH_CAP_BYTES + 100];
        Arrays.fill(bigBody, (byte) 'x');
        byte[] head = "POST /api HTTP/1.1\r\nHost: a\r\n\r\n".getBytes(StandardCharsets.UTF_8);
        byte[] raw = new byte[head.length + bigBody.length];
        System.arraycopy(head, 0, raw, 0, head.length);
        System.arraycopy(bigBody, 0, raw, head.length, bigBody.length);

        String fp = RequestFingerprint.compute("POST", "https://a.example/api", raw);
        assertTrue(fp.endsWith("-" + bigBody.length), "应附加总长度后缀，实际：" + fp);
        // 与"前 64KB 相同但总长度不同"的 body 指纹必须不同（长度后缀参与区分）
        byte[] smallerBody = Arrays.copyOf(bigBody, RequestFingerprint.HASH_CAP_BYTES);
        byte[] rawSmaller = new byte[head.length + smallerBody.length];
        System.arraycopy(head, 0, rawSmaller, 0, head.length);
        System.arraycopy(smallerBody, 0, rawSmaller, head.length, smallerBody.length);
        assertNotEquals(
                RequestFingerprint.compute("POST", "https://a.example/api", raw),
                RequestFingerprint.compute("POST", "https://a.example/api", rawSmaller));
    }
}
