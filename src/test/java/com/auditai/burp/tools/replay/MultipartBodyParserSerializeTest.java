package com.auditai.burp.tools.replay;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link MultipartBodyParser} 的 parse → serialize <b>字节级</b>回归测试。
 *
 * <p>为什么必须做字节级断言：{@code ReplayServiceTest} 里对 multipart 替换的断言只检查
 * "新值子串是否存在"，因此历史上 {@code Part} 存错偏移（存了 header 起点而 serialize
 * 期望 value 起点）时，替换后的 body 会丢掉被替换 part 的整个 {@code Content-Disposition}
 * 头、且相邻 part 之间丢一个 {@code \r\n}，而测试依然全绿——模型看到"替换成功"、
 * 实际发出去的却是畸形报文。本测试用整段等值比较把这类缺陷钉死。</p>
 *
 * <p>纯字节入口 {@link MultipartBodyParser#parseBody(byte[], String)} 不依赖 Montoya
 * 运行时对象工厂，因此可在无 Burp 环境下直接断言。</p>
 */
final class MultipartBodyParserSerializeTest {

    private static final String BOUNDARY = "TestB";

    /** 构造 3 个 part 的标准 multipart body（每个 part 带完整的 Content-Disposition 头）。 */
    private static byte[] threePartBody() {
        String body = "--" + BOUNDARY + "\r\n"
                + "Content-Disposition: form-data; name=\"alpha\"\r\n"
                + "\r\n"
                + "1111\r\n"
                + "--" + BOUNDARY + "\r\n"
                + "Content-Disposition: form-data; name=\"beta\"\r\n"
                + "\r\n"
                + "2222\r\n"
                + "--" + BOUNDARY + "\r\n"
                + "Content-Disposition: form-data; name=\"gamma\"; filename=\"g.txt\"\r\n"
                + "\r\n"
                + "3333\r\n"
                + "--" + BOUNDARY + "--\r\n";
        return body.getBytes(StandardCharsets.UTF_8);
    }

    private static Map<String, String> replacements(String... kv) {
        Map<String, String> map = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            map.put(kv[i], kv[i + 1]);
        }
        return map;
    }

    private static String asString(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("无替换时 serialize 必须是原 body 的等值拷贝")
    void serialize_withoutReplacements_isIdentity() {
        byte[] body = threePartBody();
        List<MultipartBodyParser.Part> parts = MultipartBodyParser.parseBody(body, BOUNDARY);

        assertEquals(3, parts.size(), "应解析出 3 个 part");
        byte[] out = MultipartBodyParser.serialize(body, BOUNDARY, parts, Map.of());
        assertEquals(asString(body), asString(out), "无替换必须逐字节等价");
    }

    @Test
    @DisplayName("替换第 1 个 part 时，其 Content-Disposition 头必须保留")
    void serialize_replacingFirstPart_keepsHeader() {
        byte[] body = threePartBody();
        List<MultipartBodyParser.Part> parts = MultipartBodyParser.parseBody(body, BOUNDARY);

        byte[] out = MultipartBodyParser.serialize(body, BOUNDARY, parts, replacements("alpha", "1' OR 1=1--"));
        String text = asString(out);

        assertTrue(text.contains("Content-Disposition: form-data; name=\"alpha\"\r\n\r\n1' OR 1=1--"),
                "被替换 part 的 Content-Disposition 头不得丢失，实际：" + text);
        assertTrue(text.contains("name=\"beta\"\r\n\r\n2222"), "未替换的 part 必须原样保留");
    }

    @Test
    @DisplayName("替换中间 part 时，boundary 行与 part header 之间的 CRLF 不得丢失")
    void serialize_replacingMiddlePart_keepsBoundaryCrlfAndHeader() {
        byte[] body = threePartBody();
        List<MultipartBodyParser.Part> parts = MultipartBodyParser.parseBody(body, BOUNDARY);

        byte[] out = MultipartBodyParser.serialize(body, BOUNDARY, parts, replacements("beta", "BBBB"));
        String text = asString(out);

        assertTrue(text.contains("--" + BOUNDARY + "\r\nContent-Disposition: form-data; name=\"beta\""),
                "boundary 行与 part header 之间必须有一个 CRLF（不得粘连），实际：" + text);
        assertTrue(text.contains("\r\n\r\nBBBB\r\n--" + BOUNDARY),
                "替换后的 value 必须落在正确的 part 内，实际：" + text);
        // 归零校验：只有 beta 的值变了，其余字节完全一致
        assertEquals(asString(body).replace("2222", "BBBB"), text, "除目标值外不得有任何其它字节变化");
    }

    @Test
    @DisplayName("替换最后一个 part 时，terminator 与结尾 CRLF 必须保留")
    void serialize_replacingLastPart_keepsTerminator() {
        byte[] body = threePartBody();
        List<MultipartBodyParser.Part> parts = MultipartBodyParser.parseBody(body, BOUNDARY);

        byte[] out = MultipartBodyParser.serialize(body, BOUNDARY, parts, replacements("gamma", "GGGG"));
        String text = asString(out);

        assertTrue(text.contains("filename=\"g.txt\""), "文件 part 的 header 必须保留");
        assertTrue(text.contains("\r\n\r\nGGGG\r\n--" + BOUNDARY + "--\r\n"),
                "终止 boundary 与结尾 CRLF 必须保留，实际：" + text);
        assertEquals(asString(body).replace("3333", "GGGG"), text, "除目标值外不得有任何其它字节变化");
    }

    @Test
    @DisplayName("多 part 同时替换：每个 part 的头都在，且顺序不变")
    void serialize_replacingAllParts_keepsAllHeaders() {
        byte[] body = threePartBody();
        List<MultipartBodyParser.Part> parts = MultipartBodyParser.parseBody(body, BOUNDARY);

        byte[] out = MultipartBodyParser.serialize(body, BOUNDARY, parts,
                replacements("alpha", "A2", "beta", "B2", "gamma", "G2"));
        String text = asString(out);

        assertEquals(asString(body)
                        .replace("1111", "A2").replace("2222", "B2").replace("3333", "G2"),
                text, "三个 part 各自替换后，除 value 外不应有任何差异");
    }

    @Test
    @DisplayName("Part 暴露的 valueOffset 必须指向 value 起点（而不是 header 起点）")
    void parseBody_valueOffsetPointsAtValue() {
        byte[] body = threePartBody();
        List<MultipartBodyParser.Part> parts = MultipartBodyParser.parseBody(body, BOUNDARY);

        for (MultipartBodyParser.Part part : parts) {
            assertEquals(part.value(),
                    asString(body).substring(part.valueOffset(), part.valueEndOffset()),
                    "body[valueOffset, valueEndOffset) 必须恰好是该 part 的 value：" + part.name());
        }
    }
}
