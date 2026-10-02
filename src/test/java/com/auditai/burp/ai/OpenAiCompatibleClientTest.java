package com.auditai.burp.ai;

import com.auditai.burp.config.AiConfig;
import com.auditai.burp.config.Settings;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.http.HttpRequest;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link OpenAiCompatibleClient} 的纯逻辑单元测试：端点拼接、超时夹取、
 * Authorization 头与前置校验。
 *
 * <p>为什么这些用例必须存在：历史实现里 {@code baseUrl.replace("/+$", "")} 把正则当字面量，
 * 带尾斜杠的 baseUrl 会请求到 {@code //chat/completions}，而本类此前<b>没有任何单测</b>，
 * 缺陷因此长期存活。这里全部只断言不依赖网络的构造期行为（不发真实请求）。</p>
 */
final class OpenAiCompatibleClientTest {

    /** 组装一个以 config 为激活项的客户端。 */
    private static OpenAiCompatibleClient clientFor(AiConfig config) {
        return new OpenAiCompatibleClient(new Settings(List.of(config), config.getName(), ""));
    }

    private static AiConfig config(String baseUrl, String apiKey, int timeoutSeconds) {
        return new AiConfig("测试配置", baseUrl, apiKey, "test-model", timeoutSeconds, 128);
    }

    private static HttpRequest requestFor(String baseUrl, String apiKey, int timeoutSeconds) {
        AiConfig config = config(baseUrl, apiKey, timeoutSeconds);
        return clientFor(config).buildChatRequest(config, new JsonObject());
    }

    // ========== 端点拼接 ==========

    @Test
    @DisplayName("baseUrl 不带尾斜杠：直接拼 /chat/completions")
    void buildEndpoint_withoutTrailingSlash() {
        assertEquals("https://api.deepseek.com/v1/chat/completions",
                OpenAiCompatibleClient.buildEndpoint("https://api.deepseek.com/v1"));
    }

    @Test
    @DisplayName("非行尾的斜杠不受影响")
    void buildEndpoint_keepsInnerSlashes() {
        assertEquals("https://gw.example.com/openai/v1/chat/completions",
                OpenAiCompatibleClient.buildEndpoint("https://gw.example.com/openai/v1"));
    }

    @Test
    @DisplayName("buildChatRequest 的 URI 不得出现双斜杠")
    void buildChatRequest_uriHasNoDoubleSlash() {
        HttpRequest request = requestFor("https://api.deepseek.com/v1/", "", 60);
        assertEquals("https://api.deepseek.com/v1/chat/completions", request.uri().toString());
    }

    @Test
    @DisplayName("baseUrl 含空格等非法字符：转成可读的 AiException 而不是裸 IAE")
    void buildChatRequest_illegalBaseUrl_throwsAiException() {
        AiException ex = assertThrows(AiException.class,
                () -> requestFor("ht tp://api.example.com/v1", "", 60));
        assertTrue(ex.getMessage().contains("baseUrl"), "错误信息应指出 baseUrl，实际：" + ex.getMessage());
    }

    // ========== 超时夹取 ==========

    @Test
    @DisplayName("超时按下限/上限夹取：0 与负值 → MIN，超大值 → MAX，正常值原样")
    void buildChatRequest_clampsTimeout() {
        assertEquals(Duration.ofSeconds(AiConfig.MIN_TIMEOUT_SECONDS),
                requestFor("https://h/v1", "", 0).timeout().orElseThrow());
        assertEquals(Duration.ofSeconds(AiConfig.MIN_TIMEOUT_SECONDS),
                requestFor("https://h/v1", "", -5).timeout().orElseThrow());
        assertEquals(Duration.ofSeconds(AiConfig.MAX_TIMEOUT_SECONDS),
                requestFor("https://h/v1", "", 99_999).timeout().orElseThrow());
        assertEquals(Duration.ofSeconds(60),
                requestFor("https://h/v1", "", 60).timeout().orElseThrow());
    }

    // ========== API Key ==========

    @Test
    @DisplayName("Key 非空时带 Bearer 头；Key 为空时不带 Authorization")
    void buildChatRequest_authorizationHeader() {
        HttpRequest withKey = requestFor("https://h/v1", "sk-abc", 60);
        assertEquals("Bearer sk-abc",
                withKey.headers().firstValue("Authorization").orElseThrow());
        HttpRequest withoutKey = requestFor("https://h/v1", "", 60);
        assertTrue(withoutKey.headers().firstValue("Authorization").isEmpty(),
                "本地 Ollama 等无需 Key 的场景不应带空 Bearer 头");
    }

    @Test
    @DisplayName("Key 含 CR/LF：直接拒绝，避免破坏 HTTP 头结构")
    void buildChatRequest_apiKeyWithBreak_throwsAiException() {
        assertThrows(AiException.class, () -> requestFor("https://h/v1", "sk-a\nb", 60));
        assertThrows(AiException.class, () -> requestFor("https://h/v1", "sk-a\rb", 60));
    }

    // ========== 前置校验 ==========

    @Test
    @DisplayName("未配置任何 AI 服务：同步抛可读的 AiException（不发请求）")
    void completeAsync_withoutConfig_throwsAiException() {
        OpenAiCompatibleClient client =
                new OpenAiCompatibleClient(new Settings(List.of(), null, ""));
        AiException ex = assertThrows(AiException.class,
                () -> client.completeAsync("system", "user"));
        assertTrue(ex.getMessage().contains("尚未配置"), "实际：" + ex.getMessage());
    }

    @Test
    @DisplayName("baseUrl 为空白：同步抛 AiException（不发请求）")
    void completeAsync_blankBaseUrl_throwsAiException() {
        AiConfig config = config("   ", "", 60);
        OpenAiCompatibleClient client = clientFor(config);
        assertThrows(AiException.class, () -> client.completeAsync("system", "user"));
    }

    @Test
    @DisplayName("messages 为 null / 空：同步抛 AiException")
    void completeJsonAsync_emptyMessages_throwsAiException() {
        OpenAiCompatibleClient client = clientFor(config("https://h/v1", "", 60));
        assertThrows(AiException.class, () -> client.completeJsonAsync(null, true));
        assertThrows(AiException.class, () -> client.completeJsonAsync(List.of(), true));
        assertThrows(AiException.class, () -> client.completeJsonAsyncWithFallback(List.of()));
    }

    // ========== parseResponseBody：响应结构化字段处理 ==========

    @Test
    @DisplayName("finish_reason=length：抛 AiException，提示调大 max_tokens")
    void parseResponseBody_finishReasonLength_throwsAiException() {
        // 模型返回 200 OK 但 content 是被 max_tokens 截断的字符串（外层 JSON 合法，
        // 但 content 字段值内部明显被砍断——这正是用户能"看上去像截断"的真实场景）：
        // 旧实现会"无声"返回截断的 content，下游 JSON 解析失败——现在显式抛错。
        String truncatedJson = "{\"choices\":[{\"index\":0,\"finish_reason\":\"length\","
                + "\"message\":{\"role\":\"assistant\","
                + "\"content\":\"{\\\"analysis\\\":\\\"有点风险\\\"\"}}]}";
        AiException ex = assertThrows(AiException.class,
                () -> OpenAiCompatibleClient.parseResponseBody(truncatedJson, 200, true));
        assertTrue(ex.getMessage().contains("finish_reason=length"),
                "错误信息应明确指出 finish_reason=length，实际：" + ex.getMessage());
        assertTrue(ex.getMessage().contains("max_tokens"),
                "错误信息应提示 max_tokens，实际：" + ex.getMessage());
    }

    @Test
    @DisplayName("finish_reason=stop：正常返回 content，不抛错")
    void parseResponseBody_finishReasonStop_returnsContent() throws Exception {
        String okJson = "{\"choices\":[{\"index\":0,\"finish_reason\":\"stop\","
                + "\"message\":{\"role\":\"assistant\",\"content\":\"hello\"}}]}";
        String content = OpenAiCompatibleClient.parseResponseBody(okJson, 200, true);
        assertEquals("hello", content);
    }

    @Test
    @DisplayName("finish_reason 字段缺失：正常返回 content（不阻断）")
    void parseResponseBody_missingFinishReason_returnsContent() throws Exception {
        // 老版本 OpenAI 兼容协议可能不返回 finish_reason 字段——不应阻断解析。
        String okJson = "{\"choices\":[{\"index\":0,"
                + "\"message\":{\"role\":\"assistant\",\"content\":\"hi\"}}]}";
        String content = OpenAiCompatibleClient.parseResponseBody(okJson, 200, true);
        assertEquals("hi", content);
    }
}
