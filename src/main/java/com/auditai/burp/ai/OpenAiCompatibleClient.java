package com.auditai.burp.ai;

import com.auditai.burp.config.AiConfig;
import com.auditai.burp.config.Settings;
import com.auditai.burp.util.WorkflowLogger;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * 基于 OpenAI Chat Completions 协议（{@code POST {baseUrl}/chat/completions}）的
 * AiClient 实现。
 *
 * <p>出站走 JDK {@code HttpClient}，不经过 Burp 任何中间件——AI 流量的
 * prompt / API Key / 响应均不出现在 Logger / Proxy history / 拦截器。</p>
 */
public final class OpenAiCompatibleClient implements AiClient {

    /** 采样温度。 */
    private static final double TEMPERATURE = 0.2;

    /** OpenAI 兼容协议的端点路径（拼在用户填写的 baseUrl 末尾）。 */
    private static final String CHAT_COMPLETIONS_PATH = "/chat/completions";

    /** connect 阶段允许的最大等待秒数。 */
    private static final int MAX_CONNECT_TIMEOUT_SECONDS = 30;

    /** 共享设置引用：每次发请求都读当前激活配置。 */
    private final Settings settings;

    /** 必填：注入 owned executor 让 close() 能彻底释放线程。 */
    private final ExecutorService httpExecutor;

    /** connect 超时使用本类硬上限，每次请求超时取自配置。 */
    private final HttpClient httpClient;

    /** 线程安全的 JSON 工具。 */
    private final Gson gson = new Gson();

    /**
     * @param settings     共享的完整设置（含当前激活 AI 服务配置 + 全局提示词）。
     * @param httpExecutor 出站调用绑定的执行器。
     */
    public OpenAiCompatibleClient(Settings settings, ExecutorService httpExecutor) {
        if (httpExecutor == null) {
            throw new IllegalArgumentException("httpExecutor 不能为 null：JDK HttpClient 需要 owned executor 才能在 close() 时释放。");
        }
        this.settings = settings;
        this.httpExecutor = httpExecutor;
        HttpClient.Builder builder = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(MAX_CONNECT_TIMEOUT_SECONDS));
        builder.executor(httpExecutor);
        this.httpClient = builder.build();
    }

    /**
     * 关闭 owned executor。同一实例多次调用幂等。
     */
    public void close() {
        ExecutorService toClose = httpExecutor;
        if (toClose == null || toClose.isShutdown()) {
            return;
        }
        toClose.shutdownNow();
        try {
            toClose.awaitTermination(100, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String complete(String systemPrompt, String userPrompt) throws AiException {
        return completeAsync(systemPrompt, userPrompt).await();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public CancellableAiCall completeAsync(String systemPrompt, String userPrompt) throws AiException {
        WorkflowLogger logger = WorkflowLogger.current();
        List<ChatMessage> messages = new ArrayList<>(2);
        messages.add(new ChatMessage("system", systemPrompt));
        messages.add(new ChatMessage("user", userPrompt));
        return completeJsonAsync(messages, false).mapResponse(r -> parseAndLog(logger, r, false));
    }

    /**
     * 带"远端不支持 json_object"自动降级的 JSON 调用：先按 {@code requireJson=true} 发，
     * 若遇到 4xx 且错误体提示不支持 {@code response_format}，自动重试一次（去掉该字段）。
     *
     * <p>调用方拿到的是最终成功的句柄；如果两次都失败则抛出最后一次的异常。</p>
     *
     * <p>首请求 + 降级重试拼成同一条 {@code CompletableFuture} 链，
     * cancel 一次贯通两次出站。</p>
     */
    public CancellableAiCall completeJsonAsyncWithFallback(List<ChatMessage> messages) throws AiException {
        AiConfig config = requireConfig();
        if (messages == null || messages.isEmpty()) {
            throw new AiException("消息列表不能为空。");
        }
        WorkflowLogger logger = WorkflowLogger.current();
        if (logger != null) {
            logger.appendAgent(config, messages, true);
        }

        JsonObject firstPayload = buildPayload(config, messages, true);
        CompletableFuture<CancellableAiCall.HttpResponseFrame> firstFuture = sendFrameAsync(config, firstPayload);
        // 重试阶段的原始出站 future：取消时由 whenComplete 钩子一并 cancel。
        AtomicReference<CompletableFuture<CancellableAiCall.HttpResponseFrame>> retryFutureRef = new AtomicReference<>();

        CompletableFuture<String> chained = firstFuture.thenCompose(frame -> {
            try {
                String parsed = parseAndLog(logger, frame, true);
                return CompletableFuture.completedFuture(parsed);
            } catch (AiException parseEx) {
                if (!looksLikeUnsupportedJsonObject(parseEx)) {
                    CompletableFuture<String> failed = new CompletableFuture<>();
                    failed.completeExceptionally(parseEx);
                    return failed;
                }
                return retryWithoutJsonFormatAsync(logger, messages, parseEx, retryFutureRef);
            }
        });

        chained.whenComplete((result, ex) -> {
            if (!chained.isCancelled()) {
                return;
            }
            if (!firstFuture.isDone()) {
                firstFuture.cancel(true);
            }
            CompletableFuture<CancellableAiCall.HttpResponseFrame> retryFuture = retryFutureRef.get();
            if (retryFuture != null && !retryFuture.isDone()) {
                retryFuture.cancel(true);
            }
        });
        return CancellableAiCall.fromChained(chained);
    }

    /**
     * 异步降级重试：去掉 {@code response_format} 重新发一次，与首请求同链挂载。
     * 原始出站 future 写入 {@code retryFutureRef}，供取消钩子贯通第二次请求。
     */
    private CompletableFuture<String> retryWithoutJsonFormatAsync(
            WorkflowLogger logger,
            List<ChatMessage> messages,
            AiException firstFailure,
            AtomicReference<CompletableFuture<CancellableAiCall.HttpResponseFrame>> retryFutureRef) {
        AiConfig config = requireConfig();
        if (logger != null) {
            logger.appendAgent(config, messages, false);
        }
        JsonObject payload = buildPayload(config, messages, false);
        CompletableFuture<CancellableAiCall.HttpResponseFrame> retryFuture = sendFrameAsync(config, payload);
        retryFutureRef.set(retryFuture);
        return retryFuture
                .thenApply(frame -> {
                    String content = parseResponse(frame, false);
                    if (logger != null) {
                        logger.appendAi(frame.body());
                    }
                    return content;
                })
                .exceptionally(throwable -> {
                    Throwable cause = throwable instanceof CompletionException && throwable.getCause() != null
                            ? throwable.getCause() : throwable;
                    if (cause instanceof java.util.concurrent.CancellationException) {
                        throw new CompletionException(cause);
                    }
                    if (cause instanceof java.util.concurrent.TimeoutException) {
                        throw new CompletionException(new AiException("AI 请求超时：超过设置的超时时间。", cause));
                    }
                    if (cause instanceof AiException ai) {
                        if (logger != null) {
                            logger.appendError(ai.getMessage());
                        }
                        throw new CompletionException(ai);
                    }
                    String message = "JSON 模式降级重试失败（首次：" + firstFailure.getMessage()
                            + "；重试：" + cause.getClass().getSimpleName() + "：" + cause.getMessage() + "）";
                    if (logger != null) {
                        logger.appendError(message);
                    }
                    throw new CompletionException(new AiException(message, cause));
                });
    }

    /** 识别"远端不支持 json_object"错误，以决定是否触发降级重试。 */
    private static boolean looksLikeUnsupportedJsonObject(AiException e) {
        String m = e.getMessage();
        return m != null && m.contains("不支持 json_object");
    }

    /**
     * 单轮异步调用：直接发一次，不做降级。
     */
    @Override
    public CancellableAiCall completeJsonAsync(List<ChatMessage> messages, boolean requireJson) throws AiException {
        AiConfig config = requireConfig();
        if (messages == null || messages.isEmpty()) {
            throw new AiException("消息列表不能为空。");
        }

        WorkflowLogger.logRequest(config, messages, requireJson);

        JsonObject payload = buildPayload(config, messages, requireJson);

        return new CancellableAiCall(sendFrameAsync(config, payload),
                frame -> parseResponse(frame, requireJson));
    }

    /** 异步发出 chat/completions 请求，返回 frame future。 */
    private CompletableFuture<CancellableAiCall.HttpResponseFrame> sendFrameAsync(AiConfig config,
                                                                                 JsonObject payload) {
        HttpRequest request = buildChatRequest(config, payload);
        // 同步 send 包进 supplyAsync：cancel(true) 才能中断底层 HTTP 交换。
        // 超时由 request.timeout() 兜底，connect 阶段另有 HttpClient 的硬上限。
        return CompletableFuture.supplyAsync(() -> {
            try {
                HttpResponse<String> response = httpClient.send(request,
                        HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                return new CancellableAiCall.HttpResponseFrame(response.statusCode(), response.body());
            } catch (IOException e) {
                throw new CompletionException(e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new CompletionException(e);
            }
        }, httpExecutor);
    }

    /**
     * 解析响应 frame 并写一条工作流日志：成功记"响应 [assistant]"、失败记"响应 [error]"。
     *
     * @param logger      调用方在分析线程上抓的 logger 引用（可为 null——为 null 时跳过落盘）。
     * @param frame       HTTP 响应帧（statusCode + body）。
     * @param requireJson 是否期望 JSON 输出（用于错误信息文案）。
     */
    private String parseAndLog(WorkflowLogger logger, CancellableAiCall.HttpResponseFrame frame, boolean requireJson) throws AiException {
        try {
            String content = parseResponse(frame, requireJson);
            if (logger != null) {
                logger.appendAi(frame.body());
            }
            return content;
        } catch (AiException e) {
            if (logger != null) {
                logger.appendError(e.getMessage());
            }
            throw e;
        } catch (RuntimeException e) {
            if (logger != null) {
                logger.appendError("响应解析失败：" + e.getMessage());
            }
            throw e;
        }
    }

    // 网络层错误（连接失败/超时/DNS）在 CancellableAiCall.await() 统一包装为 AiException。

    // ========== 请求组装 ==========

    /** 读取并校验当前激活配置；未配置时给出可读指引（避免后续 NPE 或远端返回 4xx）。 */
    private AiConfig requireConfig() {
        AiConfig config = settings.activeConfig();
        if (config == null) {
            throw new AiException("尚未配置任何 AI 服务：请到『设置』页点击下拉末位『<新增配置>』添加。");
        }
        if (config.getBaseUrl() == null || config.getBaseUrl().isBlank()) {
            throw new AiException("尚未配置 AI 服务地址（baseUrl）。");
        }
        if (config.getModel() == null || config.getModel().isBlank()) {
            throw new AiException("尚未配置模型名（model）：请到『设置』页填写当前激活配置的模型字段。");
        }
        return config;
    }

    /** 把 {@code timeoutSeconds} 夹取到 {@code AiConfig} 的 MIN~MAX 区间（持久化脏数据可能越界）。 */
    static int clampTimeoutSeconds(int configTimeoutSeconds) {
        return Math.max(AiConfig.MIN_TIMEOUT_SECONDS,
                Math.min(configTimeoutSeconds, AiConfig.MAX_TIMEOUT_SECONDS));
    }

    /** 组装 OpenAI 兼容请求体（model / temperature / max_tokens / messages [+ response_format]）。 */
    private static JsonObject buildPayload(AiConfig config, List<ChatMessage> messages, boolean requireJson) {
        JsonObject payload = new JsonObject();
        payload.addProperty("model", config.getModel());
        payload.addProperty("temperature", TEMPERATURE);
        payload.addProperty("max_tokens", config.getMaxTokens());

        JsonArray msgs = new JsonArray();
        for (ChatMessage cm : messages) {
            msgs.add(message(cm.role(), cm.content()));
        }
        payload.add("messages", msgs);
        if (requireJson) {
            JsonObject responseFormat = new JsonObject();
            responseFormat.addProperty("type", "json_object");
            payload.add("response_format", responseFormat);
        }
        return payload;
    }

    /**
     * 构造 chat/completions 请求：JDK {@code HttpRequest.Builder} 链式设
     * URI / 超时 / 头 / body。
     *
     * <p>包级可见：同包单测直接断言"端点拼接 / 超时夹取 / Key 换行校验"这三条
     * 不依赖网络的纯逻辑。</p>
     */
    HttpRequest buildChatRequest(AiConfig config, JsonObject payload) {
        String endpoint = buildEndpoint(config.getBaseUrl());
        URI uri;
        try {
            uri = URI.create(endpoint);
        } catch (IllegalArgumentException e) {
            throw new AiException("AI 服务地址不合法（baseUrl=" + config.getBaseUrl() + "）："
                    + e.getMessage(), e);
        }

        int timeoutSeconds = clampTimeoutSeconds(config.getTimeoutSeconds());
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(uri)
                .timeout(Duration.ofSeconds(timeoutSeconds))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        gson.toJson(payload), StandardCharsets.UTF_8));

        char[] apiKey = config.getApiKey();
        if (apiKey != null && apiKey.length > 0) {
            if (hasHeaderBreak(apiKey)) {
                throw new AiException("API Key 包含换行/回车等非法字符，请检查『设置』中的密钥配置。");
            }
            requestBuilder.header("Authorization", "Bearer " + new String(apiKey));
        }
        return requestBuilder.build();
    }

    /** API Key 中不允许出现 CR / LF（会破坏 HTTP 头结构，header() 也会抛 IAE）。 */
    static boolean hasHeaderBreak(char[] chars) {
        for (char c : chars) {
            if (c == '\r' || c == '\n') {
                return true;
            }
        }
        return false;
    }

    /**
     * 拼接 chat/completions 端点：先剥掉 baseUrl 末尾的一个或多个 {@code /} 再拼路径。
     *
     * @param baseUrl 用户填写的服务根地址；调用方已保证非 null / 非空白（见 {@code requireConfig()}）。
     * @return 形如 {@code https://host/v1/chat/completions} 的端点。
     */
    static String buildEndpoint(String baseUrl) {
        return baseUrl.replaceAll("/+$", "") + CHAT_COMPLETIONS_PATH;
    }

    // ========== 响应解析 ==========

    /**
     * 解析 chat/completions 响应：非 2xx 抛错，成功则提取 {@code choices[0].message.content}。
     *
     * @param frame       异步请求返回的响应帧。
     * @param requireJson 本次请求是否带 {@code response_format: json_object}。
     *                    4xx 错误里若能识别出"远端不支持 json_object"，抛出更明确的信息，
     *                    供调用方决定是否降级。
     * @return 模型返回的文本内容。
     * @throws AiException 状态码异常或响应结构异常时抛出。
     */
    private String parseResponse(CancellableAiCall.HttpResponseFrame frame, boolean requireJson) throws AiException {
        return parseResponseBody(frame.body(), frame.statusCode(), requireJson);
    }

    /**
     * 按响应 body 解析出模型内容：与 {@code parseResponse} 行为一致，
     * 但接收字符串 body 而非 frame——便于同包单测直接传 fixture 字符串验证
     * {@code finish_reason=length} 等结构化字段的处理路径，无需 mock 任何 HTTP 客户端。
     */
    static String parseResponseBody(String body, int statusCode, boolean requireJson) throws AiException {
        // 非 2xx 状态码：把远端错误信息摘要带回，便于在 UI 与日志中定位。
        if (statusCode != 200) {
            String detail = body;
            if (detail != null && detail.length() > 300) {
                detail = detail.substring(0, 300) + "…";
            }
            if (requireJson && (statusCode == 400 || statusCode == 422)
                    && detail != null && detail.toLowerCase(Locale.ROOT).contains("json")) {
                throw new AiException("AI 接口不支持 json_object 输出模式（HTTP "
                        + statusCode + "）：" + detail);
            }
            throw new AiException("AI 接口返回 HTTP " + statusCode + "：" + detail);
        }

        try {
            // 解析响应：标准结构为 choices[0].message.content。
            JsonElement root = JsonParser.parseString(body);
            if (root == null || !root.isJsonObject()) {
                throw new AiException("AI 响应不是合法 JSON 对象（HTTP " + statusCode + "）。");
            }
            JsonElement choices = root.getAsJsonObject().get("choices");
            if (choices == null || !choices.isJsonArray() || choices.getAsJsonArray().isEmpty()) {
                throw new AiException("AI 响应缺少非空 choices 数组（HTTP " + statusCode + "）。");
            }
            JsonElement message = choices.getAsJsonArray().get(0)
                    .getAsJsonObject().get("message");
            if (message == null || !message.isJsonObject()) {
                throw new AiException("AI 响应缺少 choices[0].message 字段（HTTP " + statusCode + "）。");
            }
            JsonElement content = message.getAsJsonObject().get("content");
            if (content == null || content.isJsonNull()) {
                throw new AiException("AI 响应中缺少 choices[0].message.content 字段，可能是模型返回了非文本内容。");
            }
            // 检测 finish_reason=length：max_tokens 不够会拿到不完整 JSON，提前抛可读错误。
            JsonElement choice0 = choices.getAsJsonArray().get(0).getAsJsonObject();
            JsonElement finishReason = choice0.getAsJsonObject().get("finish_reason");
            if (finishReason != null && !finishReason.isJsonNull()
                    && "length".equals(finishReason.getAsString())) {
                throw new AiException("AI 响应被 max_tokens 截断（finish_reason=length），"
                        + "请到『设置』调大『最大 Token 数』后再试。");
            }
            if (content.isJsonArray()) {
                StringBuilder sb = new StringBuilder();
                for (JsonElement part : content.getAsJsonArray()) {
                    if (part.isJsonObject()) {
                        JsonElement text = part.getAsJsonObject().get("text");
                        if (text != null && text.isJsonPrimitive()) {
                            sb.append(text.getAsString());
                        }
                    } else if (part.isJsonPrimitive()) {
                        sb.append(part.getAsString());
                    }
                }
                if (sb.isEmpty()) {
                    throw new AiException("AI 响应中 choices[0].message.content 为空数组（HTTP " + statusCode + "）。");
                }
                return sb.toString();
            }
            return content.getAsString();
        } catch (AiException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new AiException("AI 响应解析失败（HTTP " + statusCode + "）：" + e.getMessage(), e);
        }
    }

    /** 构造一条 role + content 的消息对象。 */
    private static JsonObject message(String role, String content) {
        JsonObject msg = new JsonObject();
        msg.addProperty("role", role);
        msg.addProperty("content", content);
        return msg;
    }
}
