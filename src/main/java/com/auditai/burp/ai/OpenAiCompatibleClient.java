package com.auditai.burp.ai;

import com.auditai.burp.config.AiConfig;
import com.auditai.burp.config.Settings;
import com.auditai.burp.util.WorkflowLogger;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * 基于 OpenAI Chat Completions 协议（{@code POST {baseUrl}/chat/completions}）的
 * {@link AiClient} 实现。
 *
 * <p>该协议已成为事实标准：DeepSeek、OpenAI、通义千问、Kimi、本地 Ollama 等
 * 大多提供兼容端点，因此只需在配置中修改 baseUrl / apiKey / model 即可切换厂商，
 * 无需改动本类代码。</p>
 *
 * <p><b>故意不走 Montoya 的 {@code api.http()}</b>：AI 出站流量调远端厂商服务时，
 * 若走 Burp 的 HTTP 栈，会被 Burp 的上游代理 / Proxy 历史 / 拦截器拦截——
 * 1) 用户的 Proxy 上游规则通常只针对目标站，AI 出站不应被代理；2) AI 请求会污染
 * Proxy 历史（用户看自己的目标流量时混入 AI 调用）；3) 极端情况下可能形成循环
 * （AI 调试自己被 Burp 拦截的请求）。所以这里直接用 JDK 自带的
 * {@link java.net.http.HttpClient} 走系统栈，由用户在 baseUrl 里配 localhost /
 * 内网 IP / 自己的代理端口即可。</p>
 *
 * <p>实现说明：</p>
 * <ul>
 *   <li>使用 JDK 自带的 {@link java.net.http.HttpClient}，零第三方 HTTP 依赖；</li>
 *   <li>使用 {@code sendAsync} 发起请求，返回 {@link CancellableAiCall} 句柄，
 *       支持用户点击 Cancel 中断进行中的请求；</li>
 *   <li>JSON 编解码使用 Gson（已在 pom.xml 中声明并随插件打包）；</li>
 *   <li>{@link HttpClient} 与 {@link Gson} 都是线程安全的，本类可被多线程并发调用。</li>
 * </ul>
 */
public final class OpenAiCompatibleClient implements AiClient {

    /** connect 阶段允许的最大等待秒数，避免被设置面板上的大值（默认上限 300s）拖死 TCP 握手。 */
    private static final int MAX_CONNECT_TIMEOUT_SECONDS = 30;

    /** 采样温度：偏保守，安全分析需要稳定输出（主路径与降级重试路径共用）。 */
    private static final double TEMPERATURE = 0.2;

    /** OpenAI 兼容协议的端点路径（拼在用户填写的 baseUrl 末尾）。 */
    private static final String CHAT_COMPLETIONS_PATH = "/chat/completions";

    /**
     * 共享设置引用：每次发请求都从 {@code settings.activeConfig()} 读最新字段，
     * 因此用户在下拉列表里切换配置后，<b>下一次</b>请求就自动用上新值，
     * 不需要重建本客户端对象。
     */
    private final Settings settings;

    /** 线程安全的 HTTP 客户端；connect 超时使用本类硬上限，每次请求超时取自配置。 */
    private final HttpClient httpClient;

    /**
     * 由调用方注入的 executor（仅用于持有可关闭的线程池）。{@code null} 时回退到 JDK
     * 默认 cached executor（无法关闭，对 Burp 插件单例场景影响很小，但临时实例或
     * 重建场景会有线程残留，所以 {@link SettingsPanel} 的"测试连接"瞬时实例也走默认）。
     */
    private final ExecutorService ownerExecutor;

    /** 线程安全的 JSON 工具。 */
    private final Gson gson = new Gson();

    /**
     * @param settings 共享的完整设置（含当前激活 AI 服务配置 + 全局提示词）。
     */
    public OpenAiCompatibleClient(Settings settings) {
        this(settings, null);
    }

    /**
     * 与 {@link #OpenAiCompatibleClient(Settings)} 等价，但允许调用方注入可关闭的 executor。
     * 插件主实例应使用本构造器，在卸载路径调 {@link #close()} 关闭 executor，避免
     * {@code httpClient} 内部的默认 cached executor 在 Burp 重载插件后留有残留线程。
     *
     * @param settings       共享的完整设置
     * @param ownerExecutor  可选的 owned executor（{@code null} 时走 JDK 默认 cached executor）
     */
    public OpenAiCompatibleClient(Settings settings, ExecutorService ownerExecutor) {
        this.settings = settings;
        this.ownerExecutor = ownerExecutor;
        HttpClient.Builder builder = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(MAX_CONNECT_TIMEOUT_SECONDS));
        // 仅当调用方注入 executor 时接管：让 owned executor 既能跑 HTTP 异步回调，
        // 又能在 close() 时被统一关闭，避免双份线程池同时存在。
        if (ownerExecutor != null) {
            builder.executor(ownerExecutor);
        }
        this.httpClient = builder.build();
    }

    /**
     * 释放客户端持有的资源：关闭调用方注入的 executor（JDK 默认 executor 不可关闭，跳过）。
     * JDK {@code HttpClient} 本身没有公开的 close 方法，缓存线程池通过 owned executor 兜底。
     * 同一实例多次调用幂等。
     */
    public void close() {
        ExecutorService toClose = ownerExecutor;
        if (toClose == null || toClose.isShutdown()) {
            return;
        }
        // shutdownNow：插件卸载时要求"立刻停"，不需要等待挂起的请求收尾——超时/取消
        // 由上层 cancel(true) 负责；这里只关线程池本身，避免空转线程。
        toClose.shutdownNow();
        try {
            // 给正在跑的回调 100ms 收尾时间窗口，避免极端情况下甩出 RejectedExecutionException。
            if (!toClose.awaitTermination(100, TimeUnit.MILLISECONDS)) {
                // 已经 shutdownNow()，再次无意义；保持沉默即可。
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>同步入口：直接转发到 {@link #completeAsync} 并阻塞等待结果。</p>
     */
    @Override
    public String complete(String systemPrompt, String userPrompt) throws AiException {
        return completeAsync(systemPrompt, userPrompt).await();
    }

    /**
     * {@inheritDoc}
     *
     * <p>流程：校验配置 → 组装 chat/completions 请求体 → {@code sendAsync} 发起
     * 可取消的异步请求，返回句柄；响应解析（状态码检查 + 提取
     * {@code choices[0].message.content}）在句柄的 {@code await()} 中执行。</p>
     */
    @Override
    public CancellableAiCall completeAsync(String systemPrompt, String userPrompt) throws AiException {
        // 旧接口语义是"单条 system + 单条 user"，且不强制 JSON 输出；
        // 复用新接口但只传两条消息、关闭 JSON 模式，保持对设置页"测试连接"等调用方零影响。
        // 显式套一层带日志的 mapper：completeJsonAsync 内部的 mapper 只做解析不记日志，
        // 由各入口按需 mapResponse 决定是否落盘——避免三个入口共享同一 mapper 时
        // 响应日志被多次重复记录。
        //
        // 把 logger 引用从分析线程抓到 closure：mapper 实际在 await 线程上跑，
        // 那里 ThreadLocal 没值，必须用 instance 方法 appendAi/appendError。
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
     * <p>调用方拿到的是最终成功的句柄；如果两次都失败则抛出最后一次的异常。
     * 用户视角下"应该用 JSON 但远端不配合"不再需要手工重试。</p>
     *
     * <p><b>取消语义贯通</b>：本方法把"首请求 + 降级重试"用 {@code thenCompose}
     * 拼成<b>同一条</b> {@link CompletableFuture} 链——两次 {@code sendAsync}
     * 都是异步的，cancel(true) 会同时中断两次未完成的 HTTP 请求，不会出现
     * "取消后降级重试仍在跑直到 JDK HTTP 自身超时"的情况。</p>
     */
    public CancellableAiCall completeJsonAsyncWithFallback(List<ChatMessage> messages) throws AiException {
        AiConfig config = requireConfig();
        if (messages == null || messages.isEmpty()) {
            throw new AiException("消息列表不能为空。");
        }
        // 在分析线程上抓 logger 引用：thenCompose / thenApply 回调默认在 HttpClient
        // worker 或 ForkJoinPool.commonPool 上执行——那里 ThreadLocal 拿不到当前
        // logger，WorkflowLogger.logRequest 会静默丢弃。必须把引用作为
        // final 局部变量下传到闭包，回调里改用 logger.appendAi/appendError。
        //
        // 首次请求的工作流日志在这里打——和 retryWithoutJsonFormatAsync 内部
        // 的 N+1 日志形成"请求 1 [json] → 响应 1 [error] → 请求 2 [non-json] →
        // 响应 2 [content]"完整链路，便于排错。
        WorkflowLogger logger = WorkflowLogger.current();
        if (logger != null) {
            logger.appendAgent(config, messages, true);
        }

        JsonObject firstPayload = buildPayload(config, messages, true);
        HttpRequest firstRequest = buildChatRequest(config, firstPayload);
        CompletableFuture<HttpResponse<String>> firstFuture = httpClient.sendAsync(
                firstRequest, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

        // thenCompose 拼"首请求 → 解析 → 可能触发降级"为同一条链：
        //   - 解析成功 → completedFuture 立即结束；
        //   - 解析失败且属于"不支持 json_object" → 链上挂异步重试（也是 sendAsync）；
        //   - 解析失败且属于其他错误 → failedFuture 立即结束（透传给 await）。
        // 两条 sendAsync 共享同一个父 future 链，cancel(true) 一次贯通。
        CompletableFuture<String> chained = firstFuture.thenCompose(response -> {
            try {
                String parsed = parseAndLog(logger, response, true);
                return CompletableFuture.completedFuture(parsed);
            } catch (AiException parseEx) {
                if (!looksLikeUnsupportedJsonObject(parseEx)) {
                    // 非"不支持 json_object"错误（4xx 但不是该类型、5xx、响应结构异常等）：
                    // parseAndLog 内部已记 [error]，透传给 await。
                    CompletableFuture<String> failed = new CompletableFuture<>();
                    failed.completeExceptionally(parseEx);
                    return failed;
                }
                // 走异步降级重试：仍是 sendAsync，挂在 thenCompose 链上受父 cancel 控制。
                return retryWithoutJsonFormatAsync(logger, messages, parseEx);
            }
        });

        // Cancel 向上传播：JDK 的 {@link CompletableFuture#cancel(boolean)} 只把
        // 取消信号向下游依赖阶段传播，<b>不</b>向链路上游的 {@code firstFuture}
        // 传播——直接调 {@code chained.cancel(true)} 时 firstFuture 仍在跑，连接
        // 不会立即释放。注册 whenComplete 钩子在 chained 取消时主动 cancel 上游，
        // 确保两个 sendAsync 阶段都能在用户点 Cancel 后立即被中断。
        // 重试分支的内层 future 是 thenCompose 内部产生的，作为 chained 的下游
        // 会被 JDK 沿链自动 cancel——无需手动处理。
        chained.whenComplete((result, ex) -> {
            if (!chained.isCancelled()) {
                return;
            }
            if (!firstFuture.isDone()) {
                firstFuture.cancel(true);
            }
        });
        return CancellableAiCall.fromChained(chained);
    }

    /**
     * 异步降级重试：去掉 {@code response_format} 重新发一次，与首请求同链挂载。
     *
     * <p>全部走 {@code sendAsync} + {@code thenApply}，本方法不会在 await 线程上
     * 阻塞——cancel(true) 立即中断未完成的 sendAsync 阶段，await 在毫秒级返回
     * {@code AiException.cancelled}。</p>
     *
     * @param logger       调用方在分析线程上抓的 logger 引用（异步回调线程用 instance 方法写）；
     *                     为 null 时跳过落盘（行为与"无 bind"对齐）。
     * @param messages     与首请求相同的消息列表。
     * @param firstFailure 首请求的 AiException（用于在日志中保留首次失败的根因）。
     * @return 异步结果 future：成功返回模型 content；失败（解析或网络）以 CompletionException 包装。
     */
    private CompletableFuture<String> retryWithoutJsonFormatAsync(WorkflowLogger logger,
                                                                  List<ChatMessage> messages,
                                                                  AiException firstFailure) {
        AiConfig config = requireConfig();
        // 重试作为一次独立的"请求 N+1"落盘，与首次失败那条"响应 N [error]"前后呼应，便于排查对照。
        if (logger != null) {
            logger.appendAgent(config, messages, false);
        }
        JsonObject payload = buildPayload(config, messages, false);
        HttpRequest request = buildChatRequest(config, payload);
        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
                .thenApply(resp -> {
                    // 解析 + 响应落盘：parseResponse 失败抛 AiException，thenApply
                    // 自动包成 CompletionException 传给下游 exceptionally。
                    String content = parseResponse(resp, false);
                    if (logger != null) {
                        logger.appendAi(resp.body());
                    }
                    return content;
                })
                .exceptionally(throwable -> {
                    Throwable cause = throwable instanceof CompletionException && throwable.getCause() != null
                            ? throwable.getCause() : throwable;
                    if (cause instanceof AiException ai) {
                        // parseResponse 自身抛的 4xx 等业务错误：appendError 落盘后透传。
                        if (logger != null) {
                            logger.appendError(ai.getMessage());
                        }
                        throw new CompletionException(ai);
                    }
                    // 网络层错误（连接被拒 / 超时 / DNS 失败 / InterruptedException）：
                    // 把首次失败原因一起写进消息，便于排错。
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
     * 单轮异步调用：直接发一次，不做降级。{@code completeAsync} 与
     * {@code completeJsonAsyncWithFallback} 的底层实现均会委派到这里。
     *
     * <p><b>线程约束：</b>本方法返回的 {@link CancellableAiCall} 在任意线程调
     * {@code await()} 都不会阻塞——HTTP 阶段是 {@code sendAsync}，响应映射在
     * await 线程上执行（仅做状态码检查 + JSON 字段提取，纯内存操作，纳秒级）。
     * 真正的网络等待由 {@link CompletableFuture#join()} 处理。</p>
     *
     * <p><b>降级重试路径的 cancel 语义：</b>{@code completeJsonAsyncWithFallback}
     * 不调本方法——它把"首请求 + 降级重试"用 {@code thenCompose} 拼成同一条
     * CompletableFuture 链，确保 cancel(true) 一次贯通两次 sendAsync。详见该方法注释。</p>
     */
    @Override
    public CancellableAiCall completeJsonAsync(List<ChatMessage> messages, boolean requireJson) throws AiException {
        // 每次调用都从共享设置读"当前激活配置"——切换配置后下一次请求立即用上新值。
        AiConfig config = requireConfig();
        if (messages == null || messages.isEmpty()) {
            throw new AiException("消息列表不能为空。");
        }

        // 工作流日志埋点：在真正发请求之前先把"待发请求体（model / messages / response_format）"原样落盘。
        // 本行跑在分析线程上（发送前的同步阶段），用静态入口 + ThreadLocal 没问题；
        // 异步阶段的响应落盘由调用方（completeAsync / completeJsonAsyncWithFallback）
        // 显式传 logger 引用，绕过 ThreadLocal。
        WorkflowLogger.logRequest(config, messages, requireJson);

        JsonObject payload = buildPayload(config, messages, requireJson);
        HttpRequest request = buildChatRequest(config, payload);

        // 异步发送：CompletableFuture 可被 cancel() 中断（对应 UI 的 Cancel 按钮）。
        CompletableFuture<HttpResponse<String>> rawFuture = httpClient.sendAsync(
                request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        // mapper 故意只做"纯解析"，不记日志：直接调本方法的入口（{@link #completeAsync}
        // / 本方法的直接 await）由调用方在 mapper 里调 parseAndLog，避免重复落盘；
        // 走 {@link #completeJsonAsyncWithFallback} 时外层 thenCompose 会再调
        // parseAndLog 一次——保证两个入口（completeAsync / completeJsonAsyncWithFallback）
        // 响应日志各记一次不丢不重。
        return new CancellableAiCall(rawFuture, response -> parseResponse(response, requireJson));
    }

    /**
     * 解析 HTTP 响应并写一条工作流日志：成功记"响应 [assistant]"、失败记"响应 [error]"。
     *
     * <p><b>为什么必须抽成公共方法</b>：所有走 JSON 路径的入口
     * （{@link #completeJsonAsync} 内部 mapper / {@link #completeAsync} 链式
     * mapper / {@link #completeJsonAsyncWithFallback} 的 thenCompose）都需要在
     * "解析成功 → 记响应"和"解析失败 → 记 error"两条路径都打日志——把"解析 + 记响应"
     * 集中到本方法后，所有调用方各自只调一次，响应日志不丢不重。</p>
     *
     * <p><b>为什么 logger 作为参数传入</b>：本方法可能在异步回调线程
     * （HttpClient worker / commonPool）上执行——{@code WorkflowLogger.current()}
     * 在这些线程上返回 null，{@link WorkflowLogger#logRequest} 等静态入口会
     * 静默丢弃记录。调用方在分析线程上把 logger 引用抓成 final 局部变量传进来，
     * 本方法直接走 {@link WorkflowLogger#appendAi} / {@link WorkflowLogger#appendError}
     * 实例方法，保证响应/error 即使在异步回调线程上也能落盘。</p>
     *
     * @param logger      调用方在分析线程上抓的 logger 引用（可为 null——为 null 时跳过落盘，
     *                    行为与"无 bind"语义对齐）。
     * @param response    HTTP 响应。
     * @param requireJson 是否期望 JSON 输出（用于错误信息文案）。
     */
    private String parseAndLog(WorkflowLogger logger, HttpResponse<String> response, boolean requireJson) throws AiException {
        try {
            String content = parseResponse(response, requireJson);
            // 落盘原始响应 body：让审计 XML 看到的是模型实际返回的完整 JSON，
            // 而非我们解析后提取的 content 字符串。
            if (logger != null) {
                logger.appendAi(response.body());
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

    // 异步网络层错误（连接被拒 / 超时 / DNS 失败等走 CompletionException 路径）
    // 由 CancellableAiCall.await() 统一包装为 AiException 并上抛；调用方在
    // sink / orchestrator 路径里再决定是否走 logger.appendError。
    // 这避免了给 future 包一层无意义的 handle：在新的内存缓冲式 logger 下，
    // 写日志是 O(1) append，不需要再在 future 完成时抢占线程。

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
        // model 缺失同样会让远端返回 4xx（"model not found" / "invalid model"），但错误文案
        // 往往被远端截断到前 300 字符，难以一眼定位；这里提前拦截给用户清晰指引。
        if (config.getModel() == null || config.getModel().isBlank()) {
            throw new AiException("尚未配置模型名（model）：请到『设置』页填写当前激活配置的模型字段。");
        }
        return config;
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
            // 强制 JSON：让模型必须输出一个 JSON 对象，避免下游解析失败。
            JsonObject responseFormat = new JsonObject();
            responseFormat.addProperty("type", "json_object");
            payload.add("response_format", responseFormat);
        }
        return payload;
    }

    /**
     * 构造 chat/completions 请求：校验 baseUrl 可解析为 URI、去掉末尾斜杠拼接端点，
     * 超时按 {@link AiConfig#MIN_TIMEOUT_SECONDS} ~ {@link AiConfig#MAX_TIMEOUT_SECONDS}
     * 夹取（持久化脏数据可能为 0/负值），API Key 校验不含 CR/LF 后再放行。
     *
     * <p>包级可见（而非 private）：让同包单测能直接断言"端点拼接 / 超时夹取 / Key 换行校验"
     * 这三条不依赖网络的纯逻辑，无需起 HTTP 服务。</p>
     */
    HttpRequest buildChatRequest(AiConfig config, JsonObject payload) {
        String endpoint = buildEndpoint(config.getBaseUrl());
        URI uri;
        try {
            uri = URI.create(endpoint);
        } catch (IllegalArgumentException e) {
            // baseUrl 含空格 / 非法字符等：URI.create 抛 IAE（运行时、非 AiException），
            // 必须转成可读业务错误，避免原始 IAE 上抛给调用方。
            throw new AiException("AI 服务地址不合法（baseUrl=" + config.getBaseUrl() + "）："
                    + e.getMessage(), e);
        }

        int timeoutSeconds = Math.max(AiConfig.MIN_TIMEOUT_SECONDS,
                Math.min(config.getTimeoutSeconds(), AiConfig.MAX_TIMEOUT_SECONDS));
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(uri)
                .timeout(Duration.ofSeconds(timeoutSeconds))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        gson.toJson(payload), StandardCharsets.UTF_8));

        char[] apiKey = config.getApiKey();
        if (apiKey != null && apiKey.length > 0) {
            if (containsHeaderBreak(apiKey)) {
                throw new AiException("API Key 包含换行/回车等非法字符，请检查『设置』中的密钥配置。");
            }
            // char[] → String：HTTP 头要求 String；转换发生在最末一刹那，String 生命周期极短。
            requestBuilder.header("Authorization", "Bearer " + new String(apiKey));
        }
        return requestBuilder.build();
    }

    /** API Key 中不允许出现 CR / LF（会破坏 HTTP 头结构，header() 也会抛 IAE）。 */
    private static boolean containsHeaderBreak(char[] chars) {
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
     * <p><b>为什么必须剥</b>：用户常直接从厂商文档复制 {@code https://host/v1/}（带尾斜杠），
     * 不剥就会请求 {@code https://host/v1//chat/completions}——双斜杠在部分网关/反向代理上
     * 会被判 404 或路由失败。</p>
     *
     * <p><b>为什么是 {@code replaceAll} 而不是 {@code replace}</b>：{@code "/+$"} 是正则
     * （一个或多个行尾斜杠），而 {@code String.replace} 按<b>字面量</b>替换，
     * 会去找 "/+$" 这四个字符，永远匹配不上——历史实现正是踩了这个坑。</p>
     *
     * @param baseUrl 用户填写的服务根地址；调用方已保证非 null / 非空白（见 {@link #requireConfig()}）。
     * @return 形如 {@code https://host/v1/chat/completions} 的端点。
     */
    static String buildEndpoint(String baseUrl) {
        return baseUrl.replaceAll("/+$", "") + CHAT_COMPLETIONS_PATH;
    }

    // ========== 响应解析 ==========

    /**
     * 解析 chat/completions 响应：非 2xx 抛错，成功则提取 {@code choices[0].message.content}。
     *
     * @param response    异步请求返回的响应。
     * @param requireJson 本次请求是否带 {@code response_format: json_object}。
     *                    4xx 错误里若能识别出"远端不支持 json_object"，抛出更明确的信息，
     *                    供调用方决定是否降级。
     * @return 模型返回的文本内容。
     * @throws AiException 状态码异常或响应结构异常时抛出。
     */
    private String parseResponse(HttpResponse<String> response, boolean requireJson) throws AiException {
        return parseResponseBody(response.body(), response.statusCode(), requireJson);
    }

    /**
     * 按响应 body 解析出模型内容：与 {@link #parseResponse(HttpResponse, boolean)} 行为一致，
     * 但接收字符串 body 而非 HttpResponse——便于同包单测直接传 fixture 字符串验证
     * {@code finish_reason=length} 等结构化字段的处理路径，无需 mock HttpClient。
     */
    static String parseResponseBody(String body, int statusCode, boolean requireJson) throws AiException {
        // 非 2xx 状态码：把远端错误信息摘要带回，便于在 UI 与日志中定位。
        if (statusCode != 200) {
            String detail = body;
            if (detail != null && detail.length() > 300) {
                detail = detail.substring(0, 300) + "…";
            }
            // 识别"远端不支持 json_object"：常见于老版本 Ollama 等。提示调用方可以软降级。
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
            // 检测 finish_reason：长度截断（length）会让下游拿到不完整 JSON（analysis 字段值
            // 缺引号 / 缺闭合括号），解析层只能感知"JSON 解析失败"但不知道为什么。
            // 这里显式抛错，把"max_tokens 不够"的诊断信息透传给用户——用户能在设置里调大。
            JsonElement choice0 = choices.getAsJsonArray().get(0).getAsJsonObject();
            JsonElement finishReason = choice0.getAsJsonObject().get("finish_reason");
            if (finishReason != null && !finishReason.isJsonNull()
                    && "length".equals(finishReason.getAsString())) {
                throw new AiException("AI 响应被 max_tokens 截断（finish_reason=length），"
                        + "请到『设置』调大『最大 Token 数』后再试。");
            }
            if (content.isJsonArray()) {
                // 部分新协议把 content 拆成多段（如 [{"type":"text","text":"..."}]）：
                // 按顺序拼接其中的 text 字段，兼容旧客户端。
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
            // 非法 JSON / 结构不符合预期（缺字段、类型不匹配等）→ 统一转可读业务错误，
            // 避免原始 JsonSyntaxException / NPE / ClassCastException 上抛。
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
