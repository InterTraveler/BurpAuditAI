package com.auditai.burp.ai;

import java.net.http.HttpResponse;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.function.Function;

/**
 * 一次<b>可取消</b>的 AI 调用句柄。
 *
 * <p>由 {@link AiClient#completeAsync} 返回，支持两种用法：</p>
 * <ul>
 *   <li>{@link #await()}：阻塞等待调用完成并返回模型文本（失败抛 {@link AiException}）；</li>
 *   <li>{@link #cancel()}：从任意线程中断进行中的 HTTP 请求（底层为
 *       {@link CompletableFuture#cancel(boolean)}）；调用后 {@link #await()} 会以
 *       “分析已取消”的 {@link AiException} 结束。</li>
 * </ul>
 *
 * <p>线程安全性：本类内部状态由 {@link CompletableFuture} 保证，可被多线程并发访问。
 * {@link #await()} 是<b>幂等</b>的——响应映射（{@code responseMapper}）只在第一次
 * await 时执行一次，成功/失败结果被缓存，后续 await 直接返回缓存，避免降级重试等
 * 带副作用的 mapper 被并发/重复执行。</p>
 */
public final class CancellableAiCall {

    /** 底层异步 HTTP 请求（cancel 即取消它）。为 null 时表示走 {@link #mappedResult} 链式路径。 */
    private final CompletableFuture<HttpResponse<String>> future;

    /** 把 HTTP 响应映射为最终文本（状态码检查 + JSON 解析，见实现类）。 */
    private final Function<HttpResponse<String>, String> responseMapper;

    /**
     * 链式映射结果 future：用于"整条链路已编排为 CompletableFuture 链"的入口
     * （典型场景：JSON 降级重试——两次 sendAsync 用 thenCompose 拼成同一条链，
     * 这样 cancel 贯通整条链路，不会在降级分支失效）。
     *
     * <p>与 {@link #future}/{@link #responseMapper} 二选一：同时只能有一个非 null。
     * 二者并存会让 cancel/await 语义含糊，故构造时强制约束。</p>
     */
    private final CompletableFuture<String> mappedResult;

    /** await 结果缓存：确保 mapper 只执行一次（见类注释）。 */
    private boolean computed;
    private String cachedResult;
    private AiException cachedFailure;

    /**
     * @param future         异步 HTTP 请求。
     * @param responseMapper 响应 → 文本的映射函数（可抛 AiException）。
     */
    public CancellableAiCall(CompletableFuture<HttpResponse<String>> future,
                             Function<HttpResponse<String>, String> responseMapper) {
        this.future = future;
        this.responseMapper = responseMapper;
        this.mappedResult = null;
    }

    /**
     * 链式结果构造：调用方已用 {@code thenCompose} / {@code thenApply} 把整条响应处理
     * 链路编排为一个 {@link CompletableFuture}，本工厂直接包装。
     *
     * <p><b>为什么需要这个入口：</b>{@link com.auditai.burp.ai.OpenAiCompatibleClient}
     * 的 JSON 降级重试路径要保证 cancel 贯通到第二次 sendAsync——若仍走"首请求 future
     * + 同步重试 mapper"的两段式结构，cancel 只能中断首请求，第二次同步 send
     * 会让 await 阻塞到 JDK HTTP 自身超时。链路必须编排成"两次 sendAsync thenCompose
     * 拼成一条 CompletableFuture 链"，{@code cancel(true)} 才能在整条链上收得到。</p>
     *
     * @param mappedResult 已编排好的结果 future；await 时直接 join 即可。
     */
    public static CancellableAiCall fromChained(CompletableFuture<String> mappedResult) {
        return new CancellableAiCall(mappedResult);
    }

    private CancellableAiCall(CompletableFuture<String> mappedResult) {
        this.future = null;
        this.responseMapper = null;
        this.mappedResult = mappedResult;
    }

    /**
     * 暴露底层 future 给同包内的"重试包装"使用：包内调用方拿到底层 future
     * 后可构造一个新的 {@link CancellableAiCall} 复用同一请求的 await/cancel 语义。
     *
     * <p>仅在构造时传入 HttpResponse future 的对象上可用；链式路径返回 null，
     * 调用方应改用 {@link #fromChained} 重新构造。</p>
     *
     * @return 底层 {@link CompletableFuture}；引用本对象生命周期内有效，调用方不应缓存。
     */
    public CompletableFuture<HttpResponse<String>> futureForAwait() {
        return future;
    }

    /**
     * 链式替换响应映射器：返回一个新的 {@link CancellableAiCall}，复用同一个底层
     * {@link CompletableFuture}，但 await 阶段改用 {@code mapper} 处理响应。
     *
     * <p>仅适用于"底层 future 是 HttpResponse"的对象；链式路径调用本方法会抛
     * {@link IllegalStateException}（链式路径的结果已经是 String，再套一层
     * HttpResponse 映射语义上不成立——请用 {@link #fromChained} 重新编排）。</p>
     *
     * @param mapper 新的响应 → 文本映射函数。
     * @return 包装同一 future 的新 {@link CancellableAiCall}。
     */
    public CancellableAiCall mapResponse(Function<HttpResponse<String>, String> mapper) {
        if (mappedResult != null) {
            throw new IllegalStateException(
                    "mapResponse 不能用于已链式映射的 CancellableAiCall——请改用 CancellableAiCall.fromChained 重新编排整条链。");
        }
        return new CancellableAiCall(future, mapper);
    }

    /**
     * 阻塞等待调用完成并返回模型文本。
     *
     * <p>幂等：无论调用多少次，底层请求与响应映射都只会执行一次；后续调用直接
     * 返回第一次的结果（或重抛第一次的失败）。</p>
     *
     * @return 模型返回的文本内容。
     * @throws AiException 网络错误、鉴权失败、响应解析失败、或被取消时抛出。
     */
    public synchronized String await() throws AiException {
        if (computed) {
            if (cachedFailure != null) {
                throw cachedFailure;
            }
            return cachedResult;
        }
        try {
            String result;
            if (mappedResult != null) {
                // 链式路径：整条响应处理已编排好，直接 join 即可。
                // 取消传播由 CompletableFuture 链本身保证（cancel(true) 会中断所有未完成阶段）。
                try {
                    result = mappedResult.join();
                } catch (CancellationException e) {
                    throw AiException.cancelled(e);
                } catch (CompletionException e) {
                    throw unwrapAi(e);
                }
            } else {
                result = awaitOnce();
            }
            cachedResult = result;
            computed = true;
            return result;
        } catch (AiException e) {
            cachedFailure = e;
            computed = true;
            throw e;
        }
    }

    /** 真正执行一次 await（由 {@link #await()} 的缓存逻辑调用）。 */
    private String awaitOnce() throws AiException {
        try {
            HttpResponse<String> response = future.join();
            return mapResponse(response);
        } catch (CancellationException e) {
            // 用户点了 Cancel：把"取消"转成可读的业务信息
            throw AiException.cancelled(e);
        } catch (CompletionException e) {
            throw unwrapAi(e);
        }
    }

    /** 把 CompletionException 解包为 AiException（保持原异常或包装为通用失败）。 */
    private static AiException unwrapAi(CompletionException e) {
        Throwable cause = e.getCause();
        if (cause instanceof AiException ai) {
            return ai;
        }
        // JDK {@link java.net.http.HttpClient#sendAsync} 的 cancel(true) 把 future 标为
        // "exceptionally completed with CancellationException"（{@code isCancelled()}
        // 返回 false 但 {@code isDone()} true）。{@code join()} 抛
        // {@code CompletionException(CancellationException)}，必须重新识别为取消
        // 并抛 {@link AiException#cancelled}，否则调用方会把它当普通失败处理。
        if (cause instanceof CancellationException) {
            return AiException.cancelled(cause);
        }
        return new AiException("调用 AI 接口失败：" + (cause != null ? cause.getMessage() : e.getMessage()), cause);
    }

    /**
     * 执行响应 → 文本映射，并把映射阶段抛出的非业务异常统一包装为 {@link AiException}，
     * 避免原始 NPE / JsonSyntaxException 等裸抛给 UI（表现为难读的原始异常文案）。
     */
    private String mapResponse(HttpResponse<String> response) throws AiException {
        try {
            return responseMapper.apply(response);
        } catch (AiException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new AiException("AI 响应解析失败：" + e.getMessage(), e);
        }
    }

    /**
     * 取消本次调用：中断进行中的 HTTP 请求。链式路径会一次性取消整条
     * {@link CompletableFuture} 链（包括重试分支），不再有"降级重试无法取消"
     * 的语义漏洞。
     *
     * @return 是否成功取消（已完成的调用返回 false）。
     */
    public boolean cancel() {
        if (mappedResult != null) {
            return mappedResult.cancel(true);
        }
        return future.cancel(true);
    }
}
