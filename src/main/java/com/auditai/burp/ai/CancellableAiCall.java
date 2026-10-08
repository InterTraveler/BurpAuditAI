package com.auditai.burp.ai;

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
 *   <li>{@link #cancel()}：从任意线程中断进行中的请求（底层为
 *       {@link CompletableFuture#cancel(boolean)}）；调用后 {@link #await()} 会以
 *       "分析已取消"的 {@link AiException} 结束。</li>
 * </ul>
 *
 * <p>{@link #await()} 是<b>幂等</b>的——响应映射只在第一次 await 时执行一次，
 * 成功/失败结果被缓存，后续 await 直接返回缓存。</p>
 */
public final class CancellableAiCall {

    /**
     * 一次网络调用的最小响应载荷：状态码 + 字符串 body。
     */
    public record HttpResponseFrame(int statusCode, String body) {
    }

    /** 底层异步网络请求（cancel 即取消它）。为 null 时表示走 {@link #mappedResult} 链式路径。 */
    private final CompletableFuture<HttpResponseFrame> future;

    /** 把网络响应帧映射为最终文本（状态码检查 + JSON 解析，见实现类）。 */
    private final Function<HttpResponseFrame, String> responseMapper;

    /**
     * 链式结果 future（与 {@link #future}/{@link #responseMapper} 二选一）：
     * 用于 JSON 降级重试等已用 thenCompose 编排好的整条链路。
     */
    private final CompletableFuture<String> mappedResult;

    /** await 结果缓存：确保 mapper 只执行一次（见类注释）。 */
    private boolean computed;
    private String cachedResult;
    private AiException cachedFailure;

    /**
     * @param future         异步网络请求（已包成 frame 的 future）。
     * @param responseMapper frame → 文本的映射函数（可抛 AiException）。
     */
    public CancellableAiCall(CompletableFuture<HttpResponseFrame> future,
                             Function<HttpResponseFrame, String> responseMapper) {
        this.future = future;
        this.responseMapper = responseMapper;
        this.mappedResult = null;
    }

    /**
     * 链式结果构造：调用方已用 {@code thenCompose} / {@code thenApply} 把整条响应处理
     * 链路编排为一个 {@link CompletableFuture}，本工厂直接包装。
     *
     * <p>JSON 降级重试路径专用：两次出站必须挂同一条链，cancel 才能贯通到第二次。</p>
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
     * 链式替换响应映射器：复用同一个底层 {@link CompletableFuture}，await 阶段改用新 mapper。
     *
     * <p>链式路径调用本方法会抛 {@link IllegalStateException}——链式结果已经是 String，
     * 套一层 frame 映射语义上不成立。</p>
     */
    public CancellableAiCall mapResponse(Function<HttpResponseFrame, String> mapper) {
        if (mappedResult != null) {
            throw new IllegalStateException(
                    "mapResponse 不能用于已链式映射的 CancellableAiCall——请改用 CancellableAiCall.fromChained 重新编排整条链。");
        }
        return new CancellableAiCall(future, mapper);
    }

    /**
     * 阻塞等待调用完成并返回模型文本。幂等。
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
            HttpResponseFrame frame = future.join();
            return mapResponse(frame);
        } catch (CancellationException e) {
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
        // cancel 后 future 以 CancellationException 异常完成（isCancelled() 为 false），
        // 须重新识别为取消，否则会被当普通失败处理。
        if (cause instanceof CancellationException) {
            return AiException.cancelled(cause);
        }
        if (cause instanceof java.util.concurrent.TimeoutException) {
            return new AiException("AI 请求超时：超过设置的超时时间，请检查网络或调大超时。", cause);
        }
        return new AiException("调用 AI 接口失败：" + (cause != null ? cause.getMessage() : e.getMessage()), cause);
    }

    /**
     * 执行响应 → 文本映射，并把映射阶段抛出的非业务异常统一包装为 {@link AiException}。
     */
    private String mapResponse(HttpResponseFrame frame) throws AiException {
        try {
            return responseMapper.apply(frame);
        } catch (AiException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new AiException("AI 响应解析失败：" + e.getMessage(), e);
        }
    }

    /**
     * 取消本次调用：链式路径一次性取消整条 {@link CompletableFuture} 链（包括重试分支）。
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
