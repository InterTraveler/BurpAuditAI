package com.auditai.burp.ai;

import org.junit.jupiter.api.Test;

import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link CancellableAiCall} 单元测试：覆盖正常返回、自定义异常、用户取消三类路径。
 *
 * <p>底层 future 用 {@link CompletableFuture#completedFuture} 桩，无须真实 HTTP 客户端。</p>
 */
final class CancellableAiCallTest {

    @Test
    void awaitReturnsMapperResult() throws Exception {
        CancellableAiCall.HttpResponseFrame fake = null; // 桩：mapper 直接忽略入参
        CompletableFuture<CancellableAiCall.HttpResponseFrame> future = CompletableFuture.completedFuture(fake);
        CancellableAiCall call = new CancellableAiCall(future, ignored -> "hello");

        assertEquals("hello", call.await());
    }

    @Test
    void awaitWrapsAiException() {
        CompletableFuture<CancellableAiCall.HttpResponseFrame> future = CompletableFuture.completedFuture(null);
        CancellableAiCall call = new CancellableAiCall(future, ignored -> {
            throw new AiException("远端 4xx");
        });

        AiException ex = assertThrows(AiException.class, call::await);
        assertEquals("远端 4xx", ex.getMessage());
    }

    @Test
    void cancelTranslatesToAiException() {
        // 用一个永不完成的 future + cancel(true)，模拟"调用进行中被取消"。
        CompletableFuture<CancellableAiCall.HttpResponseFrame> future = new CompletableFuture<>();
        CancellableAiCall call = new CancellableAiCall(future, ignored -> "should not reach");

        boolean cancelled = call.cancel();
        assertTrue(cancelled, "首次 cancel 应返回 true");

        // future 被 cancel(true) 后 join() 抛 CancellationException
        assertThrows(java.util.concurrent.CancellationException.class, future::join);

        // CancellableAiCall.await() 把 CancellationException 转成业务可读的 AiException
        AiException ex = assertThrows(AiException.class, call::await);
        assertEquals("分析已取消", ex.getMessage());
    }

    @Test
    void awaitOnWrappedIoFailureProducesAiException() {
        // 模拟底层 future 失败（网络错误）：CompletionException 包 IOException
        CompletableFuture<CancellableAiCall.HttpResponseFrame> future = CompletableFuture.failedFuture(
                new java.io.IOException("连接超时"));
        CancellableAiCall call = new CancellableAiCall(future, ignored -> "x");

        AiException ex = assertThrows(AiException.class, call::await);
        assertTrue(ex.getMessage().contains("调用 AI 接口失败"),
                "网络错误应包装为 '调用 AI 接口失败' 提示；实际：" + ex.getMessage());
        assertTrue(ex.getMessage().contains("连接超时"));
    }

    /**
     * 契约：fromChained 包装的链被 cancel 后，外层 future 立即 cancelled，await 立即抛
     * AiException.cancelled。注意 CompletableFuture.cancel 不沿 thenCompose 向上游传播，
     * 上游 firstFuture 由 OpenAiCompatibleClient 的 whenComplete 钩子手动取消（本测试不重复断言）。
     */
    @Test
    void chainedFutureCancelsEntireChain() {
        // 模拟"首请求 future 永远不完成"（代表远端卡住）。
        CompletableFuture<CancellableAiCall.HttpResponseFrame> firstFuture = new CompletableFuture<>();
        // 模拟"重试 future 永远不完成"——这条挂在 thenCompose 链里。
        CompletableFuture<String> retryFuture = new CompletableFuture<>();

        CompletableFuture<String> chained = firstFuture.thenCompose(response -> retryFuture);

        CancellableAiCall call = CancellableAiCall.fromChained(chained);

        // 取消外层链 future：CancellableAiCall 契约保证外层被取消 + await 立即抛。
        assertTrue(call.cancel(), "cancel 应成功（链处于 PENDING 状态）");
        assertTrue(chained.isCancelled(), "外层链 future 必须被 cancelled");

        // 复现 OpenAiCompatibleClient.whenComplete 里对上游 firstFuture 的取消动作。
        if (!firstFuture.isDone()) {
            firstFuture.cancel(true);
        }
        assertTrue(firstFuture.isCancelled(), "上游 firstFuture 必须在 cancel 传播后被取消");

        // await 必须立即抛 AiException，不能阻塞到 retry 完成。
        AiException ex = assertThrows(AiException.class, call::await);
        assertEquals("分析已取消", ex.getMessage(),
                "取消后 await 应立即抛 '分析已取消'，不能阻塞到链路里的同步重试结束");
    }

    /**
     * 链式路径上对已完成的 future 调 cancel 应返回 false（无副作用）。
     */
    @Test
    void chainedCancelOnCompletedFutureReturnsFalse() throws Exception {
        CompletableFuture<String> chained = CompletableFuture.completedFuture("done");
        CancellableAiCall call = CancellableAiCall.fromChained(chained);

        assertFalse(call.cancel(), "已完成的 future cancel 应返回 false");
        assertEquals("done", call.await());
    }

    /**
     * 链式路径上调 {@code mapResponse} 必须抛 {@link IllegalStateException}——
     * 链式结果已经是 String，套一层 frame mapper 语义上不成立。
     */
    @Test
    void mapResponseOnChainedThrows() {
        CompletableFuture<String> chained = new CompletableFuture<>();
        CancellableAiCall call = CancellableAiCall.fromChained(chained);

        assertThrows(IllegalStateException.class,
                () -> call.mapResponse(ignored -> "x"),
                "链式 CancellableAiCall 不应再套 frame mapper");
    }
}
