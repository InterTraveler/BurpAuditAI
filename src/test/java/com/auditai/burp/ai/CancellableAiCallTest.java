package com.auditai.burp.ai;

import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
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
        HttpResponse<String> fake = null; // 桩：mapper 直接忽略入参
        CompletableFuture<HttpResponse<String>> future = CompletableFuture.completedFuture(fake);
        CancellableAiCall call = new CancellableAiCall(future, ignored -> "hello");

        assertEquals("hello", call.await());
    }

    @Test
    void awaitWrapsAiException() {
        CompletableFuture<HttpResponse<String>> future = CompletableFuture.completedFuture(null);
        CancellableAiCall call = new CancellableAiCall(future, ignored -> {
            throw new AiException("远端 4xx");
        });

        AiException ex = assertThrows(AiException.class, call::await);
        assertEquals("远端 4xx", ex.getMessage());
    }

    @Test
    void cancelTranslatesToAiException() {
        // 用一个永不完成的 future + cancel(true)，模拟"调用进行中被取消"。
        CompletableFuture<HttpResponse<String>> future = new CompletableFuture<>();
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
        CompletableFuture<HttpResponse<String>> future = CompletableFuture.failedFuture(
                new java.io.IOException("连接超时"));
        CancellableAiCall call = new CancellableAiCall(future, ignored -> "x");

        AiException ex = assertThrows(AiException.class, call::await);
        assertTrue(ex.getMessage().contains("调用 AI 接口失败"),
                "网络错误应包装为 '调用 AI 接口失败' 提示；实际：" + ex.getMessage());
        assertTrue(ex.getMessage().contains("连接超时"));
    }

    @Test
    void futureForAwaitExposesUnderlyingFuture() throws Exception {
        // futureForAwait 是降级重试路径用的：让 OpenAiCompatibleClient 能拿到 future
        // 构造新 CancellableAiCall 包同一请求。
        CompletableFuture<HttpResponse<String>> future = CompletableFuture.completedFuture(null);
        CancellableAiCall call = new CancellableAiCall(future, ignored -> "first");

        assertSame(future, call.futureForAwait());
    }

    /**
     * 链路层契约：链式编排的 {@link CompletableFuture} 被 cancel 时，外层链 future
     * 必须立即被取消，await 必须立即抛 {@code AiException.cancelled}，不能阻塞到
     * 链路里的任何一段重试。
     *
     * <p>覆盖链路：要保证 cancel 贯通到第二次 sendAsync——若链路是"首请求 future
     * + 同步重试 mapper"的两段式结构，cancel 只能中断首请求，第二次同步 send 会让 await
     * 阻塞到 JDK HTTP 自身超时。链路必须编排成 {@code thenCompose} 串起来的
     * {@code CompletableFuture<String>} 链，再走 {@code CancellableAiCall.fromChained}。
     * 本测试用纯 {@code CompletableFuture} 桩模拟这条链，验证 CancellableAiCall 层的契约：</p>
     * <ol>
     *   <li>{@code fromChained} 构造的 CancellableAiCall 在 await 时直接返回链结果；</li>
     *   <li>{@code cancel()} 把外层链 future 标记为 cancelled；</li>
     *   <li>await 立即抛 AiException.cancelled 异常。</li>
     * </ol>
     *
     * <p><b>关于 upstream cancel 传播：</b>JDK 的 {@code CompletableFuture.cancel}
     * 不沿 {@code thenCompose} 链向上游传播——上游 {@code firstFuture} 必须由链路
     * 构建方（{@code OpenAiCompatibleClient}）通过 {@code whenComplete} 钩子手动
     * 取消。{@code OpenAiCompatibleClientTest}（待补）应覆盖这一步；本测试不重复断言。</p>
     */
    @Test
    void chainedFutureCancelsEntireChain() {
        // 模拟"首请求 future 永远不完成"（代表远端卡住）。
        CompletableFuture<HttpResponse<String>> firstFuture = new CompletableFuture<>();
        // 模拟"重试 future 永远不完成"——这条挂在 thenCompose 链里。
        CompletableFuture<String> retryFuture = new CompletableFuture<>();

        CompletableFuture<String> chained = firstFuture.thenCompose(response -> retryFuture);

        CancellableAiCall call = CancellableAiCall.fromChained(chained);

        // 取消外层链 future：CancellableAiCall 契约保证外层被取消 + await 立即抛。
        assertTrue(call.cancel(), "cancel 应成功（链处于 PENDING 状态）");
        assertTrue(chained.isCancelled(), "外层链 future 必须被 cancelled");

        // 模拟 OpenAiCompatibleClient 里的 cancel propagation 钩子：
        // chained 取消时显式取消上游 firstFuture。这步在产品代码里由
        // OpenAiCompatibleClient.whenComplete 完成，测试里复现这个动作。
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
     * 链式结果已经是 String，套一层 HttpResponse mapper 语义上不成立。
     */
    @Test
    void mapResponseOnChainedThrows() {
        CompletableFuture<String> chained = new CompletableFuture<>();
        CancellableAiCall call = CancellableAiCall.fromChained(chained);

        assertThrows(IllegalStateException.class,
                () -> call.mapResponse(ignored -> "x"),
                "链式 CancellableAiCall 不应再套 HttpResponse mapper——这会让 cancel 语义降级回旧 BUG。");
    }
}
