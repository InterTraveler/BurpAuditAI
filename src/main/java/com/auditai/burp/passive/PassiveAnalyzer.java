package com.auditai.burp.passive;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.auditai.burp.http.AnalysisResult;
import com.auditai.burp.http.AnalysisTask;
import com.auditai.burp.http.TrafficAnalyzer;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * 被动分析编排器：在独立线程池里把"原始请求 / 响应字节"重建为 Montoya 的
 * {@link HttpRequest} / {@link HttpResponse}，再调用 {@link TrafficAnalyzer#analyzeAsync}，
 * 并把结果（成功 / 失败）通过结果回调（通常是 {@code FindingStore.addFindings}）落库。
 *
 * <p>关键设计：</p>
 * <ul>
 *   <li><b>字节级重建</b>：Proxy 回调线程拿到的 {@code InterceptedRequest} 不能跨线程持有，
 *       必须在进入被动分析线程前把它的 {@code toByteArray()} 拷贝出来；本类用
 *       {@code api.http().httpRequest(httpService, byteArray)} 重新构造 HttpRequest，
 *       等价于从 raw 报文重建——这与 Repeater / 上下文菜单送入分析页的路径完全一致；</li>
 *   <li><b>异常隔离</b>：整条分析链路任何位置抛异常都 try-catch 吞掉并写日志，
 *       绝不回传到 {@link PassiveAnalysisExecutor} 的线程——避免 AI 临时不可用时
 *       反复打印栈浪费用户视线；</li>
 *   <li><b>结果回调</b>：通过构造器注入 {@code AnalysisResultHandler}，携带原始
 *       request/response 字节（被动分析现在也会把原文交给"历史"页签），默认实现
 *       仅落 FindingStore；测试可注入 mock 验证调用。</li>
 * </ul>
 */
public final class PassiveAnalyzer {

    /**
     * 分析结果回调：与 {@code FindingStore.addFindings} 单参版不同，本回调多带
     * request/response 原始字节，让"历史"页签能在被动分析条目下展示完整报文。
     */
    @FunctionalInterface
    public interface AnalysisResultHandler {
        /**
         * @param result         来自 {@link TrafficAnalyzer} 的分析结果。
         * @param requestBytes   本次分析使用的原始请求字节（可为 null）。
         * @param responseBytes  本次分析使用的原始响应字节（可为 null / 无响应）。
         */
        void handle(AnalysisResult result, byte[] requestBytes, byte[] responseBytes);
    }

    private final MontoyaApi api;
    private final TrafficAnalyzer trafficAnalyzer;
    private final AnalysisResultHandler resultHandler;

    /**
     * 在飞的被动分析任务句柄。
     *
     * <p>手动分析由 {@code MessageTab} 持有 {@code currentTask} 并在关闭/取消时中断；
     * 被动分析此前把 {@code analyzeAsync} 的返回值直接丢弃，于是<b>没有任何取消路径</b>——
     * 插件卸载时 {@code PassiveAnalysisExecutor.shutdownNow()} 只是中断线程，而 AI 等待用的是
     * {@code CompletableFuture.join()}（<b>不响应中断</b>），请求会一直跑到 JDK HTTP 超时
     * （最长 300s）。这里登记句柄，卸载时逐个 {@code cancel()} 真正中断。</p>
     */
    private final Set<AnalysisTask> inFlight = ConcurrentHashMap.newKeySet();

    /**
     * @param api             Montoya API 门面（用于重建 HttpRequest / HttpResponse）。
     * @param trafficAnalyzer 主分析器（注入依赖，不自己 new——便于测试）。
     * @param resultHandler   分析结果回调；通常包成
     *                        {@code (r, req, resp) -> { findingStore.addFindings(r); historyStore.add(r, PASSIVE, req, resp); }}。
     *                        允许为 null（null 时丢弃结果，仅记日志）。
     */
    public PassiveAnalyzer(MontoyaApi api, TrafficAnalyzer trafficAnalyzer,
                           AnalysisResultHandler resultHandler) {
        this.api = api;
        this.trafficAnalyzer = trafficAnalyzer;
        this.resultHandler = resultHandler == null ? (r, req, resp) -> { } : resultHandler;
    }

    /**
     * 在独立线程池里执行一次完整的"请求 + 响应 → AI 分析 → 落库"流程。
     *
     * <p>本方法不抛异常：所有内部错误一律 try-catch + 日志。</p>
     *
     * @param httpService    请求归属的 HTTP 服务（从 InterceptedRequest.httpService() 拿）；
     *                       重建 HttpRequest 必须用同一个 service 才能正确还原 Host / TLS 标志。
     * @param method         HTTP 方法。
     * @param url            完整 URL。
     * @param requestBytes   原始请求字节（来自 InterceptedRequest.toByteArray()）。
     * @param responseBytes  原始响应字节（来自 InterceptedResponse.toByteArray()）；
     *                       可为 null（无响应，仅分析请求）。
     */
    public void analyzeAsync(HttpService httpService, String method, String url,
                             byte[] requestBytes, byte[] responseBytes) {
        analyzeAsync(httpService, method, url, requestBytes, responseBytes, null);
    }

    /**
     * {@link #analyzeAsync(HttpService, String, String, byte[], byte[])} 的扩展版：
     * 在全局 {@code resultHandler} 执行后再多触发一次 per-call 回调
     * {@code onResult}，给"需要看到本次结果才能决定后续动作"的调用方用
     * （典型场景：失败时让调用方回滚 dedup 指纹）。可空。
     */
    public void analyzeAsync(HttpService httpService, String method, String url,
                             byte[] requestBytes, byte[] responseBytes,
                             Consumer<AnalysisResult> onResult) {
        // 在线程切换前先拷贝：调用方传入的字节数组是本类唯一持有者，跨线程前必须脱钩。
        final byte[] safeReqBytes = clone(requestBytes);
        final byte[] safeRespBytes = clone(responseBytes);
        try {
            // 1. 重建 HttpRequest —— 用 raw 字节 + httpService 拼出完整请求对象
            //    静态工厂方法位于 HttpRequest 接口本身（不是 api.http()），Montoya 文档约定。
            //    注意：safeReqBytes 上面已 clone 过一次，此处直接引用即可（不再二次拷贝）。
            ByteArray reqByteArray = ByteArray.byteArray(safeReqBytes);
            HttpRequest request = httpService == null
                    ? HttpRequest.httpRequest(reqByteArray)
                    : HttpRequest.httpRequest(httpService, reqByteArray);

            // 2. 重建 HttpResponse（可选）—— 同样走 raw 字节路径
            HttpResponse response = null;
            if (safeRespBytes != null && safeRespBytes.length > 0) {
                response = HttpResponse.httpResponse(ByteArray.byteArray(safeRespBytes));
            }

            // 3. 走主分析器；它内部已有自己的线程池 + 取消逻辑。
            //    被动分析是"全速"模式：不开新线程，由调用方在 PassiveAnalysisExecutor 线程里跑。
            //    这里直接调用 private analyze(...) 不行，所以走 sync 路径：
            //    用 analyzeAsync + 回调。
            //    但这会再次把任务排队进 TrafficAnalyzer 的单线程队列，潜在排队更慢——
            //    实际场景下 TrafficAnalyzer 队列瞬时清空，性能可接受；
            //    想要"同线程执行"需要 TrafficAnalyzer 单独暴露同步入口。
            final HttpResponse finalResponse = response;
            final Consumer<AnalysisResult> safeOnResult = onResult;
            // 句柄持有者：回调需要把"自己"从 inFlight 摘掉，而 lambda 创建时 task 还没返回，
            // 故用一个 holder 传递。
            final AtomicReference<AnalysisTask> holder = new AtomicReference<>();
            AnalysisTask task = trafficAnalyzer.analyzeAsync(request, finalResponse, result -> {
                AnalysisTask finished = holder.get();
                if (finished != null) {
                    inFlight.remove(finished);
                }
                // 异常已经在 TrafficAnalyzer 内被 try-catch 化为 AnalysisResult.error；
                // 这里再兜一道：避免 resultHandler 自身抛异常把 TrafficAnalyzer 队列污染。
                try {
                    resultHandler.handle(result, safeReqBytes, safeRespBytes);
                } catch (RuntimeException handlerEx) {
                    logError("被动分析结果回调失败：" + handlerEx.getMessage(), handlerEx);
                }
                // per-call 回调：dedup 回滚等"调用方根据结果决定后续动作"的场景。
                // 独立 try-catch：避免 per-call 异常污染 trafficAnalyzer 的后续任务派发。
                if (safeOnResult != null) {
                    try {
                        safeOnResult.accept(result);
                    } catch (RuntimeException onResultEx) {
                        logError("被动分析 per-call 回调失败：" + onResultEx.getMessage(), onResultEx);
                    }
                }
            });
            holder.set(task);
            inFlight.add(task);
        } catch (RuntimeException ex) {
            // 重建 HttpRequest / HttpResponse 失败（例如 raw 字节损坏）—— 不影响 Proxy 流量。
            logError("被动分析请求重建失败：" + method + " " + url + "：" + ex.getMessage(), ex);
        }
    }

    /** 防御性拷贝：避免外部数组在 PassiveAnalysisExecutor 线程执行时被改写。 */
    private static byte[] clone(byte[] src) {
        return src == null ? new byte[0] : src.clone();
    }

    /**
     * 取消所有在飞的被动分析（插件卸载路径调用）。
     *
     * <p>为什么必须显式取消：{@code PassiveAnalysisExecutor.shutdownNow()} 只能中断线程，
     * 而 AI 等待走的是不响应中断的 {@code CompletableFuture.join()}——不调本方法的话，
     * 卸载后这些请求会继续占着连接直到 JDK HTTP 超时。</p>
     */
    public void cancelInFlight() {
        for (AnalysisTask task : inFlight) {
            try {
                task.cancel();
            } catch (RuntimeException ex) {
                logError("取消被动分析任务失败：" + ex.getMessage(), ex);
            }
        }
        inFlight.clear();
    }

    /**
     * 输出错误日志到 Burp Extender。
     *
     * <p>{@code api} 为 null 时（测试场景）保留 {@link Throwable#printStackTrace()}
     * 兜底——单测里没人看 stderr，但异常栈仍然能在测试输出里出现，便于定位失败原因。</p>
     */
    private void logError(String message, Throwable t) {
        if (api != null) {
            api.logging().logToError("AuditAI " + message, t);
            return;
        }
        if (t != null) {
            t.printStackTrace(System.err);
        }
    }
}
