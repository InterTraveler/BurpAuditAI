package com.auditai.burp.http;

import com.auditai.burp.ai.CancellableAiCall;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 一次<b>可取消</b>的分析任务句柄（由 {@link TrafficAnalyzer#analyzeAsync} 返回）。
 *
 * <p>每个页签持有自己当前任务的句柄：</p>
 * <ul>
 *   <li>任务<b>还在排队</b>（尚未开始）：调用 {@link #cancel()} 置取消标志，
 *       任务真正运行时检测到标志会直接放弃，不调用 AI；</li>
 *   <li>任务<b>正在执行</b>（AI 请求进行中）：调用 {@link #cancel()} 会中断底层
 *       HTTP 请求（{@link CancellableAiCall#cancel()}）；</li>
 *   <li>不同页签持有各自的任务句柄，取消互不影响。</li>
 * </ul>
 */
public final class AnalysisTask implements Runnable {

    /** 取消标志：排队期间被取消后，任务运行时据此直接放弃。 */
    private final AtomicBoolean cancelled = new AtomicBoolean(false);

    /** 当前正在执行的 AI 调用（运行时才设置）。 */
    private final AtomicReference<CancellableAiCall> activeCall = new AtomicReference<>();

    /** 实际分析主体（由 TrafficAnalyzer 注入）。 */
    private volatile Runnable body;

    /** 由 TrafficAnalyzer 注入分析主体。 */
    void setBody(Runnable body) {
        this.body = body;
    }

    /** 任务运行时把自己正在执行的 AI 调用注册进来，供 cancel() 中断。 */
    void attachCall(CancellableAiCall call) {
        activeCall.set(call);
    }

    /** 是否已被取消（排队期间被取消时为 true）。 */
    boolean isCancelled() {
        return cancelled.get();
    }

    /**
     * 取消本次分析：中断正在进行的 AI 请求；尚未开始的任务置取消标志即可。
     *
     * @return 是否成功取消。
     */
    public boolean cancel() {
        cancelled.set(true);
        CancellableAiCall call = activeCall.get();
        if (call != null) {
            return call.cancel();
        }
        return true; // 排队中：仅置标志，任务运行时自行放弃
    }

    @Override
    public void run() {
        Runnable b = body;
        if (b != null) {
            b.run();
        }
    }
}
