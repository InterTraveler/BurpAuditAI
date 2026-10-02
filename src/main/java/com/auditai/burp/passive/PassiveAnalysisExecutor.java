package com.auditai.burp.passive;

import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * 被动分析的独立线程池：显式创建 {@link ThreadPoolExecutor}，与 {@code TrafficAnalyzer}
 * 的单线程分析器隔离——AI 调用慢、被队列阻塞都不会影响 Proxy 回调或 UI 渲染。
 *
 * <p>参数（合理默认值，按"被动分析"语义选定，不暴露给用户配置）：</p>
 * <ul>
 *   <li>核心线程数 = 2：低并发即可消化大多数渗透测试流量；</li>
 *   <li>最大线程数 = 4：流量激增时（跑自动化扫描）允许临时扩容；</li>
 *   <li>队列容量 = 200：积压缓冲，避免偶发毛刺直接触发拒绝；</li>
 *   <li>空闲线程存活 = 60 秒：峰值后自动缩回到核心线程数；</li>
 *   <li>线程工厂 = 自定义守护线程（线程名前缀 {@code burp-audit-ai-passive-}），不阻塞 Burp 退出；</li>
 *   <li>拒绝策略 = 自定义"丢弃 + 写告警日志"：被动分析是"锦上添花"功能，绝不能因为
 *       队列满/线程池关闭就回压到 Burp Proxy 回调线程；丢一条比卡住 Burp 划算。</li>
 * </ul>
 *
 * <p>线程安全：所有方法均可被任意线程调用。</p>
 */
public final class PassiveAnalysisExecutor {

    /** 核心线程数。 */
    public static final int CORE_POOL_SIZE = 2;

    /** 最大线程数。 */
    public static final int MAX_POOL_SIZE = 4;

    /** 任务队列容量。 */
    public static final int QUEUE_CAPACITY = 200;

    /** 空闲线程存活时间（毫秒）。 */
    public static final long KEEP_ALIVE_MS = 60_000L;

    private final ThreadPoolExecutor executor;
    private final Consumer<String> errorLogger;

    /**
     * 使用默认参数构造；不指定 errorLogger 时静默吞掉拒绝/关闭异常——
     * 默认构造仅用于单测，生产路径（{@code AuditAiExtension}）必须走
     * {@link #PassiveAnalysisExecutor(Consumer)} 注入 {@code api.logging().logToError}。
     * 走 stderr 容易被"刷屏"且错过 Burp 自己的日志窗口，因此默认按静默处理。
     */
    public PassiveAnalysisExecutor() {
        this(msg -> { });
    }

    /**
     * @param errorLogger 拒绝 / 关闭异常时的日志回调；可为 null（null 时静默）。
     */
    public PassiveAnalysisExecutor(Consumer<String> errorLogger) {
        this.errorLogger = errorLogger == null ? msg -> { } : errorLogger;
        this.executor = new ThreadPoolExecutor(
                CORE_POOL_SIZE,
                MAX_POOL_SIZE,
                KEEP_ALIVE_MS,
                TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>(QUEUE_CAPACITY),
                new PassiveThreadFactory());
        // 显式设置"丢弃 + 告警"拒绝策略：队列满或线程池已关闭（卸载竞态）时任务被丢弃，
        // 但必须留下一条可诊断日志——绝不能把异常抛回 Proxy 回调线程。
        executor.setRejectedExecutionHandler((task, pool) -> errorLogger.accept(
                "被动分析任务被丢弃（线程池已关闭或队列已满），当前队列深度=" + pool.getQueue().size()));
    }

    /**
     * 提交一条分析任务。队列/线程池已满时<b>丢弃 + 写告警日志</b>，
     * 绝不把异常抛回 Proxy 回调线程。
     *
     * @param task 要执行的任务；null 时直接 return。
     */
    public void submit(Runnable task) {
        if (task == null) {
            return;
        }
        try {
            executor.execute(task);
        } catch (RejectedExecutionException ex) {
            // 拒绝策略是"丢弃 + 日志"，正常情况下 execute 不会再抛；
            // 这里仅作为最后防线（策略被误改 / 未捕获路径），避免异常冒泡到调用方。
            errorLogger.accept("被动分析任务提交被拒绝：" + ex.getMessage());
        }
    }

    /**
     * 关闭线程池：插件卸载时调用。
     *
     * <p>策略：先 {@code shutdown()} 平让 worker 完成进行中的分析任务，再等最多
     * {@link #SHUTDOWN_WAIT_MS} ms，最后 {@code shutdownNow()} 兜底——保证最后一条
     * 任务能跑完（拿到完整的错误日志），同时不会卡死 Burp 重载路径。</p>
     */
    public void shutdown() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(SHUTDOWN_WAIT_MS, TimeUnit.MILLISECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            // 当前线程被中断：强制 shutdownNow + 还原中断状态
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    /** 关闭等待时间：让最后一条分析任务有时间完成。 */
    static final long SHUTDOWN_WAIT_MS = 2_000L;

    /** 当前线程池里的任务数（仅供监控/调试用）。 */
    public int queueSize() {
        return executor.getQueue().size();
    }

    /** 自定义线程工厂：守护线程 + 顺序命名 + 未捕获异常写日志。 */
    private final class PassiveThreadFactory implements ThreadFactory {
        private final AtomicInteger counter = new AtomicInteger(1);

        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(r, "burp-audit-ai-passive-" + counter.getAndIncrement());
            t.setDaemon(true);
            // 任务里如果意外抛出未捕获异常，绝不能让线程静默死掉：写日志便于诊断。
            t.setUncaughtExceptionHandler((thread, ex) -> errorLogger.accept(
                    "被动分析线程 " + thread.getName() + " 未捕获异常：" + ex.getMessage()));
            return t;
        }
    }
}
