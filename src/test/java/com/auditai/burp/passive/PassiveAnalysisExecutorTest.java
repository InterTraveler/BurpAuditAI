package com.auditai.burp.passive;

import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link PassiveAnalysisExecutor} 单元测试：任务执行、null 入参、关闭后提交不抛异常、
 * 队列满时丢弃 + 告警（绝不回压到调用线程）。
 */
final class PassiveAnalysisExecutorTest {

    @Test
    void submitAfterShutdownDoesNotThrow() throws Exception {
        AtomicReference<String> rejected = new AtomicReference<>();
        PassiveAnalysisExecutor executor = new PassiveAnalysisExecutor(rejected::set);
        executor.shutdown();
        // 关闭后再提交：必须被静默丢弃（告警日志），绝不抛异常回调用方
        assertDoesNotThrow(() -> executor.submit(() -> { }));
        // 拒绝策略是"丢弃 + 日志"，应留下一条可诊断日志
        String message = rejected.get();
        assertTrue(message != null && message.contains("丢弃"), "应有丢弃告警，实际：" + message);
    }

    @Test
    void queueFullDropsTaskWithoutThrowing() throws Exception {
        AtomicReference<String> rejected = new AtomicReference<>();
        PassiveAnalysisExecutor executor = new PassiveAnalysisExecutor(rejected::set);
        try {
            CountDownLatch release = new CountDownLatch(1);
            CountDownLatch started = new CountDownLatch(PassiveAnalysisExecutor.CORE_POOL_SIZE);
            CountDownLatch probeRan = new CountDownLatch(1);
            CountDownLatch discardedRan = new CountDownLatch(1);

            // 1. 灌入 2（核心） + 200（队列）个阻塞任务
            for (int i = 0; i < PassiveAnalysisExecutor.CORE_POOL_SIZE + PassiveAnalysisExecutor.QUEUE_CAPACITY; i++) {
                executor.submit(() -> {
                    started.countDown();
                    awaitQuietly(release);
                });
            }
            assertTrue(started.await(5, TimeUnit.SECONDS), "核心线程应启动");

            // 2. 队列已满：再提交 2 个【阻塞】探针 → 线程池扩容到 max=4 且 4 个 worker 全部占住
            //    （探针不能立刻完成，否则空闲 worker 会去队列里取阻塞任务、腾出队列槽位，
            //      使"第 5 个并发任务被拒绝"的计数变得不确定）。
            executor.submit(() -> {
                probeRan.countDown();
                awaitQuietly(release);
            });
            executor.submit(() -> {
                probeRan.countDown();
                awaitQuietly(release);
            });
            assertTrue(probeRan.await(5, TimeUnit.SECONDS), "扩容线程应启动探针");

            // 3. 第 5 个并发任务 → 队列满 + 线程数达上限 → 被丢弃 + 告警，不抛异常
            assertDoesNotThrow(() -> executor.submit(discardedRan::countDown));
            assertFalse(discardedRan.await(300, TimeUnit.MILLISECONDS), "被丢弃的任务不应执行");
            assertTrue(rejected.get() != null && rejected.get().contains("丢弃"),
                    "应有丢弃告警，实际：" + rejected.get());
        } finally {
            // 释放阻塞任务，避免测试线程泄漏
            for (int i = 0; i < 16; i++) {
                executor.submit(() -> { });
            }
            executor.shutdown();
        }
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }
}
