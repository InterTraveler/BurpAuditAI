package com.auditai.burp.passive;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link PassiveAnalysisErrorBus} 单元测试：状态设置 / 清除、监听器触发、
 * 异常隔离、多次连续操作的幂等性等。
 *
 * <p>注意：{@code PassiveAnalysisErrorBus} 是进程内单例（{@link PassiveAnalysisErrorBus#INSTANCE}），
 * 每个测试方法在 {@code @BeforeEach} 中重置为 cleared 状态、在 {@code @AfterEach} 中
 * 清理监听器，避免用例间互相污染。</p>
 */
final class PassiveAnalysisErrorBusTest {

    @BeforeEach
    void resetState() {
        // 清空所有可能残留的监听器（其它测试可能误注册）
        PassiveAnalysisErrorBus.INSTANCE.clearError();
        // 当前测试不需要带 listener，但为了幂等性先 clear
    }

    @AfterEach
    void clearListeners() {
        // 监听器由测试方法内部 add/remove 配对管理；这里仅保证 cleared 状态。
        PassiveAnalysisErrorBus.INSTANCE.clearError();
    }

    @Test
    void setErrorStoresAndTriggersListener() {
        AtomicInteger callCount = new AtomicInteger();
        PassiveAnalysisErrorBus.ErrorInfo[] captured = new PassiveAnalysisErrorBus.ErrorInfo[1];

        Runnable listener = () -> {
            callCount.incrementAndGet();
            captured[0] = PassiveAnalysisErrorBus.INSTANCE.getError();
        };
        PassiveAnalysisErrorBus.INSTANCE.addListener(listener);
        try {
            PassiveAnalysisErrorBus.INSTANCE.setError("网络超时", PassiveAnalysisErrorBus.ErrorKind.NETWORK);

            assertEquals(1, callCount.get(), "setError 应触发一次监听器");
            assertNotNull(captured[0]);
            assertFalse(captured[0].isCleared());
            assertEquals("网络超时", captured[0].getMessage());
            assertEquals(PassiveAnalysisErrorBus.ErrorKind.NETWORK, captured[0].getKind());
        } finally {
            PassiveAnalysisErrorBus.INSTANCE.removeListener(listener);
        }
    }

    @Test
    void clearErrorTriggersListenerOnlyIfPreviouslyHadError() {
        AtomicInteger callCount = new AtomicInteger();
        Runnable listener = callCount::incrementAndGet;
        PassiveAnalysisErrorBus.INSTANCE.addListener(listener);
        try {
            // 1. 已经是 cleared 状态：clearError 不会触发
            PassiveAnalysisErrorBus.INSTANCE.clearError();
            assertEquals(0, callCount.get(), "cleared 状态下 clearError 不应触发监听器");

            // 2. 设置后清除：触发 1 次
            PassiveAnalysisErrorBus.INSTANCE.setError("X", PassiveAnalysisErrorBus.ErrorKind.REMOTE);
            assertEquals(1, callCount.get());
            PassiveAnalysisErrorBus.INSTANCE.clearError();
            assertEquals(2, callCount.get(), "setError + clearError 共触发 2 次");
            assertTrue(PassiveAnalysisErrorBus.INSTANCE.getError().isCleared());

            // 3. 再次 clearError：仍是 cleared，幂等
            PassiveAnalysisErrorBus.INSTANCE.clearError();
            assertEquals(2, callCount.get(), "重复 clearError 不应触发监听器");
        } finally {
            PassiveAnalysisErrorBus.INSTANCE.removeListener(listener);
        }
    }

    @Test
    void listenerThrowingDoesNotBreakOtherListeners() {
        AtomicInteger healthyCount = new AtomicInteger();
        Runnable broken = () -> {
            throw new RuntimeException("boom");
        };
        Runnable healthy = healthyCount::incrementAndGet;

        PassiveAnalysisErrorBus.INSTANCE.addListener(broken);
        PassiveAnalysisErrorBus.INSTANCE.addListener(healthy);
        try {
            // 不应抛出到 setError 调用方
            org.junit.jupiter.api.Assertions.assertDoesNotThrow(
                    () -> PassiveAnalysisErrorBus.INSTANCE.setError("X", PassiveAnalysisErrorBus.ErrorKind.NETWORK));
            assertEquals(1, healthyCount.get(), "前一个监听器抛异常不应影响后续监听器");
        } finally {
            PassiveAnalysisErrorBus.INSTANCE.removeListener(broken);
            PassiveAnalysisErrorBus.INSTANCE.removeListener(healthy);
        }
    }

    @Test
    void setErrorOverwritesPreviousError() {
        PassiveAnalysisErrorBus.INSTANCE.setError("first", PassiveAnalysisErrorBus.ErrorKind.NETWORK);
        assertEquals("first", PassiveAnalysisErrorBus.INSTANCE.getError().getMessage());

        PassiveAnalysisErrorBus.INSTANCE.setError("second", PassiveAnalysisErrorBus.ErrorKind.REMOTE);
        assertEquals("second", PassiveAnalysisErrorBus.INSTANCE.getError().getMessage());
        assertEquals(PassiveAnalysisErrorBus.ErrorKind.REMOTE,
                PassiveAnalysisErrorBus.INSTANCE.getError().getKind());
    }
}
