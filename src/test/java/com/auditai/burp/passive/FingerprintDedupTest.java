package com.auditai.burp.passive;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link FingerprintDedup} 单元测试：markIfNew 语义、容量上限 + LRU 淘汰、
 * 线程安全冒烟。
 */
final class FingerprintDedupTest {

    @Test
    void markIfNewReturnsTrueOnlyOnFirstSeen() {
        FingerprintDedup dedup = new FingerprintDedup();
        assertTrue(dedup.markIfNew("fp-1"));
        assertFalse(dedup.markIfNew("fp-1"));
        assertTrue(dedup.markIfNew("fp-2"));
        assertFalse(dedup.markIfNew("fp-2"));
    }

    @Test
    void capacityEvictsLeastRecentlyUsed() {
        // 容量 3：插入 A B C；访问（命中）A 使其成为最近使用；插入 D 应淘汰最久未用的 B。
        FingerprintDedup dedup = new FingerprintDedup(3);
        assertTrue(dedup.markIfNew("A"));
        assertTrue(dedup.markIfNew("B"));
        assertTrue(dedup.markIfNew("C"));
        assertFalse(dedup.markIfNew("A")); // 命中 A → A 变为最近使用
        assertTrue(dedup.markIfNew("D"));  // 触发淘汰：最久未用的 B 出局
        assertEquals(3, dedup.size());
        assertTrue(dedup.contains("A"));
        assertFalse(dedup.contains("B"));
        assertTrue(dedup.contains("C"));
        assertTrue(dedup.contains("D"));
    }

    @Test
    void remove_unmarksOnlyTheTargetedFingerprint() {
        // 复现"历史页签删除单条记录 → 该记录指纹从 dedup 移除 → 同 URL 可重新分析"。
        FingerprintDedup dedup = new FingerprintDedup();
        assertTrue(dedup.markIfNew("fp-keep"));
        assertTrue(dedup.markIfNew("fp-drop"));
        assertFalse(dedup.markIfNew("fp-drop"));

        dedup.remove("fp-drop");
        assertEquals(1, dedup.size());
        assertFalse(dedup.contains("fp-drop"), "被移除的指纹不应再被标记");
        assertTrue(dedup.contains("fp-keep"), "其它指纹不受影响");

        // 移除后该指纹应被重新视为"首次"——删除记录后同 URL 新报文的业务期望
        assertTrue(dedup.markIfNew("fp-drop"));
    }

    @Test
    void remove_handlesNullUnknownAndUnmarkedFingerprintsSafely() {
        FingerprintDedup dedup = new FingerprintDedup();
        assertTrue(dedup.markIfNew("fp-1"));
        // null / 未见过的指纹 / 空串：均为安全 no-op
        dedup.remove(null);
        dedup.remove("never-seen");
        dedup.remove("");
        assertEquals(1, dedup.size());
        assertTrue(dedup.contains("fp-1"));
        // 对已移除指纹再移除：no-op，不抛异常
        dedup.remove("fp-1");
        dedup.remove("fp-1");
        assertEquals(0, dedup.size());
    }

    @Test
    void clearResetsAllFingerprints() {
        // 复现"清空历史 → 同 URL 应该重新分析"：clear 后已知指纹必须重新返回 true。
        FingerprintDedup dedup = new FingerprintDedup();
        assertTrue(dedup.markIfNew("fp-1"));
        assertTrue(dedup.markIfNew("fp-2"));
        assertFalse(dedup.markIfNew("fp-1"));
        assertEquals(2, dedup.size());

        dedup.clear();
        assertEquals(0, dedup.size());
        assertFalse(dedup.contains("fp-1"));
        assertFalse(dedup.contains("fp-2"));

        // clear 后两个指纹都应被重新视为"首次"——这是"清空历史"操作的业务期望。
        assertTrue(dedup.markIfNew("fp-1"));
        assertTrue(dedup.markIfNew("fp-2"));
        assertEquals(2, dedup.size());
    }

    @Test
    void concurrentMarkIfNewIsSafeAndAccurate() throws InterruptedException {
        FingerprintDedup dedup = new FingerprintDedup(10_000);
        int threads = 8;
        int perThread = 1_000;
        Thread[] workers = new Thread[threads];
        AtomicReference<Throwable> failure = new AtomicReference<>();
        for (int i = 0; i < threads; i++) {
            final int seed = i;
            workers[i] = new Thread(() -> {
                try {
                    for (int j = 0; j < perThread; j++) {
                        dedup.markIfNew("fp-" + seed + "-" + j);
                    }
                } catch (Throwable t) {
                    failure.set(t);
                }
            });
            workers[i].start();
        }
        for (Thread w : workers) {
            w.join();
        }
        if (failure.get() != null) {
            throw new AssertionError("并发 markIfNew 失败", failure.get());
        }
        // 每个指纹恰好被标记一次：无重复无丢失
        assertEquals(threads * perThread, dedup.size());
        Set<String> expected = new HashSet<>();
        for (int i = 0; i < threads; i++) {
            for (int j = 0; j < perThread; j++) {
                expected.add("fp-" + i + "-" + j);
            }
        }
        for (String fp : expected) {
            assertTrue(dedup.contains(fp), "指纹应被标记：" + fp);
        }
    }
}
