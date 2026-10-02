package com.auditai.burp.http;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@link FindingStore} 的内存索引、排序、监听器、持久化的单元测试。 */
class FindingStoreTest {

    @Test
    void addFindingsDedupesByFindingId(@TempDir Path tempDir) throws Exception {
        try (FindingStore store = new FindingStore(tempDir, 100)) {
            AnalysisResult r1 = AnalysisResult.success(1000L, "GET", "http://a", 200,
                    "summary", 10L,
                    List.of(Finding.create("XSS", 80, "high", "desc",
                            "GET", "http://a", 1000L, 1000L)));
            store.addFindings(r1);
            assertEquals(1, store.list().size());
            // 重复添加相同 finding 不会重复入库
            store.addFindings(r1);
            assertEquals(1, store.list().size());
        }
    }

    @Test
    void listOrdersByCapturedTimeAscending(@TempDir Path tempDir) throws Exception {
        // 关键回归测试：list() 必须按安装时间升序（最旧在顶、最新在底），与"历史"页签一致。
        // 同 capturedAtMillis 时退化为插入顺序（List.sort stable）。
        try (FindingStore store = new FindingStore(tempDir, 100)) {
            // 故意以"乱序"加入：先 B(200) → A(100) → C(300)
            store.addFindings(AnalysisResult.success(200L, "GET", "http://2", 200, "s", 0L,
                    List.of(Finding.create("B", 50, "high", "d2", "GET", "http://2", 200L, 200L))));
            store.addFindings(AnalysisResult.success(100L, "GET", "http://1", 200, "s", 0L,
                    List.of(Finding.create("A", 50, "low", "d1", "GET", "http://1", 100L, 100L))));
            store.addFindings(AnalysisResult.success(300L, "GET", "http://3", 200, "s", 0L,
                    List.of(Finding.create("C", 50, "high", "d3", "GET", "http://3", 300L, 300L))));
            List<Finding> sorted = store.list();
            // 安装时间升序：A(100) → B(200) → C(300)，与 confidence / severity 完全无关
            assertEquals("A", sorted.get(0).getType());
            assertEquals("B", sorted.get(1).getType());
            assertEquals("C", sorted.get(2).getType());
        }
    }

    @Test
    void listStableForSameCapturedTime(@TempDir Path tempDir) throws Exception {
        // capturedAtMillis 完全相等时（极少见，但占位 finding / 同毫秒批处理可能撞上），
        // 退化为 LinkedHashMap 插入顺序（稳定排序保证）。
        try (FindingStore store = new FindingStore(tempDir, 100)) {
            // 同时间戳 = 500，三条 finding 在同一次 addFindings 里按数组顺序入库
            store.addFindings(AnalysisResult.success(500L, "GET", "http://x", 200, "s", 0L,
                    List.of(
                            Finding.create("First", 30, "critical", "d", "GET", "http://x", 500L, 500L),
                            Finding.create("Second", 90, "low", "d", "GET", "http://x", 500L, 500L),
                            Finding.create("Third", 50, "high", "d", "GET", "http://x", 500L, 500L)
                    )));
            List<Finding> sorted = store.list();
            // 时间相同时顺序完全由入库顺序决定：First → Second → Third
            assertEquals("First", sorted.get(0).getType());
            assertEquals("Second", sorted.get(1).getType());
            assertEquals("Third", sorted.get(2).getType());
        }
    }

    @Test
    void listenerFiresOnChanges(@TempDir Path tempDir) throws Exception {
        try (FindingStore store = new FindingStore(tempDir, 100)) {
            AtomicInteger count = new AtomicInteger();
            store.addListener(ignored -> count.incrementAndGet());
            // 没有 finding 的 result 不应触发（hasContext 但无 findings）
            store.addFindings(AnalysisResult.success(1L, "GET", "http://a", 200, "s", 0L));
            assertEquals(0, count.get());
            // 有 finding 触发
            store.addFindings(AnalysisResult.success(2L, "GET", "http://b", 200, "s", 0L,
                    List.of(Finding.create("X", 50, "info", "d", "GET", "http://b", 2L, 2L))));
            assertEquals(1, count.get());
            // clear 触发
            store.clear();
            assertEquals(2, count.get());
        }
    }

    @Test
    void contextForReturnsStoredReport(@TempDir Path tempDir) throws Exception {
        try (FindingStore store = new FindingStore(tempDir, 100)) {
            Finding f = Finding.create("XSS", 80, "high", "desc",
                    "GET", "http://a", 1000L, 999L);
            store.addFindings(AnalysisResult.success(999L, "GET", "http://a", 200,
                    "完整报告内容", 50L, List.of(f)));
            FindingStore.AnalysisContext ctx = store.contextFor(f);
            assertEquals(999L, ctx.getTimestampMillis());
            assertEquals("GET", ctx.getMethod());
            assertEquals("http://a", ctx.getUrl());
            assertEquals(200, ctx.getStatusCode());
            assertEquals("完整报告内容", ctx.getSummary());
        }
    }

    @Test
    void persistAndReload(@TempDir Path tempDir) throws Exception {
        try (FindingStore store = new FindingStore(tempDir, 100)) {
            store.addFindings(AnalysisResult.success(1000L, "GET", "http://a", 200,
                    "summary-A", 50L,
                    List.of(Finding.create("XSS", 80, "high", "descA",
                            "GET", "http://a", 1000L, 1000L))));
            store.addFindings(AnalysisResult.success(2000L, "GET", "http://b", 404,
                    "summary-B", 60L,
                    List.of(Finding.create("SQL", 95, "critical", "descB",
                            "GET", "http://b", 2000L, 2000L))));
        }
        // 重新打开：数据应恢复
        try (FindingStore reopened = new FindingStore(tempDir, 100)) {
            List<Finding> list = reopened.list();
            assertEquals(2, list.size());
            // 安装时间升序：XSS(1000) 在前，SQL(2000) 在后（与 confidence 无关）
            assertEquals("XSS", list.get(0).getType());
            assertEquals(80, list.get(0).getConfidence());
            assertEquals("SQL", list.get(1).getType());
            // 报告内容也已恢复
            FindingStore.AnalysisContext ctx = reopened.contextFor(list.get(0));
            assertEquals("summary-A", ctx.getSummary());
        }
    }

    @Test
    void addFindingsWithoutFindingsStillCachesContext(@TempDir Path tempDir) throws Exception {
        try (FindingStore store = new FindingStore(tempDir, 100)) {
            store.addFindings(AnalysisResult.success(123L, "GET", "http://a", 200,
                    "本次未发现问题", 50L));
            Finding probe = Finding.create("X", 50, "info", "d",
                    "GET", "http://a", 123L, 123L);
            FindingStore.AnalysisContext ctx = store.contextFor(probe);
            assertEquals("本次未发现问题", ctx.getSummary());
        }
    }

    @Test
    void placeholderFindingsPersistAndReload(@TempDir Path tempDir) throws Exception {
        try (FindingStore store = new FindingStore(tempDir, 100)) {
            store.addFindings(AnalysisResult.success(123L, "GET", "http://a", 200,
                    "完整 analysis 文本", 50L,
                    List.of(Finding.placeholder("截取自 analysis", Severity.HIGH,
                            "GET", "http://a", 123L, 123L))));
        }
        try (FindingStore reopened = new FindingStore(tempDir, 100)) {
            List<Finding> list = reopened.list();
            assertEquals(1, list.size());
            Finding f = list.get(0);
            assertTrue(f.isPlaceholder());
            assertEquals("需关注", f.getType());
            assertEquals("截取自 analysis", f.getDescription());
            assertSame(Severity.HIGH, f.getSeverity());
        }
    }

    @Test
    void primarySortIsCapturedTimeNotConfidence(@TempDir Path tempDir) throws Exception {
        // 关键回归测试：list() 主排序是"安装时间升序"，与 confidence / severity 完全脱钩。
        // 一个 critical/confidence 极低但安装时间晚，一个 high/confidence 极高但安装时间早
        // ——按新规则"晚安装"在后，"早安装"在前，而不是按可信度排。
        try (FindingStore store = new FindingStore(tempDir, 100)) {
            // Critical 装得晚（capturedAt=2000），confidence=30
            store.addFindings(AnalysisResult.success(0L, "GET", "http://1", 200, "s", 0L,
                    List.of(Finding.create("Critical", 30, "critical", "d",
                            "GET", "http://1", 2000L, 0L))));
            // High 装得早（capturedAt=1000），confidence=90
            store.addFindings(AnalysisResult.success(0L, "GET", "http://2", 200, "s", 0L,
                    List.of(Finding.create("High", 90, "high", "d",
                            "GET", "http://2", 1000L, 0L))));
            List<Finding> list = store.list();
            // 安装时间升序：High(1000) 在前，Critical(2000) 在后
            assertEquals("High", list.get(0).getType());
            assertEquals("Critical", list.get(1).getType());
            // confidence 不再是排序键：高 confidence(90) 在低 confidence(30) 之前只是巧合
            assertEquals(90, list.get(0).getConfidence());
            assertEquals(30, list.get(1).getConfidence());
        }
    }

    @Test
    void contextCarriesRequestAndResponseBytes(@TempDir Path tempDir) throws Exception {
        // 分析时附带原文 → AnalysisContext 里能拿到 → UI 选中 finding 时直接显示
        try (FindingStore store = new FindingStore(tempDir, 100)) {
            byte[] req = "GET /api?id=1 HTTP/1.1\r\nHost: x\r\n\r\n".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            Finding f = Finding.create("X", 50, "info", "d",
                    "GET", "http://x", 123L, 123L);
            store.addFindings(AnalysisResult.success(123L, "GET", "http://x", 200, "s", 0L, List.of(f)),
                    req, resp);
            FindingStore.AnalysisContext ctx = store.contextFor(f);
            assertNotNull(ctx.getRequestBytes());
            assertNotNull(ctx.getResponseBytes());
            assertEquals("GET /api?id=1", new String(ctx.getRequestBytes(),
                    java.nio.charset.StandardCharsets.UTF_8).split(" ")[0] + " " + new String(ctx.getRequestBytes(),
                    java.nio.charset.StandardCharsets.UTF_8).split(" ")[1]);
        }
    }

    @Test
    void requestAndResponseBytesNotPersisted(@TempDir Path tempDir) throws Exception {
        // 关键约束：request/response 字节只内存保留，重启后必须为 null
        // （避免 findings-index.json 暴涨；让 UI 重启后回退到 AnalysisHistoryStore 反查）
        try (FindingStore store = new FindingStore(tempDir, 100)) {
            byte[] req = "GET / HTTP/1.1\r\n\r\n".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] resp = "HTTP/1.1 200 OK\r\n\r\n".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            Finding f = Finding.create("X", 50, "info", "d",
                    "GET", "http://x", 1L, 1L);
            store.addFindings(AnalysisResult.success(1L, "GET", "http://x", 200, "s", 0L, List.of(f)),
                    req, resp);
        }
        // 重新打开 → context 里没有原文（持久化只写 finding 元数据 + summary）
        try (FindingStore reopened = new FindingStore(tempDir, 100)) {
            FindingStore.AnalysisContext ctx = reopened.contextFor(reopened.list().get(0));
            assertEquals(null, ctx.getRequestBytes());
            assertEquals(null, ctx.getResponseBytes());
        }
    }

    @Test
    void contextCountCappedToPreventMemoryExplosion(@TempDir Path tempDir) throws Exception {
        // 关键回归测试：内存安全
        // 用 maxContexts=3 验证：连续 addFindings 超过上限时，最旧 context 被淘汰
        // 但 finding 列表和 summary 仍保留。
        try (FindingStore store = new FindingStore(tempDir, 100, 3)) {
            // 5 次分析，每次 1MB 字节
            byte[] big = new byte[1024 * 1024];
            for (int i = 0; i < 5; i++) {
                long ts = 1000L + i;
                Finding f = Finding.create("X" + i, 50, "info", "d",
                        "GET", "http://x" + i, ts, ts);
                store.addFindings(AnalysisResult.success(ts, "GET", "http://x" + i, 200, "s" + i, 0L, List.of(f)),
                        big, big);
            }
            // 5 条 finding 都应该保留（远低于 maxFindings=100）
            assertEquals(5, store.list().size());
            // 但 context 最多 3 条（最旧的 2 条被淘汰）
            // 通过检查 request/response 字节的可访问性来验证：找最早两条 finding
            // 应该拿不到 bytes（context 已被淘汰），最新的 3 条应能拿到
            FindingStore.AnalysisContext ctx0 = store.contextFor(store.list().stream()
                    .filter(f -> f.getType().equals("X0")).findFirst().orElseThrow());
            // X0 是最早 context：被淘汰，bytes 应该为 null（兜底 context）
            assertEquals(null, ctx0.getRequestBytes());
            assertEquals(null, ctx0.getResponseBytes());
            // X4 是最新 context：仍能拿到原文
            FindingStore.AnalysisContext ctx4 = store.contextFor(store.list().stream()
                    .filter(f -> f.getType().equals("X4")).findFirst().orElseThrow());
            assertNotNull(ctx4.getRequestBytes());
            assertEquals(1024 * 1024, ctx4.getRequestBytes().length);
        }
    }

    @Test
    void contextForEvictedFindingReturnsFallbackWithFindingFields(@TempDir Path tempDir) throws Exception {
        // 关键边界：context 淘汰后，contextFor 不应返回 null（之前已经返回兜底）
        // 兜底 context 用 finding 自身字段填充，但 request/response bytes 为 null
        try (FindingStore store = new FindingStore(tempDir, 100, 2)) {
            byte[] big = new byte[1024 * 1024];
            for (int i = 0; i < 3; i++) {
                long ts = 1000L + i;
                Finding f = Finding.create("X" + i, 50, "info", "d",
                        "GET", "http://x" + i, ts, ts);
                store.addFindings(AnalysisResult.success(ts, "GET", "http://x" + i, 200, "s" + i, 0L, List.of(f)),
                        big, big);
            }
            // X0 已被淘汰：兜底 context 仍能从 finding 自身字段构造 method / url / summary 为空
            Finding f0 = store.list().stream()
                    .filter(f -> f.getType().equals("X0")).findFirst().orElseThrow();
            FindingStore.AnalysisContext ctx0 = store.contextFor(f0);
            assertNotNull(ctx0);
            // 兜底 context：method / url 来自 finding（兜底逻辑）
            assertEquals("GET", ctx0.getMethod());
            assertEquals("http://x0", ctx0.getUrl());
            // request/response 字节为 null（让 UI 回退到 AnalysisHistoryStore 反查）
            assertEquals(null, ctx0.getRequestBytes());
            assertEquals(null, ctx0.getResponseBytes());
        }
    }

    @Test
    void removeByFindingIdRemovesEntryAndNotifies(@TempDir Path tempDir) throws Exception {
        try (FindingStore store = new FindingStore(tempDir, 100)) {
            Finding f1 = Finding.create("XSS", 80, "high", "d1", "GET", "http://a", 1L, 1L);
            Finding f2 = Finding.create("SQLi", 90, "high", "d2", "GET", "http://b", 2L, 1L);
            store.addFindings(AnalysisResult.success(1L, "GET", "http://a", 200, "s", 0L, List.of(f1, f2)));
            assertEquals(2, store.list().size());

            AtomicInteger notifications = new AtomicInteger();
            store.addListener(ignored -> notifications.incrementAndGet());

            // 删除存在的 finding：返回 true、list 少 1 条、通知一次
            assertTrue(store.remove(f1.getFindingId()));
            assertEquals(1, store.list().size());
            assertEquals(1, notifications.get());
            assertEquals("SQLi", store.list().get(0).getType());

            // 不存在的 findingId：返回 false、不通知
            assertFalse(store.remove("not-exists"));
            assertEquals(1, notifications.get());

            // null / 空白：返回 false、不抛异常
            assertFalse(store.remove(null));
            assertFalse(store.remove(""));
            assertFalse(store.remove("   "));
        }
    }

    @Test
    void removeLastFindingOfAnalysisEvictsOrphanContext(@TempDir Path tempDir) throws Exception {
        // 删除一条 finding 后，若它的 analysisTimestamp 没有其它 finding 引用，
        // 对应 AnalysisContext 也应被回收（避免 context 表长期持有已无主 finding 的字节）。
        try (FindingStore store = new FindingStore(tempDir, 100)) {
            Finding f1 = Finding.create("XSS", 80, "high", "d1", "GET", "http://a", 1L, 10L);
            Finding f2 = Finding.create("SQLi", 70, "high", "d2", "GET", "http://b", 2L, 20L);
            // 两次独立分析：f1 → ts=10（带 req/resp 字节），f2 → ts=20（带另外一组字节）
            store.addFindings(AnalysisResult.success(10L, "GET", "http://a", 200, "ctxA", 0L, List.of(f1)),
                    new byte[]{1, 2, 3}, new byte[]{4});
            store.addFindings(AnalysisResult.success(20L, "GET", "http://b", 200, "ctxB", 0L, List.of(f2)),
                    new byte[]{5}, new byte[]{6});

            Finding stored1 = store.list().stream()
                    .filter(f -> f.getAnalysisTimestamp() == 10L).findFirst().orElseThrow();
            Finding stored2 = store.list().stream()
                    .filter(f -> f.getAnalysisTimestamp() == 20L).findFirst().orElseThrow();
            assertEquals(2, store.list().size());

            // 删除 f1：ts=10 没有其它引用 → context[10] 被回收
            assertTrue(store.remove(stored1.getFindingId()));
            assertEquals(1, store.list().size());
            // 仍存在的 f2 应能拿到自己 ts=20 的原文
            FindingStore.AnalysisContext ctx20 = store.contextFor(stored2);
            assertNotNull(ctx20.getRequestBytes());
            assertNotNull(ctx20.getResponseBytes());
        }
    }

    @Test
    void removeOneOfMultipleFindingsWithSameTimestampKeepsContext(@TempDir Path tempDir) throws Exception {
        // 同一 analysisTimestamp 下有两条 finding：删一条，另一条仍引用 context → 不应回收
        try (FindingStore store = new FindingStore(tempDir, 100)) {
            Finding f1 = Finding.create("XSS", 80, "high", "d1", "GET", "http://a", 1L, 10L);
            Finding f2 = Finding.create("SQLi", 70, "high", "d2", "GET", "http://a", 2L, 10L);
            store.addFindings(AnalysisResult.success(10L, "GET", "http://a", 200, "ctx", 0L, List.of(f1, f2)),
                    new byte[]{1, 2, 3}, new byte[]{4});

            List<Finding> all = store.list();
            assertEquals(2, all.size());
            Finding one = all.get(0);
            Finding other = all.get(1);

            // 删一条：另一条仍引用 ts=10 → context 不应被回收
            assertTrue(store.remove(one.getFindingId()));
            assertEquals(1, store.list().size());

            FindingStore.AnalysisContext ctx = store.contextFor(other);
            assertNotNull(ctx.getRequestBytes());
            assertNotNull(ctx.getResponseBytes());
        }
    }
}
