package com.auditai.burp.history;

import com.auditai.burp.http.AnalysisResult;
import com.auditai.burp.passive.RequestFingerprint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link AnalysisHistoryStore} 单元测试：
 * <ul>
 *   <li>基本 add / get / list 行为；</li>
 *   <li>容量淘汰：超出 maxEntries 时按插入顺序淘汰最旧；</li>
 *   <li>单条字节裁剪：超过 maxEntryBytes 的 body 走 BodyStorage 策略；</li>
 *   <li>findByDomain：基于二级域名的同域反查；</li>
 *   <li>findLatestByUrl：(method, url) 取最近一条；</li>
 *   <li>落盘 + 重启加载：index.json + bodies/ 持久化 + 重新构造可读回；</li>
 *   <li>clear：清空后 list 为空，磁盘 bodies 也清空；</li>
 *   <li>delete：按 id 删单条、不误删其它记录、释放不再被引用的 body 文件；</li>
 *   <li>老 ProxyTrafficStore 数据清理：构造时检测到 &lt;sessionRoot&gt;/bodies + index.json 自动删。</li>
 * </ul>
 */
class AnalysisHistoryStoreTest {

    @Test
    void addAndGet_basicEntry(@TempDir Path tempDir) throws Exception {
        AnalysisHistoryStore store = newStore(tempDir);
        AnalysisResult result = AnalysisResult.success(1000L, "GET", "http://example.com/api", 200,
                "ok", 50L, List.of());
        long id = store.add(result, AnalysisTrigger.MANUAL,
                "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n".getBytes(StandardCharsets.UTF_8),
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".getBytes(StandardCharsets.UTF_8), null);
        AnalysisHistoryEntry entry = store.get(id);
        assertNotNull(entry);
        assertEquals("GET", entry.getMethod());
        assertEquals("http://example.com/api", entry.getUrl());
        assertEquals(200, entry.getStatusCode());
        assertEquals(AnalysisTrigger.MANUAL, entry.getTriggerType());
        assertTrue(entry.isHasResponse());
        assertNotNull(entry.getRequestFile());
        assertNotNull(entry.getResponseFile());
    }

    @Test
    void add_errorResult_isRecorded(@TempDir Path tempDir) throws Exception {
        AnalysisHistoryStore store = newStore(tempDir);
        AnalysisResult result = AnalysisResult.error(2000L, "POST", "http://x.test/v1", 500, "boom", 30L);
        long id = store.add(result, AnalysisTrigger.PASSIVE, null, null, null);
        AnalysisHistoryEntry entry = store.get(id);
        assertNotNull(entry);
        assertEquals(AnalysisTrigger.PASSIVE, entry.getTriggerType());
        assertFalse(entry.isHasResponse());
        assertEquals("boom", entry.getError());
    }

    @Test
    void list_returnsOldestFirstForBurpNativeOrder(@TempDir Path tempDir) throws Exception {
        AnalysisHistoryStore store = newStore(tempDir);
        for (int i = 0; i < 3; i++) {
            store.add(success(1000L + i, "GET", "http://x.test/" + i),
                    AnalysisTrigger.MANUAL, null, null, null);
        }
        List<AnalysisHistoryEntry> list = store.list();
        assertEquals(3, list.size());
        // 升序：与 Burp 原生 HTTP history 一致（最旧在前、最新在底）
        assertEquals("http://x.test/0", list.get(0).getUrl());
        assertEquals("http://x.test/1", list.get(1).getUrl());
        assertEquals("http://x.test/2", list.get(2).getUrl());
    }

    @Test
    void capacity_evictsOldestInInsertionOrder(@TempDir Path tempDir) throws Exception {
        // maxEntries=3
        AnalysisHistoryStore store = new AnalysisHistoryStore(tempDir, 3, 10 * 1024 * 1024, msg -> { });
        store.add(success(1L, "GET", "http://a"), AnalysisTrigger.MANUAL, null, null, null);
        store.add(success(2L, "GET", "http://b"), AnalysisTrigger.MANUAL, null, null, null);
        store.add(success(3L, "GET", "http://c"), AnalysisTrigger.MANUAL, null, null, null);
        store.add(success(4L, "GET", "http://d"), AnalysisTrigger.MANUAL, null, null, null);
        // 容量 = 3：第 4 条进来后第 1 条被淘汰
        List<AnalysisHistoryEntry> list = store.list();
        assertEquals(3, list.size());
        // list() 按时间升序（与 Burp 原生 HTTP history 一致：最旧在前、最新在底）
        assertEquals("http://b", list.get(0).getUrl());
        assertEquals("http://c", list.get(1).getUrl());
        assertEquals("http://d", list.get(2).getUrl());
    }

    @Test
    void findByDomain_excludesOtherHostAndSelf(@TempDir Path tempDir) throws Exception {
        AnalysisHistoryStore store = newStore(tempDir);
        // 同域（api.x.test）两条
        store.add(success(100L, "GET", "http://api.x.test/v1"), AnalysisTrigger.MANUAL, null, null, null);
        store.add(success(200L, "GET", "http://api.x.test/v2"), AnalysisTrigger.MANUAL, null, null, null);
        // 不同域
        store.add(success(300L, "GET", "http://other.test/v1"), AnalysisTrigger.MANUAL, null, null, null);
        // 当前请求
        AnalysisResult current = success(999L, "GET", "http://api.x.test/v3");
        long currentId = store.add(current, AnalysisTrigger.MANUAL, null, null, null);
        List<AnalysisHistoryEntry> related = store.findByDomain(currentId, "api.x.test", 10);
        assertEquals(2, related.size());
        // 排除自己（currentId）+ 排除 other.test
        for (AnalysisHistoryEntry e : related) {
            assertFalse(e.getUrl().contains("other.test"));
            assertFalse(e.getUrl().equals("http://api.x.test/v3"));
        }
    }

    @Test
    void findLatestByUrl_returnsMostRecentMatch(@TempDir Path tempDir) throws Exception {
        AnalysisHistoryStore store = newStore(tempDir);
        store.add(success(100L, "GET", "http://x.test/api"), AnalysisTrigger.MANUAL, null, null, null);
        store.add(success(200L, "POST", "http://x.test/api"), AnalysisTrigger.PASSIVE, null, null, null);
        store.add(success(300L, "GET", "http://x.test/api"), AnalysisTrigger.MANUAL, null, null, null);
        // 默认不区分 method：取最近一条
        AnalysisHistoryEntry latest = store.findLatestByUrl(null, "http://x.test/api");
        assertNotNull(latest);
        assertEquals("GET", latest.getMethod());
        assertEquals(300L, latest.getTimestamp());
        // 区分 method：取最近一条 POST
        AnalysisHistoryEntry latestPost = store.findLatestByUrl("POST", "http://x.test/api");
        assertNotNull(latestPost);
        assertEquals("POST", latestPost.getMethod());
    }

    @Test
    void findLatestByUrl_nullOrBlankUrl_returnsNull(@TempDir Path tempDir) throws Exception {
        AnalysisHistoryStore store = newStore(tempDir);
        assertNull(store.findLatestByUrl("GET", null));
        assertNull(store.findLatestByUrl("GET", ""));
        assertNull(store.findLatestByUrl("GET", "   "));
    }

    @Test
    void persistAndReload_preservesEntries(@TempDir Path tempDir) throws Exception {
        AnalysisHistoryStore store = newStore(tempDir);
        store.add(success(1L, "GET", "http://a.test/x"),
                AnalysisTrigger.MANUAL,
                "GET /x HTTP/1.1\r\n\r\n".getBytes(StandardCharsets.UTF_8),
                "HTTP/1.1 200 OK\r\n\r\n".getBytes(StandardCharsets.UTF_8), null);
        store.add(success(2L, "POST", "http://b.test/y"),
                AnalysisTrigger.PASSIVE,
                "POST /y HTTP/1.1\r\n\r\n".getBytes(StandardCharsets.UTF_8),
                "HTTP/1.1 201 Created\r\n\r\n".getBytes(StandardCharsets.UTF_8), null);
        // 强制 flush：close 触发
        store.close();
        // index.json + bodies 存在
        assertTrue(Files.exists(tempDir.resolve("history/index.json")));
        assertTrue(Files.list(tempDir.resolve("history/bodies")).findAny().isPresent());
        // 重新打开
        AnalysisHistoryStore reopened = newStore(tempDir);
        List<AnalysisHistoryEntry> list = reopened.list();
        assertEquals(2, list.size());
        // 时间升序：先插入的 a.test/x 在前，后插入的 b.test/y 在后
        assertEquals("http://a.test/x", list.get(0).getUrl());
        assertEquals(AnalysisTrigger.MANUAL, list.get(0).getTriggerType());
        assertEquals("http://b.test/y", list.get(1).getUrl());
        assertEquals(AnalysisTrigger.PASSIVE, list.get(1).getTriggerType());
    }

    /**
     * 重启后 {@code totalBodyBytes} 必须按磁盘实际情况重建。
     *
     * <p>回归用例：该字段只在"新建 body 文件"时累加，历史实现 {@code loadIndex} 不重建它，
     * 于是重启后它停在 0——{@code DEFAULT_MAX_TOTAL_BYTES}（200MB 磁盘上限）完全失效，
     * 且后续 {@code deleteUnreferencedBodies} 的扣减会扣掉从未计入的字节（被 {@code Math.max(0,..)}
     * 夹断），计数只单向偏低。用反射直接断言私有字段，因为磁盘上限常量不可注入。</p>
     */
    @Test
    void reopenedStore_rebuildsTotalBodyBytes(@TempDir Path tempDir) throws Exception {
        AnalysisHistoryStore store = newStore(tempDir);
        store.add(success(1L, "GET", "http://a.test/x"),
                AnalysisTrigger.MANUAL,
                "GET /x HTTP/1.1\r\n\r\n".getBytes(StandardCharsets.UTF_8),
                "HTTP/1.1 200 OK\r\n\r\n".getBytes(StandardCharsets.UTF_8), null);
        long bodyBytesOnDisk = bodyDirectoryBytes(tempDir);
        assertTrue(bodyBytesOnDisk > 0, "落盘后 bodies 目录应有内容");
        store.close();

        AnalysisHistoryStore reopened = newStore(tempDir);
        assertEquals(bodyBytesOnDisk, readTotalBodyBytes(reopened),
                "重启后 totalBodyBytes 必须等于磁盘实际占用，否则 200MB 磁盘上限失效");
    }

    /** 重启后继续入库：不得因为 totalBodyBytes 错乱而把已有历史整体淘汰。 */
    @Test
    void reopenedStore_keepsExistingEntriesWhenAddingMore(@TempDir Path tempDir) throws Exception {
        AnalysisHistoryStore store = new AnalysisHistoryStore(tempDir, 3, 2L * 1024 * 1024, msg -> { });
        store.add(success(1L, "GET", "http://a.test/1"), AnalysisTrigger.MANUAL, null, null, null);
        store.add(success(2L, "GET", "http://a.test/2"), AnalysisTrigger.MANUAL, null, null, null);
        store.close();

        AnalysisHistoryStore reopened = new AnalysisHistoryStore(tempDir, 3, 2L * 1024 * 1024, msg -> { });
        assertEquals(2, reopened.list().size(), "重启后应恢复 2 条历史");
        reopened.add(success(3L, "GET", "http://a.test/3"), AnalysisTrigger.MANUAL, null, null, null);
        assertEquals(3, reopened.list().size(), "未超条数上限时不得淘汰任何条目");
        reopened.close();
    }

    /** 读私有字段 {@code totalBodyBytes}（磁盘上限不可注入，只能直接断言计数）。 */
    private static long readTotalBodyBytes(AnalysisHistoryStore store) throws Exception {
        java.lang.reflect.Field field = AnalysisHistoryStore.class.getDeclaredField("totalBodyBytes");
        field.setAccessible(true);
        return field.getLong(store);
    }

    /** 求和 {@code <sessionRoot>/history/bodies/} 下所有文件大小。 */
    private static long bodyDirectoryBytes(Path sessionRoot) throws IOException {
        Path bodies = sessionRoot.resolve("history/bodies");
        if (!Files.isDirectory(bodies)) {
            return 0L;
        }
        long total = 0L;
        try (var files = Files.list(bodies)) {
            for (Path file : files.filter(Files::isRegularFile).toList()) {
                total += Files.size(file);
            }
        }
        return total;
    }

    @Test
    void clear_removesAllEntriesAndBodyFiles(@TempDir Path tempDir) throws Exception {
        AnalysisHistoryStore store = newStore(tempDir);
        store.add(success(1L, "GET", "http://a"),
                AnalysisTrigger.MANUAL,
                "GET / HTTP/1.1\r\n\r\n".getBytes(StandardCharsets.UTF_8),
                "HTTP/1.1 200 OK\r\n\r\n".getBytes(StandardCharsets.UTF_8), null);
        // 清空前 bodies 目录应有文件
        long before = countBodyFiles(tempDir);
        assertTrue(before > 0);
        store.clear();
        assertEquals(0, store.list().size());
        // 清空后 bodies 目录应为空（或目录被清空）
        long after = countBodyFiles(tempDir);
        assertEquals(0, after);
    }

    @Test
    void purgeLegacyTrafficData_removesOldProxyTrafficStoreData(@TempDir Path tempDir) throws Exception {
        // 在 sessionRoot 下创建老 ProxyTrafficStore 留下的 bodies/ + index.json
        Path legacyBodies = tempDir.resolve("bodies");
        Path legacyIndex = tempDir.resolve("index.json");
        Files.createDirectories(legacyBodies);
        Files.writeString(legacyBodies.resolve("abc.req.gz"), "legacy");
        Files.writeString(legacyIndex, "{}");
        // 构造新 store：应自动清理老数据
        newStore(tempDir);
        assertFalse(Files.exists(legacyBodies), "老 bodies/ 目录应被清理");
        assertFalse(Files.exists(legacyIndex), "老 index.json 应被清理");
        // 新 store bodies 目录应建好（index.json 首次 add 后才落盘，构造期不写）
        assertTrue(Files.exists(tempDir.resolve("history/bodies")), "新 store bodies 目录应建好");
    }

    @Test
    void singleEntryByteTruncation_appliesWhenExceedingLimit(@TempDir Path tempDir) throws Exception {
        // maxEntryBytes = 100 字节
        AnalysisHistoryStore store = new AnalysisHistoryStore(tempDir, 100, 100L, msg -> { });
        // 构造 5KB body：超限
        byte[] huge = new byte[5 * 1024];
        java.util.Arrays.fill(huge, (byte) 'A');
        store.add(success(1L, "GET", "http://x"), AnalysisTrigger.MANUAL, huge, null, null);
        AnalysisHistoryEntry entry = store.list().get(0);
        assertTrue(entry.isRequestTruncated(), "超限 body 应标记 truncated");
    }

    @Test
    void delete_removesOnlyTheRequestedEntry(@TempDir Path tempDir) throws Exception {
        AnalysisHistoryStore store = newStore(tempDir);
        long keepId = store.add(success(1L, "GET", "http://a.test/x"),
                AnalysisTrigger.MANUAL, null, null, null);
        long dropId = store.add(success(2L, "POST", "http://b.test/y"),
                AnalysisTrigger.PASSIVE, null, null, null);
        AnalysisHistoryEntry removed = store.delete(dropId);
        assertNotNull(removed, "存在的 id 应返回被删除的 entry");
        assertEquals(dropId, removed.getId());
        // 被删的 id 消失，其它记录原样保留
        assertNull(store.get(dropId));
        assertNotNull(store.get(keepId));
        List<AnalysisHistoryEntry> list = store.list();
        assertEquals(1, list.size());
        assertEquals(keepId, list.get(0).getId());
        // 删除不存在的 id：返回 null 且不误删
        assertNull(store.delete(9999L));
        assertNull(store.delete(dropId), "重复删除同一 id 应返回 null");
        assertEquals(1, store.list().size());
    }

    @Test
    void delete_persistsAcrossReload(@TempDir Path tempDir) throws Exception {
        AnalysisHistoryStore store = newStore(tempDir);
        long keepId = store.add(success(1L, "GET", "http://a.test/x"),
                AnalysisTrigger.MANUAL,
                "GET /x HTTP/1.1\r\n\r\n".getBytes(StandardCharsets.UTF_8),
                "HTTP/1.1 200 OK\r\n\r\n".getBytes(StandardCharsets.UTF_8), null);
        long dropId = store.add(success(2L, "GET", "http://b.test/y"),
                AnalysisTrigger.MANUAL,
                "GET /y HTTP/1.1\r\n\r\n".getBytes(StandardCharsets.UTF_8),
                "HTTP/1.1 201 Created\r\n\r\n".getBytes(StandardCharsets.UTF_8), null);
        assertNotNull(store.delete(dropId));
        // close 触发全量落盘，重新打开后删除结果应保持一致
        store.close();
        AnalysisHistoryStore reopened = newStore(tempDir);
        List<AnalysisHistoryEntry> list = reopened.list();
        assertEquals(1, list.size());
        assertEquals(keepId, list.get(0).getId());
        assertNull(reopened.get(dropId));
    }

    @Test
    void delete_freesBodyFilesOnlyWhenNoLongerShared(@TempDir Path tempDir) throws Exception {
        AnalysisHistoryStore store = newStore(tempDir);
        byte[] sharedReq = "GET /shared HTTP/1.1\r\n\r\n".getBytes(StandardCharsets.UTF_8);
        long idA = store.add(success(1L, "GET", "http://a.test/shared"),
                AnalysisTrigger.MANUAL, sharedReq, null, null);
        long idB = store.add(success(2L, "GET", "http://b.test/shared"),
                AnalysisTrigger.MANUAL, sharedReq, null, null);
        // 两条记录共享同一份 request body（SHA-256 去重后路径相同）
        assertEquals(store.get(idA).getRequestFile(), store.get(idB).getRequestFile());
        assertTrue(countBodyFiles(tempDir) >= 1);
        // 删除其中一条：body 文件仍被另一条引用，必须保留
        store.delete(idA);
        assertNotNull(store.get(idB).getRequestFile());
        assertTrue(Files.exists(store.get(idB).getRequestFile()), "共享 body 应保留");
        assertTrue(countBodyFiles(tempDir) >= 1);
        // 删除最后一条引用：body 文件应被清理
        store.delete(idB);
        assertEquals(0, countBodyFiles(tempDir));
    }

    @Test
    void delete_andFingerprintSync_keepMarkerWhileSharedByAnotherEntry(@TempDir Path tempDir) throws Exception {
        AnalysisHistoryStore store = newStore(tempDir);
        // 同 method + url + body → 同指纹（RequestFingerprint 含 body），这里用相同 body 确保共享指纹
        byte[] shared = "identical-body".getBytes(StandardCharsets.UTF_8);
        long idA = store.add(success(1L, "GET", "http://x.test/same"),
                AnalysisTrigger.MANUAL, shared, null, null);
        long idB = store.add(success(2L, "GET", "http://x.test/same"),
                AnalysisTrigger.PASSIVE, shared, null, null);
        String fpA = store.get(idA).getRequestFingerprint();
        String fpB = store.get(idB).getRequestFingerprint();
        assertNotNull(fpA);
        assertEquals(fpA, fpB, "同 method+url+body 应共享同一指纹");
        // 删除其中一条：指纹仍被另一条记录持有 → containsFingerprint 为 true（dedup 标记应保留）
        assertNotNull(store.delete(idA));
        assertTrue(store.containsFingerprint(fpA), "另一条记录仍持有该指纹");
        // 删除最后一条：指纹不再被任何记录持有 → 应移除 dedup 标记
        assertNotNull(store.delete(idB));
        assertFalse(store.containsFingerprint(fpA));
        // null / 空指纹查询恒为 false
        assertFalse(store.containsFingerprint(null));
        assertFalse(store.containsFingerprint(""));
    }

    @Test
    void delete_returnsEntryCarryingFingerprintForDedupSync(@TempDir Path tempDir) throws Exception {
        AnalysisHistoryStore store = newStore(tempDir);
        byte[] req = "GET /fp HTTP/1.1\r\n\r\n".getBytes(StandardCharsets.UTF_8);
        long id = store.add(success(1L, "GET", "http://x.test/fp"),
                AnalysisTrigger.MANUAL, req, null, null);
        AnalysisHistoryEntry removed = store.delete(id);
        assertNotNull(removed);
        // 返回的 entry 携带与删除前一致的指纹，供 UI 同步被动分析去重缓存
        assertEquals(RequestFingerprint.compute("GET", "http://x.test/fp", req),
                removed.getRequestFingerprint());
        // 删除后无任何记录持有该指纹 → containsFingerprint 为 false
        assertFalse(store.containsFingerprint(removed.getRequestFingerprint()));
    }

    @Test
    void listener_firesOnAdd(@TempDir Path tempDir) throws Exception {
        AnalysisHistoryStore store = newStore(tempDir);
        java.util.concurrent.atomic.AtomicInteger count = new java.util.concurrent.atomic.AtomicInteger();
        store.addListener(ignored -> count.incrementAndGet());
        store.add(success(1L, "GET", "http://x"), AnalysisTrigger.MANUAL, null, null, null);
        store.add(success(2L, "GET", "http://y"), AnalysisTrigger.MANUAL, null, null, null);
        // 触发可能异步：等待短时
        Thread.sleep(50);
        assertTrue(count.get() >= 1, "至少触发 1 次 add 事件");
    }

    /**
     * 关键不变量：500ms 防抖窗口内的连续 {@code add} 调用，必须有一条统一的调度器
     * 线程任务负责把脏数据补写盘，进程退出前这条数据不能丢。
     *
     * <p>已知失败模式：如果落盘只在每次 {@code add} 调用时根据
     * "距上次落盘是否已过 500ms"决定是否 flush——500ms 窗口内连续 add 多次时，
     * 第一次 flush、其余只置 dirty 标位但<b>没有任何调度器</b>消费，
     * 进程退出时这条数据就丢了。本测试构造 100 条 add 间隔 5ms（远小于 500ms
     * 防抖窗口），然后等 600ms 让调度器任务跑完，验证重新打开 store 能读回全部
     * 100 条。</p>
     */
    @Test
    void burstAddsAllPersistedViaScheduler(@TempDir Path tempDir) throws Exception {
        AnalysisHistoryStore store = newStore(tempDir);
        int n = 100;
        for (int i = 0; i < n; i++) {
            store.add(success(1000L + i, "GET", "http://burst.test/" + i),
                    AnalysisTrigger.PASSIVE, null, null, null);
            // 5ms 间隔：远小于 500ms 防抖窗口，模拟"突发流量"。
            Thread.sleep(5);
        }
        // 关键：等过防抖窗口 500ms（这里等 700ms 留余量），让调度器线程上的
        // 一次性任务有机会把 dirty 数据补写盘。
        Thread.sleep(700);
        // 重新打开 store 强制从磁盘读 index.json，验证全部 100 条都落盘了。
        AnalysisHistoryStore reopened = newStore(tempDir);
        assertEquals(n, reopened.list().size(),
                "突发 add 100 条后等过防抖窗口，重启加载应见到全部 100 条");
    }

    // ========== 辅助 ==========

    private static AnalysisHistoryStore newStore(Path tempDir) throws IOException {
        return new AnalysisHistoryStore(tempDir, 500, 2L * 1024 * 1024, msg -> { });
    }

    private static AnalysisResult success(long timestamp, String method, String url) {
        return AnalysisResult.success(timestamp, method, url, 200, "ok", 0L, List.of());
    }

    private static long countBodyFiles(Path tempDir) throws IOException {
        try (var files = Files.list(tempDir.resolve("history/bodies"))) {
            return files.filter(Files::isRegularFile).count();
        }
    }
}