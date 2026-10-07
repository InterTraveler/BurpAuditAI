package com.auditai.burp.history;

import com.auditai.burp.http.AnalysisResult;
import com.auditai.burp.http.BodyStorage;
import com.auditai.burp.passive.RequestFingerprint;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * "历史"页签背后的落盘式 FIFO 容器。
 *
 * <p>仅记录"经 AI 分析过的报文"（手动 / 被动分析完成回调），不保存全量代理流量。
 * 元数据写入 {@code history/index.json}，正文 gzip + SHA-256 去重写入
 * {@code history/bodies/}。路径形如 {@code <数据根>/projects/<id>/history/} 或
 * {@code <数据根>/temporary/history/}（数据根见 SessionPaths 类）。</p>
 *
 * <p>#add / #delete / #clear / #close 在 #lock 内
 * 串行化；#list / #get 加同一把锁保证读到一致快照。监听器回调在锁外执行
 * （避免回调里死锁）。</p>
 */
public final class AnalysisHistoryStore implements AutoCloseable {

    /** 默认保留的最大记录数。 */
    public static final int DEFAULT_MAX_ENTRIES = 500;

    /**
     * 默认正文目录总盘占用上限（500 条 × 单条 ≤ 2MB，理论 1GB 但 gzip 后实际数百 MB）。
     * 用 200MB 兜底：避免单条大 body 撑爆磁盘。超限时优先按 insertionOrder 淘汰最旧。
     */
    private static final long DEFAULT_MAX_TOTAL_BYTES = 200L * 1024 * 1024;

    /** 默认单条记录 request + response 字节上限（未压缩字节数）。 */
    public static final int DEFAULT_MAX_ENTRY_BYTES = 2 * 1024 * 1024;

    /** 数据目录名（与 ProxyTrafficStore 平级）；最终路径 = {@code <sessionRoot>/history}。 */
    public static final String HISTORY_DIRECTORY_NAME = "history";

    private static final String INDEX_FILE_NAME = "index.json";
    private static final String BODIES_DIRECTORY_NAME = "bodies";

    /** 索引落盘防抖：高频分析时不必每条都落盘，统一延迟 500ms flush。 */
    private static final long PERSIST_DEBOUNCE_MS = 500L;

    private final Path historyDirectory;
    private final Path indexFile;
    private final Path bodyDirectory;
    private final Path auditTrailsDirectory;
    private final int maxEntries;
    private final long maxEntryBytes;
    private final LinkedHashSet<Long> insertionOrder = new LinkedHashSet<>();
    private final java.util.concurrent.ConcurrentHashMap<Long, AnalysisHistoryEntry> entries =
            new java.util.concurrent.ConcurrentHashMap<>();
    private final Object lock = new Object();
    private final List<Consumer<Void>> listeners = new CopyOnWriteArrayList<>();
    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();
    private final AtomicLong nextId = new AtomicLong(1L);

    /**
     * 正文目录的<b>增量维护</b>磁盘占用字节数（锁内读写）。新建 gzip 文件时累加
     * 实际文件大小、删除文件时扣减，#evictIfNeeded 直接与阈值比较，
     * 不再每次入库都全目录 {@code Files.walk} 扫描（500+ 文件时是 O(N²) 磁盘 IO）。
     */
    private long totalBodyBytes;

    /** 索引是否有未落盘脏数据（锁内读写）。 */
    private boolean persistDirty;

    /** 上次真正落盘的时间戳（毫秒）。 */
    private long lastPersistAtMs;

    /** 是否已关闭。 */
    private boolean closed;

    /**
     * 索引落盘调度器：单线程守护线程，处理"延迟落盘"和"窗口期补落盘"。
     * 每次 add 走 {@code schedule(500ms)} 排一个一次性任务做"若 dirty 则 flush"，
     * 覆盖"窗口期后无新 add 进来"和"窗口期内多次 add"两种丢数据场景；任务幂等。
     */
    private final ScheduledExecutorService persister = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "auditai-history-persister");
        t.setDaemon(true);
        return t;
    });

    /** 当前已调度但未执行的落盘任务引用：用于"窗口期内多次 add 只保留最新一次调度"去重。 */
    private volatile ScheduledFuture<?> pendingFlush;

    /** 错误日志回调（不允许 null，调用方必须注入）；用于索引损坏、落盘失败等诊断信息。 */
    private final Consumer<String> errorLogger;

    /**
     * 构造器：建 {@code <sessionRoot>/history/} 数据目录 + 一次性清理老
     * {@code ProxyTrafficStore} 留下的 {@code bodies/} + {@code index.json}（迁移期设计）。
     *
     * @param sessionRoot     会话根目录（{@code SessionPaths#createProjectDirectory(...).path()} 的输出）。
     * @param maxEntries      最大记录数。
     * @param maxEntryBytes   单条 request + response 字节上限（未压缩）。
     * @param errorLogger     落盘失败时的日志回调（不允许 null）。
     * @throws IOException 任何 IO 异常。
     */
    public AnalysisHistoryStore(Path sessionRoot, int maxEntries, long maxEntryBytes,
                                Consumer<String> errorLogger) throws IOException {
        if (sessionRoot == null) {
            throw new IllegalArgumentException("sessionRoot is null");
        }
        if (maxEntries < 1 || maxEntryBytes < 1) {
            throw new IllegalArgumentException("Storage limits must be positive");
        }
        Objects.requireNonNull(errorLogger, "errorLogger");
        this.maxEntries = maxEntries;
        this.maxEntryBytes = maxEntryBytes;
        this.errorLogger = errorLogger;
        this.historyDirectory = sessionRoot.resolve(HISTORY_DIRECTORY_NAME);
        this.indexFile = historyDirectory.resolve(INDEX_FILE_NAME);
        this.bodyDirectory = historyDirectory.resolve(BODIES_DIRECTORY_NAME);
        this.auditTrailsDirectory = sessionRoot.resolve(
                com.auditai.burp.util.WorkflowLogger.AUDIT_TRAILS_DIRECTORY_NAME);
        Files.createDirectories(bodyDirectory);
        Files.createDirectories(auditTrailsDirectory);
        // 一次性清理老 ProxyTrafficStore 数据（迁移期设计）：失败仅写错误日志，不阻塞启动。
        purgeLegacyTrafficData(sessionRoot, this.errorLogger);
        loadIndex();
        // 重启后按磁盘实际情况重建 totalBodyBytes（该字段只在"新建 body 文件"时累加，
        // 不重建会停在 0，DEFAULT_MAX_TOTAL_BYTES 在重启后失效）。
        recomputeTotalBodyBytes();
    }

    /**
     * 添加一条"分析完成"记录。
     *
     * @param result         一次完整分析的结果。
     * @param trigger        触发来源（手动 / 被动）。
     * @param requestBytes   原始请求字节；可为 null（不携带）。
     * @param responseBytes  原始响应字节；可为 null（无响应 / 不携带）。
     * @param auditTrailFile 审计轨迹 XML 绝对路径（位于 {@code <sessionRoot>/audit-trails/}）；
     *                       可为 null。该文件在入库前<b>必须已存在</b>——
     *                       落盘时机由 {@code AnalysisResultSink} 在调用本方法前完成。
     * @return 新分配的 entry id；调用方可用于关联。
     */
    public long add(AnalysisResult result, AnalysisTrigger trigger,
                    byte[] requestBytes, byte[] responseBytes,
                    Path auditTrailFile) throws IOException {
        if (result == null) {
            return -1L;
        }
        AnalysisTrigger safeTrigger = trigger == null ? AnalysisTrigger.MANUAL : trigger;
        long id;
        synchronized (lock) {
            if (closed) {
                // 插件卸载后迟到的回调仍可能 add：直接忽略并留一条日志，避免写孤儿文件。
                errorLogger.accept("历史库已关闭，忽略迟到的入库请求（插件卸载竞态）。");
                // audit-trail 文件已写盘但 entry 落空：留作孤儿文件，后续容量淘汰 / clear 时再清理
                return -1L;
            }
            id = nextId.getAndIncrement();
            RiskLevel risk = RiskLevel.derive(result);
            // request 字节：按 BodyStorage.prepareStoredMessage 裁剪，超限再硬截
            byte[] safeReq = requestBytes == null ? new byte[0] : requestBytes.clone();
            boolean reqTruncated = false;
            if (safeReq.length > maxEntryBytes) {
                safeReq = BodyStorage.prepareStoredMessage(safeReq);
                reqTruncated = true;
                if (safeReq.length > maxEntryBytes) {
                    safeReq = truncateBytes(safeReq, maxEntryBytes);
                }
            }
            BodyWrite reqWrite = writeBodyIfAbsent(safeReq, "req", id);
            // response 字节：同上
            byte[] safeResp = responseBytes == null ? new byte[0] : responseBytes.clone();
            boolean respTruncated = false;
            if (safeResp.length > maxEntryBytes) {
                safeResp = BodyStorage.prepareStoredMessage(safeResp);
                respTruncated = true;
                if (safeResp.length > maxEntryBytes) {
                    safeResp = truncateBytes(safeResp, maxEntryBytes);
                }
            }
            BodyWrite respWrite = writeBodyIfAbsent(safeResp, "res", id);
            // 增量维护磁盘占用
            if (reqWrite.created) {
                totalBodyBytes += reqWrite.fileSize;
            }
            if (respWrite.created) {
                totalBodyBytes += respWrite.fileSize;
            }
            // requestFingerprint 用【原始】requestBytes 算（与被动分析在线算的指纹严格一致），
            // 不受 truncate / prepareStoredMessage 影响
            String requestFingerprint = RequestFingerprint.compute(
                    result.getMethod(), result.getUrl(), requestBytes);
            AnalysisHistoryEntry entry = new AnalysisHistoryEntry(
                    id,
                    result.getTimestampMillis(),
                    safeTrigger,
                    result.getMethod(),
                    result.getUrl(),
                    result.getStatusCode(),
                    result.getSummary(),
                    result.getError(),
                    risk,
                    result.getDurationMillis(),
                    responseBytes != null && responseBytes.length > 0,
                    null, null,
                    reqTruncated, respTruncated,
                    reqWrite.path, respWrite.path,
                    reqWrite.hash, respWrite.hash,
                    requestFingerprint,
                    result.getFindings() == null ? 0 : result.getFindings().size(),
                    auditTrailFile);
            entries.put(id, entry);
            insertionOrder.add(id);
            persistIndexDebounced();
            evictIfNeeded();
        }
        notifyListeners();
        return id;
    }

    /** 按 id 取一条记录；找不到返回空。 */
    public AnalysisHistoryEntry get(long id) {
        synchronized (lock) {
            return entries.get(id);
        }
    }

    /**
     * 按 (method, url) 反查时间最近的一条；method 为空时只按 URL 匹配。
     * 供 {@code FindingsPanel} 在 {@code AnalysisContext} 上下文缺失时兜底反查。
     */
    public AnalysisHistoryEntry findLatestByUrl(String method, String url) {
        if (url == null || url.isBlank()) {
            return null;
        }
        synchronized (lock) {
            AnalysisHistoryEntry best = null;
            long bestTs = Long.MIN_VALUE;
            for (Long entryId : insertionOrder) {
                AnalysisHistoryEntry entry = entries.get(entryId);
                if (entry == null) {
                    continue;
                }
                if (!url.equals(entry.getUrl())) {
                    continue;
                }
                // HTTP method 按 RFC 7230 大小写不敏感,两侧都走 Locale.ROOT toLowerCase,
                // 避免土耳其语 locale 把 "I"/"İ" 当同字母
                if (method != null && !method.isBlank()
                        && !method.toLowerCase(java.util.Locale.ROOT)
                                .equals(entry.getMethod().toLowerCase(java.util.Locale.ROOT))) {
                    continue;
                }
                if (entry.getTimestamp() > bestTs) {
                    bestTs = entry.getTimestamp();
                    best = entry;
                }
            }
            return best;
        }
    }

    /**
     * 按 (host, excludeId, limit) 取同二级域名（PSL 简化版：取 host 切 "." 后最后两段）的
     * 摘要。供 {@code TrafficAnalyzer} 的"多报文协同分析"使用。
     *
     * <p>替代 {@code ProxyTrafficStore.findByDomain}：行为兼容，差异仅在数据源
     * 从"全量代理流量"变为"已分析历史"（语义更聚焦）。</p>
     *
     * @param excludeEntryId 要排除的 entry id（通常就是当前正在分析的那一条）；-1 表示不排除。
     * @param host           目标 host（不含协议 / 端口；IP 视为整体）。
     * @param limit          最多返回条数。
     * @return 按时间倒序的 entry 列表（可能为空）。
     */
    public List<AnalysisHistoryEntry> findByDomain(long excludeEntryId, String host, int limit) {
        if (limit <= 0) {
            return Collections.emptyList();
        }
        String suffix = com.auditai.burp.http.DomainClassifier.extractSecondLevelDomain(host);
        if (suffix.isEmpty()) {
            return Collections.emptyList();
        }
        synchronized (lock) {
            List<AnalysisHistoryEntry> all = new ArrayList<>();
            for (Long entryId : insertionOrder) {
                if (entryId == excludeEntryId) {
                    continue;
                }
                AnalysisHistoryEntry entry = entries.get(entryId);
                if (entry == null) {
                    continue;
                }
                String entryHost = hostOfUrl(entry.getUrl());
                if (entryHost.isEmpty()) {
                    continue;
                }
                String entrySuffix = com.auditai.burp.http.DomainClassifier.extractSecondLevelDomain(entryHost);
                // 域名后缀走 ASCII 不区分大小写比对,Locale.ROOT 避免土耳其语 locale 把
                // "I"/"İ" 当同字母
                if (suffix.toLowerCase(java.util.Locale.ROOT)
                        .equals(entrySuffix.toLowerCase(java.util.Locale.ROOT))) {
                    all.add(entry);
                }
            }
            all.sort((a, b) -> Long.compare(b.getTimestamp(), a.getTimestamp()));
            if (all.size() > limit) {
                return Collections.unmodifiableList(new ArrayList<>(all.subList(0, limit)));
            }
            return Collections.unmodifiableList(all);
        }
    }

    /**
     * 返回当前所有 entry，按时间升序（最旧在前、最新在底），与 Burp 原生
     * HTTP history 表格的"新条目滚到底部"行为一致。
     *
     * <p>注：#findByDomain 内部仍按时间倒序——那是给"同域历史摘要"
     * 用的（多报文协同分析），与表格展示无关。</p>
     */
    public List<AnalysisHistoryEntry> list() {
        synchronized (lock) {
            List<AnalysisHistoryEntry> result = new ArrayList<>(entries.size());
            for (Long entryId : insertionOrder) {
                AnalysisHistoryEntry entry = entries.get(entryId);
                if (entry != null) {
                    result.add(entry);
                }
            }
            result.sort((a, b) -> Long.compare(a.getTimestamp(), b.getTimestamp()));
            return Collections.unmodifiableList(result);
        }
    }

    /** 清空所有记录 + 删除所有落盘文件（包括 audit-trail 目录下的所有 XML）。 */
    public void clear() {
        synchronized (lock) {
            entries.clear();
            insertionOrder.clear();
            totalBodyBytes = 0L;
            try (var files = Files.list(bodyDirectory)) {
                for (Path file : files.filter(Files::isRegularFile).toList()) {
                    Files.deleteIfExists(file);
                }
            } catch (IOException e) {
                // 清空是 best-effort：失败不阻塞流程（内存索引已清、UI 不依赖磁盘彻底清空），
                // 但必须留一条诊断——否则"磁盘没清掉"这件事用户和排错者都无从发现。
                errorLogger.accept("清空历史 body 目录失败：" + e.getMessage());
            }
            clearAuditTrailFiles();
            persistIndexDebounced();
        }
        notifyListeners();
    }

    /**
     * 按 id 删除<b>单条</b>记录（"历史"页签右键删除入口）。
     *
     * <p>与 #clear() 的差异：只删一条、不动其它记录。删除后对不再被任何
     * entry 引用的 body 文件做一次清理——body 按 SHA-256 跨记录去重共享，某条
     * 记录独占的文件被释放，仍被其它记录引用的文件保留。随后防抖落盘 + 通知监听器。</p>
     *
     * <p>返回被删除的 entry（而非 boolean），让调用方能拿到 {@code requestFingerprint}
     * 去同步被动分析去重缓存——删除后该指纹若不再被任何保留记录持有，应从
     * {@code FingerprintDedup} 移除，保证"删除记录 → 同 URL 可重新被动分析"。
     * 注意：body 文件可能已随删除清理，返回的 entry 只应读元数据，不应再读盘。</p>
     *
     * <p>UI 语义：右键菜单本身已是明确的删除意图，<b>不需要</b>再弹确认框
     * （与 {@code Clear} 全清仍保留确认不同，由调用方决定文案）。</p>
     *
     * @param id 要删除的 entry id（来自表格"序号"列）。
     * @return 被删除的 entry；id 不存在或 store 已关闭时返回 null。
     */
    public AnalysisHistoryEntry delete(long id) {
        AnalysisHistoryEntry removed;
        synchronized (lock) {
            if (closed) {
                return null;
            }
            removed = entries.remove(id);
            if (removed == null) {
                return null;
            }
            insertionOrder.remove(id);
            try {
                // 单条删除 best-effort：body 文件清理失败不阻塞删除本身，索引已从内存移除，
                // 遗留孤儿文件会在下次容量淘汰 / clear 时被 deleteUnreferencedBodies 清理。
                totalBodyBytes = Math.max(0L, totalBodyBytes - deleteUnreferencedBodies());
            } catch (IOException e) {
                errorLogger.accept("删除历史记录 " + id + " 后清理 body 文件失败：" + e.getMessage());
            }
            // audit-trail 是 1:1 绑定本 entry：直接删，无需引用计数
            deleteAuditTrailFile(removed.getAuditTrailFile());
            persistIndexDebounced();
        }
        notifyListeners();
        return removed;
    }

    /**
     * 是否有<b>保留中</b>的记录仍持有指定请求指纹。
     *
     * <p>用途："历史"页签删除单条记录后，判断是否应同步从被动分析去重缓存
     * （{@code FingerprintDedup}）移除该指纹——若仍有其它记录持有同一指纹，说明该请求
     * 仍有一条"已分析"记录存在，dedup 标记应保留（避免同请求被反复分析烧 token）；
     * 与 {@code delete} 清理 body 文件时"仍被引用则保留"的语义保持一致。</p>
     *
     * @param requestFingerprint 请求指纹；null 恒返回 false。
     */
    public boolean containsFingerprint(String requestFingerprint) {
        if (requestFingerprint == null) {
            return false;
        }
        synchronized (lock) {
            for (AnalysisHistoryEntry entry : entries.values()) {
                if (requestFingerprint.equals(entry.getRequestFingerprint())) {
                    return true;
                }
            }
            return false;
        }
    }

    /**
     * 返回当前会话的存储目录（便于日志 / 诊断）。
     */
    public Path sessionDirectory() {
        return historyDirectory;
    }

    /**
     * 返回 audit-trail 目录：与 #sessionDirectory() 同级，存放每次分析的
     * agent ↔ AI 交互 XML。供 {@code AnalysisResultSink} 在入库前把 XML 落盘到此目录。
     */
    public Path auditTrailsDirectory() {
        return auditTrailsDirectory;
    }

    @Override
    public void close() {
        synchronized (lock) {
            if (closed) {
                return;
            }
            closed = true;
            try {
                flushPersistLocked(System.currentTimeMillis());
            } catch (IOException ioe) {
                errorLogger.accept("关闭前 persistIndex 失败：" + ioe.getMessage());
            }
            entries.clear();
            insertionOrder.clear();
        }
        // 关掉调度器：插件卸载时及时中断排队的延迟落盘任务，避免 Burp 重载后
        // 残留线程访问已 close 的 store 触发 NPE。
        ScheduledFuture<?> pending = pendingFlush;
        if (pending != null) {
            pending.cancel(false);
        }
        // 先 shutdown() 让最后一段落盘任务完成，再 awaitTermination + shutdownNow 兜底。
        // 比直接 shutdownNow 更稳：避免"刚加的 entry 在 close() 路径漏盘"。
        persister.shutdown();
        try {
            if (!persister.awaitTermination(SHUTDOWN_WAIT_MS, TimeUnit.MILLISECONDS)) {
                persister.shutdownNow();
            }
        } catch (InterruptedException e) {
            persister.shutdownNow();
            Thread.currentThread().interrupt();
        }
        // 清空监听器：插件卸载后 store 已不可用，避免对匿名 lambda 无法定向注销
        // 时留下对外部 UI（AnalysisHistoryPanel）等的常驻引用。
        listeners.clear();
    }

    /** 关闭等待时间：让最后一次落盘任务有时间完成。 */
    private static final long SHUTDOWN_WAIT_MS = 2_000L;

    /** 注册变更监听器。 */
    public void addListener(Consumer<Void> listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    public void removeListener(Consumer<Void> listener) {
        listeners.remove(listener);
    }

    // ==================== 内部：audit-trail 清理 ====================

    /**
     * 删单个 audit-trail 文件。文件不存在 / 路径为空 / 不在 audit-trails 目录下时
     * 安全 no-op（防御误传任意路径）。失败仅记日志，不阻塞删除本身。
     */
    private void deleteAuditTrailFile(Path file) {
        if (file == null) {
            return;
        }
        // 安全：仅允许删 audit-trails 目录下的文件，避免任何路径注入
        if (!file.toAbsolutePath().normalize().startsWith(auditTrailsDirectory.toAbsolutePath().normalize())) {
            errorLogger.accept("拒绝删除 audit-trail 文件（路径越界）：" + file);
            return;
        }
        try {
            Files.deleteIfExists(file);
        } catch (IOException e) {
            errorLogger.accept("删除 audit-trail 文件失败（" + file.getFileName() + "）：" + e.getMessage());
        }
    }

    /** 清空 audit-trails 目录下的所有 XML（供 #clear 使用）。 */
    private void clearAuditTrailFiles() {
        if (!Files.isDirectory(auditTrailsDirectory)) {
            return;
        }
        try (var files = Files.list(auditTrailsDirectory)) {
            for (Path file : files.filter(Files::isRegularFile).toList()) {
                Files.deleteIfExists(file);
            }
        } catch (IOException e) {
            // best-effort：失败仅记日志
            errorLogger.accept("清空 audit-trail 目录失败：" + e.getMessage());
        }
    }

    // ==================== 内部：落盘 ====================

    /**
     * 一次性清理老 {@code ProxyTrafficStore} 留下的 {@code <sessionRoot>/bodies/}
     * 和 {@code <sessionRoot>/index.json}（迁移期设计：本插件升级后不再写全量代理流量，
     * 老数据留着没意义且会误导用户）。
     *
     * <p>失败仅写错误日志，不阻塞新 store 启动。</p>
     */
    private static void purgeLegacyTrafficData(Path sessionRoot, Consumer<String> errorLogger) {
        if (sessionRoot == null) {
            return;
        }
        Consumer<String> logger = Objects.requireNonNull(errorLogger, "errorLogger");
        Path legacyBodies = sessionRoot.resolve("bodies");
        Path legacyIndex = sessionRoot.resolve("index.json");
        try {
            if (Files.exists(legacyBodies)) {
                try (var files = Files.list(legacyBodies)) {
                    for (Path file : files.filter(Files::isRegularFile).toList()) {
                        Files.deleteIfExists(file);
                    }
                }
                Files.deleteIfExists(legacyBodies);
            }
        } catch (IOException | RuntimeException e) {
            logger.accept("清理老 ProxyTrafficStore bodies/ 失败：" + e.getMessage());
        }
        try {
            Files.deleteIfExists(legacyIndex);
        } catch (IOException | RuntimeException e) {
            logger.accept("清理老 ProxyTrafficStore index.json 失败：" + e.getMessage());
        }
    }

    /**
     * 容量淘汰：超 {@code maxEntries} 或超总盘字节时按 insertionOrder 头删最旧 + 释放磁盘。
     *
     * <p><b>为什么磁盘上限单独一轮循环</b>：body 文件按 SHA-256 跨记录去重，一个文件可能被
     * 多条 entry 共享，因此"淘汰一条 entry"并不等于"释放了它名下那些字节"——只能先淘汰条目、
     * 再物理删除不再被引用的文件、然后按磁盘实际占用重算 #totalBodyBytes。
     * 历史实现把删条目和重算混在一个循环里且循环内不更新计数，导致一旦越过磁盘上限，
     * 循环会把<b>所有</b>历史全部淘汰（而不是"淘汰到低于上限为止"）。</p>
     */
    private void evictIfNeeded() throws IOException {
        // 第一轮：先满足"条数"上限（与历史行为一致，纯内存操作）。
        boolean evictedByCount = false;
        while (entries.size() > maxEntries && evictOldest()) {
            evictedByCount = true;
        }
        // 第二轮：只有真淘汰过条目，才可能有 body 文件失去唯一引用需要释放；
        // 未淘汰则跳过全目录扫描，避免每次 add 都做一次 body 目录遍历。
        if (evictedByCount) {
            totalBodyBytes = Math.max(0L, totalBodyBytes - deleteUnreferencedBodies());
        }
        while (totalBodyBytes > DEFAULT_MAX_TOTAL_BYTES && evictOldest()) {
            totalBodyBytes = Math.max(0L, totalBodyBytes - deleteUnreferencedBodies());
        }
        persistIndexDebounced();
    }

    /**
     * 淘汰插入顺序最旧的一条（连同它的 audit-trail 文件）。
     *
     * @return true 表示确实淘汰了一条；false 表示已无可淘汰条目（调用方必须据此停止循环，
     *         否则会死循环或把历史清空）。
     */
    private boolean evictOldest() {
        Long oldestId = insertionOrder.isEmpty() ? null : insertionOrder.iterator().next();
        if (oldestId == null) {
            return false;
        }
        AnalysisHistoryEntry evicted = entries.remove(oldestId);
        insertionOrder.remove(oldestId);
        if (evicted != null) {
            // 淘汰时同样物理删除 audit-trail 文件
            deleteAuditTrailFile(evicted.getAuditTrailFile());
        }
        return true;
    }

    /**
     * 按 body 目录里实际存在的文件大小重算 #totalBodyBytes。
     *
     * <p>统计口径包含孤儿文件（没有任何 entry 引用的历史遗留），因为该字段控制的是
     * <b>磁盘占用</b>上限，而 #deleteUnreferencedBodies() 返回的正是孤儿文件的字节数
     * ——两者口径一致才能保证"加/减"配对。</p>
     */
    private void recomputeTotalBodyBytes() {
        long total = bodyDirectoryBytes();
        synchronized (lock) {
            totalBodyBytes = total;
        }
    }

    /** 求和 body 目录下所有普通文件的大小；失败时记日志并返回 0（上限退化为"按条数控制"）。 */
    private long bodyDirectoryBytes() {
        long total = 0L;
        try (var files = Files.list(bodyDirectory)) {
            for (Path file : files.filter(Files::isRegularFile).toList()) {
                total += Files.size(file);
            }
        } catch (IOException e) {
            errorLogger.accept("统计历史 body 目录占用失败（磁盘上限将按 0 计）：" + e.getMessage());
            return 0L;
        }
        return total;
    }

    /** 删除不再被任何 entry 引用的 body 文件，返回释放的字节数。 */
    private long deleteUnreferencedBodies() throws IOException {
        Set<Path> referenced = new HashSet<>();
        for (AnalysisHistoryEntry entry : entries.values()) {
            if (entry.getRequestFile() != null) {
                referenced.add(entry.getRequestFile());
            }
            if (entry.getResponseFile() != null) {
                referenced.add(entry.getResponseFile());
            }
        }
        long freed = 0L;
        try (var files = Files.list(bodyDirectory)) {
            for (Path file : files.filter(Files::isRegularFile).toList()) {
                if (!referenced.contains(file)) {
                    freed += Files.size(file);
                    Files.deleteIfExists(file);
                }
            }
        }
        return freed;
    }

    /**
     * 写 body 字节到 {@code <bodyDirectory>/<hash>.<type>.gz}：已存在则复用，
     * 不存在则写临时文件 + 原子移动。
     *
     * <p><b>线程安全约定：</b>由调用方在 #lock 内调用，与 {@code ProxyTrafficStore}
     * 一致。</p>
     */
    private BodyWrite writeBodyIfAbsent(byte[] content, String type, long entryId) throws IOException {
        String hash = BodyStorage.sha256(content);
        Path target = bodyDirectory.resolve(hash + "." + type + ".gz");
        if (Files.exists(target)) {
            return new BodyWrite(target, false, 0L, hash);
        }
        Path temporary = Files.createTempFile(bodyDirectory, hash, ".tmp");
        try {
            try (var output = Files.newOutputStream(temporary);
                 var gzip = new java.util.zip.GZIPOutputStream(output)) {
                gzip.write(content);
            }
            try {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
            }
            return new BodyWrite(target, true, Files.size(target), hash);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    /** 按字节截断 content 到 maxBytes（不解析 HTTP 头尾，最朴素截断）。 */
    private static byte[] truncateBytes(byte[] content, long maxBytes) {
        if (content.length <= maxBytes) {
            return content;
        }
        int cap = (int) maxBytes;
        byte[] truncated = new byte[cap];
        System.arraycopy(content, 0, truncated, 0, cap);
        return truncated;
    }

    private void loadIndex() {
        if (!Files.exists(indexFile)) {
            return;
        }
        String text;
        try {
            text = Files.readString(indexFile, java.nio.charset.StandardCharsets.UTF_8);
        } catch (IOException e) {
            // 读不了（权限 / 半截文件）：把损坏文件改名留证，避免下一次 add 落盘时用
            // 空列表覆盖它（历史被静默丢弃）。
            errorLogger.accept("读取历史索引失败（" + e.getClass().getSimpleName() + "）："
                    + e.getMessage() + "，已把 index.json 改名保留现场");
            quarantineCorruptIndex();
            return;
        }
        JsonObject root;
        try {
            root = JsonParser.parseString(text).getAsJsonObject();
        } catch (RuntimeException e) {
            errorLogger.accept("历史索引 JSON 损坏：" + e.getMessage() + "，已把 index.json 改名保留现场");
            quarantineCorruptIndex();
            return;
        }
        if (root == null) {
            return;
        }
        synchronized (lock) {
            long maxIdSeen = 0L;
            if (root.has("entries") && root.get("entries").isJsonArray()) {
                JsonArray array = root.getAsJsonArray("entries");
                for (JsonElement el : array) {
                    if (el == null || !el.isJsonObject()) {
                        continue;
                    }
                    try {
                        // fromJson 对"语法合法但类型损坏"（如 id 是字符串、requestFile 含 NUL）
                        // 会抛 NumberFormatException / InvalidPathException 等运行时异常——
                        // 逐条容错：跳过坏条目，绝不能因为单条脏数据拖垮扩展启动。
                        AnalysisHistoryEntry entry = AnalysisHistoryEntry.fromJson(el.getAsJsonObject());
                        entries.put(entry.getId(), entry);
                        insertionOrder.add(entry.getId());
                        if (entry.getId() > maxIdSeen) {
                            maxIdSeen = entry.getId();
                        }
                    } catch (RuntimeException ex) {
                        errorLogger.accept("跳过损坏的历史索引条目：" + ex.getMessage());
                    }
                }
            }
            nextId.set(maxIdSeen + 1);
        }
    }

    /** 把损坏的 index.json 改名留证（避免下次落盘覆盖破坏现场）；失败仅记日志。 */
    private void quarantineCorruptIndex() {
        try {
            Path quarantined = indexFile.resolveSibling(
                    "index.json.corrupt-" + System.currentTimeMillis());
            Files.move(indexFile, quarantined, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException | RuntimeException e) {
            errorLogger.accept("改名损坏的 index.json 失败：" + e.getMessage());
        }
    }

    /**
     * 索引落盘调度：每次 add 调用本方法排一个 500ms 后执行的一次性任务，
     * 任务内部判 #persistDirty 决定是否真落盘。
     *
     * <p>设计要点：</p>
     * <ul>
     *   <li>窗口期内多次 add → 多次 {@code schedule}，但单线程调度器天然串行执行；
     *       最新一次任务看到 dirty 标位即落盘，之前的任务看到 dirty 已被消费则 no-op；</li>
     *   <li>窗口期外 add → 仍走 500ms 延迟（而非立即落盘），保留防抖语义；</li>
     *   <li>进程退出前 close() 仍会 flushPersistLocked 做最终落盘，覆盖所有未执行的调度任务。</li>
     * </ul>
     */
    private void persistIndexDebounced() {
        // 标记 dirty：任务执行时会基于这个标记决定是否真落盘。
        // 必须在 schedule 之前置位——若先 schedule 后置位，竞态下任务可能在
        // 我们写 dirty 之前就完成并判定为"无需落盘"。
        synchronized (lock) {
            if (closed) {
                return;
            }
            persistDirty = true;
        }
        // 已排队的任务不重复排：单线程调度器已经能保证有序执行，多次 schedule
        // 只会在队列里塞 N 个空转任务。直接 cancel 上一次的 future 即可去重。
        ScheduledFuture<?> previous = pendingFlush;
        if (previous != null && !previous.isDone()) {
            previous.cancel(false);
        }
        pendingFlush = persister.schedule(this::runScheduledFlush,
                PERSIST_DEBOUNCE_MS, TimeUnit.MILLISECONDS);
    }

    /**
     * 调度器线程上执行的实际落盘决策。
     *
     * <p>注意：本方法不在 #lock 内被调用，是从调度器线程进入的；
     * 但 #flushPersistLocked 内部会获取 #lock，与 {@code add} /
     * {@code close} 等并发路径串行化。</p>
     */
    private void runScheduledFlush() {
        // 调度线程上无锁读 persistDirty 是安全的：boolean 单字段赋值是原子的，
        // 且业务语义是"add 写 / 落盘写"是 happens-before 关系（schedule 之前
        // 已同步置位，见 persistIndexDebounced）。
        if (!persistDirty) {
            return;
        }
        try {
            synchronized (lock) {
                if (closed || !persistDirty) {
                    return;
                }
                flushPersistLocked(System.currentTimeMillis());
            }
        } catch (IOException ioe) {
            // 落盘失败不抛：调度器任务抛异常会被 ScheduledExecutorService 静默吞掉，
            // 但这里只记日志，不影响后续 add 触发的下次尝试。
            errorLogger.accept("防抖落盘失败：" + ioe.getMessage());
        }
    }

    /** 把 index.json 真正写入磁盘。调用方必须持有 #lock。 */
    private void flushPersistLocked(long now) throws IOException {
        JsonObject root = new JsonObject();
        JsonArray array = new JsonArray();
        for (Long entryId : insertionOrder) {
            AnalysisHistoryEntry entry = entries.get(entryId);
            if (entry != null) {
                array.add(entry.toJson());
            }
        }
        root.add("entries", array);
        root.addProperty("maxEntries", maxEntries);
        root.addProperty("maxEntryBytes", maxEntryBytes);
        String text = gson.toJson(root);
        Path temporary = Files.createTempFile(historyDirectory, "index", ".tmp");
        try {
            Files.writeString(temporary, text, java.nio.charset.StandardCharsets.UTF_8);
            try {
                Files.move(temporary, indexFile, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temporary, indexFile, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
        lastPersistAtMs = now;
        persistDirty = false;
    }

    private void notifyListeners() {
        for (Consumer<Void> listener : listeners) {
            try {
                listener.accept(null);
            } catch (RuntimeException ignored) {
                // 监听器异常不影响其它监听器
            }
        }
    }

    /**
     * 解析 URL 字符串拿到 host（不含协议 / 端口）；失败返回空串。
     * 简陋解析，足够用于 PSL 简化版的二级域名提取。
     */
    private static String hostOfUrl(String url) {
        if (url == null) {
            return "";
        }
        String stripped = url;
        int protoIdx = stripped.indexOf("://");
        if (protoIdx >= 0) {
            stripped = stripped.substring(protoIdx + 3);
        }
        int pathIdx = stripped.indexOf('/');
        if (pathIdx >= 0) {
            stripped = stripped.substring(0, pathIdx);
        }
        int portIdx = stripped.indexOf(':');
        if (portIdx >= 0) {
            stripped = stripped.substring(0, portIdx);
        }
        return stripped;
    }

    /** #writeBodyIfAbsent 的返回结果。 */
    private static final class BodyWrite {
        final Path path;
        final boolean created;
        final long fileSize;
        final String hash;

        BodyWrite(Path path, boolean created, long fileSize, String hash) {
            this.path = path;
            this.created = created;
            this.fileSize = fileSize;
            this.hash = hash;
        }
    }
}
