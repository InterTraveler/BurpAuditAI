package com.auditai.burp.http;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * "问题列表"页签背后的全局问题库。
 *
 * 每次分析完成的 Finding 合并进本 store，按时间升序对外暴露。
 * 关联的完整报告 / HTTP 方法 / URL 缓存在 AnalysisContext 旁路表里。
 * 持久化策略参考 com.auditai.burp.history.AnalysisHistoryStore：紧凑 JSON 写到
 * {@code <sessionRoot>/findings/findings-index.json}，FIFO 上限 #DEFAULT_MAX_FINDINGS。
 */
public final class FindingStore implements AutoCloseable {

    /** 默认最大保留条数。 */
    static final int DEFAULT_MAX_FINDINGS = 5_000;

    /**
     * 默认最大内存 context 数：避免 request/response 字节把内存吃爆。
     *
     * context 被淘汰后，对应 finding 调 #contextFor 时回退为"兜底 context"
     * （用 finding 自身字段构造，无 request/response 字节），UI 仍可经
     * {@code AnalysisHistoryStore} 反查路径拿到原文。
     */
    static final int DEFAULT_MAX_CONTEXTS = 200;

    /** 数据目录名（与 AnalysisHistoryStore 的 {@code history/} 同级；最终路径 = {@code <sessionRoot>/findings}）。 */
    public static final String FINDINGS_DIRECTORY_NAME = "findings";

    private static final String INDEX_FILE_NAME = "findings-index.json";

    private final Path findingsDirectory;
    private final Path indexFile;
    private final int maxFindings;
    private final int maxContexts;
    /**
     * finding 库：LinkedHashMap 天然按插入顺序迭代。所有读写经 #lock 串行。
     */
    private final LinkedHashMap<String, Finding> findings = new LinkedHashMap<>();
    /** 维护 findings 的 FIFO 插入顺序,用于按最旧淘汰。 */
    private final LinkedHashSet<String> findingIdsInOrder = new LinkedHashSet<>();
    /** analysisId → 同一分析的所有 finding；与 Finding.findingId 全局唯一正交。 */
    private final LinkedHashMap<String, List<Finding>> findingsByAnalysisId = new LinkedHashMap<>();
    /**
     * 一次完整分析的上下文：key = {@code AnalysisResult.getAnalysisId()}。
     * 完整报告 / HTTP method / URL / 状态码 / 关联 requestId 在此共享。
     * 同 id 二次入库时 {@code remove + put} 把它移到末尾。
     */
    private final LinkedHashMap<String, AnalysisContext> contexts = new LinkedHashMap<>();
    /**
     * 被标记为"误报"的 findingId 集合。
     *
     * 不放在 Finding 字段里:保持 Finding 的不可变语义;标记属于"用户对当前 store
     * 的视图选择",与 finding 本身的分析结果无关。
     * finding 从主索引离开的所有路径(remove / clear / FIFO 淘汰)都同步清理本 set,
     * 避免 set 与 findings map 状态不一致。
     */
    private final LinkedHashSet<String> markedFalsePositiveIds = new LinkedHashSet<>();
    private final List<Consumer<Void>> listeners = new CopyOnWriteArrayList<>();
    private final Object lock = new Object();
    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    /**
     * 用已解析好的会话根目录构建问题库。
     *
     * @param sessionRoot 会话根目录（{@code SessionPaths.createProjectDirectory(...).path()} 的输出）；
     *                    findings 索引落在 {@code <sessionRoot>/findings/findings-index.json}。
     * @throws IOException 无法创建存储目录时抛出。
     */
    public FindingStore(Path sessionRoot) throws IOException {
        this(sessionRoot, DEFAULT_MAX_FINDINGS, DEFAULT_MAX_CONTEXTS);
    }

    /**
     * 包级构造：测试可调，仅控制 findings 上限（contexts 用默认值）。
     */
    FindingStore(Path sessionRoot, int maxFindings) throws IOException {
        this(sessionRoot, maxFindings, DEFAULT_MAX_CONTEXTS);
    }

    /**
     * 包级构造：测试可调，单独控制 findings / contexts 上限。
     */
    FindingStore(Path sessionRoot, int maxFindings, int maxContexts) throws IOException {
        this.findingsDirectory = sessionRoot.resolve(FINDINGS_DIRECTORY_NAME);
        this.indexFile = findingsDirectory.resolve(INDEX_FILE_NAME);
        this.maxFindings = maxFindings;
        this.maxContexts = maxContexts;
        Files.createDirectories(findingsDirectory);
        loadIndex();
    }

    /**
     * 把一次分析的 findings 合并到全局库。
     *
     * 同一次分析内的多条 finding 分别独立入库（每条都有唯一 findingId）；
     * 重复添加（findingId 已存在）会被静默忽略——正常流程里 findingId 不会冲突。
     *
     * 同时把该次分析的 AnalysisResult 缓存到 AnalysisContext，
     * 供下方详情页签读取"完整分析报告"和"关联 requestId"。
     *
     * request / response 字节：该方法不携带原文。AnalysisContext 里
     * 这两个字段会是 null，UI 选中 finding 时会回退到 {@code AnalysisHistoryStore} 反查。
     * 需要"原文直达"时调 #addFindings(AnalysisResult, byte[], byte[])。
     *
     * @param result 来自 TrafficAnalyzer 的分析结果。
     */
    public void addFindings(AnalysisResult result) {
        addFindings(result, null, null);
    }

    /**
     * 把一次分析的 findings 合并到全局库，并缓存分析时使用的原始 request / response 字节。
     *
     * request / response 字节仅存内存（不持久化到 findings-index.json），原因是：
     * 报文可能很大，且 AnalysisHistoryStore 已经按需持久化完整报文；问题库磁盘只保留
     * finding 元数据 + summary。重启后这两字段会丢失，UI 选中时回退到 trafficStore 反查。
     *
     * 这一路径让"Repeater 主动发起的报文"等不在 Proxy 历史里的请求也能在下方
     * 报文页签完整展示。
     *
     * @param result        来自 TrafficAnalyzer 的分析结果。
     * @param requestBytes  分析时使用的原始请求字节；可为 null（不携带）。
     * @param responseBytes 分析时使用的原始响应字节；可为 null（无响应 / 不携带）。
     */
    public void addFindings(AnalysisResult result, byte[] requestBytes, byte[] responseBytes) {
        if (result == null) {
            return;
        }
        List<Finding> list = result.getFindings();
        boolean hasContext = result.getSummary() != null
                || result.getMethod() != null
                || result.getUrl() != null;
        boolean changed = false;
        synchronized (lock) {
            String analysisId = result.getAnalysisId();
            // 1. 缓存分析上下文（即便没有 findings 也存，UI 可能需要查看"无问题"的报告）
            if (hasContext) {
                AnalysisContext newCtx = new AnalysisContext(analysisId, result.getTimestampMillis(),
                        result.getMethod(), result.getUrl(), result.getStatusCode(),
                        result.getSummary(), requestBytes, responseBytes);
                if (contexts.containsKey(analysisId)) {
                    // 已存在该 analysisId 的 context：remove + put 把 LinkedHashMap 中的
                    // 条目重新移动到末尾（"刷新时同步更新插入顺序末尾"语义）。
                    contexts.remove(analysisId);
                }
                contexts.put(analysisId, newCtx);
                evictContextsIfNeeded();
            }
            // 2. 合并 findings
            if (list != null) {
                for (Finding f : list) {
                    if (f == null) {
                        continue;
                    }
                    // putIfAbsent 语义保留：findingId 已存在时静默忽略。
                    if (findings.putIfAbsent(f.getFindingId(), f) == null) {
                        findingIdsInOrder.add(f.getFindingId());
                        // 同步建 analysisId → finding 桶：首次见到该 analysisId 时创建,后续 finding 复用同一 list。
                        List<Finding> bucket = findingsByAnalysisId.get(analysisId);
                        if (bucket == null) {
                            bucket = new ArrayList<>();
                            findingsByAnalysisId.put(analysisId, bucket);
                        }
                        bucket.add(f);
                        changed = true;
                    }
                }
                evictIfNeeded();
            }
            if (changed) {
                persistIndex();
            }
        }
        if (changed) {
            notifyListeners();
        }
    }

    /**
     * 返回当前所有问题，按"安装时间升序"排序（最旧在前、最新在底），与
     * com.auditai.burp.history.AnalysisHistoryStore#list() 的"新条目滚到底部"
     * 行为保持一致，UI 表格直接按返回顺序填模型行即可。
     *
     * List#sort(Comparator) 是 stable sort：当多条 finding 的
     * {@code capturedAtMillis} 相同时，退化为 LinkedHashMap 的插入顺序
     * （即 #addFindings 的到达先后）。
     */
    public List<Finding> list() {
        List<Finding> result;
        synchronized (lock) {
            // LinkedHashMap.values() 保留插入顺序；新 ArrayList 拷贝避免外部
            // 持有内部视图后被后续 mutation 影响。
            result = new ArrayList<>(findings.values());
        }
        result.sort(SORT_BY_CAPTURED_TIME_ASC);
        return Collections.unmodifiableList(result);
    }

    /**
     * 默认排序：按 Finding#getCapturedAtMillis() 升序——最旧 finding 在列表顶部，
     * 最新 finding 在列表底部，让"最新发现滚到底部"的视觉规律与"历史"页签一致。
     */
    static final Comparator<Finding> SORT_BY_CAPTURED_TIME_ASC =
            Comparator.comparingLong(Finding::getCapturedAtMillis);

    /**
     * 返回指定 finding 所属分析的完整上下文（报告、method、url、状态码）。
     *
     * 找不到对应分析时（极少见：finding 是磁盘恢复出来的、但 context 被清理），
     * 返回仅含 findingId 占位的最小 context，永不返回 null。
     */
    public AnalysisContext contextFor(Finding finding) {
        if (finding == null) {
            return AnalysisContext.empty();
        }
        AnalysisContext ctx;
        synchronized (lock) {
            // 必须与写侧（addFindings / remove / clear / evict*）共用同一把锁：
            // contexts 是 LinkedHashMap，本方法由 EDT 在"选中 finding"时调用，
            // 而写侧在分析线程上做结构性修改（put/remove），无锁读会读到撕裂状态。
            ctx = contexts.get(finding.getAnalysisId());
        }
        if (ctx != null) {
            return ctx;
        }
        // 兜底：用 finding 自身字段构造一个最小 context，确保 UI 不会 NPE
        return new AnalysisContext(finding.getAnalysisId(), finding.getCapturedAtMillis(),
                finding.getMethod(), finding.getUrl(), -1, "");
    }

    /**
     * 按 analysisId 取本次分析的所有 finding；未命中返回空列表(非 null)。
     * 返回的 list 是内部引用副本,调用方可放心遍历或修改。
     */
    public List<Finding> findingsByAnalysisId(String analysisId) {
        if (analysisId == null || analysisId.isBlank()) {
            return List.of();
        }
        synchronized (lock) {
            List<Finding> bucket = findingsByAnalysisId.get(analysisId);
            if (bucket == null || bucket.isEmpty()) {
                return List.of();
            }
            return new ArrayList<>(bucket);
        }
    }

    /** 按 analysisId 取完整分析上下文；找不到返回 AnalysisContext.empty()（永不 null）。 */
    public AnalysisContext contextForAnalysisId(String analysisId) {
        if (analysisId == null || analysisId.isBlank()) {
            return AnalysisContext.empty();
        }
        synchronized (lock) {
            AnalysisContext ctx = contexts.get(analysisId);
            if (ctx != null) {
                return ctx;
            }
        }
        return AnalysisContext.empty();
    }

    /**
     * 删除单条问题。
     *
     * 按 {@code findingId} 精确删除（findingId 是 finding 的全局唯一 ID，由
     * Finding#create / Finding#placeholder(String, Severity, String, String, long, long)
     * 工厂方法随机生成）；
     * 删除后若该 finding 所属的 {@code analysisTimestamp} 没有任何其它 finding
     * 引用，则把对应的 AnalysisContext 也一并清理掉（避免 context 表
     * 长期持有已被删除 finding 的 request/response 字节）。
     *
     * 未找到指定 {@code findingId} 时静默忽略；调用方无需额外判空。
     * 删除成功后同步刷新磁盘索引并通知监听器。
     *
     * @param findingId 要删除的问题 ID；为 null / 空白 / 不存在时不做任何操作。
     * @return 是否实际执行了删除（用于 UI 上区分"删掉了" vs "本来就没有"）。
     */
    public boolean remove(String findingId) {
        if (findingId == null || findingId.isBlank()) {
            return false;
        }
        synchronized (lock) {
            Finding existing = findings.remove(findingId);
            if (existing == null) {
                return false;
            }
            findingIdsInOrder.remove(findingId);
            // 同步清理误报标记：finding 删了,标记不能再引用 dangling id
            markedFalsePositiveIds.remove(findingId);
            String aid = existing.getAnalysisId();
            // 同步清理 analysisId → finding 索引桶
            List<Finding> bucket = findingsByAnalysisId.get(aid);
            if (bucket != null) {
                bucket.remove(existing);
                if (bucket.isEmpty()) {
                    findingsByAnalysisId.remove(aid);
                }
            }
            // 如果这条 finding 是它所在 analysisId 的最后一条引用，回收 context
            boolean stillReferenced = false;
            for (Finding f : findings.values()) {
                if (aid.equals(f.getAnalysisId())) {
                    stillReferenced = true;
                    break;
                }
            }
            if (!stillReferenced) {
                contexts.remove(aid);
            }
            persistIndex();
        }
        // 走到这里说明确实删掉了一条（上面的 early-return 已覆盖"未找到"分支）。
        notifyListeners();
        return true;
    }

    /**
     * 给指定 finding 打/取消"误报"标记。{@code marked=true} 表示该 finding 已被人工判定为误报,
     * {@code marked=false} 表示取消标记。
     *
     * 状态真正发生变化时同步写盘 + 通知监听器;状态未变(findingId 未命中 store 或
     * 已经是目标状态)时静默返回 false,不写盘、不通知,避免无意义的 IO / 刷新风暴。
     *
     * @return 是否实际改变了状态(用于区分"本次设置有效"vs"本来就是这个状态")。
     */
    public boolean setFalsePositive(String findingId, boolean marked) {
        if (findingId == null || findingId.isBlank()) {
            return false;
        }
        boolean changed;
        synchronized (lock) {
            if (!findings.containsKey(findingId)) {
                return false;
            }
            if (marked) {
                changed = markedFalsePositiveIds.add(findingId);
            } else {
                changed = markedFalsePositiveIds.remove(findingId);
            }
            if (changed) {
                persistIndex();
            }
        }
        if (changed) {
            notifyListeners();
        }
        return changed;
    }

    /**
     * 查询某条 finding 当前是否处于"标记误报"状态。
     *
     * findingId 为 null / 空白 / 不存在时一律返回 false(不抛异常)。
     * 与 #setFalsePositive 配对使用,UI 渲染器按行调用决定列显示。
     */
    public boolean isMarkedFalsePositive(String findingId) {
        if (findingId == null || findingId.isBlank()) {
            return false;
        }
        synchronized (lock) {
            return markedFalsePositiveIds.contains(findingId);
        }
    }

    /**
     * 清空所有问题。
     */
    public void clear() {
        boolean changed;
        synchronized (lock) {
            changed = !findings.isEmpty() || !contexts.isEmpty() || !findingsByAnalysisId.isEmpty()
                    || !markedFalsePositiveIds.isEmpty();
            findings.clear();
            contexts.clear();
            findingsByAnalysisId.clear();
            findingIdsInOrder.clear();
            markedFalsePositiveIds.clear();
            if (changed) {
                persistIndex();
            }
        }
        if (changed) {
            notifyListeners();
        }
    }

    /**
     * 返回问题库目录 {@code <sessionRoot>/findings}（用于诊断 / 日志）。
     */
    public Path findingsDirectory() {
        return findingsDirectory;
    }

    /**
     * 释放内存索引；磁盘文件保留，重启后自动恢复。
     *
     * 本 store 没有后台线程或文件句柄等需要显式清理的资源（内存索引随 GC 回收），
     * close 仅用于满足 AutoCloseable 契约，无实际动作。
     */
    @Override
    public void close() {
        // 磁盘数据保留（重启后自动恢复），但卸载时清空所有匿名监听器，避免
        // FindingStore 长期持有外部 lambda/Consumer 引用（如 FindingsPanel 实例），
        // 在 close() 路径上漏走时的最后一道防线。
        clearListeners();
    }

    /**
     * 注册更新监听器：每次 #addFindings(AnalysisResult) /
     * #clear() 真正修改了库时同步触发。
     */
    public void addListener(Consumer<Void> listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    public void removeListener(Consumer<Void> listener) {
        listeners.remove(listener);
    }

    /**
     * 清空所有更新监听器。卸载路径兜底使用，避免对匿名 lambda 无法定向注销。
     */
    public void clearListeners() {
        listeners.clear();
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
     * 超过 #maxContexts 上限时按插入顺序淘汰最旧 context。
     *
     * 不连带删除 finding —— finding 仍按 #evictIfNeeded 控制的上限
     * 保留元数据 + summary。被淘汰的 context 对应 finding 调 #contextFor
     * 时会拿到"兜底 context"（用 finding 自身字段构造，无 request/response 字节），
     * UI 自动回退到 {@code AnalysisHistoryStore} 反查路径。
     */
    private void evictContextsIfNeeded() {
        while (contexts.size() > maxContexts) {
            String oldest = contexts.isEmpty() ? null : contexts.keySet().iterator().next();
            if (oldest == null) {
                return;
            }
            contexts.remove(oldest);
        }
    }

    /**
     * 超过上限时按插入顺序淘汰最旧条目；同时丢弃这些 finding 关联的 context（避免 context 表无限增长）。
     */
    private void evictIfNeeded() {
        while (findings.size() > maxFindings) {
            String oldest = findingIdsInOrder.isEmpty() ? null : findingIdsInOrder.iterator().next();
            if (oldest == null) {
                return;
            }
            Finding removed = findings.remove(oldest);
            findingIdsInOrder.remove(oldest);
            // 同步清理误报标记:FIFO 淘汰时也必须移除 dangling id,与 #remove 行为一致。
            // 不清的话 isMarkedFalsePositive(oldest) 还会返回 true,但 store 已找不到该 finding,
            // 形成"set 里有标记、findings map 里没记录"的不一致状态。
            markedFalsePositiveIds.remove(oldest);
            if (removed != null) {
                String aid = removed.getAnalysisId();
                // 同步清理 analysisId 索引桶
                List<Finding> bucket = findingsByAnalysisId.get(aid);
                if (bucket != null) {
                    bucket.remove(removed);
                    if (bucket.isEmpty()) {
                        findingsByAnalysisId.remove(aid);
                    }
                }
                // 只在没有任何 finding 引用该 analysisId 时才清掉 context
                if (findings.values().stream().noneMatch(f -> aid.equals(f.getAnalysisId()))) {
                    contexts.remove(aid);
                }
            }
        }
    }

    private void loadIndex() throws IOException {
        if (!Files.exists(indexFile)) {
            return;
        }
        String text = Files.readString(indexFile, StandardCharsets.UTF_8);
        JsonObject root;
        try {
            root = gson.fromJson(text, JsonObject.class);
        } catch (RuntimeException e) {
            return;
        }
        if (root == null) {
            return;
        }
        synchronized (lock) {
            // 1. 恢复 contexts（LinkedHashMap.put 自带"按调用顺序追加"语义，
            //    磁盘恢复的 context 没有 request/response 字节，内存压力小，全部保留）
            if (root.has("contexts") && root.get("contexts").isJsonArray()) {
                JsonArray ctxs = root.getAsJsonArray("contexts");
                for (int i = 0; i < ctxs.size(); i++) {
                    JsonElement el = ctxs.get(i);
                    if (el == null || !el.isJsonObject()) {
                        continue;
                    }
                    JsonObject c = el.getAsJsonObject();
                    long ts = c.has("timestampMillis") && c.get("timestampMillis").isJsonPrimitive()
                            ? c.get("timestampMillis").getAsLong() : 0L;
                    // 老 findings-index.json 的 context 缺 analysisId 字段时兜底成空串,不阻塞加载。
                    String aid = c.has("analysisId") && c.get("analysisId").isJsonPrimitive()
                            ? c.get("analysisId").getAsString() : "";
                    String method = readString(c, "method");
                    String url = readString(c, "url");
                    int status = c.has("statusCode") && c.get("statusCode").isJsonPrimitive()
                            ? c.get("statusCode").getAsInt() : -1;
                    String summary = readString(c, "summary");
                    if (ts > 0 || !aid.isEmpty()) {
                        contexts.put(aid, new AnalysisContext(aid, ts, method, url, status, summary));
                    }
                }
            }
            // 2. 恢复 findings（同上：LinkedHashMap.put 按 JSON 数组顺序保留插入序）
            if (root.has("findings") && root.get("findings").isJsonArray()) {
                JsonArray arr = root.getAsJsonArray("findings");
                for (int i = 0; i < arr.size(); i++) {
                    JsonElement el = arr.get(i);
                    if (el == null || !el.isJsonObject()) {
                        continue;
                    }
                    Finding parsed = deserializeFinding(el.getAsJsonObject());
                    if (parsed != null) {
                        findings.put(parsed.getFindingId(), parsed);
                        findingIdsInOrder.add(parsed.getFindingId());
                        // 同步重建 analysisId → finding 索引。
                        String aid = parsed.getAnalysisId();
                        List<Finding> bucket = findingsByAnalysisId.get(aid);
                        if (bucket == null) {
                            bucket = new ArrayList<>();
                            findingsByAnalysisId.put(aid, bucket);
                        }
                        bucket.add(parsed);
                    }
                }
            }
            // 3. 恢复"标记误报"集合:仅保留当前仍存在于 findings map 中的 id,
            //    老版本磁盘文件(无 markedFindingPositiveIds 字段)或指向已删除 finding 的
            //    dangling id 都会被静默丢弃,不会影响加载。
            if (root.has("markedFalsePositiveIds") && root.get("markedFalsePositiveIds").isJsonArray()) {
                JsonArray ids = root.getAsJsonArray("markedFalsePositiveIds");
                for (int i = 0; i < ids.size(); i++) {
                    JsonElement el = ids.get(i);
                    String id = el == null || !el.isJsonPrimitive() ? null : el.getAsString();
                    if (id != null && findings.containsKey(id)) {
                        markedFalsePositiveIds.add(id);
                    }
                }
            }
        }
    }

    private static Finding deserializeFinding(JsonObject obj) {
        try {
            String id = obj.has("findingId") && obj.get("findingId").isJsonPrimitive()
                    ? obj.get("findingId").getAsString() : null;
            // analysisId:老 findings-index.json 缺该字段时为 null,由 Finding.restore 内部兜底 UUID。
            String analysisId = obj.has("analysisId") && obj.get("analysisId").isJsonPrimitive()
                    ? obj.get("analysisId").getAsString() : null;
            String method = readString(obj, "method");
            String url = readString(obj, "url");
            String type = readString(obj, "type");
            int confidence = obj.has("confidence") && obj.get("confidence").isJsonPrimitive()
                    ? obj.get("confidence").getAsInt() : 0;
            Severity severity = Severity.parse(readString(obj, "severity"));
            String description = readString(obj, "description");
            long capturedAt = obj.has("capturedAtMillis") && obj.get("capturedAtMillis").isJsonPrimitive()
                    ? obj.get("capturedAtMillis").getAsLong() : System.currentTimeMillis();
            long analysisTs = obj.has("analysisTimestamp") && obj.get("analysisTimestamp").isJsonPrimitive()
                    ? obj.get("analysisTimestamp").getAsLong() : capturedAt;
            boolean placeholder = obj.has("placeholder") && obj.get("placeholder").isJsonPrimitive()
                    && obj.get("placeholder").getAsBoolean();
            // 旧版本磁盘文件里可能存在 title 字段（旧的字段名）；当前 Finding 已改用 description，
            // 反序列化时若 description 缺失则用 title 兜底，避免数据丢失。
            if (description == null || description.isBlank()) {
                description = readString(obj, "title");
            }
            // 直接走 restore() 工厂把 placeholder 标记也带回去，restore 内部会处理 findingId。
            return Finding.restore(id, analysisId, method, url, type, confidence, severity, description,
                    capturedAt, analysisTs, placeholder);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String readString(JsonObject obj, String key) {
        if (!obj.has(key)) {
            return null;
        }
        return AnalysisResponseParser.readString(obj, key);
    }

    private void persistIndex() {
        JsonObject root = new JsonObject();
        JsonArray arr = new JsonArray();
        JsonArray ctxs = new JsonArray();
        JsonArray marked = new JsonArray();
        synchronized (lock) {
            for (Finding f : findings.values()) {
                arr.add(serializeFinding(f));
            }
            for (AnalysisContext ctx : contexts.values()) {
                ctxs.add(serializeContext(ctx));
            }
            for (String id : markedFalsePositiveIds) {
                marked.add(id);
            }
        }
        root.add("findings", arr);
        root.add("contexts", ctxs);
        root.add("markedFalsePositiveIds", marked);
        try {
            Path tmp = Files.createTempFile(findingsDirectory, "findings-index", ".tmp");
            try {
                Files.writeString(tmp, gson.toJson(root), StandardCharsets.UTF_8);
                try {
                    Files.move(tmp, indexFile, StandardCopyOption.ATOMIC_MOVE,
                            StandardCopyOption.REPLACE_EXISTING);
                } catch (AtomicMoveNotSupportedException e) {
                    Files.move(tmp, indexFile, StandardCopyOption.REPLACE_EXISTING);
                }
            } finally {
                Files.deleteIfExists(tmp);
            }
        } catch (IOException e) {
            // 持久化失败不应影响功能；下一次写入会再次尝试
        }
    }

    private static JsonObject serializeFinding(Finding f) {
        JsonObject obj = new JsonObject();
        obj.addProperty("findingId", f.getFindingId());
        obj.addProperty("analysisId", f.getAnalysisId());
        obj.addProperty("method", f.getMethod());
        obj.addProperty("url", f.getUrl());
        obj.addProperty("type", f.getType());
        obj.addProperty("confidence", f.getConfidence());
        obj.addProperty("severity", f.getSeverity().name());
        obj.addProperty("description", f.getDescription());
        obj.addProperty("placeholder", f.isPlaceholder());
        obj.addProperty("capturedAtMillis", f.getCapturedAtMillis());
        obj.addProperty("analysisTimestamp", f.getAnalysisTimestamp());
        return obj;
    }

    private static JsonObject serializeContext(AnalysisContext ctx) {
        JsonObject obj = new JsonObject();
        obj.addProperty("analysisId", ctx.analysisId == null ? "" : ctx.analysisId);
        obj.addProperty("timestampMillis", ctx.timestampMillis);
        obj.addProperty("method", ctx.method == null ? "" : ctx.method);
        obj.addProperty("url", ctx.url == null ? "" : ctx.url);
        obj.addProperty("statusCode", ctx.statusCode);
        obj.addProperty("summary", ctx.summary == null ? "" : ctx.summary);
        return obj;
    }

    /**
     * 一次完整分析（AnalysisResult）的上下文：仅存"按 finding 共享的"信息，
     * 避免每条 finding 重复存同一份 summary。
     *
     * request / response 字节：仅内存持有，不进磁盘。原因：报文可能很大，
     * 且 HTTP history（AnalysisHistoryStore）已经按需持久化完整报文；问题库磁盘上
     * 只需要保留 finding 元数据 + summary，重启后让 UI 回退到 AnalysisHistoryStore
     * 反查。重启后内存里的字节就丢失，#getRequestBytes() /
     * #getResponseBytes() 会返回 null。
     */
    public static final class AnalysisContext {
        private final String analysisId;
        private final long timestampMillis;
        private final String method;
        private final String url;
        private final int statusCode;
        private final String summary;
        private final byte[] requestBytes;
        private final byte[] responseBytes;

        /** 磁盘恢复用：request/response 字节为 null。 */
        AnalysisContext(String analysisId, long timestampMillis, String method, String url, int statusCode,
                        String summary) {
            this(analysisId, timestampMillis, method, url, statusCode, summary, null, null);
        }

        /** 完整构造：request/response 字节由调用方传入；为 null 表示"未提供"。 */
        AnalysisContext(String analysisId, long timestampMillis, String method, String url, int statusCode,
                        String summary, byte[] requestBytes, byte[] responseBytes) {
            this.analysisId = analysisId == null ? "" : analysisId;
            this.timestampMillis = timestampMillis;
            this.method = method == null ? "" : method;
            this.url = url == null ? "" : url;
            this.statusCode = statusCode;
            this.summary = summary == null ? "" : summary;
            this.requestBytes = requestBytes;
            this.responseBytes = responseBytes;
        }

        static AnalysisContext empty() {
            return new AnalysisContext("", 0L, "", "", -1, "");
        }

        /** 本次分析的共享 ID,与 AnalysisResult.getAnalysisId() / Finding.getAnalysisId() 一致。 */
        public String getAnalysisId() {
            return analysisId;
        }

        public long getTimestampMillis() {
            return timestampMillis;
        }

        public String getMethod() {
            return method;
        }

        public String getUrl() {
            return url;
        }

        public int getStatusCode() {
            return statusCode;
        }

        public String getSummary() {
            return summary;
        }

        /**
         * 分析时使用的原始请求字节；可能为 null（来自磁盘恢复 / 调用方未提供）。
         * 返回的数组是 store 内部持有的一份拷贝（或原引用），调用方不应修改。
         */
        public byte[] getRequestBytes() {
            return requestBytes;
        }

        /** 分析时使用的原始响应字节；可能为 null（无响应 / 来自磁盘恢复 / 调用方未提供）。 */
        public byte[] getResponseBytes() {
            return responseBytes;
        }
    }
}
