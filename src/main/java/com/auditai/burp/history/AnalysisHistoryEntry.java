package com.auditai.burp.history;

import com.google.gson.JsonObject;

import java.nio.file.Path;

/**
 * 单条"经 AI 分析过的报文"快照。
 *
 * <p>由 {@link AnalysisHistoryStore} 在分析完成回调里一次性构造，UI 只读；
 * 所有字段在构造时确定，之后不再修改，天然线程安全。</p>
 *
 * <p>正文（request/response 字节）落盘到独立 gzip 文件，本类只保留文件路径；
 * UI 选中行时通过 {@link #getRequestFile()} / {@link #getResponseFile()} 拿到
 * 路径再由 {@code BodyStorage.readCompressed} 按需解压读盘，内存峰值可控。</p>
 */
public final class AnalysisHistoryEntry {

    /** 自增 ID（按分析时间升序；UI "序号" 列直接展示）。 */
    private final long id;

    /** 分析开始时间戳（毫秒），与 {@link com.auditai.burp.http.AnalysisResult#getTimestampMillis()} 一致。 */
    private final long timestamp;

    /** 触发来源：手动 / 被动。 */
    private final AnalysisTrigger triggerType;

    /** HTTP 方法（GET / POST / …）。 */
    private final String method;

    /** 完整请求 URL。 */
    private final String url;

    /** 响应状态码；无响应时为 {@code -1}。 */
    private final int statusCode;

    /** AI 摘要（成功时）；失败时为错误描述。 */
    private final String summary;

    /** 错误信息；成功时为 {@code null}。 */
    private final String error;

    /** 风险等级（从 findings 推导；失败或无 finding 时为 NONE）。 */
    private final RiskLevel riskLevel;

    /** 分析耗时（毫秒），含 AI 接口往返时间。 */
    private final long durationMillis;

    /** 是否存在响应（区别"无响应"和"空响应体"）。 */
    private final boolean hasResponse;

    /** 原始请求字节（可空；优先走 on-disk 路径，仅在内存缓存可命中时使用）。 */
    private final byte[] requestBytes;

    /** 原始响应字节（可空；无响应时为 null）。 */
    private final byte[] responseBytes;

    /** 请求字节是否被裁剪（true 时下方编辑器看到的可能是占位符）。 */
    private final boolean requestTruncated;

    /** 响应字节是否被裁剪。 */
    private final boolean responseTruncated;

    /** 请求正文落盘文件路径（null 表示无请求字节或未落盘）。 */
    private final Path requestFile;

    /** 响应正文落盘文件路径（null 表示无响应字节或未落盘）。 */
    private final Path responseFile;

    /** 请求 SHA-256 哈希（用于跨记录去重 / 调试）。 */
    private final String requestHash;

    /** 响应 SHA-256 哈希。 */
    private final String responseHash;

    /**
     * 被动分析指纹（{@link com.auditai.burp.passive.RequestFingerprint#compute} 的输出）。
     *
     * <p>在 {@link AnalysisHistoryStore#add} 写入时一次性计算并落盘，启动时
     * {@link com.auditai.burp.passive.FingerprintDedup} 读它做去重预热——保证 dedup
     * 与 history 的指纹算法完全一致（避免 body 哈希口径不同导致 miss）。</p>
     *
     * <p>老数据（升级前写入的 entry）反序列化时该字段为 {@code null}，启动预热会跳过，
     * 不影响加载与展示。</p>
     */
    private final String requestFingerprint;

    /** 模型给出的 finding 数量（成功时 >= 0；失败 / summary 为空时为 0）。 */
    private final int findingCount;

    /**
     * 审计轨迹 XML 文件路径：与本 entry 一一对应，记录本次分析中 agent 与 AI 的全部交互。
     * 位于 {@code <sessionRoot>/audit-trails/}；删除 entry 时同步物理删除该文件。
     * 取消 / 未完成分析不写 entry，自然也不会有该文件。
     */
    private final Path auditTrailFile;

    /**
     * 构造器：所有字段必须由调用方一次性确定。
     *
     * @param id                自增 ID。
     * @param timestamp         分析开始时间戳（毫秒）。
     * @param triggerType       触发来源。
     * @param method            HTTP 方法。
     * @param url               完整请求 URL。
     * @param statusCode        响应状态码；无响应时为 -1。
     * @param summary           AI 摘要 / 失败描述。
     * @param error             错误信息；成功时为 null。
     * @param riskLevel         风险等级。
     * @param durationMillis    分析耗时。
     * @param hasResponse       是否有响应。
     * @param requestBytes      请求字节（可空）。当前主流程一律传 {@code null}：正文走
     *                          {@code requestFile} 落盘按需解压，该字段仅为潜在的内存缓存路径预留。
     * @param responseBytes     响应字节（可空）。同上，主流程传 {@code null}。
     * @param requestTruncated  请求字节是否被裁剪。
     * @param responseTruncated 响应字节是否被裁剪。
     * @param requestFile       请求正文落盘路径。
     * @param responseFile      响应正文落盘路径。
     * @param requestHash       请求 SHA-256 哈希。
     * @param responseHash      响应 SHA-256 哈希。
     * @param requestFingerprint 被动分析指纹（与 {@link com.auditai.burp.passive.RequestFingerprint#compute} 严格一致）。
     * @param findingCount      finding 数量。
     * @param auditTrailFile    审计轨迹 XML 文件路径（可空：取消 / 不启用 audit-trail 时为 null）。
     */
    public AnalysisHistoryEntry(long id, long timestamp, AnalysisTrigger triggerType,
                                String method, String url, int statusCode,
                                String summary, String error, RiskLevel riskLevel,
                                long durationMillis, boolean hasResponse,
                                byte[] requestBytes, byte[] responseBytes,
                                boolean requestTruncated, boolean responseTruncated,
                                Path requestFile, Path responseFile,
                                String requestHash, String responseHash,
                                String requestFingerprint,
                                int findingCount,
                                Path auditTrailFile) {
        this.id = id;
        this.timestamp = timestamp;
        this.triggerType = triggerType;
        this.method = method == null ? "" : method;
        this.url = url == null ? "" : url;
        this.statusCode = statusCode;
        this.summary = summary == null ? "" : summary;
        this.error = error;
        this.riskLevel = riskLevel == null ? RiskLevel.NONE : riskLevel;
        this.durationMillis = durationMillis;
        this.hasResponse = hasResponse;
        this.requestBytes = requestBytes;
        this.responseBytes = responseBytes;
        this.requestTruncated = requestTruncated;
        this.responseTruncated = responseTruncated;
        this.requestFile = requestFile;
        this.responseFile = responseFile;
        this.requestHash = requestHash;
        this.responseHash = responseHash;
        this.requestFingerprint = requestFingerprint;
        this.findingCount = Math.max(0, findingCount);
        this.auditTrailFile = auditTrailFile;
    }

    public long getId() {
        return id;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public AnalysisTrigger getTriggerType() {
        return triggerType;
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

    public String getError() {
        return error;
    }

    public RiskLevel getRiskLevel() {
        return riskLevel;
    }

    public long getDurationMillis() {
        return durationMillis;
    }

    public boolean isHasResponse() {
        return hasResponse;
    }

    public byte[] getRequestBytes() {
        return requestBytes;
    }

    public byte[] getResponseBytes() {
        return responseBytes;
    }

    public boolean isRequestTruncated() {
        return requestTruncated;
    }

    public boolean isResponseTruncated() {
        return responseTruncated;
    }

    public Path getRequestFile() {
        return requestFile;
    }

    public Path getResponseFile() {
        return responseFile;
    }

    public String getRequestHash() {
        return requestHash;
    }

    public String getResponseHash() {
        return responseHash;
    }

    /**
     * 被动分析指纹（{@link com.auditai.burp.passive.RequestFingerprint#compute} 输出）。
     *
     * <p>可能为 {@code null}：写入前调用方未传、或从老 index.json 升级上来的 entry。
     * 调用方使用前应做 null 检查。</p>
     */
    public String getRequestFingerprint() {
        return requestFingerprint;
    }

    public int getFindingCount() {
        return findingCount;
    }

    /**
     * 审计轨迹 XML 文件路径：与本 entry 一一对应。删除 entry 时同步物理删除该文件。
     * 可空（取消 / 老数据）。
     */
    public Path getAuditTrailFile() {
        return auditTrailFile;
    }

    /**
     * 序列化为 JSON：供 {@link AnalysisHistoryStore} 写入 index.json。
     *
     * <p>仅持久化轻量元数据 + 路径 / 哈希，<b>不</b>包含 body 字节（body 单独落盘）。</p>
     */
    JsonObject toJson() {
        JsonObject obj = new JsonObject();
        obj.addProperty("id", id);
        obj.addProperty("timestamp", timestamp);
        obj.addProperty("triggerType", triggerType.name());
        obj.addProperty("method", method);
        obj.addProperty("url", url);
        obj.addProperty("statusCode", statusCode);
        obj.addProperty("summary", summary);
        if (error != null) {
            obj.addProperty("error", error);
        }
        obj.addProperty("riskLevel", riskLevel.name());
        obj.addProperty("durationMillis", durationMillis);
        obj.addProperty("hasResponse", hasResponse);
        obj.addProperty("requestTruncated", requestTruncated);
        obj.addProperty("responseTruncated", responseTruncated);
        if (requestFile != null) {
            obj.addProperty("requestFile", requestFile.toString());
        }
        if (responseFile != null) {
            obj.addProperty("responseFile", responseFile.toString());
        }
        if (requestHash != null) {
            obj.addProperty("requestHash", requestHash);
        }
        if (responseHash != null) {
            obj.addProperty("responseHash", responseHash);
        }
        if (requestFingerprint != null) {
            obj.addProperty("requestFingerprint", requestFingerprint);
        }
        obj.addProperty("findingCount", findingCount);
        if (auditTrailFile != null) {
            obj.addProperty("auditTrailFile", auditTrailFile.toString());
        }
        return obj;
    }

    /**
     * 从 JSON 反序列化
     * 缺字段 / 字段类型不合法时回退为安全默认（保证不会 NPE）。
     */
    static AnalysisHistoryEntry fromJson(JsonObject obj) {
        long id = obj.has("id") && obj.get("id").isJsonPrimitive() ? obj.get("id").getAsLong() : 0L;
        long ts = obj.has("timestamp") && obj.get("timestamp").isJsonPrimitive()
                ? obj.get("timestamp").getAsLong() : 0L;
        AnalysisTrigger trigger = AnalysisTrigger.MANUAL;
        try {
            String t = obj.has("triggerType") && obj.get("triggerType").isJsonPrimitive()
                    ? obj.get("triggerType").getAsString() : "MANUAL";
            trigger = AnalysisTrigger.valueOf(t);
        } catch (RuntimeException ignored) {
            // 旧版本数据缺 triggerType 字段时默认 MANUAL
        }
        String method = readString(obj, "method");
        String url = readString(obj, "url");
        int statusCode = obj.has("statusCode") && obj.get("statusCode").isJsonPrimitive()
                ? obj.get("statusCode").getAsInt() : -1;
        String summary = readString(obj, "summary");
        String error = obj.has("error") && obj.get("error").isJsonPrimitive()
                ? obj.get("error").getAsString() : null;
        RiskLevel risk = RiskLevel.NONE;
        try {
            String r = obj.has("riskLevel") && obj.get("riskLevel").isJsonPrimitive()
                    ? obj.get("riskLevel").getAsString() : "NONE";
            risk = RiskLevel.valueOf(r);
        } catch (RuntimeException ignored) {
            // 老数据 riskLevel 字段缺失或非法时回退为 NONE
        }
        long duration = obj.has("durationMillis") && obj.get("durationMillis").isJsonPrimitive()
                ? obj.get("durationMillis").getAsLong() : 0L;
        boolean hasResp = obj.has("hasResponse") && obj.get("hasResponse").isJsonPrimitive()
                && obj.get("hasResponse").getAsBoolean();
        boolean reqTrunc = obj.has("requestTruncated") && obj.get("requestTruncated").isJsonPrimitive()
                && obj.get("requestTruncated").getAsBoolean();
        boolean respTrunc = obj.has("responseTruncated") && obj.get("responseTruncated").isJsonPrimitive()
                && obj.get("responseTruncated").getAsBoolean();
        Path reqFile = obj.has("requestFile") && obj.get("requestFile").isJsonPrimitive()
                ? java.nio.file.Paths.get(obj.get("requestFile").getAsString()) : null;
        Path respFile = obj.has("responseFile") && obj.get("responseFile").isJsonPrimitive()
                ? java.nio.file.Paths.get(obj.get("responseFile").getAsString()) : null;
        String reqHash = obj.has("requestHash") && obj.get("requestHash").isJsonPrimitive()
                ? obj.get("requestHash").getAsString() : null;
        String respHash = obj.has("responseHash") && obj.get("responseHash").isJsonPrimitive()
                ? obj.get("responseHash").getAsString() : null;
        // requestFingerprint：老 index.json 没有该字段时为 null（启动预热会跳过，不影响加载）。
        String reqFp = obj.has("requestFingerprint") && obj.get("requestFingerprint").isJsonPrimitive()
                ? obj.get("requestFingerprint").getAsString() : null;
        int findingCount = obj.has("findingCount") && obj.get("findingCount").isJsonPrimitive()
                ? obj.get("findingCount").getAsInt() : 0;
        Path auditTrailFile = obj.has("auditTrailFile") && obj.get("auditTrailFile").isJsonPrimitive()
                ? java.nio.file.Paths.get(obj.get("auditTrailFile").getAsString()) : null;
        return new AnalysisHistoryEntry(id, ts, trigger, method, url, statusCode,
                summary, error, risk, duration, hasResp, null, null,
                reqTrunc, respTrunc, reqFile, respFile, reqHash, respHash, reqFp, findingCount,
                auditTrailFile);
    }

    private static String readString(JsonObject obj, String key) {
        if (!obj.has(key) || !obj.get(key).isJsonPrimitive()) {
            return "";
        }
        try {
            return obj.get(key).getAsString();
        } catch (RuntimeException ignored) {
            return "";
        }
    }
}
