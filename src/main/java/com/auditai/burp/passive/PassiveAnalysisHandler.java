package com.auditai.burp.passive;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

import java.io.Serial;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * 被动分析 Proxy 回调：实现 Montoya 的 {@link ProxyRequestHandler} + {@link ProxyResponseHandler}，
 * 把"开启开关后才放行"的过滤 + "请求+响应配对" + "指纹去重" + "独立线程池" 全部串起来。
 *
 * <p><b>流程（v2）：</b></p>
 * <ol>
 *   <li>请求到达（Proxy 回调线程）：只做两件廉价的事——跳过静态资源后缀、把"raw 字节 + 元数据"
 *       暂存到 {@code pending}（按 messageId）。<b>不做</b> URL 正则匹配、不做 SHA-256：
 *       这些移到响应到达后的工作线程，避免 Proxy 回调线程被大报文哈希卡住，也避免
 *       正则灾难性回溯卡住 Burp 代理转发；</li>
 *   <li>响应到达（Proxy 回调线程）：从 {@code pending} 取到配对请求，复制响应字节后
 *       提交到 {@link PassiveAnalysisExecutor}；pending 找不到配对时直接放行；</li>
 *   <li>工作线程（{@link PassiveAnalysisExecutor}）：先过 {@link UrlRegexFilter}，
 *       再算指纹（{@link RequestFingerprint#compute}，body-only + 大小上限），
 *       {@link FingerprintDedup#markIfNew} 决定是否首次见到——首次才真正调用
 *       {@link PassiveAnalyzer#analyzeAsync} 做 AI 分析；重复/不匹配直接跳过。</li>
 * </ol>
 *
 * <p><b>关键设计选择</b>（每条都对应一类已知阻塞 / 资源浪费风险）：</p>
 * <ul>
 *   <li>指纹哈希在工作线程执行——大上传时不会卡住 Proxy 回调线程；</li>
 *   <li>指纹只哈希请求体（不含动态 header）——Cookie / CSRF 等高频变化不会破坏去重；</li>
 *   <li>去重标记推迟到"响应已到达、即将分析"的工作线程——响应永不回调的请求不会永久
 *       占用 dedup，重试同一请求仍会被正常分析；</li>
 *   <li>URL 正则匹配在工作线程执行，并做输入截断——灾难性回溯正则不会阻塞 Burp Proxy；</li>
 *   <li>开关关闭的瞬间清空 pending 快照——避免残留字节与无意义配对。</li>
 * </ul>
 *
 * <p><b>关键不变量：</b></p>
 * <ul>
 *   <li>开关关闭时（{@link #isActive()} == false）所有回调直接放行，零开销；</li>
 *   <li>pending map 用 LRU 容量 {@value #DEFAULT_PENDING_CAPACITY}——响应永不回调的请求
 *       会被自然淘汰，避免内存泄漏；</li>
 *   <li>dedup LRU 与 pending LRU 是两个独立结构：dedup 防"重复分析"，pending 防"未配对请求泄漏"。</li>
 * </ul>
 */
public final class PassiveAnalysisHandler implements ProxyRequestHandler, ProxyResponseHandler {

    /**
     * pending map 容量上限：超过后按访问顺序淘汰最久未见的 messageId。
     *
     * <p>正常情况下 pending 里的条目只在请求到响应之间短暂存在（毫秒级），2000 足够；
     * 响应永不回调（连接中断 / Burp 异常）的请求最终会被 LRU 淘汰，内存可控。</p>
     */
    static final int DEFAULT_PENDING_CAPACITY = 2_000;

    /**
     * 单次分析允许的请求 + 响应总字节数上限。超过时跳过分析（写一条日志）。
     * 避免超大报文（数百 MB 上传/下载）把被动线程池与 AI 请求体撑爆。
     */
    static final int MAX_ANALYSIS_BYTES = 10 * 1024 * 1024;

    /** 当前开关 + URL 过滤：UI 改完点"保存被动分析"会调 {@link #updateConfig(boolean, String)}。 */
    private volatile boolean active;
    private volatile UrlRegexFilter urlFilter;

    /** 最近一次推送的 URL 正则（用于 updateConfig 变化检测，避免每次按键都打日志）。 */
    private String lastUrlRegex = "";

    private final MontoyaApi api;
    private final FingerprintDedup dedup;
    private final PassiveAnalysisExecutor executor;
    private final PassiveAnalyzer analyzer;

    /**
     * messageId → 等待响应的请求快照。
     * 使用 {@code Collections.synchronizedMap + LinkedHashMap(capacity, 0.75f, true)}
     * 跟 dedup 同款实现：线程安全 + LRU 自动淘汰。
     */
    private final Map<Integer, PendingEntry> pending;

    /**
     * 错误日志回调：注册/卸载阶段异常时使用；转发给 Montoya 的 logToError。
     */
    private final Consumer<String> errorLogger;

    /**
     * @param api      Montoya API 门面。
     * @param dedup    指纹去重（线程安全，可单例复用）。
     * @param executor 独立线程池。
     * @param analyzer 真正的分析编排器（调 TrafficAnalyzer + 写 FindingStore）。
     * @param errorLogger 错误日志回调；可为 null（null 时降级到 stderr）。
     */
    public PassiveAnalysisHandler(MontoyaApi api, FingerprintDedup dedup,
                                  PassiveAnalysisExecutor executor, PassiveAnalyzer analyzer,
                                  Consumer<String> errorLogger) {
        this.api = api;
        this.dedup = dedup;
        this.executor = executor;
        this.analyzer = analyzer;
        this.errorLogger = errorLogger == null ? msg -> { } : errorLogger;
        this.active = false;
        this.urlFilter = new UrlRegexFilter("", null);
        this.pending = Collections.synchronizedMap(new LinkedHashMap<Integer, PendingEntry>(
                DEFAULT_PENDING_CAPACITY, 0.75f, true) {
            @Serial
            private static final long serialVersionUID = 1L;

            @Override
            protected boolean removeEldestEntry(Map.Entry<Integer, PendingEntry> eldest) {
                return size() > DEFAULT_PENDING_CAPACITY;
            }
        });
    }

    /**
     * 动态更新开关 + URL 过滤：UI 改完"保存被动分析"后调用，<b>不重建 Handler 也不重新注册 Proxy 回调</b>，
     * 避免关闭→开启瞬间丢失正在分析中的请求。
     *
     * <p>值没有变化时不重复打日志（DocumentListener 防抖之外的最后一道防线）；
     * 开关从开→关时清空 pending 快照（不再有分析发生，立即释放在途字节）。</p>
     *
     * @param enabled  是否启用被动分析。
     * @param urlRegex URL 过滤正则（空串/null → 匹配全部）。
     */
    public void updateConfig(boolean enabled, String urlRegex) {
        String normalized = urlRegex == null ? "" : urlRegex;
        boolean stateChanged = enabled != this.active;
        boolean regexChanged = !normalized.equals(this.lastUrlRegex);
        if (stateChanged && !enabled) {
            // 关闭瞬间清掉在途快照：响应到达时不再配对，避免残留字节和无意义分析。
            pending.clear();
        }
        this.active = enabled;
        this.urlFilter = new UrlRegexFilter(normalized, this::logError);
        this.lastUrlRegex = normalized;
        if (stateChanged || regexChanged) {
            logInfo("被动分析配置更新：enabled=" + enabled + "，regex=" + normalized);
        }
    }

    /** 当前是否启用。 */
    public boolean isActive() {
        return active;
    }

    // ========== ProxyRequestHandler ==========

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest request) {
        try {
            if (!active) {
                return ProxyRequestReceivedAction.continueWith(request);
            }
            // 静态资源不参与被动分析（省钱 + 避免大文件哈希）：与历史 ProxyTrafficCollector
            // 行为一致；判断逻辑搬到了本类内（ProxyTrafficCollector 已下线）。
            if (isStaticResource(request.url())) {
                return ProxyRequestReceivedAction.continueWith(request);
            }
            // 只做快照拷贝，不在这里算指纹/匹配正则（避免 Proxy 回调线程被大报文哈希或
            // 灾难性回溯正则卡住）；两者都推迟到响应到达后的工作线程（见 handleResponseReceived）。
            byte[] requestBytes = request.toByteArray().getBytes();
            pending.put(request.messageId(), new PendingEntry(
                    request.httpService(),
                    request.method(),
                    request.url(),
                    requestBytes));
        } catch (RuntimeException ex) {
            // 任何意外都不能影响 Proxy 流量转发
            logError("handleRequestReceived 失败：" + ex.getMessage());
        }
        return ProxyRequestReceivedAction.continueWith(request);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest request) {
        return ProxyRequestToBeSentAction.continueWith(request);
    }

    // ========== ProxyResponseHandler ==========

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
        try {
            int messageId = response.messageId();
            if (!active) {
                // 关闭后到达的响应：把残留的快照也清掉（防止 disable 之后 pending 里堆积）。
                pending.remove(messageId);
                return ProxyResponseReceivedAction.continueWith(response);
            }
            PendingEntry entry = pending.remove(messageId);
            if (entry == null) {
                // 没找到配对请求：可能请求在开关关闭期间到达、或已被 LRU 淘汰。
                // 直接放行，绝不能因为被动分析而阻塞响应。
                return ProxyResponseReceivedAction.continueWith(response);
            }
            // 复制响应字节后提交到线程池（响应对象不能跨线程持有）
            byte[] responseBytes = response.toByteArray().getBytes();
            executor.submit(() -> analyzeInWorker(entry, responseBytes));
        } catch (RuntimeException ex) {
            logError("handleResponseReceived 失败：" + ex.getMessage());
        }
        return ProxyResponseReceivedAction.continueWith(response);
    }

    /**
     * 工作线程内的完整决策：URL 正则过滤 → 大小上限 → 指纹去重 → 分析。
     * 所有"可能慢/可能失败"的步骤都在这条线程上执行，绝不阻塞 Proxy 回调。
     */
    private void analyzeInWorker(PendingEntry entry, byte[] responseBytes) {
        try {
            // 1. URL 正则过滤（工作线程内执行：灾难性回溯正则只占用本线程，不阻塞 Proxy）
            UrlRegexFilter filter = urlFilter;
            if (filter == null || !filter.matches(entry.url)) {
                return;
            }
            // 2. 大小上限：超大报文跳过（请求+响应总字节）
            if (entry.requestBytes.length + responseBytes.length > MAX_ANALYSIS_BYTES) {
                logError("跳过超大报文分析（请求+响应 > " + (MAX_ANALYSIS_BYTES / 1024 / 1024)
                        + " MB）：" + entry.method + " " + entry.url);
                return;
            }
            // 3. 指纹去重：只有响应已到达、即将真正分析时才标记——
            //    响应永不回调的请求不会占用 dedup，重试同一请求仍会被分析。
            String fingerprint = RequestFingerprint.compute(entry.method, entry.url, entry.requestBytes);
            if (!dedup.markIfNew(fingerprint)) {
                return; // 已分析过
            }
            // 4. 真正分析：失败时把指纹从 dedup 移除（用户在 UI 改正配置后能重新触发分析）
            analyzer.analyzeAsync(entry.httpService, entry.method, entry.url,
                    entry.requestBytes, responseBytes,
                    result -> {
                        if (result != null && result.getError() != null) {
                            dedup.remove(fingerprint);
                        }
                    });
        } catch (RuntimeException ex) {
            // 线程池里的 runnable 不能抛出未捕获异常（会触发 UncaughtExceptionHandler 但仍要兜底）
            logError("被动分析任务执行失败：" + ex.getMessage());
        }
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse response) {
        return ProxyResponseToBeSentAction.continueWith(response);
    }

    /**
     * 释放资源：插件卸载时调用。清空 pending（不再有响应到达，但避免持有响应字节）。
     * 线程池 shutdown 由 {@code PassiveAnalysisExecutor} 持有方负责。
     */
    public void shutdown() {
        pending.clear();
    }

    /**
     * DEBUG 级别日志：受 {@code -Dauditai.debug.prompt} 控制，默认不输出——避免
     * 被动流量分析时刷屏。仅在开发期需要核对"被动分析器到底跑没跑"时打开。
     */
    private void logInfo(String message) {
        if (api != null && Boolean.getBoolean("auditai.debug.prompt")) {
            api.logging().logToOutput("AuditAI [DEBUG] " + message);
        }
    }

    private void logError(String message) {
        errorLogger.accept(message);
    }

    /**
     * 等待响应的请求快照：所有字段在 Proxy 请求回调线程里赋值，
     * 之后只能被响应回调或 LRU 淘汰访问，跨线程使用时由 PassiveAnalyzer 再次重建 HttpRequest。
     */
    private static final class PendingEntry {
        final HttpService httpService;
        final String method;
        final String url;
        final byte[] requestBytes;

        PendingEntry(HttpService httpService, String method, String url, byte[] requestBytes) {
            this.httpService = httpService;
            this.method = method;
            this.url = url;
            this.requestBytes = requestBytes;
        }
    }

    /**
     * 静态资源判定：取 URL 路径最后一段的扩展名，命中白名单（图片 / 字体 / 音视频 /
     * 前端脚本样式 / sourcemap）即视为静态资源。
     *
     * <p>原 {@code ProxyTrafficCollector.isStaticResource} 已下线；本方法是它的内联版本，
     * 行为完全一致，供被动分析在请求回调时跳过这些资源。</p>
     */
    private static boolean isStaticResource(String url) {
        if (url == null) {
            return false;
        }
        // 1. 去掉查询串与片段
        int queryIdx = url.indexOf('?');
        String pathPart = queryIdx >= 0 ? url.substring(0, queryIdx) : url;
        int fragIdx = pathPart.indexOf('#');
        if (fragIdx >= 0) {
            pathPart = pathPart.substring(0, fragIdx);
        }
        // 2. 取路径部分（去掉协议与 host）
        int protoIdx = pathPart.indexOf("://");
        if (protoIdx >= 0) {
            pathPart = pathPart.substring(protoIdx + 3);
        }
        int slashIdx = pathPart.indexOf('/');
        String path = slashIdx >= 0 ? pathPart.substring(slashIdx) : "";
        if (path.isEmpty()) {
            return false;
        }
        // 3. 取最后一段的文件名（去掉目录前缀）
        int lastSlash = path.lastIndexOf('/');
        String fileName = lastSlash >= 0 ? path.substring(lastSlash + 1) : path;
        if (fileName.isEmpty()) {
            return false;
        }
        // 4. 取最后一个 "." 之后的内容作为扩展名
        int dotIdx = fileName.lastIndexOf('.');
        if (dotIdx < 0 || dotIdx == fileName.length() - 1) {
            return false;
        }
        String ext = fileName.substring(dotIdx + 1).toLowerCase(java.util.Locale.ROOT);
        return STATIC_EXTENSIONS.contains(ext);
    }

    /** 视为"静态资源"的 URL 后缀集合（与原 ProxyTrafficCollector.STATIC_EXTENSIONS 内容一致）。 */
    private static final java.util.Set<String> STATIC_EXTENSIONS = java.util.Set.of(
            // 图片
            "png", "jpg", "jpeg", "gif", "svg", "webp", "bmp", "ico", "avif",
            // 字体
            "woff", "woff2", "ttf", "otf", "eot",
            // 音视频
            "mp3", "mp4", "webm", "ogg", "wav", "flac", "aac",
            "mov", "avi", "mkv", "m3u8", "ts", "m4s",
            // 前端脚本与样式
            "js", "mjs", "css",
            // sourcemap
            "map"
    );
}
