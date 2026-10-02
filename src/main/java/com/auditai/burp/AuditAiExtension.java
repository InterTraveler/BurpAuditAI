package com.auditai.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.auditai.burp.ai.AiClient;
import com.auditai.burp.ai.OpenAiCompatibleClient;
import com.auditai.burp.ai.PromptBuilder;
import com.auditai.burp.config.Settings;
import com.auditai.burp.config.SettingsStore;
import com.auditai.burp.history.AnalysisHistoryEntry;
import com.auditai.burp.history.AnalysisHistoryStore;
import com.auditai.burp.history.AnalysisTrigger;
import com.auditai.burp.http.FindingStore;
import com.auditai.burp.http.TrafficAnalyzer;
import com.auditai.burp.passive.*;
import com.auditai.burp.skills.CustomSkillStore;
import com.auditai.burp.skills.SkillLoader;
import com.auditai.burp.skills.SkillStateStore;
import com.auditai.burp.ui.I18n;
import com.auditai.burp.ui.MainTab;
import com.auditai.burp.ui.SendToAuditAiMenuProvider;
import com.auditai.burp.util.SessionPaths;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * AuditAI 扩展的唯一入口类。
 *
 * <p>Burp 加载插件 JAR 后，会实例化用户在 Extender 页面中指定的类（即本类），
 * 然后调用 {@link #initialize(MontoyaApi)}。因此本方法承担的是"装配"职责：
 * 创建各个组件并把它们按依赖方向连起来，而不是把业务逻辑写在入口里。</p>
 *
 * <p>组件装配关系（依赖自顶向下）：</p>
 * <pre>
 * AuditAiExtension（入口，装配）
 *   ├── SettingsStore / AiConfig       —— 配置读取与持久化
 *   ├── AiClient                       —— AI 通信抽象（统一 OpenAI 兼容协议）
 *   ├── TrafficAnalyzer                —— 编排：报文 → 提示词 → AI → 分析结果
 *   ├── AnalysisHistoryStore           —— "历史"页签背后的已分析历史库
 *   ├── MainTab（多页签）              —— "分析"页（请求/响应编辑 + 手动分析）
 *   │                                   ＋"设置"页（AI 服务 / 提示词）
 *   │                                   ＋"历史"页（经 AI 分析的报文）
 *   │                                   ＋"问题"页（Finding 列表 + 详情）
 *   │                                   ＋"技能"页（SKILL.md 文件网格）
 *   └── SendToAuditAiMenuProvider      —— 上下文菜单：从其他模块发送报文到分析页
 * </pre>
 *
 * <p>交互模型：分析由<b>用户主动触发</b>（手动）或<b>被动规则触发</b>（被动流量分析），
 * 两路回调统一落到 {@link FindingStore}（"问题"页签）和 {@link AnalysisHistoryStore}
 * （"历史"页签）。</p>
 *
 * <p>约定：本类只做依赖装配，不写具体业务；后续新增功能应各自独立成包，在这里统一接线。</p>
 */
public final class AuditAiExtension implements BurpExtension {

    /**
     * Burp 回调的扩展初始化入口。
     *
     * @param api Burp 注入的 Montoya API 门面；它统一提供日志、HTTP、UI、持久化等官方能力，
     *            所有扩展功能都应经由该门面获取，避免直接依赖 Burp 内部实现类。
     */
    @Override
    @SuppressWarnings("try")
    // @SuppressWarnings("try")：historyStore / findingStore 是"整个会话期"的资源，
    // 生命周期与 Burp 扩展一致，必须在插件卸载时（registerUnloadingHandler）才关闭；
    // 不能用 try-with-resources（try 块结束就关，扩展就没法用了）。IDE 的
    // "resource should be managed by try-with-resources" 在这里是误报。
    public void initialize(MontoyaApi api) {
        // 0. 统一错误日志回调：所有失败路径都走这里，避免各处重复 lambda。
        final java.util.function.Consumer<String> errorLog =
                message -> api.logging().logToError("AuditAI " + message);
        final java.util.function.BiConsumer<String, Throwable> errorLogWithCause =
                (message, cause) -> api.logging().logToError("AuditAI " + message, cause);

        // 1. 设置扩展名：会显示在 Burp 的 Extender 列表中，便于确认加载的是正确的 JAR。
        api.extension().setName("AuditAI");

        // 2. 加载配置：从 Burp 的持久化存储读取；首次使用则取默认值（见 Settings.createDefault）。
        //    Settings 持有"多份 AI 服务配置 + 当前激活项 + 全局提示词 + 被动分析配置 + 历史容量配置"。
        SettingsStore settingsStore = new SettingsStore(api.persistence().preferences());
        Settings settings = settingsStore.load();

        // 3. 创建 AI 客户端：统一使用 OpenAI Chat Completions 兼容协议。
        //    远程服务填写 API Key；本地 Ollama / LM Studio 等可把 Key 留空。
        //    注入 owned executor：JDK HttpClient 内部默认 cached executor 不可关闭，
        //    插件重载后会有残留线程（thread name 默认带并发编号，泄漏迹象隐蔽）。
        //    用守护线程工厂让 JVM 退出时不会因为 AI 线程卡死导致 Burp 关不掉。
        ExecutorService aiHttpExecutor = Executors.newCachedThreadPool(new ThreadFactory() {
            private final AtomicInteger n = new AtomicInteger();
            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r, "AuditAI-AiHttp-" + n.incrementAndGet());
                t.setDaemon(true);
                return t;
            }
        });
        AiClient aiClient = new OpenAiCompatibleClient(settings, aiHttpExecutor);

        // 4. 计算当前项目的会话根目录（专业版 / 社区版分流由 SessionPaths 处理）。
        AnalysisHistoryStore historyStore = null;
        FindingStore findingStore = null;
        // 用户技能目录挂在 sessionRoot 下：与历史库 / 问题库同级，独立子目录。
        Path sessionRoot = null;
        String projectId = SessionPaths.isDiskProject(api) ? api.project().id() : SessionPaths.TEMPORARY_PROJECT_ID;
        try {
            sessionRoot = SessionPaths.createProjectDirectory(api.extension().filename(), projectId);
            final AnalysisHistoryStore createdHistoryStore = new AnalysisHistoryStore(sessionRoot,
                    AnalysisHistoryStore.DEFAULT_MAX_ENTRIES,
                    AnalysisHistoryStore.DEFAULT_MAX_ENTRY_BYTES,
                    errorLog);
            historyStore = createdHistoryStore;
            api.extension().registerUnloadingHandler(() -> closeHistoryStore(createdHistoryStore));
            api.logging().logToOutput("AuditAI Project：" + api.project().name()
                    + "，存储模式：" + (SessionPaths.TEMPORARY_PROJECT_ID.equals(projectId) ? "Temporary" : "Disk")
                    + "，已分析历史目录：" + historyStore.sessionDirectory());
        } catch (IOException e) {
            api.logging().logToError("AuditAI 无法创建已分析历史存储，'历史'页签将显示空态。", e);
        }
        // 问题库独立建一次：失败时问题页签会显示空态，不影响其它功能。
        try {
            final FindingStore createdFindingStore = new FindingStore(api.extension().filename(), projectId);
            findingStore = createdFindingStore;
            api.extension().registerUnloadingHandler(() -> closeFindingStore(createdFindingStore));
            api.logging().logToOutput("AuditAI 问题库目录：" + findingStore.sessionDirectory());
        } catch (IOException e) {
            api.logging().logToError("AuditAI 无法创建问题存储，问题页签将显示空态。", e);
        }

        // 5. 创建分析编排器（内部含异步执行器，AI 调用不阻塞 UI 线程）。
        //    单轮 + 技能驱动：
        //      - SkillStateStore 告诉分析器"哪些技能被启用"
        //      - SkillLoader 提供 classpath:/skills/ + <sessionRoot>/custom-skills/ 两类来源
        //        （用户技能目录不存在时降级为只扫 classpath）
        //      - historyStore 为 null（如历史存储初始化失败）时，技能 userContext 里的
        //        {related} 占位符自动回退为"历史库不可用"占位文本，不影响单轮主流程。
        SkillStateStore skillStateStore = new SkillStateStore(api.persistence().preferences());
        // 用户技能目录：与 historyStore 共用同一 sessionRoot；建失败时降级为 null（添加技能按钮隐藏）。
        CustomSkillStore customSkillStore = sessionRoot == null
                ? null
                : new CustomSkillStore(sessionRoot, msg -> api.logging().logToError("AuditAI " + msg));
        SkillLoader skillLoader = SkillLoader.fromClasspathAndUserDirectory("skills",
                AuditAiExtension.class.getClassLoader(),
                customSkillStore == null ? null : customSkillStore.rootDirectory(),
                msg -> api.logging().logToError("AuditAI " + msg));
        // 工具工厂：每次分析时按当前请求创建一组 Tool。PromptBuilder 无状态可重建，
        // 与 TrafficAnalyzer 内部的 PromptBuilder 保持同 supplier 即可。
        // 目前只注册"重放"工具——将来加爆破/解码器只需在这里追加 List<Tool>。
        java.util.function.BiFunction<burp.api.montoya.http.message.requests.HttpRequest,
                burp.api.montoya.http.message.responses.HttpResponse,
                List<com.auditai.burp.tools.Tool>> toolFactory = (req, resp) -> {
            if (req == null) {
                return List.of();
            }
            com.auditai.burp.ai.PromptBuilder pb = new com.auditai.burp.ai.PromptBuilder(
                    settings::customPrompt, I18n.get()::current);
            return List.of(new com.auditai.burp.tools.replay.ReplayTool(api, pb, req));
        };
        TrafficAnalyzer analyzer = new TrafficAnalyzer(api, aiClient, settings, historyStore,
                skillStateStore, skillLoader, toolFactory, I18n.get()::current);

        // 5.5 被动流量分析模块：独立线程池 + 独立 AI 执行器 + 指纹去重 + ProxyRequest/Response 回调。
        //     注册到 Proxy：仅监听"Burp 代理转发到本进程"的请求/响应，
        //     Repeater / Intruder / Scanner 等主动工具流量走不同 API，不进入本回调。
        //     用 finalHistoryStore / finalFindingStore 提取出 effectively-final 引用，
        //     否则它们在 try 块里被赋值后 lambda 捕获会报"非 final 变量"。
        final AnalysisHistoryStore finalHistoryStore = historyStore;
        final FindingStore finalFindingStore = findingStore;
        PassiveAnalysisExecutor passiveExecutor = new PassiveAnalysisExecutor(
                errorLog);
        FingerprintDedup passiveDedup = new FingerprintDedup();
        // 用已落盘的"分析历史"做去重预热：history 里有 fingerprint 的请求，
        // 重启后再次出现时直接跳过 AI——避免重启 → 重放历史流量 → 重复消耗 token。
        // historyStore 可能为 null（创建失败）或 entry 是老数据（fingerprint 字段为 null），
        // primeAll 内部都会跳过，行为安全。
        if (historyStore != null) {
            List<String> existingFingerprints = new ArrayList<>();
            for (AnalysisHistoryEntry entry : historyStore.list()) {
                String fp = entry.getRequestFingerprint();
                if (fp != null && !fp.isEmpty()) {
                    existingFingerprints.add(fp);
                }
            }
            if (!existingFingerprints.isEmpty()) {
                passiveDedup.primeAll(existingFingerprints);
                api.logging().logToOutput("AuditAI 被动分析去重预热：" + existingFingerprints.size()
                        + " 条历史指纹已加载");
            }
        }
        // 被动分析使用独立的 TrafficAnalyzer 实例：与手动分析各自独占一个
        // 单线程执行器，被动流量洪峰不会把分析页的手动分析饿死在队尾。
        TrafficAnalyzer passiveTrafficAnalyzer = new TrafficAnalyzer(
                api, aiClient, settings, historyStore, skillStateStore, skillLoader,
                toolFactory, true, I18n.get()::current);
        // 被动分析结果回调：成功 / 失败统一走这里——
        //   1. 写问题库（findingStore 非 null 时；null 时降级丢弃结果）
        //   2. 写历史库（historyStore 非 null 时；null 时降级丢弃，request/response 字节用于下方编辑器）
        //   3. 失败时把"AI 拒服务"原因打到 Burp 的 Output 日志（节流：每 30s 最多一条
        //      完整日志，其余合并计数），方便用户在不切到分析页时也能及时发现问题，
        //      又不会在扫描器场景刷出几千条。
        FailureLogThrottle failureLogThrottle = new FailureLogThrottle();
        // 被动 / 手动两路分析结果共享一个 sink：写问题库 + 写历史库 + IO 失败日志
        // 全部集中到 AnalysisResultSink，避免两处 lambda 复制粘贴。
        AnalysisResultSink passiveSink = new AnalysisResultSink(
                api, finalFindingStore, finalHistoryStore, AnalysisTrigger.PASSIVE);
        PassiveAnalyzer passiveAnalyzer = new PassiveAnalyzer(api, passiveTrafficAnalyzer, (result, req, resp) -> {
            // 落库（findings + history）：被动分析始终没有 request/response 原文直达，
            // 传 null 让 findingStore 走 AnalysisHistoryStore 反查路径。
            passiveSink.accept(result, req, resp);
            if (result.getError() != null) {
                failureLogThrottle.log(api, result.getMethod() + " " + result.getUrl()
                        + "（" + result.getError() + "，耗时 " + result.getDurationMillis() + " ms）");
                // 同步到 UI 错误总线：让设置页签红字提示 + 标题感叹号。
                // 只把真正的错误描述（result.getError()）放进 UI 红字——
                // 完整 method/url 已写进 Burp Output 日志（上一行），便于事后排查。
                PassiveAnalysisErrorBus.INSTANCE.setError(
                        result.getError(),
                        classifyPassiveFailure(result.getError()));
            } else if (settings.isPassiveAnalysisEnabled()) {
                // 成功且开关仍开：清除错误总线上"残留的失败提示"——
                // 开关关闭后不会产生新的成功/失败回调，错误状态可保留作"上次失败原因"供用户参考。
                PassiveAnalysisErrorBus.INSTANCE.clearError();
            }
        });
        PassiveAnalysisHandler passiveHandler = new PassiveAnalysisHandler(
                api, passiveDedup, passiveExecutor, passiveAnalyzer,
                errorLog);
        // 启动时把当前持久化的配置推给 handler（避免每次 UI 改完还要重启插件才生效）。
        passiveHandler.updateConfig(settings.isPassiveAnalysisEnabled(),
                settings.getPassiveAnalysisUrlRegex());
        api.proxy().registerRequestHandler(passiveHandler);
        api.proxy().registerResponseHandler(passiveHandler);

        // 6. 创建多页签主界面（分析页为"多报文页签"，每次发送自动新建编号页签），
        //    页签标题与插件名保持一致：AuditAI。
        //    技能启用态走 SkillStateStore：首次安装返回 DefaultEnabledSkill 默认集，
        //    之后走用户持久化的选择。
        //    "历史"页签消费 historyStore；analysis 内部走单条 lambda 把结果同时写到 findingStore + historyStore。

        // 语言回放:从 Montoya Preferences 读取上次保存的语言,先于 MainTab 构造设置,
        // 让 MainTab 创建时已是目标语言,首次 refreshI18n 直接显示正确文案。
        restoreLanguage(api);
        // 持久化:用户切换语言时立刻写回 Preferences。
        I18n.get().onChange(lang -> persistLanguage(api, lang));

        MainTab mainTab = new MainTab(api, settings, settingsStore, analyzer, historyStore,
                findingStore, skillStateStore, customSkillStore,
                passiveDedup);
        // 手动分析也复用同一个 sink：trigger=MANUAL；request/response 来自编辑器。
        AnalysisResultSink manualSink = new AnalysisResultSink(
                api, finalFindingStore, finalHistoryStore, AnalysisTrigger.MANUAL);
        mainTab.setOnAnalysisCompleted(manualSink::accept);
        // 6.1 让设置面板的"保存被动分析"按钮实时通知 passiveHandler 热更新：
        //     避免"保存了但 Burp 还在用旧值"的撕裂感；hook 里读 settings 当前值即可。
        mainTab.setOnPassiveAnalysisSaved(() -> passiveHandler.updateConfig(
                settings.isPassiveAnalysisEnabled(), settings.getPassiveAnalysisUrlRegex()));
        api.userInterface().registerSuiteTab("AuditAI", mainTab);

        // 6.5 注册卸载清理：中断分析线程（手动 + 被动两个执行器）、停止 Toast 调度线程等，
        //     避免 Burp 重载插件后残留旧线程与对象图。MainTab.close() 内部会逐层透传
        //     到 AnalysisPanel / AnalysisHistoryPanel / FindingsPanel / SkillsPanel，
        //     每个子页签各自释放 Timer、cancel SwingWorker、注销 I18n 监听器。
        //     最后再补一刀清掉全局单例的监听器（PassiveAnalysisErrorBus）+ I18n 订阅表
        //     —— SettingsPanel.close() 已逐个 removeListener，但任何忘走的子页签仍
        //     会留强引用，这一步是最后防线。
        //
        //     每一步单独 try-catch：任一关闭路径抛异常都不能中断后续清理——
        //     比如线程池关闭成功但 mainTab.close() 抛错时，仍要把 ErrorBus / I18n
        //     单例清干净，否则下一次重载会出现 NPE / 内存泄漏。
        api.extension().registerUnloadingHandler(() -> {
            safeClose(errorLogWithCause, "analyzer.shutdown", analyzer::shutdown);
            safeClose(errorLogWithCause, "passiveTrafficAnalyzer.shutdown", passiveTrafficAnalyzer::shutdown);
            // 先取消在飞的被动分析（中断底层 HTTP），再关线程池：
            // 线程池的 shutdownNow 只能中断线程，而 AI 等待用的 CompletableFuture.join()
            // 不响应中断，必须靠 AnalysisTask.cancel() 才能立即释放连接。
            safeClose(errorLogWithCause, "passiveAnalyzer.cancelInFlight", passiveAnalyzer::cancelInFlight);
            safeClose(errorLogWithCause, "passiveExecutor.shutdown", passiveExecutor::shutdown);
            safeClose(errorLogWithCause, "passiveHandler.shutdown", passiveHandler::shutdown);
            // AI 客户端 close：关闭注入的 executor，避免 HttpClient 内部线程池在
            // 插件重载后成为残留线程；幂等，多次注册安全（Burp 的 unload handler
            // 每次都触发本 lambda）。
            safeClose(errorLogWithCause, "aiClient.close", aiClient::close);
            safeClose(errorLogWithCause, "mainTab.close", mainTab::close);
            safeClose(errorLogWithCause, "ErrorBus.clearListeners",
                    PassiveAnalysisErrorBus.INSTANCE::clearListeners);
            // BodyStorage 的 SHA-256 ThreadLocal 也要清：长生命周期线程（Burp 线程池）
            // 会持有 MessageDigest，重载插件后这些线程复用了就拿陈旧实例。
            safeClose(errorLogWithCause, "BodyStorage.releaseForCurrentThread",
                    com.auditai.burp.http.BodyStorage::releaseForCurrentThread);
        });

        // 7. 注册上下文菜单：在 Proxy 历史 / Repeater 等模块右键选中报文，
        //    可一键发送到分析页（见 SendToAuditAiMenuProvider）。
        //    注入 MontoyaApi：Repeater 等场景下 selectedRequestResponses() 只含请求不含响应，
        //    需要从 api.proxy().history() 反查补全。
        api.userInterface().registerContextMenuItemsProvider(
                new SendToAuditAiMenuProvider(api, mainTab));
    }

    /** 关闭已分析历史库（内存索引释放；磁盘数据保留）。 */
    private static void closeHistoryStore(AnalysisHistoryStore store) {
        if (store != null) {
            store.close();
        }
    }

    /** 关闭问题库（内存索引释放；磁盘数据保留）。 */
    private static void closeFindingStore(FindingStore store) {
        if (store != null) {
            store.close();
        }
    }

    /** Montoya Preferences key:语言选择。 */
    private static final String LANG_PREF_KEY = "com.auditai.i18n.lang";

    /**
     * 从 Montoya Preferences 恢复语言选择。key 缺失/非法时保持默认(ZH)。
     */
    private static void restoreLanguage(MontoyaApi api) {
        try {
            String saved = api.persistence().preferences().getString(LANG_PREF_KEY);
            if (saved == null || saved.isBlank()) {
                return;
            }
            PromptBuilder.Lang lang;
            try {
                lang = PromptBuilder.Lang.valueOf(saved.trim());
            } catch (IllegalArgumentException ex) {
                return;
            }
            I18n.get().set(lang);
        } catch (RuntimeException ignored) {
            // 读不到/写不进时保持默认,不影响插件启动
        }
    }

    /**
     * 用户切语言时落盘。失败仅记录到 Burp Output,不影响 UI 状态。
     */
    private static void persistLanguage(MontoyaApi api, PromptBuilder.Lang lang) {
        try {
            api.persistence().preferences().setString(LANG_PREF_KEY, lang.name());
        } catch (RuntimeException ex) {
            api.logging().logToError("AuditAI 保存语言选择失败: " + ex.getMessage());
        }
    }

    /**
     * 把 AnalysisResult.getError() 文本（已包含原始异常 message）按用户可读的
     * "下一步该检查什么"分类。
     *
     * <p>AnalysisResult 的 error 字段是字符串而非 Throwable 链，因此走按消息文本
     * 分类的路径（{@link PassiveAnalysisErrorClassifier#classifyByMessage}）。
     * 之前若在 SettingsPanel 测过连接并被分类，会优先用同款规则归类，
     * 保证"测试连接"和"被动分析"看到的分类一致。</p>
     */
    private static PassiveAnalysisErrorBus.ErrorKind classifyPassiveFailure(String errorMessage) {
        return PassiveAnalysisErrorClassifier.classifyByMessage(errorMessage);
    }

    /**
     * 被动分析失败日志的节流器：AI 服务不可用时每个去重通过的请求都会失败一次，
     * 逐条打 Output 会在扫描器场景刷出几千条日志。策略：每 {@link #WINDOW_MS} 窗口
     * 只输出一条完整日志，窗口内的其余失败合并为计数追加到下一条日志里。
     * 线程安全（Atomic 字段），可在分析器线程并发调用。
     */
    private static final class FailureLogThrottle {

        /** 节流窗口：同一窗口内只输出一条完整失败日志。 */
        private static final long WINDOW_MS = 30_000L;

        private final AtomicLong lastLoggedAt = new AtomicLong(0L);
        private final AtomicInteger suppressedCount = new AtomicInteger(0);

        void log(MontoyaApi api, String message) {
            long now = System.currentTimeMillis();
            long last = lastLoggedAt.get();
            if (now - last >= WINDOW_MS && lastLoggedAt.compareAndSet(last, now)) {
                int skipped = suppressedCount.getAndSet(0);
                String suffix = skipped > 0 ? "（另有 " + skipped + " 条失败日志已合并省略）" : "";
                // 被动分析失败走 DEBUG 通道：与全局 INFO 日志精简策略对齐——
                // 避免扫描器场景下失败信息刷屏。开发期开 -Dauditai.debug.prompt 可见。
                if (Boolean.getBoolean("auditai.debug.prompt")) {
                    api.logging().logToOutput("AuditAI [DEBUG] 被动分析失败：" + message + suffix);
                }
            } else {
                suppressedCount.incrementAndGet();
            }
        }
    }

    /**
     * 卸载路径的"原子化"包装：执行 {@code step}，任何异常都被吞掉并写日志——
     * 卸载路径每一步都可能抛（线程池已 shutdown / 文件被占用 / EDT 状态异常），
     * 但任何一步失败都不应阻断后续清理，否则残留资源（I18n listener / ErrorBus
     * 单例 / ThreadLocal MessageDigest）会泄漏到下一次插件加载。
     */
    private static void safeClose(java.util.function.BiConsumer<String, Throwable> logger,
                                  String label, Runnable step) {
        try {
            step.run();
        } catch (RuntimeException e) {
            logger.accept(label + " 抛异常：" + e.getMessage(), e);
        } catch (Error e) {
            logger.accept(label + " 抛 Error：" + e.getMessage(), e);
        }
    }
}
