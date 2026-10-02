package com.auditai.burp.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.auditai.burp.ai.AiClient;
import com.auditai.burp.ai.AiException;
import com.auditai.burp.ai.CancellableAiCall;
import com.auditai.burp.ai.PromptBuilder;
import com.auditai.burp.config.Settings;
import com.auditai.burp.history.AnalysisHistoryEntry;
import com.auditai.burp.history.AnalysisHistoryStore;
import com.auditai.burp.history.RiskLevel;
import com.auditai.burp.skills.Skill;
import com.auditai.burp.skills.SkillLoader;
import com.auditai.burp.skills.SkillStateStore;
import com.auditai.burp.util.TextUtil;
import com.auditai.burp.util.TrafficCompactor;
import com.auditai.burp.util.WorkflowLogger;

import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * 流量分析编排器：<b>技能驱动的两阶段调用</b>。
 *
 * <p>整体流程（业内做法 = Anthropic Skills / OpenAI Function Calling / MCP 通用模式）：</p>
 * <ul>
 *   <li><b>无任何技能启用</b>：单次模型调用直接出结论（最便宜的路径）；</li>
 *   <li><b>有技能启用</b>：两阶段调用——
 *     <ol>
 *       <li>阶段 1（技能选择）：system 段展示"可选技能目录"（id + 名称 + 用途），
 *           加上脱敏的报文 user 段。模型返回 {@code {"active_skill_ids": [...], "analysis": "..."}}。
 *           模型可主动选 0 个或多个技能；若 0 个且 analysis 非空则直接收尾，跳过阶段 2；</li>
 *       <li>阶段 2（最终分析）：把模型选中的技能 prompt 拼到 system 段、userContext 拼到
 *           user 段，再次调模型，拿到最终 analysis。</li>
 *     </ol>
 *   </li>
 * </ul>
 *
 * <p>关键设计：</p>
 * <ul>
 *   <li><b>异步</b>：AI 调用是秒级慢操作，不能阻塞 Swing 事件线程（EDT），
 *       所有分析任务统一提交到单线程执行器按到达顺序串行执行；</li>
 *   <li><b>逐任务可取消</b>：{@link #analyzeAsync} 返回 {@link AnalysisTask} 句柄，
 *       每个页签持有自己的句柄——排队中的任务置取消标志直接放弃，
 *       执行中的任务中断底层 HTTP 请求（{@link CancellableAiCall#cancel()}）；</li>
 *   <li><b>模型有选择权</b>：所有启用技能作为"候选"出现在阶段 1 的 system 段，
 *       但 user 段不会预填任何技能的 userContext（多报文协同的历史摘要等）——
 *       避免"硬塞信息给模型"导致的 token 浪费与决策权丢失；</li>
 *   <li><b>降级链</b>：阶段 1 JSON 解析失败 → 全量启用所有候选技能；阶段 2 失败 → 用阶段 1
 *       的 analysis 兜底（若有），否则整体失败；</li>
 *   <li>守护线程：Burp 退出时不会因本插件的线程被阻塞而无法退出。</li>
 * </ul>
 */
public final class TrafficAnalyzer {

    /**
     * 开发期调试日志开关（运行时动态读取 JVM 系统属性，测试可在 {@code @BeforeAll}
     * 打开、{@code @AfterAll} 关闭，而无需重编译或重启 JVM）。
     *
     * <p>开启时把与模型交互的全部内容（系统提示词、用户提示词、模型原始 JSON、
     * 解析过程、降级路径等）打印到 Burp 的 Extender Output 窗口，
     * 仅用于开发阶段核对"插件到底把什么内容发给了大模型 / 大模型回了什么"。</p>
     *
     * <p>默认关闭（避免把完整报文留在用户的 Burp 日志中）；开发期可通过 JVM 系统属性
     * {@code -Dauditai.debug.prompt=true} 临时开启，无需重新编译。</p>
     */
    private static boolean debugPromptEnabled() {
        return Boolean.getBoolean("auditai.debug.prompt");
    }

    /** 输出到 Burp 日志时的统一前缀，便于在大量日志中过滤本插件内容。 */
    private static final String LOG_PREFIX = "AuditAI";

    /** 时间戳格式化器：摘要行展示"抓取时间"用，本地时区。 */
    private static final DateTimeFormatter TIME_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    /** 单线程分析执行器（守护线程）；队列有界，任务本身支持协作式取消（见 {@link AnalysisTask}）。 */
    private final ThreadPoolExecutor executor;

    /** 分析任务队列容量：有界，避免洪峰（如被动扫描）时无限堆积大报文引用导致 OOM。 */
    private static final int QUEUE_CAPACITY = 256;

    /**
     * 是否输出"开始分析"这类每条分析一条的 info 日志。
     *
     * <p>手动分析（UI 触发）和被动分析都默认 true——让用户在 Output 看到每条分析的
     * 进度边界（【开始分析：】/【分析完成：】）。中间步骤（phase 切换、phase 1 决策、
     * 工具循环次数等）走 debug 通道,默认不打印,避免被动分析时刷屏——
     * 开发期开 -Dauditai.debug.prompt=true 即可一键全部可见。
     * 刷屏风险由调用方按需控制：失败路径仍由 {@code FailureLogThrottle} 节流（30s 一条完整
     * + 合并计数），错误日志（logToError）不受此开关影响。</p>
     */
    private final boolean logInfoEnabled;

    private final MontoyaApi api;
    private final AiClient aiClient;
    private final Settings settings;
    private final PromptBuilder promptBuilder;
    private final AnalysisHistoryStore store;
    private final SkillStateStore skillStateStore;
    private final SkillLoader skillLoader;
    /** 工具工厂：每次分析时按当前请求创建一组 {@link com.auditai.burp.tools.Tool}。
     *  为什么是"工厂"而不是"已构造好的 List"：大多数工具（如"重放"）需要拿到原请求
     *  来锁定 host:port:scheme，按请求逐次构造最自然；工厂让工具的实现可以无状态、
     *  TrafficAnalyzer 也可以 singleton 复用。 */
    private final java.util.function.BiFunction<HttpRequest, HttpResponse,
            List<com.auditai.burp.tools.Tool>> toolFactory;

    /**
     * @param api               Burp API 门面（仅用于日志输出）。
     * @param aiClient          AI 客户端实现。
     * @param settings          共享完整设置（用于读取当前激活 AI 配置 + 全局自定义提示词）。
     * @param store             当前会话的"已分析历史"库；可为 null（此时 {@code userContext}
     *                          里的 {@code {related}} 占位符回退为"历史库不可用"占位文本）。
     * @param skillStateStore   技能启用态仓库：{@code TrafficAnalyzer} 每次分析时读一次，
     *                          拿到最新启用的 id 列表。
     * @param skillLoader       技能文件加载器：按 id 过滤出本次启用的 {@link Skill}。
     * @param toolFactory       工具工厂：按当前请求创建一组 {@link com.auditai.burp.tools.Tool}。
     *                          传 {@code null} 时退化为空工厂（不启用任何工具，行为与"未配置"等同）。
     * @param languageSupplier  当前 UI 语言提供方（{@code () -> I18n.get().current()}），
     *                          传 null 时固定中文。
     */
    public TrafficAnalyzer(MontoyaApi api, AiClient aiClient, Settings settings,
                          AnalysisHistoryStore store,
                          SkillStateStore skillStateStore, SkillLoader skillLoader,
                          java.util.function.BiFunction<HttpRequest, HttpResponse,
                                  List<com.auditai.burp.tools.Tool>> toolFactory,
                          Supplier<PromptBuilder.Lang> languageSupplier) {
        this(api, aiClient, settings, store, skillStateStore, skillLoader, toolFactory, true, languageSupplier);
    }

    /** 便捷构造器：固定中文（不感知 UI 语言切换），无工具。 */
    public TrafficAnalyzer(MontoyaApi api, AiClient aiClient, Settings settings,
                          AnalysisHistoryStore store,
                          SkillStateStore skillStateStore, SkillLoader skillLoader) {
        this(api, aiClient, settings, store, skillStateStore, skillLoader, null, true, null);
    }

    /**
     * 完整构造器（含 info 日志开关 + 工具工厂 + 语言 supplier）：被动分析等高频路径可关掉
     * "每条分析一条日志"。
     */
    public TrafficAnalyzer(MontoyaApi api, AiClient aiClient, Settings settings,
                           AnalysisHistoryStore store,
                           SkillStateStore skillStateStore, SkillLoader skillLoader,
                           java.util.function.BiFunction<HttpRequest, HttpResponse,
                                   List<com.auditai.burp.tools.Tool>> toolFactory,
                           boolean logInfoEnabled,
                           Supplier<PromptBuilder.Lang> languageSupplier) {
        this.api = api;
        this.aiClient = aiClient;
        this.settings = settings;
        this.logInfoEnabled = logInfoEnabled;
        // 提示词构造器:Supplier 让 customPrompt / language 都实时取,这样在设置界面
        // 改完提示词或切语言后无需重建分析器即可立即生效。
        this.promptBuilder = new PromptBuilder(settings::customPrompt, languageSupplier);
        this.store = store;
        this.skillStateStore = skillStateStore;
        this.skillLoader = skillLoader;
        this.toolFactory = toolFactory;
        // 单线程串行执行 AI 分析；队列有界（256）——被动流量洪峰等极端场景下
        // 拒绝新任务而不是无限堆积 request/response 引用造成 OOM（见 analyzeAsync 的拒绝处理）。
        // 线程命名带递增序号（与 PassiveAnalysisExecutor 的 burp-audit-ai-passive-N 风格一致），
        // 便于线程 dump 时区分"分析线程 #3 还是 #5 卡在 AI 调用上"。
        this.executor = new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>(QUEUE_CAPACITY), new ThreadFactory() {
            private final java.util.concurrent.atomic.AtomicInteger counter =
                    new java.util.concurrent.atomic.AtomicInteger(1);

            @Override
            public Thread newThread(Runnable r) {
                Thread thread = new Thread(r, "burp-audit-ai-analyzer-"
                        + counter.getAndIncrement());
                thread.setDaemon(true);
                return thread;
            }
        });
    }

    /**
     * 提交"请求 + 响应"报文进行异步分析，返回可取消的任务句柄。
     * 调用方（UI 线程）无需等待，立即返回。
     *
     * @param request  发起分析的请求快照。
     * @param response 响应快照；为 null 时只分析请求。
     * @param onResult 结果回调（在分析线程触发；回调内若操作 Swing 组件需自行切到 EDT）。
     * @return 分析任务句柄：调用方可持有关联它自己的页签，随时 {@link AnalysisTask#cancel()}。
     */
    public AnalysisTask analyzeAsync(HttpRequest request, HttpResponse response,
                                     Consumer<AnalysisResult> onResult) {
        AnalysisTask task = new AnalysisTask();
        task.setBody(() -> analyze(request, response, onResult, task));
        try {
            executor.execute(task);
        } catch (java.util.concurrent.RejectedExecutionException e) {
            // 队列满（极端洪峰）或执行器已关闭（插件卸载竞态）：不能无限堆积任务，
            // 也不能阻塞调用线程；以错误结果回调收尾，让上层（历史/UI）感知本次分析被跳过。
            error("分析任务被拒绝（执行器队列已满或已关闭）：" + request.method() + " " + request.url(), e);
            if (onResult != null) {
                long start = System.currentTimeMillis();
                onResult.accept(AnalysisResult.error(start, request.method(), request.url(),
                        response != null ? response.statusCode() : -1,
                        "分析队列已满或插件正在卸载，本次分析被跳过。", 0L));
            }
        }
        return task;
    }

    /** 实际分析逻辑（在执行器线程中运行）。 */
    private void analyze(HttpRequest request, HttpResponse response,
                         Consumer<AnalysisResult> onResult, AnalysisTask task) {
        // 审计轨迹（agent ↔ AI 交互 XML）：分析入口创建 logger 并绑定到当前执行器线程，
        // AI 调用层通过静态方法把数据追加进同一个缓冲；出口必须 unbind，避免执行器
        // 线程复用时把后续分析的内容写进上一个 logger。文件落盘由 AnalysisResultSink
        // 在历史记录入库时完成（路径与 history entry 一一对应）。
        WorkflowLogger analysisLogger = WorkflowLogger.openForAnalysis();
        analysisLogger.bindToCurrentThread();
        try {
            doAnalyze(request, response, onResult, task);
        } finally {
            WorkflowLogger.unbindFromCurrentThread();
        }
    }

    /** 实际的分析主体（被 {@link #analyze} 用 try/finally 包起来管理 logger 生命周期）。 */
    private void doAnalyze(HttpRequest request, HttpResponse response,
                           Consumer<AnalysisResult> onResult, AnalysisTask task) {
        if (task.isCancelled()) {
            return;
        }

        long start = System.currentTimeMillis();
        String method = request.method();
        String url = request.url();
        int statusCode = response != null ? response.statusCode() : -1;

        // 1. 取启用的技能快照（按"默认枚举顺序 + 其余按字典序"拼接——与 SkillStateStore.save 一致）。
        List<Skill> enabledSkills = resolveEnabledSkills();
        // 自动激活的技能：始终在 phase 2 注入 system 段，不进 phase 1 候选目录——避免模型被问"是否启用"。
        // pinnedSkills ⊆ enabledSkills（自动激活隐含启用）。
        List<Skill> pinnedSkills = resolvePinnedSkills();

        info("开始分析：" + method + " " + url);

        AnalysisResult result;
        boolean forcedWrapUp = false;
        try {
            // 不论用户启用了哪些 skill，"重放"能力都是 phase 2 的常驻内置能力。
            // 设计动机：SQL 注入 / 鉴权绕过等漏洞仅凭原始报文很难 100% 确认，
            // 必须靠修改参数后观察真实响应才能下结论——让模型在做 phase 2 分析时
            // 始终能调用"重放请求"工具（3 次预算硬上限），而不是把"是否需要重放"
            // 变成一次额外的 skill 选择决策。
            //
            // 流程：
            //   1. 有 skill 启用 → phase 1 让模型先选 skill（候选 = 普通启用 - 自动激活）；
            //      phase 2 注入选中 skill + 自动激活 skill + 重放能力
            //   2. 无 skill 启用 → 直接 phase 2（系统提示词里只含"重放"工具，无 skill 段）
            Phase2Outcome phase2;
            if (enabledSkills.isEmpty()) {
                debug("无 skill 启用 → 直接 phase 2（系统提示词里只含「重放」工具说明）");
                phase2 = analyzeWithTools(List.of(), task, request, response,
                        start, method, url, statusCode);
            } else {
                debug("有 " + enabledSkills.size() + " 个 skill 启用 → phase 1 让模型选 skill + phase 2 工具增强");
                phase2 = analyzeWithSkillSelectionAndTools(enabledSkills, pinnedSkills, task, request, response,
                        start, method, url, statusCode);
            }
            result = phase2.result();
            forcedWrapUp = phase2.forcedWrapUp();
        } catch (Exception e) {
            error("AI 流量分析失败：" + method + " " + url, e);
            result = AnalysisResult.error(start, method, url, statusCode, e.getMessage(),
                    System.currentTimeMillis() - start);
        }

        // 分析完成：把"耗时 + findings 数 + 风险"打到 Output。
        // 这是 INFO 级别下唯一保留的"收尾提示"，让被动流量洪峰时也能确认
        // "这条请求确实跑完了、没卡住"。失败结果也打（error 路径会带"失败"字样）。
        // 其他中间步骤（phase 切换 / 工具循环次数 / phase 1 决策等）走 debug 通道，
        // 默认不打印,避免被动分析时刷屏——开发期开 -Dauditai.debug.prompt 即可全部可见。
        //
        // 工具循环在 MAX_LOOPS 之内未自然收尾（被强制 wrap-up）时，打 ⚠ 行而非"分析完成"——
        // 两者互斥,避免用户看到两条都说"已完成"的歧义日志；
        // ⚠ 行走 debug 通道（受 -Dauditai.debug.prompt 控制）,排查
        // "为什么最后一段 analysis 是占位"时配合该开关一起看。
        long cost = System.currentTimeMillis() - start;
        int findingsCount = result.getFindings().size();
        if (forcedWrapUp) {
            debug("⚠ 工具循环超时强制收尾：" + method + " " + url
                    + "  耗时 " + cost + " ms"
                    + "  风险=" + RiskLevel.derive(result).name()
                    + "  findings=" + findingsCount);
        } else {
            info("分析完成：" + method + " " + url
                    + "  耗时 " + cost + " ms"
                    + "  风险=" + RiskLevel.derive(result).name()
                    + "  findings=" + findingsCount);
        }

        if (onResult != null) {
            onResult.accept(result);
        }
    }

    /**
     * 释放资源：插件卸载时调用。
     *
     * <p>中断执行器（排队任务放弃、进行中的 AI 请求由 {@link AnalysisTask#cancel()}
     * 路径取消），避免 Burp 重载插件后残留旧分析线程与任务队列。</p>
     */
    public void shutdown() {
        executor.shutdownNow();
    }

    /**
     * 工具增强分析入口：把 phase 2 交给 {@link com.auditai.burp.tools.ToolLoopOrchestrator}，
     * 让模型在分析过程中自主决定调用哪些工具（"重放"等）来验证假设。
     *
     * <p>系统提示词由 {@code PromptBuilder.buildSystemPromptForReplay} 构造（含工具说明），
     * 用户段由 {@code PromptBuilder.buildUserPrompt} 构造（再叠加 skill userContext）。</p>
     *
     * <p>工具是 phase 2 的<b>常驻能力</b>，不再与 skill 列表耦合——即使用户一个 skill
     * 都没启用，模型仍然能调任何已注册的工具来验证假设。</p>
     */
    private Phase2Outcome analyzeWithTools(List<Skill> enabledSkills, AnalysisTask task,
                                            HttpRequest request, HttpResponse response,
                                            long start, String method, String url, int statusCode)
            throws AiException {
        // 关键入口日志——确保用户能在 Output 看到 phase 2 工具增强确实启动了
        debug("analyzeWithTools 进入：选中 skill 数=" + enabledSkills.size()
                + "（" + summarizeEnabled(enabledSkills) + "），url=" + method + " " + url);
        // 在调用 orchestrator 之前预渲染"基础 user 段 + skill userContext 模板替换"。
        // 通过 supplier 注入给 ToolLoopOrchestrator：保证多报文协同这类"行为注入型"技能
        // 的 userContext 仍然能影响工具循环的初始 user 段（与原两阶段路径行为一致）。
        final String baseUser = promptBuilder.buildUserPrompt(request, response);
        final String userWithSkillContext = buildUserPromptWithSkills(baseUser, enabledSkills, request);
        // 通过工具工厂按当前请求创建一组 Tool；转成 Map<String, Tool> 让 orchestrator
        // 内部按 name O(1) 路由
        Map<String, com.auditai.burp.tools.Tool> toolMap = new LinkedHashMap<>();
        List<com.auditai.burp.tools.Tool> perRequestTools =
                toolFactory != null ? toolFactory.apply(request, response) : List.of();
        for (com.auditai.burp.tools.Tool t : perRequestTools) {
            toolMap.put(t.name(), t);
        }
        // 阶段 2 提示词级 DEBUG：与阶段 1 的日志对称——开启 -Dauditai.debug.prompt=true 时，
        // 这里打印"进入阶段 2 后把哪些信息交给模型"，避免 Output 日志在"解析结果"后就断档。
        // 只打概要信息（选中技能 + 已注册工具），不打印初始 user 完整内容——
        // 完整 user 段对排错价值有限（可重看阶段 1），徒增日志量。
        // 逐轮细节（每轮 system 长度 / model raw / 解析 / 工具分发）由 ToolLoopOrchestrator
        // 通过注入的 debug logger 输出。
        debug("===== 阶段 2 工具增强分析：agent → model =====");
        debug("选中技能：" + summarizeEnabled(enabledSkills));
        debug("已注册工具：" + (toolMap.isEmpty() ? "（无）" : toolMap.keySet().toString()));
        com.auditai.burp.tools.ToolLoopOrchestrator orchestrator =
                new com.auditai.burp.tools.ToolLoopOrchestrator(
                        api, aiClient, promptBuilder, toolMap, enabledSkills, request, response,
                        com.auditai.burp.tools.ToolLoopOrchestrator.DEFAULT_BUDGET,
                        () -> userWithSkillContext,
                        this::debug);
        com.auditai.burp.tools.ToolLoopOrchestrator.Outcome outcome =
                orchestrator.run(task::isCancelled);
        int used = orchestrator.usedBudget();
        // 阶段 2 收尾 debug：核对工具循环实际用了多少次预算、是否被 MAX_LOOPS 强制收尾，
        // 以及最终 analysis 长度——与阶段 1 的"解析结果"行首尾呼应。
        debug("===== 阶段 2 工具增强分析：model → agent END =====");
        debug("  实际工具调用=" + used + "/"
                + com.auditai.burp.tools.ToolLoopOrchestrator.DEFAULT_BUDGET
                + "  forcedWrapUp=" + outcome.forcedWrapUp()
                + "  最终 analysis 长度=" + outcome.analysis().length());
        if (used > 0) {
            debug("工具增强分析：实际工具调用 " + used + "/"
                    + com.auditai.burp.tools.ToolLoopOrchestrator.DEFAULT_BUDGET + " 次");
        }
        // 走统一的 extractFindings 路径：用 orchestrator 暴露的最后一轮 AI 原始响应，
        // 让 risk / findings 与单轮 / 两阶段路径行为完全一致。
        AnalysisResponseParser.ExtractedFindings extracted =
                AnalysisResponseParser.extractFindings(outcome.lastRaw(), method, url, start, start);
        List<Finding> findings = AnalysisResponseParser.resolveFindings(
                extracted, outcome.analysis(), method, url, start, start);
        return new Phase2Outcome(
                AnalysisResult.success(start, method, url, statusCode, outcome.analysis(),
                        System.currentTimeMillis() - start, findings),
                outcome.forcedWrapUp());
    }

    /**
     * "有 skill 启用"时的入口：先做 phase 1 让模型选 skill（或直接给结论），
     * 再把 phase 2 交给 {@link com.auditai.burp.tools.ToolLoopOrchestrator}，
     * 用选中的 skill 列表 + 常驻工具做多轮分析。
     *
     * <p>与 {@link #analyzeWithTools} 的唯一差别是 phase 1 这一步——把"该不该用 skill"
     * 这个低价值决策从模型手里拿走（强制选 skill），再让模型在 phase 2 用 skill + 工具
     * 做最终分析。</p>
     */
    private Phase2Outcome analyzeWithSkillSelectionAndTools(List<Skill> enabledSkills,
                                                             List<Skill> pinnedSkills,
                                                             AnalysisTask task,
                                                             HttpRequest request, HttpResponse response,
                                                             long start, String method, String url, int statusCode)
            throws AiException {
        // pinned id 集合：用于短路 A 判断 / PromptBuilder 拼【必选技能】目录 / phase 2 去重
        Set<String> pinnedIdSet = new HashSet<>();
        for (Skill p : pinnedSkills) {
            pinnedIdSet.add(p.id());
        }

        // 阶段 1 候选（不含 pinned）= 普通启用：
        // pinned 不作为 phase 1 的"白名单"——它在独立的【必选技能】段展示、由 PromptBuilder
        // 通过 pinnedSkills 参数注入；resolveSelection 用本列表过滤普通启用的拼写错误，
        // 即便模型把 pinned id 误写到 active_skill_ids 也会被当作 unknown 拒绝。
        // pinned 的 prompt 内容不拼到 phase 1（避免 phase 1 没 tool_calls 时模型被"何时调工具"
        // 指令误导），由 phase 2 完整注入。
        List<Skill> regularCandidates = new ArrayList<>(enabledSkills.size() - pinnedSkills.size());
        for (Skill s : enabledSkills) {
            if (!pinnedIdSet.contains(s.id())) {
                regularCandidates.add(s);
            }
        }

        // —— 优化路径 A：所有启用都是 pinned ——
        // regularCandidates 为空时模型无"普通技能"可挑，phase 1 调一次是浪费；
        // 直接进入 phase 2 把 pinned 全部注入——节省一次模型调用。
        // 这是用户只勾 pinned 的最小集场景。
        if (regularCandidates.isEmpty() && !pinnedSkills.isEmpty()) {
            debug("phase 1 候选为空（所有启用都是自动激活）→ 跳过 phase 1，"
                    + "直接进入 phase 2 注入 " + pinnedSkills.size() + " 个自动激活技能 + 重放能力");
            return analyzeWithTools(pinnedSkills, task, request, response,
                    start, method, url, statusCode);
        }

        // 阶段 2 选中 = 模型在 phase 1 选的 + 自动激活的。
        // 顺序：先 pinned（"系统默认要带的"在最末），再模型选的（"模型主动选的"在前）。
        // 去重 pinned：phase 1 目录里 pinned 已被标"自动激活"，resolveSelection 用 regularCandidates
        // 作为白名单不接受 pinned id，但兜底过滤避免 prompt 重复拼接同一段 prompt 内容。
        List<Skill> phase2Selection = new ArrayList<>(regularCandidates.size() + pinnedSkills.size());

        // —— 阶段 1：技能选择 ——
        // system 段结构：基础 + 【可选技能】(普通启用) + 【必选技能】(pinned) +
        //               选择指令 + 必选说明 + 输出格式。
        // pinned prompt 内容不拼——避免 phase 1 没 tool_calls 时模型被"何时调工具"指令误导。
        String phase1System = promptBuilder.buildSystemPromptForSkillSelection(regularCandidates, pinnedSkills);
        String phase1User = promptBuilder.buildUserPrompt(request, response);

        // —— 阶段 1 提示词级 DEBUG：只打"概要信息 + 长度"，不打印完整 system / user 文本 ——
        // 设计动机：阶段 1 单次请求内容动辄 5K+ 字符，每个字段完整打 8K 输出洪流；
        // 真正排错需要看的内容（模型原始 JSON、解析结果）已经在 model→agent 段落里。
        // 完整 system / user 文本可以用 -Dauditai.debug.prompt.full=true（见 buildUserPromptDebug）
        // 单独开启（暂未实现，本轮先按下不表）。
        debug("===== 阶段 1 技能选择：agent → model =====");
        debug("候选技能（普通启用 - 自动激活）：" + summarizeEnabled(regularCandidates));
        if (!pinnedSkills.isEmpty()) {
            debug("自动激活（已直接拼到 phase 1 system 段，phase 2 也会再拼一次）：" + summarizeEnabled(pinnedSkills));
        }
        debug("  phase1 systemPrompt 长度=" + phase1System.length()
                + "  userPrompt 长度=" + phase1User.length());

        String phase1Raw = executeAndAwait(task, () -> {
            List<AiClient.ChatMessage> messages = new ArrayList<>(2);
            messages.add(new AiClient.ChatMessage("system", phase1System));
            messages.add(new AiClient.ChatMessage("user", phase1User));
            return aiClient.completeJsonAsyncWithFallback(messages);
        });

        debug("===== 阶段 1 技能选择：model → agent =====");
        debug(TextUtil.prettyJson(phase1Raw));

        // 阶段 1 解析只看 regularCandidates（普通启用）——模型在 phase 1 只能从普通启用里挑，
        // 自动激活技能的 id 即使被模型"再选一次"也会被 resolveSelection 当作 unknown 拒绝。
        AnalysisResponseParser.ParseAttempt parseAttempt = parseSelection(phase1Raw, regularCandidates);

        // 阶段 1 解析完全失败（模型返回的根本不是 JSON，宽松 fallback 也无法提取）：
        // 不进 phase 2，直接 fail-fast 收尾——避免已知模型会乱返时浪费一次模型调用，
        // 且让用户能从 ERROR 日志清楚看到失败原因。
        if (!parseAttempt.isSuccess()) {
            String reason = parseAttempt.failureReason();
            error("阶段 1 模型响应解析失败，跳过 phase 2 直接收尾：" + reason, null);
            return new Phase2Outcome(
                    AnalysisResult.success(start, method, url, statusCode,
                            "（阶段 1 解析失败：" + reason + "）",
                            System.currentTimeMillis() - start, List.of()),
                    false);
        }

        AnalysisResponseParser.SelectionResult selection =
                AnalysisResponseParser.resolveSelection(parseAttempt.selection(), regularCandidates);
        // 模型尝试挑了不存在的技能 id（拼写错 / 幻觉 / 版本不匹配）——
        // resolveSelection 已主动拒绝把它降级到全量兜底，这里把名单打出来方便排查。
        if (!selection.unknownIds().isEmpty()) {
            debug("阶段 1 模型返回了不存在的技能 id（已拒绝降级到全量兜底，避免 prompt 爆炸）："
                    + selection.unknownIds());
        }
        debug("解析结果：选中技能=" + summarizeEnabled(selection.activeSkills())
                + " analysisProvided=" + !selection.analysis().isEmpty()
                + " tookPhase2=" + (selection.tookPhase2() ? "true" : "false（直接收尾）")
                + " unknownIds=" + selection.unknownIds());

        if (!selection.tookPhase2()) {
            // 模型主动跳过阶段 2：直接用阶段 1 的 analysis 收尾。
            // 阶段 1 不暴露重放工具（重放只对 phase 2 启用）——这里只走风险/finding 抽取。
            //
            // —— 优化路径 B：有 pinned 时仍要进 phase 2 ——
            // 模型"选 0 个 skill"是基于 regularCandidates 做的判断；pinned 不在候选中（白名单外）
            // 所以模型即便写了 pinned id 也会被拒绝。但 pinned 是用户明确配置的常驻能力，
            // 不应被模型的"不需要 skill"结论吞掉——只要 pinned 非空，仍进入 phase 2 用 pinned
            // + 重放工具做最终分析（即便模型没把 pinned id 写到 active_skill_ids）。
            if (!pinnedSkills.isEmpty()) {
                debug("phase 1：模型选 0 个 skill 但有 " + pinnedSkills.size()
                        + " 个必选技能 → 不直接收尾，强制进入 phase 2 用 pinned + 重放能力");
                return analyzeWithTools(pinnedSkills, task, request, response,
                        start, method, url, statusCode);
            }
            debug("phase 1：模型选择 0 个 skill 且给了 analysis → 跳过 phase 2，直接收尾（注意：phase 1 不暴露重放工具，所以这里没有重放机会）");
            AnalysisResponseParser.ExtractedFindings extracted =
                    AnalysisResponseParser.extractFindings(phase1Raw, method, url, start, start);
            List<Finding> findings = AnalysisResponseParser.resolveFindings(
                    extracted, selection.analysis(), method, url, start, start);
            return new Phase2Outcome(
                    AnalysisResult.success(start, method, url, statusCode,
                            selection.analysis().isEmpty() ? "（模型未给出分析结论）" : selection.analysis(),
                            System.currentTimeMillis() - start, findings),
                    false);
        }

        // —— 阶段 2：多轮 agent 循环 ——
        // 阶段 2 注入：自动激活技能（先）+ 模型在 phase 1 选中的（去重 pinned）。
        // 顺序：先 pinned（"系统默认要带的"在最末），再模型选的（"模型主动选的"在前）。
        // 去重 pinned：phase 1 目录里 pinned 已被标"自动激活"，模型本不该写到 active_skill_ids，
        // 但兜底过滤避免 prompt 重复拼接同一段 prompt 内容。
        Set<String> selectedIds = new HashSet<>();
        for (Skill s : pinnedSkills) {
            if (selectedIds.add(s.id())) {
                phase2Selection.add(s);
            }
        }
        for (Skill s : selection.activeSkills()) {
            if (selectedIds.add(s.id())) {
                phase2Selection.add(s);
            }
        }
        debug("phase 1：模型选中了 " + selection.activeSkills().size() + " 个 skill（"
                + summarizeEnabled(selection.activeSkills())
                + "）+ 自动激活 " + pinnedSkills.size() + " 个"
                + " → 进入 phase 2 工具增强分析（合计 " + phase2Selection.size() + " 个）");
        return analyzeWithTools(phase2Selection, task, request, response,
                start, method, url, statusCode);
    }

    /**
     * 阶段 1 解析入口：返回 {@link AnalysisResponseParser.ParseAttempt}，让调用方拿到
     * 失败原因决定走 fail-fast 还是 continue。
     *
     * <p>具体决策表（按用户拍板的协议）见 {@link AnalysisResponseParser#resolveSelection}；
     * 本方法只在解析失败时打一条 debug 日志，方便定位阶段 1 异常。</p>
     */
    private AnalysisResponseParser.ParseAttempt parseSelection(String rawText, List<Skill> enabledSkills) {
        AnalysisResponseParser.ParseAttempt attempt =
                AnalysisResponseParser.tryParseSelectionWithReason(rawText);
        if (!attempt.isSuccess()) {
            debug("阶段 1 解析失败：" + attempt.failureReason());
        } else if (attempt.selection().analysis().isEmpty() && attempt.selection().activeIds().isEmpty()) {
            // 不扩张到全量启用——尊重模型的"啥都没说"意图。
            debug("阶段 1 未返回有效选择（active_skill_ids=[] + analysis 空），按'模型没结论'收尾");
        }
        return attempt;
    }

    /**
     * 取启用的技能：先按 {@link com.auditai.burp.skills.DefaultEnabledSkill#ids()} 顺序
     * 拼接默认启用的，再按字典序补上用户手动启用、但不在默认列表里的 id。
     */
    private List<Skill> resolveEnabledSkills() {
        Set<String> enabledIds = skillStateStore.loadEnabledIds();
        if (enabledIds.isEmpty()) {
            return List.of();
        }
        Map<String, Skill> byId = new LinkedHashMap<>();
        for (Skill skill : skillLoader.load()) {
            byId.put(skill.id(), skill);
        }
        List<Skill> result = new ArrayList<>();
        for (String id : enabledIds) {
            Skill skill = byId.get(id);
            if (skill != null) {
                result.add(skill);
            }
        }
        return result;
    }

    /**
     * 取"自动激活"的技能：永远不进 phase 1 候选目录，但每次 phase 2 都会自动注入。
     *
     * <p>顺序：先按 {@link com.auditai.burp.skills.DefaultEnabledSkill#ids()} 拼接
     * （与 enabledSkills 顺序保持一致），再按字典序补上其余 id。</p>
     */
    private List<Skill> resolvePinnedSkills() {
        Set<String> pinnedIds = skillStateStore.loadPinnedIds();
        if (pinnedIds.isEmpty()) {
            return List.of();
        }
        Map<String, Skill> byId = new LinkedHashMap<>();
        for (Skill skill : skillLoader.load()) {
            byId.put(skill.id(), skill);
        }
        List<Skill> result = new ArrayList<>();
        for (String id : pinnedIds) {
            Skill skill = byId.get(id);
            if (skill != null) {
                result.add(skill);
            }
        }
        return result;
    }

    /** 把启用技能列表压缩成 "id1,id2,..." 形式，方便日志中一眼看清。 */
    private static String summarizeEnabled(List<Skill> skills) {
        if (skills == null || skills.isEmpty()) {
            return "（无）";
        }
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < skills.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(skills.get(i).id());
        }
        return sb.append("]").toString();
    }

    /**
     * 渲染启用技能列表的 userContext 模板，按每个技能的 {@code userContext} 拼到基础
     * user 段之后。技能声明的"附加上下文"（如多报文协同的历史摘要）通过此机制注入 user 段。
     *
     * <p>在新的"工具"编排里，本方法的结果会被 {@code analyzeWithTools} 进一步
     * 通过 {@code ToolLoopOrchestrator.初始 user supplier} 注入——保证多报文协同
     * 等"行为注入型"技能仍然能影响 user 段。</p>
     */
    private String buildUserPromptWithSkills(String baseUserPrompt, List<Skill> skills, HttpRequest request) {
        if (skills == null || skills.isEmpty()) {
            return baseUserPrompt;
        }
        StringBuilder sb = new StringBuilder(baseUserPrompt);
        for (Skill skill : skills) {
            if (skill.hasUserContext()) {
                sb.append("\n\n【技能：").append(skill.name()).append("】\n")
                  .append(renderUserContext(skill, request));
            }
        }
        return sb.toString();
    }

    /**
     * 把单个技能 {@code userContext} 模板按占位符替换为实际内容。
     *
     * <p>支持的占位符：</p>
     * <ul>
     *   <li>{@code {related}}：同域历史摘要（按技能声明的 {@code summaryCount} 截取），
     *       历史库不可用 / host 解析失败 / 无历史时回退到说明性占位文本；</li>
     *   <li>{@code {summaryCount}}：本次实际取得的摘要条数（数字）。</li>
     * </ul>
     */
    private String renderUserContext(Skill skill, HttpRequest request) {
        String template = skill.userContext();
        if (template.contains("{related}") || template.contains("{summaryCount}")) {
            RelatedFetch fetched = fetchRelated(skill, request);
            if (template.contains("{related}")) {
                template = template.replace("{related}", fetched.body);
            }
            if (template.contains("{summaryCount}")) {
                template = template.replace("{summaryCount}", String.valueOf(fetched.actualCount));
            }
        }
        return template;
    }

    /**
     * 拉取同域历史摘要：取技能声明的 {@code summaryCount}（缺省走
     * {@link Skill#DEFAULT_SUMMARY_COUNT}）。历史库不可用 / host 缺失时返回占位文本，
     * 仍给 {@code actualCount=0}，让占位符替换结果可见。
     */
    private RelatedFetch fetchRelated(Skill skill, HttpRequest request) {
        int requested = skill.summaryCount() > 0 ? skill.summaryCount() : Skill.DEFAULT_SUMMARY_COUNT;
        if (store == null) {
            return new RelatedFetch("（同域历史库不可用：未启用 Proxy 收集或临时项目）", 0);
        }
        if (request == null) {
            return new RelatedFetch("（无法解析 host：原请求不可用）", 0);
        }
        burp.api.montoya.http.message.HttpHeader hostHeader = request.header("host");
        if (hostHeader == null) {
            return new RelatedFetch("（无法解析 host：请求头缺少 Host）", 0);
        }
        long excludeId = findSelfEntryId(request);
        List<AnalysisHistoryEntry> related =
                store.findByDomain(excludeId, hostHeader.value(), requested);
        if (related.isEmpty()) {
            return new RelatedFetch("（同域暂无历史请求）", 0);
        }
        StringBuilder body = new StringBuilder();
        body.append("（按时间倒序，共 ").append(related.size())
            .append(" 条；每条含 method/URL/状态码/headers/极简 body）\n\n");
        for (AnalysisHistoryEntry meta : related) {
            body.append(renderRelatedEntry(meta));
        }
        return new RelatedFetch(body.toString(), related.size());
    }

    /**
     * 在历史库中定位与当前请求 (method + url) 匹配的<b>最近一条</b>记录 id；
     * 找不到返回 -1（不排除任何记录）。仅用于"同域历史摘要"排除自身。
     */
    private long findSelfEntryId(HttpRequest request) {
        String method = request.method();
        String url = request.url();
        long best = -1L;
        long bestTs = Long.MIN_VALUE;
        for (AnalysisHistoryEntry m : store.list()) {
            // HTTP method 按 RFC 7230 大小写不敏感,用 Locale.ROOT 比对避免土耳其语 locale 异常
            if (method != null && !method.isEmpty()
                    && !method.equals(m.getMethod().toLowerCase(java.util.Locale.ROOT))) {
                continue;
            }
            if (url != null && !url.isEmpty() && !url.equals(m.getUrl())) {
                continue;
            }
            if (m.getTimestamp() > bestTs) {
                bestTs = m.getTimestamp();
                best = m.getId();
            }
        }
        return best;
    }

    /**
     * 把单条历史元数据 + 完整请求/响应原始字节压缩为一段"摘要段落"。
     */
    private String renderRelatedEntry(AnalysisHistoryEntry meta) {
        StringBuilder entry = new StringBuilder(1024);
        String capturedAt = TIME_FORMATTER.format(Instant.ofEpochMilli(meta.getTimestamp()));
        entry.append("── ID=").append(meta.getId())
            .append("  ").append(capturedAt)
            .append("  ").append(meta.getMethod())
            .append(' ').append(meta.getUrl());
        if (meta.getStatusCode() >= 0) {
            entry.append("  → ").append(meta.getStatusCode());
        } else {
            entry.append("  → ?");
        }
        entry.append("  (").append("?")
            .append('/')
            .append(meta.isHasResponse() ? "?" : "—")
            .append(") ──\n");
        try {
            byte[] rawReq = readEntryBody(meta.getRequestFile());
            byte[] rawResp = meta.isHasResponse() ? readEntryBody(meta.getResponseFile()) : null;
            entry.append(TrafficCompactor.compactRawPair(rawReq, rawResp));
        } catch (IOException e) {
            entry.append("（读取失败：").append(e.getClass().getSimpleName()).append("）");
        }
        entry.append("\n\n");
        return entry.toString();
    }

    /** 从 gzip 落盘文件读 entry body；文件为 null 时返回 null。 */
    private static byte[] readEntryBody(java.nio.file.Path file) throws IOException {
        if (file == null) {
            return null;
        }
        byte[] bytes = BodyStorage.readCompressed(file);
        return bytes.length == 0 ? null : bytes;
    }

    /** 拉取同域历史的结果：实际文本与条数。 */
    private record RelatedFetch(String body, int actualCount) {}

    /**
     * 在执行器线程里同步等待一个 {@link CancellableAiCall}。
     *
     * <p>先注册任务正在执行的调用（{@code attachCall}）再检查取消标志——
     * 若先检查后注册，取消会落在"activeCall 仍为空"的窗口里：cancel() 只置标志，
     * 已经发出的 AI 请求无人取消，会完整跑完（用户以为取消了，模型调用仍在计费）。</p>
     */
    private String executeAndAwait(AnalysisTask task, java.util.function.Supplier<CancellableAiCall> starter)
            throws AiException {
        CancellableAiCall call = starter.get();
        task.attachCall(call);
        if (task.isCancelled()) {
            call.cancel();
            throw AiException.cancelled();
        }
        return call.await();
    }

    // —— 日志输出 ——

    private void info(String message) {
        if (api != null && logInfoEnabled) {
            api.logging().logToOutput(LOG_PREFIX + " " + message);
        }
    }

    private void error(String message, Throwable t) {
        if (api != null) {
            api.logging().logToError(LOG_PREFIX + " " + message, t);
        }
    }

    private void debug(String message) {
        if (debugPromptEnabled() && api != null) {
            api.logging().logToOutput(LOG_PREFIX + " [DEBUG] " + message);
        }
    }

    // 历史代码迁出说明：
    //  - JSON 解析相关（tryParseSelection / parseSelection / extractAnalysis / extractFindings
    //    / resolveFindings / readString / readInt 与 ParsedSelection / SelectionResult /
    //    ExtractedFindings）已迁到 AnalysisResponseParser。

    /**
     * Phase 2（工具增强分析）的返回值：分析结果 + 是否因 {@code MAX_LOOPS} 强制收尾。
     *
     * <p>把 {@code forcedWrapUp} 从编排器透到外层 {@link #analyze}，让"⚠ 工具循环超时强制收尾"
     * 这条 debug 日志只在真正被强制收尾时打出来——和【分析完成：】形成互斥关系，
     * 避免用户看到两条都说"已完成"的歧义日志。该行走 debug 通道,
     * 由 {@code -Dauditai.debug.prompt} 开关统一控制是否输出。</p>
     */
    private record Phase2Outcome(AnalysisResult result, boolean forcedWrapUp) {
    }
}
