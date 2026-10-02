package com.auditai.burp.tools;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.auditai.burp.ai.AiClient;
import com.auditai.burp.ai.AiException;
import com.auditai.burp.ai.CancellableAiCall;
import com.auditai.burp.ai.PromptBuilder;
import com.auditai.burp.skills.Skill;
import com.auditai.burp.util.TextUtil;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * 通用"工具循环"编排器：在分析流程里实现 OpenAI Function Calling / Anthropic Tool Use
 * 模式的多轮 agent 循环。
 *
 * <p><b>设计参考</b>：</p>
 * <ul>
 *   <li>OpenAI Function Calling / Anthropic Tool Use —— 模型在每次输出里携带
 *       {@code tool_calls}，由服务端执行后回填到下一轮 user 段；</li>
 *   <li>ReAct / MRKL 范式 —— "思考 → 行动 → 观察 → 思考"的循环；</li>
 *   <li>Burp Repeater 体验 —— 用户在 Repeater 里能反复按"Go"重发修改后的请求，
 *       这里把"按 Go"的能力交给模型自主决策，但<b>限定 3 次预算</b>防止失控。</li>
 * </ul>
 *
 * <p><b>工具路由</b>：本类对具体工具（"重放"/"爆破"/"解码"等）完全无感知——
 * 调用方通过构造器注入 {@link Map}{@code <String, Tool>} 工具表，路由逻辑就是
 * {@code toolMap.get(call.toolName())}。加新工具 = 加一个 {@code Tool} 实现 + 注册，
 * 本类一行不用改。</p>
 *
 * <p><b>硬约束</b>：</p>
 * <ol>
 *   <li>总工具调用次数 ≤ {@link #DEFAULT_BUDGET}（3）；预算与 trace 用 {@link AtomicInteger}
 *       / 集合承载，当前由<b>单一分析线程串行调用</b>，原子类型只是为将来并发预留；</li>
 *   <li>单次分析最多循环 {@link #MAX_LOOPS} 轮（8）—— 防止模型"再来一次"无限循环；
 *       超过即强制收尾；</li>
 *   <li>任何一次 AI 调用失败 → 用最后一次成功轮次的 analysis 兜底（与现有
 *       {@code TrafficAnalyzer.analyzeWithSkillSelection} 的回退策略保持一致）。</li>
 * </ol>
 */
public final class ToolLoopOrchestrator {

    /**
     * 单次分析允许的最大工具调用次数。
     *
     * <p>业内经验值：3 次足够覆盖"基础验证 → 时间盲注 → 提取数据"这条主线；
     * 同时也能兜住"误报 / 失败 / 重发"等正常损耗，再多就属于"扫描器"范畴，应交给
     * Burp 自带的 Intruder 而不是模型循环。</p>
     */
    public static final int DEFAULT_BUDGET = 3;

    /**
     * 单次分析最多循环轮数（含"系统提示 + 响应 + 工具结果"的完整对话轮）。
     * 8 轮够用：1 轮原始分析 + 3 轮重放 + 3 轮响应观察 + 1 轮收尾，剩余是缓冲。
     */
    public static final int MAX_LOOPS = 8;

    private final MontoyaApi api;
    private final AiClient aiClient;
    private final PromptBuilder promptBuilder;
    private final Map<String, Tool> tools;
    private final List<Skill> enabledSkills;
    private final HttpRequest originalRequest;
    private final HttpResponse originalResponse;
    /** 初始 user 段提供方：测试可注入桩，避开 Montoya factory 依赖。 */
    private final Supplier<String> initialUserPromptSupplier;

    private final int budget;
    private final AtomicInteger usedBudget = new AtomicInteger(0);
    private final List<ToolTrace> trace = new ArrayList<>();

    /** DEBUG 级别日志回调：由生产路径（{@code TrafficAnalyzer}）注入它的 {@code debug()}，
     *  让阶段 2 工具循环的逐轮细节（system / 消息上下文 / model raw / 解析 / 收尾）与阶段 1
     *  共用同一个开关 {@code -Dauditai.debug.prompt}，日志格式统一为
     *  {@code AuditAI [DEBUG] ...}。传 null 时回退到本类自带的 api + 系统属性开关
     *  （仅限未走 TrafficAnalyzer 的独立用法 / 测试场景）。 */
    private final Consumer<String> debugLogger;

    /**
     * 完整构造器：注入工具表 + 原始请求 + 初始 user 段 supplier + debug 日志回调。
     *
     * <p>工具表用 {@link LinkedHashMap} 以保留插入顺序——日志里能看出工具注册顺序。
     * 工具名重复时后者覆盖前者（与 Map 语义一致）。</p>
     *
     * <p>{@code debugLogger} 用于把逐轮 prompt 级细节打到 Burp Output（生产路径注入
     * {@code TrafficAnalyzer.debug}，与阶段 1 共用 {@code -Dauditai.debug.prompt}）；
     * 传 null 时回退到本类自带的 api + 系统属性开关。</p>
     */
    public ToolLoopOrchestrator(MontoyaApi api, AiClient aiClient, PromptBuilder promptBuilder,
                                Map<String, Tool> tools,
                                List<Skill> enabledSkills,
                                HttpRequest originalRequest, HttpResponse originalResponse,
                                int budget,
                                Supplier<String> initialUserPromptSupplier,
                                Consumer<String> debugLogger) {
        // api / originalRequest / originalResponse 都允许为 null（测试场景）。
        this.api = api;
        this.aiClient = Objects.requireNonNull(aiClient, "aiClient");
        this.promptBuilder = Objects.requireNonNull(promptBuilder, "promptBuilder");
        this.tools = tools != null ? new LinkedHashMap<>(tools) : Map.of();
        this.enabledSkills = enabledSkills != null ? List.copyOf(enabledSkills) : List.of();
        this.originalRequest = originalRequest;
        this.originalResponse = originalResponse;
        this.budget = Math.max(0, Math.min(budget, DEFAULT_BUDGET));
        this.initialUserPromptSupplier = initialUserPromptSupplier;
        this.debugLogger = debugLogger;
    }

    /** 测试 / 高级用法：注入自定义预算（生产路径用 {@link #DEFAULT_BUDGET}），无 supplier / debug logger。 */
    public ToolLoopOrchestrator(MontoyaApi api, AiClient aiClient, PromptBuilder promptBuilder,
                                Map<String, Tool> tools,
                                List<Skill> enabledSkills,
                                HttpRequest originalRequest, HttpResponse originalResponse,
                                int budget) {
        this(api, aiClient, promptBuilder, tools, enabledSkills, originalRequest, originalResponse,
                budget, null, null);
    }

    /** 完整控制版（带 supplier，无 debug logger）：测试注入桩 user 段时使用。 */
    public ToolLoopOrchestrator(MontoyaApi api, AiClient aiClient, PromptBuilder promptBuilder,
                                Map<String, Tool> tools,
                                List<Skill> enabledSkills,
                                HttpRequest originalRequest, HttpResponse originalResponse,
                                int budget,
                                Supplier<String> initialUserPromptSupplier) {
        this(api, aiClient, promptBuilder, tools, enabledSkills, originalRequest, originalResponse,
                budget, initialUserPromptSupplier, null);
    }

    /** 默认预算的便捷构造器。 */
    public ToolLoopOrchestrator(MontoyaApi api, AiClient aiClient, PromptBuilder promptBuilder,
                                Map<String, Tool> tools,
                                List<Skill> enabledSkills,
                                HttpRequest originalRequest, HttpResponse originalResponse) {
        this(api, aiClient, promptBuilder, tools, enabledSkills, originalRequest, originalResponse,
                DEFAULT_BUDGET, null, null);
    }

    /**
     * 跑完整的多轮循环：发起第一轮 → 解析 → 执行工具调用 → 喂回结果 → 循环 → 收尾。
     *
     * <p>本方法是阻塞的（与现有 {@code TrafficAnalyzer} 的"分析线程里同步等待"模式一致）；
     * 调用方应当已经处于分析执行器线程里（不是 EDT）。</p>
     *
     * <p>返回 {@link Outcome} 而不是裸 String：保留最后一轮 AI 调用的原始响应，
     * 供调用方走统一的 {@code extractFindings} 路径（避免"分析文本里写了 risk=high 但
     * findings 列表丢"的撕裂感）。</p>
     *
     * @param cancelled 取消检查器：每次发起 AI 调用前调用，true 时立即抛
     *                   {@link AiException} 终止循环。本参数允许 null（永不被取消）。
     * @return 最终结果：分析文本 + 最后一轮 AI 原始响应。
     * @throws AiException AI 调用本身失败时抛出；循环内已成功收尾则不抛。
     */
    public Outcome run(BooleanSupplier cancelled) throws AiException {
        BooleanSupplier cancelCheck = cancelled != null ? cancelled : () -> false;
        // 关键流程事件：进入工具循环。
        // 已注册工具 + 预算写 INFO，让用户在不开启 DEBUG 模式时也能确认流程已启动。
        // TrafficAnalyzer.analyzeWithTools 已经写过一条带 URL 的 INFO，本条只补
        // "工具侧视角"的信息（工具名 + 预算），便于在多 skill + 多工具的复杂场景下
        // 一眼看清"这轮实际能用什么工具"。
        debug("工具循环：已注册工具 "
                + (tools.isEmpty() ? "（无）" : tools.keySet())
                + "，预算 " + budget + " 次");
        // 初始 user 段：测试可注入桩（避开 Montoya factory），生产路径走 PromptBuilder 走正常路径。
        String baseUser = initialUserPromptSupplier != null
                ? initialUserPromptSupplier.get()
                : promptBuilder.buildUserPrompt(originalRequest, originalResponse);
        // 追加"可替换参数"清单到 user 段末尾（仅生产路径：测试桩不用关心）
        // 这是 v2 重放协议的关键——告诉模型"原请求里有哪些 key 可用、属于哪类"，
        // 模型就只需要写 {"key":"newValue"} 而不用再粘整段 HTTP 报文。
        // 用 ReplayService.listAddressableParamsStatic 直接读 HttpRequest.parameters()，
        // 不依赖 Montoya factory（生产路径下 originalRequest 非 null；为 null 时返回 ""）。
        if (initialUserPromptSupplier == null) {
            String addrParams = com.auditai.burp.tools.replay.ReplayService
                    .listAddressableParamsStatic(originalRequest);
            if (!addrParams.isEmpty()) {
                // 醒目前缀：明确告诉模型"调 replay_request 必须从这里选 key"，
                // 防止小模型照搬系统提示词里的 `{"id":"1'"}` 模板。
                // 文案 / 语言分支统一走 PromptBuilder.buildAddressableParamsGuard()，
                // 本类不感知语言细节——保持工具调度器纯逻辑层的边界。
                baseUser = baseUser + promptBuilder.buildAddressableParamsGuard() + addrParams;
            }
        }
        List<AiClient.ChatMessage> messages = new ArrayList<>();
        String lastAnalysis = "";
        String lastRaw = "";
        for (int loop = 0; loop < MAX_LOOPS; loop++) {
            if (cancelCheck.getAsBoolean()) {
                throw AiException.cancelled();
            }
            int remaining = budget - usedBudget.get();
            String systemPrompt = promptBuilder.buildSystemPromptForReplay(enabledSkills, remaining);
            if (loop == 0) {
                messages.add(new AiClient.ChatMessage("user", baseUser));
            }
            // —— DEBUG：agent → model ——
            // 设计目标：用户在 Burp Output 里能一眼看清"本轮模型回了什么 + 编排器怎么派发"，
            // 至于"agent 把什么发给了模型"只打概要（system 长度 + 消息条数）——
            // 完整 system / 完整消息上下文 / 下一轮 user 段在每轮都打，会让单条分析
            // 的日志量爆炸（典型 3 轮工具循环 → 24K+ 字符的"输入侧"日志）。
            // 真要看完整内容，可临时把下面两行注释打开，或用 -Dauditai.debug.prompt.full
            // 之类的开关控制（暂未实现）。
            debug("===== 阶段 2 工具循环 round " + (loop + 1) + "/" + MAX_LOOPS
                    + "：agent → model =====");
            debug("  systemPrompt 长度=" + systemPrompt.length()
                    + "  消息条数=" + messages.size()
                    + "  剩余预算=" + remaining + "/" + budget);

            String raw = callModel(cancelCheck, messages, systemPrompt);
            lastRaw = raw;
            ToolCallParser.Parsed parsed = ToolCallParser.parse(raw);

            // —— DEBUG：model → agent ——
            // 保留完整的"模型回了什么 + 编排器怎么派发"——这是排错时最有价值的内容。
            // raw 响应走 TextUtil.prettyJson 美化为多行 JSON，方便肉眼扫读关键字段。
            debug("===== 阶段 2 工具循环 round " + (loop + 1) + "/" + MAX_LOOPS
                    + "：model → agent =====");
            debug(TextUtil.prettyJson(truncate(raw, RAW_DEBUG_CHARS)));
            StringBuilder parsedDump = new StringBuilder(256);
            parsedDump.append("--- 解析 ---\n");
            if (parsed.analysis() == null) {
                parsedDump.append("analysis：无草稿\n");
            } else {
                parsedDump.append("analysis（").append(parsed.analysis().length()).append(" 字符）: ")
                        .append(abbreviate(parsed.analysis(), 200)).append('\n');
            }
            if (parsed.toolCalls().isEmpty()) {
                parsedDump.append("tool_calls：[]（本轮收尾）\n");
            } else {
                parsedDump.append("tool_calls：共 ").append(parsed.toolCalls().size()).append(" 个\n");
                for (int ti = 0; ti < parsed.toolCalls().size(); ti++) {
                    ToolCall c = parsed.toolCalls().get(ti);
                    parsedDump.append("  [").append(ti + 1).append("] name=").append(c.toolName())
                            .append(", reason=").append(c.reason() == null ? "（无）" : c.reason()).append('\n')
                            .append("      arguments=").append(c.argumentsJson()).append('\n');
                }
            }
            if (!parsed.errors().isEmpty()) {
                parsedDump.append("解析错误：").append(parsed.errors()).append('\n');
            }
            debug(parsedDump.toString());

            if (parsed.analysis() != null) {
                lastAnalysis = parsed.analysis();
            }
            // 决策：模型要么"还要调用工具"（tool_calls 非空），要么"收尾"（tool_calls 空）。
            if (!parsed.hasToolCalls()) {
                debug("--- 决策：模型收尾（tool_calls=[]），工具循环结束 ---");
                debug("模型收尾：第 " + (loop + 1) + " 轮未发起工具调用，分析结束"
                        + "（本次使用 " + usedBudget.get() + " / " + budget + " 次工具预算）");
                return new Outcome(lastAnalysis, raw, false);
            }
            // 追加本轮 assistant 输出到历史，让模型下一轮能看到"我刚才发过什么"。
            messages.add(new AiClient.ChatMessage("assistant", raw));
            // 执行所有 tool_calls（按数组顺序）；用 budget 控制执行上限。
            int accepted = Math.min(parsed.toolCalls().size(), budget - usedBudget.get());
            StringBuilder userReply = new StringBuilder(1024);
            // —— DEBUG：工具分发 ——
            StringBuilder dispatchDump = new StringBuilder(256);
            dispatchDump.append("--- 工具分发（请求 ").append(parsed.toolCalls().size())
                    .append(" 个；budget=" + remaining + "/" + budget
                            + "，可执行=" + accepted + "）---\n");
            for (int i = 0; i < parsed.toolCalls().size(); i++) {
                ToolCall call = parsed.toolCalls().get(i);
                // 取消检查：用户可能在"本轮工具调用执行到一半"时点 Cancel，而每次
                // dispatchTool 内部都是一次阻塞的 HTTP 发送——不在循环内检查的话，
                // 本轮剩余调用会全部发完（最多再打 2 发），用户以为已经取消。
                if (cancelCheck.getAsBoolean()) {
                    dispatchDump.append("  --- 已取消：跳过本轮剩余 ")
                            .append(parsed.toolCalls().size() - i).append(" 个工具调用 ---\n");
                    debug("已取消：跳过本轮剩余工具调用（" + (parsed.toolCalls().size() - i) + " 个）");
                    break;
                }
                if (i < accepted) {
                    ToolOutcome outcome = dispatchTool(call);
                    int newUsed = usedBudget.incrementAndGet();
                    String callId = "tc-" + (trace.size() + 1) + "-" + UUID.randomUUID().toString().substring(0, 8);
                    trace.add(new ToolTrace(callId, call, outcome));
                    // info 级别：让用户在 Output 看到具体工具调用结果（成功/失败 + 原因）
                    String toolName = call.toolName();
                    String reason = call.reason() != null ? call.reason() : "（无 reason）";
                    if (outcome.success()) {
                        debug("工具调用 [" + toolName + "] 成功（" + newUsed + "/" + budget + "）："
                                + reason);
                    } else {
                        debug("工具调用 [" + toolName + "] 失败（" + newUsed + "/" + budget + "）："
                                + outcome.error() + "（reason=" + reason + "）");
                    }
                    dispatchDump.append("  [").append(i + 1).append("] ").append(toolName)
                            .append(outcome.success() ? "：成功" : "：失败")
                            .append("  callId=").append(callId)
                            .append("  used=").append(newUsed).append("/").append(budget)
                            .append("  reason=").append(reason).append('\n');
                    if (!outcome.success()) {
                        dispatchDump.append("      error=").append(outcome.error()).append('\n');
                    }
                    String frag = outcome.userPromptFragment() == null ? "" : outcome.userPromptFragment();
                    dispatchDump.append("      回填 user 片段（").append(frag.length()).append(" 字符）: ")
                            .append(abbreviate(frag, 300)).append('\n');
                    userReply.append(outcome.userPromptFragment());
                } else {
                    // 预算耗尽：构造一条"rejected"占位结果回填到 user 段。
                    debug("工具调用 [" + call.toolName() + "] 被拒：预算已耗尽（" + budget + "/" + budget + "）");
                    dispatchDump.append("  [").append(i + 1).append("] ").append(call.toolName())
                            .append("：被拒（预算已耗尽，0 / ").append(budget).append("）\n");
                    userReply.append("[工具被拒] ").append(call.toolName())
                            .append(": 预算已耗尽（剩余 0 / " + budget + "），该调用被服务端拒绝。\n");
                }
            }
            if (usedBudget.get() >= budget) {
                // 走到这里说明本轮把预算正好用完：附加一条终止信号，让模型绝对收尾。
                userReply.append(promptBuilder.buildBudgetExhaustedUserPrompt(usedBudget.get()));
                dispatchDump.append("--- 预算已耗尽：附加终止信号到下一条 user 消息 ---");
            }
            debug(dispatchDump.toString());
            messages.add(new AiClient.ChatMessage("user", userReply.toString()));
        }
        // 达到 MAX_LOOPS 上限仍未收尾：返回当前 lastAnalysis（可能为空时给占位），
        // 防止循环卡死。
        debug("工具循环达到 MAX_LOOPS=" + MAX_LOOPS + " 仍未收尾，强制收尾");
        debug("达到 MAX_LOOPS=" + MAX_LOOPS + " 仍未收尾，强制 wrap-up（已用 "
                + usedBudget.get() + "/" + budget + " 次工具预算）");
        String finalAnalysis = lastAnalysis.isEmpty()
                ? "（模型在 " + MAX_LOOPS + " 轮工具循环内未给出最终结论，已强制收尾；最近一次 raw 输出：" + truncate(lastRaw, 200) + "）"
                : lastAnalysis;
        return new Outcome(finalAnalysis, lastRaw, true);
    }

    /**
     * 把工具调用路由到对应的 {@link Tool} 实现。工具未注册时返回"未注册"失败结果——
     * 而不是抛异常，让循环继续（模型看到后会调整行为）。
     */
    private ToolOutcome dispatchTool(ToolCall call) {
        Tool tool = tools.get(call.toolName());
        if (tool == null) {
            String err = "未注册的工具：" + call.toolName()
                    + "（已注册：" + tools.keySet() + "）";
            return ToolOutcome.failure(err, "[工具被拒] " + call.toolName() + "：" + err);
        }
        try {
            return tool.execute(call);
        } catch (RuntimeException e) {
            // Tool 实现违反"不抛异常"契约：兜底成失败结果，但记录堆栈供排查。
            debug("工具 " + call.toolName() + " 抛异常 " + e.getClass().getSimpleName()
                    + "：" + e.getMessage());
            return ToolOutcome.failure(
                    "工具执行抛出 " + e.getClass().getSimpleName() + "：" + e.getMessage(),
                    "[工具异常] " + call.toolName() + "：" + e.getMessage());
        }
    }

    /**
     * 发起一次 AI 调用，并在执行前/后做取消检查。
     */
    private String callModel(BooleanSupplier cancelled, List<AiClient.ChatMessage> messages,
                             String systemPrompt) throws AiException {
        // 与 TrafficAnalyzer 同样的"先 attachCall 再检查取消"模式：避免 cancel() 落到
        // activeCall 还没注册的窗口里。
        List<AiClient.ChatMessage> snapshot = new ArrayList<>(messages);
        snapshot.add(0, new AiClient.ChatMessage("system", systemPrompt));
        if (cancelled.getAsBoolean()) {
            throw AiException.cancelled();
        }
        CancellableAiCall call = aiClient.completeJsonAsyncWithFallback(snapshot);
        if (cancelled.getAsBoolean()) {
            call.cancel();
            throw AiException.cancelled();
        }
        return call.await();
    }

    /**
     * 单次模型 raw 输出在 DEBUG 日志里的最大字符数。
     *
     * <p>模型一次输出是单个 JSON 对象（analysis 草稿 + tool_calls + risk + findings），
     * 正常 ≤ 1～2K；这里给 30000 的上限纯粹是兜底防"模型跑飞输出超长文本"时刷爆日志——
     * 默认尽量完整，调试时一眼能看清"模型到底回了什么 JSON"。</p>
     */
    private static final int RAW_DEBUG_CHARS = 30_000;

    private static String truncate(String s, int maxChars) {
        if (s == null) {
            return "";
        }
        if (s.length() <= maxChars) {
            return s;
        }
        return s.substring(0, maxChars) + "...（已截断）";
    }

    /**
     * 把字符串截到 {@code max} 字符并附"..."——用于 DEBUG 段落里的"摘要"展示
     * （analysis / tool fragment 完整内容太长时给个前 200/300 字符的预览）。
     */
    private static String abbreviate(String s, int max) {
        if (s == null) {
            return "（null）";
        }
        if (s.length() <= max) {
            return s;
        }
        return s.substring(0, max) + "...";
    }

    /**
     * DEBUG 总开关：与 {@code TrafficAnalyzer} 的 {@code -Dauditai.debug.prompt} 对齐，
     * 使阶段 2 工具循环的逐轮细节与阶段 1 的 prompt 日志同时出现；保留旧开关
     * {@code auditai.debug.tool} 兼容（未注入 debugLogger 的独立用法仍可用）。
     */
    private static boolean debugEnabled() {
        return Boolean.getBoolean("auditai.debug.prompt")
                || Boolean.getBoolean("auditai.debug.tool");
    }

    private void debug(String message) {
        if (debugLogger != null) {
            // 生产路径：由 TrafficAnalyzer.debug 统一加 "AuditAI [DEBUG] " 前缀并做开关判断。
            debugLogger.accept(message);
        } else if (api != null && debugEnabled()) {
            api.logging().logToOutput("AuditAI [DEBUG] " + message);
        }
    }

    /**
     * 当前已用预算（供 UI 实时展示"已用 N/3"）。
     */
    public int usedBudget() {
        return usedBudget.get();
    }

    /**
     * 本次分析实际发起的工具调用轨迹（成功 / 失败都包含）。
     */
    public List<ToolTrace> trace() {
        return List.copyOf(trace);
    }

    /**
     * 单条工具调用轨迹：调用 id + 模型提交的调用 + 工具返回的结果。
     */
    public record ToolTrace(String callId, ToolCall call, ToolOutcome outcome) {
    }

    /**
     * 编排结果：分析文本 + 最后一轮 AI 原始响应 + 是否因 {@link #MAX_LOOPS} 强制收尾。
     */
    public record Outcome(String analysis, String lastRaw, boolean forcedWrapUp) {
    }
}
