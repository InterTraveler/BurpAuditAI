package com.auditai.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.auditai.burp.http.AnalysisResult;
import com.auditai.burp.http.AnalysisTask;
import com.auditai.burp.http.FindingStore;
import com.auditai.burp.http.TrafficAnalyzer;
import com.auditai.burp.ai.AiException;
import com.auditai.burp.ai.PromptBuilder;
import com.auditai.burp.passive.PassiveAnalysisErrorBus;
import com.auditai.burp.passive.PassiveAnalysisErrorClassifier;

import javax.swing.BorderFactory;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.border.TitledBorder;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.io.Serial;
import java.util.function.Consumer;

/**
 * 分析页中的<b>单个报文页签</b>（对应一次“Send to AuditAI”或一次“新建报文”）。
 *
 * <p>布局与配色尽量贴近 Burp 的 Repeater：</p>
 * <ul>
 *   <li><b>Analyze / Cancel</b> 两个按钮位于<b>左侧</b>（请求编辑区上方，左对齐），
 *       Analyze 为<b>橙色</b>（白字、无边框）、Cancel 为<b>白色</b>（深灰字、细灰边框），
 *       圆角小按钮，与 Repeater 的 Send / Cancel 风格一致；</li>
 *   <li>编辑区标题使用英文 <b>Request / Response</b>，结果区标题为 <b>Result</b>；</li>
 *   <li>请求/响应编辑器为 Burp 原生组件，与 Repeater/Proxy 外观一致。</li>
 * </ul>
 *
 * <p>取消逻辑：Analyze 提交后本页签持有该任务的 {@link AnalysisTask} 句柄，
 * 点 Cancel 只中断<b>本页签</b>正在进行的分析（排队中直接放弃、执行中中断 HTTP 请求），
 * 不影响其他页签。</p>
 */
public final class MessageTab extends JPanel implements LocaleAware {

    @Serial
    private static final long serialVersionUID = 1L;

    /** Burp 风格的橙色（对应 Repeater Send 按钮的橙色）。 */
    private static final Color BURP_ORANGE = new Color(255, 102, 0);

    /** Analyze 按钮（橙色白字，悬停变深橙；外观由 Burp 主题渲染，与 Repeater Send 一致）。 */
    private final RoundedButton analyzeButton =
            new RoundedButton(I18n.get().t("ui.messageTab.analyze"), BURP_ORANGE, new Color(230, 92, 0), Color.WHITE);

    /** Cancel 按钮（白底深灰字，悬停变浅灰；外观由 Burp 主题渲染，与 Repeater Cancel 一致）。 */
    private final RoundedButton cancelButton =
            new RoundedButton(I18n.get().t("ui.messageTab.cancel"), Color.WHITE, new Color(235, 235, 235), new Color(80, 80, 80));

    /** Burp API 门面：用于将"读取编辑器/写入问题库"等内部异常上报到 Extender Output。 */
    private final MontoyaApi api;

    /** 分析编排器：负责异步执行 AI 分析。 */
    private final TrafficAnalyzer analyzer;

    /** 全局问题库：分析完成后把结构化 finding 写入这里（为 null 时跳过）。 */
    private final FindingStore findingStore;

    /**
     * 分析完成回调：在 findingStore.addFindings 之后触发，携带原始 request/response 字节，
     * 供"历史"页签等其它组件消费（多目标回调，避免 MessageTab 知道所有 consumer）。
     */
    private final AnalysisResultHook onAnalysisCompleted;

    /** Burp 原生请求编辑器（可编辑，支持粘贴原始报文）。 */
    private final HttpRequestEditor requestEditor;

    /** Burp 原生响应编辑器（可编辑，支持粘贴原始报文）。 */
    private final HttpResponseEditor responseEditor;

    /** 本页签的分析结果展示区（只读）。 */
    private final JTextArea resultArea;

    /** 本页签当前进行的分析任务（无任务时为 null）。仅 EDT 内读写。 */
    private AnalysisTask currentTask;

    /**
     * 分析代次：每次 {@link #startAnalysis()} / {@link #cancelAnalysis()} / {@link #close()}
     * 自增；回调携带发起时的代次快照，仅当与当前代次一致才继续（更新 UI 或落库）
     * ——防止"旧任务回调晚到"覆盖新任务状态（快速 Analyze → Cancel → Analyze 场景）。
     *
     * <p><b>volatile</b>：落库路径在分析线程上读它做代次校验（见 {@link #persistResult}），
     * 而写发生在 EDT，需要可见性保证。</p>
     */
    private volatile long analysisToken;

    /**
     * 本页签的 I18n 语言切换监听器。
     *
     * <p>页签是短生命周期组件：I18n 监听器被全局强引用持有，页签关闭时若未注销，
     * 本页签连同其 Burp 原生报文编辑器会被常驻引用（内存泄漏）。因此把监听器存为字段，
     * 在 {@link #close()} 里调用 {@link I18n#off} 注销。</p>
     */
    private final Consumer<PromptBuilder.Lang> i18nListener = lang -> refreshI18n();

    /**
     * 分析完成回调：与 {@code PassiveAnalyzer.AnalysisResultHandler} 签名一致，
     * 方便装配阶段把手动 + 被动两条链路用同一个 hook 表达式统一处理。
     */
    public interface AnalysisResultHook {
        /**
         * @param result         本次分析结果。
         * @param requestBytes   本次分析使用的请求字节（可为 null）。
         * @param responseBytes  本次分析使用的响应字节（可为 null）。
         */
        void onCompleted(AnalysisResult result, byte[] requestBytes, byte[] responseBytes);
    }

    /**
     * @param api                 Burp API 门面（创建原生编辑器）。
     * @param analyzer            分析编排器。
     * @param findingStore        全局问题库；为 null 时不写入 finding（历史用法兼容）。
     * @param tabNumber           页签编号（1、2、3…，保留参数以便将来在标题/日志中使用）。
     * @param onAnalysisCompleted 分析完成回调；可为 null。回调在 findingStore.addFindings
     *                            之后触发，携带原始 request/response 字节。
     */
    public MessageTab(MontoyaApi api, TrafficAnalyzer analyzer, FindingStore findingStore,
                      int tabNumber, AnalysisResultHook onAnalysisCompleted) {
        super(new BorderLayout());
        this.api = api;
        this.analyzer = analyzer;

        // I18n:注册语言切换监听器;页签关闭时由 close() 注销(防泄漏)。
        I18n.get().onChange(i18nListener);
        this.findingStore = findingStore;
        this.onAnalysisCompleted = onAnalysisCompleted == null
                ? (result, req, resp) -> { } : onAnalysisCompleted;
        this.requestEditor = api.userInterface().createHttpRequestEditor();
        this.responseEditor = api.userInterface().createHttpResponseEditor();

        // —— 按钮：外观交给 Burp 主题渲染（与 Repeater 的 Send/Cancel 完全一致），这里只统一字体 ——
        styleButton(analyzeButton);
        styleButton(cancelButton);
        analyzeButton.addActionListener(e -> startAnalysis());
        cancelButton.addActionListener(e -> cancelAnalysis());
        cancelButton.setEnabled(false); // 初始无任务，Cancel 不可用

        // —— 顶部：按钮栏（位于 Request/Response 两个标题框之外、整个分栏上方，与 Repeater 一致，
        //    保证两个编辑器的顶部对齐，不被按钮挤下去） ——
        JPanel buttonBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        // 在按钮栏与上方提示/下方编辑器之间各增加 1px 间距。
        buttonBar.setBorder(BorderFactory.createEmptyBorder(1, 0, 1, 0));
        buttonBar.add(analyzeButton);
        buttonBar.add(cancelButton);
        add(buttonBar, BorderLayout.NORTH);

        // —— 中部：Request | Response（左右分栏，顶部对齐） ——
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        Font titleFont = api.userInterface().currentDisplayFont();
        if (titleFont != null) {
            titleFont = titleFont.deriveFont(Font.BOLD);
        }
        split.setLeftComponent(titled(requestEditor.uiComponent(), I18n.get().t("ui.common.request"), titleFont));
        split.setRightComponent(titled(responseEditor.uiComponent(), I18n.get().t("ui.common.response"), titleFont));
        split.setResizeWeight(0.5);
        add(split, BorderLayout.CENTER);

        // —— 底部：本页签的分析结果 ——
        resultArea = new JTextArea(8, 80);
        resultArea.setEditable(false);
        resultArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        add(titled(new JScrollPane(resultArea), I18n.get().t("ui.common.result"), titleFont), BorderLayout.SOUTH);
    }

    /**
     * 用一条来自其他模块（上下文菜单）的报文填充本页签。应在 EDT 调用。
     *
     * <p><b>响应判空策略：</b>不依赖 {@link HttpRequestResponse#hasResponse()}，
     * 因为 Montoya 2026.7 的 {@code hasResponse()} 只判断 response 字段非 null，
     * 而空响应对象会让它返回 true，结果编辑器显示"空白但有框架"的视觉歧义。
     * 这里直接看 {@code response} 是否为 null：null 时把响应编辑器清空到 "No response"
     * 占位符；非 null 时正常显示。</p>
     *
     * @param message 请求/响应快照；response 字段为 null 表示"没有响应"。
     */
    public void setMessage(HttpRequestResponse message) {
        requestEditor.setRequest(message.request());
        HttpResponse response = message.response();
        // 真正没响应：让 Montoya 显示 No response 占位符
        responseEditor.setResponse(response);
    }

    /** 关闭页签前调用：中断仍在进行的分析任务 + 注销 I18n 监听器，避免后台任务 / 全局监听器继续持有本页签。 */
    public void close() {
        // 递增代次：与 cancelAnalysis 一致——让"已在飞行中、结果马上回调"的任务失效，
        // 否则页签关闭后它仍会把结果写进问题库 / 历史库（代次校验在 persistResult 里）。
        analysisToken++;
        if (currentTask != null) {
            currentTask.cancel();
            currentTask = null;
        }
        I18n.get().off(i18nListener);
    }

    /** Analyze 按钮动作：读取本页签编辑器内容 → 提交异步分析。 */
    private void startAnalysis() {
        HttpRequest request = requestEditor.getRequest();
        // 空编辑器返回空请求对象（toByteArray 长度为 0），视为未填写
        if (request == null || request.toByteArray().length() == 0) {
            resultArea.setText(I18n.get().t("ui.messageTab.empty"));
            // 空编辑器不发分析，但要确保按钮态可点——上次分析若还在跑、按钮是 disabled，
            // 早退前重置回可点状态，避免"按了没反应"的错觉。
            resetButtonState();
            return;
        }
        HttpResponse response = responseEditor.getResponse();
        // 空响应编辑器视为“无响应”（只分析请求）
        HttpResponse finalResponse = (response == null || response.toByteArray().length() == 0) ? null : response;

        resultArea.setText(I18n.get().t("ui.messageTab.analyzing"));
        // 每次分析携带本页签自己的回调：结果只回到本页签，多个页签互不串扰；
        // 句柄由本页签持有，Cancel 只取消本页签的任务。
        // token 快照：后续若用户发起新分析，旧回调会被 token 校验拦下。
        final long token = ++analysisToken;
        // 编辑器是 Swing 组件，只能在 EDT 上读——所以这里（EDT）先把原始字节取出来，
        // 交给分析线程去落库。落库（gzip + SHA-256 + 原子写盘 + 索引落盘）绝不能在 EDT 上做，
        // 否则大 body 时会直接卡住界面。
        final byte[] requestBytes = safeReadRequest();
        final byte[] responseBytes = safeReadResponse();
        // 回调在分析线程触发（TrafficAnalyzer 的 try 块内、WorkflowLogger 已绑定到该线程）：
        // 先落库（sink 内部走 WorkflowLogger.current()，此时取到的正是本次分析的 logger，
        // 不再需要把 logger 引用借到 EDT 的 ThreadLocal 上），再切 EDT 更新界面。
        currentTask = analyzer.analyzeAsync(request, finalResponse, result -> {
            persistResult(result, token, requestBytes, responseBytes);
            showResult(result, token);
        });
        analyzeButton.setEnabled(false);
        cancelButton.setEnabled(true);
    }

    /**
     * 把一次分析结果落库（问题库 + 历史库 + audit-trail），<b>在分析线程执行</b>。
     *
     * <p>为什么放在分析线程而不是 EDT：{@code AnalysisResultSink} 内部要 gzip 压缩、
     * 算 SHA-256、写临时文件 + 原子 move，还会重写整份索引 JSON——历史上这些都在
     * {@code SwingUtilities.invokeLater} 里跑，等于在 EDT 上做阻塞 IO（大 body 时界面卡死）。
     * 被动分析路径本来就在分析线程落库，本路径也按此设计。</p>
     *
     * <p>代次校验与过滤：过期结果（用户已发起新分析 / 取消 / 关闭页签）和失败结果不落库，
     * 语义与改动前保持一致。</p>
     */
    private void persistResult(AnalysisResult result, long token,
                               byte[] requestBytes, byte[] responseBytes) {
        if (result.getError() != null || token != analysisToken) {
            return;
        }
        try {
            onAnalysisCompleted.onCompleted(result, requestBytes, responseBytes);
        } catch (RuntimeException ex) {
            // hook 失败不应影响分析结果展示，但要留诊断便于排错。
            logError("分析完成回调失败：" + ex.getMessage(), ex);
        }
    }

    /** 把按钮重置为"可点 Analyze、不可点 Cancel"——startAnalysis 早退与 cancelAnalysis 共用。 */
    private void resetButtonState() {
        analyzeButton.setEnabled(true);
        cancelButton.setEnabled(false);
    }

    /** Cancel 按钮动作：取消本页签正在进行的分析。 */
    private void cancelAnalysis() {
        if (currentTask != null) {
            currentTask.cancel();
            // 递增代次：使尚未执行的旧回调失效，防止其晚到后重置新任务状态
            analysisToken++;
            // 立即恢复按钮状态：排队中被取消的任务不会回调结果，不能等回调恢复按钮
            currentTask = null;
            analyzeButton.setEnabled(true);
            cancelButton.setEnabled(false);
            // 提示文案统一由 showResult 处理（识别 AiException("分析已取消") 显示对应文案）。
        }
    }

    /**
     * 展示分析结果（由 TrafficAnalyzer 在分析线程回调，内部切回 EDT）。
     *
     * <p>本方法只负责界面：落库已由 {@link #persistResult} 在分析线程完成，
     * 这里不再出现任何磁盘 IO。</p>
     */
    private void showResult(AnalysisResult result, long token) {
        SwingUtilities.invokeLater(() -> {
            // 过期回调（期间用户已发起新分析或取消）：直接丢弃，避免污染新任务状态
            if (token != analysisToken) {
                return;
            }
            StringBuilder sb = new StringBuilder();
            if (result.getError() != null) {
                // 用统一常量判定"取消"——避免在 UI 里硬编码中英文字面比较：
                // CancellableAiCall.awaitOnce / ToolLoopOrchestrator.run / TrafficAnalyzer.executeAndAwait
                // 在用户点 Cancel 时统一抛 AiException.CANCELLED_MESSAGE，UI 拿到的 error 字符串
                // 就是这个常量；改文案只需改 AiException 一处。
                if (AiException.isCancelledMessage(result.getError())) {
                    // 被用户 Cancel：显示为"已取消"而不是"失败"
                    sb.append(I18n.get().t("ui.messageTab.cancelled", result.getDurationMillis()));
                } else {
                    // 失败帧本地化 + 原始错误保留;再按错误类别追加一句本地化引导
                    sb.append(I18n.get().t("ui.messageTab.failed", result.getDurationMillis(), result.getError()));
                    String guide = errorGuidance(result.getError());
                    if (!guide.isEmpty()) {
                        sb.append('\n').append(guide);
                    }
                }
            } else {
                sb.append(I18n.get().t("ui.messageTab.complete", result.getDurationMillis(), result.getSummary()));
            }
            resultArea.setText(sb.toString());
            resultArea.setCaretPosition(0);

            // 任务结束：恢复按钮状态（Cancel 按钮已提前恢复时此处幂等）
            currentTask = null;
            analyzeButton.setEnabled(true);
            cancelButton.setEnabled(false);
        });
    }

    /**
     * 安全读取当前 request 编辑器的字节：editor.getRequest() 可能为 null，
     * toByteArray() 在空编辑器时长度 0，try-catch 兜底所有异常。
     */
    private byte[] safeReadRequest() {
        try {
            HttpRequest request = requestEditor.getRequest();
            if (request == null) {
                return null;
            }
            return request.toByteArray().getBytes();
        } catch (RuntimeException ex) {
            logError("读取 request 编辑器失败：" + ex.getMessage(), ex);
            return null;
        }
    }

    /**
     * 安全读取当前 response 编辑器的字节：editor.getResponse() 为 null 表示
     * "无响应"，返回 null 让 UI 显示 "No response" 占位符。
     */
    private byte[] safeReadResponse() {
        try {
            HttpResponse response = responseEditor.getResponse();
            if (response == null) {
                return null;
            }
            int len = response.toByteArray().length();
            if (len == 0) {
                return null;
            }
            return response.toByteArray().getBytes();
        } catch (RuntimeException ex) {
            logError("读取 response 编辑器失败：" + ex.getMessage(), ex);
            return null;
        }
    }

    /** 把诊断信息写入 Burp Extender；api 为 null 时（仅测试场景）降级到 stderr。 */
    private void logError(String message, Throwable t) {
        if (api != null) {
            api.logging().logToError("AuditAI " + message, t);
            return;
        }
        if (t != null) {
            t.printStackTrace(System.err);
        }
    }

    /**
     * 按钮字体与 Repeater 一致：取当前 L&F（Burp 主题）配置的 Button.font。
     * 其余外观（形状、圆角、悬停、禁用）完全由主题渲染，与 Repeater 按钮同源。
     */
    private static void styleButton(RoundedButton button) {
        Font uiFont = UIManager.getFont("Button.font");
        button.setFont(uiFont != null ? uiFont : button.getFont());
        // 增加上下内边距，让 Analyze/Cancel 高度比默认按钮略大，接近 Repeater 的操作按钮。
        button.setMargin(new java.awt.Insets(5, 16, 5, 16));
    }

    /** 给组件包一层带标题边框的面板；标题字体由 Burp 当前显示字体派生，以贴近 Repeater。 */
    private static JPanel titled(Component component, String title, Font titleFont) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder(null, title, TitledBorder.DEFAULT_JUSTIFICATION,
                TitledBorder.DEFAULT_POSITION, titleFont, null));
        panel.add(component, BorderLayout.CENTER);
        return panel;
    }
    /**
     * 失败分析按错误类别返回本地化引导句（展示层包裹：底层异常原文可能仍是中文，
     * 但英文用户能从这里知道"该去查什么"）。无法归类 / 异常时返回空串。
     */
    private static String errorGuidance(String error) {
        try {
            PassiveAnalysisErrorBus.ErrorKind kind = PassiveAnalysisErrorClassifier.classifyByMessage(error);
            String key = switch (kind) {
                case CONFIG -> "ui.error.guide.config";
                case NETWORK -> "ui.error.guide.network";
                case REMOTE -> "ui.error.guide.remote";
            };
            return I18n.get().t(key);
        } catch (RuntimeException ignored) {
            return "";
        }
    }

    @Override
    public void refreshI18n() {
        analyzeButton.setText(I18n.get().t("ui.messageTab.analyze"));
        cancelButton.setText(I18n.get().t("ui.messageTab.cancel"));
        // Result 标题在构造期创建,无需刷新;请求/响应标题也是。
    }

}
