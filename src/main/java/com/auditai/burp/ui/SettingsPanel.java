package com.auditai.burp.ui;

import com.auditai.burp.ai.AiException;
import com.auditai.burp.ai.CancellableAiCall;
import com.auditai.burp.ai.OpenAiCompatibleClient;
import com.auditai.burp.ai.PromptBuilder;
import com.auditai.burp.config.AiConfig;
import com.auditai.burp.config.Settings;
import com.auditai.burp.config.SettingsStore;
import com.auditai.burp.passive.PassiveAnalysisErrorBus;
import com.auditai.burp.passive.UrlRegexFilter;

import burp.api.montoya.MontoyaApi;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JLayeredPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.UIManager;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionListener;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.text.Collator;
import java.util.Comparator;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * "设置"页签：垂直排布两个功能区。
 *
 * <ul>
 *   <li><b>AI 服务</b>：支持保存多份 AI 服务配置（DeepSeek / Ollama / 自定义…），
 *       通过顶部下拉列表切换。下拉列表的最后一项是固定的占位项
 *       {@code addNewLabel}——选中它会立即新增一条全空的配置并切过去。
 *       当前激活项的字段统一使用 OpenAI Chat Completions 兼容协议，包含
 *       Base URL、可选 API Key、模型名、超时 / 最大 Token 两个公共参数，支持
 *       "测试连接"。底部按钮按顺序：测试连接 / 删除设置——表单字段随动：
 *       任意字段变化后 {@value #SERVICE_DEBOUNCE_MS}ms 自动保存到 settings + 磁盘，
 *       校验失败（名称空 / 重名 / 等于占位项）弹 Toast 提示并保留旧值。</li>
 *   <li><b>提示词</b>：编辑自定义系统提示词（留空 = 使用内置默认），可"恢复默认"。
 *       提示词是全局设置，不随 AI 服务配置切换。</li>
 * </ul>
 *
 * <p>自定义分析技能已迁出到独立 SKILLS 页签（见 {@code com.auditai.burp.skills}）。</p>
 *
 * <p>线程约定：测试连接是慢操作，使用 {@link SwingWorker} 在后台线程执行，
 * 避免阻塞 Swing 事件线程（EDT）。表单防抖（{@link DebouncedAction}）也仅在 EDT 上调度。</p>
 *
 * <p>反馈约定：测试结果 / 自动保存校验失败统一用右下角非模态 Toast 提示（{@link Toast}），
 * 约 3 秒后自动淡出、不占布局空间，避免行内状态标签的 HTML 渲染与按钮布局偏移问题。</p>
 *
 * <p>布局约定：GridBagLayout 每行都新建独立的 {@link GridBagConstraints} 实例
 * （见 {@link #addRow}），避免共享可变约束导致行位置塌陷、文字互相覆盖。</p>
 *
 * <p>数据流约定：本类持有 {@link Settings} 引用；表单字段变化经防抖调用
 * {@link #tryApplyFormToSettings} 整体替换 activeConfig——避免多字段非原子写
 * 引发"新 baseUrl + 旧 model"的撕裂读。切换 / 增删也走同一入口，UI 表单是
 * 激活项的视图层。</p>
 */
public final class SettingsPanel extends JPanel implements LocaleAware {

    private static final long serialVersionUID = 1L;

    /**
     * 下拉列表末位的占位项文字：选中后会立即在列表里新增一条全空配置。
     *
     * <p>使用尖括号包裹让它的"非真实配置"语义一眼可辨；用户也不太可能给自己的
     * 配置起这种名字（且 {@link #tryApplyFormToSettings} 里也会拒绝以这个名字保存）。</p>
     */
    private String addNewLabel = I18n.get().t("ui.settings.addNew");

    /** 完整设置（多份 AI 服务配置 + 当前激活 + 全局提示词）——所有 UI 写操作都通过它生效。 */
    private final Settings settings;

    private final SettingsStore settingsStore;
    private final PromptBuilder promptBuilder;

    /**
     * Montoya API 门面：用于把"hook / 监听器异常"等诊断写入 Extender Output，
     * 而不是 stderr。可为 null（仅测试 / 预览场景降级到 stderr）——生产路径
     * {@code MainTab} 必须传非 null。
     */
    private final MontoyaApi api;

    /** 非模态提示：右下角浮出、自动消失，用于测试/校验失败等轻量反馈。 */
    private final Toast toast;

    // —— AI 服务区：顶部下拉 + 名称 ——
    private final JComboBox<String> serviceDropdown;

    /**
     * 下拉列表的"用户操作"监听器（实例字段，确保 add/remove 是同一个对象）：
     * {@link #refreshDropdown} 在批量改 items 之前摘掉它、改完再装回去，
     * 否则每条 {@code addItem} / {@code setSelectedItem} 都会触发回调、
     * 递归调进 {@link #onDropdownChanged} 把列表状态搅乱。
     *
     * <p>注意：必须存成字段，不能写成 {@code () -> onDropdownChanged()} 形式——
     * 那样每次 addActionListener 时都会产生新的 lambda 实例，
     * {@code removeActionListener} 就摘不掉了（这是之前那个"保存后下拉只剩第一项"
     * BUG 的根因）。</p>
     */
    private final ActionListener dropdownChangeListener = e -> onDropdownChanged();

    /**
     * 标记当前是否处于 {@link #refreshDropdown} 的"批量改 items"期间：
     * 进入时置 true、退出时（finally）置 false。即便 listener 摘/装没起到作用
     * （例如 Swing 在某些版本上 listener 摘除时机不一致），这个标志位也能
     * 拦住 {@link #onDropdownChanged} 的递归调用，避免 addItem /
     * setSelectedItem 期间回调被反复触发。
     */
    private boolean refreshingDropdown;

    /**
     * 名称字段：独立占第 1 行（"名称:" 标签与其他行的标签同列对齐），
     * 编辑后经 {@link #SERVICE_DEBOUNCE_MS}ms 防抖自动保存到 settings + 磁盘。
     */
    private final JTextField nameField = new JTextField(20);

    // —— AI 服务区：当前激活配置的连接参数 ——
    private final JTextField baseUrlField = new JTextField(32);
    private final JPasswordField apiKeyField = new JPasswordField(32);
    private final JTextField modelField = new JTextField(24);

    // —— AI 服务区：公共参数与底部按钮 ——
    private final JSpinner timeoutField = new JSpinner(new SpinnerNumberModel(30, 5, 300, 5));
    private final JSpinner maxTokensField = new JSpinner(new SpinnerNumberModel(AiConfig.DEFAULT_MAX_TOKENS, 128, 16384, 256));
    private final JButton testButton = RoundedButton.standard(I18n.button("ui.common.test"));
    private final JButton deleteServiceButton = RoundedButton.standard(I18n.button("ui.common.deleteSettings"));

    /**
     * 当前"测试连接"对应的可取消句柄：在 {@link #testConnection} 起点持有，
     * 由 {@link #onDropdownChanged} / {@link #close} 调 {@link #cancelInflightTest}
     * 中断，让下拉切换或面板卸载时旧 HTTP 请求能立刻停止而不再挂起到超时。
     *
     * <p>{@code volatile} 与本类其他回调字段保持一致（见 {@link #passiveAnalysisSavedHook}）。</p>
     */
    private volatile CancellableAiCall currentTestCall;

    /**
     * 测试连接代次：{@link #testConnection} 起点递增 1，{@link #cancelInflightTest}
     * 也会递增。{@link SwingWorker#done} 在闭包里捕获本次测试开始时的代次，
     * 回调触发时若不匹配，说明这次结果属于已被中断/替换的旧测试——直接 return
     * 不动 UI。
     */
    private long testGeneration;

    // —— 提示词区 ——
    private final JTextArea promptArea = new JTextArea(10, 70);
    private final JButton savePromptButton = RoundedButton.standard(I18n.button("ui.settings.savePrompt"));
    private final JButton resetPromptButton = RoundedButton.standard(I18n.button("ui.common.reset"));

    /**
     * 提示词框当前内容是否为"内置默认提示词的参考展示"（而非用户草稿）。
     *
     * <p>无自定义提示词时，框内展示当前语言的默认提示词供参考/修改。切语言时若框内
     * 仍是上一语言的"参考默认"（用户没动过），应跟随语言重填；但若用户已输入未保存的
     * 草稿，切换语言绝不能把它覆盖掉。用户一旦编辑（DocumentListener）或保存（savePrompt）
     * 即置 false；resetPrompt 与 refreshI18n 重填默认后置 true。</p>
     */
    private boolean promptAreaShowsDefault;

    // —— 被动分析区：开关 + URL 过滤正则（实时生效，无保存按钮） ——
    /**
     * 是否开启被动流量分析：开启后 AuditAI 自动分析 Proxy 转发到本进程的请求/响应。
     * 默认关闭；勾选 / 取消立即通过 {@link #passiveAnalysisSavedHook} 推给 handler。
     */
    private final JCheckBox passiveEnabledCheck = I18n.checkBox("ui.settings.passiveEnable");

    /**
     * URL 过滤正则：仅分析 URL（含 query）匹配该正则的报文；留空匹配全部。
     * 非法正则由 {@link com.auditai.burp.passive.UrlRegexFilter} 在运行期兜底
     * （回退到匹配全部 + 写日志），不在 UI 层阻断输入。
     * 修改后立即持久化 + 推给 handler，无需手动保存。
     */
    private final JTextField passiveRegexField = new JTextField(30);

    /**
     * URL 过滤正则的实时校验状态行：紧贴 {@link #passiveRegexField} 下方，
     * 用 {@link UrlRegexFilter#validate(String)} 在每次键入时刷新——告诉用户
     * 当前输入是"空 / 合法 / 含伪正则翻译 / 非法"。
     *
     * <p>不走 I18n 自动订阅：状态文案包含动态内容（用户原文 + 展开后的正则），
     * 切语言时只能整体重算一次，不需要逐条订阅。
     * 颜色按状态切换：EMPTY 灰、VALID/VALID_EXPANDED 绿、INVALID 红。</p>
     */
    private final JLabel passiveRegexStatusLabel = new JLabel(" ", JLabel.LEFT);

    /**
     * 被动分析配置变更后的"广播"回调：通常由 {@code AuditAiExtension} 注入，
     * 用来在 UI 改完配置后立刻把最新值推给 {@code PassiveAnalysisHandler}，避免
     * "改了但 Burp 还在用旧值"的撕裂感。
     *
     * <p>不为 null 时在复选框 / 输入框变化时同步触发；为 null 时仅持久化、不广播
     * （单测场景可注入 null）。</p>
     *
     * <p><b>volatile：</b>当前注入与触发都在 EDT 单线程，无需同步；加 volatile
     * 仅为防御未来出现非 EDT 调用方。</p>
     */
    private volatile Runnable passiveAnalysisSavedHook;

    /**
     * 被动分析错误状态变化回调：通常由 {@code MainTab} 注入，<b>在 EDT 上</b>触发，
     * 用于在"设置"页签标题右侧加 / 移感叹号，让用户停留在其他页签时也能感知到
     * 被动分析失败。
     *
     * <p>回调签名为 {@code boolean hasError}：true 时外部应展示感叹号，
     * false 时外部应清除感叹号（恢复原标题）。</p>
     *
     * <p>为 null 时不通知外部（单测场景可注入 null）。</p>
     */
    private volatile java.util.function.Consumer<Boolean> passiveAnalysisErrorChangedHook;

    /**
     * "被动分析"区下方的红字错误提示组件：常态为空（占位空白），错误时填充红字内容。
     *
     * <p>采用 {@link JTextArea} 而非 {@link JLabel}：</p>
     * <ul>
     *   <li><b>不用 HTML</b>：Burp 的某些 LaF / Dark 主题下，{@code JLabel} 的 HTML 渲染
     *       可能直接以纯文本显示出来（带 {@code <html>} 字面量），用户能看到未渲染的标签
     *       字符；{@code JTextArea} 是纯文本组件，输出什么就显示什么，绝无 HTML 解析；</li>
     *   <li><b>自动换行</b>：错误消息可能很长（远端返回 300+ 字符的详细错误体），
     *       {@code JTextArea} 默认开启 {@code lineWrap + wrapStyleWord}，长文本按词换行，
     *       不会撑爆窗口；</li>
     *   <li><b>去边框 + 透明背景</b>：setOpaque(false) + setBorder(null) 让它视觉上像
     *       一个"红字标签"，而不是个文本框。</li>
     * </ul>
     *
     * <p>始终占布局位置（不切换 visible），用 setText 控制内容：常态设为单个空格
     * 保留高度；错误时填充"⚠ 分类：消息"格式。</p>
     */
    private final JTextArea passiveErrorArea = new JTextArea(" ", 1, 0);

    /**
     * 包装红字区域的容器：始终可见，承载红字组件。
     */
    private final JPanel passiveErrorPanel = new JPanel(new BorderLayout());

    /**
     * 缓存错误总线监听器引用：{@link #close} 时需要把同一个引用
     * 传给 {@link PassiveAnalysisErrorBus#removeListener}——若每次用
     * {@code this::onPassiveErrorChanged} 新建方法引用，remove 不会生效，
     * 错误总线会持有已销毁的 UI 对象。
     */
    private final Runnable passiveErrorListener = this::onPassiveErrorChanged;

    /**
     * 被动分析控件的防抖延迟（毫秒）。输入框每次按键都重启定时器，
     * 停止输入 {@value #PASSIVE_DEBOUNCE_MS}ms 后才真正应用——避免把打字过程中的
     * 中间正则态实时推给 handler（中间态可能非法 → 回退 match-all → 把本不该分析的
     * 请求 mark 进去重表），也避免每次按键都写 2 个 Preferences 键 + 打日志。
     */
    private static final int PASSIVE_DEBOUNCE_MS = 300;

    /**
     * AI 服务区表单的防抖延迟（毫秒）。任意字段变化都重启定时器，停止输入
     * {@value #SERVICE_DEBOUNCE_MS}ms 后再整体应用 + 持久化。和被动分析共用同一
     * 个节奏，体感一致；也避开"打一个字就触发一次 Preferences 写 + 一次 replaceActive"
     * 的性能与撕裂读问题。
     */
    private static final int SERVICE_DEBOUNCE_MS = 300;

    /** 被动分析防抖动作：到点统一读取两个控件的当前值并写回 settings + 持久化 + 广播 hook。 */
    private final DebouncedAction passiveDebounce;

    /**
     * AI 服务表单防抖动作：到点统一读取所有控件并走 {@link #tryApplyFormToSettings} 应用 + 持久化。
     * 下拉切换 / 新增前会调用 {@link DebouncedAction#flushIfPending} 强行同步执行，
     * 避免"切走时丢失防抖窗口内的编辑"。
     */
    private final DebouncedAction serviceDebounce;

    /**
     * 生产构造器：注入 {@link MontoyaApi} 让 hook / 监听器异常走 Extender Output。
     *
     * @param api           Montoya API 门面（不可为 null）。
     * @param settings      完整设置对象：所有写操作通过它生效。
     * @param settingsStore 配置持久化仓库。
     */
    public SettingsPanel(MontoyaApi api, Settings settings, SettingsStore settingsStore) {
        super(new BorderLayout());
        // api 可为 null：仅测试场景（无需 api.logging 输出）。生产路径必须传非 null。
        this.api = api;
        this.settings = settings;
        this.settingsStore = settingsStore;
        this.promptBuilder = new PromptBuilder(settings::customPrompt, I18n.get()::current);

        // 下拉列表只放"配置名称 + 末位占位项"——和持久化数据解耦，所有变更都通过 settings 走。
        this.serviceDropdown = new JComboBox<>();

        // 四个功能区垂直排布，整体放入滚动面板（设置项多时也能完整展示）。
        // 顺序：AI 服务 → 被动分析 → 提示词 → 语言（语言放在最末,与 SettingsPanel 内
        // 其它"配置"项区分开,让用户清楚它是"切换 UI 表现"而非"业务配置"）。
        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setAlignmentX(Component.LEFT_ALIGNMENT);
        content.add(Box.createVerticalStrut(8));
        content.add(leftAligned(buildServiceSection()));
        content.add(Box.createVerticalStrut(8));
        content.add(leftAligned(buildPassiveAnalysisSection()));
        content.add(Box.createVerticalStrut(8));
        content.add(leftAligned(buildPromptSection()));
        content.add(Box.createVerticalStrut(8));
        content.add(leftAligned(buildLanguageSection()));

        // 根容器用 JLayeredPane：正文铺满底层，Toast 浮在 POPUP 层右下角。
        // 提示不占布局空间，也就不会把按钮等元素挤动；窗口缩放时 Toast 自行贴回右下角。
        JLayeredPane layered = new JLayeredPane();
        JScrollPane scrollPane = new JScrollPane(content);
        layered.add(scrollPane, JLayeredPane.DEFAULT_LAYER);
        toast = new Toast(layered);
        layered.add(toast, JLayeredPane.POPUP_LAYER);
        layered.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                scrollPane.setBounds(0, 0, layered.getWidth(), layered.getHeight());
            }
        });
        add(layered, BorderLayout.CENTER);
        scrollPane.setBounds(0, 0, 1, 1); // 初始占位，首次缩放时纠正

        // —— 初始化 UI：填充下拉、回填表单 ——
        refreshDropdown();
        populateFormFromActive();
        // 提示词区：有自定义显示自定义，否则显示当前生效的默认提示词（供参考/修改）。
        String currentPrompt = settings.customPrompt();
        boolean hasCustomPrompt = currentPrompt != null && !currentPrompt.isBlank();
        promptArea.setText(hasCustomPrompt ? currentPrompt : promptBuilder.buildDefaultSystemPrompt());
        promptAreaShowsDefault = !hasCustomPrompt;
        promptArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        // 用户编辑(含删除到空)即视为"框内不再是默认参考",防止切语言时覆盖未保存草稿。
        promptArea.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                promptAreaShowsDefault = false;
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                promptAreaShowsDefault = false;
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                promptAreaShowsDefault = false;
            }
        });

        // 被动分析区：先回填、再挂监听器（顺序很关键——挂监听器之前的 setSelected/setText
        // 会触发 ChangeListener / DocumentListener，导致初始化时"无意义的自动保存"）。
        populatePassiveAnalysisFromSettings();
        this.passiveDebounce = new DebouncedAction(PASSIVE_DEBOUNCE_MS, this::applyPassiveAnalysisChange);
        wirePassiveAnalysisListeners();

        // AI 服务区：同理——populateFormFromActive 在更靠前的初始化阶段已调用过，
        // 那里 setText 不会触发未挂载的监听器；这里建好 debounce + 挂表单监听器。
        this.serviceDebounce = new DebouncedAction(SERVICE_DEBOUNCE_MS, this::applyAiServiceChange);
        wireAiServiceListeners();

        // 错误提示：订阅共享错误总线。监听器被错误总线在调用线程同步触发——
        // 错误来源可能是被动分析线程（最常见），也可能是测试连接 EDT；
        // 统一在监听器内部用 SwingUtilities.invokeLater 切到 EDT 后再改 Swing 状态。
        PassiveAnalysisErrorBus.INSTANCE.addListener(passiveErrorListener);
        // 同步一次当前状态：UI 启动时如果上一次会话残留了"持久化的错误快照"（v1 不持久化，
        // 但保留接口以备将来扩展），应立刻展示；目前 getError() 永远返回 cleared()，
        // 同步调用仅占一行无副作用。
        onPassiveErrorChanged();

        // —— 事件绑定 ——
        serviceDropdown.addActionListener(dropdownChangeListener);
        testButton.addActionListener(e -> testConnection());
        deleteServiceButton.addActionListener(e -> deleteCurrentService());
        savePromptButton.addActionListener(e -> savePrompt());
        resetPromptButton.addActionListener(e -> resetPrompt());

        // 注册 I18n 监听:语言切换时刷新所有可见文案。
        I18n.get().onChange(lang -> refreshI18n());
        // 构造末尾主动刷新一次:语言按钮的文本/高亮只在 refreshI18n 里填充,
        // 依赖"首次调用"完成初始化(MainTab 不再向下转发,面板须自行完成初始填充)。
        refreshI18n();
    }

    /** 将纵向 BoxLayout 的子面板强制左对齐，避免默认按中心对齐造成左右偏移。 */
    private static JPanel leftAligned(JPanel panel) {
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        return panel;
    }

    // ========== AI 服务区 ==========

    /**
     * 构建"AI 服务"标题区：
     * <pre>
     *   AI 服务: [DeepSeek ▼]
     *   名称:    [__________]
     *   Base URL / API Key / 模型 / 超时 / 最大 Token
     *   [测试连接]  [删除设置]
     * </pre>
     *
     * <p>下拉列表末尾固定一项 {@code addNewLabel}——选中它即视为"新增"指令，
     * 立刻在列表里追加一条全空配置并切过去。底部按钮只有
     * "测试连接 / 删除设置"——表单字段随动自动保存（见
     * {@link #wireAiServiceListeners} 与 {@link #applyAiServiceChange}）。所有配置
     * 都是用户自己加的，没有"内置项不可删"或"恢复默认"这类例外。</p>
     */
    private JPanel buildServiceSection() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(I18n.titledBorder("ui.settings.section.service"));

        JPanel form = new JPanel(new GridBagLayout());

        // 第 0 行：AI 服务下拉列表（名称字段独立占第 1 行，见下）。
        GridBagConstraints c0 = new GridBagConstraints();
        c0.gridx = 0;
        c0.gridy = 0;
        c0.insets = new Insets(3, 6, 3, 6);
        c0.anchor = GridBagConstraints.WEST;
        form.add(I18n.label("ui.settings.choose"), c0);

        JPanel dropdownCell = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        dropdownCell.add(serviceDropdown);
        GridBagConstraints c1 = new GridBagConstraints();
        c1.gridx = 1;
        c1.gridy = 0;
        c1.insets = new Insets(3, 6, 3, 6);
        c1.anchor = GridBagConstraints.WEST;
        form.add(dropdownCell, c1);

        // 第 1 行：名称（编辑后经 SERVICE_DEBOUNCE_MS 自动保存并出现在下拉列表中）。
        // 标签放第 0 列、输入框放第 1 列，与其他行的"标签-控件"对齐方式完全一致
        // （此前把"名称:" 标签和输入框一起塞进第 1 列，导致它比其他行偏右一格）。
        GridBagConstraints nameL = new GridBagConstraints();
        nameL.gridx = 0;
        nameL.gridy = 1;
        nameL.insets = new Insets(3, 6, 3, 6);
        nameL.anchor = GridBagConstraints.WEST;
        form.add(I18n.label("ui.settings.name"), nameL);

        GridBagConstraints nameC = new GridBagConstraints();
        nameC.gridx = 1;
        nameC.gridy = 1;
        nameC.insets = new Insets(3, 6, 3, 6);
        nameC.anchor = GridBagConstraints.WEST;
        form.add(nameField, nameC);

        addRow(form, 2, "ui.settings.baseUrl", baseUrlField);
        addRow(form, 3, "ui.settings.apiKey", apiKeyField);
        addRow(form, 4, "ui.settings.model", modelField);
        addRow(form, 5, "ui.settings.timeout", timeoutField);
        addRow(form, 6, "ui.settings.maxTokens", maxTokensField);

        // 底部按钮固定顺序：测试连接 / 删除设置。
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        buttons.add(testButton);
        buttons.add(deleteServiceButton);
        GridBagConstraints bc = new GridBagConstraints();
        bc.gridx = 1;
        bc.gridy = 7;
        bc.insets = new Insets(3, 6, 3, 6);
        bc.anchor = GridBagConstraints.WEST;
        form.add(buttons, bc);

        // GridBagLayout 默认会把整个网格在可用空间内居中；外面包一层左对齐 FlowLayout，
        // 让 AI 服务表单整体贴到最左侧，而不是显示在标题框中间。
        JPanel leftWrap = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        leftWrap.add(form);
        panel.add(leftWrap, BorderLayout.CENTER);
        return panel;
    }

    /**
     * GridBagLayout 辅助：添加一行（标签 + 控件）。
     *
     * <p><b>关键约定</b>：每行都新建独立的 {@link GridBagConstraints} 实例并显式传入行号。
     * 实测共享同一个约束对象、在 add 之后修改 gridy 会让多行塌陷到同一位置（文字互相覆盖），
     * 因此这里不做任何跨行复用。</p>
     *
     * <p>标签通过 {@link I18n#label(String)} 创建：内部订阅语言切换事件，
     * 切语言时自动 setText 新文案。调用方传 i18n key 即可，<b>不要</b>传
     * {@code I18n.get().t("...")} 的结果——那样只翻译一次，刷新不到。</p>
     */
    private static void addRow(JPanel panel, int gridy, String labelKey, JComponent field) {
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = gridy;
        c.insets = new Insets(3, 6, 3, 6);
        c.anchor = GridBagConstraints.WEST;
        panel.add(I18n.label(labelKey), c);
        c.gridx = 1;
        panel.add(field, c);
    }

    // ========== 下拉 / 表单同步 ==========

    /**
     * 重新填充下拉列表条目：真实配置按名称自然顺序（{@link #NAME_NATURAL_ORDER}）
     * 排列，最后追加占位项 {@code addNewLabel}；把当前激活项设为选中。
     *
     * <p>设置 selectedItem 前后临时摘掉监听器，避免触发 {@link #onDropdownChanged}
     * 递归回调——特别是在我们刚 addAndSwitchTo 后刷新下拉时。</p>
     */
    private void refreshDropdown() {
        refreshingDropdown = true;
        // 摘/装 同一个 listener 引用（见 dropdownChangeListener 注释）——以前用
        // this::onDropdownChangedStub 想摘的其实是另一个 listener，摘不掉，
        // 导致 addItem 过程中回调被反复触发、把下拉状态搅乱。
        serviceDropdown.removeActionListener(dropdownChangeListener);
        try {
            serviceDropdown.removeAllItems();
            // 按名称自然顺序排序（拼音序 + 数字按数值比较）；占位项固定留在末位。
            // 排序只影响下拉的展示顺序，不改变 settings.configs() 的存储顺序。
            settings.configs().stream()
                    .map(AiConfig::getName)
                    .map(name -> name == null ? "" : name)
                    .sorted(NAME_NATURAL_ORDER)
                    .forEach(serviceDropdown::addItem);
            serviceDropdown.addItem(addNewLabel);
            // 列表为空时 activeName 为 null，setSelectedItem(null) 退回到首项（即占位项）。
            serviceDropdown.setSelectedItem(settings.activeName());
        } finally {
            serviceDropdown.addActionListener(dropdownChangeListener);
            refreshingDropdown = false;
        }
        // 列表为空时禁用"删除设置"——无激活项可删。
        deleteServiceButton.setEnabled(!settings.configs().isEmpty());
    }

    /** 中文拼音序的 {@link Collator}（PRIMARY 强度：忽略大小写，仅按拼音排序）。 */
    private static final Collator NAME_COLLATOR = createNameCollator();

    private static Collator createNameCollator() {
        Collator collator = Collator.getInstance(Locale.CHINA);
        collator.setStrength(Collator.PRIMARY);
        return collator;
    }

    /**
     * AI 服务配置名的自然顺序比较器（仅用于下拉列表的展示排序，
     * 不改变 {@link Settings#configs()} 的存储顺序）：
     * <ul>
     *   <li>文本片段用中文感知的拼音序比较（{@link Collator} + {@link Locale#CHINA}，
     *       PRIMARY 强度，即大小写不敏感）；</li>
     *   <li>连续数字片段按数值比较——"新配置 2" 排在 "新配置 10" 之前，
     *       前导零（"配置 02" vs "配置 2"）视为相同；</li>
     *   <li>同前缀时短字符串排在前面（"配置" &lt; "配置 1"）。</li>
     * </ul>
     *
     * <p>线程约定：{@link Collator} 非线程安全，本比较器只在 Swing EDT 上
     * （{@link #refreshDropdown}）使用，与其余 Swing 组件一致。</p>
     */
    static final Comparator<String> NAME_NATURAL_ORDER = (a, b) -> {
        int i = 0;
        int j = 0;
        while (i < a.length() && j < b.length()) {
            char ca = a.charAt(i);
            char cb = b.charAt(j);
            if (Character.isDigit(ca) && Character.isDigit(cb)) {
                int endA = i;
                while (endA < a.length() && Character.isDigit(a.charAt(endA))) {
                    endA++;
                }
                int endB = j;
                while (endB < b.length() && Character.isDigit(b.charAt(endB))) {
                    endB++;
                }
                int cmp = compareDigitRuns(a, i, endA, b, j, endB);
                if (cmp != 0) {
                    return cmp;
                }
                i = endA;
                j = endB;
            } else {
                int cmp = NAME_COLLATOR.compare(String.valueOf(ca), String.valueOf(cb));
                if (cmp != 0) {
                    return cmp;
                }
                i++;
                j++;
            }
        }
        return Integer.compare(a.length() - i, b.length() - j);
    };

    /**
     * 比较两段连续数字（由 {@code [start, end)} 界定）：去掉前导零后
     * 先比位数（位数少的小），位数相同再按字典序比（同为纯数字时等价于数值比较）。
     */
    private static int compareDigitRuns(String a, int startA, int endA, String b, int startB, int endB) {
        String numA = stripLeadingZeros(a, startA, endA);
        String numB = stripLeadingZeros(b, startB, endB);
        int cmp = Integer.compare(numA.length(), numB.length());
        return cmp != 0 ? cmp : numA.compareTo(numB);
    }

    /** 去掉数字串的前导零（"000" 保留为 "0"）。 */
    private static String stripLeadingZeros(String digits, int start, int end) {
        int i = start;
        while (i < end - 1 && digits.charAt(i) == '0') {
            i++;
        }
        return digits.substring(i, end);
    }

    /**
     * 用当前激活项的字段回填表单（下拉切换 / 增删 / 初始化时调用）。
     *
     * <p>列表为空（{@link Settings#activeConfig()} 返回 null）时清空所有字段，
     * 让用户看到一份空白表单，提示"应该去下拉里加一条"。</p>
     */
    private void populateFormFromActive() {
        AiConfig active = settings.activeConfig();
        if (active == null) {
            nameField.setText("");
            baseUrlField.setText("");
            apiKeyField.setText("");
            modelField.setText("");
            timeoutField.setValue(60);
            maxTokensField.setValue(AiConfig.DEFAULT_MAX_TOKENS);
            return;
        }
        nameField.setText(active.getName() == null ? "" : active.getName());
        baseUrlField.setText(active.getBaseUrl() == null ? "" : active.getBaseUrl());
        // JPasswordField 内部以 String 存储，回填不可避免会构造一份 String。
        apiKeyField.setText(active.getApiKey() == null ? "" : new String(active.getApiKey()));
        modelField.setText(active.getModel() == null ? "" : active.getModel());
        timeoutField.setValue(active.getTimeoutSeconds());
        maxTokensField.setValue(active.getMaxTokens());
    }

    // ========== 事件处理 ==========

    /**
     * 持久化设置：捕获加密失败等可预期异常并转成 Toast 提示，避免异常冒泡到 EDT
     * （用户看到"无反应"）。其它运行时异常仍按原样抛出，便于暴露真实缺陷。
     */
    private void saveSettings() {
        try {
            settingsStore.save(settings);
        } catch (com.auditai.burp.config.ApiKeyCipher.ApiKeyCipherException e) {
            toast.showError(I18n.get().t("ui.settings.toast.savedFailed", e.getMessage()));
        }
    }

    /**
     * 下拉列表选中项变化：分两种情况——
     * <ul>
     *   <li>选中了占位项 {@code addNewLabel}：立即在列表里追加一条全空配置并切过去；
     *       下拉刷新后新配置被选中，占位项继续保持在末位；</li>
     *   <li>选中了真实配置：先把当前表单"未保存"的编辑通过 {@link #serviceDebounce}
     *       的 {@link DebouncedAction#flushIfPending flushIfPending} 同步落进
     *       {@link Settings#activeConfig()}（避免切走时丢失防抖窗口内的编辑），
     *       再切换激活项、回填表单、保存到磁盘。</li>
     * </ul>
     *
     * <p>切换 / 新增前先调 {@link #cancelInflightTest} 中断正在飞的"上一个模型的
     * 测试连接"。</p>
     */
    private void onDropdownChanged() {
        // 防御性拦截：refreshDropdown 批量改 items 期间即便 listener 没摘掉
        // （或者 Swing 在某些实现上 listener 摘/装不及时），也不要递归回调
        // ——否则会出现"保存一条新配置后下拉只剩一项"的诡异 BUG。
        if (refreshingDropdown) {
            return;
        }
        Object selected = serviceDropdown.getSelectedItem();
        if (!(selected instanceof String)) {
            return;
        }
        String selectedName = (String) selected;
        cancelInflightTest();
        // 切走前先把当前表单的编辑强制同步进 activeConfig(防抖窗口内的最后几次键入)。
        serviceDebounce.flushIfPending();
        if (addNewLabel.equals(selectedName)) {
            addNewService();
            return;
        }
        String oldName = settings.activeName();
        if (selectedName.equals(oldName)) {
            return;
        }
        // 2. 切换激活项
        settings.switchTo(selectedName);
        // 3. 用新激活项的字段回填表单
        populateFormFromActive();
        // 4. 刷新下拉:确保 selectedItem 跟 activeName 对齐（中间过程里如果
        //    flushIfPending 触发了 applyAiServiceChange 路径,可能会改 activeName）。
        refreshDropdown();
        // 5. 持久化：激活项变更要立刻落盘，否则下次启动又回到旧激活项
        saveSettings();
        toast.show(I18n.get().t("ui.settings.toast.switched", selectedName));
    }

    /**
     * AI 服务区表单字段的"自动保存"统一入口：校验 → 整体替换 activeConfig →
     * 持久化。所有 UI 写操作都走这条路径,避免多字段非原子写引发的撕裂读。
     *
     * <p>校验失败时弹 Toast 并保留旧 settings 状态，不阻断 UI;{@link DebouncedAction}
     * 防抖保证 Toast 不会密集连发。</p>
     *
     * <p>不刷新下拉 / 表单 —— 由调用方负责:下拉切换场景不需要刷新
     * ({@link #onDropdownChanged} 会做),自动保存进入阶段只在重命名时补刷
     * ({@link #applyAiServiceChange})。</p>
     *
     * @return 表单合法且已应用到 settings + 持久化时返回 true;校验失败或持久化
     *         异常时返回 false(settings 不变)。
     */
    private boolean tryApplyFormToSettings() {
        // 列表为空 / 无激活项时静默跳过——表单此时是占位空表,没东西可保存。
        // 不弹 Toast 引导"请先添加":用户大概率在下拉里加新配置,或者只是浏览。
        if (settings.activeConfig() == null) {
            return false;
        }
        String newName = nameField.getText() == null ? "" : nameField.getText().trim();
        if (newName.isEmpty()) {
            toast.show(I18n.get().t("ui.settings.toast.nameEmpty"));
            return false;
        }
        // 占位符是下拉列表的"伪配置"——禁止用户用这个字符串作为真实配置名。
        if (addNewLabel.equals(newName)) {
            toast.show(I18n.get().t("ui.settings.toast.nameIllegal", addNewLabel));
            return false;
        }
        // 重名校验：与列表中"除当前激活项以外"的条目比对。
        Set<String> existing = settings.existingNames();
        for (String name : existing) {
            if (name.equals(newName) && !name.equals(settings.activeName())) {
                toast.show(I18n.get().t("ui.settings.toast.nameDup", newName));
                return false;
            }
        }
        // 从表单字段构造一个新 AiConfig（一次性把全部字段定下来）
        String oldName = settings.activeName();
        AiConfig newActive = buildAiConfigFromForm(newName);
        // 整体替换 activeConfig 引用——避免原地 copyFrom 引发撕裂读。
        // 注意:replaceActive 会把 activeName 一并替换为 newName,所以"是否改名"
        // 必须用 oldName(替换前捕获)判断,而不能用 settings.activeName()。
        settings.replaceActive(newActive);
        if (!newName.equals(oldName)) {
            // 改名后移除旧名条目(replaceActive 已把激活项换成新名,
            // 旧名条目不再被引用;不移除会在下拉里留下"幽灵配置")。
            settings.removeConfigByName(oldName);
        }
        // 持久化：SettingsStore.save 内部调用 syncActiveEntry 把 activeConfig
        // 同步回列表条目。加密失败等可预期异常转成 Toast,避免冒泡到 EDT。
        try {
            settingsStore.save(settings);
        } catch (com.auditai.burp.config.ApiKeyCipher.ApiKeyCipherException e) {
            toast.showError(I18n.get().t("ui.settings.toast.savedFailed", e.getMessage()));
            return false;
        }
        return true;
    }

    /**
     * 把当前表单字段打包为一个新 {@link AiConfig}（一次性确定所有字段，无中间可见态）。
     *
     * <p>专供 {@link #tryApplyFormToSettings} 使用：必须<b>不要</b>直接修改
     * {@code settings.activeConfig()} 的内部字段——那样会产生多字段非原子写，
     * 跨线程读会出现"新 baseUrl + 旧 model"等撕裂读，导致被动分析请求被发到错误 AI。</p>
     */
    private AiConfig buildAiConfigFromForm(String name) {
        char[] keyChars = trimCopy(apiKeyField.getPassword());
        try {
            return new AiConfig(
                    name,
                    baseUrlField.getText().trim(),
                    keyChars, // AiConfig 构造器内部会 clone()，原数组可立即清零
                    modelField.getText().trim(),
                    (Integer) timeoutField.getValue(),
                    (Integer) maxTokensField.getValue());
        } finally {
            // 用完即擦除：JPasswordField 返回的 char[] 副本立即清零
            java.util.Arrays.fill(keyChars, '\0');
        }
    }

    /**
     * 给 AI 服务区表单的所有控件挂"自动保存"监听器：四个文本字段
     * （name / baseUrl / apiKey / model）用 {@link DocumentListener}，两个
     * {@link JSpinner}（timeout / maxTokens）用 {@link ChangeListener}。任一变化
     * 都通过 {@link #serviceDebounce} 重启定时器，停止输入
     * {@value #SERVICE_DEBOUNCE_MS}ms 后由 {@link #applyAiServiceChange} 统一处理。
     *
     * <p>必须先于本方法在初始化表单之后再调——构造期 setText 会触发 DocumentListener，
     * 若监听器已挂，会在初始化阶段产生"无意义的自动保存"流。</p>
     */
    private void wireAiServiceListeners() {
        DocumentListener docListener = new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                serviceDebounce.schedule();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                serviceDebounce.schedule();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                serviceDebounce.schedule();
            }
        };
        nameField.getDocument().addDocumentListener(docListener);
        baseUrlField.getDocument().addDocumentListener(docListener);
        apiKeyField.getDocument().addDocumentListener(docListener);
        modelField.getDocument().addDocumentListener(docListener);
        ChangeListener changeListener = e -> serviceDebounce.schedule();
        timeoutField.addChangeListener(changeListener);
        maxTokensField.addChangeListener(changeListener);
    }

    /**
     * {@link #serviceDebounce} 防抖定时器到期时调用：尝试把表单应用到
     * settings + 持久化,成功后清除"被动分析失败"提示;仅在名字变化(且下拉未打开)
     * 时 {@link #refreshDropdown 重建下拉}。
     *
     * <p>不做 {@link #populateFormFromActive 表单回填}:表单是数据源,自动保存
     * 后已与 activeConfig 一致;setText 会触发 DocumentListener 重启定时器,
     * 形成"setText → 重 schedule → 再 apply → 再 setText"的死循环。</p>
     *
     * <p>下拉打开时跳过重建:removeAllItems 期间 selectedIndex 被重设,
     * 鼠标物理位置不变但高亮条目已跳。下拉关闭后由 {@link #onDropdownChanged} /
     * 新增删除 / 语言切换兜住展示。</p>
     */
    private void applyAiServiceChange() {
        String oldName = settings.activeName();
        if (!tryApplyFormToSettings()) {
            return;
        }
        String newName = settings.activeName();
        if (!Objects.equals(oldName, newName) && !serviceDropdown.isPopupVisible()) {
            refreshDropdown();
        }
        PassiveAnalysisErrorBus.INSTANCE.clearError();
    }

    /** 把表单当前值复制到指定配置对象（仅测试连接构造临时配置时）。 */
    private void applyFormToConfig(AiConfig target) {
        String name = nameField.getText() == null ? "" : nameField.getText().trim();
        target.setName(name);
        target.setBaseUrl(baseUrlField.getText().trim());
        // API Key：直接以 char[] 写入 AiConfig——避免中途构造 String 落进常量池。
        // trim() 用一个手写的小工具实现，因为 char[] 没有 trim 方法。
        char[] keyChars = trimCopy(apiKeyField.getPassword());
        try {
            target.setApiKey(keyChars);
        } finally {
            // 用完即擦除：JPasswordField 返回的 char[] 副本立即清零
            java.util.Arrays.fill(keyChars, '\0');
        }
        target.setModel(modelField.getText().trim());
        target.setTimeoutSeconds((Integer) timeoutField.getValue());
        target.setMaxTokens((Integer) maxTokensField.getValue());
    }

    /**
     * 返回 {@code source} 去掉首尾空白字符后的副本（不修改原数组）。
     * 用于 {@link #applyFormToConfig} 与 {@link #buildAiConfigFromForm}：
     * 把 {@link javax.swing.JPasswordField#getPassword()} 返回的 char[] 去前后空白后
     * 再写入 AiConfig，行为等价于原 String.trim()。
     */
    private static char[] trimCopy(char[] source) {
        if (source == null) {
            return new char[0];
        }
        int start = 0;
        int end = source.length;
        while (start < end && Character.isWhitespace(source[start])) {
            start++;
        }
        while (end > start && Character.isWhitespace(source[end - 1])) {
            end--;
        }
        if (start == 0 && end == source.length) {
            return source.clone();
        }
        return java.util.Arrays.copyOfRange(source, start, end);
    }

    /**
     * 选中下拉末位占位项"新增配置"时触发：往列表里追加一条全空配置，立刻切过去。
     *
     * <p>新条目名称用 {@link #generateUniqueName} 生成（"新配置 1"、"新配置 2"…），
     * 避免与现有条目冲突；下拉刷新后新配置被选中，{@code addNewLabel}
     * 占位项继续保持在末位等待下一次新增。</p>
     */
    private void addNewService() {
        AiConfig fresh = new AiConfig(generateUniqueName(), "", "", "", 60, AiConfig.DEFAULT_MAX_TOKENS);
        settings.addAndSwitchTo(fresh);
        saveSettings();
        refreshDropdown();
        populateFormFromActive();
        toast.show(I18n.get().t("ui.settings.toast.added", fresh.getName()));
    }

    /**
     * 生成一个在当前列表中不存在的默认名（"新配置 1"、"新配置 2"…）。
     * 失败时回退到时间戳后缀，避免无限循环。
     */
    private String generateUniqueName() {
        Set<String> existing = settings.existingNames();
        for (int i = 1; i < 1000; i++) {
            String candidate = I18n.get().t("ui.settings.uniqueName", i);
            if (!existing.contains(candidate) && !addNewLabel.equals(candidate)) {
                return candidate;
            }
        }
        return I18n.get().t("ui.settings.uniqueName", System.currentTimeMillis());
    }

    /**
     * "删除设置"：移除当前激活项。如果删的是最后一条，列表进入"空"状态——
     * 下拉只剩占位项 {@code addNewLabel}，表单清空，删除按钮禁用。
     */
    private void deleteCurrentService() {
        if (settings.configs().isEmpty() || settings.activeName() == null) {
            toast.show(I18n.get().t("ui.settings.toast.noDel"));
            return;
        }
        String removedName = settings.activeName();
        boolean removed = settings.removeActive();
        if (!removed) {
            toast.showError(I18n.get().t("ui.settings.toast.delFailed"));
            return;
        }
        refreshDropdown();
        populateFormFromActive();
        saveSettings();
        if (settings.activeName() == null) {
            toast.show(I18n.get().t("ui.settings.toast.deletedEmpty", removedName, addNewLabel));
        } else {
            toast.show(I18n.get().t("ui.settings.toast.deletedSwitch", removedName, settings.activeName()));
        }
    }

    /**
     * 用当前表单值测试一次真实连接（SwingWorker 后台执行）。
     *
     * <p>基于表单值构造临时配置，测试失败不污染已保存配置。
     * 测试期间先显示常驻"正在测试连接…"提示（{@link Toast#showPersistent}），
     * 让用户在整个等待期间都看得到状态；出结果后由 {@code show} 替换内容
     * （成功 / 失败 / 异常三条路径都会执行到）。</p>
     *
     * <p>用 {@link AiClient#completeAsync} 拿可取消句柄而不是直接 {@code complete}：
     * 后者内部 {@code await()} 阻塞 SwingWorker 线程、外部无法中断；持有
     * {@link CancellableAiCall} 后下拉切换 / 关闭面板可通过
     * {@link #cancelInflightTest} 立即中断 HTTP。{@link SwingWorker#done} 用
     * {@link #testGeneration} 代次判断本次结果是否仍有效——已被新一次测试 / 主动取消
     * 覆盖的旧测试若延迟到达，直接 return 不动 UI。</p>
     *
     * <p>附带：测试成功时清除 {@link PassiveAnalysisErrorBus} 上的错误——用户主动验证
     * 通过代表配置正确，应同步把"被动分析失败"的红字提示和"设置"页签感叹号一并清除。
     * 测试失败时<b>不</b>主动设置错误——避免测试连接（用户主动验证）覆盖被动分析
     * 的真实错误状态（用户可能想看被动分析那条 URL 的具体错误）。</p>
     */
    private void testConnection() {
        cancelInflightTest();

        testButton.setEnabled(false);
        // 用 showPersistent 而不是默认 3 秒的 show：测试连接是慢操作，默认时长
        // 经常不足以覆盖网络往返 / 模型响应；常驻提示会一直挂住直到 done() 内的
        // show() 替换（成功 / 失败 / 异常三条路径都覆盖），用户随时能看到"还在跑"。
        toast.showPersistent(I18n.get().t("ui.settings.testConnecting"));
        AiConfig temp = new AiConfig();
        applyFormToConfig(temp);

        OpenAiCompatibleClient client = new OpenAiCompatibleClient(buildTestSettings(temp));
        CancellableAiCall call;
        try {
            call = client.completeAsync(
                    I18n.get().t("ui.settings.testPrompt.system"),
                    I18n.get().t("ui.settings.testPrompt.user"));
        } catch (AiException ex) {
            // 前置校验失败（如 baseUrl / apiKey 缺失）：同步抛异常，无句柄可取消。
            // 直接在 EDT 上提示并恢复按钮即可。
            testButton.setEnabled(true);
            toast.showError(I18n.get().t("ui.settings.testFailed", ex.getMessage()));
            return;
        }
        currentTestCall = call;
        // 本次测试的代次快照：done() 触发时若已被覆盖（cancelInflightTest / 下一次 testConnection
        // 已递增），直接 return 不动 UI。
        final long myGeneration = ++testGeneration;

        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                try {
                    return call.await();
                } catch (AiException ex) {
                    // 不吞掉，让 done() 拿到异常后能识别"被取消"。
                    throw ex;
                }
            }

            @Override
            protected void done() {
                // 代次不匹配：本次结果属于已被中断/替换的旧测试。
                if (myGeneration != testGeneration) {
                    return;
                }
                currentTestCall = null;
                testButton.setEnabled(true);
                try {
                    String reply = get().trim();
                    toast.show(I18n.get().t("ui.settings.testSuccess", reply));
                    // 用户主动验证通过 → 清除"被动分析失败"提示和设置页签感叹号
                    PassiveAnalysisErrorBus.INSTANCE.clearError();
                } catch (Exception ex) {
                    // SwingWorker 把 doInBackground 异常包成 ExecutionException,
                    // 真正根因挂在 getCause()。unwrap 后判定取消。
                    Throwable cause = ex.getCause() != null ? ex.getCause() : ex;
                    if (cause instanceof AiException ai && ai.isCancelled()) {
                        // 常驻"正在测试…"提示已由 cancelInflightTest 隐藏,
                        // 这里不再弹 Toast。
                        return;
                    }
                    String message = cause.getMessage();
                    toast.showError(I18n.get().t("ui.settings.testFailed",
                            message != null ? message : cause.getClass().getSimpleName()));
                    // 不主动设置错误状态：测试连接是用户主动行为，失败时用 Toast 已经足够；
                    // 真正的"被动分析失败"提示留给被动分析路径，避免两条互相覆盖。
                }
            }
        }.execute();
    }

    /**
     * 取消当前正在跑的"测试连接"（如有）。{@link CancellableAiCall#cancel()} 中断进行中的 HTTP；
     * 递增 {@link #testGeneration} 让仍在飞的 {@link SwingWorker#done} 判定为陈旧；
     * 恢复按钮可用（陈旧 done() 直接 return 不会恢复按钮）；隐藏常驻"正在测试连接…"提示。
     * 幂等：无 inflight 时直接返回。
     */
    private void cancelInflightTest() {
        CancellableAiCall call = currentTestCall;
        if (call != null) {
            call.cancel();
        }
        currentTestCall = null;
        testGeneration++;
        testButton.setEnabled(true);
        toast.dismiss();
    }

    /**
     * 为"测试连接"构造一个临时 {@link Settings}：保留主设置里的 customPrompt，
     * 但 activeConfig 用表单值临时构造（不影响持久化的配置列表）。
     */
    private Settings buildTestSettings(AiConfig tempActive) {
        return new Settings(
                new java.util.ArrayList<>(java.util.List.of(tempActive)),
                tempActive.getName(),
                settings.customPrompt());
    }

    // ========== 提示词区 ==========

    /** 构建"提示词"标题区。 */
    private JPanel buildPromptSection() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(I18n.titledBorder("ui.settings.section.prompt"));

        JLabel hint = I18n.label("ui.settings.promptHint");
        hint.setFont(hint.getFont().deriveFont(Font.PLAIN, 12f));
        hint.setBorder(BorderFactory.createEmptyBorder(0, 6, 4, 6));
        panel.add(hint, BorderLayout.NORTH);

        panel.add(new JScrollPane(promptArea), BorderLayout.CENTER);

        // 左对齐 + 与 AI 服务区一致的按钮间距，保证两个功能区的按钮视觉对齐。
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        buttons.add(savePromptButton);
        buttons.add(resetPromptButton);
        panel.add(buttons, BorderLayout.SOUTH);
        return panel;
    }

    /** 保存提示词:编辑器内容 → 共享配置 → 持久化。 */
    private void savePrompt() {
        settings.setCustomPrompt(promptArea.getText());
        settingsStore.saveCustomPrompt(settings.customPrompt());
        // 保存后框内内容 = 用户自定义,不再是"默认参考",后续语言切换不再重写它。
        promptAreaShowsDefault = false;
        toast.show(I18n.get().t("ui.settings.toast.savedPrompt"));
    }

    // ========== 语言切换区 ==========

    /** 两个语言按钮:点击立刻调 I18n.set(...),所有注册过 onChange 的 UI 都会刷新。
     *  文本走 {@link I18n#button} 工厂(自动订阅,切语言时 setText),高亮态由
     *  {@link #refreshI18n()} 单独按当前语言切换。 */
    private final JButton langZhButton = I18n.button("ui.lang.zh");
    private final JButton langEnButton = I18n.button("ui.lang.en");

    /**
     * 构建"语言"标题区:放置在"提示词"区下面作为最后一个模块。
     * <pre>
     *   语言:
     *   [ 中文 ]  [ English ]   &lt;-- 当前语言高亮(蓝字加粗)
     * </pre>
     */
    private JPanel buildLanguageSection() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(I18n.titledBorder("ui.settings.section.lang"));

        // 用 FlowLayout + 左对齐容器,与其他 section 的对齐方式一致
        JPanel form = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        styleLangButton(langZhButton);
        styleLangButton(langEnButton);
        langZhButton.addActionListener(e -> I18n.get().set(PromptBuilder.Lang.ZH));
        langEnButton.addActionListener(e -> I18n.get().set(PromptBuilder.Lang.EN));
        form.add(langZhButton);
        form.add(langEnButton);

        JPanel leftWrap = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        leftWrap.add(form);
        panel.add(leftWrap, BorderLayout.CENTER);
        return panel;
    }

    /**
     * 语言按钮统一样式:无填充、无边框、纯文字外观;高亮态由
     * {@link #refreshI18n()} 按当前 I18n.current() 切换。
     */
    private static void styleLangButton(JButton btn) {
        btn.setFocusPainted(false);
        btn.setMargin(new java.awt.Insets(2, 12, 2, 12));
        btn.setBorderPainted(false);
        btn.setContentAreaFilled(false);
        btn.setOpaque(false);
        btn.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        btn.setFont(btn.getFont().deriveFont(Font.PLAIN, 12f));
        btn.setCursor(new java.awt.Cursor(java.awt.Cursor.HAND_CURSOR));
    }

    // ========== 被动分析区 ==========

    /**
     * 构建"被动分析"标题区：
     * <pre>
     *   被动分析:
     *   [x] 启用被动流量分析
     *   URL 过滤正则: [____________________]
     *   全流程自动完成：实时监听 Proxy，按 URL 过滤+指纹去重后调用 AI 分析报文。
     *   ⚠ 错误信息（红字，仅错误时显示）   &lt;-- 新增：错误时显示
     * </pre>
     *
     * <p>开启后 AuditAI 会监听 Burp Proxy 转发到本进程的请求/响应（不影响 Repeater /
     * Intruder / Scanner 等主动工具流量），按"URL 过滤 + 指纹去重"自动提交到独立线程池
     * 做 AI 分析。指纹 = HTTP方法 + URL(含query) + 请求体 Hash；同一指纹只分析一次，
     * 队列满时丢弃并写告警日志，不会回压到 Burp 代理线程。</p>
     *
     * <p>无"保存"按钮：复选框 / 输入框变化时立即持久化 + 推给 handler（即时生效）。</p>
     *
     * <p>错误提示：默认隐藏；订阅 {@link PassiveAnalysisErrorBus}，AI 调用失败时
     * 立刻在下方展示红字错误（短消息 + ⚠ 警示图标），用户改完配置后下次分析成功
     * 会自动消失。配合 MainTab 在"设置"页签标题右侧加感叹号，停留在其他页签时
     * 也能感知问题。</p>
     */
    private JPanel buildPassiveAnalysisSection() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(I18n.titledBorder("ui.settings.section.passive"));

        JPanel form = new JPanel(new GridBagLayout());

        // 第 0 行：复选框（无"启用:"标签，直接 checkbox 自带文字 + 中文描述）
        GridBagConstraints c0 = new GridBagConstraints();
        c0.gridx = 0;
        c0.gridy = 0;
        c0.insets = new Insets(3, 6, 3, 6);
        c0.anchor = GridBagConstraints.WEST;
        form.add(passiveEnabledCheck, c0);

        // 第 1 行：URL 过滤正则——和 label 紧贴、input 占满剩余宽度：
        // 把 label + field 包成一个 BorderLayout 子 panel（label 在 WEST、field 在 CENTER），
        // 跨两列 + HORIZONTAL fill，让 input 跟 label 直接挨着并延伸到右沿，
        // 不受 gridx=0/1 两列宽度分配的拉扯。
        JPanel passiveRegexRow = new JPanel(new BorderLayout(4, 0)); // label 与 field 之间 4px
        passiveRegexRow.setOpaque(false);
        passiveRegexRow.add(I18n.label("ui.settings.passiveRegex"), BorderLayout.WEST);
        passiveRegexRow.add(passiveRegexField, BorderLayout.CENTER);
        GridBagConstraints pRegexRowC = new GridBagConstraints();
        pRegexRowC.gridx = 0;
        pRegexRowC.gridy = 1;
        pRegexRowC.gridwidth = 2;
        pRegexRowC.insets = new Insets(3, 6, 3, 6);
        pRegexRowC.fill = GridBagConstraints.HORIZONTAL;
        pRegexRowC.weightx = 1.0;
        pRegexRowC.anchor = GridBagConstraints.WEST;
        form.add(passiveRegexRow, pRegexRowC);

        // 第 2 行：URL 过滤正则的实时校验状态（紧贴输入框下方）。
        // 始终占布局位置 —— 初始为单个空格占位，避免 preferredSize 突变造成跳动；
        // 内容由 refreshPassiveRegexStatus 按 validate() 结果填充，避免运行时兜底回退到
        // "匹配全部"时用户毫无感知。
        passiveRegexStatusLabel.setFont(passiveRegexStatusLabel.getFont().deriveFont(Font.PLAIN, 12f));
        passiveRegexStatusLabel.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
        passiveRegexStatusLabel.setForeground(UIManager.getColor("Label.disabledForeground"));
        GridBagConstraints c2 = new GridBagConstraints();
        c2.gridx = 0;
        c2.gridy = 2;
        c2.gridwidth = 2;
        c2.insets = new Insets(0, 0, 0, 0);
        c2.anchor = GridBagConstraints.WEST;
        c2.fill = GridBagConstraints.HORIZONTAL;
        c2.weightx = 1.0;
        form.add(passiveRegexStatusLabel, c2);

        // 第 3 行：功能说明（小字、灰字、跨两列贴左）。颜色取系统 disabled 前景色以跟随主题。
        JLabel passiveHint = I18n.label("ui.settings.passiveHint");
        passiveHint.setFont(passiveHint.getFont().deriveFont(Font.PLAIN, 12f));
        passiveHint.setForeground(UIManager.getColor("Label.disabledForeground"));
        GridBagConstraints c3 = new GridBagConstraints();
        c3.gridx = 0;
        c3.gridy = 3;
        c3.gridwidth = 2;
        c3.insets = new Insets(14, 6, 3, 6);
        c3.anchor = GridBagConstraints.WEST;
        form.add(passiveHint, c3);

        // 第 4 行：错误提示（红字 + ⚠ 图标）。始终占布局位置，用 setText 切换内容。
        //          跨两列贴左 + 横向铺满：长错误（>300 字符）能自动换行。
        // 颜色：取系统 Label.errorForeground；LaF 主题未提供时回退到固定红色。
        java.awt.Color errorColor = UIManager.getColor("Label.errorForeground");
        if (errorColor == null) {
            errorColor = new java.awt.Color(0xC0, 0x39, 0x2B);
        }
        passiveErrorArea.setForeground(errorColor);
        passiveErrorArea.setFont(passiveErrorArea.getFont().deriveFont(Font.PLAIN, 12f));
        // 纯文本 + 自动换行 + 按词换行：远端错误可能 300+ 字符，JLabel 不会换行会撑爆。
        // JTextArea 渲染纯文本，绝对不会输出 <html> 字面字符（LaF 主题无 HTML 渲染问题）。
        passiveErrorArea.setLineWrap(true);
        passiveErrorArea.setWrapStyleWord(true);
        passiveErrorArea.setEditable(false);
        passiveErrorArea.setFocusable(false);
        passiveErrorArea.setOpaque(false);  // 透明背景——视觉上像一个 label
        passiveErrorArea.setBorder(null);   // 去边框——视觉上像一个 label
        // 用 BorderLayout 包一层：让 JTextArea 占满宽度，便于长错误换行。
        passiveErrorPanel.setBorder(BorderFactory.createEmptyBorder(4, 6, 6, 6));
        passiveErrorPanel.add(passiveErrorArea, BorderLayout.CENTER);
        // 不切换 panel 可见性——始终占布局位置；内容由 JTextArea 文本控制。
        GridBagConstraints c4 = new GridBagConstraints();
        c4.gridx = 0;
        c4.gridy = 4;
        c4.gridwidth = 2;
        c4.insets = new Insets(0, 0, 0, 0);
        c4.anchor = GridBagConstraints.WEST;
        c4.fill = GridBagConstraints.HORIZONTAL;
        form.add(passiveErrorPanel, c4);

        JPanel leftWrap = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        leftWrap.add(form);
        panel.add(leftWrap, BorderLayout.CENTER);
        return panel;
    }

    /**
     * 把 settings 里的被动分析配置回填到开关 + 正则输入框。
     *
     * <p>必须先于 {@link #wirePassiveAnalysisListeners} 调用——否则 populate 时
     * 也会触发 ChangeListener / DocumentListener 引起无意义的"自动保存"流。</p>
     *
     * <p>同时刷新校验状态行：用户切换 UI 语言后第一次回到该面板就能看到本地化后的状态文案。</p>
     */
    private void populatePassiveAnalysisFromSettings() {
        passiveEnabledCheck.setSelected(settings.isPassiveAnalysisEnabled());
        passiveRegexField.setText(settings.getPassiveAnalysisUrlRegex() == null
                ? "" : settings.getPassiveAnalysisUrlRegex());
        refreshPassiveRegexStatus();
    }

    /**
     * 给被动分析的两个控件挂"实时生效"监听器：复选框用 {@link ChangeListener}，
     * 输入框用 {@link DocumentListener}。任何变化都重启 {@link #passiveDebounceTimer}，
     * 停止输入 {@value #PASSIVE_DEBOUNCE_MS}ms 后才统一应用（写 settings + 持久化 + 广播 hook）。
     *
     * <p>正则输入框的 DocumentListener <b>额外立即</b>调用 {@link #refreshPassiveRegexStatus}
     * ——校验反馈不参与防抖（用户键入应立刻看见状态行变色），只有"apply to settings + 持久化"
     * 走 300ms 防抖；这样既保证状态行实时、又不会出现"打一个字就触发一次 Preferences 写"的
     * 性能 / 日志问题。</p>
     *
     * <p>实现要点：</p>
     * <ul>
     *   <li><b>输入框防抖</b>：DocumentListener 触发频率 = 每次按键，不防抖会把
     *       中间正则态实时推给 handler——非法中间态（如未闭合括号）会触发"回退匹配全部"，
     *       把本不该匹配的请求 mark 进 dedup，用户补全正则后这些请求永不分析（去重污染）；
     *       同时每次按键 2 次 Preferences 写 + 1 条 Output 日志（注册表写 + 刷屏）。
     *       防抖后只在停止输入时应用一次；</li>
     *   <li>不在每次变化时弹 Toast——用户改一个字就弹一条会把 UI 顶得很难看；</li>
     *   <li>hook 抛异常时只打日志不打扰用户——handler 重建 {@code UrlRegexFilter}
     *       失败（非法正则）已经会写告警日志。</li>
     * </ul>
     */
    private void wirePassiveAnalysisListeners() {
        passiveEnabledCheck.addChangeListener(e -> passiveDebounce.schedule());
        passiveRegexField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                passiveDebounce.schedule();
                refreshPassiveRegexStatus();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                passiveDebounce.schedule();
                refreshPassiveRegexStatus();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                passiveDebounce.schedule();
                refreshPassiveRegexStatus();
            }
        });
    }

    /**
     * 根据 {@link #passiveRegexField} 当前文本重新填充状态行：EMPTY 留空匹配全部、
     * VALID 绿字"合法"、VALID_EXPANDED 绿字"含伪正则展开（原 → 译）"、INVALID 红字"非法"。
     *
     * <p>不防抖、不抛 Toast：校验是 UI 反馈，应当和键入同步；只有
     * "apply to settings + 持久化"才走防抖（避免半截输入落盘）。</p>
     *
     * <p>状态行的颜色用系统提供的语义色：禁用灰 / 成功色 / 错误色——跟随 LaF / Dark 主题。
     * 主题未提供对应键时回退到固定颜色，避免 UI 完全不可读。</p>
     */
    private void refreshPassiveRegexStatus() {
        String text = passiveRegexField.getText();
        UrlRegexFilter.ValidationResult result = UrlRegexFilter.validate(text);
        I18n i18n = I18n.get();
        java.awt.Color fallbackNeutral = UIManager.getColor("Label.disabledForeground");
        java.awt.Color success = UIManager.getColor("Label.foreground");
        java.awt.Color danger = UIManager.getColor("Label.errorForeground");
        if (fallbackNeutral == null) {
            fallbackNeutral = new java.awt.Color(120, 120, 120);
        }
        if (success == null) {
            success = new java.awt.Color(0x2E, 0x7D, 0x32);
        }
        if (danger == null) {
            danger = new java.awt.Color(0xC0, 0x39, 0x2B);
        }
        switch (result.status()) {
            case EMPTY -> {
                passiveRegexStatusLabel.setText(i18n.t("ui.settings.regexStatus.empty"));
                passiveRegexStatusLabel.setForeground(fallbackNeutral);
            }
            case VALID -> {
                passiveRegexStatusLabel.setText(i18n.t("ui.settings.regexStatus.valid"));
                passiveRegexStatusLabel.setForeground(success);
            }
            case VALID_EXPANDED -> {
                String userInput = text == null ? "" : text;
                passiveRegexStatusLabel.setText(i18n.t("ui.settings.regexStatus.validExpanded",
                        userInput, result.translatedRegex()));
                passiveRegexStatusLabel.setForeground(success);
            }
            case INVALID -> {
                String reason = result.message() == null ? "" : result.message();
                // 校验 result 自带"正则非法："前缀，去掉避免重复
                String cleaned = reason.startsWith("正则非法：")
                        ? reason.substring("正则非法：".length())
                        : reason;
                passiveRegexStatusLabel.setText(i18n.t("ui.settings.regexStatus.invalid", cleaned));
                passiveRegexStatusLabel.setForeground(danger);
            }
        }
    }

    /**
     * 把当前两个控件的值写回 settings + 持久化 + 广播 hook。
     * 不弹 Toast：调用频率高，频繁提示会破坏输入体验。
     */
    private void applyPassiveAnalysisChange() {
        settings.setPassiveAnalysisEnabled(passiveEnabledCheck.isSelected());
        String regex = passiveRegexField.getText() == null ? "" : passiveRegexField.getText().trim();
        settings.setPassiveAnalysisUrlRegex(regex);
        settingsStore.savePassiveAnalysis(settings.isPassiveAnalysisEnabled(),
                settings.getPassiveAnalysisUrlRegex());
        Runnable hook = passiveAnalysisSavedHook;
        if (hook != null) {
            try {
                hook.run();
            } catch (RuntimeException ex) {
                logError("被动分析热更新失败：" + ex.getMessage(), ex);
            }
        }
    }

    /** 恢复默认：清空自定义提示词，并把编辑器内容恢复为默认提示词。 */
    private void resetPrompt() {
        settings.setCustomPrompt("");
        settingsStore.saveCustomPrompt("");
        promptArea.setText(promptBuilder.buildDefaultSystemPrompt());
        // setText 触发的 DocumentListener 会把标记置 false,这里补回:
        // 重置后框内是"当前语言的默认参考",后续切语言时应跟随重填。
        promptAreaShowsDefault = true;
        toast.show(I18n.get().t("ui.settings.toast.resetPrompt"));
    }

    /**
     * 语言切换时刷新设置页签内的非自动订阅 UI 元素:
     * <ul>
     *   <li>{@code addNewLabel}（下拉占位符）+ 整条下拉（按最新翻译重排条目）；</li>
     *   <li>语言按钮的高亮态（按当前语言切换"加粗蓝字 / 平铺灰字"）；</li>
     *   <li>默认提示词（框内为"参考默认"且无自定义时）跟随语言重填。</li>
     * </ul>
     * 其它按钮 / 复选框 / Label / TitledBorder / tooltip 由 {@link I18n} 弱引用
     * 订阅自动刷新,这里不再手动 setText。
     *
     * <p>TitledBorder 创建时已写死,重建主 panel 代价大,这里不重画——视觉上仅是
     * 辅助标题,切语言时用户通常也会离开设置页一会儿,体验上不构成问题。</p>
     */
    @Override
    public void refreshI18n() {
        addNewLabel = I18n.get().t("ui.settings.addNew");
        // 重新填充下拉:占位项的"翻译"需实时生效。
        refreshDropdown();
        // 语言按钮:文案已由 I18n.button 工厂自动刷新,这里只切高亮态。
        PromptBuilder.Lang cur = I18n.get().current();
        highlightLangButton(langZhButton, cur == PromptBuilder.Lang.ZH);
        highlightLangButton(langEnButton, cur == PromptBuilder.Lang.EN);
        // 默认提示词(框内为"参考默认"且无自定义时):跟随 UI 语言切换重填。
        // 保护两条边界:
        //  1) 用户已自定义提示词(那是给 AI 看的指令,跟用户语言习惯走) → 不动;
        //  2) 框内有"未保存草稿"(promptAreaShowsDefault=false) → 绝不能覆盖。
        String custom = settings.customPrompt();
        if ((custom == null || custom.isBlank()) && promptAreaShowsDefault) {
            promptArea.setText(promptBuilder.buildDefaultSystemPrompt(cur));
            // setText 触发的 DocumentListener 会把标记置 false,这里补回。
            promptAreaShowsDefault = true;
        }
        // 被动分析正则校验状态:文案是 i18n 化的,切语言后必须基于当前输入重新填充。
        refreshPassiveRegexStatus();
    }

    /**
     * 语言按钮高亮:当前语言蓝字加粗,非选中灰色平铺。
     * 用 foreground + font 区分,不依赖 setBackground,
     * 避免被 FlatLaf 在切换时强制覆盖成系统色。
     */
    private static void highlightLangButton(JButton btn, boolean active) {
        if (active) {
            btn.setForeground(new java.awt.Color(0, 90, 200));
            btn.setFont(btn.getFont().deriveFont(Font.BOLD));
        } else {
            btn.setForeground(new java.awt.Color(120, 120, 120));
            btn.setFont(btn.getFont().deriveFont(Font.PLAIN));
        }
    }

    /** 释放资源：插件卸载时调用（停止 Toast 的守护调度线程 + 防抖定时器）。 */
    public void close() {
        if (passiveDebounce != null) {
            passiveDebounce.stop();
        }
        if (serviceDebounce != null) {
            serviceDebounce.stop();
        }
        // 中断仍在飞的"测试连接",避免旧 HTTP 的 done() 回调回到 EDT 时操作
        // 已 dispose 的 Swing 组件。
        cancelInflightTest();
        // 注销错误总线监听器：避免 PassiveAnalysisErrorBus 持有已卸载的 UI 引用。
        PassiveAnalysisErrorBus.INSTANCE.removeListener(passiveErrorListener);
        toast.close();
    }

    /**
     * 注册"被动分析配置保存后"的回调：让 {@code AuditAiExtension} 把最新的
     * 开关 + 正则推给 {@code PassiveAnalysisHandler}。运行期多次设置以最后一次为准。
     *
     * @param hook 回调；为 null 表示清空（不广播）。
     */
    public void setOnPassiveAnalysisSaved(Runnable hook) {
        this.passiveAnalysisSavedHook = hook;
    }

    /**
     * 注册"被动分析错误状态变化"的回调：让 {@code MainTab} 在"设置"页签标题右侧
     * 展示 / 清除感叹号，让用户停留在其他页签时也能感知到被动分析失败。
     *
     * <p>回调在 EDT 上触发，签名 {@code boolean hasError}——
     * true 时外部应在页签标题加警示（如"设置 ⚠"），false 时恢复原标题。</p>
     *
     * <p>注册后<b>不会</b>立即触发一次回调——调用方如需当前状态请自行
     * 读取 {@link #isPassiveAnalysisInError()}。</p>
     *
     * @param hook 回调；为 null 表示清空（不通知）。
     */
    public void setOnPassiveAnalysisErrorChanged(java.util.function.Consumer<Boolean> hook) {
        this.passiveAnalysisErrorChangedHook = hook;
    }

    /**
     * 当前是否处于"被动分析失败"状态：true 时 UI 已展示红字错误。
     * 仅查询，不触发任何回调。供装配方在初始化时同步一次"设置"页签标题。
     */
    public boolean isPassiveAnalysisInError() {
        return !PassiveAnalysisErrorBus.INSTANCE.getError().isCleared();
    }

    /**
     * 错误总线回调：把当前错误状态映射到"红字标签"和"页签感叹号"两个 UI 副作用。
     *
     * <p>调用线程：任意。监听器在错误总线里<b>同步</b>触发——可能来自被动分析线程
     * （{@code PassiveAnalyzer} 回调）。Singer-related 操作必须在 EDT，本方法内
     * 统一用 {@link SwingUtilities#invokeLater} 切到 EDT 后再操作 Swing 组件。
     * </p>
     */
    private void onPassiveErrorChanged() {
        PassiveAnalysisErrorBus.ErrorInfo info = PassiveAnalysisErrorBus.INSTANCE.getError();
        boolean hasError = !info.isCleared();
        SwingUtilities.invokeLater(() -> applyPassiveErrorToUi(info, hasError));
    }

    /**
     * EDT 上把错误状态应用到 UI：JTextArea 文本 + 通知外部（MainTab）更新页签。
     *
     * <p>不切换 panel 可见性（始终占布局位置），用 {@code passiveErrorArea} 文本
     * 内容控制显示：有错误时填充红字 + Unicode 警示符；无错误时设为单个空格占位。</p>
     *
     * <p>用纯文本 + Unicode 字符（⚠）而非 HTML 渲染：避免某些 LaF / Dark 主题下
     * JLabel 的 HTML 渲染失效、直接显示 {@code <html>} 字面字符。{@link JTextArea}
     * 是纯文本组件，输出什么就显示什么。</p>
     *
     * @param info     当前错误快照（可能为 cleared()）。
     * @param hasError 是否有错误。
     */
    private void applyPassiveErrorToUi(PassiveAnalysisErrorBus.ErrorInfo info, boolean hasError) {
        if (hasError) {
            String message = info.getMessage() == null ? I18n.get().t("ui.settings.errorUnknown") : info.getMessage();
            // 简短前缀 + 用户消息：让用户知道"这是哪一类问题 + 具体描述"。
            // 分类前缀（配置 / 网络 / 远端）取自 ErrorKind.toString() + 中文映射。
            String prefix = switch (info.getKind()) {
                case CONFIG -> I18n.get().t("ui.settings.errorConfig");
                case NETWORK -> I18n.get().t("ui.settings.errorNetwork");
                case REMOTE -> I18n.get().t("ui.settings.errorRemote");
            };
            // ⚠ Unicode 字符（U+26A0）作为警示符：纯文本在所有 LaF 下都能稳定显示，
            // 不会因为图标主题缺失而消失。
            String guideKey = switch (info.getKind()) {
                case CONFIG -> "ui.error.guide.config";
                case NETWORK -> "ui.error.guide.network";
                case REMOTE -> "ui.error.guide.remote";
            };
            // 第一行"⚠ 类别：消息"，第二行按类别给本地化引导句（展示层包裹，
            // 底层异常原文可能仍是中文，但用户能知道下一步该检查什么）。
            passiveErrorArea.setText(I18n.get().t("ui.settings.errorPrefix", prefix, message)
                    + "\n" + I18n.get().t(guideKey));
        } else {
            // 清空文本：保留一个不可见空格占位，保证 preferredSize 稳定。
            // JTextArea 在 setText("") 时 preferredSize 会缩为 0，下次 setText 非空时
            // 高度突然恢复会有"跳一下"的视觉问题；用单个空格作为占位让高度稳定。
            passiveErrorArea.setText(" ");
        }
        // 重新计算布局：setText 改变了 preferredSize，GridBagLayout 需要重新算 cell 高度。
        java.awt.Container parent = passiveErrorPanel.getParent();
        if (parent != null) {
            parent.revalidate();
            parent.repaint();
        }

        // 通知 MainTab 更新"设置"页签标题：失败时加感叹号，正常时清除。
        // hook 由 MainTab 注入；为 null 时仅本地更新（单测场景）。
        java.util.function.Consumer<Boolean> hook = passiveAnalysisErrorChangedHook;
        if (hook != null) {
            try {
                hook.accept(hasError);
            } catch (RuntimeException ex) {
                logError("错误状态钩子抛出异常：" + ex.getMessage(), ex);
            }
        }
    }

    /**
     * 把诊断信息写入 Burp Extender。
     *
     * <p>{@code api} 为 null 时（仅测试场景）<b>直接抛 RuntimeException 让测试 fail-fast</b>，
     * 而不是静默吞掉或降级到 stderr——避免"hook 抛异常但测试仍然通过"的假绿。</p>
     */
    private void logError(String message, Throwable t) {
        if (api != null) {
            api.logging().logToError("AuditAI " + message, t);
        } else {
            throw new IllegalStateException("AuditAI SettingsPanel logError in test: " + message, t);
        }
    }

    // ========== 防抖辅助类 ==========

    /**
     * 把"延迟 N ms 后执行"的逻辑收敛到一个对象里：内部持有 {@link javax.swing.Timer}，
     * 提供 {@link #schedule 重启} / {@link #flushIfPending 立即触发挂起任务} /
     * {@link #stop 永久停止} 三种语义。
     *
     * <p>用于表单字段防抖：每次键入都 {@code schedule()}，停止输入 N ms 后才真正执行;
     * 切换激活项 / 卸载面板时调 {@code flushIfPending()} 强行同步执行未挂起的任务。</p>
     *
     * <p><b>线程约定</b>：所有方法(含构造方法)只能在 EDT 上调用。
     * Timer 的 listener 由 Swing 在 EDT 上触发。</p>
     */
    private static final class DebouncedAction implements java.awt.event.ActionListener {
        private final Runnable action;
        private final javax.swing.Timer timer;

        DebouncedAction(int delayMs, Runnable action) {
            this.action = action;
            this.timer = new javax.swing.Timer(delayMs, this);
            this.timer.setRepeats(false);
        }

        @Override
        public void actionPerformed(java.awt.event.ActionEvent e) {
            action.run();
        }

        /**
         * 重启定时器:连续调用时只会在最后一次 {@code schedule()} 之后
         * 经过 {@code delayMs} 才真正触发一次——防抖的核心语义。
         */
        void schedule() {
            timer.restart();
        }

        /**
         * 立即执行未挂起的任务(如果有),并停掉定时器。用于必须立即生效的场景:
         * 下拉切换前把"切走前最后几次键入"同步落进旧激活项;
         * 面板卸载 / 关闭前确保挂起任务先执行完。
         *
         * <p>同步在 EDT 上执行 action:调用方需保证 action 自身是 EDT 安全且无重入。</p>
         */
        void flushIfPending() {
            if (timer.isRunning()) {
                timer.stop();
                action.run();
            }
        }

        /** 永久停止定时器(面板卸载 / 关闭)。不会执行挂起任务——配合 {@link #flushIfPending} 使用。 */
        void stop() {
            timer.stop();
        }
    }
}
