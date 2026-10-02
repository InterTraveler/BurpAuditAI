package com.auditai.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.auditai.burp.ai.PromptBuilder;
import com.auditai.burp.config.Settings;
import com.auditai.burp.config.SettingsStore;
import com.auditai.burp.history.AnalysisHistoryStore;
import com.auditai.burp.http.FindingStore;
import com.auditai.burp.http.TrafficAnalyzer;
import com.auditai.burp.passive.FingerprintDedup;
import com.auditai.burp.skills.CustomSkillStore;
import com.auditai.burp.skills.SkillLoader;
import com.auditai.burp.skills.SkillStateStore;
import com.auditai.burp.skills.SkillsPanel;

import javax.swing.JTabbedPane;
import java.io.Serial;
import java.nio.file.Path;
import java.util.function.Consumer;

/**
 * 插件主界面：多页签容器。
 *
 * <p>当前包含五个页签，将来可继续扩展（{@link JTabbedPane#addTab} 追加即可）：</p>
 * <ul>
 *   <li><b>分析</b>：{@link AnalysisPanel}——报文页签容器（类似 Repeater，每次发送/新建
 *       生成编号页签 1、2、3…，每个页签独立分析，可切换查看）；</li>
 *   <li><b>设置</b>：{@link SettingsPanel}——AI 服务、提示词、被动分析、<b>语言切换</b>；</li>
 *   <li><b>历史</b>：{@link AnalysisHistoryPanel}——经 AI 分析模块处理过的报文记录
 *       （手动 / 被动分析）；</li>
 *   <li><b>问题</b>：{@link FindingsPanel}——经模型分析后认为存在 / 可疑的 URL 列表，
 *       下方展示报告 + Request/Response（在"历史"之后）；</li>
 *   <li><b>技能</b>：{@link SkillsPanel}——技能网格，每个技能取自
 *       <code>src/main/resources/skills/</code> 目录下的 {@code <id>/SKILL.md}
 *       （含 <code>vuln/</code>、<code>auxiliary/</code> 两个分类子目录）。</li>
 * </ul>
 *
 * <p>本类还对外提供 {@link #acceptMessage(HttpRequestResponse)}：供上下文菜单
 * （"Send to AuditAI"）把其他模块（Proxy 历史、Repeater 等）的报文送入分析页。</p>
 *
 * <p>语言切换的位置在"设置"页签的最后一个模块(由 {@link SettingsPanel} 持有),
 * 这样整体布局与原版一致——只在设置页签底部多出一行"语言: 中文 | English"。</p>
 */
public final class MainTab extends JTabbedPane implements LocaleAware {

    @Serial
    private static final long serialVersionUID = 1L;

    /** 分析页（多报文页签容器）。 */
    private final AnalysisPanel analysisPanel;

    /** 设置页（AI 服务 / 提示词 / 被动分析 / 语言切换）。 */
    private final SettingsPanel settingsPanel;

    /** "历史"页签：经 AI 分析模块处理过的报文记录（手动 / 被动分析）。 */
    private final AnalysisHistoryPanel historyPanel;

    /** 问题页（模型分析后的发现列表）。 */
    private final FindingsPanel findingsPanel;

    /** "技能"页签：技能网格。 */
    private final SkillsPanel skillsPanel;

    /**
     * 本容器自身注册到 I18n 的语言切换监听器：close() 时必须注销，避免插件卸载后
     * I18n 强引用本 MainTab（含 Burp 原生编辑器、SettingsPanel 等重型组件）造成泄漏。
     */
    private final Consumer<PromptBuilder.Lang> i18nListener = lang -> refreshI18n();

    /** "分析"页签的索引。 */
    private final int analysisTabIndex;
    /** "设置"页签的索引：用于在"被动分析失败"时给页签标题加感叹号。 */
    private final int settingsTabIndex;
    /** "历史"页签的索引。 */
    private final int historyTabIndex;
    /** "问题"页签的索引；用于数量变化时更新标题。 */
    private final int findingsTabIndex;
    /** "技能"页签的索引。 */
    private final int skillsTabIndex;

    /** "设置"页签在"被动分析失败"时附加的警告后缀。 */
    private static final String SETTINGS_TAB_ERROR_SUFFIX = "  \u26A0";

    /**
     * 被动分析当前是否处于错误态：决定"设置"页签标题是否带 {@value #SETTINGS_TAB_ERROR_SUFFIX}。
     * 单独缓存一份，语言切换刷新标题时按它恢复后缀，避免切语言把错误标记冲掉。
     * 仅在 EDT 读写。
     */
    private boolean passiveAnalysisInError;

    /**
     * 完整构造器：把分析完成回调（手动分析 → 写历史库）显式注入到分析页。
     *
     * @param api              Burp API 门面（用于创建原生报文编辑器等）。
     * @param settings         完整设置（多份 AI 服务配置 + 当前激活 + 全局提示词），设置页读写。
     * @param settingsStore    配置持久化仓库。
     * @param analyzer         分析编排器（每个报文页签触发 AI 调用）。
     * @param historyStore     "历史"页签使用的已分析历史 store；为 null 时页签显示空态。
     * @param findingStore     模型分析产出的"问题"库；为 null 时问题页签显示空态。
     * @param skillStateStore  技能启用态持久化仓库；首次安装走 {@code DefaultEnabledSkill} 默认值。
     * @param customSkillStore 用户自定义技能文件系统仓库；可为 null（不允许用户导入，添加技能按钮隐藏）。
     * @param passiveDedup     被动分析去重缓存；传给"历史"页签以在 Clear 时同步清空，
     *                         避免"清空历史后同 URL 仍被判为已分析"的歧义。可为 null（向后兼容）。
     */
    public MainTab(MontoyaApi api, Settings settings, SettingsStore settingsStore,
                   TrafficAnalyzer analyzer, AnalysisHistoryStore historyStore,
                   FindingStore findingStore, SkillStateStore skillStateStore,
                   CustomSkillStore customSkillStore,
                   FingerprintDedup passiveDedup) {
        this.analysisPanel = new AnalysisPanel(api, analyzer, findingStore);
        this.settingsPanel = new SettingsPanel(api, settings, settingsStore);
        // "历史"页签：只展示经 AI 分析过的报文，不再记录全量代理流量。
        // 注入 passiveDedup：让 Clear 操作同时清空去重缓存，保持与 history 镜像一致。
        this.historyPanel = new AnalysisHistoryPanel(api, historyStore, passiveDedup);
        // 问题页：依赖 historyStore 反查 Request/Response（AnalysisContext 缺失时兜底）；
        // historyStore 为 null 时 Request/Response 页签空。
        this.findingsPanel = new FindingsPanel(api, findingStore, historyStore, this::onFindingsCountChanged);
        // 技能页从 classpath:/skills/ 目录扫描 <id>/SKILL.md（含 vuln/、auxiliary/ 子目录），
        // 再叠加 <sessionRoot>/custom-skills/ 作为扁平形态的用户技能根。
        Path userSkillDir = customSkillStore == null ? null : customSkillStore.rootDirectory();
        this.skillsPanel = new SkillsPanel(
                SkillLoader.fromClasspathAndUserDirectory("skills", MainTab.class.getClassLoader(),
                        userSkillDir, msg -> api.logging().logToError("AuditAI " + msg)),
                skillStateStore,
                customSkillStore);

        addTab("", analysisPanel);
        this.analysisTabIndex = indexOfComponent(analysisPanel);
        addTab("", settingsPanel);
        this.settingsTabIndex = indexOfComponent(settingsPanel);
        addTab("", historyPanel);
        this.historyTabIndex = indexOfComponent(historyPanel);
        addTab("", findingsPanel);
        this.findingsTabIndex = indexOfComponent(findingsPanel);
        addTab("", skillsPanel);
        this.skillsTabIndex = indexOfComponent(skillsPanel);
        // FindingsPanel 构造时会 refresh 一次并回调 onFindingsCountChanged，但那时
        // findingsTabIndex 尚未赋值（读到默认值 0）且页签数为 0，回调会被守卫挡掉；
        // addTab 之后这里再主动同步一次（覆盖磁盘恢复场景）——数量本身已在构造期
        // 由 findingsCurrentCount 记下，因此这里只是补一次标题刷新。
        findingsPanel.triggerCountCallback();

        // 被动分析错误状态 → 设置页签标题感叹号：透传 SettingsPanel 的回调。
        // 必须在 addTab 之后注入（settingsTabIndex 已确定），否则第一次回调无法更新标题。
        settingsPanel.setOnPassiveAnalysisErrorChanged(this::onPassiveAnalysisErrorChanged);
        // 启动时如果错误总线已经处于"失败"状态（v1 不持久化，理论上总是 cleared；
        // 但保留同步一次以备将来扩展），立即同步标题。
        if (settingsPanel.isPassiveAnalysisInError()) {
            onPassiveAnalysisErrorChanged(true);
        }

        // 注册到 I18n：语言切换时只刷新本容器的页签标题与数字徽章。
        // 五个子 Panel 各自在构造期已注册自己的 I18n 监听器负责内部文案刷新。
        I18n.get().onChange(i18nListener);
        refreshI18n();
    }

    /**
     * 语言切换时刷新页签标题："问题 (N)" 数字徽章按缓存计数重画，"设置"页签
     * 按缓存的被动分析错误态决定是否带 ⚠ 后缀。子 Panel 由各自监听器自行刷新。
     */
    @Override
    public void refreshI18n() {
        I18n i18n = I18n.get();
        setTitleAt(analysisTabIndex, i18n.t("ui.tab.analysis"));
        setTitleAt(settingsTabIndex,
                settingsTabNormalTitle() + (passiveAnalysisInError ? SETTINGS_TAB_ERROR_SUFFIX : ""));
        setTitleAt(historyTabIndex, i18n.t("ui.tab.history"));
        setTitleAt(findingsTabIndex, findingsTabNormalTitle(findingsCurrentCount));
        setTitleAt(skillsTabIndex, i18n.t("ui.tab.skills"));
    }

    /** "设置"页签正常态标题——错误态由回调单独追加后缀。 */
    private String settingsTabNormalTitle() {
        return I18n.get().t("ui.tab.settings");
    }

    /** 记录最近一次 findingsCount,refreshI18n 时按这个数字重画 tab 标题。 */
    private int findingsCurrentCount = 0;

    /**
     * "问题"页签数量变化回调:count = 0 时仅显示"问题"(不写数字徽章,避免空态还挂着"(0)"),
     * count > 0 时显示"问题 (N)"。风格贴近 Burp 原生页签(同 Suite 的 Site map、HTTP history
     * 也是这种"标题 + 数字"风格,没有边框/背景,仅文本后缀)。
     */
    private void onFindingsCountChanged(int count) {
        this.findingsCurrentCount = count;
        // 构造期保护：FindingsPanel 在 :114 就被构造（并触发一次 refresh 回调），
        // 而 findingsTabIndex 要到 :128 才赋值——此时它虽是 final，读到的是 0，
        // 页签数量也还是 0。因此必须用"是否已 addTab"判断，不能只判 <0
        // （历史上只判 <0，导致构造期 setTitleAt(0,...) 抛 IndexOutOfBoundsException
        //  并被 FindingsPanel 的 refresh 回调 catch 静默吞掉）。
        if (!isTabIndexReady(findingsTabIndex, getTabCount())) {
            return;
        }
        setTitleAt(findingsTabIndex, findingsTabNormalTitle(count));
    }

    /**
     * 页签索引是否已经指向真实存在的页签。
     *
     * <p>为什么单独抽成方法：本容器在构造期就会收到子面板的回调，而索引字段那时尚未赋值
     * （blank final 的运行时默认值是 <b>0</b>，不是 -1），"<0 即未就绪"这种写法会漏判，
     * 于是 {@code setTitleAt(0,...)} 在 0 个页签时抛 {@code IndexOutOfBoundsException}。
     * 抽出来后可被单测直接钉住这个不变量。</p>
     *
     * @param tabIndex 页签索引（构造期可能是未赋值的默认值 0）。
     * @param tabCount 当前实际页签数量。
     * @return true 表示索引落在 {@code [0, tabCount)} 内，可以安全调 {@code setTitleAt}。
     */
    static boolean isTabIndexReady(int tabIndex, int tabCount) {
        return tabIndex >= 0 && tabIndex < tabCount;
    }

    private String findingsTabNormalTitle(int count) {
        String base = I18n.get().t("ui.tab.findings");
        if (count <= 0) {
            return base;
        }
        return base + " (" + count + ")";
    }

    /**
     * "被动分析错误状态"变化回调:true 时在"设置"页签标题右侧加感叹号 + 警示前缀
     * ("设置 ⚠"),false 时恢复正常标题。
     *
     * <p>使用 Unicode 字符 ⚠(U+26A0)而非 emoji,Burp 的 LaF 对该字符渲染稳定,
     * 不会出现方块 / 不同字体下显示不一致。感叹号前后加空格保证视觉分隔。</p>
     *
     * <p>线程:{@link SettingsPanel} 保证在 EDT 上调用本方法。</p>
     */
    private void onPassiveAnalysisErrorChanged(boolean hasError) {
        this.passiveAnalysisInError = hasError;
        if (!isTabIndexReady(settingsTabIndex, getTabCount())) {
            return;
        }
        setTitleAt(settingsTabIndex,
                settingsTabNormalTitle() + (hasError ? SETTINGS_TAB_ERROR_SUFFIX : ""));
    }

    /**
     * 接收一条来自其他模块(上下文菜单)的报文:新建编号页签并切换到分析页。
     *
     * @param message 选中报文的请求/响应快照。
     */
    public void acceptMessage(HttpRequestResponse message) {
        analysisPanel.acceptMessage(message);
        setSelectedComponent(analysisPanel);
    }

    /**
     * 释放资源：插件卸载时调用。逐层透传到所有子页签，让它们各自释放
     * 定时器、取消在飞行的 SwingWorker、注销 I18n 监听器——避免
     * Burp 重载扩展后残留旧线程与对象图。
     *
     * <p>最后调 {@link I18n#clearAll()}：主动清空全局订阅表 + 监听器列表，
     * 切断对旧 MainTab（含子组件、Burp 原生编辑器等重型对象）的强引用链。
     * 详细原因见 {@link I18n#clearAll()}。</p>
     */
    public void close() {
        settingsPanel.close();
        analysisPanel.close();
        historyPanel.close();
        findingsPanel.close();
        skillsPanel.close();
        I18n.get().off(i18nListener);
        // 主动清空所有订阅表 + 监听器列表：避免重载插件后旧 MainTab 通过
        // I18n 强引用链驻留，并防止切语言时旧组件被错触 setText 引发 NPE。
        I18n.get().clearAll();
    }

    /**
     * 注册"被动分析配置保存后"的回调(由 {@code AuditAiExtension} 调用):
     * 透传给 {@link SettingsPanel},让 UI 保存完立刻通知 {@code PassiveAnalysisHandler} 热更新。
     *
     * @param hook 回调;为 null 表示清空。
     */
    public void setOnPassiveAnalysisSaved(Runnable hook) {
        settingsPanel.setOnPassiveAnalysisSaved(hook);
    }

    /**
     * 注册"手动分析完成"回调(由 {@code AuditAiExtension} 调用):透传到
     * {@link AnalysisPanel},影响后续新建的 MessageTab。
     *
     * <p>典型用法:装配方先 new MainTab(hook 尚未就绪)→ addTab → 拿到 historyStore
     * 引用后回填 hook。已有页签的 hook 已在构造期确定,无法回填——所以通常在
     * 装配方应该用 <b>先 new MainTab → 立即 setOnAnalysisCompleted</b> 的顺序,
     * 保证用户首次右键发送的报文能进"历史"。</p>
     *
     * @param hook 回调;为 null 表示清空(仅影响后续动态新增的 MessageTab)。
     */
    public void setOnAnalysisCompleted(MessageTab.AnalysisResultHook hook) {
        analysisPanel.setOnAnalysisCompleted(hook);
    }
}
