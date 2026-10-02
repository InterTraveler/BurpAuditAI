package com.auditai.burp.skills;

import com.auditai.burp.ui.I18n;
import com.auditai.burp.ui.LocaleAware;
import com.auditai.burp.ui.RoundedButton;
import com.auditai.burp.ui.Toast;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JLayeredPane;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.SwingConstants;
import javax.swing.SwingWorker;
import javax.swing.UIManager;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics2D;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.io.Serial;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * SKILLS 页签主体：网格摆放技能卡片，顶部展示技能数量与说明。
 *
 * <p>布局：</p>
 * <ul>
 *   <li>整个页签用 {@link CardLayout} 在两张卡之间切换：
 *     <ul>
 *       <li>{@code "list"}：原技能列表——顶部页头（标题"技能" + 副标题行内左起依次为
 *           "添加技能"按钮、"共 N 个技能（已启用 M）"），中部 {@link SkillGridPanel}（内含 {@link WrapLayout}）
 *           横向流式排卡片（内置技能在上、分割线、用户技能在下），
 *           底部状态栏（空目录时显示"暂无技能"提示等）；</li>
 *       <li>{@code "detail"}：{@link SkillDetailPanel}——点击卡片后切到此处展示完整字段，
 *           左上角"← 返回"按钮触发后切回 {@code "list"}。</li>
 *     </ul>
 *   </li>
 * </ul>
 *
 * <p>加载约定：技能解析（classpath 扫描 + 文件解析）走 {@link SwingWorker} 后台线程，
 * 完成后切回 EDT 重建网格，避免极端情况下（classpath 大量条目）首次打开页签卡顿。</p>
 *
 * <p>交互约定：</p>
 * <ul>
 *   <li><b>左键</b>：切换到详情页（{@link #showSkillDetails}）；</li>
 *   <li><b>右键</b>：根据当前状态显示"启用 / 禁用"切换项；用户技能额外显示"卸载"项，
 *       内置技能的"卸载"项置灰不可点；</li>
 *   <li><b>顶部"添加技能"按钮</b>：弹文件选择器选 .md → 弹 id 输入对话框 → 调
 *       {@link CustomSkillStore#install} 落盘 → 重新加载并 Toast 反馈；</li>
 *   <li>启用态通过 {@link SkillStateStore} 持久化到 Burp Preferences（首次安装走
 *       {@link DefaultEnabledSkill} 默认集，之后尊重用户选择）。</li>
 * </ul>
 */
public final class SkillsPanel extends JPanel implements LocaleAware {

    @Serial
    private static final long serialVersionUID = 1L;

    /** CardLayout 的卡片 key：列表 / 详情。 */
    private static final String CARD_LIST = "list";
    private static final String CARD_DETAIL = "detail";

    /** 卡片四周内边距。 */
    private static final int CONTENT_PADDING = 16;

    /**
     * "自动激活"技能的上限：防止 phase 1/2 system prompt 同时拼入太多技能导致上下文爆炸。
     * 上限选 3 是基于经验：常驻能力太多会稀释模型的注意力，且单次请求的 token 预算
     * 会快速膨胀；3 个常驻技能已能覆盖"重放 + 漏洞检测 + 通用风险"三种典型场景。
     */
    static final int MAX_PINNED = 3;

    private final SkillLoader loader;
    private final SkillStateStore stateStore;
    private final CustomSkillStore customSkillStore;

    private final CardLayout cardLayout;

    /** 内置技能网格（WrapLayout，水平排卡片，超宽换行）。 */
    private final SkillGridPanel builtInGrid = new SkillGridPanel();
    /** 用户技能网格（同上，独立的 WrapLayout 容器，让分区独立换行）。 */
    private final SkillGridPanel userGrid = new SkillGridPanel();
    /**
     * 内置 / 用户之间的分隔线面板（独立组件，不放进任一网格）。
     * 顶部内边距 + 浅灰细线 + "自定义"小标签，让分区在视觉上明确。
     */
    private final JPanel dividerPanel = buildSectionDivider();
    /** Toast：导入 / 卸载成功时弹右下角；与 SettingsPanel 同一组件，确保交互一致性。 */
    private final Toast toast;
    private final JLayeredPane contentLayeredPane = new JLayeredPane();

    private final JLabel countLabel;
    private final JLabel statusLabel;
    /** 页头加粗大标题("技能" / "Skills"),切语言时由 refreshI18n 刷新。 */
    private final JLabel headerTitle = new JLabel();
    /** 顶部"添加技能"按钮——切语言时同步刷新文案；统一样式。 */
    private final JButton addSkillButton = RoundedButton.standard(I18n.button("ui.skills.add"));

    /**
     * 启用态注册表：key = 技能 id，value = true。
     * 缺省所有技能都是禁用——首次加载时被扫到的技能若未在此表内则视为禁用。
     * 切换时只更新本表与对应 {@link SkillCard}，不重建网格。
     */
    private final Map<String, Boolean> enabledIds = new HashMap<>();

    /**
     * "自动激活"id 注册表：被自动激活的技能 id 集合（一定也在 enabledIds 内）。
     * 与 enabledIds 平行存储——独立的语义（"是否启用"vs"是否常驻自动注入"），让宿主
     * 可以独立读取 / 写入；解除自动激活时不一定要禁用。切换时同样只更新本表 + 对应卡片。
     */
    private final Set<String> pinnedIds = new HashSet<>();

    /** 当前已渲染的卡片引用：右键菜单触发后用 id 找回对应卡片直接调 setEnabled。 */
    private final Map<String, SkillCard> cardsById = new LinkedHashMap<>();

    /**
     * @param loader          技能加载器；推荐用
     *                        {@code SkillLoader.fromClasspath("skills", getClass().getClassLoader())}。
     *                        加载器会扫描 <code>skills/</code> 根目录以及约定的
     *                        <code>skills/vuln/</code>、<code>skills/auxiliary/</code>
     *                        两个子目录，其它子目录自动跳过。
     * @param stateStore      启用态持久化仓库；首次安装时返回 {@link DefaultEnabledSkill#ids()}，
     *                        之后返回用户持久化的状态。
     * @param customSkillStore 用户技能文件系统仓库；可为 null（不允许用户导入）。为 null 时
     *                        顶部"添加技能"按钮隐藏、右键"卸载"项不显示。
     */
    public SkillsPanel(SkillLoader loader, SkillStateStore stateStore,
                       CustomSkillStore customSkillStore) {
        super(new CardLayout());
        this.loader = loader;
        this.stateStore = stateStore;
        this.customSkillStore = customSkillStore;
        this.cardLayout = (CardLayout) getLayout();

        // 先把所有 final 字段构造出来，再调用任何可能引用它们的方法（如 buildHeader 会用到 countLabel）。
        this.countLabel = new JLabel(I18n.get().t("ui.skills.count", 0));
        this.statusLabel = new JLabel(" ", JLabel.LEFT);
        // 两个网格的底色跟面板一致，避免 WrapLayout 在卡片间露出默认底色。
        builtInGrid.setBackground(getBackground());
        userGrid.setBackground(getBackground());

        // 加载持久化的启用态：首次安装走枚举默认值，之后走 CSV 持久化。
        for (String id : stateStore.loadEnabledIds()) {
            enabledIds.put(id, Boolean.TRUE);
        }
        // 加载持久化的"自动激活"集合：与启用态平行、不回退到默认（自动激活是明确用户意图）。
        pinnedIds.addAll(stateStore.loadPinnedIds());

        // 列表视图：包住原页头 + 网格 + 状态栏，对应 CardLayout 的 {@code "list"}。
        // 只在构造期使用，无需作为字段。
        JPanel listCard = new JPanel(new BorderLayout());
        listCard.setBorder(BorderFactory.createEmptyBorder(
                CONTENT_PADDING, CONTENT_PADDING, CONTENT_PADDING, CONTENT_PADDING));

        listCard.add(buildHeader(), BorderLayout.NORTH);

        // 内容栈：垂直 BoxLayout 让内置网格 / 分隔线 / 用户网格 三段天然上下排布，
        // 不依赖 WrapLayout 推断分隔线是否该换行（WrapLayout 会把分隔线当成普通卡片贴在前一行末尾）。
        // stackPanel 自身实现 Scrollable + tracksViewportWidth=true：让 JScrollPane 把宽度钉在视口宽，
        // 避免下层 builtInGrid（WrapLayout 在 width=0 时算成"一行铺所有卡片"）撑出横向滚动条。
        JPanel stackPanel = new SkillsStackPanel();
        stackPanel.setLayout(new BoxLayout(stackPanel, BoxLayout.Y_AXIS));
        stackPanel.setOpaque(false);
        stackPanel.add(builtInGrid);
        // dividerPanel 一开始就放在栈里；空用户列表时 userGrid 高度为 0，不影响视觉。
        stackPanel.add(dividerPanel);
        stackPanel.add(userGrid);
        // 关键：让两个网格的 max width 撑满 stackPanel（BoxLayout 按 max 决定 X 是否拉伸）。
        builtInGrid.setMaximumSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));
        userGrid.setMaximumSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));
        dividerPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 40));

        JScrollPane scrollPane = new JScrollPane(stackPanel);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);

        // JLayeredPane：DEFAULT 层放滚动面板，POPUP 层放 Toast。
        // Toast 锚定右下角（参 Toast.reposition()），不会随滚动面板的滚动而移动。
        // 状态栏放在 listCard 的 BorderLayout.SOUTH 而非 layeredPane 里，避免 Toast 与状态栏视觉重叠。
        contentLayeredPane.setLayout(null); // 手工控制各层 bounds
        scrollPane.setBounds(0, 0, 1, 1);
        contentLayeredPane.add(scrollPane, JLayeredPane.DEFAULT_LAYER);
        contentLayeredPane.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                scrollPane.setBounds(0, 0, contentLayeredPane.getWidth(), contentLayeredPane.getHeight());
            }
        });
        listCard.add(contentLayeredPane, BorderLayout.CENTER);

        this.toast = new Toast(contentLayeredPane);
        contentLayeredPane.add(toast, JLayeredPane.POPUP_LAYER);

        statusLabel.setBorder(BorderFactory.createEmptyBorder(8, 2, 0, 2));
        statusLabel.setForeground(new Color(120, 120, 120));
        listCard.add(statusLabel, BorderLayout.SOUTH);

        // CardLayout：先放列表卡；详情卡按需 add 并 show。
        add(listCard, CARD_LIST);

        reload();

        // I18n
        I18n.get().onChange(i18nListener);
    }

    /** I18n 语言切换监听器：close() 时注销。 */
    private final java.util.function.Consumer<com.auditai.burp.ai.PromptBuilder.Lang> i18nListener =
            lang -> refreshI18n();

    /**
     * 释放资源：插件卸载时调用。取消在飞行的扫描任务、注销 I18n 监听器、
     * 关闭 Toast（释放守护线程），避免后台 SwingWorker 继续引用已卸载的 UI。
     */
    public void close() {
        if (loadInFlight != null && !loadInFlight.isDone()) {
            loadInFlight.cancel(true);
        }
        I18n.get().off(i18nListener);
        toast.close();
    }

    /**
     * "添加技能"按钮回调：弹文件选择器 → 让用户确认 id → 写入 store → 重新加载网格。
     *
     * <p>全程在 EDT 上同步进行；最重的操作（{@link SkillLoader#load()}）仍走 SwingWorker，
     * 避免大目录扫描时 UI 卡顿。</p>
     */
    void onAddSkillClicked() {
        if (customSkillStore == null) {
            return;
        }
        Path userDir = customSkillStore.rootDirectory();
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle(I18n.get().t("ui.skills.add.dialogTitle"));
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        chooser.setMultiSelectionEnabled(false);
        chooser.setFileFilter(new FileNameExtensionFilter(
                I18n.get().t("ui.skills.add.filterDescription"), "md"));
        if (userDir != null && Files.isDirectory(userDir)) {
            // 优先把对话框定位到 custom-skills/：用户刚卸载一个，下一次想装回去更顺手。
            chooser.setCurrentDirectory(userDir.toFile());
        }
        int result = chooser.showOpenDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }
        Path picked = chooser.getSelectedFile() == null ? null : chooser.getSelectedFile().toPath();
        if (picked == null) {
            return;
        }
        String content;
        try {
            content = Files.readString(picked, StandardCharsets.UTF_8);
        } catch (java.io.IOException ex) {
            showErrorDialog("ui.skills.add.readError", ex.getMessage());
            return;
        }
        // 解析 SKILL.md 抽 name → 派生 id → 直接 install；不再弹 id 输入框。
        // SkillLoader.parseForInstallCheck 返回的 Skill.id 就是传入的 id，
        // 这里我们只取它的 name() 字段。
        String derivedName = extractNameFromContent(content);
        if (derivedName == null) {
            showErrorDialog("ui.skills.add.invalidId",
                    I18n.get().t("ui.skills.add.noName"));
            return;
        }
        String id = CustomSkillStore.suggestIdFromName(derivedName);
        if (id == null) {
            showErrorDialog("ui.skills.add.invalidId",
                    I18n.get().t("ui.skills.add.noName"));
            return;
        }
        java.nio.file.Path target;
        try {
            target = customSkillStore.install(id, content, true);
        } catch (java.io.IOException ex) {
            showErrorDialog("ui.skills.add.installError", ex.getMessage());
            return;
        }
        // 实际写入的目录名（可能因冲突自动追加 -2/-3 后缀），从返回路径的父目录名取
        String actualId = target.getParent().getFileName().toString();
        if (actualId.equals(id)) {
            flashStatus(I18n.get().t("ui.skills.add.success", id));
        } else {
            // 自动重命名了——明确告诉用户
            flashStatus(I18n.get().t("ui.skills.add.successRenamed", id, actualId));
        }
        reload();
    }

    /**
     * 用 {@link SkillLoader#parseForInstallCheck} 解析 SKILL.md 文本，只取 name 字段。
     * 解析失败返回 null（让上层报错"缺 name"）。
     */
    private static String extractNameFromContent(String content) {
        Skill parsed = SkillLoader.parseForInstallCheck("probe", content);
        if (parsed == null) {
            return null;
        }
        String name = parsed.name();
        return (name == null || name.isBlank()) ? null : name;
    }

    /**
     * 卸载用户技能回调：弹确认对话框 → 用户确认后调 store 卸载 → 重新加载。
     *
     * <p>二次确认（{@link JOptionPane#showConfirmDialog}）防误删；用户点"取消"或
     * 直接关窗都不动数据。</p>
     */
    void onUninstall(Skill skill) {
        if (customSkillStore == null || skill.source() != SkillSource.USER) {
            return;
        }
        int answer = JOptionPane.showConfirmDialog(this,
                I18n.get().t("ui.skills.uninstall.confirm", skill.name()),
                I18n.get().t("ui.skills.uninstall.title"),
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);
        if (answer != JOptionPane.YES_OPTION) {
            return;
        }
        try {
            customSkillStore.uninstall(skill.id());
        } catch (java.io.IOException ex) {
            showErrorDialog("ui.skills.uninstall.error", ex.getMessage());
            return;
        }
        // 同步清理启用态与自动激活态：避免下次启动仍把它当作"已启用 / 自动激活"，但目录已不存在。
        enabledIds.remove(skill.id());
        if (pinnedIds.remove(skill.id())) {
            stateStore.savePinnedIds(extractPinnedIds());
        }
        stateStore.saveEnabledIds(extractEnabledIds());
        flashStatus(I18n.get().t("ui.skills.uninstall.success", skill.id()));
        reload();
    }

    /**
     * 错误对话框：操作失败时直接弹一个阻塞的 JOptionPane（用户期望明确感知错误）。
     * 不走 Toast——错误是异常路径，应该用更强的视觉信号让用户注意到。
     */
    private void showErrorDialog(String i18nKey, String detail) {
        JOptionPane.showMessageDialog(this,
                I18n.get().t(i18nKey, detail == null ? "" : detail),
                I18n.get().t("ui.skills.uninstall.title"),
                JOptionPane.ERROR_MESSAGE);
    }

    /**
     * 成功反馈：在面板右下角弹一个 Toast（约 3 秒后淡出）。
     * 与 SettingsPanel 等模块共用同一组件，交互一致性 + 不打断用户当前操作。
     */
    private void flashStatus(String message) {
        toast.show(message);
    }

    /** 当前在飞行的技能扫描 SwingWorker。 */
    private SwingWorker<List<Skill>, Void> loadInFlight;

    /** 顶部页头：标题 + （计数 + 添加按钮） 同行。 */
    private JPanel buildHeader() {
        JPanel header = new JPanel();
        header.setLayout(new BoxLayout(header, BoxLayout.Y_AXIS));
        header.setOpaque(false);
        // 左侧留白 12px：与技能卡片网格的 WrapLayout hgap(12) 对齐，
        // 让标题 / 按钮行与下方卡片的左边缘在同一竖线上。
        header.setBorder(BorderFactory.createEmptyBorder(0, 12, 12, 2));

        JLabel title = headerTitle;
        title.setFont(title.getFont().deriveFont(Font.BOLD, 18f));
        title.setAlignmentX(Component.LEFT_ALIGNMENT);
        title.setText(I18n.get().t("ui.tab.skills"));
        header.add(title);

        header.add(Box.createVerticalStrut(16));

        // 第二行：左侧"添加技能"按钮 + 计数文字（按钮紧贴计数文字左边）。
        JPanel countRow = new JPanel();
        countRow.setLayout(new BoxLayout(countRow, BoxLayout.X_AXIS));
        countRow.setOpaque(false);
        countRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        countRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 32));

        if (customSkillStore != null) {
            // 仅当 customSkillStore 可用时显示"添加技能"按钮：
            // 1) toast 通道可复用，2) 用户数据目录可写。
            addSkillButton.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            addSkillButton.setAlignmentY(Component.CENTER_ALIGNMENT);
            addSkillButton.addActionListener(e -> onAddSkillClicked());
            countRow.add(addSkillButton);
            countRow.add(Box.createHorizontalStrut(10));
        }
        countLabel.setAlignmentY(Component.CENTER_ALIGNMENT);
        countRow.add(countLabel);
        countRow.add(Box.createHorizontalGlue());
        header.add(countRow);
        return header;
    }

    /**
     * 重新扫描并刷新整个网格：清空旧卡片、把每个技能渲染为 {@link SkillCard}，更新计数与状态。
     *
     * <p>{@link #render} 只在空态 / 错误分支刷新 {@link #statusLabel}；非空分支保留现有
     * 文本，由 {@link #flashStatus} 触发的 Toast/Timer 自行管理生命周期——避免一次成功
     * 提示被紧接着的扫描覆盖。</p>
     */
    public void reload() {
        // 取消上一轮未完成的扫描，避免旧任务回调覆盖新一次扫描的渲染结果。
        if (loadInFlight != null && !loadInFlight.isDone()) {
            loadInFlight.cancel(true);
        }
        loadInFlight = new SwingWorker<List<Skill>, Void>() {
            @Override
            protected List<Skill> doInBackground() {
                return loader.load();
            }

            @Override
            protected void done() {
                // 已被新一次扫描/卸载路径取消时不再渲染（避免陈旧数据覆盖新结果）。
                if (isCancelled()) {
                    return;
                }
                try {
                    render(get());
                } catch (Exception e) {
                    builtInGrid.removeAll();
                    userGrid.removeAll();
                    statusLabel.setText(I18n.get().t("ui.skills.loadFailed", e.getMessage()));
                }
            }
        };
        loadInFlight.execute();
    }

    /** 用最新技能列表重建网格：内置技能在上，分割线（仅当有用户技能时），用户技能在下。 */
    private void render(List<Skill> skills) {
        builtInGrid.removeAll();
        userGrid.removeAll();
        cardsById.clear();
        if (skills.isEmpty()) {
            statusLabel.setText(I18n.get().t("ui.skills.empty", I18n.get().t("ui.common.refresh")));
            dividerPanel.setVisible(false);
        } else {
            // 把内置与用户分开：内置先行（保持 SkillLoader 字典序），用户后续追加。
            // 非空分支保留 statusLabel 现有文本，flashStatus 的成功提示由 Toast/Timer 自行管理。
            List<Skill> builtins = new java.util.ArrayList<>();
            List<Skill> userSkills = new java.util.ArrayList<>();
            for (Skill s : skills) {
                if (s.source() == SkillSource.USER) {
                    userSkills.add(s);
                } else {
                    builtins.add(s);
                }
            }
            for (Skill skill : builtins) {
                addSkillCard(skill, builtInGrid);
            }
            for (Skill skill : userSkills) {
                addSkillCard(skill, userGrid);
            }
            // 没有用户技能时隐藏分隔线（避免出现"自定义"标签下面空空如也的尴尬）
            dividerPanel.setVisible(!userSkills.isEmpty());
        }
        // 让 WrapLayout 的"行数 = ceil(count/columns)"立即生效，避免空状态切回非空后高度没刷新。
        builtInGrid.revalidate();
        builtInGrid.repaint();
        userGrid.revalidate();
        userGrid.repaint();
        // 计数：用 size + enabledIds.size() 即可，不重复遍历 skills。
        int total = skills.size();
        if (total > 0) {
            int enabledCount = 0;
            for (Skill s : skills) {
                if (Boolean.TRUE.equals(enabledIds.get(s.id()))) {
                    enabledCount++;
                }
            }
            countLabel.setText(formatCount(total, enabledCount));
        }
    }

    /** 渲染单个技能卡片：把卡片塞进指定网格容器 + cardsById。 */
    private void addSkillCard(Skill skill, SkillGridPanel target) {
        boolean enabled = Boolean.TRUE.equals(enabledIds.get(skill.id()));
        boolean pinned = pinnedIds.contains(skill.id());
        SkillCard card = new SkillCard(skill, enabled, pinned,
                SkillsPanel.this::showSkillDetails,
                SkillsPanel.this::onToggle,
                SkillsPanel.this::onPin,
                customSkillStore == null ? null : SkillsPanel.this::onUninstall);
        cardsById.put(skill.id(), card);
        target.add(card);
    }

    /**
     * 内置 / 用户分割线：横贯整个内容栈宽度，左侧小标签 + 右侧细线。
     *
     * <p>用自定义 paintComponent 直接把标签画在 (8, vertical-center)、把细线画在
     * (labelWidth, vertical-center) 到 (width, vertical-center)。完全绕开 BorderLayout /
     * BoxLayout 在不同 L&F 与容器尺寸下"标签被推到中间"的隐式分配问题。</p>
     */
    private static JPanel buildSectionDivider() {
        return new DividerPanel();
    }

    /**
     * 自绘分隔线面板：
     * <ul>
     *   <li>文字"自定义"在 x=8 垂直居中；</li>
     *   <li>细线从标签右侧 8px 处到面板右边缘；</li>
     *   <li>用 {@link JSeparator} 取主题色（避免硬编码让暗色主题下看不见）。</li>
     * </ul>
     */
    private static final class DividerPanel extends JPanel {
        @Serial
        private static final long serialVersionUID = 1L;

        // 左侧贴齐 stackPanel 起点（即 listCard 内容区最左边缘），让"自定义"标签
        // 视觉上完全左对齐。卡片左边因 WrapLayout 的 hgap(12) 会比标签靠右 12px，
        // 这是卡片之间的最小间距，刻意保留——否则卡片之间没间距也不美观。
        private static final int LEFT_PADDING = 12;
        private static final int RIGHT_PADDING = 12;
        private static final int GAP_AFTER_LABEL = 12;
        private static final int LINE_THICKNESS = 1;
        private static final int V_PADDING = 10;

        DividerPanel() {
            setOpaque(false);
            // 占位文字用于宽度测量：paintComponent 里自己画，但 preferredSize 要有合理值
            // 让 BoxLayout 能算出 divider 行高（=字号 + 上下 10px 留白）。
            JLabel probe = new JLabel(I18n.get().t("ui.skills.section.user"));
            probe.setFont(probe.getFont().deriveFont(Font.PLAIN, 12f));
            Dimension pref = probe.getPreferredSize();
            int height = pref.height + V_PADDING * 2;
            setPreferredSize(new Dimension(0, height));
            setMaximumSize(new Dimension(Integer.MAX_VALUE, height));
            setMinimumSize(new Dimension(0, height));
            // BoxLayout(Y_AXIS) 的横轴是"对齐线"分配：本栈里的 builtInGrid / userGrid 都是默认
            // CENTER_ALIGNMENT(0.5)，整列对齐线落在容器水平中点。这里若用 LEFT_ALIGNMENT(0.0)，
            // 面板会被 BoxLayout 推到对齐线右侧（偏移 = 半宽），导致"自定义"标签与分割线都从
            // 水平中点开始、左边空出半屏空白。只有 CENTER_ALIGNMENT + 最大宽 Integer.MAX_VALUE
            // 才能让 BoxLayout 把面板拉伸到整列宽度且 x=0 贴左，paintComponent 里 LEFT_PADDING=0 才生效。
            setAlignmentX(Component.CENTER_ALIGNMENT);
        }

        @Override
        protected void paintComponent(java.awt.Graphics g) {
            super.paintComponent(g);
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                g2.setRenderingHint(java.awt.RenderingHints.KEY_ANTIALIASING,
                        java.awt.RenderingHints.VALUE_ANTIALIAS_ON);

                // 取主题色：暗色主题下默认 SeparatorColor 已是浅灰，直接用即可
                // （避免硬编码 Color(220,224,230) 在暗色 Burp 主题下变白线）。
                Color separatorColor = UIManager.getColor("Separator.foreground");
                if (separatorColor == null) {
                    separatorColor = UIManager.getColor("Separator.background");
                }
                if (separatorColor == null) {
                    separatorColor = new Color(220, 224, 230);
                }

                // 文字样式：跟原 JLabel 一致
                Font font = getFont().deriveFont(Font.PLAIN, 12f);
                g2.setFont(font);
                FontMetrics fm = g2.getFontMetrics();
                int textY = (getHeight() - fm.getHeight()) / 2 + fm.getAscent();
                String text = I18n.get().t("ui.skills.section.user");

                // 1. 画文字（左对齐到 LEFT_PADDING）
                g2.setColor(new Color(140, 140, 140));
                g2.drawString(text, LEFT_PADDING, textY);

                // 2. 画细线：从文字右侧 GAP_AFTER_LABEL 像素开始，到面板右 - RIGHT_PADDING
                int lineStartX = LEFT_PADDING + fm.stringWidth(text) + GAP_AFTER_LABEL;
                int lineEndX = getWidth() - RIGHT_PADDING;
                if (lineEndX > lineStartX) {
                    int lineY = getHeight() / 2;
                    g2.setColor(separatorColor);
                    g2.fillRect(lineStartX, lineY - LINE_THICKNESS / 2,
                            lineEndX - lineStartX, LINE_THICKNESS);
                }
            } finally {
                g2.dispose();
            }
        }
    }

    /**
     * 收到卡片的"切换启用态"回调：先记到注册表，立刻持久化，再让卡片自己重画。
     * SkillCard 在自己的右键菜单里已经调过 setEnabled 刷新了 UI，
     * 这里只负责把"全局状态"和"持久化"职责收口。
     *
     * <p><b>同步清理自动激活：</b>若用户从"自动激活"卡片选了"禁用"，SkillCard.setSkillEnabled(false)
     * 已同步清掉本地 pinned 字段；这里也要同步把 id 从 pinnedIds 集合移除并持久化，
     * 否则下次启动会出现"pinned=true 但 enabled=false"的脏状态。</p>
     */
    void onToggle(Skill skill, boolean enabled) {
        if (enabled) {
            enabledIds.put(skill.id(), Boolean.TRUE);
        } else {
            enabledIds.remove(skill.id());
            // 同步清掉 pinned：禁用与自动激活互斥。
            if (pinnedIds.remove(skill.id())) {
                stateStore.savePinnedIds(extractPinnedIds());
                syncCardPinState(skill.id(), false);
            }
        }
        // 立刻持久化当前状态：用户改一次就脱离"首次安装"分支，避免下次启动被默认值覆盖。
        stateStore.saveEnabledIds(extractEnabledIds());
        // 重新计算"已启用 N"文案：直接用 enabledIds / cardsById 的 size，
        // 不再为拿个计数重建 skill 列表（避免每点一次右键做 N 次 map lookup）。
        int total = cardsById.size();
        if (total > 0) {
            int enabledCount = 0;
            for (Boolean v : enabledIds.values()) {
                if (Boolean.TRUE.equals(v)) {
                    enabledCount++;
                }
            }
            countLabel.setText(formatCount(total, enabledCount));
        }
    }

    /**
     * 收到卡片的"切换自动激活态"回调：更新 pinnedIds 集合、持久化。
     *
     * <p>SkillCard 在右键菜单里已经处理了"自动激活隐含启用"的副作用（包括触发
     * {@link #onToggle(Skill, boolean)}），本方法只同步注册表 + 持久化 + 刷新卡片本地
     * 视觉（如果是从其它路径触发的）。</p>
     *
     * <p><b>上限拦截：</b>把第 {@value #MAX_PINNED}+1 个技能设为自动激活时拒绝，
     * 弹 toast 提示用户并把卡片本地状态回滚——避免 UI 出现"卡片已 pin 但注册表没记"的
     * 不一致。解除自动激活时不受此限制。</p>
     *
     * <p><b>解除自动激活时</b>只清掉 pinnedIds，<b>不</b>联动 enabledIds——语义上
     * "取消自动激活"只是不再常驻注入，技能本身仍可处于普通启用态（让用户继续
     * 在 phase 1 候选中看到它）。</p>
     */
    void onPin(Skill skill, boolean pinned) {
        if (pinned) {
            if (pinnedIds.size() >= MAX_PINNED) {
                // 拒绝并回滚：SkillCard 已在 setPinned(true) 里把本地 pinned=true，
                // 这里通过 syncCardPinState 把卡片本地状态退回 false，与未生效的注册表对齐。
                flashStatus(I18n.get().t("ui.skills.pinLimitReached", MAX_PINNED));
                syncCardPinState(skill.id(), false);
                return;
            }
            pinnedIds.add(skill.id());
        } else {
            pinnedIds.remove(skill.id());
        }
        stateStore.savePinnedIds(extractPinnedIds());
        syncCardPinState(skill.id(), pinned);
    }

    /**
     * 把卡片本地的 pinned 字段与全局注册表对齐——右键菜单已通过 setPinned 同步过，
     * 这里用于"卸载导致 id 从 enabledIds 中移除"等场景外的兜底，正常路径下
     * 卡片自身已处于正确状态，重复设置是无副作用的。
     */
    private void syncCardPinState(String id, boolean pinned) {
        SkillCard card = cardsById.get(id);
        if (card != null && card.isPinned() != pinned) {
            card.setPinned(pinned);
        }
    }

    /** 从注册表抽出所有 pinned id（保持插入顺序）。 */
    private Set<String> extractPinnedIds() {
        return new LinkedHashSet<>(pinnedIds);
    }

    /** 顶部"共 N 个技能（已启用 M）" 文案。 */
    private static String formatCount(int total, int enabledCount) {
        return enabledCount == 0
                ? I18n.get().t("ui.skills.count", total)
                : I18n.get().t("ui.skills.countEnabled", total, enabledCount);
    }

    /** 从注册表抽出所有启用 id，按 {@link DefaultEnabledSkill#ids()} 顺序优先、其余 id 按字典序追加。 */
    private Set<String> extractEnabledIds() {
        Set<String> result = new LinkedHashSet<>();
        for (String id : DefaultEnabledSkill.ids()) {
            if (Boolean.TRUE.equals(enabledIds.get(id))) {
                result.add(id);
            }
        }
        // 兜底：把枚举里没列、但用户手动启用的 id 也保留下来
        result.addAll(enabledIds.keySet().stream()
                .filter(id -> Boolean.TRUE.equals(enabledIds.get(id)))
                .sorted()
                .toList());
        return result;
    }

    /**
     * 点击卡片后：把"列表"卡整体替换为"详情"卡，展示技能完整信息。
     * 详情卡上的"← 返回"按钮回调 {@link #showList()} 切回列表。
     */
    void showSkillDetails(Skill skill) {
        // 移除旧的详情卡（如果有），放一张新的——保证每次展示的是最新数据
        for (Component c : getComponents()) {
            if (CARD_DETAIL.equals(c.getName())) {
                remove(c);
            }
        }
        SkillDetailPanel detail = new SkillDetailPanel(skill, this::showList);
        detail.setName(CARD_DETAIL);
        add(detail, CARD_DETAIL);
        cardLayout.show(this, CARD_DETAIL);
    }

    /** 切回技能列表卡。 */
    void showList() {
        cardLayout.show(this, CARD_LIST);
    }
    @Override
    public void refreshI18n() {
        // 页头大标题("技能" / "Skills"):切语言时同步刷新
        headerTitle.setText(I18n.get().t("ui.tab.skills"));
        // 重算计数(其他标题在构造期写死,但技能数据来自 SKILL.md 文件,不翻译)
        int total = cardsById.size();
        if (total > 0) {
            int enabledCount = 0;
            for (Boolean v : enabledIds.values()) {
                if (Boolean.TRUE.equals(v)) {
                    enabledCount++;
                }
            }
            countLabel.setText(enabledCount == 0
                    ? I18n.get().t("ui.skills.count", total)
                    : I18n.get().t("ui.skills.countEnabled", total, enabledCount));
        }
        // 转发给子组件(当前只有详情卡 SkillDetailPanel 实现 LocaleAware):
        // 语言切换时若正停留在技能详情页,直接重建它,避免整页停留在旧语言。
        for (Component child : getComponents()) {
            if (child instanceof LocaleAware aware) {
                try {
                    aware.refreshI18n();
                } catch (RuntimeException ignored) {
                    // 单个组件刷新异常不阻断其他组件
                }
            }
        }
        // 重新构建网格(卡片内菜单项也用 I18n)
        reload();
    }

    /**
     * 内容栈 Scrollable 适配器：把 {@link BoxLayout#Y_AXIS} 包装栈标记为
     * "宽度跟随视口"，让 {@link javax.swing.JScrollPane} 把本栈钉在视口宽度上。
     *
     * <p>为什么需要：栈内 {@link SkillGridPanel} 用 {@link WrapLayout}，
     * WrapLayout 在容器 width=0 时按"一行铺所有卡片"算 preferredSize，会把整排卡片
     * 算成几千像素宽——撑出横向滚动条。让本栈标记 tracksViewportWidth 后，
     * JScrollPane 先把栈 width 钉到视口宽、再让 BoxLayout 把两个网格都拉满到该宽度，
     * 两个网格的 WrapLayout 才能拿到真实宽度做"一行几个"的换行计算。</p>
     */
    private static final class SkillsStackPanel extends JPanel implements javax.swing.Scrollable {
        @Serial
        private static final long serialVersionUID = 1L;

        @Override
        public Dimension getPreferredScrollableViewportSize() {
            return getPreferredSize();
        }

        @Override
        public int getScrollableUnitIncrement(java.awt.Rectangle visibleRect, int orientation, int direction) {
            return orientation == javax.swing.SwingConstants.VERTICAL ? 32 : 64;
        }

        @Override
        public int getScrollableBlockIncrement(java.awt.Rectangle visibleRect, int orientation, int direction) {
            return orientation == javax.swing.SwingConstants.VERTICAL ? visibleRect.height : visibleRect.width;
        }

        @Override
        public boolean getScrollableTracksViewportWidth() {
            return true;
        }

        @Override
        public boolean getScrollableTracksViewportHeight() {
            return false;
        }
    }
}
