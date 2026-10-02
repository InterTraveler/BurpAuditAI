package com.auditai.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Theme;
import com.auditai.burp.http.FindingStore;
import com.auditai.burp.http.TrafficAnalyzer;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Insets;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.Serial;

/**
 * “分析”页签：管理多个报文页签（Repeater 风格）。
 *
 * <p>行为：</p>
 * <ul>
 *   <li>每次从其他模块右键 <b>“Send to AuditAI”</b> → 自动<b>新建一个编号页签</b>
 *       （1、2、3…）填入该报文并选中——<b>不会覆盖之前的报文</b>，可通过页签栏切换；</li>
 *   <li>页签栏<b>末尾的“+”</b>（Repeater 风格）：点击即新建一个空白页签，用于手动粘贴原始报文；</li>
 *   <li>每个页签（{@link MessageTab}）拥有独立的 Request/Response 编辑器、
 *       Analyze/Cancel 按钮与结果区，分析结果互不串扰。</li>
 * </ul>
 */
public final class AnalysisPanel extends JPanel implements LocaleAware {

    @Serial
    private static final long serialVersionUID = 1L;

    /** Burp API 门面（透传给每个 MessageTab 创建原生编辑器）。 */
    private final MontoyaApi api;

    /** 分析编排器（透传给每个 MessageTab）。 */
    private final TrafficAnalyzer analyzer;

    /**
     * 全局问题库：每个 MessageTab 完成分析后，把 finding 列表写入这里。
     * 为 null 时（findingStore 创建失败等）跳过写入。
     */
    private final FindingStore findingStore;

    /**
     * 分析完成回调：每个 MessageTab 完成分析后透传给它的"历史"页签 / 其它消费者；
     * 为 null 时 MessageTab 用 no-op hook（不向其它 store 通知）。
     *
     * <p>非 final：允许装配阶段先 new AnalysisPanel（构造期 hook 已知），
     * 也允许通过 {@link #setOnAnalysisCompleted} 在面板已存在时再注入
     * （典型场景：装配方先 addTab 再回填 hook）。</p>
     */
    private MessageTab.AnalysisResultHook onAnalysisCompleted;

    /** 报文页签容器：每页一个 MessageTab，标题为编号。 */
    private final JTabbedPane messageTabs = new JTabbedPane();

    /** 末尾的“+”占位页签：被选中时新建一个空白报文页签（始终保持在最后）。 */
    private final JPanel plusPlaceholder = new JPanel();

    /** 页签编号（从 1 递增）。仅在 EDT 内修改，无需并发保护。 */
    private int tabCounter = 0;

    /**
     * 建页签重入保护标志。
     * JDK 的 JTabbedPane.insertTab 在插入位置 &lt;= 当前选中索引时，会执行
     * model.setSelectedIndex(选中索引+1) 并触发 stateChanged 事件；
     * “+”监听器若在此时再次建页签，会形成无限递归（页签暴增）。该标志阻止重入。
     */
    private boolean creatingTab = false;

    /**
     * 同一"发送"动作重复触发的合并窗口（毫秒）。
     * Burp 的上下文菜单在个别版本/场景下点击一次会偶发多次 ActionEvent，
     * 若每次都新建页签会一次生成 1、2、3… 多个页签（表现为页面爆满、卡顿）。
     * 窗口内仅合并<b>指纹相同</b>的重复事件（同一报文），不同报文的连续发送不受影响。
     */
    private static final long ACCEPT_DEBOUNCE_MS = 300L;

    /** 上一次通过 acceptMessage 新建页签的时间（毫秒）。仅 EDT 内读写。 */
    private long lastAcceptAt = 0L;

    /** 上一次通过 acceptMessage 新建页签的报文指纹。仅 EDT 内读写。 */
    private String lastAcceptFingerprint = "";

    /** 最大页签数：防止异常场景下页签失控增长拖垮界面（每个页签含 2 个 Burp 原生编辑器）。 */
    private static final int MAX_TABS = 100;

    /**
     * 简化构造器（兼容历史用法）：不挂分析完成回调。
     */
    public AnalysisPanel(MontoyaApi api, TrafficAnalyzer analyzer, FindingStore findingStore) {
        this(api, analyzer, findingStore, null);
    }

    /**
     * @param api                 Burp API 门面（创建原生编辑器）。
     * @param analyzer            分析编排器。
     * @param findingStore        全局问题库；为 null 时不做 finding 收集（兼容历史用法）。
     * @param onAnalysisCompleted 分析完成回调（透传到每个 MessageTab）；可为 null。
     */
    public AnalysisPanel(MontoyaApi api, TrafficAnalyzer analyzer, FindingStore findingStore,
                         MessageTab.AnalysisResultHook onAnalysisCompleted) {
        super(new BorderLayout());
        this.api = api;
        this.analyzer = analyzer;
        this.findingStore = findingStore;
        this.onAnalysisCompleted = onAnalysisCompleted;

        // —— 顶部：操作提示（新建入口已改为页签栏末尾的“+”） ——
        JLabel hint = I18n.label("ui.analysis.hint");
        add(hint, BorderLayout.NORTH);

        // —— 中部：报文页签容器 ——
        // 末尾“+”页签：始终保持在最后；被选中时创建真实页签并选中它。
        // 注意：insertTab 会因选中索引后移触发 stateChanged（见 creatingTab 注释），
        // 因此建页签统一走 safeAddTab()，由 creatingTab 标志阻止递归。
        messageTabs.setOpaque(true);
        messageTabs.setBackground(panelBackground());
        // Burp/FlatLaf 会给 JTabbedPane 默认预留左右 tabInsets，正是页签间距偏大的主要来源。
        // 通过组件级 client property 清零，避免修改全局 UIManager 影响 Burp 其他界面。
        messageTabs.putClientProperty("JTabbedPane.tabInsets", new Insets(0, 0, 0, 0));
        messageTabs.putClientProperty("JTabbedPane.tabAreaInsets", new Insets(0, 0, 0, 0));
        messageTabs.putClientProperty("JTabbedPane.selectedTabPadInsets", new Insets(0, 0, 0, 0));
        messageTabs.addTab("+", plusPlaceholder);
        messageTabs.setTabComponentAt(0, createPlusTabComponent());
        messageTabs.addChangeListener(changeListener);
        api.userInterface().applyThemeToComponent(messageTabs);
        messageTabs.setBackground(panelBackground());
        add(messageTabs, BorderLayout.CENTER);

        // I18n:本面板与插件同生命周期,close() 里注销避免卸载后常驻引用。
        I18n.get().onChange(i18nListener);
    }

    /** “+”页签同样使用自定义标题组件，给加号左右增加内边距，扩大鼠标可点击区域。 */
    private JPanel createPlusTabComponent() {
        JPanel plusTab = new JPanel(new BorderLayout());
        plusTab.setOpaque(false);
        plusTab.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));

        JLabel plusLabel = new JLabel("+");
        plusLabel.setHorizontalAlignment(JLabel.CENTER);
        plusLabel.setForeground(Color.BLACK);
        Font tabFont = api.userInterface().currentDisplayFont();
        if (tabFont != null) {
            plusLabel.setFont(tabFont.deriveFont(Font.BOLD));
        }
        plusLabel.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (messageTabs.getSelectedComponent() == plusPlaceholder) {
                    // 初始状态只有一个“+”页签，它已经处于选中状态；再次点击不会触发
                    // change event，因此这里直接创建新页签。
                    safeAddTab();
                } else {
                    messageTabs.setSelectedComponent(plusPlaceholder);
                }
            }
        });

        plusTab.add(plusLabel, BorderLayout.CENTER);
        return plusTab;
    }

    /**
     * 从其他模块（上下文菜单）接收报文：新建一个编号页签并填入，自动选中。
     * 可在任意线程调用：内部切回 EDT。
     *
     * <p>防抖：同一次右键动作若被 Burp 重复触发（短时间内多次调用且报文指纹相同），
     * 只新建一次页签；不同报文的连续发送不受 300ms 窗口限制。</p>
     *
     * @param message 请求/响应快照。
     */
    public void acceptMessage(HttpRequestResponse message) {
        SwingUtilities.invokeLater(() -> {
            long now = System.currentTimeMillis();
            String fingerprint = fingerprint(message);
            if (now - lastAcceptAt < ACCEPT_DEBOUNCE_MS
                    && fingerprint.equals(lastAcceptFingerprint)) {
                // 同一报文的重复事件：丢弃（页签已由第一次事件创建）
                return;
            }
            lastAcceptAt = now;
            lastAcceptFingerprint = fingerprint;

            MessageTab tab = safeAddTab();
            if (tab != null) {
                tab.setMessage(message);
            }
        });
    }

    /**
     * 生成报文的轻量指纹（method + url + body hash），用于识别"同一报文的重复右键事件"。
     * 不同报文（哪怕 URL 相同但 body 不同）会得到不同指纹，不会被误合并。
     */
    private static String fingerprint(HttpRequestResponse message) {
        HttpRequest request = message != null ? message.request() : null;
        if (request == null) {
            return "";
        }
        return request.method() + "|" + request.url() + "|"
                + java.util.Arrays.hashCode(request.body().getBytes());
    }

    /** 带重入保护的建页签入口（“+”监听器与发送路径共用）。 */
    private MessageTab safeAddTab() {
        if (creatingTab) {
            return null; // 正处于建页签流程（insertTab 触发 stateChanged 重入），忽略
        }
        creatingTab = true;
        try {
            return addMessageTab();
        } finally {
            creatingTab = false;
        }
    }

    /**
     * 注册分析完成回调：影响后续新建的 MessageTab。已有页签不回填
     * （它们的 hook 已在构造期确定）。典型场景：装配阶段构造 AnalysisPanel
     * 时 hook 还未就绪，addTab 之后再用本方法回填。
     */
    public void setOnAnalysisCompleted(MessageTab.AnalysisResultHook hook) {
        this.onAnalysisCompleted = hook;
    }

    /** 新建一个空白报文页签（编号自增，插入到末尾“+”页签之前）并选中。 */
    private MessageTab addMessageTab() {
        if (tabCounter >= MAX_TABS) {
            // 上限保护：拒绝继续创建，避免界面失控（异常重复触发时兜底）
            // 走 DEBUG 通道：避免异常重复触发时刷屏，开发期开 -Dauditai.debug.prompt 可见。
            if (Boolean.getBoolean("auditai.debug.prompt")) {
                api.logging().logToOutput("AuditAI [DEBUG]: tab limit ("
                        + MAX_TABS + ") reached, stop creating.");
            }
            return null;
        }
        tabCounter++;
        MessageTab tab = new MessageTab(api, analyzer, findingStore, tabCounter, onAnalysisCompleted);
        int insertIndex = messageTabs.getTabCount() - 1; // 插到“+”页签之前
        messageTabs.insertTab(String.valueOf(tabCounter), null, tab, null, insertIndex);
        messageTabs.setTabComponentAt(insertIndex, new TabHeader(tab, String.valueOf(tabCounter)));
        messageTabs.setSelectedComponent(tab);
        return tab;
    }

    /**
     * 刷新所有报文页签的关闭按钮可见性：只有当前选中的页签显示“×”，
     * 其余页签隐藏，与 Burp Repeater 的行为一致。
     */
    private void refreshCloseButtons() {
        Component selected = messageTabs.getSelectedComponent();
        for (int i = 0; i < messageTabs.getTabCount(); i++) {
            Component tabComponent = messageTabs.getTabComponentAt(i);
            if (tabComponent instanceof TabHeader header) {
                header.setCloseVisible(messageTabs.getComponentAt(i) == selected);
            }
        }
    }

    /** 关闭指定报文页签：先中断其分析任务，再从页签栏移除。 */
    private void closeMessageTab(MessageTab tab) {
        int index = messageTabs.indexOfComponent(tab);
        if (index < 0) {
            return;
        }
        tab.close();
        messageTabs.removeTabAt(index);
    }

    /**
     * I18n 语言切换监听器：close() 时注销。
     */
    private final java.util.function.Consumer<com.auditai.burp.ai.PromptBuilder.Lang> i18nListener =
            lang -> refreshI18n();

    /**
     * JTabbedPane 切换监听器：close() 时注销，避免外部匿名 lambda 持有本面板的引用。
     */
    private final javax.swing.event.ChangeListener changeListener = e -> {
        refreshCloseButtons();
        if (messageTabs.getSelectedComponent() == plusPlaceholder) {
            safeAddTab();
        }
    };

    /**
     * 释放资源：插件卸载时调用。关闭所有页签内的分析任务，避免后台执行器
     * 继续引用已被卸载的编辑器；注销 I18n 监听器，避免本面板被常驻引用。
     */
    public void close() {
        for (int i = 0; i < messageTabs.getTabCount(); i++) {
            Component c = messageTabs.getComponentAt(i);
            if (c instanceof MessageTab tab) {
                tab.close();
            }
        }
        // 对称注销：JTabbedPane 内部 ChangeEvent 监听器若不摘，messageTabs 字段会
        // 持续强引用 changeListener，进而锚住整个 AnalysisPanel 实例。
        messageTabs.removeChangeListener(changeListener);
        I18n.get().off(i18nListener);
    }

    /** 页签条底色：与 Burp 当前面板背景一致，只有页签块本身显示灰色。 */
    private Color panelBackground() {
        Color panelColor = UIManager.getColor("Panel.background");
        return panelColor != null ? panelColor : messageTabs.getBackground();
    }

    /** 单个页签块的灰色背景。 */
    private Color tabSurfaceBackground() {
        return api.userInterface().currentTheme() == Theme.DARK
                ? new Color(60, 63, 65)
                : new Color(240, 240, 240);
    }

    /**
     * Repeater 风格的页签标题组件。
     *
     * <p>非编辑态使用 {@link JLabel} 显示标题，因此点击标题时事件会正常交给
     * {@link JTabbedPane} 处理，不会像 JTextField 那样吞掉点击导致页签无法切换；
     * 双击标题后切到同尺寸的编辑框进行重命名。</p>
     */
    private final class TabHeader extends JPanel {

        /** 序列化版本号。 */
        @Serial
        private static final long serialVersionUID = 1L;

        /** 页签当前显示的标题文本（可为默认编号或用户重命名后的名称）。 */
        private String title;

        /**
         * 用户是否重命名过本页签（进过编辑态并提交）。
         *
         * <p>未重命名时标题 tooltip 是"双击重命名"提示文案（需随语言切换刷新）；
         * 重命名后 tooltip 改为展示完整标题（截断时悬停看全名，非翻译文案），
         * 语言切换时保持不变。</p>
         */
        private boolean renamed;

        /** 对应的报文面板。 */
        private final MessageTab tab;

        /** 标题区两种状态的切换器。 */
        private final CardLayout titleLayout = new CardLayout();
        private final JPanel titleCards = new JPanel(titleLayout);

        /** 非编辑态的只读标题。 */
        private final JLabel titleLabel = new JLabel();

        /** 编辑态输入框，大小与标题标签保持一致。 */
        private final JTextField titleEditor = new JTextField();

        /** 仅当前选中页签可见的关闭按钮。 */
        private final JButton closeButton = new JButton("×");

        private TabHeader(MessageTab tab, String initialTitle) {
            super(new BorderLayout(0, 0));
            this.tab = tab;
            this.title = initialTitle;

            // 外层是页签条底色；左右留白会露出页签条颜色，形成 Repeater 的“页签之间有间隔”效果。
            setOpaque(true);
            setBackground(panelBackground());
            setBorder(BorderFactory.createEmptyBorder(0, 2, 0, 2));

            // 内层才是真正的灰色页签块：背景统一使用当前主题的灰色，文字/按钮都放在这个块里。
            JPanel tabSurface = new JPanel(new BorderLayout(6, 0));
            tabSurface.setOpaque(true);
            tabSurface.setBackground(tabSurfaceBackground());
            tabSurface.setBorder(BorderFactory.createEmptyBorder(1, 6, 1, 6));

            Font tabFont = api.userInterface().currentDisplayFont();
            if (tabFont != null) {
                titleLabel.setFont(tabFont);
                titleEditor.setFont(tabFont);
            }

            titleLabel.setText(title);
            titleLabel.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));
            titleLabel.setForeground(Color.BLACK);
            titleLabel.setToolTipText(I18n.get().t("ui.analysis.tabHeader"));
            titleLabel.addMouseListener(new MouseAdapter() {
                @Override
                public void mousePressed(MouseEvent e) {
                    // JLabel 不会像 JTextField 那样吞掉点击，但自定义 TabComponent 内的子组件
                    // 不会自动把鼠标事件转发给 JTabbedPane。这里显式切换到当前页签，
                    // 保证点击标题文字本身也能完成页签选择。
                    messageTabs.setSelectedComponent(tab);
                }

                @Override
                public void mouseClicked(MouseEvent e) {
                    if (e.getClickCount() == 2) {
                        startEditing();
                    }
                }
            });

            titleEditor.setBorder(BorderFactory.createEmptyBorder());
            titleEditor.setOpaque(false);
            titleEditor.setMargin(new java.awt.Insets(2, 4, 2, 4));
            titleEditor.setForeground(Color.BLACK);
            titleEditor.addActionListener(e -> commitEditing());
            titleEditor.addFocusListener(new java.awt.event.FocusAdapter() {
                @Override
                public void focusLost(java.awt.event.FocusEvent e) {
                    commitEditing();
                }
            });
            titleEditor.getDocument().addDocumentListener(new DocumentListener() {
                @Override
                public void insertUpdate(DocumentEvent e) {
                    updateTitleSize(titleEditor.getText());
                }

                @Override
                public void removeUpdate(DocumentEvent e) {
                    updateTitleSize(titleEditor.getText());
                }

                @Override
                public void changedUpdate(DocumentEvent e) {
                    updateTitleSize(titleEditor.getText());
                }
            });

            titleCards.add(titleLabel, "label");
            titleCards.add(titleEditor, "editor");
            titleCards.setOpaque(false);
            tabSurface.add(titleCards, BorderLayout.CENTER);

            styleCloseButton(closeButton, tabFont);
            closeButton.addActionListener(e -> closeMessageTab(tab));
            tabSurface.add(closeButton, BorderLayout.EAST);
            add(tabSurface, BorderLayout.CENTER);

            updateTitleSize(title);
        }

        /**
         * 根据当前标题计算标题区尺寸，并同时应用到标签和编辑框。
         * 这样 CardLayout 切换时页签宽度不会跳动，也不会缩成一个字符。
         */
        private void updateTitleSize(String displayTitle) {
            FontMetrics metrics = titleLabel.getFontMetrics(titleLabel.getFont());
            int textWidth = metrics.stringWidth(displayTitle);
            int width = textWidth + titleLabel.getInsets().left + titleLabel.getInsets().right;
            Dimension size = new Dimension(width, 20);
            titleLabel.setPreferredSize(size);
            titleLabel.setMinimumSize(size);
            titleEditor.setPreferredSize(size);
            titleEditor.setMinimumSize(size);
            revalidate();
            repaint();
        }

        /** 双击标题后进入编辑态：位置和尺寸不变，直接全选原标题供覆盖。 */
        private void startEditing() {
            titleEditor.setText(title);
            titleLayout.show(titleCards, "editor");
            titleEditor.requestFocusInWindow();
            titleEditor.selectAll();
        }

        /** 提交重命名：空白输入回退原标题；非空白则更新页签标题并退出编辑态。 */
        private void commitEditing() {
            if (!titleEditor.isShowing()) {
                return;
            }
            String newTitle = titleEditor.getText().trim();
            if (newTitle.isEmpty()) {
                newTitle = title;
            }
            title = newTitle;
            this.renamed = true;
            titleLabel.setText(title);
            titleLabel.setToolTipText(title);

            int index = messageTabs.indexOfComponent(tab);
            if (index >= 0) {
                messageTabs.setTitleAt(index, title);
            }

            titleLayout.show(titleCards, "label");
            updateTitleSize(title);
        }

        /** 根据外层选中状态显隐“×”。 */
        private void setCloseVisible(boolean visible) {
            closeButton.setVisible(visible);
        }

        /**
         * 语言切换后刷新标题 tooltip：未重命名的页签刷新"双击重命名"提示（跟随语言），
         * 已重命名的页签 tooltip 是完整标题（数据而非文案），保持不变。
         */
        private void refreshTooltipText() {
            if (!renamed) {
                titleLabel.setToolTipText(I18n.get().t("ui.analysis.tabHeader"));
            }
        }
    }

    /** 去掉按钮默认边框与背景，只保留一个紧贴文字的“×”，贴近 Repeater 页签关闭按钮。 */
    private void styleCloseButton(JButton closeButton, Font tabFont) {
        closeButton.setBorderPainted(false);
        closeButton.setContentAreaFilled(false);
        closeButton.setFocusPainted(false);
        closeButton.setOpaque(false);
        closeButton.setRolloverEnabled(false);
        closeButton.setMargin(new java.awt.Insets(0, 0, 0, 0));
        closeButton.setPreferredSize(new Dimension(14, 14));
        // 关闭按钮 tooltip 跟随语言自动刷新(I18n 弱引用订阅,组件销毁后自动清理)。
        I18n.tooltip(closeButton, "ui.analysis.closeTab");
        if (tabFont != null) {
            closeButton.setFont(tabFont.deriveFont(Font.BOLD));
        }
    }
    @Override
    public void refreshI18n() {
        // 顶部 hint 文案:JLabel 已通过 I18n.label 弱引用订阅自动刷新;这里只处理
        // 无法用简单 setText 覆盖的"页签头"组件(重命名 tooltip)。
        for (int i = 0; i < messageTabs.getTabCount(); i++) {
            java.awt.Component tabComponent = messageTabs.getTabComponentAt(i);
            if (tabComponent instanceof TabHeader header) {
                header.refreshTooltipText();
            }
        }
        // Tab 标题编号(1,2,3...)是数据驱动,不翻译。
    }

}
