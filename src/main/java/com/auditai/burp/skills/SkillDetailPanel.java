package com.auditai.burp.skills;

import com.auditai.burp.ui.I18n;
import com.auditai.burp.ui.LocaleAware;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ButtonModel;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingConstants;
import javax.swing.plaf.basic.BasicButtonUI;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Insets;
import java.awt.RenderingHints;
import java.io.Serial;

/**
 * 单个技能的详情视图：取代原 {@code JOptionPane} 弹框，
 * 切换到与技能列表同级的新界面，左上角带"返回"按钮回到原列表。
 *
 * <p>布局：</p>
 * <ul>
 *   <li>顶部工具栏：左上角"← 返回"按钮，点击后通过 {@code onBack} 回调切回列表；</li>
 *   <li>头部：技能图标（左侧大号方块）+ 技能名 + id；</li>
 *   <li>正文（可滚动）：描述、System prompt、User context、历史摘要条数 等所有可用字段，
 *       无内容的字段自动隐藏对应区块。</li>
 * </ul>
 *
 * <p>可滚动正文的存在让超长 prompt / description 不会撑爆界面，
 * 同时保持列表页的标题栏 / 状态栏位置不变（它们属于"列表卡"，本面板不持有）。</p>
 */
public final class SkillDetailPanel extends JPanel implements LocaleAware {

    @Serial
    private static final long serialVersionUID = 1L;

    /** 详情页四周内边距：与列表页保持一致。 */
    private static final int CONTENT_PADDING = 16;

    /** 头部大图标的方块边长。 */
    private static final int ICON_SIDE = 72;

    private static final Color ICON_BACKGROUND = new Color(238, 242, 247);
    private static final Color SECTION_TITLE_COLOR = new Color(80, 80, 80);
    private static final Color SECTION_BG_COLOR = new Color(248, 250, 252);
    private static final Color SUBTLE_COLOR = new Color(120, 120, 120);
    /** Finding type chip 背景：暖米色（贴合整体暖色审美，区别于 section 的冷灰）。 */
    private static final Color CHIP_BG_COLOR = new Color(253, 243, 226);
    /** Finding type chip 文字：暖棕灰。 */
    private static final Color CHIP_TEXT_COLOR = new Color(140, 100, 60);

    /** 持有回调与 skill 引用,refreshI18n 时重建 UI。 */
    private final Runnable onBackRef;
    private final Skill currentSkillRef;

    /**
     * @param skill  要展示的技能数据。
     * @param onBack 用户点击"返回"按钮时触发的回调；用于通知宿主切回列表。
     */
    public SkillDetailPanel(Skill skill, Runnable onBack) {
        super(new BorderLayout());
        this.onBackRef = onBack;
        this.currentSkillRef = skill;
        setBorder(BorderFactory.createEmptyBorder(
                CONTENT_PADDING, CONTENT_PADDING, CONTENT_PADDING, CONTENT_PADDING));

        add(buildToolbar(onBack), BorderLayout.NORTH);
        add(buildContent(skill), BorderLayout.CENTER);
    }

    /** 顶部工具栏：左上一个"← 返回"按钮，靠右留空以备未来扩展。 */
    private JPanel buildToolbar(Runnable onBack) {
        JPanel toolbar = new JPanel();
        toolbar.setLayout(new BoxLayout(toolbar, BoxLayout.X_AXIS));
        toolbar.setOpaque(false);
        toolbar.setBorder(BorderFactory.createEmptyBorder(0, 0, 12, 0));

        toolbar.add(createBackButton(onBack));

        toolbar.add(Box.createHorizontalGlue());
        return toolbar;
    }

    /**
     * 构建胶囊样式的"返回"按钮：白底 + 浅灰描边 + 圆角，hover 变浅蓝/灰、pressed 稍深。
     *
     * <p>视觉参考：白底卡片式导航按钮（← 箭头 + "返回"文字），
     * 颜色克制、圆角较小（≈8px），整体风格接近 Notion / Linear 导航 chip。</p>
     *
     * <p>实现说明：用 {@link BasicButtonUI} 替换默认矩形背景绘制，仅接管背景与描边，
     * 文字/icon 仍走主题渲染——这样在 Burp 主题（FlatLaf）和预览环境（默认 L&F）
     * 下都能呈现一致的圆角效果，不会被 L&F 强制覆盖。</p>
     */
    private JButton createBackButton(Runnable onBack) {
        final Color defaultBg = new Color(255, 255, 255);
        final Color hoverBg = new Color(243, 246, 250);
        final Color pressedBg = new Color(230, 237, 244);
        final Color borderColor = new Color(220, 224, 230);
        final Color textColor = new Color(74, 85, 104);
        final int arc = 8;

        JButton button = I18n.button("ui.skills.detail.back");
        button.setFocusPainted(false);
        button.setForeground(textColor);
        button.setFont(button.getFont().deriveFont(Font.PLAIN, 13f));
        button.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        // 边框留白：左右略宽，让箭头+文字居中看起来更舒展
        button.setBorder(BorderFactory.createEmptyBorder(7, 16, 7, 16));
        button.setMargin(new Insets(0, 0, 0, 0));
        button.setAlignmentX(Component.LEFT_ALIGNMENT);
        button.setHorizontalAlignment(SwingConstants.LEFT);
        // 关闭默认矩形填充，由下方自定义 UI 画圆角背景
        button.setContentAreaFilled(false);
        button.setOpaque(false);

        button.setUI(new BasicButtonUI() {
            @Override
            public void paint(Graphics g, JComponent c) {
                Graphics2D g2 = (Graphics2D) g.create();
                try {
                    g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                            RenderingHints.VALUE_ANTIALIAS_ON);

                    ButtonModel model = button.getModel();
                    Color bg = defaultBg;
                    if (model.isPressed() || model.isArmed()) {
                        bg = pressedBg;
                    } else if (model.isRollover()) {
                        bg = hoverBg;
                    }

                    int w = c.getWidth();
                    int h = c.getHeight();
                    g2.setColor(bg);
                    g2.fillRoundRect(0, 0, w, h, arc, arc);
                    g2.setColor(borderColor);
                    g2.drawRoundRect(0, 0, w - 1, h - 1, arc, arc);
                } finally {
                    g2.dispose();
                }
                // 文字 / focus 仍走默认渲染，保留主题观感
                super.paint(g, c);
            }
        });

        button.addActionListener(e -> onBack.run());
        return button;
    }

    /** 内容区：头部 + 可滚动正文。 */
    private JPanel buildContent(Skill skill) {
        JPanel content = new JPanel(new BorderLayout());
        content.setOpaque(false);

        content.add(buildHeader(skill), BorderLayout.NORTH);

        JScrollPane scrollPane = new JScrollPane(buildBody(skill));
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        content.add(scrollPane, BorderLayout.CENTER);

        return content;
    }

    /** 头部：左侧大图标 + 右侧名称 / id。 */
    private JPanel buildHeader(Skill skill) {
        JPanel header = new JPanel();
        header.setLayout(new BoxLayout(header, BoxLayout.X_AXIS));
        header.setOpaque(false);
        header.setBorder(BorderFactory.createEmptyBorder(0, 0, 16, 0));
        header.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel icon = new JLabel(skill.icon(), SwingConstants.CENTER);
        icon.setPreferredSize(new Dimension(ICON_SIDE, ICON_SIDE));
        icon.setMinimumSize(new Dimension(ICON_SIDE, ICON_SIDE));
        icon.setMaximumSize(new Dimension(ICON_SIDE, ICON_SIDE));
        icon.setOpaque(true);
        icon.setBackground(ICON_BACKGROUND);
        icon.setFont(icon.getFont().deriveFont(Font.PLAIN, 36f));
        icon.setAlignmentY(Component.TOP_ALIGNMENT);
        header.add(icon);

        header.add(Box.createHorizontalStrut(16));

        JPanel nameBlock = new JPanel();
        nameBlock.setLayout(new BoxLayout(nameBlock, BoxLayout.Y_AXIS));
        nameBlock.setOpaque(false);
        nameBlock.setAlignmentY(Component.TOP_ALIGNMENT);

        JLabel name = new JLabel(skill.name());
        name.setFont(name.getFont().deriveFont(Font.BOLD, 22f));
        name.setAlignmentX(Component.LEFT_ALIGNMENT);
        nameBlock.add(name);

        nameBlock.add(Box.createVerticalStrut(4));

        JLabel id = new JLabel(I18n.get().t("ui.skills.detail.idPrefix", skill.id()));
        id.setFont(id.getFont().deriveFont(Font.PLAIN, 12f));
        id.setForeground(SUBTLE_COLOR);
        id.setAlignmentX(Component.LEFT_ALIGNMENT);
        nameBlock.add(id);

        // Finding type 是个 tag（单词级短串），紧跟 id 一起放进 header；
        // 这样它不占 body 区域，把空间完整留给 System prompt 等长内容。
        if (skill.hasFindingType()) {
            nameBlock.add(Box.createVerticalStrut(8));
            JLabel findingChip = new JLabel(skill.findingType());
            findingChip.setOpaque(true);
            findingChip.setBackground(CHIP_BG_COLOR);
            findingChip.setForeground(CHIP_TEXT_COLOR);
            findingChip.setBorder(BorderFactory.createEmptyBorder(3, 10, 3, 10));
            findingChip.setFont(findingChip.getFont().deriveFont(Font.PLAIN, 12f));
            findingChip.setAlignmentX(Component.LEFT_ALIGNMENT);
            nameBlock.add(findingChip);
        }

        header.add(nameBlock);
        return header;
    }

    /**
     * 正文：垂直堆叠若干 section；空字段不渲染。
     * 使用 {@link JTextArea}（只读、带背景）而非 JLabel+HTML：渲染稳定、不依赖 HTML
     * 解析器，且能完美支持多行 / 长串换行。
     */
    private JPanel buildBody(Skill skill) {
        JPanel body = new JPanel();
        body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));
        body.setOpaque(true);
        body.setBackground(Color.WHITE);

        addSection(body, I18n.get().t("ui.findings.col.desc"), skill.description());
        // Finding type 已移至 header (buildHeader) 与 name/id 同行展示，不占 body 空间。
        addSection(body, I18n.get().t("ui.skills.detail.systemPrompt"), skill.prompt());
        addSection(body, I18n.get().t("ui.skills.detail.userContext"), skill.userContext());
        if (skill.summaryCount() > 0) {
            addSection(body, I18n.get().t("ui.skills.detail.summaryCount"), String.valueOf(skill.summaryCount()));
        }
        return body;
    }

    private void addSection(JPanel parent, String title, String content) {
        addSection(parent, title, content, 0);
    }

    private void addSection(JPanel parent, String title, String content, int maxVisibleRows) {
        if (content == null || content.isEmpty()) {
            return;
        }
        JPanel section = new JPanel();
        // 用 BorderLayout 让 text area 在水平方向撑满 section 宽度（驱动 line wrap 计算）。
        section.setLayout(new BorderLayout(0, 4));
        section.setOpaque(false);
        section.setAlignmentX(Component.LEFT_ALIGNMENT);
        section.setBorder(BorderFactory.createEmptyBorder(0, 0, 16, 0));
        // 给 section 一个最大宽度 = 无限，让 BoxLayout 把它拉伸到父容器宽度
        section.setMaximumSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));

        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 13f));
        titleLabel.setForeground(SECTION_TITLE_COLOR);
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        section.add(titleLabel, BorderLayout.NORTH);

        JTextArea textArea = new JTextArea(content);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setEditable(false);
        textArea.setFocusable(false);
        textArea.setOpaque(true);
        textArea.setBackground(SECTION_BG_COLOR);
        textArea.setFont(textArea.getFont().deriveFont(Font.PLAIN, 13f));
        textArea.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));

        if (maxVisibleRows > 0) {
            // 紧凑模式：限制可见行数并开启纵向滚动，避免短字段把长字段挤到屏幕外。
            textArea.setRows(maxVisibleRows);
            FontMetrics fm = textArea.getFontMetrics(textArea.getFont());
            int lineHeight = fm.getHeight();
            Insets pad = textArea.getBorder().getBorderInsets(textArea);
            int compactHeight = lineHeight * maxVisibleRows + pad.top + pad.bottom;
            textArea.setMaximumSize(new Dimension(Integer.MAX_VALUE, compactHeight));

            JScrollPane sp = new JScrollPane(textArea);
            sp.setBorder(BorderFactory.createEmptyBorder());
            sp.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
            sp.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
            sp.setMaximumSize(new Dimension(Integer.MAX_VALUE, compactHeight));
            sp.setAlignmentX(Component.LEFT_ALIGNMENT);
            section.add(sp, BorderLayout.CENTER);
        } else {
            section.add(textArea, BorderLayout.CENTER);
        }

        parent.add(section);
    }
    @Override
    public void refreshI18n() {
        // 整个面板的标题/段落都是构造期固定的:最简实现是 removeAll + 重建
        // 详情页是临时页(用户点卡片才会创建),重建代价小。
        removeAll();
        add(buildToolbar(onBackRef), BorderLayout.NORTH);
        add(buildContent(currentSkillRef), BorderLayout.CENTER);
        revalidate();
        repaint();
    }

}
