package com.auditai.burp.skills;

import com.auditai.burp.ui.I18n;
import com.auditai.burp.ui.LocaleAware;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.SwingConstants;
import javax.swing.border.LineBorder;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.Serial;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

/**
 * 单个技能的卡片视图。
 *
 * <p>布局：水平 {@link BorderLayout}，左侧是固定正方形的图标区（居中显示单字符 / emoji），
 * 中间是技能名称（垂直居中），右侧是状态徽章区域（启用态显示绿色 ✓，自动激活态显示橙色 📌）。
 * 整张卡片带浅色描边、内边距，鼠标悬停时高亮背景、按下时切换为"已选"色，</p>
 *
 * <p><b>状态视觉：</b></p>
 * <ul>
 *   <li>禁用（默认）：灰色细边框，无徽章；</li>
 *   <li>启用：<b>绿色</b>细边框，右侧徽章区显示绿色对号 ✓；</li>
 *   <li>自动激活：同样<b>绿色</b>细边框（与"启用"同色，刻意保持视觉上的同一类），
 *       徽章区显示绿色图钉 📌——通过字符形状差异（✓ vs 📌）一眼分辨哪些是"无需模型选择、
 *       每次都注入"的常驻能力。</li>
 * </ul>
 *
 * <p><b>交互：</b></p>
 * <ul>
 *   <li>左键单击：通过 {@code onClick} 回调通知宿主（无论状态都响应——
 *       查看详情不受状态限制）；</li>
 *   <li>右键弹出菜单：根据当前状态显示"启用 / 禁用"、"自动激活 / 取消自动激活"两个独立项；
 *       用户技能额外有"卸载"项，内置技能的"卸载"项置灰不可点；</li>
 *   <li>状态切换：通过 {@code onToggle}（启用 / 禁用）和 {@code onPin}
 *       （自动激活 / 取消自动激活）两个独立回调通知宿主——两者解耦，让 SkillsPanel
 *       各自维护独立的注册表。</li>
 * </ul>
 *
 * <p>尺寸约定：只设 {@code preferredSize}，不限制最大/最小尺寸——这样
 * {@link WrapLayout} 可以按卡片原始宽度自动换行。</p>
 */
public final class SkillCard extends JPanel implements LocaleAware {

    @Serial
    private static final long serialVersionUID = 1L;

    /** 卡片偏好尺寸。 */
    static final Dimension CARD_SIZE = new Dimension(240, 72);

    /** 左侧正方形图标区边长（像素）。 */
    private static final int ICON_SIDE = 48;

    /** 右侧状态徽章区域宽度（像素）：用于把 ✓ / 📌 固定到卡片"右下"位置。 */
    private static final int BADGE_WIDTH = 28;

    private static final Color BORDER_DISABLED = new Color(210, 210, 210);
    private static final Color BORDER_ENABLED = new Color(76, 175, 80); // Material Green 500
    private static final Color HOVER_BACKGROUND = new Color(245, 247, 250);
    private static final Color PRESSED_BACKGROUND = new Color(225, 232, 240);
    private static final Color ICON_BACKGROUND = new Color(238, 242, 247);

    private final Skill skill;
    private final Consumer<Skill> onClick;
    private final BiConsumer<Skill, Boolean> onToggle;
    private final BiConsumer<Skill, Boolean> onPin;
    private final Consumer<Skill> onUninstall;

    /** 当前徽章：保存引用以便切换状态时改文字 / 改前景色。 */
    private final JLabel statusLabel;

    /** 当前启用态——保存以便按需重画边框（避免重新创建 border 对象）。 */
    private boolean enabled;

    /** 当前"自动激活"态。{@code pinned=true} 隐含 {@code enabled=true}。 */
    private boolean pinned;

    /**
     * @param skill       技能数据；{@link Skill#source()} 决定"卸载"项是否可用。
     * @param enabled     初始启用态；调用 {@link #setSkillEnabled(boolean)} 之后会实时反映到 UI。
     * @param pinned      初始"自动激活"态；调用 {@link #setPinned(boolean)} 之后会实时反映到 UI。
     *                    业务约束：{@code pinned=true} 隐含 {@code enabled=true}，
     *                    调用 {@link #setSkillEnabled(boolean)} 时若设为 false 应同步清掉 pinned。
     * @param onClick     左键点击回调；传 null 时不响应左键。
     * @param onToggle    启用 / 禁用切换回调（参数为新的启用态）；传 null 时右键菜单不显示切换项。
     * @param onPin       "自动激活 / 取消自动激活" 回调（参数为新的 pinned 态）；
     *                    传 null 时右键菜单不显示自动激活项。语义上 onPin 的 true 会让卡片
     *                    自动 setSkillEnabled(true) 并把 enabled 状态也回传 onToggle，
     *                    让 SkillsPanel 同时维护两份注册表。
     * @param onUninstall 卸载回调（仅用户技能触发）；传 null 时右键菜单不显示卸载项。
     */
    public SkillCard(Skill skill, boolean enabled, boolean pinned,
                     Consumer<Skill> onClick,
                     BiConsumer<Skill, Boolean> onToggle,
                     BiConsumer<Skill, Boolean> onPin,
                     Consumer<Skill> onUninstall) {
        super(new BorderLayout(10, 0));
        this.skill = skill;
        this.onClick = onClick;
        this.onToggle = onToggle;
        this.onPin = onPin;
        this.onUninstall = onUninstall;

        setBackground(Color.WHITE);
        setOpaque(true);
        setPreferredSize(CARD_SIZE);
        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        setToolTipText(skill.description());

        add(buildIconLabel(), BorderLayout.WEST);
        add(buildNameLabel(), BorderLayout.CENTER);

        this.statusLabel = new JLabel("", SwingConstants.CENTER);
        this.statusLabel.setFont(statusLabel.getFont().deriveFont(Font.BOLD, 18f));
        add(buildStatusBadge(this.statusLabel), BorderLayout.EAST);

        // 初始化状态（setSkillEnabled / setPinned 内部会画边框 + 改徽章）
        // 顺序：先 enabled 再 pinned——pinned=true 时 setPinned 会顺带把徽章调成图钉，
        // 但边框颜色会被随后设的 pinned=true 覆盖。
        setSkillEnabled(enabled);
        setPinned(pinned);

        // 悬停/按下反馈：直接操作 background，不引入 LookAndFeel 自定义 UI，避免跨平台差异。
        MouseAdapter hover = new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                setBackground(HOVER_BACKGROUND);
            }

            @Override
            public void mouseExited(MouseEvent e) {
                setBackground(Color.WHITE);
            }

            @Override
            public void mousePressed(MouseEvent e) {
                setBackground(PRESSED_BACKGROUND);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                setBackground(contains(e.getPoint()) ? HOVER_BACKGROUND : Color.WHITE);
            }

            @Override
            public void mouseClicked(MouseEvent e) {
                // 右键交给 componentPopupMenu 处理；左键才回调 onClick。
                // 无论状态如何都允许查看详情——状态只是业务开关，不影响"查看"。
                if (e.getButton() == MouseEvent.BUTTON1 && onClick != null) {
                    onClick.accept(skill);
                }
            }
        };
        addMouseListener(hover);
        // 子组件上的事件也要转发到卡片自己，否则鼠标移到内部控件时 mouseExited 会先触发再进来
        for (Component child : getComponents()) {
            child.addMouseListener(hover);
        }

        // 右键菜单：用 setComponentPopupMenu 让 Swing 自动接管 right-click，
        // 不会和左键 MouseListener 冲突。
        setComponentPopupMenu(buildContextMenu());
    }

    /**
     * 兼容旧构造（无 pinned / onPin）：保持旧调用方与现有测试不变。
     *
     * <p>等价于 {@code new SkillCard(skill, enabled, false, onClick, onToggle, null, onUninstall)}。</p>
     */
    public SkillCard(Skill skill, boolean enabled,
                     Consumer<Skill> onClick,
                     BiConsumer<Skill, Boolean> onToggle,
                     Consumer<Skill> onUninstall) {
        this(skill, enabled, false, onClick, onToggle, null, onUninstall);
    }

    /**
     * 切换启用态并刷新视觉（边框颜色 + 右下角徽章 + 右键菜单项）。
     *
     * <p>本方法会同步触发 {@code repaint()}，调用方无需手动重画。
     * 右键菜单需要整体重建——菜单项文案是构造时根据初始状态决定的，
     * 切换后必须替换否则用户会看到与状态不符的菜单项。</p>
     *
     * <p><b>业务约束：</b>把启用从 true 切到 false 时同步清掉 pinned——"自动激活"
     * 隐含启用，禁用时不可能还处于自动激活。这一步在方法体内自动完成，
     * 由后续 {@code refreshVisual()} 一起画出新边框 + 徽章 + 菜单。</p>
     *
     * <p>命名 {@code setSkillEnabled} 而非覆写 {@link #setEnabled(boolean)}：
     * 本方法只管理"技能启用"的业务状态（边框 / 徽章 / 菜单），不改变 Swing
     * 组件本身的 enable 语义（焦点、事件派发、无障碍仍走 JComponent）。</p>
     */
    public void setSkillEnabled(boolean enabled) {
        this.enabled = enabled;
        if (!enabled && this.pinned) {
            this.pinned = false;
        }
        refreshVisual();
    }

    /**
     * 切换"自动激活"态并刷新视觉（边框颜色 + 右下角徽章 + 右键菜单项）。
     *
     * <p>把 pinned 从 false 切到 true 且当前 disabled 时，先把 enabled 设为 true——
     * 自动激活必须启用，否则 SkillsPanel 的 enabledIds / pinnedIds 会不一致。
     * 这里直接调 {@link #setSkillEnabled(boolean)}：它会把 {@code enabled=true}
     * 应用后再走一次 {@link #refreshVisual()}，所以本方法最后再调一次
     * {@code refreshVisual()} 看似冗余（实际不是——{@code this.pinned} 在
     * {@code setSkillEnabled} 之后才被设置，需要把 pinned=true 纳入视觉刷新）。</p>
     */
    public void setPinned(boolean pinned) {
        if (pinned && !this.enabled) {
            // 自动激活隐含启用；走 setSkillEnabled 顺带画边框（pinned 字段随后覆盖边框色）。
            setSkillEnabled(true);
        }
        this.pinned = pinned;
        refreshVisual();
    }

    /** 重画边框 + 徽章 + 右键菜单（无副作用的视觉刷新）。 */
    private void refreshVisual() {
        // 边框颜色：启用 / 自动激活都用同一绿色——与"禁用"的灰色形成二态对比。
        // 自动激活与普通启用的差异只由徽章字符（📌 vs ✓）承担，刻意保持单一色调，
        // 让"启用"与"自动激活"在视觉层级上是同一类（都属于"激活"），只是程度不同。
        Color borderColor = (pinned || enabled) ? BORDER_ENABLED : BORDER_DISABLED;
        int borderWidth = 1;
        setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(borderColor, borderWidth, true),
                BorderFactory.createEmptyBorder(8, 10, 8, 10)));
        // 徽章：pinned → 📌，enabled → ✓，disabled → 空。
        // 颜色同为绿色——形状差异（对号 vs 图钉）已足以一眼分辨。
        Color badgeColor = (pinned || enabled) ? BORDER_ENABLED : null;
        statusLabel.setForeground(badgeColor);
        statusLabel.setText(pinned ? "📌" : enabled ? "✓" : "");
        // 右键菜单项也跟着翻转：避免状态与菜单项文案不一致。
        setComponentPopupMenu(buildContextMenu());
        repaint();
    }

    /** 当前是否已启用。 */
    public boolean isSkillEnabled() {
        return enabled;
    }

    /** 当前是否处于"自动激活"态。 */
    public boolean isPinned() {
        return pinned;
    }

    /** 关联的技能数据。 */
    public Skill skill() {
        return skill;
    }

    /** 左侧正方形图标：固定 48x48，浅灰底，单字符居中，字体偏大以适配方框。 */
    private JLabel buildIconLabel() {
        JLabel icon = new JLabel(skill.icon(), SwingConstants.CENTER);
        icon.setPreferredSize(new Dimension(ICON_SIDE, ICON_SIDE));
        icon.setMinimumSize(new Dimension(ICON_SIDE, ICON_SIDE));
        icon.setMaximumSize(new Dimension(ICON_SIDE, ICON_SIDE));
        icon.setOpaque(true);
        icon.setBackground(ICON_BACKGROUND);
        icon.setFont(icon.getFont().deriveFont(Font.PLAIN, 26f));
        return icon;
    }

    /** 中间技能名称：垂直居中、单行省略（保留 tooltip 完整描述）。 */
    private JLabel buildNameLabel() {
        JLabel name = new JLabel(skill.name(), SwingConstants.LEFT);
        name.setVerticalAlignment(SwingConstants.CENTER);
        name.setFont(name.getFont().deriveFont(Font.PLAIN, 14f));
        return name;
    }

    /**
     * 右侧状态徽章区：固定 28×72，把 {@code status} 用 {@code BorderLayout.SOUTH}
     * 贴到卡片右下角；禁用态时 status 文本为空也保留占位，避免名字被拉长。
     */
    private JPanel buildStatusBadge(JLabel status) {
        JPanel badge = new JPanel(new BorderLayout());
        badge.setOpaque(false);
        badge.setPreferredSize(new Dimension(BADGE_WIDTH, CARD_SIZE.height));
        // 内边距：留 4px 给徽章"呼吸"，并把徽章贴到右下（SOUTH）
        badge.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 6));
        badge.add(status, BorderLayout.SOUTH);
        return badge;
    }

    /**
     * 构建右键菜单：根据当前 enabled / pinned 态显示对应项。
     *
     * <p>菜单结构（按顺序）：</p>
     * <ul>
     *   <li>启用 / 禁用（二选一）—— 存在即互斥；</li>
     *   <li>自动激活 / 取消自动激活（二选一）—— pinned=false 时显示"自动激活"，
     *       pinned=true 时显示"取消自动激活"；</li>
     *   <li>卸载（仅用户技能可点，内置技能置灰）。</li>
     * </ul>
     *
     * <p><b>关键交互：</b>选"自动激活"且当前为禁用态时，先在卡片本地把 enabled 设为 true
     * 再触发 onPin(true) 与 onToggle(true)——让 SkillsPanel 同时把 id 加入
     * enabledIds 与 pinnedIds，避免出现"pinned=true 但 enabled=false"的脏状态。</p>
     */
    private JPopupMenu buildContextMenu() {
        JPopupMenu menu = new JPopupMenu();

        // —— 启用 / 禁用 ——
        if (onToggle != null) {
            if (enabled) {
                JMenuItem disable = new JMenuItem(I18n.get().t("ui.skills.disable"));
                disable.addActionListener(e -> {
                    setSkillEnabled(false);
                    onToggle.accept(skill, false);
                });
                menu.add(disable);
            } else {
                JMenuItem enable = new JMenuItem(I18n.get().t("ui.skills.enable"));
                enable.addActionListener(e -> {
                    setSkillEnabled(true);
                    onToggle.accept(skill, true);
                });
                menu.add(enable);
            }
        }

        // —— 自动激活 / 取消自动激活 ——
        if (onPin != null) {
            if (pinned) {
                JMenuItem unpin = new JMenuItem(I18n.get().t("ui.skills.unpin"));
                unpin.addActionListener(e -> {
                    // 取消自动激活：保留启用态，只清掉 pinned。语义上"只是不再自动激活"。
                    setPinned(false);
                    onPin.accept(skill, false);
                });
                menu.add(unpin);
            } else {
                JMenuItem pin = new JMenuItem(I18n.get().t("ui.skills.pin"));
                pin.addActionListener(e -> {
                    // 设为自动激活：本地 setSkillEnabled(true) 同步把 enabled 置 true，
                    // 然后触发 onToggle(true) 让宿主把 id 加入 enabledIds；最后 setPinned(true)
                    // 写本地字段 + 触发 onPin(true)。顺序保证：enabled 先于 pinned。
                    if (!enabled) {
                        setSkillEnabled(true);
                        onToggle.accept(skill, true);
                    }
                    setPinned(true);
                    onPin.accept(skill, true);
                });
                menu.add(pin);
            }
        }

        // —— 卸载 ——
        if (onUninstall != null) {
            JMenuItem uninstall = new JMenuItem(I18n.get().t("ui.skills.uninstall"));
            boolean canUninstall = skill.source() == SkillSource.USER;
            uninstall.setEnabled(canUninstall);
            if (canUninstall) {
                uninstall.addActionListener(e -> onUninstall.accept(skill));
            }
            menu.add(uninstall);
        }
        return menu;
    }
    @Override
    public void refreshI18n() {
        // 重新构建右键菜单(文案依赖 I18n)
        setComponentPopupMenu(buildContextMenu());
    }

}