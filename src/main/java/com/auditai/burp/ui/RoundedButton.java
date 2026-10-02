package com.auditai.burp.ui;

import javax.swing.JButton;
import javax.swing.UIManager;
import java.awt.Color;
import java.awt.Font;
import java.awt.Insets;
import java.io.Serial;

/**
 * 统一风格按钮：主题原生渲染（Repeater 风格）。
 *
 * <p>不再自定义绘制：按钮的形状、圆角、悬停、按下、禁用等外观<b>完全交给当前 L&amp;F
 * （Burp 的主题）渲染</b>——与 Repeater 的 Send / Cancel 按钮走完全相同的渲染路径，
 * 因此样式与大小原生一致，不需要手工仿制。</p>
 *
 * <p>配色通过两路设置：</p>
 * <ul>
 *   <li>{@code setBackground / setForeground}：对大多数 L&amp;F 生效（含预览环境的默认 L&amp;F）；</li>
 *   <li>{@code FlatLaf.style} 客户端属性：Burp 主题基于 FlatLaf，用 style 强制
 *       背景 / 悬停背景 / 前景色，并让悬停只变背景、文字颜色不变（与主题按钮行为一致）。</li>
 * </ul>
 *
 * <p>除构造函数外，本类提供 {@link #standard(JButton)} 静态改造方法：把已有的
 * {@code JButton}（通常是 {@code I18n.button(...)} 的返回值，保留其"切语言自动刷新文案"
 * 的订阅）原地套上统一样式（白底深灰字 + 统一字体 + 统一内边距）。这样设置页的
 * 保存 / 测试 / 删除 / 恢复默认等按钮，以及技能页的"添加技能"按钮，都共享同一套观感，
 * 不做任何单独配色区分。</p>
 */
public final class RoundedButton extends JButton {

    @Serial
    private static final long serialVersionUID = 1L;

    /** 统一样式配色：白底深灰字，悬停浅灰（与 Repeater Cancel 一致）。 */
    private static final Color STANDARD_FILL = Color.WHITE;
    private static final Color STANDARD_HOVER = new Color(245, 246, 248);
    private static final Color STANDARD_FOREGROUND = new Color(70, 76, 84);

    /** 统一内边距：让所有按钮的高度与左右留白一致。 */
    private static final Insets UNIFIED_MARGIN = new Insets(5, 14, 5, 14);

    /**
     * @param text           按钮文字。
     * @param fillColor      背景色（Burp 内由 FlatLaf style 生效，其他 L&amp;F 由 setBackground 生效）。
     * @param hoverFillColor 悬停背景色（仅 FlatLaf 生效；其他 L&amp;F 用主题默认悬停效果）。
     * @param foreground     文字颜色（启用态；禁用态由主题自动处理）。
     */
    public RoundedButton(String text, Color fillColor, Color hoverFillColor, Color foreground) {
        super(text);
        applyColors(this, fillColor, hoverFillColor, foreground);
    }

    /**
     * 统一样式（白底深灰字）：适用于所有常规操作按钮，不做主/次配色区分。
     *
     * @param button 已创建好的按钮（通常来自 {@code I18n.button(...)}，保留语言订阅）。
     * @return 传入的同一个按钮（便于链式 / 字段初始化）。
     */
    public static JButton standard(JButton button) {
        applyColors(button, STANDARD_FILL, STANDARD_HOVER, STANDARD_FOREGROUND);
        applyUnifiedMetrics(button);
        return button;
    }

    /** 统一字体（跟随当前 L&amp;F 的 Button.font）与内边距，保证按钮高度 / 留白一致。 */
    private static void applyUnifiedMetrics(JButton button) {
        Font uiFont = UIManager.getFont("Button.font");
        button.setFont(uiFont != null ? uiFont : button.getFont());
        button.setMargin(UNIFIED_MARGIN);
    }

    /**
     * 把配色写入按钮：
     * <ul>
     *   <li>FlatLaf（Burp 主题）：style 客户端属性强制背景 / 悬停背景 / 前景色，
     *       并锁定 hover/pressed 前景色不变、focus 不画外框；</li>
     *   <li>其它 L&amp;F（如预览环境默认 L&amp;F）：setBackground / setForeground 生效。</li>
     * </ul>
     */
    private static void applyColors(JButton button, Color fill, Color hover, Color foreground) {
        button.setFocusPainted(false);
        // style 客户端属性必须先于 setBackground/setForeground，
        // 否则 FlatLaf 在后续刷新时可能用 UIManager 默认色覆盖掉 style。
        button.putClientProperty("FlatLaf.style",
                "background: " + toHex(fill)
                        + "; foreground: " + toHex(foreground)
                        + "; hoverForeground: " + toHex(foreground)
                        + "; pressedForeground: " + toHex(foreground)
                        + "; hoverBackground: " + toHex(hover)
                        + "; focusWidth: 0");
        button.setForeground(foreground);
        button.setBackground(fill);
    }

    /** 把颜色转为 FlatLaf style 需要的 #RRGGBB 十六进制。 */
    private static String toHex(Color color) {
        return String.format("#%02X%02X%02X", color.getRed(), color.getGreen(), color.getBlue());
    }
}
