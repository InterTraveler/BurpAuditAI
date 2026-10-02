package com.auditai.burp.ui;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLayeredPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.UIManager;
import java.awt.AlphaComposite;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Insets;
import java.awt.RenderingHints;
import java.awt.Shape;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.geom.RoundRectangle2D;
import java.io.Serial;
import java.util.ArrayList;
import java.util.List;
import java.util.TimerTask;

/**
 * 非模态 Toast 提示：浮在宿主面板右下角，默认约 3 秒后淡出消失。
 *
 * <p>卡片背景自绘（深色半透明圆角），文字由内嵌 {@link JTextArea} 渲染——
 * 自绘负责外观与淡出透明度，JTextArea 负责文字渲染、鼠标拖选与 Ctrl+C 复制。</p>
 *
 * <p><b>交互说明</b>：右上角"×"按钮立即关闭；文字区可拖选 Ctrl+C 复制；
 * {@link #showError} 错误模式<b>常驻</b>，不启动倒计时，必须用户主动关闭。</p>
 *
 * <p><b>自动消失的双保险（Burp 兼容性关键）</b>：</p>
 * <ul>
 *   <li>{@link javax.swing.Timer} 的 TimerQueue 绑定创建线程的 AppContext；Burp
 *       加载扩展的线程与 EDT 往往不在同一 AppContext，构造函数里创建 Timer 会
 *       让事件永远到不了 EDT（表现：PreviewApp 正常、Burp 里不消失）。因此
 *       Swing Timer 在 {@link #show(String, int)} 里<b>惰性创建</b>，show() 必然
 *       运行在 EDT（按钮点击 / SwingWorker.done）；</li>
 *   <li>另设一个独立守护线程（{@link java.util.Timer}）兜底：到点后若 Toast 仍可见则
 *       直接隐藏，不依赖 Swing 事件分发；用 generation 计数防止旧任务误伤新提示。</li>
 * </ul>
 *
 * <p>用法：{@code toast.show("已保存。")} 默认 3 秒后淡出；异步场景（如测试连接）
 * 先 {@code toast.showPersistent("正在测试…")}（不自动消失），出结果后再用
 * {@code toast.show("连接成功")} 替换内容。即使传 {@code durationMs <= 0} 也受
 * {@link #MAX_STAY_MS} 上限约束，绝不会永久滞留（仅 {@link #showPersistent} /
 * {@link #showError} 例外，由调用方保证最终替换 / 关闭）。</p>
 */
public final class Toast extends JComponent {

    @Serial
    private static final long serialVersionUID = 1L;

    /** 距宿主右下角的边距。 */
    private static final int INSET = 16;
    /** 最大宽度，超过则换行。已减去右侧关闭按钮区，避免长文覆盖按钮。 */
    private static final int MAX_WIDTH = 480;
    /** 最小宽度：短提示（如"已保存。"）也不至于显得太小。 */
    private static final int MIN_WIDTH = 280;
    /** 水平内边距。 */
    private static final int PAD_X = 16;
    /** 垂直内边距。 */
    private static final int PAD_Y = 10;
    /** 关闭按钮边长。 */
    private static final int CLOSE_SIZE = 20;
    /** 关闭按钮距卡片顶 / 右边距。 */
    private static final int CLOSE_MARGIN = 4;
    /** 内容右侧为关闭按钮让出的总宽度（按钮 + 边距 + 与文本间距）。 */
    private static final int CLOSE_RESERVED = CLOSE_SIZE + CLOSE_MARGIN * 2 + 4;
    /** 最大显示行数，超出截断加省略号。 */
    private static final int MAX_LINES = 6;
    /** 默认自动消失时长（毫秒）。 */
    private static final int DEFAULT_DURATION_MS = 3000;
    /** 常驻模式（durationMs <= 0）的停留上限，防止提示永久滞留。 */
    private static final int MAX_STAY_MS = 10000;
    /** 圆角半径。 */
    private static final int CORNER_RADIUS = 10;
    /** 错误模式顶部的红色细色条高度，区分普通 / 错误提示。 */
    private static final int ERROR_ACCENT_HEIGHT = 3;
    /** 淡出动画：每帧间隔（毫秒）、透明度步进与淡出总时长。 */
    private static final int FADE_TICK_MS = 15;
    private static final float FADE_STEP = 0.05f;
    private static final int FADE_OUT_MS = FADE_TICK_MS * (int) (1f / FADE_STEP);

    /** 深色半透明底（接近不透明，浅色 / 深色主题都清晰）。 */
    private static final Color BACKGROUND = new Color(30, 30, 34, 235);
    /** 一圈极淡的描边，让卡片在浅色背景上也有边界感。 */
    private static final Color BORDER = new Color(255, 255, 255, 55);
    /** 文字颜色。 */
    private static final Color TEXT = new Color(250, 250, 250, 255);
    /** 关闭按钮 hover 时的圆形高亮。 */
    private static final Color CLOSE_HOVER_BG = new Color(255, 255, 255, 38);
    /** 错误模式顶部的细色条，给错误常驻提示一点视觉信号。 */
    private static final Color ERROR_ACCENT = new Color(232, 99, 99, 220);
    /** 深色卡片上文字选区色：半透明蓝灰，避免与默认浅蓝反差太大。 */
    private static final Color SELECTION_BG = new Color(120, 160, 220, 180);
    /** 选中文本颜色——背景已较亮，这里用白字与原高对比度足。 */
    private static final Color SELECTION_FG = Color.WHITE;

    private final JLayeredPane host;

    /** 右上角关闭按钮。 */
    private final JButton closeButton;
    /** 内容文字区：原生支持鼠标拖选 + Ctrl+C。 */
    private final JTextArea contentArea;

    /** 当前截断后的文本行，仅供测试反射断言超长截断行为。 */
    private List<String> lines = List.of();

    // —— 自动隐藏：Swing Timer（EDT 动画）+ 守护线程兜底 双通道 ——

    /** 到时触发淡出的 Swing Timer（EDT）；见类注释：必须在 show() 里惰性创建。 */
    private Timer hideTimer;
    /** 淡出动画 Timer（EDT），同样惰性创建。 */
    private Timer fadeTimer;
    private boolean timersReady;

    /** 兜底调度器：独立守护线程，不依赖 Swing 事件分发。 */
    private final java.util.Timer scheduler = new java.util.Timer("AuditAI-Toast", true);
    /** 当前这条提示的兜底强制隐藏任务。 */
    private TimerTask forceHideTask;
    /** 代次：每次 show() 递增；兜底任务用快照值判断自己是否已过期。 */
    private long generation;
    /** close() 后为 true：{@link #scheduler} 已 cancel，后续 show/showError/showPersistent 必须静默返回。 */
    private volatile boolean closed;

    /** 当前是否处于"错误常驻"模式：关闭前不自动消失。 */
    private boolean errorMode;

    /** 整卡不透明度（0..1），淡出时递减。 */
    private float alpha = 1f;
    private boolean fadingOut = false;
    private boolean dismissed = false;

    /**
     * @param host 宿主分层面板：Toast 放到它的 POPUP 层，并锚定在右下角。
     */
    public Toast(JLayeredPane host) {
        this.host = host;
        setOpaque(false);
        // Toast 自身不抢 Tab 焦点；JTextArea 设为 focusable 才能接收鼠标拖选
        setFocusable(false);
        setLayout(null);
        // JComponent 默认 visible=true，必须显式关闭避免 add 后被画一个空卡片
        setVisible(false);

        Font base = UIManager.getFont("Label.font");
        Font contentFont = base != null ? base.deriveFont(base.getSize2D() + 2f)
                : new Font(Font.SANS_SERIF, Font.PLAIN, 13);

        contentArea = buildContentArea(contentFont);
        add(contentArea);

        closeButton = buildCloseButton();
        add(closeButton);

        host.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                if (isVisible()) {
                    reposition();
                }
            }
        });
    }

    private JTextArea buildContentArea(Font font) {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setOpaque(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setFont(font);
        area.setForeground(TEXT);
        area.setSelectionColor(SELECTION_BG);
        area.setSelectedTextColor(SELECTION_FG);
        area.setMargin(new Insets(0, 0, 0, 0));
        area.setBorder(null);
        area.setFocusable(true);
        return area;
    }

    private JButton buildCloseButton() {
        JButton btn = new JButton("×");
        btn.setFont(btn.getFont().deriveFont(Font.PLAIN, 15f));
        btn.setForeground(TEXT);
        btn.setBorder(null);
        btn.setContentAreaFilled(false);
        btn.setFocusable(false);
        btn.setFocusPainted(false);
        btn.setMargin(new Insets(0, 0, 0, 0));
        btn.setPreferredSize(new Dimension(CLOSE_SIZE, CLOSE_SIZE));
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        // hover 时画一圈半透明圆形高亮
        btn.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                btn.setContentAreaFilled(true);
                btn.setBackground(CLOSE_HOVER_BG);
                btn.setOpaque(true);
            }

            @Override
            public void mouseExited(MouseEvent e) {
                btn.setContentAreaFilled(false);
                btn.setOpaque(false);
            }
        });
        btn.addActionListener(e -> dismiss());
        return btn;
    }

    /** 暴露关闭按钮，供测试验证"× 在右上角、点击后隐藏"。 */
    JButton getCloseButton() {
        return closeButton;
    }

    /** 暴露内容文本框，供测试验证选区 / 复制。 */
    JTextArea getContentArea() {
        return contentArea;
    }

    /** 当前是否处于错误常驻模式，供测试断言。 */
    boolean isShowingErrorMode() {
        return errorMode;
    }

    /** 显示一条 Toast，默认时长（3 秒）后淡出消失。 */
    public void show(String message) {
        show(message, DEFAULT_DURATION_MS);
    }

    /**
     * 显示一条常驻 Toast：不启动自动隐藏，直到被下一次 {@link #show(String, int)}
     * 替换或 {@link #close()} 关闭。适合异步操作的"进行中"反馈（如"正在测试连接…"），
     * 让用户在整个等待期间都看得到状态，而不是默认 3 秒后凭空消失。
     *
     * <p>必须在 EDT 上调用（{@link #show(String, int)} 同）。</p>
     */
    public void showPersistent(String message) {
        if (closed) {
            return;
        }
        ensureTimersOnEdt();

        errorMode = false;
        applyMessage(message);
        alpha = 1f;
        fadingOut = false;
        dismissed = false;
        fadeTimer.stop();
        if (hideTimer != null) {
            hideTimer.stop();
        }
        if (forceHideTask != null) {
            forceHideTask.cancel();
            forceHideTask = null;
        }
        // 让旧 forceHideTask 立即失效，避免在新提示上误触发
        ++generation;
        setPreferredSize(measure());
        reposition();
        setVisible(true);
        host.moveToFront(this);
        contentArea.repaint();
    }

    /**
     * 显示一条错误 Toast：常驻不消失，直到用户主动点右上角"×"。
     * 适用于"测试连接失败"、"密钥加密失败"等用户需要排查 / 转发详情的错误。
     */
    public void showError(String message) {
        if (closed) {
            return;
        }
        ensureTimersOnEdt();

        errorMode = true;
        applyMessage(message);
        alpha = 1f;
        fadingOut = false;
        dismissed = false;
        fadeTimer.stop();
        if (hideTimer != null) {
            hideTimer.stop();
        }
        if (forceHideTask != null) {
            forceHideTask.cancel();
            forceHideTask = null;
        }
        ++generation;
        setPreferredSize(measure());
        reposition();
        setVisible(true);
        host.moveToFront(this);
        contentArea.repaint();
    }

    /**
     * 显示一条 Toast。
     *
     * @param message    提示文本（可为空）。
     * @param durationMs 自动消失时长（毫秒）；{@code <= 0} 时按 {@link #MAX_STAY_MS}
     *                   兜底，避免提示永久滞留。
     */
    public void show(String message, int durationMs) {
        if (closed) {
            return;
        }
        ensureTimersOnEdt();

        errorMode = false;
        applyMessage(message);
        int stay = durationMs > 0 ? durationMs : MAX_STAY_MS;
        alpha = 1f;
        fadingOut = false;
        dismissed = false;
        fadeTimer.stop();
        if (forceHideTask != null) {
            forceHideTask.cancel();
        }
        setPreferredSize(measure());
        reposition();
        setVisible(true);
        host.moveToFront(this);
        contentArea.repaint();

        // 主通道 Swing Timer + 兜底守护线程双保险；generation 快照避免过期任务误伤新提示
        hideTimer.setInitialDelay(stay);
        hideTimer.restart();

        long gen = ++generation;
        forceHideTask = new TimerTask() {
            @Override
            public void run() {
                if (gen == generation && !dismissed && isVisible()) {
                    SwingUtilities.invokeLater(Toast.this::dismissNow);
                }
            }
        };
        // 调度前再判一次 closed，避免 close() 已 cancel 的 scheduler 再 schedule 抛异常
        if (closed) {
            return;
        }
        scheduler.schedule(forceHideTask, stay + FADE_OUT_MS + 400L);
    }

    /**
     * 立即隐藏当前 Toast（含常驻模式挂起的提示），不依赖自动倒计时。
     * 与 {@link #close()} 的区别是本方法不动 {@link #closed} 标志、不 cancel 调度器。
     * 线程安全：从任意线程调用都会把隐藏操作切到 EDT 执行。
     */
    public void dismiss() {
        if (closed) {
            return;
        }
        if (SwingUtilities.isEventDispatchThread()) {
            dismissNow();
        } else {
            SwingUtilities.invokeLater(this::dismissNow);
        }
    }

    /**
     * 释放资源：插件卸载时调用。停止守护调度器并隐藏当前提示。
     */
    public void close() {
        closed = true;
        scheduler.cancel();
        SwingUtilities.invokeLater(this::dismissNow);
    }

    /**
     * 真正隐藏。可从 EDT（淡出结束）或守护线程（兜底）调用；幂等。
     *
     * <p>注意：不能命名为 hide()，否则会重写 {@link java.awt.Component#hide()} 废弃方法，
     * 导致 setVisible(false) 内部回调本方法造成无限递归、栈溢出。</p>
     */
    private void dismissNow() {
        if (dismissed) {
            return;
        }
        dismissed = true;
        if (hideTimer != null) {
            hideTimer.stop();
        }
        if (fadeTimer != null) {
            fadeTimer.stop();
        }
        if (forceHideTask != null) {
            forceHideTask.cancel();
        }
        alpha = 0f;
        setVisible(false);
        // 隐藏后重绘宿主与顶层容器，避免 Toast 区域残影
        host.repaint();
        host.revalidate();
        if (getRootPane() != null) {
            getRootPane().repaint();
        }
    }

    /** 开始淡出（仅一次，正在淡出时忽略重复触发）。 */
    private void beginFadeOut() {
        if (dismissed || fadingOut || !isVisible() || errorMode) {
            return;
        }
        fadingOut = true;
        fadeTimer.start();
    }

    /**
     * 惰性创建 Swing Timer：必须在 EDT 上执行（见类注释）。
     */
    private void ensureTimersOnEdt() {
        if (timersReady) {
            return;
        }
        hideTimer = new Timer(DEFAULT_DURATION_MS, e -> beginFadeOut());
        hideTimer.setRepeats(false);
        fadeTimer = new Timer(FADE_TICK_MS, e -> {
            alpha -= FADE_STEP;
            if (alpha <= 0f) {
                dismissNow();
            } else {
                repaint();
            }
        });
        fadeTimer.setRepeats(true);
        timersReady = true;
    }

    /** 按右下角定位：宽高取首选尺寸，宿主过小时夹紧到 (0, 0)。 */
    private void reposition() {
        Dimension size = getPreferredSize();
        setBounds(
                Math.max(0, host.getWidth() - size.width - INSET),
                Math.max(0, host.getHeight() - size.height - INSET),
                size.width,
                size.height);

        int textInset = errorMode ? ERROR_ACCENT_HEIGHT : 0;
        contentArea.setBounds(
                PAD_X,
                PAD_Y + textInset,
                size.width - 2 * PAD_X - CLOSE_RESERVED,
                size.height - 2 * PAD_Y - textInset);

        closeButton.setBounds(
                size.width - CLOSE_SIZE - CLOSE_MARGIN,
                CLOSE_MARGIN,
                CLOSE_SIZE,
                CLOSE_SIZE);
    }

    /** 由当前文本估算首选尺寸：宽度夹在最小/最大之间，高度按文本框首选。 */
    private Dimension measure() {
        Dimension textPref = contentArea.getPreferredSize();
        int width = Math.max(MIN_WIDTH, Math.min(MAX_WIDTH,
                textPref.width + 2 * PAD_X + CLOSE_RESERVED));
        int height = textPref.height + 2 * PAD_Y + (errorMode ? ERROR_ACCENT_HEIGHT : 0);
        return new Dimension(width, height);
    }

    /** 把 message 写入 contentArea，清掉旧 selection（setText 后旧选区会失效）。 */
    private void applyMessage(String message) {
        String source = message == null ? "" : message;
        String truncated = truncateByLines(source);
        contentArea.setText(truncated);
        contentArea.setSelectionStart(0);
        contentArea.setSelectionEnd(0);
    }

    /** 按 \n 切行后保留前 {@link #MAX_LINES} 行；超出截断并加省略号。行内换行交给 JTextArea。 */
    private String truncateByLines(String source) {
        String normalized = source.replace("\r", "");
        String[] rawLines = normalized.split("\n", -1);
        if (rawLines.length <= MAX_LINES) {
            lines = List.of(rawLines);
            return normalized;
        }
        // 保留前 MAX_LINES-1 行原样，最后一行取下一段首段示意并 ellipsize
        StringBuilder kept = new StringBuilder();
        List<String> keptList = new ArrayList<>();
        for (int i = 0; i < MAX_LINES - 1; i++) {
            if (i > 0) {
                kept.append('\n');
            }
            kept.append(rawLines[i]);
            keptList.add(rawLines[i]);
        }
        // contentArea 此时可能尚未 layout，用最大可用宽度兜底
        FontMetrics fm = contentArea.getFontMetrics(contentArea.getFont());
        int lastWidth = contentArea.getWidth() > 0
                ? contentArea.getWidth()
                : (MAX_WIDTH - 2 * PAD_X - CLOSE_RESERVED);
        String tail = ellipsize("… " + rawLines[MAX_LINES - 1], fm, lastWidth);
        kept.append('\n').append(tail);
        keptList.add(tail);
        lines = keptList;
        return kept.toString();
    }

    /** 把单行文本缩短到能放进 textWidth，并追加省略号。 */
    private String ellipsize(String line, FontMetrics fm, int textWidth) {
        String tail = "…";
        while (!line.isEmpty() && fm.stringWidth(line + tail) > textWidth) {
            line = line.substring(0, line.length() - 1);
        }
        return line + tail;
    }

    /** 整卡自绘：背景 + 错误色条；文字由 JTextArea 子组件渲染。 */
    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, alpha));

        int w = getWidth() - 1;
        int h = getHeight() - 1;

        // 背景填充到圆角内，避免方角溢出
        Shape oldClip = g2.getClip();
        g2.setClip(new RoundRectangle2D.Float(0, 0, w + 1, h + 1, CORNER_RADIUS, CORNER_RADIUS));
        g2.setColor(BACKGROUND);
        g2.fillRect(0, 0, w + 1, h + 1);
        if (errorMode) {
            // 错误模式顶部细色条占满宽度，圆角由外框裁剪
            g2.setColor(ERROR_ACCENT);
            g2.fillRect(0, 0, w + 1, ERROR_ACCENT_HEIGHT);
        }
        g2.setClip(oldClip);

        g2.setColor(BORDER);
        g2.drawRoundRect(0, 0, w, h, CORNER_RADIUS, CORNER_RADIUS);

        g2.dispose();
    }
}