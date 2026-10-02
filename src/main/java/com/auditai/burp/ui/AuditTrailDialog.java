package com.auditai.burp.ui;

import com.auditai.burp.history.AnalysisHistoryEntry;
import com.auditai.burp.util.WorkflowLogger;
import com.auditai.burp.util.WorkflowLogger.Source;
import com.auditai.burp.util.WorkflowLogger.TrailMessage;

import javax.swing.BorderFactory;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;
import javax.swing.text.BadLocationException;
import javax.swing.text.html.HTMLDocument;
import javax.swing.text.html.HTMLEditorKit;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.function.Consumer;

/**
 * "链路追踪"窗口：以独立 {@link JFrame} 展示一条历史记录对应的 audit-trail XML。
 *
 * <p><b>为什么用 {@code JFrame} 而不是 {@code JDialog}</b>：{@code JDialog} 没有原生
 * "最大化"按钮（{@code Frame.MAXIMIZED_BOTH} 那一套 API 在 JDialog 上没有），用户期望
 * "右上角关闭按钮的左边"那个标准最大化按钮，只有 JFrame 自带。JFrame 本身非模态
 * （modal 是 Dialog 概念），满足"非模态弹出新窗口"的需求。</p>
 *
 * <p><b>数据来源</b>：{@link AnalysisHistoryEntry#getAuditTrailFile()}；每次打开都通过
 * {@link WorkflowLogger#readTrail(Path)} 实时解析，<b>不</b>做缓存，保证看到的就是磁盘上
 * 最新的轨迹内容。</p>
 *
 * <p><b>渲染规则</b>：从 XML 中提取的每条 {@link TrailMessage} 按其 {@link Source} 着色：</p>
 * <ul>
 *   <li>agent（请求侧）→ 宝蓝色 {@code #4169E1}；</li>
 *   <li>ai（响应/错误侧）→ 轻珊瑚 {@code #F08080}；</li>
 * </ul>
 */
public final class AuditTrailDialog {

    /** agent 块内容色：宝蓝色。 */
    private static final String COLOR_AGENT = "#4169E1";
    /** ai 块内容色：轻珊瑚。 */
    private static final String COLOR_AI = "#F08080";

    /** 角色标签前缀（与示例一致：[system] / [user] / [assistant] / [error]）。 */
    private static final String ROLE_PREFIX = "[";

    private final JFrame frame;
    private final JTextPane textPane;
    private final HTMLEditorKit editorKit;
    private final HTMLDocument document;
    /** 诊断信息栏：记录当前显示的"源文件路径"和条目元信息，方便用户核对数据归属。 */
    private final JLabel footerLabel;
    /** 语言切换监听器：插件运行时切换中/英，弹窗内的错误提示也同步刷新。 */
    private final Consumer<com.auditai.burp.ai.PromptBuilder.Lang> i18nListener;
    /** 最近一次渲染的 entry：用于语言切换时重渲染（i18n key 改变）。 */
    private AnalysisHistoryEntry currentEntry;

    /**
     * 包级构造器：仅供同包内的 {@code AnalysisHistoryPanel} / {@link #show} 调用。
     * 外部不应该直接 new——用 {@link #show} 走 EDT 安全路径。
     */
    AuditTrailDialog(JFrame owner, AnalysisHistoryEntry entry) {
        // JFrame 本身非模态；标题栏原生带最大化 / 最小化 / 关闭按钮（关闭按钮最右，
        // 最大化在它左边），无需自己实现任何逻辑。
        frame = new JFrame(I18n.get().t("ui.auditTrail.title"));
        frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        // 初始宽高:audit-trail 通常含系统 prompt + 完整报文 + AI JSON 响应,内容偏长;
        // 默认 1100x760 给左侧长 URL / 右侧长内容足够展示空间,用户也可拖拽或最大化。
        frame.setSize(new Dimension(1100, 760));
        frame.setLocationRelativeTo(owner);

        textPane = new JTextPane();
        textPane.setEditable(false);
        textPane.setContentType("text/html");
        Font baseFont = textPane.getFont();
        Font mono = new Font(Font.MONOSPACED, Font.PLAIN,
                baseFont != null ? baseFont.getSize() : 13);
        textPane.putClientProperty(JTextPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        textPane.setFont(mono);
        editorKit = (HTMLEditorKit) textPane.getEditorKit();
        document = (HTMLDocument) textPane.getDocument();

        JScrollPane scroll = new JScrollPane(textPane);
        scroll.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        frame.getContentPane().setLayout(new BorderLayout());
        frame.getContentPane().add(scroll, BorderLayout.CENTER);

        // 底部只放文件信息：状态栏只承担"数据归属说明"一个职责。
        footerLabel = new JLabel();
        footerLabel.setBorder(BorderFactory.createEmptyBorder(4, 8, 6, 8));
        frame.getContentPane().add(footerLabel, BorderLayout.SOUTH);

        renderEntry(entry);

        i18nListener = lang -> renderEntry(currentEntry);
        I18n.get().onChange(i18nListener);
    }

    /**
     * 弹出"链路追踪"窗口。线程安全：自动切到 EDT 启动。
     *
     * @param owner 父窗口（用于居中定位；允许为 null）
     * @param entry 选中的历史记录
     */
    public static void show(JFrame owner, AnalysisHistoryEntry entry) {
        if (entry == null) {
            return;
        }
        Runnable task = () -> {
            AuditTrailDialog dlg = new AuditTrailDialog(owner, entry);
            dlg.frame.setVisible(true);
        };
        if (SwingUtilities.isEventDispatchThread()) {
            task.run();
        } else {
            SwingUtilities.invokeLater(task);
        }
    }

    /**
     * 把 entry 解析为 HTML 写进 {@link #textPane}。解析失败时显示一个红字错误提示，
     * 仍保留窗口可见，方便用户根据错误信息排查（权限、文件被删、XML 损坏等）。
     */
    private void renderEntry(AnalysisHistoryEntry entry) {
        currentEntry = entry;
        frame.setTitle(I18n.get().t("ui.auditTrail.title") + " · #" + entry.getId());
        textPane.setText("");
        Path xml = entry.getAuditTrailFile();
        if (xml == null) {
            writeHtml(escapeHtml(I18n.get().t("ui.auditTrail.empty")));
            footerLabel.setText(buildFooter(entry, null));
            return;
        }
        try {
            List<TrailMessage> messages = WorkflowLogger.readTrail(xml);
            if (messages.isEmpty()) {
                writeHtml(escapeHtml(I18n.get().t("ui.auditTrail.empty")));
            } else {
                StringBuilder html = new StringBuilder(4096);
                html.append("<html><body style='font-family:monospace;font-size:12px; ")
                        .append("word-wrap:break-word; word-break:break-all; ")
                        .append("overflow-wrap:break-word; white-space:normal; margin:0; padding:0;'>");
                for (TrailMessage m : messages) {
                    appendMessageHtml(html, m);
                }
                html.append("</body></html>");
                writeHtml(html.toString());
            }
            footerLabel.setText(buildFooter(entry, xml));
        } catch (Exception ex) {
            String detail = ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage();
            String msg = I18n.get().t("ui.auditTrail.parseError", detail);
            writeHtml("<html><body style='color:#C0392B;'>"
                    + escapeHtml(msg) + "</body></html>");
            footerLabel.setText(buildFooter(entry, xml));
        }
    }

    /**
     * 把一条 message 拼成 HTML 片段：[role] 标签 + content 文本。
     *
     * <p><b>换行策略（关键：不用 {@code <pre>}）</b>：{@code <pre>} 在 HTMLEditorKit
     * 里有顽固的 nowrap 行为，即便 CSS 设了 {@code white-space: pre-wrap} 也经常
     * 不生效——长 URL / JSON 仍会出现水平滚动条。本方案改用 {@code <div>} + 手动
     * 把 {@code \n} 替换为 {@code <br>}，再叠加多重断行 CSS：</p>
     * <ul>
     *   <li>{@code word-wrap: break-word} 兼容老旧 LAF；</li>
     *   <li>{@code word-break: break-all} 强制在任意字符间断行，覆盖 base64 /
     *       长 URL / hash 等"无空格的长字符串"场景；</li>
     *   <li>{@code overflow-wrap: break-word} 双保险；</li>
     *   <li>{@code white-space: normal} 显式覆盖任何继承的 nowrap 行为。</li>
     * </ul>
     */
    private static void appendMessageHtml(StringBuilder html, TrailMessage m) {
        String color = m.source() == Source.AI ? COLOR_AI : COLOR_AGENT;
        String role = ROLE_PREFIX + escapeHtml(m.role()) + "]";
        String content = escapeHtml(m.content()).replace("\n", "<br>");
        html.append("<div style='color:").append(color)
                .append("; margin:10px 0 14px 0; word-wrap:break-word; ")
                .append("word-break:break-all; overflow-wrap:break-word; white-space:normal;'>")
                .append("<b>").append(role).append("</b><br>")
                .append("<div style='margin:4px 0 0 0; font-family:monospace; ")
                .append("color:").append(color).append("; ")
                .append("word-wrap:break-word; word-break:break-all; overflow-wrap:break-word; ")
                .append("white-space:normal;'>")
                .append(content)
                .append("</div>")
                .append("</div>");
    }

    /** 写 HTML 到 {@link #document}：每次都从空文档写入，避免多窗口共用模板时残留。 */
    private void writeHtml(String html) {
        try {
            document.remove(0, document.getLength());
            editorKit.insertHTML(document, 0, html, 0, 0, null);
            textPane.setCaretPosition(0);
        } catch (BadLocationException | IOException e) {
            textPane.setText(html.replaceAll("<[^>]+>", ""));
        }
    }

    /**
     * 底部状态栏：把"哪个 entry / 哪个 XML 文件"明明白白告诉用户。
     */
    private static String buildFooter(AnalysisHistoryEntry entry, Path xml) {
        String method = entry.getMethod() == null ? "" : entry.getMethod().toUpperCase(Locale.ROOT);
        String url = entry.getUrl() == null ? "" : entry.getUrl();
        String file = xml == null ? "(no file)" : xml.toString();
        return "#" + entry.getId() + "  " + method + "  " + url + "    XML: " + file;
    }

    /** 转义 5 个 HTML 文本字符。content 中可能含 {@code &} / {@code <} / {@code >}，必须转义。 */
    private static String escapeHtml(String text) {
        if (text == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(text.length() + 16);
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '&':  out.append("&amp;");  break;
                case '<':  out.append("&lt;");   break;
                case '>':  out.append("&gt;");   break;
                case '"':  out.append("&quot;"); break;
                case '\'': out.append("&#39;");  break;
                default:   out.append(c);
            }
        }
        return out.toString();
    }

    /**
     * 关闭时调用：注销 i18n 监听器，避免扩展卸载后仍持有 frame 引用。
     * 本身 {@link WindowConstants#DISPOSE_ON_CLOSE} 已处理窗口资源。
     */
    public void dispose() {
        I18n.get().off(i18nListener);
        frame.dispose();
    }

    /**
     * 提供给 {@code AnalysisHistoryPanel} 关闭时统一调用的便捷入口。
     */
    public static void disposeAll(java.util.List<AuditTrailDialog> dialogs) {
        if (dialogs == null) {
            return;
        }
        for (AuditTrailDialog d : dialogs) {
            if (d != null) {
                d.dispose();
            }
        }
        dialogs.clear();
    }

    /** 暴露底层 JFrame 仅用于父容器布局定位（一般不直接用）。 */
    JFrame asFrame() {
        return frame;
    }
}
