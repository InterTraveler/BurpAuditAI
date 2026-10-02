package com.auditai.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.auditai.burp.history.AnalysisHistoryEntry;
import com.auditai.burp.history.AnalysisHistoryStore;
import com.auditai.burp.history.RiskLevel;
import com.auditai.burp.http.BodyStorage;
import com.auditai.burp.passive.FingerprintDedup;

import javax.swing.*;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableColumn;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.HierarchyEvent;
import java.io.IOException;
import java.io.Serial;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;

/**
 * "历史"页签：展示经 AI 分析模块实际处理过的报文。
 *
 * <p>数据源是 {@link AnalysisHistoryStore}，仅记录：</p>
 * <ul>
 *   <li>手动分析（用户点 Analyze）触发的报文；</li>
 *   <li>被动分析（按规则 + 指纹去重后自动触发）触发的报文。</li>
 * </ul>
 *
 * <p>布局：</p>
 * <ul>
 *   <li><b>上方</b>表格列出 7 列：序号 / 时间 / Method / URL / 类型（手动/被动）/
 *       问题数量 / 风险等级；URL 过滤框 + 状态文本；</li>
 *   <li><b>下方</b>左右分栏显示选中记录的 Request / Response（Burp 原生编辑器，
 *       支持 Raw / Pretty / Headers / Body 切换）；</li>
 *   <li>风险等级列带颜色徽章（与"问题"页签的严重程度颜色保持一致）；</li>
 *   <li>表格<b>右键菜单</b>两项：<b>"删除记录"</b>（单条删除右键所在的记录，
 *       <b>不弹确认框</b>——右键菜单本身就是明确的删除意图）和 <b>"Clear history"</b>
 *       （清空当前项目全部历史，操作前弹确认框，语义与原先工具栏 Clear 按钮一致）。</li>
 * </ul>
 *
 * <p>报文字节按需从 {@code AnalysisHistoryStore} 写入的 gzip 文件读盘，
 * 内存峰值由 {@link AnalysisHistoryStore#DEFAULT_MAX_ENTRY_BYTES} 限制。</p>
 */
public final class AnalysisHistoryPanel extends JPanel implements LocaleAware {

    @Serial
    private static final long serialVersionUID = 1L;

    /** 表格列定义：序号 / 时间 / Method / URL / 类型 / 问题数量 / 风险（构造期取一次，详见 {@link #currentColumns()}）。 */
    private final String[] columns = currentColumns();

    /** 按当前 I18n 语言返回可见列名(列数固定 7)。切语言时 {@link #refreshI18n()} 会重设。 */
    private static String[] currentColumns() {
        return new String[]{
                I18n.get().t("ui.history.col.id"),
                I18n.get().t("ui.history.col.time"),
                I18n.get().t("ui.history.col.method"),
                I18n.get().t("ui.history.col.url"),
                I18n.get().t("ui.history.col.type"),
                I18n.get().t("ui.history.col.count"),
                I18n.get().t("ui.history.col.risk")
        };
    }

    /** 时间格式：本地时区 "yyyy-MM-dd HH:mm:ss"。 */
    private static final DateTimeFormatter TIME_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    /** 失败描述截断长度：超出后用 "..." 省略。配合"问题数量"列固定 100px 窄列，
     *  30 字能保证 "[失败] 短描述" 一行可见；完整错误仍在选中记录的详情/审计轨迹里看。 */
    private static final int ERROR_TRUNCATE_CHARS = 30;

    private final AnalysisHistoryStore store;
    /**
     * 被动分析去重缓存引用。可为 null（不注入时跳过同步清空，保留原行为）。
     * 在 {@link #clearHistory()} 时与 store 同步清空，避免"清空历史后
     * 同 URL 仍被判为已分析"的歧义。
     */
    private final FingerprintDedup passiveDedup;
    private final MontoyaApi api;
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final DefaultTableModel tableModel = new DefaultTableModel(columns, 0) {
        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };
    private final JTable table = new JTable(tableModel);
    private final JTextField filterField = new JTextField(32);
    private final JLabel statusLabel = new JLabel();
    private final Timer refreshTimer;

    /**
     * 当前在飞行的报文加载任务。切换选中行时旧任务会被取消，
     * 避免后启动的请求先完成导致编辑区显示陈旧数据。
     */
    private final AtomicReference<SwingWorker<Void, Void>> loadInFlight = new AtomicReference<>();

    /**
     * 已打开的"链路追踪"窗口列表：每个 dialog 独立非模态，用户可能连续右键不同记录
     * 弹出多个窗口。{@link #close()} 时统一 dispose，避免扩展卸载后仍有窗口残留。
     */
    private final List<AuditTrailDialog> trailDialogs = new ArrayList<>();

    /**
     * 创建"历史"页签。
     *
     * @param api          Burp API 门面，用于创建原生报文编辑器。
     * @param store        已分析历史 store；为 null 时页面显示不可用状态。
     * @param passiveDedup 被动分析去重缓存引用；为 null 时 Clear 操作只清历史库，
     *                     不动 dedup（保留旧行为）。正常装配应注入，确保
     *                     "清空历史 → 同 URL 重新分析"语义一致。
     */
    public AnalysisHistoryPanel(MontoyaApi api, AnalysisHistoryStore store, FingerprintDedup passiveDedup) {
        super(new BorderLayout(6, 6));
        this.store = store;
        this.passiveDedup = passiveDedup;
        this.api = api;
        this.requestEditor = api.userInterface().createHttpRequestEditor();
        this.responseEditor = api.userInterface().createHttpResponseEditor();
        this.refreshTimer = new Timer(300, event -> refresh());
        this.refreshTimer.setRepeats(false);
        setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

        // I18n:本面板与插件同生命周期,close() 里注销避免卸载后常驻引用。
        I18n.get().onChange(i18nListener);

        JLabel filterLabel = I18n.label("ui.history.filterLabel");

        JPanel toolbar = new JPanel(new BorderLayout(4, 0));
        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        // 过滤框 tooltip 跟随语言自动刷新(弱引用订阅,无需在 refreshI18n 里手动处理)
        I18n.tooltip(filterField, "ui.history.filterTip");
        filterField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent event) {
                refresh();
            }

            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent event) {
                refresh();
            }

            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent event) {
                refresh();
            }
        });
        filterPanel.add(filterLabel);
        filterPanel.add(filterField);
        filterPanel.add(statusLabel);
        toolbar.add(filterPanel, BorderLayout.WEST);
        add(toolbar, BorderLayout.NORTH);

        // 风险等级列用彩色渲染；其它列走默认
        table.setDefaultRenderer(Object.class, new RiskLevelAwareRenderer());
        // 表头左对齐：JTable 默认居中，但 Burp Suite 原生表格列标题一律左对齐，
        // 跟宿主视觉风格保持一致，避免用户在列标题里找居中文字（特别是"问题数量"这种
        // 短字段看起来更顺眼）。
        JTableHeader header = table.getTableHeader();
        DefaultTableCellRenderer headerRenderer = (DefaultTableCellRenderer) header.getDefaultRenderer();
        headerRenderer.setHorizontalAlignment(SwingConstants.LEFT);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(true);
        table.setFillsViewportHeight(true);
        // 列宽偏好：短字段列（序号/时间/Method/类型/问题数量/风险）固定窄宽，
        // 长字段列（URL）弹性拉伸，跟随表格宽度变化。
        // 与原 HttpHistoryPanel 行为差异：原默认所有列等宽，长 URL 被截断。
        applyColumnWidthPreferences(table);
        table.getSelectionModel().addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting()) {
                previewSelected();
            }
        });
        // 表格右键菜单：删除单条历史记录（不弹确认框）。弹出前自动选中鼠标所在行，
        // 与 FindingsPanel 的右键删除交互保持一致。
        table.setComponentPopupMenu(createContextMenu());

        JSplitPane messageSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                titled(requestEditor.uiComponent(), I18n.get().t("ui.common.request")),
                titled(responseEditor.uiComponent(), I18n.get().t("ui.common.response")));
        messageSplit.setResizeWeight(0.50);
        messageSplit.addComponentListener(new ComponentAdapter() {
            private boolean initialized;

            @Override
            public void componentResized(ComponentEvent event) {
                if (!initialized && messageSplit.getWidth() > 0) {
                    initialized = true;
                    messageSplit.setDividerLocation(0.50);
                }
            }
        });
        messageSplit.setPreferredSize(new java.awt.Dimension(900, 360));

        final JSplitPane finalContentSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table), messageSplit);
        finalContentSplit.setResizeWeight(0.50);
        finalContentSplit.addComponentListener(new ComponentAdapter() {
            private boolean initialized;

            @Override
            public void componentResized(ComponentEvent event) {
                if (!initialized && finalContentSplit.getHeight() > 0) {
                    initialized = true;
                    finalContentSplit.setDividerLocation(0.50);
                }
            }
        });
        addHierarchyListener(event -> {
            if ((event.getChangeFlags() & HierarchyEvent.SHOWING_CHANGED) != 0 && isShowing()) {
                SwingUtilities.invokeLater(() -> finalContentSplit.setDividerLocation(0.50));
            }
        });
        SwingUtilities.invokeLater(() -> finalContentSplit.setDividerLocation(0.50));
        add(finalContentSplit, BorderLayout.CENTER);

        if (store == null) {
            filterLabel.setEnabled(false);
            filterField.setEnabled(false);
            statusLabel.setText(I18n.get().t("ui.history.status.empty"));
        } else {
            store.addListener(ignored -> scheduleRefresh());
            refresh();
        }
    }

    /** 从内存索引刷新上方表格，不读取请求或响应正文。 */
    public void refresh() {
        if (store == null) {
            return;
        }
        long selectedId = selectedEntryId();
        tableModel.setRowCount(0);
        List<AnalysisHistoryEntry> records = store.list();
        String filter = filterField.getText().trim();
        for (AnalysisHistoryEntry entry : records) {
            // 筛选同时作用于 URL 与分析摘要：任一字段命中即保留
            if (!matchesFilter(filter, entry.getUrl(), entry.getSummary())) {
                continue;
            }
            tableModel.addRow(new Object[]{
                    entry.getId(),
                    TIME_FORMATTER.format(Instant.ofEpochMilli(entry.getTimestamp())),
                    entry.getMethod(),
                    entry.getUrl(),
                    // 类型列显示词随界面语言取(手动/Manual、被动/Passive)
                    I18n.get().t(entry.getTriggerType().displayKey()),
                    formatConclusion(entry.getFindingCount(), entry.getError()),
                    entry.getRiskLevel()
            });
        }
        if (selectedId >= 0) {
            for (int row = 0; row < tableModel.getRowCount(); row++) {
                Object value = tableModel.getValueAt(row, 0);
                if (value instanceof Long && (Long) value == selectedId) {
                    int viewRow = table.convertRowIndexToView(row);
                    table.setRowSelectionInterval(viewRow, viewRow);
                    break;
                }
            }
        }
        statusLabel.setText(I18n.get().t("ui.history.status.records", tableModel.getRowCount()));
    }

    /**
     * 组装"问题数量"列展示文本：失败时显示错误描述（带前缀），成功时按 finding 数量展示。
     *
     * <p>摘要原文（{@code entry.getSummary()}）不再直接出现在列表列里——
     * AI 自由生成的自然语言在表格列里既冗长又不可对比；统一用问题数量这种
     * 标准化字段，列表扫读速度更快，具体结论留在选中记录后的详情面板/弹窗里看。
     * 过滤功能仍可命中 summary（{@link #matchesFilter} 入参不变），保持原有检索习惯。</p>
     */
    private static String formatConclusion(int findingCount, String error) {
        if (error != null && !error.isEmpty()) {
            String shortErr = error.length() > ERROR_TRUNCATE_CHARS
                    ? error.substring(0, ERROR_TRUNCATE_CHARS) + "…"
                    : error;
            return I18n.get().t("ui.history.truncate.failPrefix") + shortErr;
        }
        if (findingCount <= 0) {
            return I18n.get().t("ui.history.conclusion.noIssues");
        }
        return I18n.get().t("ui.history.conclusion.findings", findingCount);
    }

    /**
     * 多字段通配符过滤：不区分大小写；星号匹配任意字符，其余按原文匹配；任一字段命中即视为通过。
     * 供本类（历史页签）和 {@code FindingsPanel}（问题页签）共用，分别传入 URL + 分析摘要 / URL + 描述。
     *
     * <p>空过滤串或 {@code "*"} 表示不过滤；任意字段为 null 视为不命中。</p>
     */
    public static boolean matchesFilter(String filter, String... fields) {
        if (filter == null || filter.isEmpty() || "*".equals(filter)) {
            return true;
        }
        if (fields == null || fields.length == 0) {
            return false;
        }
        String expression = "*" + filter.toLowerCase(Locale.ROOT) + "*";
        for (String raw : fields) {
            if (raw == null) {
                continue;
            }
            if (wildcardMatches(raw.toLowerCase(Locale.ROOT), expression)) {
                return true;
            }
        }
        return false;
    }

    /** 单值通配符匹配核心算法：仅做大小写无关的字面量 + 星号比对，无业务字段语义。 */
    private static boolean wildcardMatches(String value, String expression) {
        int valueIndex = 0;
        int expressionIndex = 0;
        int wildcardIndex = -1;
        int wildcardValueIndex = -1;
        while (valueIndex < value.length()) {
            if (expressionIndex < expression.length()
                    && expression.charAt(expressionIndex) != '*'
                    && expression.charAt(expressionIndex) == value.charAt(valueIndex)) {
                expressionIndex++;
                valueIndex++;
            } else if (expressionIndex < expression.length() && expression.charAt(expressionIndex) == '*') {
                wildcardIndex = expressionIndex++;
                wildcardValueIndex = valueIndex;
            } else if (wildcardIndex >= 0) {
                expressionIndex = wildcardIndex + 1;
                valueIndex = ++wildcardValueIndex;
            } else {
                return false;
            }
        }
        while (expressionIndex < expression.length() && expression.charAt(expressionIndex) == '*') {
            expressionIndex++;
        }
        return expressionIndex == expression.length();
    }

    /** 合并短时间内连续到达的 store 更新，避免每条记录都重绘表格。 */
    private void scheduleRefresh() {
        SwingUtilities.invokeLater(() -> {
            if (!refreshTimer.isRunning()) {
                refreshTimer.start();
            }
        });
    }

    /** 清空当前项目历史；操作前要求用户确认，避免误删。 */
    private void clearHistory() {
        if (store == null) {
            return;
        }
        // 文案：只显示主问题行,不再追加第二行括号说明。
        Object message = I18n.get().t("ui.history.confirmClear");
        int choice = JOptionPane.showConfirmDialog(this,
                message,
                I18n.get().t("ui.history.confirmTitle"), JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (choice != JOptionPane.YES_OPTION) {
            return;
        }
        try {
            store.clear();
            // 同步清空被动分析去重缓存：与"清空后同 URL 重新分析"的业务语义对齐。
            // store.clear 已清空磁盘索引 + body 文件；dedup 是内存里的"已分析指纹"集合，
            // 二者本应保持镜像——只清其一就会出现"清空了 UI 但被动分析仍跳过"的歧义。
            // 必须在 store.clear 之后做：若顺序相反，被动分析在中间窗口又命中同 URL
            // 仍会跳过（虽然概率极小，但语义上不干净）。
            if (passiveDedup != null) {
                passiveDedup.clear();
            }
            requestEditor.setRequest(HttpRequest.httpRequest());
            responseEditor.setResponse(HttpResponse.httpResponse());
            refresh();
            statusLabel.setText(passiveDedup == null ? I18n.get().t("ui.history.status.records", 0) : I18n.get().t("ui.history.status.cleared"));
        } catch (Exception e) {
            statusLabel.setText(I18n.get().t("ui.history.status.clearFailed", e.getMessage()));
        }
    }

    /**
     * 创建表格右键菜单：提供"删除记录"、"链路追踪"和"Clear history"三项。
     *
     * <p>弹出前自动选中鼠标所在行（避免"点行 A 但选中行 B"的错位，与
     * {@code FindingsPanel.createContextMenu} 的做法一致）；鼠标不在任何数据行上时
     * 禁用"删除记录"和"链路追踪"项，避免菜单在空白处可点却无事可删。"Clear history" 项
     * 在 store 不可用或当前无任何记录时禁用，保留确认弹窗语义。</p>
     *
     * <p>"删除记录"动作本身<b>不弹确认框</b>：需求约定右键菜单已表达明确的删除意图，
     * 不必再二次确认。"Clear history" 仍弹确认框，避免误清空（与原工具栏 Clear 按钮
     * 语义一致）。"链路追踪" 仅在当前 entry 对应 audit-trail 文件存在时启用——取消
     * / 旧数据 / 落盘失败时该 entry 没有 XML，菜单禁用而不是点了再弹错误。</p>
     */
    private JPopupMenu createContextMenu() {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem deleteItem = new JMenuItem(I18n.get().t("ui.menu.deleteEntry"));
        deleteItem.addActionListener(event -> deleteEntryAtSelectedRow());
        menu.add(deleteItem);
        JMenuItem trailItem = new JMenuItem(I18n.get().t("ui.menu.showAuditTrail"));
        trailItem.addActionListener(event -> showAuditTrailForSelectedRow());
        menu.add(trailItem);
        JMenuItem clearItem = new JMenuItem(I18n.get().t("ui.menu.clearHistory"));
        clearItem.addActionListener(event -> clearHistory());
        menu.add(clearItem);
        menu.addPopupMenuListener(new PopupMenuListener() {
            @Override
            public void popupMenuWillBecomeVisible(PopupMenuEvent event) {
                // 菜单在构造期只创建一次;每次弹出前按当前语言刷新文案,
                // 保证语言切换后右键菜单不会停留在旧语言。
                deleteItem.setText(I18n.get().t("ui.menu.deleteEntry"));
                trailItem.setText(I18n.get().t("ui.menu.showAuditTrail"));
                clearItem.setText(I18n.get().t("ui.menu.clearHistory"));
                Point point = table.getMousePosition();
                int row = point == null ? -1 : table.rowAtPoint(point);
                deleteItem.setEnabled(row >= 0 && store != null);
                // 链路追踪: 选中行存在 + 该 entry 关联了 audit-trail 文件;
                // 取消 / 旧数据 / 落盘失败时 entry.getAuditTrailFile() 为 null。
                AnalysisHistoryEntry selected = entryAtRow(row);
                trailItem.setEnabled(selected != null
                        && selected.getAuditTrailFile() != null
                        && java.nio.file.Files.exists(selected.getAuditTrailFile()));
                // Clear history: 至少要有一行可清空; store 不可用时禁用,避免点击后空操作
                clearItem.setEnabled(store != null && tableModel.getRowCount() > 0);
                if (row >= 0) {
                    table.setRowSelectionInterval(row, row);
                }
            }

            @Override
            public void popupMenuWillBecomeInvisible(PopupMenuEvent event) {
            }

            @Override
            public void popupMenuCanceled(PopupMenuEvent event) {
            }
        });
        return menu;
    }

    /**
     * 右键菜单"链路追踪"动作：弹出非模态窗口展示当前选中 entry 的 audit-trail。
     *
     * <p>每次都实时调用 {@link AuditTrailDialog#show} 解析 XML，<b>不</b>缓存结果——
     * 用户期望"现在看到的"就是磁盘上最新数据。如果未来要支持"刷新"按钮，再加缓存层；
     * 目前刻意保持简单，避免缓存与磁盘不一致的隐性 bug。</p>
     */
    private void showAuditTrailForSelectedRow() {
        AnalysisHistoryEntry entry = selectedEntry();
        if (entry == null || entry.getAuditTrailFile() == null) {
            return;
        }
        // 顶层 JFrame 作为父窗口:面板嵌在 MainTab 的 JScrollPane 里,直接传 null
        // 也能跑,但传入 owner 可让弹窗居中并保证最小化时一起隐藏。
        JFrame owner = findOwnerFrame();
        AuditTrailDialog dlg = new AuditTrailDialog(owner, entry);
        trailDialogs.add(dlg);
        dlg.asFrame().setVisible(true);
    }

    /** 沿父容器链找到顶层 {@link JFrame}（找不到时返回 null）。 */
    private JFrame findOwnerFrame() {
        java.awt.Window window = SwingUtilities.getWindowAncestor(this);
        if (window instanceof JFrame) {
            return (JFrame) window;
        }
        return null;
    }

    /** 返回当前表格选中行对应的 entry；未选中或 store 不可用时返回 null。 */
    private AnalysisHistoryEntry selectedEntry() {
        if (store == null) {
            return null;
        }
        long id = selectedEntryId();
        if (id < 0) {
            return null;
        }
        for (AnalysisHistoryEntry e : store.list()) {
            if (e.getId() == id) {
                return e;
            }
        }
        return null;
    }

    /**
     * 取出指定视图行的 entry（用于右键菜单弹出前判断可启用项）。
     * 与 {@link #selectedEntry()} 区别：传入具体行号，避免"鼠标在 A 行但 selectedRow
     * 还停留在 B 行"的时序问题。
     */
    private AnalysisHistoryEntry entryAtRow(int viewRow) {
        if (store == null || viewRow < 0) {
            return null;
        }
        int modelRow = table.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= tableModel.getRowCount()) {
            return null;
        }
        Object value = tableModel.getValueAt(modelRow, 0);
        if (!(value instanceof Long)) {
            return null;
        }
        long id = (Long) value;
        for (AnalysisHistoryEntry e : store.list()) {
            if (e.getId() == id) {
                return e;
            }
        }
        return null;
    }

    /**
     * 删除当前选中行的单条历史记录（右键菜单"删除记录"）。
     *
     * <p>不弹确认框。流程：先取消该记录可能仍在飞行的预览加载，再调用
     * {@link AnalysisHistoryStore#delete}；删除成功后<b>同步被动分析去重缓存</b>——
     * 若没有其它保留记录还持有同一请求指纹，则从 {@code FingerprintDedup} 移除该指纹
     * （与 Clear 全清时同步清空 dedup 同一语义：删除后同 URL 的新报文可被重新被动分析）。
     * 随后清空 Request / Response 预览区并立即刷新表格，让该行立刻消失（store listener
     * 还会再补一次延迟刷新，双重触发幂等，无副作用）。</p>
     */
    private void deleteEntryAtSelectedRow() {
        long entryId = selectedEntryId();
        if (store == null || entryId < 0) {
            return;
        }
        // 先取消在飞预览：删除后不能让陈旧报文再回填到下方编辑器
        cancelInFlightPreview();
        AnalysisHistoryEntry removed;
        try {
            removed = store.delete(entryId);
        } catch (Exception e) {
            statusLabel.setText(I18n.get().t("ui.history.deleteFailed", e.getMessage()));
            return;
        }
        if (removed == null) {
            statusLabel.setText(I18n.get().t("ui.history.alreadyGone", entryId));
            return;
        }
        // 同步被动分析去重缓存：删除该记录后，同 URL 的新报文不应再被判为"已分析过"而跳过。
        // 顺序与 Clear 全清一致（先 store 后 dedup），避免中间窗口被动分析误判。
        // 老记录 requestFingerprint 可能为 null（升级前数据）：containsFingerprint(null)
        // 与 remove(null) 都是安全 no-op，不会误删其它指纹。
        if (passiveDedup != null) {
            String fingerprint = removed.getRequestFingerprint();
            // 若还有其它保留记录持有同一指纹，说明该请求仍有一条"已分析"记录在案，
            // dedup 标记应保留（与 body 文件"仍被引用则保留"的清理语义一致）。
            if (!store.containsFingerprint(fingerprint)) {
                passiveDedup.remove(fingerprint);
            }
        }
        requestEditor.setRequest(null);
        responseEditor.setResponse(null);
        // store 的 listener 已调度一次延迟 refresh；这里立即刷一次让行立刻消失
        refresh();
    }

    /** 取消当前在飞行的报文加载任务并复位引用（删除记录时避免陈旧预览回填）。 */
    private void cancelInFlightPreview() {
        SwingWorker<Void, Void> inFlight = loadInFlight.getAndSet(null);
        if (inFlight != null && !inFlight.isDone()) {
            inFlight.cancel(true);
        }
    }

    /** 单击记录后在后台读取报文并更新下方 Request/Response 预览区。 */
    private void previewSelected() {
        long entryId = selectedEntryId();
        if (entryId >= 0 && store != null) {
            loadRecord(entryId);
        }
    }

    /**
     * 在后台读取 entry 关联的 gzip 报文并更新预览区。
     *
     * <p>旧在飞行的任务会被取消，避免快速切换时旧任务完成后覆盖新数据。</p>
     */
    private void loadRecord(long entryId) {
        SwingWorker<Void, Void> previous = loadInFlight.getAndSet(null);
        if (previous != null && !previous.isDone()) {
            previous.cancel(true);
        }

        statusLabel.setText(I18n.get().t("ui.history.preview.loading"));
        SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                AnalysisHistoryEntry entry = store.get(entryId);
                if (entry == null || isCancelled()) {
                    return null;
                }
                byte[] reqBytes = readBody(entry.getRequestFile());
                byte[] respBytes = readBody(entry.getResponseFile());
                if (isCancelled()) {
                    return null;
                }
                // 在 SwingWorker done() 里更新 UI，这里只把字节带出来
                final byte[] finalReq = reqBytes;
                final byte[] finalResp = entry.isHasResponse() ? respBytes : null;
                SwingUtilities.invokeLater(() -> {
                    if (isCancelled()) {
                        return;
                    }
                    applyToEditors(entry, finalReq, finalResp);
                });
                return null;
            }

            @Override
            protected void done() {
                if (loadInFlight.get() != this) {
                    return;
                }
                loadInFlight.set(null);
                try {
                    if (isCancelled()) {
                        statusLabel.setText(I18n.get().t("ui.history.preview.cancelled"));
                        return;
                    }
                    get();
                    statusLabel.setText(I18n.get().t("ui.history.preview.loaded", entryId));
                } catch (Exception e) {
                    statusLabel.setText(I18n.get().t("ui.history.preview.loadFailed", e.getMessage()));
                }
            }
        };
        loadInFlight.set(worker);
        worker.execute();
    }

    /** 把 request / response 字节写入 Burp 原生编辑器。 */
    private void applyToEditors(AnalysisHistoryEntry entry, byte[] reqBytes, byte[] respBytes) {
        if (reqBytes != null && reqBytes.length > 0) {
            requestEditor.setRequest(HttpRequest.httpRequest(ByteArray.byteArray(reqBytes)));
        } else {
            requestEditor.setRequest(null);
        }
        if (respBytes != null && respBytes.length > 0) {
            responseEditor.setResponse(HttpResponse.httpResponse(ByteArray.byteArray(respBytes)));
        } else {
            // 无响应时让 Montoya 显示 "No response" 占位符
            responseEditor.setResponse(null);
        }
    }

    /** 从 gzip 文件读 body 字节；文件为 null 时返回 null（语义：没有该部分）。 */
    private static byte[] readBody(Path file) {
        if (file == null) {
            return null;
        }
        try {
            byte[] decompressed = BodyStorage.readCompressed(file);
            return decompressed.length == 0 ? null : decompressed;
        } catch (IOException e) {
            return null;
        }
    }

    /** 返回当前表格选中的 entry id；没有选中记录时返回 -1。 */
    private long selectedEntryId() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            return -1L;
        }
        int modelRow = table.convertRowIndexToModel(viewRow);
        Object value = tableModel.getValueAt(modelRow, 0);
        if (value instanceof Long) {
            return (Long) value;
        }
        return -1L;
    }

    /**
     * 设置表格各列的 preferredWidth / minWidth / maxWidth。
     *
     * <p>列宽策略（按表格列顺序）：</p>
     * <ul>
     *   <li><b>序号</b>：固定 60px——纯数字 + 短</li>
     *   <li><b>时间</b>：固定 170px——"yyyy-MM-dd HH:mm:ss" 19 字符</li>
     *   <li><b>Method</b>：固定 80px——"GET" / "POST" 短字</li>
     *   <li><b>URL</b>：弹性（preferred 400、最小 200）——核心字段，最长</li>
     *   <li><b>类型</b>：固定 80px——"手动" / "被动"</li>
     *   <li><b>问题数量</b>：固定 140px——"999 个问题" / "无问题" / "[失败] 短描述"，列内容已标准化为短字</li>
     *   <li><b>风险</b>：固定 90px——"严重" / "高危" / "—" 3 字</li>
     * </ul>
     *
     * <p>弹性列允许用户在表头分隔条上拖动调整；固定列不可拖。整体布局：
     "窄-窄-窄-弹-窄-窄-窄"，与原 HttpHistoryPanel "全部等宽"相比，长字段不再被截断，
     短字段也不再虚占过多横向空间。</p>
     */
    private static void applyColumnWidthPreferences(JTable table) {
        // 列顺序必须与 currentColumns() 长度(7)一致: 序号/时间/Method/URL/类型/问题数量/风险。
        int[] fixedWidths = {60, 170, 80, 0, 80, 140, 90};
        int[] minWidths = {60, 170, 80, 200, 80, 140, 90};
        // 弹性列的 preferred 宽度（initial），后续可由用户拖动
        int[] preferredWidths = {60, 170, 80, 400, 80, 140, 90};
        for (int i = 0; i < fixedWidths.length; i++) {
            TableColumn column = table.getColumnModel().getColumn(i);
            column.setPreferredWidth(preferredWidths[i]);
            column.setMinWidth(minWidths[i]);
            if (fixedWidths[i] > 0) {
                // 固定列：maxWidth = preferred，禁止拖宽
                column.setMaxWidth(fixedWidths[i]);
                column.setResizable(false);
            } else {
                // 弹性列：maxWidth 不限，允许拖动
                column.setMaxWidth(Integer.MAX_VALUE);
                column.setResizable(true);
            }
        }
    }

    /** 使用与"分析"页签一致的标题边框包裹 Burp 原生报文编辑器。 */
    private static JPanel titled(Component component, String title) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder(title));
        panel.add(component, BorderLayout.CENTER);
        return panel;
    }

    /**
     * 风险等级颜色渲染：仅"风险"列（最后一列）按风险等级染底色 + 加粗；
     * 其它列走默认外观。"严重" 红 / "高危" 橙 / "中危" 黄 / "低危" 蓝 / "信息" 浅灰 / "—" 灰。
     */
    private static final class RiskLevelAwareRenderer extends DefaultTableCellRenderer {

        @Serial
        private static final long serialVersionUID = 1L;

        /**
         * 按语言缓存 RiskLevel → 显示词：避免每个单元格每次 paint 都查 ResourceBundle。
         * 5 个非 NONE 档位 × N 行 × 频繁 repaint 时省下 N×5 次 HashMap 查找。
         * 语言切换时 {@link #cachedLang} 与 {@link I18n#current()} 不一致，下次渲染时
         * 重建 {@link #labelCache}，不需要在 {@code refreshI18n} 里专门调用。
         */
        private final EnumMap<RiskLevel, String> labelCache = new EnumMap<>(RiskLevel.class);
        private com.auditai.burp.ai.PromptBuilder.Lang cachedLang;

        private String labelFor(RiskLevel risk) {
            if (cachedLang != I18n.get().current()) {
                labelCache.clear();
                for (RiskLevel r : RiskLevel.values()) {
                    // 无风险档位固定 "NONE",不跟随 i18n 走翻译(避免"无"/"无风险"等本地化文本过长占列宽)
                    labelCache.put(r, r == RiskLevel.NONE ? "NONE" : I18n.get().t(r.displayKey()));
                }
                cachedLang = I18n.get().current();
            }
            return labelCache.get(risk);
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (value instanceof RiskLevel risk) {
                setText(labelFor(risk));
                // 无风险档位不染底色,沿用 JTable 默认背景,避免大段无风险记录时整列灰底抢眼
                if (risk == RiskLevel.NONE) {
                    if (!isSelected) {
                        c.setBackground(table.getBackground());
                        c.setForeground(table.getForeground());
                    } else {
                        c.setBackground(table.getSelectionBackground());
                        c.setForeground(table.getSelectionForeground());
                    }
                } else {
                    Color background = colorFor(risk);
                    if (!isSelected) {
                        c.setBackground(background);
                        c.setForeground(textColorFor(risk));
                    } else {
                        // 选中态保持 Swing 默认高亮（避免用户看不清选中行）
                        c.setBackground(table.getSelectionBackground());
                        c.setForeground(table.getSelectionForeground());
                    }
                }
                setFont(getFont().deriveFont(java.awt.Font.BOLD));
            } else {
                if (!isSelected) {
                    c.setBackground(table.getBackground());
                    c.setForeground(table.getForeground());
                } else {
                    c.setBackground(table.getSelectionBackground());
                    c.setForeground(table.getSelectionForeground());
                }
                setFont(getFont().deriveFont(java.awt.Font.PLAIN));
            }
            return c;
        }

        private Color colorFor(RiskLevel risk) {
            return switch (risk) {
                case CRITICAL -> new Color(255, 200, 200);
                case HIGH -> new Color(255, 220, 180);
                case MEDIUM -> new Color(255, 240, 180);
                case LOW -> new Color(200, 220, 255);
                case INFO -> new Color(220, 220, 220);
                case NONE -> new Color(240, 240, 240);
            };
        }

        private Color textColorFor(RiskLevel risk) {
            return switch (risk) {
                case CRITICAL, HIGH -> new Color(120, 0, 0);
                case MEDIUM -> new Color(120, 80, 0);
                case LOW -> new Color(0, 50, 120);
                case INFO, NONE -> new Color(60, 60, 60);
            };
        }
    }
    @Override
    public void refreshI18n() {
        if (store == null) {
            // 空态(历史库不可用):无表可刷,只需刷新状态行文案。
            statusLabel.setText(I18n.get().t("ui.history.status.empty"));
            return;
        }
        // 列名变化:重新填充表格
        tableModel.setColumnIdentifiers(currentColumns());
        // setColumnIdentifiers 会重建 TableColumnModel，构造期 applyColumnWidthPreferences
        // 设的各列宽度随之作废——不重设的话切一次语言所有列都回到等宽默认值。
        applyColumnWidthPreferences(table);
        // 重新拉数据(用最新翻译填充行)
        refresh();
    }

    /**
     * 释放资源：插件卸载时调用。停止防抖定时器、取消在飞行的报文加载任务、
     * 注销 I18n 监听器，避免后台 SwingWorker 继续引用已卸载的编辑器。
     */
    public void close() {
        if (refreshTimer != null && refreshTimer.isRunning()) {
            refreshTimer.stop();
        }
        cancelInFlightPreview();
        // 关闭所有已打开的"链路追踪"弹窗：dialog 自身有 i18n listener，
        // 走 AuditTrailDialog.dispose() 一并注销，避免扩展卸载后仍持有 dialog 引用。
        AuditTrailDialog.disposeAll(trailDialogs);
        I18n.get().off(i18nListener);
    }

    /**
     * I18n 语言切换监听器：close() 时注销。
     */
    private final java.util.function.Consumer<com.auditai.burp.ai.PromptBuilder.Lang> i18nListener =
            lang -> refreshI18n();
}
