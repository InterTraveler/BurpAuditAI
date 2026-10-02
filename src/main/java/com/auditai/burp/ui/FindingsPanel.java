package com.auditai.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.auditai.burp.history.AnalysisHistoryEntry;
import com.auditai.burp.history.AnalysisHistoryStore;
import com.auditai.burp.http.BodyStorage;
import com.auditai.burp.http.Finding;
import com.auditai.burp.http.FindingStore;
import com.auditai.burp.http.Severity;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.Timer;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableColumn;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Point;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.HierarchyEvent;
import java.io.IOException;
import java.io.Serial;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.IntConsumer;

/**
 * "问题"页签：以"模型分析后认为存在 / 可疑"的视角展示当前会话的发现。
 *
 * <p>布局与 {@link AnalysisHistoryPanel} 一致：</p>
 * <ul>
 *   <li><b>上方</b>：表格，每行 = 一条 finding。按"安装时间升序"展示（最旧在前、
 *       最新在底，{@link FindingStore#list()} 已按该顺序返回，与"历史"页签的
 *       "新条目滚到底部"行为一致），顶部 URL 过滤框按 URL / 描述模糊过滤；</li>
 *   <li><b>下方</b>：页签容器，两个页签：
 *     <ol>
 *       <li><b>分析报告</b>（最左，符合"分析报告在左边的第一个位置"）：本次分析的完整报告 + 本条 finding 的描述/证据；</li>
 *       <li><b>报文</b>：左右分栏显示 Request / Response（与 Burp Proxy/Repeater 一致）。</li>
 *     </ol>
 *   </li>
 * </ul>
 *
 * <p>Request / Response 默认优先从 finding 所属的 {@link FindingStore.AnalysisContext}
 * 定位的原文拉取；找不到时按 (method, url) 在 {@link AnalysisHistoryStore} 反查最近一条。</p>
 */
public final class FindingsPanel extends JPanel implements LocaleAware {

    @Serial
    private static final long serialVersionUID = 1L;

    /** 表格列：严重程度 / 可信度 / 类型 / 描述 / URL / 方法 / 时间。 */
    private static final String[] COLUMNS = {
            I18n.get().t("ui.findings.col.severity"), I18n.get().t("ui.findings.col.confidence"), I18n.get().t("ui.findings.col.type"), I18n.get().t("ui.findings.col.desc"), I18n.get().t("ui.findings.col.url"), I18n.get().t("ui.findings.col.method"), I18n.get().t("ui.findings.col.time")
    };

    /**
     * 表格中"隐藏列"的下标，存放 {@link Finding#getFindingId()}。
     *
     * <p>原本"恢复选中 / 选中时反查 finding"靠 description + url 软匹配，但同一次
     * 分析多条 finding 完全可能 description + url 都一样（占位 finding 尤为明显），
     * 会选错行。把 findingId 单独放一隐藏列，所有需要精确匹配的地方都按这一列来，
     * 不再依赖软匹配。</p>
     */
    private final int COLUMN_FINDING_ID;

    /** 实例化:基于当前 columns 字段构造"可见列 + 隐藏 ID 列"的表头。 */
    private String[] buildColumnNames() {
        String[] names = new String[columns.length + 1];
        System.arraycopy(columns, 0, names, 0, columns.length);
        names[columns.length] = I18n.get().t("ui.findings.col.id");
        return names;
    }

    /** 时间格式：本地时区 "yyyy-MM-dd HH:mm:ss"。 */
    private static final SimpleDateFormat TIME_FORMAT =
            new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.ROOT);

    /** 按当前 I18n 语言返回可见列名(列数固定 7)。 */
    private static String[] currentColumns() {
        return new String[]{
                I18n.get().t("ui.findings.col.severity"),
                I18n.get().t("ui.findings.col.confidence"),
                I18n.get().t("ui.findings.col.type"),
                I18n.get().t("ui.findings.col.desc"),
                I18n.get().t("ui.findings.col.url"),
                I18n.get().t("ui.findings.col.method"),
                I18n.get().t("ui.findings.col.time")
        };
    }

    private final FindingStore store;
    private final AnalysisHistoryStore historyStore;
    /** Burp API 门面：仅用于诊断日志（logError）；非线程安全，仅 EDT 访问。 */
    private final MontoyaApi api;
    /**
     * 问题数量变化回调：每次 {@link #refresh()} 末尾调用，参数为当前可见（已过滤）条数。
     * 主界面的"问题"页签标题用它来显示数字徽章；为 null 时不通知。
     */
    private final IntConsumer onCountChanged;
    /** 可见列名(列数固定 7,内容按 I18n 实时取)。 */
    private final String[] columns;

    private final DefaultTableModel tableModel;
    private final JTable table;
    private final JTextField filterField = new JTextField(32);
    private final JLabel statusLabel = new JLabel();
    /** 合并多次刷新请求，避免每次 addFindings 都重绘表格。 */
    private final Timer refreshTimer;

    /** 下方详情：页签容器，两个页签：分析报告 / 报文（Request 与 Response 在"报文"页签内左右分栏）。 */
    private final JTabbedPane detailTabs = new JTabbedPane();
    /** 分析报告：纯文本，按"全文报告 + 每条 finding 明细"渲染。 */
    private final JTextArea reportArea = new JTextArea();
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;

    /** 当前选中的 finding（listSelectionListener 内用到）。 */
    private Finding currentSelection;

    /**
     * 在飞的"选中行报文加载"任务（{@link SwingWorker} 句柄）。
     *
     * <p>选中行切换 / 详情区清空时取消旧任务并置空引用，防止旧任务完成后把
     * 已过期选择的报文回填到编辑器（与 {@link AnalysisHistoryPanel} 的做法一致）。</p>
     */
    private final AtomicReference<SwingWorker<byte[][], Void>> messageLoadInFlight = new AtomicReference<>();

    /**
     * @param api             Burp API 门面。
     * @param store           问题库；为 null 时页签显示空态。
     * @param historyStore    已分析历史库（用于反查 Request/Response 字节）。
     * @param onCountChanged  数量变化回调（参数 = 当前可见条数），可为 null。
     */
    public FindingsPanel(MontoyaApi api, FindingStore store, AnalysisHistoryStore historyStore,
                         IntConsumer onCountChanged) {
        super(new BorderLayout(6, 6));
        this.store = store;
        this.historyStore = historyStore;
        this.api = api;
        this.onCountChanged = onCountChanged;
        this.columns = currentColumns();
        this.COLUMN_FINDING_ID = columns.length;
        this.tableModel = new DefaultTableModel(buildColumnNames(), 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        this.requestEditor = api.userInterface().createHttpRequestEditor();
        this.responseEditor = api.userInterface().createHttpResponseEditor();
        this.table = new JTable(tableModel);
        this.refreshTimer = new Timer(200, event -> refresh());
        this.refreshTimer.setRepeats(false);
        setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

        add(buildToolbar(), BorderLayout.NORTH);
        add(buildCenterSplit(), BorderLayout.CENTER);

        // I18n: 切语言时刷新列名(直接重置 DefaultTableModel 的列标识符)。
        I18n.get().onChange(i18nListener);

        // 监听 store 变化：每次新增 / 清空都触发防抖刷新
        if (store != null) {
            store.addListener(ignored -> scheduleRefresh());
            refresh();
        }
        if (historyStore == null) {
            statusLabel.setText(I18n.get().t("ui.findings.status.empty"));
        }
    }

    /** 顶部工具栏：左侧 URL 过滤 + 状态。Clear 入口已迁到表格右键菜单。 */
    private JPanel buildToolbar() {
        JPanel toolbar = new JPanel(new BorderLayout(4, 0));
        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        // 文本/tooltip 均通过 I18n 弱引用订阅自动刷新,refreshI18n 里无需再手动 setText。
        JLabel filterLabel = I18n.label("ui.findings.filterLabel");
        I18n.tooltip(filterField, "ui.findings.filterTip");
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
        return toolbar;
    }

    /** 上下分栏：上方表格 + 下方 JTabbedPane（分析报告 / Request / Response）。 */
    private JSplitPane buildCenterSplit() {
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(true);
        table.setFillsViewportHeight(true);
        // 严重程度列用彩色渲染（critical 红 / high 橙 / medium 黄 / low 蓝 / info 灰）
        table.setDefaultRenderer(Object.class, new SeverityAwareRenderer());
        // 表头左对齐：JTable 默认居中，但 Burp Suite 原生表格列标题一律左对齐，
        // 跟宿主视觉风格保持一致。
        JTableHeader header = table.getTableHeader();
        DefaultTableCellRenderer headerRenderer = (DefaultTableCellRenderer) header.getDefaultRenderer();
        headerRenderer.setHorizontalAlignment(SwingConstants.LEFT);
        table.getSelectionModel().addListSelectionListener(this::onSelectionChanged);
        // 隐藏 ID 列：仅作为 finding 精确匹配的内部 key，不暴露给用户
        applyHiddenIdColumn();
        // 表格右键菜单：删除选中记录
        table.setComponentPopupMenu(createContextMenu());

        JScrollPane tableScroll = new JScrollPane(table);

        // —— 下方：分析报告 + 报文 两个页签；报文页签内 Request/Response 左右分栏（与 Burp 其它模块一致） ——
        reportArea.setEditable(false);
        reportArea.setLineWrap(true);
        reportArea.setWrapStyleWord(true);
        reportArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        // 报文：Request | Response 左右分栏；和 AnalysisHistoryPanel 同样 50/50 起手可拖动
        JSplitPane messageSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                titled(requestEditor.uiComponent(), I18n.get().t("ui.common.request")),
                titled(responseEditor.uiComponent(), I18n.get().t("ui.common.response")));
        messageSplit.setResizeWeight(0.50);
        messageSplit.setPreferredSize(new java.awt.Dimension(900, 360));
        // 首次获得真实尺寸后再设 dividerLocation（构造期 width=0 时设置会被忽略）
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

        // 分析报告在第一个（最左）位置，符合"分析报告在左边的第一个位置"语义
        detailTabs.addTab(I18n.get().t("ui.findings.tab.report"), new JScrollPane(reportArea));
        detailTabs.addTab(I18n.get().t("ui.findings.tab.message"), messageSplit);

        final JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailTabs);
        split.setResizeWeight(0.55);
        // 与 AnalysisHistoryPanel 同样的"首次获得真实尺寸后再分"套路
        split.addComponentListener(new java.awt.event.ComponentAdapter() {
            private boolean initialized;

            @Override
            public void componentResized(java.awt.event.ComponentEvent event) {
                if (!initialized && split.getHeight() > 0) {
                    initialized = true;
                    split.setDividerLocation(0.55);
                }
            }
        });
        addHierarchyListener(event -> {
            if ((event.getChangeFlags() & HierarchyEvent.SHOWING_CHANGED) != 0 && isShowing()) {
                SwingUtilities.invokeLater(() -> split.setDividerLocation(0.55));
            }
        });
        SwingUtilities.invokeLater(() -> split.setDividerLocation(0.55));
        return split;
    }

    /** 合并短时间内的连续 addFindings / filter 输入，避免每次都重绘。 */
    private void scheduleRefresh() {
        SwingUtilities.invokeLater(() -> {
            if (!refreshTimer.isRunning()) {
                refreshTimer.start();
            }
        });
    }

    /** 重新从 store 拉取全量 finding 列表，按 URL 过滤后写入表格。 */
    void refresh() {
        if (store == null) {
            return;
        }
        Finding previousSelection = currentSelection;
        tableModel.setRowCount(0);
        List<Finding> all = store.list();
        String filter = filterField.getText().trim();
        for (Finding f : all) {
            // 筛选同时作用于 URL 与描述：任一字段命中即保留
            if (!AnalysisHistoryPanel.matchesFilter(filter, f.getUrl(), f.getDescription())) {
                continue;
            }
            // 描述列：占位 finding 加 "(占位)" 后缀，让用户一眼区分
            String description = f.getDescription();
            if (f.isPlaceholder() && !description.endsWith(I18n.get().t("ui.findings.report.placeholderSuffix"))) {
                description = description + I18n.get().t("ui.findings.report.placeholderSuffix");
            }
            Object[] row = new Object[COLUMNS.length + 1];
            // 第 0 列直接存 Severity 枚举:排序按等级档位,显示文本由渲染器按当前语言取
            row[0] = f.getSeverity();
            row[1] = f.getConfidence() + "%";
            row[2] = f.getType();
            row[3] = description;
            row[4] = f.getUrl();
            row[5] = f.getMethod();
            row[6] = TIME_FORMAT.format(new Date(f.getCapturedAtMillis()));
            row[COLUMN_FINDING_ID] = f.getFindingId();
            tableModel.addRow(row);
        }
        statusLabel.setText(I18n.get().t("ui.findings.status.count", tableModel.getRowCount()));
        // 通知数量变化（主界面"问题"页签标题用）
        if (onCountChanged != null) {
            try {
                onCountChanged.accept(tableModel.getRowCount());
            } catch (RuntimeException ignored) {
                // UI 回调异常不影响主流程
            }
        }

        // 尝试恢复旧选中：按 findingId 精确匹配（不再靠 description+url 软匹配）
        if (previousSelection != null) {
            String wantId = previousSelection.getFindingId();
            for (int row = 0; row < tableModel.getRowCount(); row++) {
                if (wantId.equals(tableModel.getValueAt(row, COLUMN_FINDING_ID))) {
                    int viewRow = table.convertRowIndexToView(row);
                    table.setRowSelectionInterval(viewRow, viewRow);
                    break;
                }
            }
        }
    }

    /**
     * 选中某条 finding 时刷新下方详情：报告 / Request / Response。
     * 报告内容由"完整分析报告 + 本条 finding 明细"组成；Request/Response 从
     * ProxyTrafficStore 反查（按 url+method 取最近一条）。
     */
    private void onSelectionChanged(ListSelectionEvent event) {
        if (event.getValueIsAdjusting()) {
            return;
        }
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            currentSelection = null;
            clearDetail();
            return;
        }
        int modelRow = table.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= tableModel.getRowCount()) {
            currentSelection = null;
            clearDetail();
            return;
        }
        // 隐藏列拿 findingId，直接去 store 精确定位当前 finding
        Object idCell = tableModel.getValueAt(modelRow, COLUMN_FINDING_ID);
        if (!(idCell instanceof String)) {
            currentSelection = null;
            clearDetail();
            return;
        }
        String findingId = (String) idCell;
        Finding found = null;
        for (Finding f : store.list()) {
            if (findingId.equals(f.getFindingId())) {
                found = f;
                break;
            }
        }
        if (found == null) {
            currentSelection = null;
            clearDetail();
            return;
        }
        currentSelection = found;
        renderDetail(found);
    }

    /** 渲染下方"分析报告"页签内容：先整段分析报告，再附"本条 finding"的完整描述。 */
    private void renderReport(Finding finding) {
        FindingStore.AnalysisContext ctx = store.contextFor(finding);
        StringBuilder sb = new StringBuilder();
        sb.append(I18n.get().t("ui.findings.report.fullTitle")).append('\n');
        if (ctx.getSummary() == null || ctx.getSummary().isBlank()) {
            sb.append(I18n.get().t("ui.findings.report.none")).append('\n');
        } else {
            sb.append(ctx.getSummary()).append('\n');
        }
        sb.append('\n');
        sb.append(I18n.get().t("ui.findings.report.detailTitle")).append('\n');
        sb.append(I18n.get().t("ui.findings.report.type")).append(finding.getType());
        if (finding.isPlaceholder()) {
            sb.append(I18n.get().t("ui.findings.report.placeholderHint"));
        }
        sb.append('\n');
        Severity severity = finding.getSeverity();
        sb.append(I18n.get().t("ui.findings.report.severity",
                severity == null ? I18n.get().t("ui.level.info") : I18n.get().t(severity.displayKey()),
                severity == null ? 0 : severity.rank)).append('\n');
        sb.append(I18n.get().t("ui.findings.report.confidence", finding.getConfidence())).append('\n');
        sb.append(I18n.get().t("ui.findings.report.url", finding.getMethod(), finding.getUrl())).append('\n');
        // 占位 finding：description 已经是 analysis 截取，不再额外展示避免重复
        if (!finding.isPlaceholder()
                && finding.getDescription() != null && !finding.getDescription().isBlank()) {
            sb.append('\n').append(I18n.get().t("ui.findings.report.descTitle"))
                    .append('\n').append(finding.getDescription()).append('\n');
        } else if (finding.isPlaceholder()
                && finding.getDescription() != null && !finding.getDescription().isBlank()) {
            sb.append('\n').append(I18n.get().t("ui.findings.report.placeholderTitle"))
                    .append('\n').append(finding.getDescription()).append('\n');
        }
        reportArea.setText(sb.toString());
        reportArea.setCaretPosition(0);
    }

    /**
     * 把 finding 对应的 Request / Response 写入下方编辑器。
     *
     * <p><b>取报文优先级：</b></p>
     * <ol>
     *   <li>{@link FindingStore.AnalysisContext#getRequestBytes()} / {@code getResponseBytes()}
     *       （由 MessageTab 在分析完成时缓存的原文，<b>仅内存</b>）；</li>
     *   <li>{@link AnalysisHistoryStore} 按 (method, url) 反查时间最近一条
     *       （磁盘恢复后或 finding 来自代理流量的兜底，按需解压读 gzip）；</li>
     *   <li>都没有 → 清空两个编辑器，Burp 编辑器自动显示 "No response" 占位符。</li>
     * </ol>
     *
     * <p>正文获取在 {@link SwingWorker} 后台线程执行：第 2 层命中时含 gzip 读盘，
     * 不能在 EDT 上同步做（与 {@link AnalysisHistoryPanel} 的后台加载范式一致）。
     * 快速切换选中行会取消旧任务（{@link #messageLoadInFlight}），防止旧数据回填。</p>
     *
     * <p>不调 {@code setRequest(HttpRequest.httpRequest())} / {@code setResponse(null)}
     * 这类"空实例"，避免让 Burp 原生编辑器进入"incomplete"异常态。
     * </p>
     */
    private void renderMessage(Finding finding) {
        // 取消上一次仍在飞行的加载任务（如果它还没结束），避免旧任务覆盖新选择
        SwingWorker<byte[][], Void> previous = messageLoadInFlight.getAndSet(null);
        if (previous != null && !previous.isDone()) {
            previous.cancel(true);
        }
        SwingWorker<byte[][], Void> worker = new SwingWorker<>() {
            @Override
            protected byte[][] doInBackground() {
                // 1. 优先：AnalysisContext 里缓存的原文（纯内存，无 IO）
                FindingStore.AnalysisContext ctx = store.contextFor(finding);
                byte[] reqBytes = ctx.getRequestBytes();
                byte[] respBytes = ctx.getResponseBytes();
                // 2. 兜底：AnalysisHistoryStore 反查（gzip 读盘只发生在后台线程）
                if (reqBytes == null || reqBytes.length == 0) {
                    byte[] historyReq = lookupRequestFromHistoryStore(finding);
                    if (historyReq != null) {
                        reqBytes = historyReq;
                    }
                }
                if (respBytes == null || respBytes.length == 0) {
                    byte[] historyResp = lookupResponseFromHistoryStore(finding);
                    if (historyResp != null) {
                        respBytes = historyResp;
                    }
                }
                if (isCancelled()) {
                    return null;
                }
                return new byte[][] {reqBytes, respBytes};
            }

            @Override
            protected void done() {
                // 只在"自己仍是当前加载任务"时才写编辑器：
                // 已被更新的选择 / 清空替换（引用被置空或换新）则直接放弃。
                if (messageLoadInFlight.get() != this) {
                    return;
                }
                messageLoadInFlight.set(null);
                if (isCancelled()) {
                    return;
                }
                try {
                    byte[][] bytes = get();
                    if (isCancelled()) {
                        return;
                    }
                    applyMessageToEditors(bytes[0], bytes[1]);
                } catch (Exception e) {
                    // 读取失败视为"找不到报文"：清空编辑器，避免展示脏数据或卡死 UI；
                    // 同时把异常写日志——SwingWorker.done() 里没有挂顶层异常处理，
                    // 这里没记就会完全静默丢失，给排错带来麻烦。
                    logError("读取历史报文失败：" + e.getMessage(), e);
                    requestEditor.setRequest(null);
                    responseEditor.setResponse(null);
                }
            }
        };
        messageLoadInFlight.set(worker);
        worker.execute();
    }

    /** 在 EDT 上把 request / response 字节写入 Burp 原生编辑器（空字节用 null 显示占位）。 */
    private void applyMessageToEditors(byte[] reqBytes, byte[] respBytes) {
        // 3. 写入编辑器：空字节用 null，让 Burp 显示 "No response" 占位符
        try {
            if (reqBytes != null && reqBytes.length > 0) {
                requestEditor.setRequest(HttpRequest.httpRequest(ByteArray.byteArray(reqBytes)));
            } else {
                requestEditor.setRequest(null);
            }
            if (respBytes != null && respBytes.length > 0) {
                responseEditor.setResponse(HttpResponse.httpResponse(ByteArray.byteArray(respBytes)));
            } else {
                responseEditor.setResponse(null);
            }
        } catch (RuntimeException ignored) {
            // 极端情况：字节非法（不是合法 HTTP 报文）。清空两个编辑器避免 UI 卡死
            requestEditor.setRequest(null);
            responseEditor.setResponse(null);
        }
    }

    /** AnalysisHistoryStore 反查 (method, url) 时间最近的 request 字节。找不到时返回 null。 */
    private byte[] lookupRequestFromHistoryStore(Finding finding) {
        AnalysisHistoryEntry entry = lookupHistoryEntry(finding);
        if (entry == null) {
            return null;
        }
        return readEntryBody(entry.getRequestFile());
    }

    /** AnalysisHistoryStore 反查 (method, url) 时间最近的 response 字节。 */
    private byte[] lookupResponseFromHistoryStore(Finding finding) {
        AnalysisHistoryEntry entry = lookupHistoryEntry(finding);
        if (entry == null) {
            return null;
        }
        if (!entry.isHasResponse()) {
            return null;
        }
        return readEntryBody(entry.getResponseFile());
    }

    /**
     * 在 historyStore 里按 (method, url) 反查时间最近的 entry；
     * method 为空时只按 URL 匹配。
     */
    private AnalysisHistoryEntry lookupHistoryEntry(Finding finding) {
        if (historyStore == null) {
            return null;
        }
        return historyStore.findLatestByUrl(finding.getMethod(), finding.getUrl());
    }

    /** 从 gzip 落盘文件读 entry body；文件为 null 或读取失败时返回 null。 */
    private static byte[] readEntryBody(java.nio.file.Path file) {
        if (file == null) {
            return null;
        }
        try {
            byte[] bytes = BodyStorage.readCompressed(file);
            return bytes.length == 0 ? null : bytes;
        } catch (IOException e) {
            return null;
        }
    }

    /** 选中变更后整体刷新下方三个页签。 */
    private void renderDetail(Finding finding) {
        renderReport(finding);
        renderMessage(finding);
    }

    /** 清空下方详情（无选中行时调用）。 */
    private void clearDetail() {
        // 取消在飞的报文加载任务：避免"清空/删除后旧任务把已删条目的报文回填"。
        cancelMessageLoad();
        reportArea.setText("");
        // 用 null 让 Burp 编辑器显示 "No response" 占位符，避免空 HttpRequest 实例
        // 让编辑器进入 "incomplete" 异常态。
        requestEditor.setRequest(null);
        responseEditor.setResponse(null);
    }

    /** 取消在飞的"选中行报文加载"任务并清空引用（详情区被清空 / 关闭时调用）。 */
    private void cancelMessageLoad() {
        SwingWorker<byte[][], Void> previous = messageLoadInFlight.getAndSet(null);
        if (previous != null && !previous.isDone()) {
            previous.cancel(true);
        }
    }

    /** 清空所有问题：操作前要求用户确认，避免误删。 */
    private void clearFindings() {
        if (store == null) {
            return;
        }
        int choice = JOptionPane.showConfirmDialog(this,
                I18n.get().t("ui.findings.confirmClear"),
                I18n.get().t("ui.findings.confirmClearTitle"),
                JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (choice != JOptionPane.YES_OPTION) {
            return;
        }
        store.clear();
        clearDetail();
        refresh();
        statusLabel.setText(I18n.get().t("ui.findings.status.count", 0));
    }

    /**
     * 删除当前选中的问题：操作前确认，避免误删单条数据。
     * 触发 store 删除后由 store listener 自动 schedule refresh，所以这里不用手动 refresh。
     */
    private void removeSelectedFinding() {
        if (store == null) {
            return;
        }
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            return;
        }
        int modelRow = table.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= tableModel.getRowCount()) {
            return;
        }
        Object idCell = tableModel.getValueAt(modelRow, COLUMN_FINDING_ID);
        if (!(idCell instanceof String)) {
            return;
        }
        String findingId = (String) idCell;
        // 用描述 + URL 拼一个更可读的确认提示
        String description = String.valueOf(tableModel.getValueAt(modelRow, 3));
        String url = String.valueOf(tableModel.getValueAt(modelRow, 4));
        String shortDesc = description.length() > 60
                ? description.substring(0, 60) + "…" : description;
        int choice = JOptionPane.showConfirmDialog(this,
                I18n.get().t("ui.findings.confirmDelete", shortDesc, url),
                I18n.get().t("ui.findings.confirmDeleteTitle"),
                JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (choice != JOptionPane.YES_OPTION) {
            return;
        }
        // 先清空下方详情，避免 refresh 后引用已删除 finding
        currentSelection = null;
        clearDetail();
        store.remove(findingId);
    }

    /**
     * 创建表格右键菜单：提供 "Delete" 与 "Clear history" 两项。弹出前自动选中鼠标所在行
     * （避免"点行 A 但选中行 B"的错位，与 {@link AnalysisHistoryPanel} 的做法一致）。
     *
     * <p>"Clear history" 在 store 不可用或当前无任何 finding 时禁用，保留确认弹窗语义
     * （与原工具栏 Clear 按钮一致）。"Delete" 在未命中数据行时禁用，避免菜单在空白处
     * 可点却无事可删。</p>
     *
     * <p>菜单在构造期只创建一次，每次弹出前按当前语言刷新文案（与历史面板一致），
     * 避免语言切换后菜单停留在旧语言。</p>
     */
    private JPopupMenu createContextMenu() {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem deleteItem = new JMenuItem(I18n.get().t("ui.findings.menu.delete"));
        deleteItem.addActionListener(event -> removeSelectedFinding());
        menu.add(deleteItem);
        JMenuItem clearItem = new JMenuItem(I18n.get().t("ui.menu.clearHistory"));
        clearItem.addActionListener(event -> clearFindings());
        menu.add(clearItem);
        menu.addPopupMenuListener(new PopupMenuListener() {
            @Override
            public void popupMenuWillBecomeVisible(PopupMenuEvent event) {
                deleteItem.setText(I18n.get().t("ui.findings.menu.delete"));
                clearItem.setText(I18n.get().t("ui.menu.clearHistory"));
                Point point = table.getMousePosition();
                int row = point == null ? -1 : table.rowAtPoint(point);
                deleteItem.setEnabled(row >= 0 && store != null);
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
     * 主动触发一次"数量变化"回调：把当前可见条数推给 {@code onCountChanged}。
     *
     * <p>用途：{@link MainTab} 在 {@code addTab("问题", findingsPanel)} 之前就已经
     * {@code new FindingsPanel(...)}，构造器里的 {@link #refresh()} 会调用回调，
     * 但此时 {@code findingsTabIndex} 还是 -1，回调被早退；{@code addTab} 之后再没人
     * 触发，页签标题就停留在初值"问题"。在 addTab 之后显式调一次可把已有数据
     * （磁盘恢复的 / 旧 session 留的）同步到标题。</p>
     */
    public void triggerCountCallback() {
        if (onCountChanged != null) {
            try {
                onCountChanged.accept(tableModel.getRowCount());
            } catch (RuntimeException ignored) {
                // UI 回调异常不影响主流程
            }
        }
    }

    /**
     * 把 findingId 列设为 0 宽不可见。
     *
     * <p>必须在<b>每次</b>列模型重建后调用：{@link #refreshI18n()} 里的
     * {@code setColumnIdentifiers} 会重建 {@code TableColumnModel}，构造期设置的宽度全部作废
     * （表现为切一次语言后 ID 列重新冒出来）。</p>
     */
    private void applyHiddenIdColumn() {
        TableColumn idColumn = table.getColumnModel().getColumn(COLUMN_FINDING_ID);
        idColumn.setMinWidth(0);
        idColumn.setMaxWidth(0);
        idColumn.setPreferredWidth(0);
        idColumn.setResizable(false);
    }

    /**
     * 语言切换时刷新列头与子页签标题，并把当前数据同步到标题。
     */
    @Override
    public void refreshI18n() {
        // 列名变化:基于 currentColumns() 重新拉一列,末尾追加隐藏 ID 列。
        // 不能复用 buildColumnNames() —— 它内部用的是构造期赋值的 columns 字段,
        // 切语言时仍是旧语言,列头不会切。必须用实时取的 currentColumns() 拼。
        String[] liveColumns = currentColumns();
        String[] headers = new String[liveColumns.length + 1];
        System.arraycopy(liveColumns, 0, headers, 0, liveColumns.length);
        headers[liveColumns.length] = I18n.get().t("ui.findings.col.id");
        tableModel.setColumnIdentifiers(headers);
        // setColumnIdentifiers 会触发 JTable 重建整个 TableColumnModel，构造期设置的
        // "隐藏 ID 列"随之丢失——不重设的话每次切语言后 findingId 都会显示出来。
        applyHiddenIdColumn();
        // 子页签标题与请求/响应编辑器
        for (int i = 0; i < detailTabs.getTabCount(); i++) {
            Component c = detailTabs.getComponentAt(i);
            if (c == detailTabs.getComponentAt(0)) {
                detailTabs.setTitleAt(i, I18n.get().t("ui.findings.tab.report"));
            } else {
                detailTabs.setTitleAt(i, I18n.get().t("ui.findings.tab.message"));
            }
        }
        // 过滤框 label / tooltip 由 I18n 弱引用订阅自动刷新,无需手动处理。
        // 状态/空态
        if (store == null) {
            statusLabel.setText(I18n.get().t("ui.findings.status.empty"));
        } else {
            refresh();
        }
    }

    /**
     * 释放资源：插件卸载时调用。停止防抖定时器、取消在飞行的报文加载任务、
     * 注销 I18n 监听器，避免后台 SwingWorker 继续引用已卸载的编辑器。
     *
     * <p>注：{@code FindingStore} 的变更监听器是以匿名 lambda 注册的、无法定向注销；
     * 由 {@code MainTab.close()} → {@link I18n#clearAll()} 与 store 生命周期结束一并回收。</p>
     */
    public void close() {
        if (refreshTimer != null && refreshTimer.isRunning()) {
            refreshTimer.stop();
        }
        SwingWorker<byte[][], Void> inFlight = messageLoadInFlight.getAndSet(null);
        if (inFlight != null && !inFlight.isDone()) {
            inFlight.cancel(true);
        }
        I18n.get().off(i18nListener);
    }

    /** I18n 语言切换监听器：close() 时注销。 */
    private final java.util.function.Consumer<com.auditai.burp.ai.PromptBuilder.Lang> i18nListener =
            lang -> refreshI18n();

    /** 给组件包一层带标题边框的面板（与 AnalysisHistoryPanel 风格一致）。 */
    private static JPanel titled(Component component, String title) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder(title));
        panel.add(component, BorderLayout.CENTER);
        return panel;
    }

    /**
     * 严重程度颜色：让"红 / 橙 / 黄 / 蓝 / 灰"在表格里一眼可辨。
     *
     * <p>实现：</p>
     * <ul>
     *   <li>"严重程度"列（第 0 列）按等级染色 + 加粗；</li>
     *   <li>"描述"列（第 3 列）如果是占位 finding（描述末尾带"（占位）"），用斜体 + 浅灰
     *       标识，让用户一眼区分"模型给的" vs "UI 兜底生成的"。</li>
     *   <li>其它列保持默认外观。</li>
     * </ul>
     */
    private static final class SeverityAwareRenderer extends DefaultTableCellRenderer {

        /** 序列化版本号。 */
        @Serial
        private static final long serialVersionUID = 1L;

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (isSelected) {
                c.setBackground(table.getSelectionBackground());
                c.setForeground(table.getSelectionForeground());
            } else {
                c.setBackground(table.getBackground());
                c.setForeground(table.getForeground());
            }
            Font plain = getFont().deriveFont(Font.PLAIN);
            if (column == 0 && value instanceof Severity sev) {
                // 严重程度显示词随界面语言取(模型值存枚举,不直接存中文 label)
                setText(I18n.get().t(sev.displayKey()));
                Color tint = colorFor(sev);
                if (tint != null) {
                    c.setForeground(tint);
                    setFont(getFont().deriveFont(Font.BOLD));
                } else {
                    setFont(plain);
                }
            } else if (column == 3 && value != null
                    && value.toString().endsWith(I18n.get().t("ui.findings.report.placeholderSuffix"))) {
                // 占位 finding：斜体 + 浅灰
                setFont(getFont().deriveFont(Font.ITALIC));
                c.setForeground(new Color(140, 140, 140));
            } else {
                setFont(plain);
            }
            return c;
        }
    }

    /** 严重程度 → 配色。 */
    private static Color colorFor(Severity severity) {
        if (severity == null) {
            return null;
        }
        return switch (severity) {
            case CRITICAL -> new Color(220, 53, 69);
            case HIGH -> new Color(255, 102, 0);
            case MEDIUM -> new Color(204, 154, 0);
            case LOW -> new Color(54, 119, 199);
            case INFO -> new Color(120, 120, 120);
        };
    }

    /**
     * 把诊断信息写入 Burp Extender 错误日志：SwingWorker.done() 默认不挂顶层异常
     * 处理，没在这里记录就会完全静默——给排错带来麻烦。
     */
    private void logError(String message, Throwable t) {
        if (api != null) {
            api.logging().logToError("AuditAI " + message, t);
        }
    }
}
