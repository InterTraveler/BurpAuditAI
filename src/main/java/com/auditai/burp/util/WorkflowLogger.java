package com.auditai.burp.util;

import com.auditai.burp.ai.AiClient;
import com.auditai.burp.config.AiConfig;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;

/**
 * 单次"分析"的 agent ↔ AI 交互轨迹记录器。
 *
 * <p>每次分析开始时通过 {@link #openForAnalysis} 创建一个 logger，AI 调用层
 * 在交互过程中通过 {@link #logRequest} 把请求追加到内存缓冲，通过实例方法
 * {@link #appendAi} / {@link #appendError} 把响应和错误追加到内存缓冲；分析结束时
 * （{@code AnalysisResultSink}）调用 {@link #writeTo(Path)} 把缓冲内容写成 XML 文件，
 * 文件路径与一条历史记录绑定，由 {@code AnalysisHistoryStore} 负责生命周期管理
 * （删除历史记录时同步删除 XML）。</p>
 *
 * <p>输出格式（不写缩进，结构紧凑）：</p>
 * <pre>{@code
 * <context>
 *   <agent>
 *     <model>...</model>
 *     <max_tokens>...</max_tokens>
 *     <messages>
 *       <message><role>system</role><content>...</content></message>
 *       <message><role>user</role><content>...</content></message>
 *     </messages>
 *     <response_format><type>json_object</type></response_format>
 *   </agent>
 *   <ai>
 *     <model>...</model>
 *     <choices>...</choices>
 *     <usage>...</usage>
 *   </ai>
 * </context>
 * }</pre>
 *
 * <p>线程模型：</p>
 * <ul>
 *   <li>{@link #openForAnalysis} + {@link #bindToCurrentThread} 把 logger 绑到分析线程上，
 *       AI 调用层的静态入口 {@link #logRequest} 通过它定位；</li>
 *   <li><b>异步回调必须用实例方法</b>：{@link #logRequest} 等静态入口依赖 ThreadLocal，
 *       <b>在 JDK HttpClient worker / commonPool 线程上 {@link #current()} 会返回 null，
 *       记录被静默丢弃</b>。AI 调用层在入口处抓取 logger 引用
 *       （{@code WorkflowLogger logger = WorkflowLogger.current()}），然后用实例方法
 *       {@link #appendAi} / {@link #appendError} 写入，保证响应/错误即使在异步回调
 *       线程上也能落盘；</li>
 *   <li>{@link #buffer} 选用 {@link StringBuffer}（线程安全）——异步路径下多个回调
 *       可能并发写同一 logger，{@code StringBuilder} 会破坏内部状态。</li>
 * </ul>
 *
 * <p>分析结束必须调 {@link #unbindFromCurrentThread}，避免执行器线程复用时把后续
 * 分析的内容写进本 logger。</p>
 */
public final class WorkflowLogger {

    /** 与 {@code history/} 同级的 audit-trail 目录名。 */
    public static final String AUDIT_TRAILS_DIRECTORY_NAME = "audit-trails";

    /**
     * 单次分析的 audit-trail 缓冲上限（字符数）。
     *
     * <p>一次分析会把完整提示词（可能含多条同域历史报文）与多轮工具循环的请求/响应全部
     * 留在内存里，被动流量洪峰下这个缓冲会持续抬高堆占用。超限后不再追加新块并落一条
     * XML 注释标记（丢弃整块而不是截断字符串，保证 XML 结构始终闭合）。</p>
     */
    private static final int MAX_BUFFER_CHARS = 4 * 1024 * 1024;

    /** 当前线程绑定的 logger：AI 调用层的静态入口通过它定位。 */
    private static final ThreadLocal<WorkflowLogger> CURRENT = new ThreadLocal<>();

    /**
     * 线程安全的缓冲：同一 logger 可能被异步回调线程并发写（如 {@code parseAndLog}
     * 在 HttpClient worker 上执行时与另一阶段的 {@code appendAi} 同时触发）。
     * 用 {@link StringBuffer} 而不是 {@code synchronized(this)} 包各 append：前者
     * 内置同步、对外 API 简单；后者容易漏包。
     */
    private final StringBuffer buffer = new StringBuffer(4096);

    /** 缓冲超上限后置位：后续块被丢弃，{@link #writeTo} 会写一条"已截断"注释。 */
    private boolean truncated;

    private WorkflowLogger() {
        buffer.append("<context>");
    }

    /**
     * 为一次"分析"创建 logger。调用方应紧接着 {@link #bindToCurrentThread}。
     *
     * <p>audit-trail 是每次分析的标配产物——不再检查任何系统属性开关。</p>
     */
    public static WorkflowLogger openForAnalysis() {
        return new WorkflowLogger();
    }

    public void bindToCurrentThread() {
        CURRENT.set(this);
    }

    public static void unbindFromCurrentThread() {
        CURRENT.remove();
    }

    /** 当前线程是否已绑定 logger（决定 {@link #logRequest} 等是否生效）。 */
    public static boolean isEnabled() {
        return CURRENT.get() != null;
    }

    /** 当前线程绑定的 logger；无绑定时返回 null。供 {@code AnalysisResultSink} 在分析结束时落盘。 */
    public static WorkflowLogger current() {
        return CURRENT.get();
    }

    /**
     * 记录一次"请求"：把 model / max_tokens / messages / [response_format]
     * 序列化为一个 {@code <agent>} 块追加到缓冲。
     *
     * <p>本入口依赖 ThreadLocal：调用方必须在分析线程上先 {@link #bindToCurrentThread}，
     * 未绑定或异步回调线程上调用时静默丢弃。</p>
     */
    public static void logRequest(AiConfig config, List<AiClient.ChatMessage> messages, boolean requireJson) {
        WorkflowLogger logger = CURRENT.get();
        if (logger == null || config == null || messages == null || messages.isEmpty()) {
            return;
        }
        logger.appendAgent(config, messages, requireJson);
    }

    /**
     * 把缓冲内容写入文件：原子写（先写 .tmp 再 rename），避免半截文件。
     *
     * @param target 目标文件绝对路径（父目录由调用方预先创建）。
     * @return 写入完成的文件路径（== target）。
     */
    public Path writeTo(Path target) throws IOException {
        // synchronized(this) 锁住"追加 </context> + toString + 写盘"全过程：避免 async 回调
        // 在 writeTo toString() 期间又 appendAi，把 </context> 嵌进未闭合的子节点。
        String snapshot;
        synchronized (this) {
            if (truncated) {
                // XML 注释里不能出现 "--"，标记文案刻意避开。
                buffer.append("<!-- AuditAI: audit-trail reached ").append(MAX_BUFFER_CHARS)
                        .append(" chars, remaining blocks omitted -->");
            }
            buffer.append("</context>");
            snapshot = buffer.toString();
        }
        Path tmp = Files.createTempFile(target.getParent(), "trail-", ".tmp");
        try {
            Files.writeString(tmp, snapshot, StandardCharsets.UTF_8);
            try {
                Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
        return target;
    }

    public void appendAgent(AiConfig config, List<AiClient.ChatMessage> messages, boolean requireJson) {
        // synchronized(this) 保证 "<agent>...</agent>" 作为一个原子块写入：
        // StringBuffer 仅保证字节级安全，不保证块级原子；并发场景下，线程 A 写到
        // "<agent><messages><message>..." 时线程 B 把 "</agent>" 插进来，会让 SAX 解析
        // 把"未闭合的 message 内容"当成纯文本解析、报"Element content must consist
        // of properly formatted character data"。锁的粒度 = 单个块，远小于完整分析。
        synchronized (this) {
            if (dropIfFull()) {
                return;
            }
            buffer.append("<agent>");
            buffer.append("<model>").append(escape(config.getModel())).append("</model>");
            buffer.append("<max_tokens>").append(config.getMaxTokens()).append("</max_tokens>");
            buffer.append("<messages>");
            for (AiClient.ChatMessage m : messages) {
                buffer.append("<message>");
                buffer.append("<role>").append(escape(m.role())).append("</role>");
                buffer.append("<content>").append(escape(m.content())).append("</content>");
                buffer.append("</message>");
            }
            buffer.append("</messages>");
            if (requireJson) {
                buffer.append("<response_format><type>json_object</type></response_format>");
            }
            buffer.append("</agent>");
        }
    }

    /**
     * 把 AI 原始响应 body 写入 {@code <ai>} 块。
     *
     * <p><b>为什么是 public</b>：{@code OpenAiCompatibleClient} 在异步回调
     * （HttpClient worker / commonPool）线程上解析响应——这时 ThreadLocal 拿不到
     * 当前 logger，所以 AI 调用层入口先把 logger 引用抓成 final 局部变量，再调用本
     * 实例方法写入，避免响应日志被静默丢弃。</p>
     */
    public void appendAi(String rawBody) {
        // synchronized(this) 同 appendAgent：保证 "<ai>...</ai>" 作为一个原子块写入，
        // 避免并发时一个块的闭合标签嵌入另一个未闭合子节点导致 XML 损坏。
        synchronized (this) {
            if (dropIfFull()) {
                return;
            }
            buffer.append("<ai>");
            if (rawBody != null && !rawBody.isBlank()) {
                try {
                    JsonElement root = JsonParser.parseString(rawBody);
                    if (root != null && root.isJsonObject()) {
                        for (var entry : root.getAsJsonObject().entrySet()) {
                            writeJsonValue(entry.getKey(), entry.getValue());
                        }
                    } else {
                        buffer.append(escape(rawBody));
                    }
                } catch (RuntimeException jsonParseFailed) {
                    // 响应不是合法 JSON：原样作为文本写入（已转义）
                    buffer.append(escape(rawBody));
                }
            }
            buffer.append("</ai>");
        }
    }

    /**
     * 把一次 AI 错误写入 {@code <ai><error>...</error></ai>} 块。
     *
     * <p>与 {@link #appendAi} 同理：异步回调线程上不能依赖 ThreadLocal，必须直接传 logger
     * 引用过来调用实例方法。</p>
     */
    public void appendError(String errorMessage) {
        // synchronized(this) 同 appendAgent/appendAi：保证 "<ai><error>...</error></ai>" 块级原子写入。
        synchronized (this) {
            if (dropIfFull()) {
                return;
            }
            buffer.append("<ai>");
            buffer.append("<error>").append(escape(errorMessage == null ? "(无详细信息)" : errorMessage)).append("</error>");
            buffer.append("</ai>");
        }
    }

    /**
     * 缓冲是否已达上限：达到则丢弃本块并置 {@link #truncated}。
     *
     * <p>丢弃的是<b>整块</b>（{@code <agent>} / {@code <ai>}），因此 XML 结构保持闭合，
     * 不会出现"半个元素"；调用方必须在 {@code synchronized(this)} 内调用。</p>
     *
     * @return true 表示本块已被丢弃，调用方应直接返回。
     */
    private boolean dropIfFull() {
        if (buffer.length() >= MAX_BUFFER_CHARS) {
            truncated = true;
            return true;
        }
        return false;
    }

    /** 把 JSON 元素序列化为一个 XML 元素（同名）：对象/数组递归，原始值转义后作为文本。 */
    private void writeJsonValue(String name, JsonElement el) {
        // key 必须规范化：JSON 允许 "1st" / "user name" 这类非法 XML 名的 key
        String tag = sanitizeElementName(name);
        if (el == null || el.isJsonNull()) {
            buffer.append("<").append(tag).append("/>");
            return;
        }
        if (el.isJsonPrimitive()) {
            buffer.append("<").append(tag).append(">")
                    .append(escape(el.getAsString()))
                    .append("</").append(tag).append(">");
            return;
        }
        if (el.isJsonObject()) {
            buffer.append("<").append(tag).append(">");
            for (var entry : el.getAsJsonObject().entrySet()) {
                writeJsonValue(entry.getKey(), entry.getValue());
            }
            buffer.append("</").append(name).append(">");
            return;
        }
        if (el.isJsonArray()) {
            buffer.append("<").append(name).append(">");
            for (JsonElement item : el.getAsJsonArray()) {
                writeJsonValue("item", item);
            }
            buffer.append("</").append(name).append(">");
        }
    }

    /**
     * 转义 XML 文本：替换 {@code <} / {@code &} / {@code >}，并丢弃 XML 1.0 不允许的控制字符。
     *
     * <p><b>为什么必须丢控制字符</b>：模型响应里的 {@code \u0000}~{@code \u001F}
     * （JSON 转义 {@code "\\u0001"} 经 Gson 还原后就是真实控制字符）在 XML 1.0 里既不能
     * 直接出现、也无法用字符引用表示；原样写盘会让整份 audit-trail <b>无法解析</b>
     * （{@code readTrail} 抛 SAXException → UI 表现为"链路追踪打不开"）。
     * {@code \t} / {@code \n} / {@code \r} 是 XML 允许的三个控制字符，保留。</p>
     */
    private static String escape(String text) {
        if (text == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(text.length() + 16);
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '<': out.append("&lt;"); break;
                case '&': out.append("&amp;"); break;
                case '>': out.append("&gt;"); break;
                default:
                    if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') {
                        // XML 1.0 禁止的 C0 控制字符：丢弃（无法用字符引用表示）
                        break;
                    }
                    out.append(c);
            }
        }
        return out.toString();
    }

    /**
     * 把 JSON key 规范成合法的 XML 元素名。
     *
     * <p>JSON 的 key 是任意字符串（{@code "1st"}、{@code "user name"}、{@code "a<b"} 都合法），
     * 直接拿来当标签名会产出解析不了的 XML。规则：首字符必须是字母或下划线，其余字符限定为
     * 字母/数字/下划线/连字符/点，非法字符一律替换成 {@code '_'}；以 {@code xml} 开头
     * （XML 保留前缀，不区分大小写）时加 {@code k_} 前缀。</p>
     */
    private static String sanitizeElementName(String name) {
        if (name == null || name.isEmpty()) {
            return "field";
        }
        StringBuilder sb = new StringBuilder(name.length() + 2);
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            boolean valid = (i == 0)
                    ? (Character.isLetter(c) || c == '_')
                    : (Character.isLetterOrDigit(c) || c == '_' || c == '-' || c == '.');
            sb.append(valid ? c : '_');
        }
        // XML 元素名前缀比较走 Locale.ROOT,避免土耳其语 locale 把 "X"/"x" 视为不同字母
        if (sb.length() >= 3 && sb.substring(0, 3).toLowerCase(java.util.Locale.ROOT).equals("xml")) {
            sb.insert(0, "k_");
        }
        return sb.toString();
    }

    // ====================== 读取端：解析 audit-trail XML ======================

    /** 消息来源：agent 块（请求）或 ai 块（响应/错误）。供 UI 着色使用。 */
    public enum Source { AGENT, AI }

    /**
     * 一条可展示的交互消息：{@code role} + {@code content} + 来源。
     *
     * <p>UI 渲染时按 {@link Source} 着色，{@code role} 决定标签头（如 [system] / [user] /
     * [assistant]），{@code content} 是消息正文。</p>
     */
    public record TrailMessage(String role, String content, Source source) {
    }

    /**
     * 解析一个 audit-trail XML 文件，提取全部 {@code <message>} 节点及 ai 块错误回退。
     *
     * <p>策略：</p>
     * <ul>
     *   <li>递归遍历所有 {@code <message>} 节点，通过祖先链定位最近的 {@code <agent>} /
     *       {@code <ai>} 父元素，决定 {@link Source}；</li>
     *   <li>若 ai 块没有任何 message（仅含 {@code <error>}），补一条 role=error 的兜底消息，
     *       保证 UI 不会"有 ai 块却无内容"；</li>
     *   <li>XML 解析失败 / 文件缺失时抛出 {@link IOException}，由调用方决定如何降级
     *       （弹窗提示用户）。<b>不</b>做缓存：每次调用都实时读盘解析，符合"链路追踪
     *       即时反映最新数据"的预期。</li>
     * </ul>
     */
    public static List<TrailMessage> readTrail(Path xmlFile) throws IOException {
        if (xmlFile == null || !Files.exists(xmlFile)) {
            throw new IOException("audit-trail file not found: " + xmlFile);
        }
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // 禁用外部实体加载，audit-trail 是内部数据，绝不解析 DTD / 外部引用。
        try {
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setExpandEntityReferences(false);
        } catch (ParserConfigurationException ignored) {
            // 老版本 JDK 不支持这些 feature 时静默忽略，audit-trail 是内部可信数据
        }
        DocumentBuilder builder;
        try {
            builder = factory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            throw new IOException("failed to create XML parser", e);
        }
        Document doc;
        try {
            doc = builder.parse(xmlFile.toFile());
        } catch (SAXException e) {
            throw new IOException("invalid audit-trail XML: " + e.getMessage(), e);
        }
        doc.getDocumentElement().normalize();

        List<TrailMessage> out = new ArrayList<>();
        // 1) 收集所有 <message> 节点 + 它们的来源祖先。
        NodeList messageNodes = doc.getElementsByTagName("message");
        for (int i = 0; i < messageNodes.getLength(); i++) {
            Node node = messageNodes.item(i);
            if (node.getNodeType() != Node.ELEMENT_NODE) {
                continue;
            }
            Element msg = (Element) node;
            String role = childText(msg, "role");
            String content = childText(msg, "content");
            Source source = nearestSourceAncestor(msg);
            out.add(new TrailMessage(role, content, source));
        }
        // 2) ai 块无 message 但含 <error> 的兜底：保证 UI 能完整呈现失败轨迹。
        NodeList aiBlocks = doc.getElementsByTagName("ai");
        for (int i = 0; i < aiBlocks.getLength(); i++) {
            Element ai = (Element) aiBlocks.item(i);
            if (ai.getElementsByTagName("message").getLength() > 0) {
                continue;
            }
            String error = childText(ai, "error");
            if (error != null && !error.isEmpty()) {
                out.add(new TrailMessage("error", error, Source.AI));
            }
        }
        return out;
    }

    /** 读取某元素的子元素文本（{@code <x>...</x>}），找不到或子元素不存在时返回空串。 */
    private static String childText(Element parent, String tagName) {
        NodeList list = parent.getElementsByTagName(tagName);
        if (list.getLength() == 0) {
            return "";
        }
        Node first = list.item(0);
        return first == null ? "" : first.getTextContent();
    }

    /** 沿父链向上找最近的 {@code <agent>} 或 {@code <ai>}，找不到时默认 AGENT（保守着色）。 */
    private static Source nearestSourceAncestor(Element message) {
        Node parent = message.getParentNode();
        while (parent != null && parent.getNodeType() == Node.ELEMENT_NODE) {
            String name = parent.getNodeName();
            if ("agent".equals(name)) {
                return Source.AGENT;
            }
            if ("ai".equals(name)) {
                return Source.AI;
            }
            parent = parent.getParentNode();
        }
        return Source.AGENT;
    }
}
