package com.auditai.burp.tools.replay;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * multipart/form-data body 的字节级解析与重组——给 v3 协议
 * {@code replace_multipart_params} 提供"按 part name 改 value"的底层能力。
 *
 * <p><b>为什么自写、不走 Burp Montoya？</b>Montoya 的 {@link HttpRequest#parameters()}
 * 不把 multipart part 视作参数（它只识别 {@code application/x-www-form-urlencoded} 等
 * 参数化 body），multipart part 全藏在 raw body 字节里，没有现成高层 API。
 * 这是 v3 协议里唯一需要"自解析 body"的分类。</p>
 *
 * <p>只支持 {@code multipart/form-data}——{@code multipart/mixed} 等不在审计场景里出现。</p>
 */
public final class MultipartBodyParser {

    private MultipartBodyParser() {}

    /**
     * 解析后的 part。value 用 UTF-8 字符串表示——multipart 文本字段全是 UTF-8；
     * 文件 part 的 value 把字节当 UTF-8 解码（不可打印字符会乱码，但审计场景下
     * 显示给模型的简述会被截断，影响小）。
     *
     * <p>{@code valueOffset} / {@code valueEndOffset} 是原 body 字节的偏移量
     * ——{@link #serialize} 在重组时用它们按段"切片"原 body 字节，只替换目标 part
     * 的 value，避免重新拼 part header（保留原始大小写 / 空格 / 顺序）。
     * {@code valueOffset} 指 part <b>value</b> 字节的起点（即 header 末尾空行
     * {@code \r\n\r\n} 之后），{@code valueEndOffset} 指 part value 字节的终点
     * （不含紧随其后的 {@code \r\n--BOUNDARY} 边界）。</p>
     *
     * <p><b>为什么是 value 起点而不是 header 起点</b>：{@link #serialize} 把
     * {@code body[partStart, valueOffset)} 整段原样拷出——这段天然包含
     * "boundary + {@code \r\n} + part header + 末尾空行"。若这里存成 header 起点，
     * 替换 value 时就会把 part header（含 {@code Content-Disposition}）整段丢掉，
     * 且相邻 part 之间的 {@code \r\n} 也会被跳过。</p>
     */
    public static final class Part {
        private final String name;
        private final String filename; // null 表示文本字段
        private final String value;
        private final int valueOffset;     // body[partStart..valueOffset) 是 boundary + part header
        private final int valueEndOffset;  // body[valueOffset..valueEndOffset) 是 value 字节

        public Part(String name, String filename, String value,
                    int valueOffset, int valueEndOffset) {
            this.name = name;
            this.filename = filename;
            this.value = value;
            this.valueOffset = valueOffset;
            this.valueEndOffset = valueEndOffset;
        }

        public String name() { return name; }
        public String filename() { return filename; }
        public String value() { return value; }
        public int valueOffset() { return valueOffset; }
        public int valueEndOffset() { return valueEndOffset; }
    }

    /**
     * 解析 multipart body。Content-Type 不是 {@code multipart/form-data} 或 body 为空 / 找不到
     * boundary 时返回空 list（不抛错——调用方据此判定"该请求不是 multipart"）。
     */
    public static List<Part> parse(HttpRequest req) {
        if (req == null) return List.of();
        String contentType = req.headerValue("Content-Type");
        // HTTP header 走 ASCII 不区分大小写比对,Locale.ROOT 避免土耳其语 locale 异常
        if (contentType == null
                || !contentType.toLowerCase(java.util.Locale.ROOT).startsWith("multipart/form-data")) {
            return List.of();
        }
        String boundary = extractBoundary(contentType);
        if (boundary == null || boundary.isEmpty()) return List.of();
        ByteArray bodyObj = req.body();
        if (bodyObj == null) return List.of();
        byte[] body = bodyObj.getBytes();
        if (body.length == 0) return List.of();
        return parseBody(body, boundary);
    }

    /**
     * 重组 body：对每个 part，原样拷贝 header 字节、按 part name 替换 value 字节、
     * 原样拷贝 boundary / terminator 字节。未列在 {@code replacements} 的 part 不动。
     */
    public static byte[] serialize(byte[] body, String boundary, List<Part> parts,
                                   Map<String, String> replacements) {
        if (parts.isEmpty()) return body;
        byte[] dashBoundaryBytes = ("--" + boundary).getBytes(StandardCharsets.US_ASCII);
        ByteArrayOutputStream out = new ByteArrayOutputStream(body.length + 64);
        // 对每个 part：拼"壳"（boundary + \r\n + part header + 空行，原样）+ value（替换/原样）
        // + 后缀（\r\n--BOUNDARY 或 \r\n--BOUNDARY--）
        // 第一 part 从 partStart=0 开始；后续 part 由上一轮 cursor 停在上一段的 --BOUNDARY 之后
        // （即 boundary 行尾的 \r\n 之前）——这样本轮的"壳"正好从该 \r\n 开始，不会漏字节。
        int cursor = 0;
        for (Part part : parts) {
            int partStart = cursor;
            if (part.valueOffset < partStart) return body;
            // boundary + \r\n + part header + 末尾空行：原样整段拷贝（value 起点之前全部是"壳"）
            writeChunk(out, body, partStart, part.valueOffset - partStart);
            // value
            String newValue = replacements.get(part.name);
            if (newValue != null) {
                writeBytes(out, newValue.getBytes(StandardCharsets.UTF_8));
            } else {
                if (part.valueEndOffset < part.valueOffset) return body;
                writeChunk(out, body, part.valueOffset, part.valueEndOffset - part.valueOffset);
            }
            // 后缀：\r\n--BOUNDARY 或 \r\n--BOUNDARY--（terminator 多 "--"）
            int nextBoundary = indexOf(body, dashBoundaryBytes, part.valueEndOffset);
            if (nextBoundary < 0) return body;
            int suffixEnd = nextBoundary + dashBoundaryBytes.length;
            // terminator 情况：boundary 后紧跟 "--\r\n"，整段都拷贝进 out
            if (suffixEnd + 1 < body.length && body[suffixEnd] == '-'
                    && body[suffixEnd + 1] == '-') {
                suffixEnd += 2;
                if (suffixEnd + 1 < body.length && body[suffixEnd] == '\r'
                        && body[suffixEnd + 1] == '\n') {
                    suffixEnd += 2;
                }
            }
            int suffixLen = suffixEnd - part.valueEndOffset;
            if (suffixLen < 0 || part.valueEndOffset + suffixLen > body.length) return body;
            writeChunk(out, body, part.valueEndOffset, suffixLen);
            // 故意不跳过 boundary 行尾的 \r\n：下一轮的 partStart 停在它之前，
            // 由下一轮的"壳"拷贝把它一并带出。若在这里 +2 跳过，就会丢掉这个换行，
            // 使下一个 part 的 --BOUNDARY 与 Content-Disposition 直接粘连（畸形报文）。
            cursor = suffixEnd;
        }
        // 尾巴（terminator 后剩的字节；如果正常处理则 cursor==body.length，tail 为空）
        if (cursor < body.length) {
            writeChunk(out, body, cursor, body.length - cursor);
        }
        return out.toByteArray();
    }

    /**
     * ByteArrayOutputStream 的 write 系列继承自 OutputStream 会抛 IOException（虽然实际不会），
     * 包一层把 checked exception 去掉。
     */
    private static void writeChunk(ByteArrayOutputStream out, byte[] src, int offset, int len) {
        if (len <= 0) return;
        out.write(src, offset, len);
    }

    private static void writeBytes(ByteArrayOutputStream out, byte[] bytes) {
        if (bytes.length == 0) return;
        out.writeBytes(bytes);
    }

    /**
     * 从 {@code Content-Type} 头里抽 {@code boundary} 参数：容忍 quoted / unquoted、
     * 大小写不敏感地匹配 {@code boundary} 关键字；尾随空白忽略。
     */
    static String extractBoundary(String contentType) {
        if (contentType == null) return null;
        int idx = contentType.toLowerCase(java.util.Locale.ROOT).indexOf("boundary=");
        if (idx < 0) return null;
        int start = idx + "boundary=".length();
        while (start < contentType.length() && Character.isWhitespace(contentType.charAt(start))) {
            start++;
        }
        if (start >= contentType.length()) return null;
        if (contentType.charAt(start) == '"') {
            int end = contentType.indexOf('"', start + 1);
            if (end < 0) return null;
            return contentType.substring(start + 1, end);
        }
        int end = start;
        while (end < contentType.length()) {
            char c = contentType.charAt(end);
            if (c == ';' || c == ',' || Character.isWhitespace(c)) break;
            end++;
        }
        return contentType.substring(start, end);
    }

    /**
     * 给 {@code listAddressableParamsStatic} 用的工具方法：从请求里抽 multipart part names。
     * 空 list 表示"该请求不是 multipart"。
     */
    public static List<String> listNames(HttpRequest req) {
        List<Part> parts = parse(req);
        if (parts.isEmpty()) return Collections.emptyList();
        List<String> out = new ArrayList<>(parts.size());
        for (Part p : parts) out.add(p.name());
        return out;
    }

    // ===== 内部 helper =====

    /**
     * 解析 body 字节为 part 列表。算法：找所有 {@code --BOUNDARY} 出现位置，
     * 跳过最后的 terminator（{@code --BOUNDARY--}），每个 part 区间解 header（找
     * {@code \r\n\r\n} 定位 header 结束）和 value（到下一 boundary 的 {@code \r\n} 为止）。
     *
     * <p>包级可见（而非 private）：{@link #parse(HttpRequest)} 依赖 Montoya 运行时对象工厂，
     * 单测环境构造不出 {@code HttpRequest}；把纯字节逻辑暴露成包级入口后，
     * {@code MultipartBodyParserTest} 可以直接对"parse → serialize"做字节级回归断言
     * ——这正是 {@code valueOffset} 语义错位曾经漏网的原因。</p>
     */
    static List<Part> parseBody(byte[] body, String boundary) {
        byte[] dashBoundaryBytes = ("--" + boundary).getBytes(StandardCharsets.US_ASCII);
        byte[] blankLine = "\r\n\r\n".getBytes(StandardCharsets.US_ASCII);

        List<Integer> boundaries = new ArrayList<>();
        for (int i = 0; i <= body.length - dashBoundaryBytes.length; ) {
            int idx = indexOf(body, dashBoundaryBytes, i);
            if (idx < 0) break;
            boundaries.add(idx);
            i = idx + dashBoundaryBytes.length;
        }
        if (boundaries.isEmpty()) return List.of();

        List<Part> parts = new ArrayList<>();
        for (int i = 0; i < boundaries.size() - 1; i++) {
            int headerOffset = boundaries.get(i) + dashBoundaryBytes.length;
            // 跳过 terminator（最后位置已经是 --BOUNDARY--）
            if (headerOffset < body.length && body[headerOffset] == '-'
                    && headerOffset + 1 < body.length && body[headerOffset + 1] == '-') {
                break;
            }
            // 跳过 \r\n（紧跟 boundary 之后）
            if (headerOffset + 1 < body.length
                    && body[headerOffset] == '\r' && body[headerOffset + 1] == '\n') {
                headerOffset += 2;
            }
            int headerEnd = indexOf(body, blankLine, headerOffset);
            if (headerEnd < 0) return parts; // body 截断
            int valueStart = headerEnd + 4;
            int nextBoundary = boundaries.get(i + 1);
            int crlfBeforeNext = nextBoundary - 2;
            int valueEnd = (crlfBeforeNext >= valueStart
                    && body[crlfBeforeNext] == '\r' && body[crlfBeforeNext + 1] == '\n')
                    ? crlfBeforeNext : nextBoundary;
            // 解析 Content-Disposition
            String headerStr = new String(body, headerOffset, headerEnd - headerOffset,
                    StandardCharsets.UTF_8);
            String[] cd = parseContentDisposition(headerStr);
            if (cd == null) continue;
            String value = new String(body, valueStart, valueEnd - valueStart,
                    StandardCharsets.UTF_8);
            // filename 长度为 0 当作 null（空 filename 视为文本 part）
            String filename = cd[1].isEmpty() ? null : cd[1];
            // 存 value 起点（而非 header 起点）：serialize 依赖它把"boundary + header"整段原样拷出。
            parts.add(new Part(cd[0], filename, value, valueStart, valueEnd));
        }
        return parts;
    }

    /**
     * 解析 {@code Content-Disposition: form-data; name="x"; filename="y"} 这种 header。
     * 返回 {@code [name, filename]}；name=null 表示该 part 没识别出 disposition，跳过。
     */
    private static String[] parseContentDisposition(String headerBlock) {
        String[] lines = headerBlock.split("\\r?\\n");
        for (String line : lines) {
            if (!line.toLowerCase(java.util.Locale.ROOT).startsWith("content-disposition")) continue;
            int colon = line.indexOf(':');
            String rest = colon >= 0 ? line.substring(colon + 1) : line;
            // 按 ; 切（不在引号内）
            List<String> tokens = new ArrayList<>();
            StringBuilder cur = new StringBuilder();
            boolean inQuote = false;
            for (int i = 0; i < rest.length(); i++) {
                char c = rest.charAt(i);
                if (c == '"') inQuote = !inQuote;
                if (c == ';' && !inQuote) {
                    tokens.add(cur.toString());
                    cur.setLength(0);
                } else {
                    cur.append(c);
                }
            }
            tokens.add(cur.toString());
            String name = null, filename = null;
            boolean first = true;
            for (String tok : tokens) {
                String t = tok.trim();
                if (t.isEmpty()) continue;
                int eq = t.indexOf('=');
                if (eq < 0) {
                    // multipart 头字段按 HTTP 规范 ASCII 不区分大小写,Locale.ROOT 避免土耳其语 locale 异常
                if (first && !t.toLowerCase(java.util.Locale.ROOT).equals("form-data")) return null;
                    first = false;
                    continue;
                }
                String k = t.substring(0, eq).trim().toLowerCase(java.util.Locale.ROOT);
                String v = t.substring(eq + 1).trim();
                if (v.length() >= 2 && v.charAt(0) == '"' && v.charAt(v.length() - 1) == '"') {
                    v = v.substring(1, v.length() - 1);
                }
                if ("name".equals(k)) name = v;
                else if ("filename".equals(k)) filename = v;
                first = false;
            }
            if (name != null) return new String[]{name, filename == null ? "" : filename};
        }
        return null;
    }

    private static int indexOf(byte[] body, byte[] needle, int from) {
        outer:
        for (int i = from; i <= body.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (body[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }
}