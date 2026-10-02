package com.auditai.burp.tools.replay;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link ReplayService} 的"端到端"测试：起一个本地 {@link HttpServer} 当被测服务，
 * 用 {@link java.net.http.HttpClient} 真发 HTTP 请求，验证"按位置分类的参数替换"在线上
 * 真的能命中目标 key、并且请求 / 响应信息打到控制台方便人对照查看。
 *
 * <p>为什么不用 {@code ReplayService.execute} 直接发？因为它内部走的是
 * {@code api.http().sendRequest(req)}（Burp Montoya API）——脱离 Burp 跑不动。
 * 这里用 {@link ReplaySimulator} 把"按位置分类"这套语义在 String/Map 层重放一遍，
 * 然后用 JDK 自带 HTTP 客户端发出去——验证的是<b>行为契约</b>（URL 编码、Content-Length、
 * JSON 编码等），不是某段 Java 代码的内部细节。{@link ReplayServiceTest} 里的单测
 * 负责覆盖{@code ReplayService} 本身的实现逻辑。</p>
 */
class ReplayServiceIntegrationTest {

    /** 启动在随机端口的本地 HTTP 服务；每个 context 一个 {@link CapturedRequest}。 */
    private HttpServer server;
    private int port;
    private HttpClient httpClient;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        port = server.getAddress().getPort();
        server.start();
        httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(2))
                .build();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    // ===== 真实 HTTP 端到端：每个分类都跑一遍 =====

    /**
     * 改 URL query 上的 {@code id} 参数。验证：单引号被正确保留、特殊字符
     * 经 URL 编码后服务器解码回来仍是 {@code 1'}；未改的 {@code page} 保持原值。
     * 典型场景：SQL 注入探测时闭合单引号。
     */
    @Test
    void replaceQueryParam_reachesServer() throws Exception {
        CapturedRequest captured = new CapturedRequest();
        server.createContext("/api/users", captureAll(captured));

        // 原始：GET /api/users?id=1&page=1
        // 重放：把 id 改成 1'（闭合单引号）
        ReplaySimulator sim = new ReplaySimulator("GET", "/api/users",
                "id=1&page=1", defaultHeaders(), null);
        printScenario("replaceQueryParam_reachesServer",
                /* originalLine = */ "GET /api/users?id=1&page=1",
                /* reason       = */ "闭合单引号看回显（SQL 注入探测）",
                /* queryParams  = */ Map.of("id", "1'"),
                /* formParams   = */ Map.of(),
                /* headerParams = */ Map.of(),
                /* jsonParams   = */ Map.of(),
                /* pathParams   = */ Map.of());
        ReplaySimulator orig = sim.copy();
        sim.replaceQueryParams(Map.of("id", "1'"));
        HttpRequest req = sim.toJdkRequest("http://127.0.0.1:" + port);

        printSent("replaceQueryParam_reachesServer", orig, sim, req);
        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        printResponse("replaceQueryParam_reachesServer", resp);

        assertEquals(200, resp.statusCode());
        // 服务器端应看到 ?id=1%27&page=1（URL 编码由 JDK HTTP 客户端做）
        assertNotNull(captured.query.get("id"), "id 应在 query 里");
        assertEquals("1'", URLDecoder.decode(captured.query.get("id"), StandardCharsets.UTF_8),
                "服务器解码后应看到闭合引号");
        assertEquals("1", captured.query.get("page"), "page 未改，保持原值");
    }

    /**
     * 改 JSON body 的<b>嵌套字段</b> {@code user.id}（点号路径）。验证：嵌套结构
     * 里的字段能被准确定位和替换；同级的 {@code user.name} 不受影响。
     * 典型场景：复杂 JSON 结构里的鉴权字段绕过。
     */
    @Test
    void replaceJsonParam_dotPath_reachesServer() throws Exception {
        CapturedRequest captured = new CapturedRequest();
        server.createContext("/api/users", captureAll(captured));

        // 原始：POST /api/users  body={"user":{"id":1,"name":"alice"}}
        // 重放：通过点号路径改 user.id
        String originalBody = "{\"user\":{\"id\":1,\"name\":\"alice\"}}";
        Map<String, String> headers = jsonHeaders("POST", originalBody);
        ReplaySimulator sim = new ReplaySimulator("POST", "/api/users", null, headers, originalBody);
        printScenario("replaceJsonParam_dotPath_reachesServer",
                /* originalLine = */ "POST /api/users  body={\"user\":{\"id\":1,\"name\":\"alice\"}}",
                /* reason       = */ "JSON 嵌套字段注入（点号路径 user.id）",
                /* queryParams  = */ Map.of(),
                /* formParams   = */ Map.of(),
                /* headerParams = */ Map.of(),
                /* jsonParams   = */ Map.of("user.id", "999"),
                /* pathParams   = */ Map.of());
        ReplaySimulator orig = sim.copy();
        sim.replaceJsonParams(Map.of("user.id", "999"));
        HttpRequest req = sim.toJdkRequest("http://127.0.0.1:" + port);

        printSent("replaceJsonParam_dotPath_reachesServer", orig, sim, req);
        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        printResponse("replaceJsonParam_dotPath_reachesServer", resp);

        assertEquals(200, resp.statusCode());
        assertTrue(captured.jsonBody.contains("\"id\":999"),
                "嵌套路径 user.id 应被替换；实际 body：" + captured.jsonBody);
        assertTrue(captured.jsonBody.contains("\"name\":\"alice\""), "user.name 未改");
    }

    /**
     * 一次重放同时改 3 类参数（query + header + json；form 留空）。
     * 验证：多分类并行改值都能生效、未列出的 key 保持原值（如 {@code X-Trace}、
     * {@code user} 字段）。
     * 典型场景：复杂业务接口的多维度探测（同时改鉴权 + 业务参数 + 数据）。
     */
    @Test
    void replaceAllFiveCategories_simultaneously() throws Exception {
        CapturedRequest captured = new CapturedRequest();
        server.createContext("/api/users", captureAll(captured));

        // 原始：POST /api/users?id=1
        //   headers: X-User-Id: guest, X-Trace: trace-1
        //   body:    {"token":"abc","user":"alice"} (json)
        // 重放：query 改 id=999；header 改 X-User-Id=admin；json 改 token=xyz
        // 注意：不显式设 Host——JDK HttpClient 会从 URI 推断，且禁止手动覆盖
        String originalBody = "{\"token\":\"abc\",\"user\":\"alice\"}";
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("X-User-Id", "guest");
        headers.put("X-Trace", "trace-1");
        headers.put("Content-Type", "application/json");
        ReplaySimulator sim = new ReplaySimulator("POST", "/api/users",
                "id=1", headers, originalBody);
        printScenario("replaceAllFiveCategories_simultaneously",
                /* originalLine = */ "POST /api/users?id=1  X-User-Id:guest  body={\"token\":\"abc\",\"user\":\"alice\"}",
                /* reason       = */ "一次重放同时改 query + header + json（form 留空）",
                /* queryParams  = */ Map.of("id", "999"),
                /* formParams   = */ Map.of(),
                /* headerParams = */ Map.of("X-User-Id", "admin"),
                /* jsonParams   = */ Map.of("token", "xyz"),
                /* pathParams   = */ Map.of());
        ReplaySimulator orig = sim.copy();
        sim.replaceQueryParams(Map.of("id", "999"));
        sim.replaceHeaderParams(Map.of("X-User-Id", "admin"));
        sim.replaceJsonParams(Map.of("token", "xyz"));
        HttpRequest req = sim.toJdkRequest("http://127.0.0.1:" + port);

        printSent("replaceAllFiveCategories_simultaneously", orig, sim, req);
        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        printResponse("replaceAllFiveCategories_simultaneously", resp);

        assertEquals(200, resp.statusCode());
        // 1) query 改了
        assertEquals("999", captured.query.get("id"));
        // 2) header 改了
        String uid = captured.headers.get("X-User-Id");
        if (uid == null) uid = captured.headers.get("x-user-id");
        assertEquals("admin", uid);
        // 3) X-Trace 未改
        String trace = captured.headers.get("X-Trace");
        if (trace == null) trace = captured.headers.get("x-trace");
        assertEquals("trace-1", trace, "X-Trace 未在替换清单里，应保持原值");
        // 4) JSON 改了
        assertTrue(captured.jsonBody.contains("\"token\":\"xyz\""), "JSON token 改值生效");
        // 5) JSON user 未改
        assertTrue(captured.jsonBody.contains("\"user\":\"alice\""), "JSON user 未改");
    }

    /**
     * 验证 URL 编码：特殊字符（空格、{@code &}、中文）写入 query 后被 JDK HTTP
     * 客户端正确编码为 {@code %xx}，服务器解码回来仍是原字符。
     * 典型场景：探测带中文 / 空格的搜索参数（避免手动加 {@code %27} 之类出错）。
     */
    @Test
    void replaceQueryParam_urlEncoding_applied() throws Exception {
        CapturedRequest captured = new CapturedRequest();
        server.createContext("/api", captureAll(captured));

        // 验证：特殊字符在 query 里被正确 URL 编码（空格→%20、中文→UTF-8 %xx）
        ReplaySimulator sim = new ReplaySimulator("GET", "/api", "q=old", defaultHeaders(), null);
        printScenario("replaceQueryParam_urlEncoding_applied",
                /* originalLine = */ "GET /api?q=old",
                /* reason       = */ "验证 URL 编码（空格、&、中文 → %xx）",
                /* queryParams  = */ Map.of("q", "hello world & 你好"),
                /* formParams   = */ Map.of(),
                /* headerParams = */ Map.of(),
                /* jsonParams   = */ Map.of(),
                /* pathParams   = */ Map.of());
        ReplaySimulator orig = sim.copy();
        sim.replaceQueryParams(Map.of("q", "hello world & 你好"));
        HttpRequest req = sim.toJdkRequest("http://127.0.0.1:" + port);

        printSent("replaceQueryParam_urlEncoding_applied", orig, sim, req);
        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        printResponse("replaceQueryParam_urlEncoding_applied", resp);

        assertEquals(200, resp.statusCode());
        // 服务器解码后应看到原始字符
        String actual = URLDecoder.decode(captured.query.get("q"), StandardCharsets.UTF_8);
        assertEquals("hello world & 你好", actual, "URL 解码后应还原特殊字符");
    }

    /**
     * <b>负面</b>：模型把 {@code ?id=1} 的 {@code id} 错放进 {@code replace_header_params}。
     * 验证：本地立刻抛 IAE，不会"成功发请求"；错误信息明确指出"哪个分类、哪个 key"
     * 以及正确位置（{@code query}）实际有哪些 key 可用——帮模型自我修正。
     * <p>这是 v3 协议的核心改进：杜绝 v2 的"key 撞名 → 优先级兜底"导致的静默错改。</p>
     */
    @Test
    void wrongPosition_queryKeyInHeaderSlot_failsLocally() {
        // 关键场景：模型把 ?id=1 的 id 错放进 replace_header_params
        // → 本地立刻报错（不会"成功发请求"）——这是 v3 协议的核心改进
        ReplaySimulator sim = new ReplaySimulator("GET", "/api", "id=1", defaultHeaders(), null);
        printScenario("wrongPosition_queryKeyInHeaderSlot_failsLocally",
                /* originalLine = */ "GET /api?id=1",
                /* reason       = */ "【负面示例】模型把 query 的 id 错放进 header 分类",
                /* queryParams  = */ Map.of(),
                /* formParams   = */ Map.of(),
                /* headerParams = */ Map.of("id", "x"),
                /* jsonParams   = */ Map.of(),
                /* pathParams   = */ Map.of());
        IllegalArgumentException ex = null;
        try {
            sim.replaceHeaderParams(Map.of("id", "x"));
        } catch (IllegalArgumentException e) {
            ex = e;
        }
        assertNotNull(ex, "应抛 IAE：原请求里 id 只在 query，不在 header");
        // 错误信息应同时包含"哪个分类、哪个 key"和"正确位置实际有哪些 key 可用"
        String msg = ex.getMessage();
        assertTrue(msg.contains("header:id"), msg);
        assertTrue(msg.contains("query=["), "应列出 query 分类下的可用 key 帮模型定位：" + msg);
        System.out.println("[" + "wrongPosition_queryKeyInHeaderSlot_failsLocally" + "] 错误信息：");
        System.out.println("  " + msg);
    }

    /**
     * <b>基线</b>：5 个 map 全空 → 实际就是把原请求原样重发（虽然语义上无意义，
     * 验证工具至少能跑通）。{@link ReplayTool#execute} 会提前用 {@code hasReplacements()}
     * 拦下这种情况并报错"必须至少填一个分类"；这里是直接调 {@code toJdkRequest}
     * 验证底层构造逻辑。
     */
    @Test
    void noReplacements_sendOriginalAsIs() throws Exception {
        CapturedRequest captured = new CapturedRequest();
        server.createContext("/api", captureAll(captured));

        // 5 个 map 都不传 → 原样发
        ReplaySimulator sim = new ReplaySimulator("GET", "/api", "id=1", defaultHeaders(), null);
        printScenario("noReplacements_sendOriginalAsIs",
                /* originalLine = */ "GET /api?id=1",
                /* reason       = */ "【基线】5 个 map 全空 → 原样发（相当于『啥也没改』）",
                /* queryParams  = */ Map.of(),
                /* formParams   = */ Map.of(),
                /* headerParams = */ Map.of(),
                /* jsonParams   = */ Map.of(),
                /* pathParams   = */ Map.of());
        HttpRequest req = sim.toJdkRequest("http://127.0.0.1:" + port);
        ReplaySimulator orig = sim.copy();

        printSent("noReplacements_sendOriginalAsIs", orig, sim, req);
        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        printResponse("noReplacements_sendOriginalAsIs", resp);

        assertEquals(200, resp.statusCode());
        assertEquals("1", captured.query.get("id"), "原样发，id 应为 1");
    }

    // ===== 控制台打印辅助 =====

    /**
     * 把"用例场景"打出来——含原请求、reason、5 类替换参数，模拟模型在 tool_calls 里
     * 提交的 arguments 视角。打印格式：
     * <pre>
     * ====== [testName] 用例场景 ======
     * 原请求: GET /api?id=1
     * 模型 arguments:
     *   {
     *     "reason": "闭合单引号看回显（SQL 注入探测）",
     *     "replace_query_params":  { "id": "1'" },
     *     "replace_form_params":   {  },
     *     "replace_header_params": {  },
     *     "replace_json_params":   {  },
     *     "replace_path_params":   {  }
     *   }
     * ======
     * </pre>
     */
    private static void printScenario(String testName, String originalLine, String reason,
                                      Map<String, String> queryParams,
                                      Map<String, String> formParams,
                                      Map<String, String> headerParams,
                                      Map<String, String> jsonParams,
                                      Map<String, String> pathParams) {
        System.out.println();
        System.out.println("====== [" + testName + "] 用例场景 ======");
        System.out.println("原请求: " + originalLine);
        System.out.println("模型 arguments:");
        System.out.println("  {");
        System.out.println("    \"reason\": \"" + reason + "\",");
        System.out.println("    \"replace_query_params\":  " + jsonString(queryParams) + ",");
        System.out.println("    \"replace_form_params\":   " + jsonString(formParams) + ",");
        System.out.println("    \"replace_header_params\": " + jsonString(headerParams) + ",");
        System.out.println("    \"replace_json_params\":   " + jsonString(jsonParams) + ",");
        System.out.println("    \"replace_path_params\":   " + jsonString(pathParams));
        System.out.println("  }");
        System.out.println("======");
    }

    /** 把 {@code {k=v, ...}} 序列化成 JSON 字符串（空 map 输出 {@code {}}）。 */
    private static String jsonString(Map<String, String> map) {
        if (map == null || map.isEmpty()) return "{ }";
        StringBuilder sb = new StringBuilder("{ ");
        boolean first = true;
        for (var e : map.entrySet()) {
            if (!first) sb.append(", ");
            sb.append("\"").append(escapeJson(e.getKey())).append("\": \"")
                    .append(escapeJson(e.getValue())).append("\"");
            first = false;
        }
        sb.append(" }");
        return sb.toString();
    }

    /** 极简 JSON 字符串转义：只处理引号和反斜杠（避免控制台破坏对齐）。 */
    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void printSent(String label, ReplaySimulator originalSim, ReplaySimulator sim, HttpRequest req) {
        System.out.println();
        System.out.println("==== [" + label + "] 原始 vs 转换后请求 ====");
        // —— 原始 sim 状态（用调用方在 replaceXxx 之前拍的快照） ——
        System.out.println("【原始 sim 状态】");
        System.out.println("  " + originalSim.method + " " + originalSim.path
                + (originalSim.queryString == null || originalSim.queryString.isEmpty() ? "" : "?" + originalSim.queryString));
        for (var e : originalSim.headers.entrySet()) {
            System.out.println("  " + e.getKey() + ": " + e.getValue());
        }
        if (originalSim.body != null && !originalSim.body.isEmpty()) {
            for (String line : originalSim.body.split("\n", -1)) {
                System.out.println("  | " + line);
            }
        }
        // —— 转换后（构造好的 JDK HttpRequest） wire 格式 ——
        System.out.println("【转换后 JDK HttpRequest（wire 格式）】");
        StringBuilder sb = new StringBuilder();
        sb.append(req.method()).append(' ').append(req.uri().getRawPath());
        if (req.uri().getRawQuery() != null) sb.append('?').append(req.uri().getRawQuery());
        sb.append(" HTTP/1.1\r\n");
        sb.append("Host: ").append(req.uri().getHost());
        if (req.uri().getPort() != -1) sb.append(':').append(req.uri().getPort());
        sb.append("\r\n");
        for (var e : req.headers().map().entrySet()) {
            for (String v : e.getValue()) {
                sb.append(e.getKey()).append(": ").append(v).append("\r\n");
            }
        }
        sb.append("\r\n");
        if (sim.body != null && !sim.body.isEmpty()) {
            sb.append(sim.body);
        }
        for (String line : sb.toString().split("\r\n", -1)) {
            System.out.println("  " + line);
        }
        System.out.println("====");
    }

    private static void printResponse(String label, HttpResponse<String> resp) {
        System.out.println("---- [" + label + "] 收到响应 ----");
        System.out.println("HTTP " + resp.statusCode());
        resp.headers().firstValue("Content-Type").ifPresent(ct -> System.out.println("Content-Type: " + ct));
        String body = resp.body();
        if (body != null && !body.isEmpty()) {
            System.out.println("Body: " + (body.length() > 200 ? body.substring(0, 200) + "..." : body));
        }
    }

    // ===== 测试工具 =====

    private static Map<String, String> defaultHeaders() {
        Map<String, String> h = new LinkedHashMap<>();
        // 不显式设 Host：JDK HttpClient 会从 URI 推断，且禁止手动覆盖
        return h;
    }

    private static Map<String, String> formHeaders(String method, String body) {
        Map<String, String> h = defaultHeaders();
        h.put("Content-Type", "application/x-www-form-urlencoded");
        return h;
    }

    private static Map<String, String> jsonHeaders(String method, String body) {
        Map<String, String> h = defaultHeaders();
        h.put("Content-Type", "application/json");
        return h;
    }

    /**
     * 把 HttpExchange 收到的请求数据捕获到 {@link CapturedRequest}。
     * 包括：method / path / query / headers / 解析后的 form body / 解析后的 JSON body（尽力而为）。
     */
    private static HttpHandler captureAll(CapturedRequest captured) {
        return exchange -> {
            captured.method = exchange.getRequestMethod();
            captured.path = exchange.getRequestURI().getPath();
            captured.query = parseQuery(exchange.getRequestURI());
            captured.headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            exchange.getRequestHeaders().forEach((k, v) -> {
                if (!v.isEmpty()) captured.headers.put(k, v.get(0));
            });
            String body = readBody(exchange);
            String ct = captured.headers.get("Content-Type");
            if (ct == null) ct = "";
            if (ct.contains("application/x-www-form-urlencoded")) {
                captured.form = parseFormBody(body);
            } else if (ct.contains("application/json")) {
                captured.jsonBody = body;
            }
            // 简化响应：200 + 一段 echo，告诉测试调用方"我收到了"
            String resp = "{\"ok\":true,\"path\":\"" + captured.path
                    + "\",\"query_count\":" + captured.query.size() + "}";
            byte[] bytes = resp.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (var os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        };
    }

    private static String readBody(HttpExchange exchange) throws IOException {
        try (InputStream is = exchange.getRequestBody()) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static Map<String, String> parseQuery(URI uri) {
        Map<String, String> out = new LinkedHashMap<>();
        String q = uri.getRawQuery();
        if (q == null || q.isEmpty()) return out;
        for (String pair : q.split("&")) {
            int eq = pair.indexOf('=');
            String k = eq < 0 ? pair : pair.substring(0, eq);
            String v = eq < 0 ? "" : pair.substring(eq + 1);
            out.put(URLDecoder.decode(k, StandardCharsets.UTF_8),
                    URLDecoder.decode(v, StandardCharsets.UTF_8));
        }
        return out;
    }

    private static Map<String, String> parseFormBody(String body) {
        Map<String, String> out = new LinkedHashMap<>();
        if (body == null || body.isEmpty()) return out;
        for (String pair : body.split("&")) {
            int eq = pair.indexOf('=');
            String k = eq < 0 ? pair : pair.substring(0, eq);
            String v = eq < 0 ? "" : pair.substring(eq + 1);
            out.put(URLDecoder.decode(k, StandardCharsets.UTF_8),
                    URLDecoder.decode(v, StandardCharsets.UTF_8));
        }
        return out;
    }

    /** 测试用：捕获一次请求的关键字段。 */
    static class CapturedRequest {
        String method;
        String path;
        Map<String, String> query = new LinkedHashMap<>();
        Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        Map<String, String> form = new LinkedHashMap<>();
        String jsonBody;
    }

    /**
     * 模拟 ReplayService 的"按位置分类"替换语义，跑在 String/Map 层（不依赖 Burp）。
     *
     * <p>行为契约：</p>
     * <ul>
     *   <li>replace_query_params：改 query string，URL 编码新值</li>
     *   <li>replace_form_params：改 form-encoded body，URL 编码新值</li>
     *   <li>replace_header_params：改请求头（大小写不敏感），值保持原样</li>
     *   <li>replace_json_params：改 JSON body 字段（支持点号路径），值 JSON 编码</li>
     *   <li>replace_path_params：改 path 的最后一段非空段（如 /api/users/123 → 改 123），
     *       要求 path-only（无 ?query）、路径至少 2 段；只接受虚拟 key "path"</li>
     * </ul>
     */
    static class ReplaySimulator {
        private final String method;
        private String path;
        private String queryString;
        private final Map<String, String> headers;
        private String body;

        ReplaySimulator(String method, String path, String queryString,
                        Map<String, String> headers, String body) {
            this.method = method;
            this.path = path;
            this.queryString = queryString;
            this.headers = new LinkedHashMap<>(headers);
            this.body = body;
        }

        /**
         * 浅拷贝快照：复制 method/path/queryString/headers/body 的当前值。
         * 用于在 {@code replaceXxxParams} 改写 sim 字段之前，保存"原始状态"以便后续打印对比。
         */
        ReplaySimulator copy() {
            ReplaySimulator c = new ReplaySimulator(method, path, queryString, headers, body);
            return c;
        }

        void replaceQueryParams(Map<String, String> changes) {
            if (changes == null || changes.isEmpty()) return;
            Map<String, String> current = parseKvString(queryString);
            List<String> notFound = new ArrayList<>();
            for (var e : changes.entrySet()) {
                if (!current.containsKey(e.getKey())) {
                    notFound.add(e.getKey());
                    continue;
                }
                current.put(e.getKey(), e.getValue());
            }
            if (!notFound.isEmpty()) {
                throw new IllegalArgumentException(formatNotFoundError("query", notFound));
            }
            this.queryString = encodeKv(current);
        }

        void replaceFormParams(Map<String, String> changes) {
            if (changes == null || changes.isEmpty()) return;
            Map<String, String> current = parseKvString(body);
            List<String> notFound = new ArrayList<>();
            for (var e : changes.entrySet()) {
                if (!current.containsKey(e.getKey())) {
                    notFound.add(e.getKey());
                    continue;
                }
                current.put(e.getKey(), e.getValue());
            }
            if (!notFound.isEmpty()) {
                throw new IllegalArgumentException(formatNotFoundError("form", notFound));
            }
            this.body = encodeKv(current);
        }

        void replaceHeaderParams(Map<String, String> changes) {
            if (changes == null || changes.isEmpty()) return;
            // header 大小写不敏感：用 TreeMap(CASE_INSENSITIVE_ORDER) 包装
            Map<String, String> ci = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            ci.putAll(headers);
            List<String> notFound = new ArrayList<>();
            for (var e : changes.entrySet()) {
                if (!ci.containsKey(e.getKey())) {
                    notFound.add(e.getKey());
                    continue;
                }
                ci.put(e.getKey(), e.getValue());
            }
            if (!notFound.isEmpty()) {
                throw new IllegalArgumentException(formatNotFoundError("header", notFound));
            }
            headers.clear();
            headers.putAll(ci);
        }

        void replaceJsonParams(Map<String, String> changes) {
            if (changes == null || changes.isEmpty()) return;
            // 简化：把 body 当作"紧凑 JSON"处理；点号路径在 path 上逐段定位
            // 这里只验证行为契约（点号路径能改到目标 key），不追求严格的 JSON 解析鲁棒性
            String newBody = body;
            for (var e : changes.entrySet()) {
                try {
                    newBody = replaceJsonPath(newBody, e.getKey(), e.getValue());
                } catch (IllegalArgumentException jpe) {
                    // 转成统一格式：[json:user.id]
                    throw new IllegalArgumentException(formatNotFoundError("json", List.of(e.getKey())));
                }
            }
            this.body = newBody;
        }

        /**
         * 按"段值"匹配替换 path 段。与 {@code ReplayService.applyPath} 规则一致：
         * key = 段的当前值，匹配后整段被替换；同值多段全部替换；URL 含 ? 时整体拒绝。
         */
        void replacePathParams(Map<String, String> changes) {
            if (changes == null || changes.isEmpty()) return;
            // path-only 场景：URL 含 ? 时不算"路径参数"形态
            if (queryString != null && !queryString.isEmpty()) {
                throw new IllegalArgumentException(formatNotFoundError("path", List.copyOf(changes.keySet())));
            }
            String[] segs = path.split("/", -1);
            for (var e : changes.entrySet()) {
                String key = e.getKey();
                String newValue = e.getValue();
                boolean found = false;
                StringBuilder newPath = new StringBuilder(path.length() + 8);
                boolean first = true;
                for (String seg : segs) {
                    if (!first) newPath.append('/');
                    first = false;
                    if (!seg.isEmpty() && seg.equals(key)) {
                        newPath.append(newValue);
                        found = true;
                    } else {
                        newPath.append(seg);
                    }
                }
                if (!found) {
                    throw new IllegalArgumentException(formatNotFoundError("path", List.of(key)));
                }
                path = newPath.toString();
                segs = path.split("/", -1);  // 后续替换基于新 path
            }
        }

        /**
         * 生成与 {@code ReplayService} 一致的"未找到可替换参数"错误信息：
         * {@code "未找到可替换参数：[query:id]；当前请求各位置的可用 key：{query=[id], form=[...], header=[...], json=[...], path=[path]}"}
         * 集成测试用这个格式断言错误信息包含"分类:key"和"分类=[可用 key 清单]"。
         */
        private String formatNotFoundError(String category, List<String> missingKeys) {
            List<String> prefixed = new ArrayList<>();
            for (String k : missingKeys) prefixed.add(category + ":" + k);
            Map<String, String> query = parseKvString(queryString);
            Map<String, String> form = parseKvString(body);
            Map<String, String> ci = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            ci.putAll(headers);
            // JSON: 简化列出顶层 key（不够严谨，但足够"提示作用"）
            Set<String> json = new TreeSet<>();
            if (body != null && !body.isEmpty()) {
                int i = 0;
                while (i < body.length()) {
                    int k1 = body.indexOf('"', i);
                    if (k1 < 0) break;
                    int k2 = body.indexOf('"', k1 + 1);
                    if (k2 < 0) break;
                    int colon = body.indexOf(':', k2);
                    if (colon < 0) break;
                    String key = body.substring(k1 + 1, k2);
                    json.add(key);
                    i = colon + 1;
                }
            }
            // path: 与 ReplayService 对齐——列出所有非空段值（去重、按出现顺序）
            Set<String> pathBucket = new TreeSet<>();
            if ((queryString == null || queryString.isEmpty()) && path != null && !path.isEmpty()) {
                for (String seg : path.split("/", -1)) {
                    if (!seg.isEmpty()) pathBucket.add(seg);
                }
            }
            return "未找到可替换参数：" + prefixed
                    + "；当前请求各位置的可用 key：{"
                    + "query=" + query.keySet()
                    + ", form=" + parseKvString(body).keySet()
                    + ", header=" + ci.keySet()
                    + ", json=" + json
                    + ", path=" + pathBucket
                    + "}";
        }

        /** 把当前状态构造成 JDK {@link HttpRequest}（带 body 的话用 BodyPublishers.ofString）。 */
        HttpRequest toJdkRequest(String baseUrl) {
            StringBuilder url = new StringBuilder(baseUrl).append(path);
            if (queryString != null && !queryString.isEmpty()) {
                url.append('?').append(queryString);
            }
            HttpRequest.Builder b = HttpRequest.newBuilder()
                    .uri(URI.create(url.toString()))
                    .timeout(Duration.ofSeconds(5));
            for (var e : headers.entrySet()) {
                b.header(e.getKey(), e.getValue());
            }
            if (body != null && !body.isEmpty()) {
                b.method(method, HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
            } else {
                b.method(method, HttpRequest.BodyPublishers.noBody());
            }
            return b.build();
        }

        private static Map<String, String> parseKvString(String s) {
            Map<String, String> out = new LinkedHashMap<>();
            if (s == null || s.isEmpty()) return out;
            for (String pair : s.split("&")) {
                int eq = pair.indexOf('=');
                String k = eq < 0 ? pair : pair.substring(0, eq);
                String v = eq < 0 ? "" : pair.substring(eq + 1);
                try {
                    out.put(URLDecoder.decode(k, StandardCharsets.UTF_8),
                            URLDecoder.decode(v, StandardCharsets.UTF_8));
                } catch (Exception e) {
                    out.put(k, v);
                }
            }
            return out;
        }

        private static String encodeKv(Map<String, String> kv) {
            StringBuilder sb = new StringBuilder();
            boolean first = true;
            for (var e : kv.entrySet()) {
                if (!first) sb.append('&');
                sb.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8))
                        .append('=')
                        .append(URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
                first = false;
            }
            return sb.toString();
        }

        /**
         * 替换 JSON 中"点号路径"对应的 value：
         * {@code replaceJsonPath("{\"user\":{\"id\":1}}", "user.id", "999") → "{\"user\":{\"id\":999}}"}.
         * 简化实现：定位 "key":VALUE，把 VALUE 替换成新值（value 是数字 → 数字；字符串 → 加引号）。
         * 真实 Burp 会做更严谨的 JSON 解析——这里只为端到端验证"点号路径能改到目标 key"。
         */
        private static String replaceJsonPath(String json, String dotPath, String newValue) {
            String[] segments = dotPath.split("\\.");
            // 从最深层往上找 "key": 的位置
            int keyIdx = 0;
            for (int i = 0; i < segments.length; i++) {
                String segment = segments[i];
                String needle = "\"" + segment + "\":";
                int found = json.indexOf(needle, keyIdx);
                if (found < 0) {
                    throw new IllegalArgumentException("JSON 中未找到路径 " + dotPath
                            + "（在 '" + segment + "' 处）");
                }
                keyIdx = found + needle.length();
            }
            // keyIdx 指向 ":" 之后；找到 value 的开始（跳过空白）
            int valueStart = keyIdx;
            while (valueStart < json.length() && Character.isWhitespace(json.charAt(valueStart))) {
                valueStart++;
            }
            // 找到 value 的结束
            int valueEnd;
            char first = json.charAt(valueStart);
            if (first == '"') {
                // 字符串：找到匹配的结束引号（不考虑转义——简化版）
                valueEnd = json.indexOf('"', valueStart + 1);
                if (valueEnd < 0) {
                    throw new IllegalArgumentException("JSON 字符串未闭合：" + json);
                }
                // 用 JSON 编码的新值替换
                String escaped = newValue.replace("\\", "\\\\").replace("\"", "\\\"");
                return json.substring(0, valueStart) + "\"" + escaped + "\"" + json.substring(valueEnd + 1);
            } else {
                // 数字 / 布尔 / null：找到下一个 , } ] 或空白
                valueEnd = valueStart;
                while (valueEnd < json.length()) {
                    char c = json.charAt(valueEnd);
                    if (c == ',' || c == '}' || c == ']' || Character.isWhitespace(c)) break;
                    valueEnd++;
                }
                return json.substring(0, valueStart) + newValue + json.substring(valueEnd);
            }
        }
    }
}
