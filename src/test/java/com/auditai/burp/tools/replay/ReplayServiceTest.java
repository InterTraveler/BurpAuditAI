package com.auditai.burp.tools.replay;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.Test;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link ReplayService} v3 协议（按位置分类的参数替换）的单元测试。
 *
 * <p>用 JDK 动态代理构造假的 {@link HttpRequest} / {@link HttpParameter} /
 * {@link MontoyaApi}——参考 {@code TrafficFlowWalkthroughTest.fakeRequest} 的套路。
 * 这里只覆盖"参数替换"的纯逻辑，不真发 HTTP；真发部分的兜底逻辑在
 * {@code ReplayServiceIntegrationTest} 里覆盖（用本地 HttpServer 跑端到端）。</p>
 *
 * <p><b>每个用例都打印"模型输入 arguments + 期望变化"</b>，方便对照查看测试流程。</p>
 */
class ReplayServiceTest {

    /**
     * 测试用 builder：把 HttpParameter 工厂替换为 JDK 动态代理，脱离 Burp 运行时也能跑通单测。
     */
    private static final ReplayService.HttpParameterBuilder FAKE_BUILDER = ReplayServiceTest::fakeParam;

    /**
     * 测试用 ByteArray 工厂：直接包成我们的 fakeByteArray，避开生产里
     * {@code ByteArray.byteArray(...)} 对 MontoyaObjectFactory.FACTORY 的强依赖。
     */
    private static final ReplayService.ByteArrayFactory FAKE_BYTE_ARRAY_FACTORY = ReplayServiceTest::fakeByteArray;

    /**
     * 把"模型输入 arguments"和"期望变化"打出来——所有替换型用例都调一次。
     * 9 参：name, reason, query, form, header, json, path, multipart, expectation
     */
    private static void printCase(String testName, String reason,
                                  Map<String, String> queryParams,
                                  Map<String, String> formParams,
                                  Map<String, String> headerParams,
                                  Map<String, String> jsonParams,
                                  Map<String, String> pathParams,
                                  Map<String, String> multipartParams,
                                  String expectation) {
        System.out.println();
        System.out.println("─────── [" + testName + "] ───────");
        System.out.println("模型 arguments:");
        System.out.println("  {");
        System.out.println("    \"reason\": \"" + (reason == null ? "" : reason) + "\",");
        System.out.println("    \"replace_query_params\":     " + miniJson(queryParams) + ",");
        System.out.println("    \"replace_form_params\":      " + miniJson(formParams) + ",");
        System.out.println("    \"replace_header_params\":    " + miniJson(headerParams) + ",");
        System.out.println("    \"replace_json_params\":      " + miniJson(jsonParams) + ",");
        System.out.println("    \"replace_path_params\":      " + miniJson(pathParams) + ",");
        System.out.println("    \"replace_multipart_params\": " + miniJson(multipartParams));
        System.out.println("  }");
        System.out.println("期望: " + expectation);
        System.out.println("───────────────────────────");
    }

    private static String miniJson(Map<String, String> map) {
        if (map == null || map.isEmpty()) return "{ }";
        StringBuilder sb = new StringBuilder("{ ");
        boolean first = true;
        for (var e : map.entrySet()) {
            if (!first) sb.append(", ");
            sb.append("\"").append(e.getKey().replace("\"", "\\\""))
                .append("\": \"").append(e.getValue().replace("\"", "\\\""))
                .append("\"");
            first = false;
        }
        sb.append(" }");
        return sb.toString();
    }

    /**
     * 打印"原始请求 vs 转换后请求"对比——方便肉眼判断 path/header 等分类改值是否生效。
     * 用法：在 {@code applyReplacements(...)} 返回后立刻调一次。
     */
    private static void printRequestDiff(HttpRequest original, ReplayService.BuildOutcome out) {
        if (out == null || out.request() == null) return;
        System.out.println();
        System.out.println("─────── [请求对比] ───────");
        System.out.println("【原始】");
        printReqSummary("  ", original);
        System.out.println("【转换后】");
        printReqSummary("  ", out.request());
        if (!out.changes().isEmpty()) {
            System.out.println("【changes 序列】");
            for (var c : out.changes()) {
                System.out.println("  " + c.shortSummary());
            }
        }
        System.out.println("───────────────────────────");
    }

    /**
     * 打印请求的关键字段：method、url（path 已包含在 url 里，不重复）；不展开 headers/body。
     */
    private static void printReqSummary(String indent, HttpRequest req) {
        if (req == null) {
            System.out.println(indent + "(null)");
            return;
        }
        System.out.println(indent + "method: " + req.method());
        if (req.url() != null) System.out.println(indent + "url:    " + req.url());
    }

    // ===== listAddressableParams =====

    @Test
    void listAddressableParams_groupsByType() {
        // query(id, page) + form(username, password) + json(data.id) + header(X-Token, User-Agent)
        List<ParsedHttpParameter> params = new ArrayList<>();
        params.add(fakeParam("id", "1", HttpParameterType.URL));
        params.add(fakeParam("page", "1", HttpParameterType.URL));
        params.add(fakeParam("username", "u", HttpParameterType.BODY));
        params.add(fakeParam("password", "p", HttpParameterType.BODY));
        params.add(fakeParam("data.id", "1", HttpParameterType.JSON));
        List<HttpHeader> headers = new ArrayList<>();
        headers.add(fakeHeader("X-Token", "abc"));
        headers.add(fakeHeader("User-Agent", "x"));

        HttpRequest req = fakeRequest(params, headers, "GET", "/api?id=1&page=1");
        String out = ReplayService.listAddressableParamsStatic(req);

        assertTrue(out.contains("【可替换参数】"));
        assertTrue(out.contains("- query: id, page"));
        assertTrue(out.contains("- form: username, password"));
        assertTrue(out.contains("- json: data.id"));
        assertTrue(out.contains("- header: X-Token, User-Agent"));
    }

    @Test
    void listAddressableParams_nullRequest_returnsEmpty() {
        assertEquals("", ReplayService.listAddressableParamsStatic(null));
    }

    @Test
    void listAddressableParams_emptyRequest_explicitEmptyHint() {
        // 5 类全部为空时，明确告诉模型"别调"——避免模型套用 `{"id":"1'"}` 模板浪费预算
        HttpRequest req = fakeRequest(List.of(), List.of(), "GET", "/");
        String out = ReplayService.listAddressableParamsStatic(req);
        assertTrue(out.startsWith("【可替换参数】\n"));
        assertTrue(out.contains("无可替换参数"));
        assertTrue(out.contains("禁止调 replay_request"));
    }

    // ===== applyReplacements：每个分类独立查 =====
    // 约定：每个调用都用 builder().queryParams(...).formParams(...)... 的形式，
    // 其它分类传 null/空 Map。

    /**
     * 改 URL 上的 query 参数 {@code id}。验证单值参数被定位到 {@code query} 分类、
     * 原值 / 新值 / 位置都正确记录。
     */
    @Test
    void applyReplacements_replacesQueryParam() {
        List<ParsedHttpParameter> params = List.of(
            fakeParam("id", "1", HttpParameterType.URL));
        List<HttpHeader> headers = List.of(fakeHeader("Host", "x.com"));
        HttpRequest req = fakeRequest(params, headers, "GET", "/api?id=1");
        printCase("applyReplacements_replacesQueryParam",
            "闭合 id 单引号看回显",
            Map.of("id", "1'"), null, null, null, null,
            null,
            "1 个 change，位置 query，key=id，old=1 → new=1'");

        ReplayService svc = new ReplayService(null, req, FAKE_BUILDER, FAKE_BYTE_ARRAY_FACTORY);
        ReplayService.BuildOutcome out = svc.applyReplacements(
            req, Map.of("id", "1'"), null, null, null, null, null);

        assertEquals(1, out.changes().size());
        ReplayRequest.ParamChange change = out.changes().get(0);
        assertEquals("id", change.key());
        assertEquals("1", change.originalValue());
        assertEquals("1'", change.newValue());
        assertEquals("query", change.location());
    }

    /**
     * 改 JSON body 嵌套字段 {@code user.id}（点号路径）。验证点号路径能跨层级
     * 准确定位目标字段。
     */
    @Test
    void applyReplacements_replacesJsonParam_withDotPath() {
        List<ParsedHttpParameter> params = List.of(
            fakeParam("user.id", "1", HttpParameterType.JSON),
            fakeParam("user.name", "alice", HttpParameterType.JSON));
        HttpRequest req = fakeRequest(params, List.of(), "POST",
            "{\"user\":{\"id\":1,\"name\":\"alice\"}}");
        printCase("applyReplacements_replacesJsonParam_withDotPath",
            "JSON 嵌套字段注入（点号路径）",
            null, null, null, Map.of("user.id", "1' OR 1=1--"), null,
            null,
            "1 个 change，位置 json，key=user.id（点号路径）");

        ReplayService svc = new ReplayService(null, req, FAKE_BUILDER, FAKE_BYTE_ARRAY_FACTORY);
        ReplayService.BuildOutcome out = svc.applyReplacements(
            req, null, null, null, Map.of("user.id", "1' OR 1=1--"), null, null);

        assertEquals(1, out.changes().size());
        assertEquals("json", out.changes().get(0).location());
        assertEquals("user.id", out.changes().get(0).key());
    }

    // ===== path 参数（URL 路径段值作 key）=====

    /**
     * 改 URL 路径的某段值。验证：段值作为 key 匹配、整段被替换；new path 保留其余段；
     * location = "path"。
     */
    @Test
    void applyReplacements_replacesPathParam_lastSegment() {
        // /api/users/123 → 改最后一段 123 为 999
        HttpRequest req = fakeRequest(List.of(), List.of(), "GET", "/api/users/123");
        printCase("applyReplacements_replacesPathParam_lastSegment",
            "改路径最后一段（key=段值）",
            null, null, null, null, Map.of("123", "999"),
            null,
            "1 个 change，位置 path，key=123，old=123 → new=999");

        ReplayService svc = new ReplayService(null, req, FAKE_BUILDER, FAKE_BYTE_ARRAY_FACTORY);
        ReplayService.BuildOutcome out = svc.applyReplacements(
            req, null, null, null, null, Map.of("123", "999"), null);

        printRequestDiff(req, out);
        assertEquals(1, out.changes().size());
        ReplayRequest.ParamChange change = out.changes().get(0);
        assertEquals("123", change.key());
        assertEquals("123", change.originalValue());
        assertEquals("999", change.newValue());
        assertEquals("path", change.location());
    }

    /**
     * 改路径中间的某段（非最后一段）。验证：key=段值、其它段保留。
     */

    /**
     * 同一段值多次出现（如 /a/1/b/1）→ 传 {"1": "X"} 会把所有值为 1 的段都改。
     */
    @Test
    void applyReplacements_replacesPathParam_duplicateValue_replacesAll() {
        // /a/1/b/1 → 改 "1" 为 "X" → /a/X/b/X
        HttpRequest req = fakeRequest(List.of(), List.of(), "GET", "/a/1/b/1");
        Map<String, String> pathChanges = new LinkedHashMap<>();
        pathChanges.put("1", "X");
        printCase("applyReplacements_replacesPathParam_duplicateValue_replacesAll",
            "同段值多次出现 → 全部替换",
            null, null, null, null, pathChanges,
            null,
            "2 个 change，位置 path，key=1，old=1 → new=X（两处都改）");

        ReplayService svc = new ReplayService(null, req, FAKE_BUILDER, FAKE_BYTE_ARRAY_FACTORY);
        ReplayService.BuildOutcome out = svc.applyReplacements(
            req, null, null, null, null, pathChanges, null);

        // 同 key 多次替换 → ParamChange 列表里应该有 2 条（每次替换一条记录）
        printRequestDiff(req, out);
        assertEquals(2, out.changes().size());
        for (var c : out.changes()) {
            assertEquals("1", c.key());
            assertEquals("1", c.originalValue());
            assertEquals("X", c.newValue());
            assertEquals("path", c.location());
        }
    }

    /**
     * 单段路径（/users）→ key = "users" 也能识别替换。
     */
    @Test
    void applyReplacements_replacesPathParam_singleSegment() {
        // /users → /members
        HttpRequest req = fakeRequest(List.of(), List.of(), "GET", "/users");
        printCase("applyReplacements_replacesPathParam_singleSegment",
            "单段路径也支持（key=users）",
            null, null, null, null, Map.of("users", "members"),
            null,
            "1 个 change，位置 path，key=users，old=users → new=members");

        ReplayService svc = new ReplayService(null, req, FAKE_BUILDER, FAKE_BYTE_ARRAY_FACTORY);
        ReplayService.BuildOutcome out = svc.applyReplacements(
            req, null, null, null, null, Map.of("users", "members"), null);

        printRequestDiff(req, out);
        assertEquals(1, out.changes().size());
        assertEquals("users", out.changes().get(0).key());
        assertEquals("users", out.changes().get(0).originalValue());
        assertEquals("members", out.changes().get(0).newValue());
    }

    /**
     * 路径以 / 结尾（如 /api/users/123/）也能正确识别段值 123。
     */
    @Test
    void applyReplacements_replacesPathParam_trailingSlash() {
        HttpRequest req = fakeRequest(List.of(), List.of(), "GET", "/api/users/123/");
        printCase("applyReplacements_replacesPathParam_trailingSlash",
            "路径末尾带 / 也能识别",
            null, null, null, null, Map.of("123", "999"),
            null,
            "1 个 change，位置 path，key=123，old=123 → new=999");

        ReplayService svc = new ReplayService(null, req, FAKE_BUILDER, FAKE_BYTE_ARRAY_FACTORY);
        ReplayService.BuildOutcome out = svc.applyReplacements(
            req, null, null, null, null, Map.of("123", "999"), null);

        printRequestDiff(req, out);
        assertEquals(1, out.changes().size());
        assertEquals("123", out.changes().get(0).originalValue());
        assertEquals("999", out.changes().get(0).newValue());
    }

    /**
     * 模型传的 key 不在路径段值里 → 整体拒绝，错误信息含 path:<key>。
     */
    @Test
    void applyReplacements_pathParam_unknownKey_fails() {
        HttpRequest req = fakeRequest(List.of(), List.of(), "GET", "/api/users/123");
        printCase("applyReplacements_pathParam_unknownKey_fails",
            "【负面】path 用了不在段值里的 key",
            null, null, null, null, Map.of("id", "999"),
            null,
            "应抛 IAE；错误信息含 path:id");

        ReplayService svc = new ReplayService(null, req, FAKE_BUILDER, FAKE_BYTE_ARRAY_FACTORY);
        try {
            svc.applyReplacements(req, null, null, null, null, Map.of("id", "999"), null);
            fail("应抛 IAE：path 段值里没有 id");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("path:id"),
                "错误信息应含 path:id；实际：" + e.getMessage());
        }
    }

    /**
     * 一次重放同时传 path + query，验证 v3 协议"任一 key notFound → 整体拒绝"语义。
     * <p>path + query 同框是"互斥"的——path-only 要求 URL 不含 {@code ?}。
     * 想同时改 path 段值和 query 参数，必须分两次重放或用 path-only URL。
     * 本测试验证：原请求有 query param（{@code expand=posts}），{@code url()} 动态拼出来
     * 会含 {@code ?}，触发 path-only 限制 → path 那条 key 进 notFound → 整体抛 IAE
     * （即使 query 那条本身合法也照样拒绝——避免模型以为替换生效了）。</p>
     */
    @Test
    void applyReplacements_pathParam_andQueryParam_together() {
        HttpRequest req = fakeRequest(
            List.of(fakeParam("expand", "posts", HttpParameterType.URL)),
            List.of(), "GET", "/api/users/123");
        printCase("applyReplacements_pathParam_andQueryParam_together",
            "path + query 同框：path 因 path-only 限制失败 → v3 协议整体拒绝",
            Map.of("expand", "comments"), null, null, null, Map.of("123", "999"),
            null,
            "应抛 IAE：URL 含 ? 时 path 不接受 → 任一 key notFound 整体拒绝（v3 协议）");

        ReplayService svc = new ReplayService(null, req, FAKE_BUILDER, FAKE_BYTE_ARRAY_FACTORY);
        try {
            svc.applyReplacements(req,
                Map.of("expand", "comments"), null, null, null, Map.of("123", "999"), null);
            fail("应抛 IAE：URL 含 ? 时 path 不接受");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("path:123"),
                "错误信息应含 path:123；实际：" + e.getMessage());
        }
    }

    /**
     * path 段值匹配严格区分大小写。{@code /api/Users/123} 传 {@code {"users":"X"}} 应失败——
     * 段值 "Users"（大写 U）不等于 "users"（小写 u）。
     */
    @Test
    void applyReplacements_pathParam_isCaseSensitive() {
        // /api/Users/123 → 段值 = [api, Users, 123]（Users 大写）
        HttpRequest req = fakeRequest(List.of(), List.of(), "GET", "/api/Users/123");
        printCase("applyReplacements_pathParam_isCaseSensitive",
            "【负面】path 段值匹配严格大小写，小写 key 找不到大写段",
            null, null, null, null, Map.of("users", "X"),
            null,
            "应抛 IAE；错误信息含 path:users");

        ReplayService svc = new ReplayService(null, req, FAKE_BUILDER, FAKE_BYTE_ARRAY_FACTORY);
        try {
            svc.applyReplacements(req, null, null, null, null, Map.of("users", "X"), null);
            assertFalse(true, "应抛 IAE：path 段值区分大小写，'users' != 'Users'");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("path:users"),
                "错误信息应含 path:users；实际：" + e.getMessage());
            // 错误信息应列出 path 段值（api, Users, 123），帮模型区分大小写
            assertTrue(e.getMessage().contains("Users"),
                "错误信息应列出实际段值（含大写 Users）；实际：" + e.getMessage());
        }
    }

    /**
     * 改请求头 X-Token（精确大小写匹配）。验证 header 改值被定位到 header 分类。
     */

    /**
     * 改请求头 X-Token（key 大小写不敏感匹配）。
     */
    @Test
    void applyReplacements_headerIsCaseInsensitive() {
        List<HttpHeader> headers = List.of(fakeHeader("X-Token", "abc"));
        HttpRequest req = fakeRequest(List.of(), headers, "GET", "/");
        printCase("applyReplacements_headerIsCaseInsensitive",
            "改 X-Token（小写 key，header 大小写不敏感）",
            null, null, Map.of("x-token", "admin"), null, null,
            null,
            "1 个 change；key 大小写不敏感匹配 X-Token");

        ReplayService svc = new ReplayService(null, req, FAKE_BUILDER, FAKE_BYTE_ARRAY_FACTORY);
        // 用小写 key 替换 → 仍能命中
        ReplayService.BuildOutcome out = svc.applyReplacements(
            req, null, null, Map.of("x-token", "admin"), null, null, null);
        assertEquals(1, out.changes().size());
    }

    /**
     * 关键负面场景：模型把 query=id 错放进 replace_header_params → 必须报错（不静默跨位置兜底）。
     */
    @Test
    void applyReplacements_wrongPosition_failsWithLocationHint() {
        List<ParsedHttpParameter> params = List.of(
            fakeParam("id", "1", HttpParameterType.URL));
        HttpRequest req = fakeRequest(params, List.of(), "GET", "/?id=1");
        printCase("applyReplacements_wrongPosition_failsWithLocationHint",
            "【负面】query 的 id 错放进 header",
            null, null, Map.of("id", "x"), null, null,
            null,
            "应抛 IAE；错误信息包含 header:id + query=[id]（提示正确位置）");
        ReplayService svc = new ReplayService(null, req, FAKE_BUILDER, FAKE_BYTE_ARRAY_FACTORY);

        try {
            svc.applyReplacements(req, null, null, Map.of("id", "x"), null, null, null);
            assertFalse(true, "应抛 IAE：id 只在 query 里，header 里没有");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("未找到可替换参数"),
                "实际：" + e.getMessage());
            assertTrue(e.getMessage().contains("header:id"),
                "应指出哪个分类、哪个 key；实际：" + e.getMessage());
            // 错误信息里应有"可用 key"提示（让模型知道该改哪儿）
            assertTrue(e.getMessage().contains("query=[") || e.getMessage().contains("query=[]"),
                "应列出 query 分类下的可用 key；实际：" + e.getMessage());
        }
    }

    /**
     * 多值 form username=alice&username=bob → 两条都改。
     */
    @Test
    void applyReplacements_multipleValuesSameName_inForm() {
        List<ParsedHttpParameter> params = List.of(
            fakeParam("username", "alice", HttpParameterType.BODY),
            fakeParam("username", "bob", HttpParameterType.BODY));
        HttpRequest req = fakeRequest(params, List.of(), "POST", "username=alice&username=bob");
        printCase("applyReplacements_multipleValuesSameName_inForm",
            "多值 form username=alice&username=bob → 两条都改",
            null, Map.of("username", "admin"), null, null, null,
            null,
            "1 个 change；同位置多值都改");

        ReplayService svc = new ReplayService(null, req, FAKE_BUILDER, FAKE_BYTE_ARRAY_FACTORY);
        ReplayService.BuildOutcome out = svc.applyReplacements(
            req, null, Map.of("username", "admin"), null, null, null, null);

        assertEquals(1, out.changes().size());
    }

    /**
     * 验证 {@code ParamChange.originalValue} 走 {@code decodeParamValue} 把 wire 上的
     * percent-encoded / JSON literal value 还原成明文给模型看。
     *
     * <p>fake 的 {@code ParsedHttpParameter.value()} 返回的字节是"wire 形态"——
     * 这里故意构造一个已经 percent-encoded 的 value（如 {@code "1%27"}），验证
     * 解码后变成明文 {@code "1'"}，而不是把密文直接塞给 model。</p>
     */
    @Test
    void applyReplacements_originalValue_isDecodedFromWire() {
        // query 参数 value = "1%27"（wire 形态） → 解码成 "1'"
        List<ParsedHttpParameter> params = List.of(
            fakeParam("q", "1%27", HttpParameterType.URL));
        HttpRequest req = fakeRequest(params, List.of(), "GET", "/?q=1%27");
        ReplayService svc = new ReplayService(null, req, FAKE_BUILDER, FAKE_BYTE_ARRAY_FACTORY);
        ReplayService.BuildOutcome out = svc.applyReplacements(
            req, Map.of("q", "999"), null, null, null, null, null);

        assertEquals(1, out.changes().size());
        assertEquals("1'", out.changes().get(0).originalValue(),
            "wire 上 1%27 应被解码成明文 1' 给 model 看");
        assertEquals("999", out.changes().get(0).newValue());
    }

    /**
     * JSON 类型同理：value 是 JSON 字符串字面量（含外层引号 + 内部转义），
     * 解码后变明文。
     */
    @Test
    void applyReplacements_originalValue_jsonLiteral_isDecodedToRaw() {
        // JSON value = "\"hello\nworld\""（带转义） → 解码成 hello\nworld
        List<ParsedHttpParameter> params = List.of(
            fakeParam("data", "\"hello\\nworld\"", HttpParameterType.JSON));
        HttpRequest req = fakeRequest(params, List.of(), "POST", "{\"data\":\"hello\\nworld\"}");
        ReplayService svc = new ReplayService(null, req, FAKE_BUILDER, FAKE_BYTE_ARRAY_FACTORY);
        ReplayService.BuildOutcome out = svc.applyReplacements(
            req, null, null, null, Map.of("data", "X"), null, null);

        assertEquals(1, out.changes().size());
        assertEquals("hello\nworld", out.changes().get(0).originalValue(),
            "JSON literal \"hello\\nworld\" 应被剥引号 + 反转义成明文");
    }

    /**
     * 一次重放同时改 4 类参数中的每一个，验证 changes 顺序与参数提交顺序一致。
     */
    @Test
    void applyReplacements_allFourCategoriesTogether() {
        List<ParsedHttpParameter> params = List.of(
            fakeParam("id", "1", HttpParameterType.URL),
            fakeParam("user", "alice", HttpParameterType.BODY),
            fakeParam("token", "abc", HttpParameterType.JSON));
        List<HttpHeader> headers = List.of(fakeHeader("X-Trace", "trace-1"));
        HttpRequest req = fakeRequest(params, headers, "POST", "/api?id=1");
        printCase("applyReplacements_allFourCategoriesTogether",
            "一次重放同时改 4 类参数",
            Map.of("id", "999"),
            Map.of("user", "admin"),
            Map.of("X-Trace", "trace-2"),
            Map.of("token", "xyz"),
            null,
            null,
            "4 个 change，按 query → form → header → json 顺序记录");

        ReplayService svc = new ReplayService(null, req, FAKE_BUILDER, FAKE_BYTE_ARRAY_FACTORY);
        ReplayService.BuildOutcome out = svc.applyReplacements(
            req,
            Map.of("id", "999"),
            Map.of("user", "admin"),
            Map.of("X-Trace", "trace-2"),
            Map.of("token", "xyz"),
            null,
            null);

        assertEquals(4, out.changes().size());
        // 顺序：query → form → header → json
        assertEquals("query", out.changes().get(0).location());
        assertEquals("form", out.changes().get(1).location());
        assertEquals("header", out.changes().get(2).location());
        assertEquals("json", out.changes().get(3).location());
    }

    /**
     * 只填 query，其它 3 类全空 → 只该 query 那一类。
     */
    @Test
    void applyReplacements_onlyOneCategory_applied() {
        List<ParsedHttpParameter> params = List.of(
            fakeParam("id", "1", HttpParameterType.URL),
            fakeParam("user", "alice", HttpParameterType.BODY),
            fakeParam("token", "abc", HttpParameterType.JSON));
        List<HttpHeader> headers = List.of(fakeHeader("X-Trace", "trace-1"));
        HttpRequest req = fakeRequest(params, headers, "POST", "/api?id=1");
        printCase("applyReplacements_onlyOneCategory_applied",
            "只改 query（其它分类留空）",
            Map.of("id", "999"), null, null, null, null,
            null,
            "1 个 change，仅 query 分类");

        ReplayService svc = new ReplayService(null, req, FAKE_BUILDER, FAKE_BYTE_ARRAY_FACTORY);
        ReplayService.BuildOutcome out = svc.applyReplacements(
            req, Map.of("id", "999"), null, null, null, null, null);

        assertEquals(1, out.changes().size());
        assertEquals("query", out.changes().get(0).location());
    }

    // ===== 负面：key 找不到整体拒绝 =====

    @Test
    void applyReplacements_queryUnknownKey_fails() {
        HttpRequest req = fakeRequest(
            List.of(fakeParam("id", "1", HttpParameterType.URL)),
            List.of(), "GET", "/?id=1");
        printCase("applyReplacements_queryUnknownKey_fails",
            "【负面】query 用了不存在的 key",
            Map.of("nonexistent", "X"), null, null, null, null,
            null,
            "应抛 IAE；错误信息含 query:nonexistent");
        ReplayService svc = new ReplayService(null, req, FAKE_BUILDER, FAKE_BYTE_ARRAY_FACTORY);
        try {
            svc.applyReplacements(req, Map.of("nonexistent", "X"), null, null, null, null, null);
            assertFalse(true, "应抛 IAE");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("query:nonexistent"));
        }
    }




    /**
     * 部分匹配也整体拒绝：4 类里只要有一类的某个 key 没找到，整体失败（不部分生效）。
     */

    // ===== 边界 =====
    @Test
    void applyReplacements_allMapsNullOrEmpty_noChanges() {
        // 5 个 map 全 null 或全空 → 没有要替换的，原样发，changes 列表为空
        HttpRequest req = fakeRequest(
            List.of(fakeParam("id", "1", HttpParameterType.URL)),
            List.of(), "GET", "/?id=1");
        ReplayService svc = new ReplayService(null, req, FAKE_BUILDER, FAKE_BYTE_ARRAY_FACTORY);
        ReplayService.BuildOutcome out = svc.applyReplacements(req, null, null, null, null, null, null);
        assertTrue(out.changes().isEmpty());

        // 空 Map 也算空
        ReplayService.BuildOutcome out2 = svc.applyReplacements(
            req, Map.of(), Map.of(), Map.of(), Map.of(), Map.of(), null);
        assertTrue(out2.changes().isEmpty());
    }

    @Test
    void applyReplacements_nullRequest_fails() {
        ReplayService svc = new ReplayService(null, null, FAKE_BUILDER, FAKE_BYTE_ARRAY_FACTORY);
        try {
            svc.applyReplacements(null, Map.of("id", "x"), null, null, null, null, null);
            assertFalse(true, "应抛 IAE");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("originalRequest 为 null"));
        }
    }

// ===== wire-level 编码：6 类参数在 wire 上的最终形态（含 console 打印）=====

    /**
     * 捕获所有 builder 调用：记录 name / value / type。
     * 用法：注入 ReplayService 后做断言 + 把 "wire-ready value" 打到 console。
     */
    private static final class CapturingBuilder implements ReplayService.HttpParameterBuilder {
        record Call(String name, String value, HttpParameterType type) {}
        final List<Call> calls = new ArrayList<>();

        @Override
        public HttpParameter build(String name, String value, HttpParameterType type) {
            calls.add(new Call(name, value, type));
            return fakeParam(name, value, type);
        }
    }

    /**
     * 通用打印 + 跑一个小用例。控制台输出包含：
     * <pre>
     *   原始请求行
     *   模型 arguments（明文）
     *   changes（key=old → key=new with location）
     *   builder 收到的 wire-ready value（query/form/json 用）
     *   最终 wire-ready path
     * </pre>
     */
    private static ReplayService.BuildOutcome runEncodingScenario(
            String title,
            HttpRequest originalReq,
            Map<String, String> query,
            Map<String, String> form,
            Map<String, String> header,
            Map<String, String> json,
            Map<String, String> path,
            Map<String, String> multipart,
            CapturingBuilder builder) {
        // 先快照原始请求的 method / url / headers / body 字节——
        // fake 的 bodyRef 是共享的，applyReplacements 改完 out.request().body() 后
        // originalReq.body() 也会变；不打快照就看不到"原始"的字节。
        // url() 优于 path()：request line 要带 query string，path() 只给路径不含 query。
        String origMethod = originalReq.method();
        String origPath = requestTarget(originalReq);
        var origHeaders = new java.util.ArrayList<>(originalReq.headers());
        byte[] origBodyBytes = originalReq.body() != null ? originalReq.body().getBytes() : new byte[0];

        ReplayService svc = new ReplayService(null, originalReq, builder, FAKE_BYTE_ARRAY_FACTORY);
        ReplayService.BuildOutcome out = svc.applyReplacements(
                originalReq, query, form, header, json, path, multipart);

        System.out.println();
        System.out.println("================================================================");
        System.out.println("【场景】 " + title);
        System.out.println("----------------------------------------------------------------");
        System.out.println("【原始请求】");
        printFullRequest(origMethod, origPath, origHeaders, origBodyBytes);
        System.out.println();
        System.out.println("【模型 arguments（明文语义值，未编码）】");
        printModelArgs(query, form, header, json, path, multipart);
        System.out.println();
        System.out.println("【替换详情（changes）】");
        for (var c : out.changes()) {
            System.out.println("  " + c.shortSummary());
        }
        // builder 收到的 wire-ready value（query/form/json 三类用 Montoya builder，path/header/multipart 不走 builder）
        if (!builder.calls.isEmpty()) {
            System.out.println();
            System.out.println("【builder 收到的 wire-ready value（query/form/json 用）】");
            for (var call : builder.calls) {
                System.out.println("  " + call.name() + " (type=" + call.type() + ") = ["
                        + call.value() + "]");
            }
        }
        System.out.println();
        System.out.println("【替换后请求（wire-ready）】");
        printFullRequest(out.request());
        System.out.println();
        System.out.println("================================================================");
        return out;
    }

    /**
     * 打印完整请求：method + path（带 query）+ 主要 headers + body（若有）。
     * body 字节按 UTF-8 解码后做最小化转义（{@code \r → \\r}、{@code \n → \\n}），便于在
     * 控制台观察真实字节而不被换行 / 回车切断。
     */
    private static void printFullRequest(HttpRequest req) {
        if (req == null) {
            System.out.println("  (null)");
            return;
        }
        // 用 url() 不用 path() —— request line 要带 query string，
        // path() 单独走只给路径，query 串被剥掉，控制台就看不到原始参数了。
        // 同时剥掉 scheme://host 前缀（如果 url 是 absolute 形态），保留 path+query 作为 request-target。
        printFullRequest(req.method(), requestTarget(req), req.headers(),
                req.body() != null ? req.body().getBytes() : new byte[0]);
    }

    /**
     * 把 {@code req.url()} 还原成 request-target（{@code /path?query}）：
     * <ul>
     *   <li>绝对 URL（{@code http://host/path?query}）→ {@code /path?query}</li>
     *   <li>相对 URL（{@code /path?query}）→ 原样返回</li>
     * </ul>
     */
    private static String requestTarget(HttpRequest req) {
        String url = req.url();
        if (url == null) {
            return req.path() != null ? req.path() : "";
        }
        int schemeEnd = url.indexOf("://");
        if (schemeEnd < 0) {
            return url;
        }
        int pathStart = url.indexOf('/', schemeEnd + 3);
        return pathStart < 0 ? "" : url.substring(pathStart);
    }

    private static void printFullRequest(String method, String path,
                                          List<HttpHeader> headers, byte[] body) {
        System.out.println("  " + method + " " + path + " HTTP/1.1");
        for (var h : headers) {
            System.out.println("  " + h.name() + ": " + h.value());
        }
        if (body.length > 0) {
            String bodyStr = new String(body, StandardCharsets.UTF_8)
                    .replace("\r", "\\r").replace("\n", "\\n\n  ");
            System.out.println();
            System.out.println("  " + bodyStr);
        }
    }

    private static void printModelArgs(Map<String, String> query, Map<String, String> form,
                                       Map<String, String> header, Map<String, String> json,
                                       Map<String, String> path, Map<String, String> multipart) {
        if (query     != null && !query.isEmpty())     System.out.println("  replace_query_params:     " + query);
        if (form      != null && !form.isEmpty())      System.out.println("  replace_form_params:      " + form);
        if (header    != null && !header.isEmpty())    System.out.println("  replace_header_params:    " + header);
        if (json      != null && !json.isEmpty())      System.out.println("  replace_json_params:      " + json);
        if (path      != null && !path.isEmpty())      System.out.println("  replace_path_params:      " + path);
        if (multipart!= null && !multipart.isEmpty())  System.out.println("  replace_multipart_params: " + multipart);
    }

    // ────────────────────────────────────────────────────────────────────────
    // 1. query（URL 参数）：percent-encode
    // ────────────────────────────────────────────────────────────────────────

    /**
     * 防御性上限：单分类 key 数量超过 {@link ReplayService#MAX_REPLACE_KEYS}（32）时拒绝。
     * 防止模型一次塞一堆 key 把请求撑爆。
     */
    @Test
    void applyReplacements_tooManyKeys_fails() {
        // 4 类加起来超过 32 → 拒绝
        HttpRequest req = fakeRequest(List.of(), List.of(), "GET", "/");
        ReplayService svc = new ReplayService(null, req, FAKE_BUILDER, FAKE_BYTE_ARRAY_FACTORY);
        Map<String, String> big = new LinkedHashMap<>();
        for (int i = 0; i <= ReplayService.MAX_REPLACE_KEYS; i++) {
            big.put("k" + i, "v");
        }
        try {
            svc.applyReplacements(req, big, null, null, null, null, null);
            assertFalse(true, "应抛 IAE");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("键数过多"));
        }
    }

    @Test
    void applyReplacements_newValueBytesTooLarge_fails() {
        // 一个 key 的 value 超过 64K → 拒绝
        HttpRequest req = fakeRequest(List.of(), List.of(), "GET", "/");
        ReplayService svc = new ReplayService(null, req, FAKE_BUILDER, FAKE_BYTE_ARRAY_FACTORY);
        StringBuilder big = new StringBuilder();
        for (int i = 0; i < ReplayService.MAX_NEW_VALUE_BYTES + 1; i++) {
            big.append('a');
        }
        try {
            svc.applyReplacements(req, null, null, null, Map.of("id", big.toString()), null, null);
            assertFalse(true, "应抛 IAE");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("新值总字节数过多"));
        }
    }

    // ===== execute 兜底：原请求 null 时返回 failure =====

    @Test
    void execute_nullOriginalRequest_failsClean() {
        ReplayService svc = new ReplayService(fakeMontoyaApi(null), null);
        ReplayRequest req = ReplayRequest.builder()
            .reason("test")
            .queryParams(Map.of("id", "1'"))
            .build();
        ReplayResult result = svc.execute(req);
        assertFalse(result.isSuccess());
        assertTrue(result.error().contains("参数替换失败") || result.error().contains("请求构造失败"));
        assertEquals(-1, result.statusCode());
    }

    @Test
    void execute_unknownKey_returnsFailure() {
        HttpRequest req = fakeRequest(
            List.of(fakeParam("id", "1", HttpParameterType.URL)),
            List.of(), "GET", "/?id=1");
        ReplayService svc = new ReplayService(fakeMontoyaApi(null), req);
        ReplayRequest call = ReplayRequest.builder()
            .reason("test")
            .queryParams(Map.of("ghost", "X"))
            .build();
        ReplayResult result = svc.execute(call);
        assertFalse(result.isSuccess());
        assertTrue(result.error().contains("未找到可替换参数"));
    }

    @Test
    void execute_allReplacementsEmpty_returnsFailure() {
        // 5 个 map 全空 → hasReplacements() == false → execute 之前就失败
        ReplayService svc = new ReplayService(fakeMontoyaApi(null), null);
        ReplayRequest call = ReplayRequest.builder().reason("noop").build();
        ReplayResult result = svc.execute(call);
        // 因为 ReplayTool.execute 会拦下 hasReplacements==false，service 这层不负责这个判定。
        // 这里直接调 execute：service 会以"参数替换失败"（原请求 null）兜住。
        assertFalse(result.isSuccess());
    }

    // ===== ReplayRequest 数据模型 =====

    @Test
    void replayRequest_hasReplacements_anyCategoryNonEmpty() {
        // 5 个分类都空 → false
        ReplayRequest none = ReplayRequest.builder().build();
        assertFalse(none.hasReplacements());

        // 只 query 非空 → true
        ReplayRequest q = ReplayRequest.builder().queryParams(Map.of("k", "v")).build();
        assertTrue(q.hasReplacements());

        // 只 form 非空 → true
        ReplayRequest f = ReplayRequest.builder().formParams(Map.of("k", "v")).build();
        assertTrue(f.hasReplacements());

        // 只 header 非空 → true
        ReplayRequest h = ReplayRequest.builder().headerParams(Map.of("k", "v")).build();
        assertTrue(h.hasReplacements());

        // 只 json 非空 → true
        ReplayRequest j = ReplayRequest.builder().jsonParams(Map.of("k", "v")).build();
        assertTrue(j.hasReplacements());

        // 只 path 非空 → true
        ReplayRequest p = ReplayRequest.builder().pathParams(Map.of("path", "v")).build();
        assertTrue(p.hasReplacements());
    }

    @Test
    void replayRequest_builtMapsAreImmutable() {
        Map<String, String> q = new LinkedHashMap<>();
        q.put("k", "v");
        ReplayRequest r = ReplayRequest.builder().queryParams(q).build();
        try {
            r.queryParams().put("k2", "v2");
            assertFalse(true, "应抛 UnsupportedOperationException");
        } catch (UnsupportedOperationException expected) {
            // ok
        }
    }

    // ===== multipart/form-data 相关测试 =====
    //
    // 走自解析 body 字节的 path：现有 fakeRequest 不带 body() / withBody()，
    // 这里另起一个 fakeMultipartRequest，行为接近真实 Montoya：
    //   - body() 返回当前字节（可变引用）；
    //   - withBody(newBytes) 返回新 request，body 替换；
    //   - headerValue("Content-Type") / withUpdatedHeader 正常工作。

    /**
     * 构造一个 multipart/form-data body 字节的快捷方法：boundary = "----Test"。
     * 每个 part 默认带 CRLF 行分隔；textPart 的 header 走最小化写法。
     * parts 用 varargs String[]...：每个 part 传一个 String[]（变长版）。
     */
    private static byte[] buildMultipartBody(String boundary, String[]... parts) {
        StringBuilder sb = new StringBuilder();
        for (String[] p : parts) {
            sb.append("--").append(boundary).append("\r\n");
            sb.append("Content-Disposition: form-data; name=\"").append(p[0]).append("\"");
            if (p.length >= 3 && p[2] != null) {
                sb.append("; filename=\"").append(p[2]).append("\"");
            }
            sb.append("\r\n\r\n");
            sb.append(p[1]).append("\r\n");
        }
        sb.append("--").append(boundary).append("--\r\n");
        return sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private static HttpRequest fakeMultipartRequest(byte[] body) {
        return fakeMultipartRequest(body, "POST", "/upload");
    }

    @SuppressWarnings("cast")
    private static HttpRequest fakeMultipartRequest(byte[] body, String method, String url) {
        List<HttpHeader> headers = new ArrayList<>();
        headers.add(fakeHeader("Content-Type", "multipart/form-data; boundary=----Test"));
        headers.add(fakeHeader("Host", "x.com"));
        burp.api.montoya.core.ByteArray[] bodyRef = {fakeByteArray(body)};
        return (HttpRequest) Proxy.newProxyInstance(
            HttpRequest.class.getClassLoader(),
            new Class<?>[]{HttpRequest.class},
            (proxy, m, a) -> {
                switch (m.getName()) {
                    case "method":
                        return method;
                    case "url":
                        return url;
                    case "path":
                        return url.indexOf('?') >= 0
                            ? url.substring(0, url.indexOf('?')) : url;
                    case "headers":
                        return List.copyOf(headers);
                    case "parameters":
                        return List.of(); // multipart part 不进 parameters()
                    case "hasHeader": {
                        String wanted = (String) a[0];
                        for (HttpHeader h : headers) {
                            if (h.name().equalsIgnoreCase(wanted)) return true;
                        }
                        return false;
                    }
                    case "headerValue": {
                        String wanted = (String) a[0];
                        for (HttpHeader h : headers) {
                            if (h.name().equalsIgnoreCase(wanted)) return h.value();
                        }
                        return null;
                    }
                    case "body":
                        return bodyRef[0];
                    case "withBody": {
                        // 接受 ByteArray 或 String 两种入参（生产代码现在用 String 避免触发
                        // MontoyaObjectFactory，单测里两种都得 handle）
                        Object arg = a[0];
                        byte[] newBodyBytes;
                        if (arg instanceof burp.api.montoya.core.ByteArray) {
                            newBodyBytes = ((burp.api.montoya.core.ByteArray) arg).getBytes();
                        } else if (arg instanceof String) {
                            newBodyBytes = ((String) arg).getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        } else {
                            return defaultValue(java.util.List.class);
                        }
                        bodyRef[0] = fakeByteArray(newBodyBytes);
                        return fakeMultipartRequest(newBodyBytes, method, url);
                    }
                    default:
                        return defaultValue(m.getReturnType());
                }
            });
    }

    /**
     * 构造一个简单的 ByteArray 代理：getBytes() 返回传入的 byte[]。
     */
    private static burp.api.montoya.core.ByteArray fakeByteArray(byte[] bytes) {
        return (burp.api.montoya.core.ByteArray) Proxy.newProxyInstance(
            burp.api.montoya.core.ByteArray.class.getClassLoader(),
            new Class<?>[]{burp.api.montoya.core.ByteArray.class},
            (proxy, m, a) -> {
                switch (m.getName()) {
                    case "getBytes":
                        return bytes;
                    case "length":
                        return bytes.length;
                    case "copy":
                        return fakeByteArray(bytes.clone());
                    case "toString":
                        return new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
                    default:
                        return defaultValue(m.getReturnType());
                }
            });
    }

    /**
     * 改 multipart part 的 value。验证 location="multipart"、key / old / new 正确记录、
     * body 字节被替换。
     */
    @Test
    void applyReplacements_replacesMultipartPart_textValue() {
        byte[] body = buildMultipartBody("----Test",
            new String[]{"username", "alice"},
            new String[]{"comment", "hello world"});
        HttpRequest req = fakeMultipartRequest(body);
        printCase("applyReplacements_replacesMultipartPart_textValue",
            "改 multipart 文本 part",
            null, null, null, null, null,
            Map.of("comment", "XSS<script>"),
            "1 个 change，位置 multipart，key=comment，old=hello world → new=XSS<script>");

        ReplayService svc = new ReplayService(null, req, FAKE_BUILDER, FAKE_BYTE_ARRAY_FACTORY);
        ReplayService.BuildOutcome out = svc.applyReplacements(
            req, null, null, null, null, null,
            Map.of("comment", "XSS<script>"));

        assertEquals(1, out.changes().size());
        ReplayRequest.ParamChange change = out.changes().get(0);
        assertEquals("comment", change.key());
        assertEquals("hello world", change.originalValue());
        assertEquals("XSS<script>", change.newValue());
        assertEquals("multipart", change.location());
        String newBodyStr = new String(out.request().body().getBytes(),
            java.nio.charset.StandardCharsets.UTF_8);
        assertTrue(newBodyStr.contains("XSS<script>"), "新 body 应包含新 value；实际：" + newBodyStr);
        assertFalse(newBodyStr.contains("hello world"), "新 body 不应再有旧 value");
    }

    /**
     * 改 multipart 文件 part 的 value（带 filename）。验证文件 part 同样可被替换。
     */
    @Test
    void applyReplacements_replacesMultipartPart_fileValue() {
        byte[] body = buildMultipartBody("----Test",
            new String[]{"file", "GIF89a-old", "shell.gif"});
        HttpRequest req = fakeMultipartRequest(body);
        printCase("applyReplacements_replacesMultipartPart_fileValue",
            "改 multipart 文件 part 的 value",
            null, null, null, null, null,
            Map.of("file", "<?php echo 1;"),
            "1 个 change，位置 multipart，key=file");

        ReplayService svc = new ReplayService(null, req, FAKE_BUILDER, FAKE_BYTE_ARRAY_FACTORY);
        ReplayService.BuildOutcome out = svc.applyReplacements(
            req, null, null, null, null, null,
            Map.of("file", "<?php echo 1;"));

        assertEquals(1, out.changes().size());
        assertEquals("multipart", out.changes().get(0).location());
        assertEquals("file", out.changes().get(0).key());
        String newBodyStr = new String(out.request().body().getBytes(),
            java.nio.charset.StandardCharsets.UTF_8);
        assertTrue(newBodyStr.contains("<?php echo 1;"));
        assertFalse(newBodyStr.contains("GIF89a-old"));
    }

    /**
     * 多 part 时按 part name 精确匹配——只替换目标 part，其余 part 的 value 完整保留。
     */
    @Test
    void applyReplacements_replacesMultipartPart_onlyTargetPartChanges() {
        byte[] body = buildMultipartBody("----Test",
            new String[]{"a", "alpha"},
            new String[]{"b", "bravo"},
            new String[]{"c", "charlie"});
        HttpRequest req = fakeMultipartRequest(body);
        printCase("applyReplacements_replacesMultipartPart_onlyTargetPartChanges",
            "多 part 时只改目标 part",
            null, null, null, null, null,
            Map.of("b", "B-NEW"),
            "1 个 change；a / c 的 value 完整保留");

        ReplayService svc = new ReplayService(null, req, FAKE_BUILDER, FAKE_BYTE_ARRAY_FACTORY);
        ReplayService.BuildOutcome out = svc.applyReplacements(
            req, null, null, null, null, null,
            Map.of("b", "B-NEW"));

        assertEquals(1, out.changes().size());
        String newBodyStr = new String(out.request().body().getBytes(),
            java.nio.charset.StandardCharsets.UTF_8);
        assertTrue(newBodyStr.contains("alpha"), "part a 应保留");
        assertTrue(newBodyStr.contains("charlie"), "part c 应保留");
        assertTrue(newBodyStr.contains("B-NEW"));
        assertFalse(newBodyStr.contains("bravo"));
    }

    /**
     * 模型传的 key 不在 part name 里 → 整体拒绝，错误信息含 multipart:<key>。
     */
    @Test
    void applyReplacements_multipartPart_unknownKey_fails() {
        byte[] body = buildMultipartBody("----Test",
            new String[]{"username", "alice"});
        HttpRequest req = fakeMultipartRequest(body);
        printCase("applyReplacements_multipartPart_unknownKey_fails",
            "【负面】multipart 用了不存在的 part name",
            null, null, null, null, null,
            Map.of("notExist", "x"),
            "应抛 IAE；错误信息含 multipart:notExist");

        ReplayService svc = new ReplayService(null, req, FAKE_BUILDER, FAKE_BYTE_ARRAY_FACTORY);
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
            () -> svc.applyReplacements(req, null, null, null, null, null,
                Map.of("notExist", "x")));
        assertTrue(ex.getMessage().contains("multipart:notExist"),
            "错误信息应含 multipart:notExist；实际：" + ex.getMessage());
    }

    /**
     * 原请求不是 multipart 时提交 replace_multipart_params → 整体拒绝，
     * 错误信息含 multipart:<key> + multipart=[] 桶。
     */
    @Test
    void applyReplacements_multipartPart_notMultipart_fails() {
        List<ParsedHttpParameter> params = List.of(
            fakeParam("username", "alice", HttpParameterType.BODY));
        HttpRequest req = fakeRequest(params, List.of(), "POST", "username=alice");
        printCase("applyReplacements_multipartPart_notMultipart_fails",
            "【负面】非 multipart 请求提交 replace_multipart_params",
            null, null, null, null, null,
            Map.of("file", "x"),
            "应抛 IAE；错误信息含 multipart:file + multipart=[] 桶");

        ReplayService svc = new ReplayService(null, req, FAKE_BUILDER, FAKE_BYTE_ARRAY_FACTORY);
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
            () -> svc.applyReplacements(req, null, null, null, null, null,
                Map.of("file", "x")));
        assertTrue(ex.getMessage().contains("multipart:file"),
            "错误信息应含 multipart:file；实际：" + ex.getMessage());
        assertTrue(ex.getMessage().contains("multipart=[]"),
            "错误信息应附 multipart=[] 桶；实际：" + ex.getMessage());
    }

    /**
     * listAddressableParams 包含 multipart part name。
     */
    @Test
    void listAddressableParams_includesMultipart_names() {
        byte[] body = buildMultipartBody("----Test",
            new String[]{"username", "alice"},
            new String[]{"file", "abc", "x.txt"});
        HttpRequest req = fakeMultipartRequest(body);
        String out = ReplayService.listAddressableParamsStatic(req);
        assertTrue(out.contains("- multipart: username, file"),
            "清单应列出 multipart part name；实际：" + out);
    }

    /**
     * 非 multipart 请求 → 清单不含 multipart 那一行（避免给模型噪音）。
     */
    @Test
    void listAddressableParams_excludesMultipart_forNonMultipart() {
        HttpRequest req = fakeRequest(List.of(), List.of(), "GET", "/");
        String out = ReplayService.listAddressableParamsStatic(req);
        assertFalse(out.contains("- multipart:"),
            "非 multipart 请求不应列 multipart 行；实际：" + out);
    }

    /**
     * 边界用例：boundary 在 Content-Type 里带引号（RFC 2046 允许）；
     * 验证 parser 正确剥引号。
     */
    @Test
    void applyReplacements_multipart_boundaryInQuotes() {
        byte[] body = buildMultipartBody("----Test",
            new String[]{"k", "v"});
        // 把 Content-Type 改成带引号的 boundary
        HttpRequest req = fakeMultipartRequestWithHeader(
            body, "multipart/form-data; boundary=\"----Test\"");
        ReplayService svc = new ReplayService(null, req, FAKE_BUILDER, FAKE_BYTE_ARRAY_FACTORY);
        ReplayService.BuildOutcome out = svc.applyReplacements(
            req, null, null, null, null, null,
            Map.of("k", "V"));
        assertEquals(1, out.changes().size());
        assertEquals("multipart", out.changes().get(0).location());
        String newBody = new String(out.request().body().getBytes(),
            java.nio.charset.StandardCharsets.UTF_8);
        assertTrue(newBody.contains("V"));
        assertFalse(newBody.contains("\nv\n"));
    }

    /**
     * 构造一个 multipart 请求，指定完整的 Content-Type（含自定义 boundary）。
     */
    @SuppressWarnings("cast")
    private static HttpRequest fakeMultipartRequestWithHeader(byte[] body, String contentType) {
        List<HttpHeader> headers = new ArrayList<>();
        headers.add(fakeHeader("Content-Type", contentType));
        headers.add(fakeHeader("Host", "x.com"));
        burp.api.montoya.core.ByteArray[] bodyRef = {fakeByteArray(body)};
        return (HttpRequest) Proxy.newProxyInstance(
            HttpRequest.class.getClassLoader(),
            new Class<?>[]{HttpRequest.class},
            (proxy, m, a) -> {
                switch (m.getName()) {
                    case "method":
                        return "POST";
                    case "url":
                        return "/upload";
                    case "path":
                        return "/upload";
                    case "headers":
                        return List.copyOf(headers);
                    case "parameters":
                        return List.of();
                    case "hasHeader": {
                        String wanted = (String) a[0];
                        for (HttpHeader h : headers) {
                            if (h.name().equalsIgnoreCase(wanted)) return true;
                        }
                        return false;
                    }
                    case "headerValue": {
                        String wanted = (String) a[0];
                        for (HttpHeader h : headers) {
                            if (h.name().equalsIgnoreCase(wanted)) return h.value();
                        }
                        return null;
                    }
                    case "body":
                        return bodyRef[0];
                    case "withBody": {
                        Object arg = a[0];
                        byte[] newBodyBytes;
                        if (arg instanceof burp.api.montoya.core.ByteArray) {
                            newBodyBytes = ((burp.api.montoya.core.ByteArray) arg).getBytes();
                        } else if (arg instanceof String) {
                            newBodyBytes = ((String) arg).getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        } else {
                            return defaultValue(java.util.List.class);
                        }
                        bodyRef[0] = fakeByteArray(newBodyBytes);
                        return fakeMultipartRequestWithHeader(newBodyBytes, contentType);
                    }
                    default:
                        return defaultValue(m.getReturnType());
                }
            });
    }

    // ===== 测试用 fake 构造工具（用 JDK 动态代理） =====

    private static ParsedHttpParameter fakeParam(String name, String value, HttpParameterType type) {
        return (ParsedHttpParameter) Proxy.newProxyInstance(
            ParsedHttpParameter.class.getClassLoader(),
            new Class<?>[]{ParsedHttpParameter.class},
            (proxy, m, a) -> {
                switch (m.getName()) {
                    case "name":
                        return name;
                    case "value":
                        return value;
                    case "type":
                        return type;
                    default:
                        return defaultValue(m.getReturnType());
                }
            });
    }

    private static HttpHeader fakeHeader(String name, String value) {
        return (HttpHeader) Proxy.newProxyInstance(
            HttpHeader.class.getClassLoader(),
            new Class<?>[]{HttpHeader.class},
            (proxy, m, a) -> {
                switch (m.getName()) {
                    case "name":
                        return name;
                    case "value":
                        return value;
                    default:
                        return defaultValue(m.getReturnType());
                }
            });
    }

    /**
     * 构造一个可被 ReplayService.applyReplacements 用的假 HttpRequest。
     * 实现了 parameters()、hasHeader(name)、headerValue(name)、
     * withUpdatedHeader(name, value)、withRemovedParameters(list)、
     * withAddedParameters(list)、path()、withPath(newPath)。
     *
     * <p>path 与 url 的关系：默认情况下 path 是从 url 去掉 query 推导出来的；
     * 带显式 path 的重载用显式值。withPath(newPath) 返回新 request，path 用新值。</p>
     */
    private static HttpRequest fakeRequest(List<ParsedHttpParameter> params,
                                           List<HttpHeader> headers,
                                           String method, String url) {
        // 默认 path 从 url 推导（去掉 query）
        String defaultPath = (url != null && url.indexOf('?') >= 0)
            ? url.substring(0, url.indexOf('?'))
            : url;
        return fakeRequest(params, headers, method, url, defaultPath, null);
    }

    /**
     * 重载：显式指定 path（用于 path-only 测试场景）。
     */
    private static HttpRequest fakeRequest(List<ParsedHttpParameter> params,
                                           List<HttpHeader> headers,
                                           String method, String url, String path) {
        return fakeRequest(params, headers, method, url, path, null);
    }

    /**
     * 重载：显式指定 path + bodyOverride（withBody 派生场景用）。
     * 把 override 透传给新 request，body() 才能正确返回新字节——
     * 否则新 request 的 bodyOverride 是新建的空 array，会回退到 params 动态构造，
     * 把 withBody 设置的字节给吞了。
     */
    private static HttpRequest fakeRequest(List<ParsedHttpParameter> params,
                                           List<HttpHeader> headers,
                                           String method, String url, String path,
                                           burp.api.montoya.core.ByteArray bodyOverride) {
        List<HttpHeader> mutableHeaders = new ArrayList<>(headers);
        // 从 url 解析初始 params（如果 url 含 ? 但调用方没传 params，把 query 解析成 URL params）
        // ——否则 url() 重建 query 时会丢原 URL 里的 ?k=v，applyPath 的 path-only 检查会失真。
        List<ParsedHttpParameter> mutableParams = new ArrayList<>(params);
        if (mutableParams.isEmpty() && url != null && url.indexOf('?') >= 0) {
            String query = url.substring(url.indexOf('?') + 1);
            for (String kv : query.split("&")) {
                int eq = kv.indexOf('=');
                String name = eq < 0 ? kv : kv.substring(0, eq);
                String value = eq < 0 ? "" : kv.substring(eq + 1);
                mutableParams.add(fakeParam(name, value, HttpParameterType.URL));
            }
        }
        String[] mutablePath = {path};
        // body override：applyMultipart 等会通过 withBody() 设置 body 字节，
        // 设了 override 后 body() 优先返回 override（否则按 params 计算）。
        // 这里用 final 数组包一层——lambda 闭包需要 effectively final 才能捕获。
        final burp.api.montoya.core.ByteArray[] bodyOverrideRef = {bodyOverride};

        return (HttpRequest) Proxy.newProxyInstance(
            HttpRequest.class.getClassLoader(),
            new Class<?>[]{HttpRequest.class},
            (InvocationHandler) (proxy, m, a) -> {
                switch (m.getName()) {
                    case "method":
                        return method;
                    case "path":
                        return mutablePath[0];
                    case "url": {
                        // 动态构造 url：path + 当前 URL 类型 params 的 query。
                        // BODY / JSON 类型不进 query（form 进 body、JSON 进 body）；只 URL 类型拼到 ? 后。
                        StringBuilder sb = new StringBuilder();
                        sb.append(mutablePath[0]);
                        boolean first = true;
                        for (var p : mutableParams) {
                            if (p.type() != HttpParameterType.URL) continue;
                            sb.append(first ? '?' : '&');
                            sb.append(p.name()).append('=').append(p.value());
                            first = false;
                        }
                        return sb.toString();
                    }
                    case "body": {
                        // 优先返回 withBody() 设置的 override（multipart 重写 body 用）
                        if (bodyOverrideRef[0] != null) {
                            return bodyOverrideRef[0];
                        }
                        // 否则动态构造 body：BODY 类型 → form-urlencoded；JSON 类型 → JSON object。
                        // value 已经是 wire-ready（percent-encoded / JSON 字面量），直接拼即可。
                        StringBuilder sb = new StringBuilder();
                        boolean firstBody = true, firstJson = true;
                        boolean hasBody = false, hasJson = false;
                        for (var p : mutableParams) {
                            if (p.type() == HttpParameterType.BODY) {
                                if (!firstBody) sb.append('&');
                                sb.append(p.name()).append('=').append(p.value());
                                firstBody = false;
                                hasBody = true;
                            }
                        }
                        for (var p : mutableParams) {
                            if (p.type() == HttpParameterType.JSON) {
                                if (!firstJson) sb.append(',');
                                // value 已经是 "..." JSON 字面量形式（含外层引号 + 转义）
                                sb.append('"').append(p.name()).append('"').append(':').append(p.value());
                                firstJson = false;
                                hasJson = true;
                            }
                        }
                        if (hasJson) {
                            String jsonBody = "{" + sb.toString() + "}";
                            return fakeByteArray(jsonBody.getBytes(StandardCharsets.UTF_8));
                        }
                        if (hasBody) {
                            return fakeByteArray(sb.toString().getBytes(StandardCharsets.UTF_8));
                        }
                        return null;
                    }
                    case "withBody": {
                        // 接受 ByteArray 或 String 两种入参（multipart 重写 body 用）
                        Object arg = a[0];
                        byte[] newBodyBytes;
                        if (arg instanceof burp.api.montoya.core.ByteArray) {
                            newBodyBytes = ((burp.api.montoya.core.ByteArray) arg).getBytes();
                        } else if (arg instanceof String) {
                            newBodyBytes = ((String) arg).getBytes(StandardCharsets.UTF_8);
                        } else {
                            return defaultValue(java.util.List.class);
                        }
                        // body 被 withBody 覆盖后，原由 params 计算出的 body 失效——
                        // 新 request 必须带上 bodyOverride，否则 body() 会回退到 params 动态构造。
                        burp.api.montoya.core.ByteArray newBa = fakeByteArray(newBodyBytes);
                        bodyOverrideRef[0] = newBa;
                        return fakeRequest(mutableParams, mutableHeaders, method, null, mutablePath[0], newBa);
                    }
                    case "headers":
                        return List.copyOf(mutableHeaders);
                    case "parameters":
                        return List.copyOf(mutableParams);
                    case "hasHeader": {
                        String wanted = (String) a[0];
                        for (HttpHeader h : mutableHeaders) {
                            if (h.name().equalsIgnoreCase(wanted)) return true;
                        }
                        return false;
                    }
                    case "headerValue": {
                        String wanted = (String) a[0];
                        for (HttpHeader h : mutableHeaders) {
                            if (h.name().equalsIgnoreCase(wanted)) return h.value();
                        }
                        return null;
                    }
                    case "withUpdatedHeader": {
                        String n = (String) a[0];
                        String v = (String) a[1];
                        List<HttpHeader> newHeaders = new ArrayList<>();
                        for (HttpHeader h : mutableHeaders) {
                            if (h.name().equalsIgnoreCase(n)) {
                                newHeaders.add(fakeHeader(n, v));
                            } else {
                                newHeaders.add(h);
                            }
                        }
                        return fakeRequest(mutableParams, newHeaders, method, null, mutablePath[0]);
                    }
                    case "withRemovedParameters": {
                        @SuppressWarnings("unchecked")
                        List<HttpParameter> toRemove = (List<HttpParameter>) a[0];
                        // 按 (name, type) 过滤：JDK 代理的 equals 是引用相等，
                        // ArrayList.removeAll 用 equals 比对，把"名字+类型相同的"全部剔掉。
                        // 这样把 toRemove 里的每个 (name, type) 都过滤掉，跟真实 Montoya 语义一致。
                        List<ParsedHttpParameter> left = new ArrayList<>();
                        for (var p : mutableParams) {
                            boolean match = false;
                            for (var r : toRemove) {
                                if (p.name().equals(r.name()) && p.type() == r.type()) {
                                    match = true;
                                    break;
                                }
                            }
                            if (!match) left.add(p);
                        }
                        // 关键：传 url=null（而不是原 url）。原 url 里的 ?k=v 在初始 fakeRequest 已经被
                        // 解析进 mutableParams；如果再传原 url，新 fakeRequest 的"params 为空就再解析 url"
                        // 逻辑会把 ?k=v 重新塞回来，导致 withRemovedParameters 之后 q=1 又冒出来。
                        return fakeRequest(left, mutableHeaders, method, null, mutablePath[0]);
                    }
                    case "withAddedParameters": {
                        @SuppressWarnings("unchecked")
                        List<HttpParameter> toAdd = (List<HttpParameter>) a[0];
                        List<ParsedHttpParameter> added = new ArrayList<>();
                        for (HttpParameter p : toAdd) {
                            added.add((ParsedHttpParameter) p);
                        }
                        List<ParsedHttpParameter> combined = new ArrayList<>(mutableParams);
                        combined.addAll(added);
                        // 派生调用，传 url=null 避免初始构造时的 URL 解析被重复触发。
                        return fakeRequest(combined, mutableHeaders, method, null, mutablePath[0]);
                    }
                    case "withPath": {
                        String newPath = (String) a[0];
                        return fakeRequest(mutableParams, mutableHeaders, method, null, newPath);
                    }
                    default:
                        return defaultValue(m.getReturnType());
                }
            });
    }

    /**
     * 构造一个假的 MontoyaApi，http().sendRequest(req) 返回传入的 response（可能为 null）。
     */
    private static MontoyaApi fakeMontoyaApi(HttpRequestResponse response) {
        return (MontoyaApi) Proxy.newProxyInstance(
            MontoyaApi.class.getClassLoader(),
            new Class<?>[]{MontoyaApi.class},
            (proxy, m, a) -> {
                if ("http".equals(m.getName())) {
                    return Proxy.newProxyInstance(
                        burp.api.montoya.http.Http.class.getClassLoader(),
                        new Class<?>[]{burp.api.montoya.http.Http.class},
                        (httpProxy, hm, ha) -> {
                            if ("sendRequest".equals(hm.getName())) {
                                if (response == null) {
                                    throw new RuntimeException("fake sendRequest called without response");
                                }
                                return response;
                            }
                            return defaultValue(hm.getReturnType());
                        });
                }
                return defaultValue(m.getReturnType());
            });
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) return null;
        if (type == boolean.class) return false;
        if (type == int.class) return 0;
        if (type == short.class) return (short) 0;
        if (type == long.class) return 0L;
        if (type == double.class) return 0d;
        if (type == float.class) return 0f;
        return null;
    }
}
