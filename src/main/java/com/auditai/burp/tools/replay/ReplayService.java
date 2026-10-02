package com.auditai.burp.tools.replay;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * "重放请求"工具执行器：把模型提交的"按位置分类的参数替换"应用到<b>原请求</b>上，
 * 再通过 Burp Montoya API 真实发送出去，并把响应回填给模型。
 *
 * <p><b>v3 协议：按位置分类的参数替换</b></p>
 *
 * <p>从 v3 开始，模型不再用单个扁平的 {@code replace_params}，而是按 HTTP 报文中
 * "参数所在的位置"分六个独立字段提交：</p>
 *
 * <ul>
 *   <li>{@code replace_query_params}     →  只匹配 URL 参数（{@code ?k=v}）</li>
 *   <li>{@code replace_form_params}      →  只匹配 form body（{@code application/x-www-form-urlencoded}）</li>
 *   <li>{@code replace_header_params}    →  只匹配请求头（大小写不敏感）</li>
 *   <li>{@code replace_json_params}      →  只匹配 JSON body 字段（支持点号路径 {@code user.id}）</li>
 *   <li>{@code replace_path_params}      →  只匹配 URL 路径的某段当前字面值（path-only 场景）</li>
 *   <li>{@code replace_multipart_params} →  只匹配 {@code multipart/form-data} body 的 part
 *       （key = part 的 {@code Content-Disposition} 里的 name 属性）；请求不是 multipart
 *       → 该分类视为空、提交的 key 全部 notFound → 整体拒绝</li>
 * </ul>
 *
 * <p>每个字段的 key 只在它"应该"出现的位置查找——不再有"header → query → body → json → cookie"
 * 那种隐式优先级。模型把 key 放错位置就直接报错（哪个分类、哪个 key、提示它
 * 正确位置有哪些 key 可用），避免静默命中"看起来名字一样但语义不同"的同名 key。</p>
 *
 * <p>优势：</p>
 * <ul>
 *   <li>不再需要模型在 JSON 字符串里转义 HTTP 报文里的引号 / 反斜杠 / 控制字符；</li>
 *   <li>URL 编码、JSON 编码、Content-Length 重算交给 Burp 自动处理；</li>
 *   <li>无法跨 host/port/scheme 重放——HttpService 始终继承自原请求；</li>
 *   <li>DEBUG 输出"key=old → key=new (location=query|form|header|json|path|multipart)"清晰可读。</li>
 * </ul>
 *
 * <p><b>同位置多值参数</b>（如 {@code ?id=1&id=2}）：全部替换为同一新值；如果只想改
 * 某一个，目前协议不支持——这在安全审计里也是罕见诉求。</p>
 */
public final class ReplayService {

    /**
     * "构造新 HttpParameter"的注入点——生产用 {@link HttpParameter#parameter(String, String, HttpParameterType)}，
     * 测试可注入一个返回代理 {@link HttpParameter} 的实现，避开 Burp 内部工厂（{@code MontoyaObjectFactory}
     * 在脱离 Burp 运行时为 null）。
     */
    @FunctionalInterface
    public interface HttpParameterBuilder {
        HttpParameter build(String name, String value, HttpParameterType type);
    }

    /** 默认 builder：走 Burp 的静态工厂。 */
    public static final HttpParameterBuilder DEFAULT_BUILDER =
            (name, value, type) -> HttpParameter.parameter(name, value, type);

    /**
     * "构造新 ByteArray"的注入点——生产用 {@link ByteArray#byteArray(byte...)}，
     * 测试可注入一个不依赖 MontoyaObjectFactory 的实现（{@code MontoyaObjectFactory.FACTORY}
     * 在脱离 Burp 运行时为 null，调用 {@code ByteArray.byteArray} 会 NPE）。
     */
    @FunctionalInterface
    public interface ByteArrayFactory {
        ByteArray build(byte[] bytes);
    }

    /** 默认 factory：走 Burp 的静态工厂。 */
    public static final ByteArrayFactory DEFAULT_BYTE_ARRAY_FACTORY =
            bytes -> ByteArray.byteArray(bytes);

    private final MontoyaApi api;
    /** 原请求：用于提取 host/port/scheme（不允许模型重放到不同服务）。 */
    private final HttpRequest originalRequest;
    /** "构造新参数"工厂：可注入以支持脱离 Burp 运行时的测试。 */
    private final HttpParameterBuilder parameterBuilder;
    /** "构造新 ByteArray"工厂：同 {@link #parameterBuilder} 的设计目的——multipart 重写 body 用。 */
    private final ByteArrayFactory byteArrayFactory;

    public ReplayService(MontoyaApi api, HttpRequest originalRequest) {
        this(api, originalRequest, DEFAULT_BUILDER, DEFAULT_BYTE_ARRAY_FACTORY);
    }

    public ReplayService(MontoyaApi api, HttpRequest originalRequest,
                         HttpParameterBuilder parameterBuilder) {
        this(api, originalRequest, parameterBuilder, DEFAULT_BYTE_ARRAY_FACTORY);
    }

    /**
     * 完整构造器：注入两个工厂以支持测试。
     * 生产路径用 {@link #ReplayService(MontoyaApi, HttpRequest)} 即可。
     */
    public ReplayService(MontoyaApi api, HttpRequest originalRequest,
                         HttpParameterBuilder parameterBuilder,
                         ByteArrayFactory byteArrayFactory) {
        // api / originalRequest 都允许为 null：null 意味着"测试场景"或"上层不关心原请求"
        // ——子类可以在测试里覆盖 execute() 跳过对 originalRequest 的使用。生产路径
        // （TrafficAnalyzer.analyzeWithTools → ToolLoopOrchestrator）里两者都是非 null。
        this.api = api;
        this.originalRequest = originalRequest;
        this.parameterBuilder = parameterBuilder != null ? parameterBuilder : DEFAULT_BUILDER;
        this.byteArrayFactory = byteArrayFactory != null ? byteArrayFactory : DEFAULT_BYTE_ARRAY_FACTORY;
    }

    /**
     * 执行一次重放：把 {@code req} 指定的 6 类参数替换应用到原请求上，发送出去，并返回结果。
     *
     * <p>本方法是本类对外暴露的<b>唯一</b>执行入口；{@code ToolLoopOrchestrator}
     * 负责在多轮循环中调用本方法并管理预算。</p>
     *
     * @param req 模型提交的"要重放的请求"。
     * @return 执行结果（成功 / 失败 / 异常 三种情况都封装在 {@link ReplayResult} 里）。
     */
    public ReplayResult execute(ReplayRequest req) {
        Objects.requireNonNull(req, "req");
        long start = System.currentTimeMillis();
        BuildOutcome built;
        try {
            built = applyReplacements(originalRequest,
                    req.queryParams(), req.formParams(),
                    req.headerParams(), req.jsonParams(),
                    req.pathParams(), req.multipartParams());
        } catch (IllegalArgumentException e) {
            // 参数替换前的"业务错误"：key 没找到 / 总数超限等，对应"参数替换失败"提示
            return ReplayResult.failure("参数替换失败：" + e.getMessage(),
                    System.currentTimeMillis() - start, List.of());
        } catch (RuntimeException e) {
            // 其他运行时异常：Mongo 工厂 NPE、byte[] 数组分配失败等，对应"请求构造失败"提示
            return ReplayResult.failure("请求构造失败：" + e.getMessage(),
                    System.currentTimeMillis() - start, List.of());
        }
        try {
            if (api == null) {
                // 构造器允许 api 为 null（纯测试路径），但生产路径真拿到 null 时不该抛 NPE——
                // 那会被下面的通用 catch 吞成"重放失败：NullPointerException：null"，
                // 模型拿不到任何可诊断信息。
                return ReplayResult.failure("重放不可用：MontoyaApi 为空",
                        System.currentTimeMillis() - start, built.changes());
            }
            HttpRequestResponse pair = api.http().sendRequest(built.request());
            if (pair == null) {
                // Montoya 约定返回非 null，但防御性判空避免把 NPE 伪装成网络错误。
                return ReplayResult.failure("重放失败：未返回请求/响应对象",
                        System.currentTimeMillis() - start, built.changes());
            }
            HttpResponse resp = pair.response();
            if (resp == null) {
                return ReplayResult.failure("未收到响应（Burp 内部错误或上游关闭）",
                        System.currentTimeMillis() - start, built.changes());
            }
            return ReplayResult.success(resp.statusCode(), System.currentTimeMillis() - start,
                    resp, built.changes());
        } catch (RuntimeException e) {
            // Montoya sendRequest 极少抛错；典型场景：host 不可达 / DNS / timeout。
            // 包装成 ReplayResult.failure 回到 agent 循环，不让单次失败拖垮整个分析。
            return ReplayResult.failure("重放失败：" + e.getClass().getSimpleName()
                    + "：" + e.getMessage(), System.currentTimeMillis() - start, built.changes());
        }
    }

    /**
     * 把 6 类参数替换应用到 {@code original} 上，构造新请求。
     *
     * <p>实现要点：</p>
     * <ul>
     *   <li>每类参数的 key 只在它"应属"的位置查（query → URL 参数；form → BODY 参数；
     *       header → 请求头；json → JSON 参数；path → URL 路径段值；multipart → body part name）；</li>
     *   <li>用 Montoya 的 {@code withParameter(HttpParameter)} / {@code withUpdatedHeader}
     *       原子改值——Burp 负责 URL 编码、JSON 编码、Content-Length 重算；</li>
     *   <li>HttpService 始终继承自 {@code original}，模型无法跨服务重放；</li>
     *   <li>任何一类的 key 在自己位置找不到 → 抛 {@link IllegalArgumentException}，
     *       由 {@link #execute} 转成 {@link ReplayResult#failure}。错误信息会明确告诉
     *       模型"哪个分类、哪个 key、当前请求里这个位置实际有哪些 key 可用"；</li>
     *   <li>所有类的 key 总数受 {@link #MAX_REPLACE_KEYS} 限制；新值字节总数受
     *       {@link #MAX_NEW_VALUE_BYTES} 限制（防 OOM / 防滥用）。</li>
     * </ul>
     *
     * @param original     原请求；为 null 时抛 IAE（execute 已处理）
     * @param queryParams  要替换的 URL 参数；可为空 Map
     * @param formParams   要替换的 form body 参数；可为空 Map
     * @param headerParams 要替换的请求头；可为空 Map
     * @param jsonParams   要替换的 JSON body 字段（key 支持点号路径）；可为空 Map
     * @param pathParams   要替换的 URL 路径段；key = 某段当前的字面值（不限于最后一段），
     *                     该段整体替换为新值；可为空 Map
     * @return 包含新请求和"每个 key 的位置 / 原值 / 新值"的变更列表
     */
    BuildOutcome applyReplacements(HttpRequest original,
                                   Map<String, String> queryParams,
                                   Map<String, String> formParams,
                                   Map<String, String> headerParams,
                                   Map<String, String> jsonParams,
                                   Map<String, String> pathParams,
                                   Map<String, String> multipartParams) {
        if (original == null) {
            throw new IllegalArgumentException("原请求不可用（originalRequest 为 null）");
        }
        int totalKeys = (queryParams == null ? 0 : queryParams.size())
                + (formParams == null ? 0 : formParams.size())
                + (headerParams == null ? 0 : headerParams.size())
                + (jsonParams == null ? 0 : jsonParams.size())
                + (pathParams == null ? 0 : pathParams.size())
                + (multipartParams == null ? 0 : multipartParams.size());
        if (totalKeys == 0) {
            // 没有要替换的：原样发，changes 列表为空
            return new BuildOutcome(original, List.of());
        }
        // 大小保护：6 类参数加起来的 key 总数超过上限 → 拒绝
        if (totalKeys > MAX_REPLACE_KEYS) {
            throw new IllegalArgumentException("替换参数键数过多（"
                    + totalKeys + " > " + MAX_REPLACE_KEYS + "）");
        }
        // 累计字节数保护：所有新值的总字节数（UTF-8）超过上限 → 拒绝
        long newValueBytes = sumBytes(queryParams) + sumBytes(formParams)
                + sumBytes(headerParams) + sumBytes(jsonParams) + sumBytes(pathParams)
                + sumBytes(multipartParams);
        if (newValueBytes > MAX_NEW_VALUE_BYTES) {
            throw new IllegalArgumentException("替换参数新值总字节数过多（"
                    + newValueBytes + " > " + MAX_NEW_VALUE_BYTES + "）");
        }

        HttpRequest current = original;
        List<ReplayRequest.ParamChange> changes = new ArrayList<>(totalKeys);
        List<String> notFound = new ArrayList<>();

        // 1) query 参数
        current = applyAll(current, queryParams, "query", notFound, changes,
                (req, e) -> applyByType(req, e.getKey(), e.getValue(), HttpParameterType.URL, "query"));
        // 2) form body 参数
        current = applyAll(current, formParams, "form", notFound, changes,
                (req, e) -> applyByType(req, e.getKey(), e.getValue(), HttpParameterType.BODY, "form"));
        // 3) 请求头
        current = applyAll(current, headerParams, "header", notFound, changes,
                (req, e) -> applyHeader(req, e.getKey(), e.getValue()));
        // 4) JSON body 字段（key 支持点号路径；类型为 JSON）
        current = applyAll(current, jsonParams, "json", notFound, changes,
                (req, e) -> applyByType(req, e.getKey(), e.getValue(), HttpParameterType.JSON, "json"));
        // 5) URL 路径参数：按段值匹配；同 key 多次匹配会造多条 ParamChange。
        // 不走 applyAll——单 key 可能产出多条 ParamChange，签名不通用。
        for (Map.Entry<String, String> e : safeEntries(pathParams, "replace_path_params")) {
            PathApplyResult r = applyPath(current, e.getKey(), e.getValue());
            if (r == null) { notFound.add("path:" + e.getKey()); continue; }
            current = r.request;
            // 同 key 多段都被替换 → 每段一条 ParamChange（oldValue == key）
            for (int i = 0; i < r.matchedCount; i++) {
                changes.add(new ReplayRequest.ParamChange(e.getKey(), e.getKey(), e.getValue(), "path"));
            }
        }
        // 6) multipart/form-data body 的 part 替换：自解析 body 字节，按 part name 匹配，
        // 整体重建 body 后用 withBody() 一次性替换；走自己的循环（不适用 applyAll 签名，与 path 一样）。
        MultipartApplyResult multiRes = applyMultipart(current, multipartParams);
        if (multiRes == null) {
            // 该请求不是 multipart 或 multipart 解析失败
            for (String k : safeKeys(multipartParams)) {
                notFound.add("multipart:" + k);
            }
        } else {
            current = multiRes.request;
            changes.addAll(multiRes.changes);
        }

        if (!notFound.isEmpty()) {
            // 任何一个 key 没找到都整体拒绝（避免模型以为替换生效了）
            // 错误信息里附上每个分类的"可用 key 清单"——告诉模型应该改哪儿
            String available = describeAvailable(original);
            throw new IllegalArgumentException("未找到可替换参数：" + notFound
                    + "；当前请求各位置的可用 key：" + available);
        }
        return new BuildOutcome(current, List.copyOf(changes));
    }

    /**
     * 把单个 key 的替换应用到 {@code req} 上：仅在指定类型（{@code expectedType}）的参数中查找。
     * 未找到返回 {@code null}。
     */
    private ApplyResult applyByType(HttpRequest req, String key, String newValue,
                                    HttpParameterType expectedType, String locationLabel) {
        List<ParsedHttpParameter> matches = new ArrayList<>();
        for (ParsedHttpParameter p : req.parameters()) {
            if (expectedType == p.type() && key.equals(p.name())) {
                matches.add(p);
            }
        }
        if (matches.isEmpty()) {
            return null;
        }
        // 同位置多值参数：全部替换为同一 newValue
        // 用 withRemovedParameters + withAddedParameters 替换最稳——
        // 某些 Montoya 版本里 withParameter 对同 name+type 的"第二个"可能 add 而不是 replace。
        // HttpParameter.parameter(name, value, type) 要求 value 已经是按 type 编码过的形式：
        //   URL/BODY → percent-encode；JSON → JSON 字符串字面量（带引号 + 转义）。
        // 把原始 newValue 透传会导致 wire 上出现字面空格/单引号/等号，目标接口解析失败。
        List<HttpParameter> toRemove = new ArrayList<>(matches);
        HttpRequest after = req.withRemovedParameters(toRemove);
        List<HttpParameter> toAdd = new ArrayList<>(matches.size());
        for (ParsedHttpParameter m : matches) {
            toAdd.add(parameterBuilder.build(m.name(), encodeForParamType(newValue, m.type()), m.type()));
        }
        after = after.withAddedParameters(toAdd);
        // matches.get(0).value() 返回的是 wire 上的 raw 字节（已被 Montoya 存为编码形式），
        // 给日志 / user 段看时解码成明文，否则 `q=1%27+or+1%3D1+--+` 这种密文根本读不懂。
        String old = matches.size() == 1
                ? decodeParamValue(matches.get(0))
                : matches.size() + " 个值（" + joinValues(matches) + "）";
        return new ApplyResult(after,
                new ReplayRequest.ParamChange(key, old, newValue, locationLabel));
    }

    /**
     * 按 {@link HttpParameterType} 对 newValue 做"wire-ready"编码：
     * <ul>
     *   <li>{@code URL} / {@code BODY}：{@link URLEncoder#encode(String, java.nio.charset.Charset)}
     *       — 处理空格 / 单引号 / `=` / `&` 等保留 / 不安全字符；</li>
     *   <li>{@code JSON}：JSON 字符串字面量（首尾双引号 + 内部 `"` `\` 控制字符转义），
     *       对齐 Montoya 把 JSON param 视为"已 JSON-encoded 字符串"的契约；</li>
     *   <li>其它类型：原样返回（防御兜底）。</li>
     * </ul>
     */
    private static String encodeForParamType(String value, HttpParameterType type) {
        if (value == null) {
            return "";
        }
        return switch (type) {
            // URL / BODY：直接 percent-encode。
            // 提示词约定模型给明文——agent 编码一次即 wire 上规范形式。
            // 二次编码（绕 WAF / 测服务端多次解码）由模型按需在 payload 里手工写
            // %27、%20 等字符，agent 不做归一化、不主动 decode，让 wire 保留模型意图。
            case URL, BODY -> URLEncoder.encode(value, StandardCharsets.UTF_8);
            // JSON：直接包成 JSON 字符串字面量。模型若想让 JSON body 已含转义，
            // 自行按 JSON 语法预转义；agent 不 unwrap。
            case JSON -> jsonStringLiteral(value);
            default -> value;
        };
    }

    /** 把 wire raw 还原成明文，给日志 / user 段读。匹配不到类型时回退到原值。 */
    private static String decodeParamValue(ParsedHttpParameter p) {
        return switch (p.type()) {
            case URL, BODY -> urlDecode(p.value());
            case JSON -> jsonStringUnquote(p.value());
            default -> p.value();
        };
    }

    private static String urlDecode(String s) {
        if (s == null || s.isEmpty()) {
            return s;
        }
        try {
            return java.net.URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (RuntimeException e) {
            return s;
        }
    }

    /**
     * 路径段专用编码：在 {@link URLEncoder#encode(String, java.nio.charset.Charset)} 基础上
     * 把空格从 {@code +} 换成 {@code %20}（路径里 {@code +} 是字面加号，不能当空格）。
     * 其它字符（{@code '} {@code =} 等）按 percent-encode 处理。模型若要二次编码，
     * 自行按 RFC 3986 在 payload 里预写 %XX，agent 不主动 decode。
     */
    private static String encodePathSegment(String value) {
        if (value == null) {
            return "";
        }
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    /**
     * 把任意字符串包装成 JSON 字符串字面量：用 {@code \} 转义 {@code "} {@code \} 控制字符，
     * 其它字符（含中文 / 单引号 / `=` 等 JSON 允许的字面）原样落入。
     */
    private static String jsonStringLiteral(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 2);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
        return sb.toString();
    }

    /**
     * 反向：把 JSON 字符串字面量还原成明文（剥外层引号 + 反转义）。失败时回退到原值。
     */
    private static String jsonStringUnquote(String s) {
        if (s == null || s.length() < 2 || s.charAt(0) != '"' || s.charAt(s.length() - 1) != '"') {
            return s;
        }
        StringBuilder sb = new StringBuilder(s.length() - 2);
        for (int i = 1; i < s.length() - 1; i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length() - 1) {
                char n = s.charAt(++i);
                switch (n) {
                    case '"' -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case 'u' -> {
                        if (i + 4 < s.length() - 1) {
                            try {
                                sb.append((char) Integer.parseInt(s.substring(i + 1, i + 5), 16));
                                i += 4;
                            } catch (NumberFormatException ex) {
                                sb.append(c).append(n);
                            }
                        } else {
                            sb.append(c).append(n);
                        }
                    }
                    default -> sb.append(c).append(n);
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * 替换请求头（大小写不敏感）。未找到（headers 里没这个名）返回 {@code null}。
     */
    private ApplyResult applyHeader(HttpRequest req, String key, String newValue) {
        if (!req.hasHeader(key)) {
            return null;
        }
        String old = req.headerValue(key);
        HttpRequest updated = req.withUpdatedHeader(key, newValue);
        return new ApplyResult(updated,
                new ReplayRequest.ParamChange(key, old, newValue, "header"));
    }

    /**
     * 按"段值"匹配替换 URL 路径。
     *
     * <p>协议说明：路径参数（如 REST 风格 {@code /api/users/123} 的 {@code 123}）不在
     * Burp 的 {@code parameters()} 体系里，需要从 {@link HttpRequest#path()} 字符串里
     * 解析。本类按"段值作为 key"匹配：把路径按 {@code /} 切分后，每个非空段都是候选 key；
     * 模型提交的 {@code key} 必须等于某段当前值，匹配后整段被替换为 {@code newValue}。
     * 同值多段（如 {@code /a/1/b/1}）会全部替换为同一新值，单段路径同样允许。</p>
     *
     * <p>未命中条件（任一即返回 {@code null}）：路径中没有任何段等于 {@code key}（按字面字符串
     * 比较，未做 URL 解码）；URL 含查询参数 {@code ?}（按提示词约定，路径参数场景是 path-only）。</p>
     *
     * <p>本方法只返回"新 path + 匹配次数"，由调用方在 {@link #applyReplacements} 里
     * 按匹配次数造对应数量的 {@link ReplayRequest.ParamChange}——因为同值多段时
     * 一条 entry 要对应多条 change 记录。</p>
     */
    private PathApplyResult applyPath(HttpRequest req, String key, String newValue) {
        // path-only 场景：URL 含 ? 时不算"路径参数"形态
        String url = req.url();
        if (url != null && url.indexOf('?') >= 0) {
            return null;
        }
        String oldPath = req.path();
        if (oldPath == null || oldPath.isEmpty()) {
            return null;
        }
        // 按 / 切分（-1 保留尾部空字符串）→ 跳过空段
        String[] segs = oldPath.split("/", -1);
        int matched = 0;
        StringBuilder newPath = new StringBuilder(oldPath.length() + 8);
        boolean firstSeg = true;
        // path 段值也要走 percent-encode —— 直接拼接会把空格 / 单引号等塞进 wire，
        // 目标 URL 解析器识别不了，整条请求失败。空格用 %20 而不是 +，避免被部分
        // 服务器误读为字面 "+"。
        String encodedNew = encodePathSegment(newValue);
        for (String seg : segs) {
            if (!firstSeg) newPath.append('/');
            firstSeg = false;
            if (!seg.isEmpty() && seg.equals(key)) {
                newPath.append(encodedNew);
                matched++;
            } else {
                newPath.append(seg);
            }
        }
        if (matched == 0) {
            return null;
        }
        HttpRequest updated = req.withPath(newPath.toString());
        return new PathApplyResult(updated, matched);
    }

    /** {@link #applyPath} 的返回：新 request + 匹配次数（用于造 N 条 ParamChange）。 */
    private static final class PathApplyResult {
        final HttpRequest request;
        final int matchedCount;
        PathApplyResult(HttpRequest request, int matchedCount) {
            this.request = request;
            this.matchedCount = matchedCount;
        }
    }

    /**
     * {@link #applyMultipart} 的返回：新 request + 已应用的 ParamChange 列表（同 name 多 part
     * 会出现多条记录，和 {@code applyPath} 的语义对齐）。
     */
    private static final class MultipartApplyResult {
        final HttpRequest request;
        final List<ReplayRequest.ParamChange> changes;
        MultipartApplyResult(HttpRequest request, List<ReplayRequest.ParamChange> changes) {
            this.request = request;
            this.changes = changes;
        }
    }

    /**
     * 替换 {@code multipart/form-data} body 的指定 part 的 value。
     *
     * <p>流程：</p>
     * <ol>
     *   <li>用 {@link MultipartBodyParser#parse} 把 body 切成 part 列表；</li>
     *   <li>对模型提交的每个 key：找同名 part、拼接旧 value 摘要、记录到 ParamChange；
     *       任何一个 key 一个 part 都找不到 → 返回 {@code null}（整体拒绝）；</li>
     *   <li>用 {@link MultipartBodyParser#serialize} 重组 body 字节（保留原 part header / boundary 拼写），</li>
     *   <li>{@code req.withBody(newBytes)} 一次性替换——Montoya 会同步更新 Content-Length。</li>
     * </ol>
     *
     * <p>未命中（请求不是 multipart / body 解析失败 / 找不到 name）→ 返回 {@code null}，由
     * 调用方把所有 key 记到 {@code notFound} 走整体拒绝分支。
     * {@code items == null / empty} 也返回 {@code null}，此时调用方走 {@code safeKeys()}
     * 不会写出任何 notFound，等价于"零侵入"。</p>
     */
    private MultipartApplyResult applyMultipart(HttpRequest req, Map<String, String> items) {
        if (items == null || items.isEmpty()) {
            return null;
        }
        List<MultipartBodyParser.Part> parts = MultipartBodyParser.parse(req);
        if (parts.isEmpty()) {
            return null;
        }
        // 单次遍历：检查存在性 + 拼 old + 生成 ParamChange；同 name 多 part 全部替换（与
        // query/form 同位置多值一致），每 part 一条 ParamChange。
        Map<String, String> replacements = new LinkedHashMap<>();
        List<ReplayRequest.ParamChange> changes = new ArrayList<>();
        for (Map.Entry<String, String> e : items.entrySet()) {
            String name = e.getKey();
            String newValue = e.getValue();
            StringBuilder old = new StringBuilder();
            int matched = 0;
            for (MultipartBodyParser.Part p : parts) {
                if (name.equals(p.name())) {
                    if (matched > 0) old.append(", ");
                    old.append(p.value());
                    matched++;
                }
            }
            if (matched == 0) {
                return null; // 任何一个 key 找不到同名 part → 整体拒绝，由调用方写 notFound
            }
            replacements.put(name, newValue);
            String oldStr = matched == 1 ? old.toString()
                    : matched + " 个值（" + old + "）";
            for (int i = 0; i < matched; i++) {
                changes.add(new ReplayRequest.ParamChange(name, oldStr, newValue, "multipart"));
            }
        }
        String boundary = MultipartBodyParser.extractBoundary(req.headerValue("Content-Type"));
        byte[] body = req.body() == null ? new byte[0] : req.body().getBytes();
        byte[] newBody = MultipartBodyParser.serialize(body, boundary, parts, replacements);
        // 走注入的 ByteArrayFactory 而不是直接 ByteArray.byteArray(...)：
        // 后者在脱离 Burp 运行时（单元测试）会因为 MontoyaObjectFactory.FACTORY=null 而 NPE。
        HttpRequest updated = req.withBody(byteArrayFactory.build(newBody));
        return new MultipartApplyResult(updated, changes);
    }

    /** 安全拿一个 map 的 key 集合（null 视为空）；给 multipart "全部 key 都不在" 时批量造 notFound。 */
    private static Iterable<String> safeKeys(Map<String, String> m) {
        if (m == null || m.isEmpty()) {
            return List.of();
        }
        return m.keySet();
    }

    /**
     * 构造一个"哪个位置有哪些 key 可用"的小摘要——错误信息里塞这个帮模型定位问题。
     */
    private String describeAvailable(HttpRequest req) {
        Map<HttpParameterType, Set<String>> byType = new LinkedHashMap<>();
        byType.put(HttpParameterType.URL, new LinkedHashSet<>());
        byType.put(HttpParameterType.BODY, new LinkedHashSet<>());
        byType.put(HttpParameterType.JSON, new LinkedHashSet<>());
        for (ParsedHttpParameter p : req.parameters()) {
            Set<String> bucket = byType.get(p.type());
            if (bucket != null) bucket.add(p.name());
        }
        Set<String> headers = new LinkedHashSet<>();
        for (var h : req.headers()) headers.add(h.name());
        Set<String> pathSegs = listPathSegments(req);
        Set<String> multipartNames = new LinkedHashSet<>(MultipartBodyParser.listNames(req));
        StringBuilder sb = new StringBuilder("{");
        appendBucket(sb, "query", byType.get(HttpParameterType.URL));
        sb.append(", ");
        appendBucket(sb, "form", byType.get(HttpParameterType.BODY));
        sb.append(", ");
        appendBucket(sb, "header", headers);
        sb.append(", ");
        appendBucket(sb, "json", byType.get(HttpParameterType.JSON));
        sb.append(", ");
        appendBucket(sb, "path", pathSegs);
        sb.append(", ");
        appendBucket(sb, "multipart", multipartNames);
        sb.append("}");
        return sb.toString();
    }

    private static void appendBucket(StringBuilder sb, String label, Set<String> names) {
        sb.append(label).append("=[");
        if (names != null && !names.isEmpty()) {
            boolean first = true;
            for (String n : names) {
                if (!first) sb.append(", ");
                sb.append(n);
                first = false;
            }
        }
        sb.append("]");
    }

    private static long sumBytes(Map<String, String> m) {
        if (m == null) return 0;
        long total = 0;
        for (String v : m.values()) {
            total += v == null ? 0 : v.getBytes(StandardCharsets.UTF_8).length;
        }
        return total;
    }

    /**
     * 安全地遍历一个 map：null 视为空；非空时返回其 entrySet 视图。
     */
    private static Iterable<Map.Entry<String, String>> safeEntries(Map<String, String> m, String label) {
        return m == null ? List.of() : m.entrySet();
    }

    private static String joinValues(List<ParsedHttpParameter> ps) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < ps.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(abbreviate(ps.get(i).value(), 30));
        }
        return sb.toString();
    }

    private static String abbreviate(String s, int max) {
        if (s == null) return "<null>";
        if (s.length() <= max) return s;
        return s.substring(0, max) + "...";
    }

    /**
     * 4 类参数替换（query / form / header / json）的共用骨架：遍历 {@code items}，用 {@code fn}
     * 把每个 entry 应用到 {@code current} 上，命中后推进 {@code current} 并追加
     * {@link ReplayRequest.ParamChange}；未命中则记到 {@code notFound}。返回推进后的 request。
     *
     * <p>仅适合"单 entry 单 ParamChange"的场景——{@code path} 类同 key 多次匹配会产出
     * 多条 ParamChange，{@code multipart} 同 name 多 part 时也是多条，签名不通用，
     * 都走自己循环。</p>
     */
    private static HttpRequest applyAll(HttpRequest current,
                                        Map<String, String> items,
                                        String location,
                                        List<String> notFound,
                                        List<ReplayRequest.ParamChange> changes,
                                        java.util.function.BiFunction<HttpRequest,
                                                Map.Entry<String, String>, ApplyResult> fn) {
        for (Map.Entry<String, String> e : safeEntries(items, location)) {
            ApplyResult r = fn.apply(current, e);
            if (r == null) {
                notFound.add(location + ":" + e.getKey());
                continue;
            }
            current = r.request;
            changes.add(r.change);
        }
        return current;
    }

    /**
     * 列出原请求里"模型可替换"的所有参数，按类别分组（写到阶段 2 user 段末尾的【可替换参数】清单）。
     *
     * <p>输出示例：</p>
     * <pre>
     * 【可替换参数】
     * - query: id, page
     * - form:  username, password
     * - json:  data.id, data.type
     * - header: User-Agent, X-Token
     * - multipart: file, comment
     * </pre>
     *
     * <p>注意：v3 协议不再支持 cookie 字段——改 cookie 用
     * {@code replace_header_params: {"Cookie": "session=xxx"}}。</p>
     *
     * <p>静态实现：不依赖 {@code api} / {@code originalRequest} 实例字段，供
     * {@code ToolLoopOrchestrator} 在"还没构造 {@code ReplayService} 实例"时也能调用。</p>
     *
     * @param original 原请求；null 或无参数时返回空串
     * @return 多行字符串，每行一个类别；空请求时返回空串
     */
    public static String listAddressableParamsStatic(HttpRequest original) {
        if (original == null) {
            return "";
        }
        // 按 type 分组收集 name
        Map<HttpParameterType, Set<String>> byType = new LinkedHashMap<>();
        byType.put(HttpParameterType.URL, new LinkedHashSet<>());
        byType.put(HttpParameterType.BODY, new LinkedHashSet<>());
        byType.put(HttpParameterType.JSON, new LinkedHashSet<>());
        for (ParsedHttpParameter p : original.parameters()) {
            Set<String> bucket = byType.get(p.type());
            if (bucket != null) {
                bucket.add(p.name());
            }
        }
        // header（大小写不敏感去重，但展示保留首次出现的形式）
        Set<String> headerNames = new LinkedHashSet<>();
        for (var h : original.headers()) {
            headerNames.add(h.name());
        }
        // path：列出所有非空段值（与 applyPath 规则保持一致：path-only + 段值作 key）
        // 这里用 LinkedHashSet 保留首次出现顺序（让模型看到段值的自然顺序）
        Set<String> pathSegmentValues = listPathSegments(original);
        // multipart：自解析 body 字节抽 part name；非 multipart 请求返回空集合——该行不显示
        Set<String> multipartNames = new LinkedHashSet<>(MultipartBodyParser.listNames(original));

        boolean queryEmpty = byType.get(HttpParameterType.URL).isEmpty();
        boolean formEmpty  = byType.get(HttpParameterType.BODY).isEmpty();
        boolean jsonEmpty  = byType.get(HttpParameterType.JSON).isEmpty();
        boolean headerEmpty = headerNames.isEmpty();
        boolean pathEmpty = pathSegmentValues.isEmpty();
        boolean multipartEmpty = multipartNames.isEmpty();

        StringBuilder sb = new StringBuilder(256);
        sb.append("【可替换参数】\n");
        appendParamSection(sb, "query", byType.get(HttpParameterType.URL));
        appendParamSection(sb, "form", byType.get(HttpParameterType.BODY));
        appendParamSection(sb, "json", byType.get(HttpParameterType.JSON));
        appendParamSection(sb, "path", pathSegmentValues);
        appendParamSection(sb, "header", headerNames);
        appendParamSection(sb, "multipart", multipartNames);

        // 6 类全部为空时，原先只输出标题，下面没有可选项——模型很容易当成"没看到"
        // 直接套用技能 prompt 里的 `{"id":"1'"}` 模板导致浪费预算。
        // 这里给一个明确提示：禁止调 replay_request，直接给最终结论。
        if (queryEmpty && formEmpty && jsonEmpty && headerEmpty && pathEmpty && multipartEmpty) {
            sb.append("（无——当前请求无可替换参数（query/form/json/path/header/multipart 都为空），")
              .append("禁止调 replay_request，请直接给最终结论 tool_calls=[]）\n");
        }
        return sb.toString();
    }

    /**
     * 提取原请求 URL 路径的"所有非空段值"——按 path 出现顺序保留首次出现（去重）。
     * 若 URL 含 {@code ?} 或路径为空，返回空 Set。
     * 与 {@link #applyPath} 的识别规则保持一致。
     */
    private static Set<String> listPathSegments(HttpRequest original) {
        Set<String> out = new LinkedHashSet<>();
        if (original == null) {
            return out;
        }
        String url = original.url();
        if (url != null && url.indexOf('?') >= 0) {
            return out;
        }
        String oldPath = original.path();
        if (oldPath == null || oldPath.isEmpty()) {
            return out;
        }
        for (String seg : oldPath.split("/", -1)) {
            if (!seg.isEmpty()) {
                out.add(seg);
            }
        }
        return out;
    }

    private static void appendParamSection(StringBuilder sb, String label, Set<String> names) {
        if (names == null || names.isEmpty()) {
            return;
        }
        sb.append("- ").append(label).append(": ");
        boolean first = true;
        for (String n : names) {
            if (!first) sb.append(", ");
            sb.append(n);
            first = false;
        }
        sb.append('\n');
    }

    /** 防御性上限：6 类参数加起来的 key 总数。 */
    public static final int MAX_REPLACE_KEYS = 32;

    /** 防御性上限：所有新值的 UTF-8 字节总数。 */
    public static final int MAX_NEW_VALUE_BYTES = 64 * 1024;

    // —— 内部小数据结构 ——

    /** {@link #applyReplacements} 的返回：构造好的请求 + 变更记录列表。 */
    static final class BuildOutcome {
        private final HttpRequest request;
        private final List<ReplayRequest.ParamChange> changes;

        BuildOutcome(HttpRequest request, List<ReplayRequest.ParamChange> changes) {
            this.request = request;
            this.changes = changes;
        }

        HttpRequest request() {
            return request;
        }

        List<ReplayRequest.ParamChange> changes() {
            return changes;
        }
    }

    /** {@link #applyByType} / {@link #applyHeader} 的返回：新请求 + 单条变更记录。 */
    private static final class ApplyResult {
        final HttpRequest request;
        final ReplayRequest.ParamChange change;

        ApplyResult(HttpRequest request, ReplayRequest.ParamChange change) {
            this.request = request;
            this.change = change;
        }
    }
}
