package com.auditai.burp.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.util.Optional;

/**
 * 公共工具：从 Burp Proxy 历史中按"方法 + URL"匹配反查与给定请求对应的响应。
 *
 * <p>用途：Burp 各模块（Repeater / Intruder / Request 编辑器等）右键时，
 * {@code ContextMenuEvent.selectedRequestResponses()} 返回的
 * {@code HttpRequestResponse} 可能只有请求没有响应——用本工具从
 * {@code api.proxy().history()} 按 URL + Method 反查补回响应。</p>
 *
 * <p><b>关于接口不统一：</b>Montoya 2026.7 中
 * {@code burp.api.montoya.http.message.HttpRequestResponse} 与
 * {@code burp.api.montoya.proxy.ProxyHttpRequestResponse} 是两个<b>平行接口</b>（不互相继承），
 * 但都暴露同名 {@code request()} / {@code response()} 方法。这里用
 * {@code instanceof} 分别走静态调用，避开反射。</p>
 */
public final class HttpResponseLookup {

    /**
     * 反查时最多扫描的历史条数上限：{@code api.proxy().history()} 通常最新在前，
     * 命中近端即可，避免超大历史项目（数万条）每次右键都全量遍历。
     */
    private static final int MAX_HISTORY_SCAN = 5000;

    private HttpResponseLookup() {
    }

    /**
     * 从 Burp Proxy 历史反查与给定请求匹配的非空响应。
     *
     * <p>匹配规则：HTTP 方法 + URL 字符串严格相等（同 URL 不同方法不算命中，
     * 避免误把 GET 命中的响应套到 POST 上）。</p>
     *
     * <p>遍历顺序：按 {@code api.proxy().history()} 的自然顺序（通常最新在前），取第一条含响应的命中。
     * 性能上：O(n) 遍历，仅在右键事件触发时执行一次，可接受。</p>
     *
     * @param api     Burp API 门面；为 null 时直接返回 empty（允许单元测试不依赖 Montoya）。
     * @param request 原始请求，仅用其 method / url 作为匹配键。
     * @return 命中的响应；若 api 不可用或未命中，返回 empty。空 body 响应（如 HEAD/304）也会被原样返回给调用方。
     */
    public static Optional<HttpResponse> lookupResponse(MontoyaApi api, HttpRequest request) {
        if (api == null || request == null) {
            return Optional.empty();
        }
        try {
            String targetMethod = request.method();
            String targetUrl = request.url();
            int scanned = 0;
            for (Object history : api.proxy().history()) {
                if (scanned >= MAX_HISTORY_SCAN) {
                    break; // 只扫描近端记录，避免超大历史全量遍历
                }
                scanned++;
                if (history == null) {
                    continue;
                }
                HttpRequest histReq = extractRequest(history);
                if (histReq == null) {
                    continue;
                }
                if (!targetMethod.equals(histReq.method())) {
                    continue;
                }
                if (!targetUrl.equals(histReq.url())) {
                    continue;
                }
                HttpResponse histResp = extractResponse(history);
                if (histResp == null) {
                    continue;
                }
                // extractResponse 的两个 instanceof 分支按合同都应返回非空响应；
                // 命中即返回（Optional.of 在此处不会遇到 null，若将来 Montoya 新增历史项类型
                // 导致 extractResponse 返回 null，会在上面的 != null 判断处提前 continue）。
                return Optional.of(histResp);
            }
        } catch (RuntimeException e) {
            // api.proxy().history() 在极少数边界情况抛错：吞掉返回 empty，
            // 调用方按"反查无结果"处理。
        }
        return Optional.empty();
    }

    /**
     * 取历史项的请求：两个平行接口二选一，都返回 {@link HttpRequest}，但静态类型不同，
     * 只能分别 instanceof 后调用。任一分支失败返回 null。
     */
    private static HttpRequest extractRequest(Object history) {
        if (history instanceof HttpRequestResponse pair) {
            return pair.request();
        }
        if (history instanceof ProxyHttpRequestResponse pair) {
            return pair.request();
        }
        return null;
    }

    /** 取历史项的响应：参见 {@link #extractRequest}。 */
    private static HttpResponse extractResponse(Object history) {
        if (history instanceof HttpRequestResponse pair) {
            return pair.response();
        }
        if (history instanceof ProxyHttpRequestResponse pair) {
            return pair.response();
        }
        return null;
    }
}
