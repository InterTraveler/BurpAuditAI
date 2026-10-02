package com.auditai.burp.tools.replay;

import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * 单次重放工具调用的执行结果（不可变）。
 *
 * <p>三条来源：</p>
 * <ul>
 *   <li><b>成功</b>：构造时传入 {@link HttpResponse} 与耗时，{@link #error} 为 {@code null}；</li>
 *   <li><b>失败（重放成功但参数替换失败等构造期错误）</b>：{@code response} 为 {@code null}，
 *       {@link #error} 非空，{@link #changes} 反映"在出错之前已应用了哪些 key"；</li>
 *   <li><b>失败（运行时 IO / 解析错误）</b>：同失败分支，{@code changes} 反映已应用的
 *       key 列表。</li>
 * </ul>
 *
 * <p>{@link #changes} 让上层（{@code ReplayTool}）能拼出"key=old → key=new (location=...)"
 * 的可读 diff，写到 DEBUG 日志 / user 段末尾——不需要再访问 {@code HttpRequest}。</p>
 */
public final class ReplayResult {

    private final int statusCode;
    private final long elapsedMillis;
    private final HttpResponse response;
    private final String error;
    private final List<ReplayRequest.ParamChange> changes;

    private ReplayResult(int statusCode, long elapsedMillis, HttpResponse response, String error,
                         List<ReplayRequest.ParamChange> changes) {
        this.statusCode = statusCode;
        this.elapsedMillis = elapsedMillis;
        this.response = response;
        this.error = error;
        this.changes = changes != null ? List.copyOf(changes) : List.of();
    }

    public static ReplayResult success(int statusCode, long elapsedMillis, HttpResponse response,
                                       List<ReplayRequest.ParamChange> changes) {
        Objects.requireNonNull(response, "response");
        return new ReplayResult(statusCode, elapsedMillis, response, null, changes);
    }

    public static ReplayResult failure(String error, long elapsedMillis,
                                       List<ReplayRequest.ParamChange> changes) {
        return new ReplayResult(-1, elapsedMillis, null, error, changes);
    }

    public int statusCode() {
        return statusCode;
    }

    public long elapsedMillis() {
        return elapsedMillis;
    }

    /** 原始响应；失败时为 {@code null}。 */
    public HttpResponse response() {
        return response;
    }

    /** 错误描述；成功时为 {@code null}。 */
    public String error() {
        return error;
    }

    /**
     * 本次重放实际应用的参数替换记录（"key=old → key=new (location=...)"）。
     * 失败时也可能非空——记录"在失败前已经替换成功的那部分 key"。
     */
    public List<ReplayRequest.ParamChange> changes() {
        return changes;
    }

    /**
     * 失败时也可能非空：{@code changes} 列表不可变。
     */
    public List<ReplayRequest.ParamChange> changesOrEmpty() {
        return changes == null ? Collections.emptyList() : changes;
    }

    public boolean isSuccess() {
        return error == null;
    }
}
