package com.auditai.burp.passive;

import com.auditai.burp.ai.AiException;

import java.io.IOException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpTimeoutException;

/**
 * 把 {@link AiException}（及底层网络异常）按用户可读的"下一步该检查什么"分类到
 * {@link PassiveAnalysisErrorBus.ErrorKind}。
 *
 * <p>分类规则（非穷尽，按实际抛出的异常类型映射）：</p>
 * <ul>
 *   <li><b>CONFIG</b>：消息文本中含"尚未配置"、"baseUrl"、"AI 服务"等关键字；
 *       这些是用户输入导致的失败，修复路径是去"设置"页改正；</li>
 *   <li><b>NETWORK</b>：底层是 {@link SocketTimeoutException} /
 *       {@link HttpConnectTimeoutException} / {@link HttpTimeoutException} /
 *       {@link ConnectException} / {@link UnknownHostException} /
 *       {@link NoRouteToHostException} 等连接阶段异常；修复路径是检查网络
 *       / 远端服务是否可达；</li>
 *   <li><b>REMOTE</b>：远端响应了，但状态码异常或响应体结构异常；
 *       修复路径是检查 API Key、模型名、配额、版本兼容性等。</li>
 * </ul>
 *
 * <p>本类为纯函数式：所有方法都是 {@code static}，无状态，便于在分析线程安全调用。
 * </p>
 */
public final class PassiveAnalysisErrorClassifier {

    private PassiveAnalysisErrorClassifier() {
    }

    /**
     * 根据异常对象分类。
     *
     * @param ex 异常（不可为 null）。
     * @return 错误分类。
     */
    static PassiveAnalysisErrorBus.ErrorKind classify(Throwable ex) {
        // 先沿 cause 链往下走一层：AI 调用通常包了一层 AiException，真实根因在 cause 里。
        Throwable current = ex;
        for (int i = 0; i < 4 && current != null; i++) {
            if (current instanceof SocketTimeoutException
                    || current instanceof HttpConnectTimeoutException
                    || current instanceof HttpTimeoutException
                    || current instanceof ConnectException
                    || current instanceof UnknownHostException
                    || current instanceof NoRouteToHostException) {
                return PassiveAnalysisErrorBus.ErrorKind.NETWORK;
            }
            // 1xx/3xx/4xx/5xx 状态码（AiException 抛出时已带"HTTP 4xx/5xx"字样）
            // 走 REMOTE；其他 IOException 走 NETWORK。
            if (current instanceof IOException) {
                return PassiveAnalysisErrorBus.ErrorKind.NETWORK;
            }
            current = current.getCause();
        }
        // 走到这里说明 cause 链里没找到网络/IO 异常：按消息文本关键字分类。
        return classifyByMessage(ex.getMessage());
    }

    /**
     * 仅按消息文本分类：用于非网络异常（如 AiException("尚未配置...")）。
     *
     * <p>注意：本方法是纯文本匹配,判定关键字必须与"抛错方实际写入 message 的原文"
     * 一致,<b>不能引用 UI 文案(如 I18n 翻译),也不能随界面语言变化</b>——否则同样的
     * 错误在切换语言后会归到不同类别,分类结果不可复现。若将来要本地化 AiException
     * 消息本身,应在抛错处携带错误类别/错误码,由这里按类别判定,而不是按翻译文本猜。</p>
     */
    public static PassiveAnalysisErrorBus.ErrorKind classifyByMessage(String message) {
        if (message == null) {
            return PassiveAnalysisErrorBus.ErrorKind.REMOTE;
        }
        String lower = message.toLowerCase(java.util.Locale.ROOT);
        // CONFIG：用户配置问题（关键字不区分大小写）。
        // 关键字来自本工程 AiException 的固定中文/中英混合原文（baseUrl/API Key 为协议字段名，
        // 不随语言变化；"尚未配置"/"AI 服务"为抛错方写死的中文字面量）。
        if (message.contains("尚未配置") || message.contains("baseUrl")
                || message.contains("AI 服务") || message.contains("API Key")) {
            return PassiveAnalysisErrorBus.ErrorKind.CONFIG;
        }
        // NETWORK：连接阶段异常文本特征
        // 注意："timed out"（Java 网络异常常见表述）也算超时；"read timed out" / "connect timed out" 都属此类。
        if (lower.contains("timeout") || lower.contains("timed out")
                || lower.contains("connection") || lower.contains("connect")
                || lower.contains("refused") || lower.contains("unreachable")
                || lower.contains("unknown host") || lower.contains("超时")
                || lower.contains("连接")) {
            return PassiveAnalysisErrorBus.ErrorKind.NETWORK;
        }
        // REMOTE：HTTP 状态码异常（4xx/5xx）/ 响应体结构异常等
        return PassiveAnalysisErrorBus.ErrorKind.REMOTE;
    }

    /**
     * 便捷方法：分类 + 提取用户可读消息。
     *
     * <p>优先用根因（cause）的消息，因为它通常更具体（"Connection refused: connect"）；
     * 根因为 null 时退化用外层消息（"AI 接口返回 HTTP 401: ..."）。</p>
     */
    static PassiveAnalysisErrorBus.ErrorKind classify(AiException ex) {
        if (ex == null) {
            return PassiveAnalysisErrorBus.ErrorKind.REMOTE;
        }
        Throwable cause = ex.getCause();
        if (cause != null) {
            return classify(cause);
        }
        return classifyByMessage(ex.getMessage());
    }
}
