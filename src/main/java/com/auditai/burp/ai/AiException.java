package com.auditai.burp.ai;

import java.io.Serial;

/**
 * AI 调用相关的异常。
 *
 * <p>继承 {@link RuntimeException}（非受检）的理由：AI 调用发生在异步分析线程中，
 * 顶层会统一捕获并转成“分析失败”结果展示给用户；使用非受检异常可避免
 * 在接口签名和调用链上到处写 try/catch 或 throws，让业务代码更简洁。</p>
 */
public final class AiException extends RuntimeException {

    /** 序列化版本号：异常沿 Throwable 序列化链传递，显式声明避免 [serial] 告警。 */
    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * "分析已取消"统一文案：抛异常路径统一走 {@link #cancelled()} / {@link #cancelled(Throwable)}，
     * 判定路径统一走 {@link #isCancelled()} / {@link #isCancelledMessage(String)}——避免
     * 业务层散落"new AiException(CANCELLED_MESSAGE, ...)"和"result.getError().equals(CANCELLED_MESSAGE)"。
     */
    public static final String CANCELLED_MESSAGE = "分析已取消";

    /** 仅带信息的构造：适用于网络失败、鉴权失败、协议错误等场景。 */
    public AiException(String message) {
        super(message);
    }

    /** 带原因链的构造：便于日志输出堆栈定位根因。 */
    public AiException(String message, Throwable cause) {
        super(message, cause);
    }

    /** 构造一个"用户取消分析"异常（无原因链）。 */
    public static AiException cancelled() {
        return new AiException(CANCELLED_MESSAGE);
    }

    /** 构造一个"用户取消分析"异常（带原因链，用于把底层 {@link java.util.concurrent.CancellationException} 串起来）。 */
    public static AiException cancelled(Throwable cause) {
        return new AiException(CANCELLED_MESSAGE, cause);
    }

    /**
     * 当前异常是否由"用户取消分析"触发。
     *
     * <p>调用方应优先用本方法而非 {@code getMessage().contains("已取消")}
     * 之类的字面比较——文案将来若被 i18n 化或调整措辞，调用方不用跟着改。</p>
     */
    public boolean isCancelled() {
        return CANCELLED_MESSAGE.equals(getMessage());
    }

    /**
     * 把任意 message 文本判定为"取消"。{@code AnalysisResult.getError()} 是字符串而非 Throwable，
     * 用此静态方法把判定口径和 {@link #isCancelled()} 保持完全一致。
     */
    public static boolean isCancelledMessage(String message) {
        return CANCELLED_MESSAGE.equals(message);
    }
}
