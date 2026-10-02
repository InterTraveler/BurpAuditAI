package com.auditai.burp.passive;

import com.auditai.burp.ai.AiException;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * {@link PassiveAnalysisErrorClassifier} 单元测试：网络异常 / 配置错误 / 远端错误
 * 三种分类的判定。
 */
final class PassiveAnalysisErrorClassifierTest {

    @Test
    void configKeywordsClassifyAsConfig() {
        assertEquals(PassiveAnalysisErrorBus.ErrorKind.CONFIG,
                PassiveAnalysisErrorClassifier.classifyByMessage("尚未配置 AI 服务地址（baseUrl）"));
        assertEquals(PassiveAnalysisErrorBus.ErrorKind.CONFIG,
                PassiveAnalysisErrorClassifier.classifyByMessage("尚未配置任何 AI 服务：请到『设置』页"));
        assertEquals(PassiveAnalysisErrorBus.ErrorKind.CONFIG,
                PassiveAnalysisErrorClassifier.classifyByMessage("API Key 配置无效"));
    }

    @Test
    void networkKeywordsClassifyAsNetwork() {
        assertEquals(PassiveAnalysisErrorBus.ErrorKind.NETWORK,
                PassiveAnalysisErrorClassifier.classifyByMessage("Connection refused: connect"));
        assertEquals(PassiveAnalysisErrorBus.ErrorKind.NETWORK,
                PassiveAnalysisErrorClassifier.classifyByMessage("Read timed out"));
        assertEquals(PassiveAnalysisErrorBus.ErrorKind.NETWORK,
                PassiveAnalysisErrorClassifier.classifyByMessage("连接超时"));
        assertEquals(PassiveAnalysisErrorBus.ErrorKind.NETWORK,
                PassiveAnalysisErrorClassifier.classifyByMessage("Unknown host: example.invalid"));
        assertEquals(PassiveAnalysisErrorBus.ErrorKind.NETWORK,
                PassiveAnalysisErrorClassifier.classifyByMessage("Connection reset by peer"));
    }

    @Test
    void remoteHttpErrorClassifiesAsRemote() {
        assertEquals(PassiveAnalysisErrorBus.ErrorKind.REMOTE,
                PassiveAnalysisErrorClassifier.classifyByMessage("AI 接口返回 HTTP 401: Unauthorized"));
        assertEquals(PassiveAnalysisErrorBus.ErrorKind.REMOTE,
                PassiveAnalysisErrorClassifier.classifyByMessage("AI 接口返回 HTTP 500: Internal Server Error"));
        assertEquals(PassiveAnalysisErrorBus.ErrorKind.REMOTE,
                PassiveAnalysisErrorClassifier.classifyByMessage("AI 接口不支持 json_object 输出模式"));
    }

    @Test
    void classifyByCauseChainForNetworkExceptions() {
        // IOException → NETWORK
        assertEquals(PassiveAnalysisErrorBus.ErrorKind.NETWORK,
                PassiveAnalysisErrorClassifier.classify(new IOException("io failed")));
        // SocketTimeoutException → NETWORK
        assertEquals(PassiveAnalysisErrorBus.ErrorKind.NETWORK,
                PassiveAnalysisErrorClassifier.classify(new SocketTimeoutException("timeout")));
        // ConnectException → NETWORK
        assertEquals(PassiveAnalysisErrorBus.ErrorKind.NETWORK,
                PassiveAnalysisErrorClassifier.classify(new ConnectException("refused")));
        // UnknownHostException → NETWORK
        assertEquals(PassiveAnalysisErrorBus.ErrorKind.NETWORK,
                PassiveAnalysisErrorClassifier.classify(new UnknownHostException("nope.invalid")));
    }

    @Test
    void aiExceptionWithCauseFollowsCauseType() {
        AiException wrapped = new AiException("AI 调用失败", new SocketTimeoutException("read timeout"));
        assertEquals(PassiveAnalysisErrorBus.ErrorKind.NETWORK,
                PassiveAnalysisErrorClassifier.classify(wrapped));
    }
}
