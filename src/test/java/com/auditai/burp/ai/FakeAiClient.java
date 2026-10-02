package com.auditai.burp.ai;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.CompletableFuture;

/**
 * 脚本化假 AI 客户端（测试用，不联网）。
 *
 * <p>按调用顺序依次返回预置的 JSON 文本，并记录调用次数与最近一次收到的 messages
 * （供断言与复盘）。<b>不重复打印 messages 全文</b>：报文全文与模型响应已由
 * TrafficAnalyzer 的 DEBUG 日志（logRoundStart / logRoundResponse）完整输出
 * （需开启 {@code auditai.debug.prompt}），这里只打一行调用摘要避免控制台噪音。</p>
 *
 * <p>只实现 {@link #completeJsonAsync}——单轮与两阶段的 JSON 模式调用都走它；
 * {@link #complete} / {@link #completeAsync} 抛 {@link UnsupportedOperationException}
 * （测试流程用不到）。</p>
 *
 * <p><b>为什么本类必须放在 {@code com.auditai.burp.ai} 包内</b>：{@link CancellableAiCall}
 * 的构造器是包私有的（{@code new CancellableAiCall(future, mapper)}），只有同包代码
 * 能构造可用的返回句柄。</p>
 */
public final class FakeAiClient implements AiClient {

    /** 预置响应队列：每次 {@link #completeJsonAsync} 弹出一条，弹空后抛异常。 */
    private final Queue<String> scriptedJsonResponses;

    /** 已处理的调用次数。 */
    private int callCount;

    /** 最近一次调用收到的 messages（供断言与复盘）。 */
    private List<ChatMessage> lastMessages;

    /**
     * 每次调用收到的 messages 列表（按调用顺序追加；第 i 个元素是第 i+1 次调用的
     * messages 副本）。供两阶段流程的测试断言"阶段 1 / 阶段 2 各拿到了什么"。
     */
    private final List<List<ChatMessage>> allMessages = new ArrayList<>();

    public FakeAiClient(String... scriptedJsonResponses) {
        this.scriptedJsonResponses = new LinkedList<>(List.of(scriptedJsonResponses));
    }

    @Override
    public CancellableAiCall completeJsonAsync(List<ChatMessage> messages, boolean requireJson)
            throws AiException {
        String response = scriptedJsonResponses.poll();
        if (response == null) {
            throw new AiException("FakeAiClient：预置响应已用尽，流程比预期多调用了一次模型");
        }
        lastMessages = List.copyOf(messages);
        allMessages.add(lastMessages);
        callCount++;

        // 只打一行摘要（内容全文由 TrafficAnalyzer 的 DEBUG 日志打印，见类注释）。
        System.out.println("[FakeAiClient] 模拟模型第 " + callCount + " 次调用"
                + "（requireJson=" + requireJson + "，messages 共 " + messages.size()
                + " 条）→ 返回脚本响应 #" + callCount);

        // 立即完成的 future（值为 null）+ 忽略入参直接返回脚本文本的映射器：
        // 保证 await() 同步返回预置内容，不真正联网。
        return new CancellableAiCall(CompletableFuture.completedFuture(null), ignored -> response);
    }

    @Override
    public String complete(String systemPrompt, String userPrompt) throws AiException {
        throw new UnsupportedOperationException("FakeAiClient 不实现 complete");
    }

    @Override
    public CancellableAiCall completeAsync(String systemPrompt, String userPrompt) throws AiException {
        throw new UnsupportedOperationException("FakeAiClient 不实现 completeAsync");
    }

    /**
     * 降级版本：测试环境不需要真正的"远端 4xx 拒绝 json_object"演练，
     * 直接复用 {@link #completeJsonAsync} 的脚本响应即可。
     */
    @Override
    public CancellableAiCall completeJsonAsyncWithFallback(List<ChatMessage> messages) throws AiException {
        return completeJsonAsync(messages, true);
    }

    /** 已发生的模型调用次数（单轮应为 1，两阶段应为 2）。 */
    public int callCount() {
        return callCount;
    }

    /** 最近一次调用收到的 messages 副本；从未调用时为 null。 */
    public List<ChatMessage> lastMessages() {
        return lastMessages;
    }

    /**
     * 每次调用收到的 messages（按调用顺序）：索引 0 = 第一次调用，1 = 第二次调用，...
     * 不可变快照集合，调用前请用 {@code callMessages().get(i)} 取第 i+1 次的 messages。
     */
    public List<List<ChatMessage>> callMessages() {
        return Collections.unmodifiableList(allMessages);
    }
}
