package com.auditai.burp.tools;

import com.auditai.burp.ai.FakeAiClient;
import com.auditai.burp.ai.PromptBuilder;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link ToolLoopOrchestrator} 核心循环单测。
 *
 * <p>使用 fake AI 客户端（脚本化响应）+ 自定义假 Tool 实现驱动整个循环，验证：
 * 多轮调度、预算硬上限、未注册工具的容错、trace 顺序保留、Outcome 暴露 lastRaw 等核心契约。</p>
 */
class ToolLoopOrchestratorTest {

    @Test
    void singleToolCallThenWrapUp() throws Exception {
        String modelTurn1 = wrapup("尝试 1 次", mkToolCall("replay_request",
                "{\"reason\":\"闭合单引号\",\"replace_query_params\":{\"id\":\"1'\"}}"));
        String modelTurn2 = "{\"analysis\":\"最终结论\",\"tool_calls\":[],\"risk\":\"high\",\"findings\":[]}";
        FakeAiClient ai = new FakeAiClient(modelTurn1, modelTurn2);
        FakeTool replay = new FakeTool("replay_request",
                ToolOutcome.success("重放结果：xxx"));
        ToolLoopOrchestrator orch = newOrchestrator(ai, replay, 3, () -> "STUB: 原始请求");
        ToolLoopOrchestrator.Outcome outcome = orch.run(null);

        assertEquals("最终结论", outcome.analysis());
        assertEquals(1, replay.executed.size());
        assertEquals(1, orch.usedBudget());
        assertEquals(1, orch.trace().size());
        assertEquals(2, ai.callCount());
    }

    @Test
    void multipleToolCallsAcrossMultipleTurns() throws Exception {
        String turn1 = wrapup("r1", mkToolCall("replay_request",
                "{\"reason\":\"r1\",\"replace_query_params\":{\"id\":\"1'\"}}"));
        String turn2 = wrapup("r2", mkToolCall("decode", "{\"encoding\":\"base64\",\"data\":\"YQ==\"}"));
        String turn3 = "{\"analysis\":\"done\",\"tool_calls\":[],\"risk\":\"none\",\"findings\":[]}";

        FakeAiClient ai = new FakeAiClient(turn1, turn2, turn3);
        FakeTool replay = new FakeTool("replay_request", ToolOutcome.success("重放：ok"));
        FakeTool decoder = new FakeTool("decode", ToolOutcome.success("解码：a"));
        ToolLoopOrchestrator orch = newOrchestrator(ai, replay, decoder, 3, () -> "STUB");
        ToolLoopOrchestrator.Outcome outcome = orch.run(null);

        assertEquals("done", outcome.analysis());
        assertEquals(1, replay.executed.size());
        assertEquals(1, decoder.executed.size());
        assertEquals(2, orch.usedBudget());
        assertEquals(3, ai.callCount());
    }

    @Test
    void budgetEnforcedAtThree() throws Exception {
        // 4 轮都想调用：第 4 次被 budget 拒绝
        String turn1 = wrapup("r1", mkToolCall("replay_request",
                "{\"reason\":\"a\",\"replace_query_params\":{\"id\":\"a\"}}"));
        String turn2 = wrapup("r2", mkToolCall("replay_request",
                "{\"reason\":\"b\",\"replace_query_params\":{\"id\":\"b\"}}"));
        String turn3 = wrapup("r3", mkToolCall("replay_request",
                "{\"reason\":\"c\",\"replace_query_params\":{\"id\":\"c\"}}"));
        String turn4 = wrapup("r4", mkToolCall("replay_request",
                "{\"reason\":\"d\",\"replace_query_params\":{\"id\":\"d\"}}"));
        String turn5 = "{\"analysis\":\"wrap\",\"tool_calls\":[],\"risk\":\"high\",\"findings\":[]}";

        FakeAiClient ai = new FakeAiClient(turn1, turn2, turn3, turn4, turn5);
        FakeTool replay = new FakeTool("replay_request",
                ToolOutcome.success("ok1"), ToolOutcome.success("ok2"),
                ToolOutcome.success("ok3"), ToolOutcome.success("ok4-never"));
        ToolLoopOrchestrator orch = newOrchestrator(ai, replay, 3, () -> "STUB");
        orch.run(null);

        assertEquals(3, replay.executed.size(), "应只执行 3 次；第 4 次被 budget 拒绝");
        assertEquals(3, orch.usedBudget());
    }

    @Test
    void wrapsUpWhenModelNeverAsksForTools() throws Exception {
        String onlyTurn = "{\"analysis\":\"无需工具\",\"tool_calls\":[],\"risk\":\"none\",\"findings\":[]}";
        FakeAiClient ai = new FakeAiClient(onlyTurn);
        FakeTool replay = new FakeTool("replay_request");
        ToolLoopOrchestrator orch = newOrchestrator(ai, replay, 3, () -> "STUB");
        ToolLoopOrchestrator.Outcome outcome = orch.run(null);
        assertEquals("无需工具", outcome.analysis());
        assertEquals(0, replay.executed.size());
        assertEquals(0, orch.usedBudget());
    }

    @Test
    void unknownToolRejectedAsOutcomeNotCrash() throws Exception {
        // 模型发了个未注册的工具调用 → orchestrator 应返回"未注册"失败，循环继续
        String turn1 = wrapup("unknown", mkToolCall("ghost_tool", "{}"));
        String turn2 = "{\"analysis\":\"wrap\",\"tool_calls\":[],\"risk\":\"none\",\"findings\":[]}";

        FakeAiClient ai = new FakeAiClient(turn1, turn2);
        FakeTool replay = new FakeTool("replay_request");  // 没有 ghost_tool
        ToolLoopOrchestrator orch = newOrchestrator(ai, replay, 3, () -> "STUB");
        ToolLoopOrchestrator.Outcome outcome = orch.run(null);

        assertEquals("wrap", outcome.analysis());
        // orchestrator 把它当作"预算已用 1 次"（仍计入 budget 防止模型用未知工具刷预算）
        assertEquals(1, orch.usedBudget());
        assertFalse(orch.trace().get(0).outcome().success());
        assertTrue(orch.trace().get(0).outcome().error().contains("未注册"));
    }

    @Test
    void toolThrowingExceptionIsCaught() throws Exception {
        // 工具实现违反了"不抛异常"契约——orchestrator 应兜底
        String turn1 = wrapup("bad", mkToolCall("replay_request", "{}"));
        String turn2 = "{\"analysis\":\"wrap\",\"tool_calls\":[],\"risk\":\"none\",\"findings\":[]}";

        FakeAiClient ai = new FakeAiClient(turn1, turn2);
        FakeTool bad = new FakeTool("replay_request") {
            @Override
            public ToolOutcome execute(ToolCall call) {
                throw new IllegalStateException("故意抛异常");
            }
        };
        ToolLoopOrchestrator orch = newOrchestrator(ai, bad, 3, () -> "STUB");
        orch.run(null);

        // 异常被 orchestrator 兜底成失败结果
        assertFalse(orch.trace().get(0).outcome().success());
        assertTrue(orch.trace().get(0).outcome().error().contains("IllegalStateException"));
    }

    @Test
    void defaultBudgetIsThree() {
        assertEquals(3, ToolLoopOrchestrator.DEFAULT_BUDGET);
    }

    @Test
    void customBudgetIsClampedToThree() throws Exception {
        String turn1 = wrapup("r1", mkToolCall("replay_request", "{}"));
        String turn2 = wrapup("r2", mkToolCall("replay_request", "{}"));
        String turn3 = wrapup("r3", mkToolCall("replay_request", "{}"));
        String turn4 = "{\"analysis\":\"wrap\",\"tool_calls\":[],\"risk\":\"none\",\"findings\":[]}";

        FakeAiClient ai = new FakeAiClient(turn1, turn2, turn3, turn4);
        FakeTool replay = new FakeTool("replay_request",
                ToolOutcome.success("a"), ToolOutcome.success("b"),
                ToolOutcome.success("c"), ToolOutcome.success("d-never"));
        // 传 99 → 应被夹到 3
        ToolLoopOrchestrator orch = new ToolLoopOrchestrator(
                null, ai, new PromptBuilder(() -> null, () -> PromptBuilder.Lang.ZH),
                Map.of("replay_request", replay), List.of(), null, null, 99, () -> "STUB");
        orch.run(null);
        assertEquals(3, orch.usedBudget());
    }

    @Test
    void tracePreservesOrderAndCallId() throws Exception {
        String turn1 = wrapup("r1", mkToolCall("replay_request", "{\"k\":\"v1\"}"));
        String turn2 = wrapup("r2", mkToolCall("decode", "{\"data\":\"x\"}"));
        String turn3 = "{\"analysis\":\"done\",\"tool_calls\":[],\"risk\":\"none\",\"findings\":[]}";

        FakeAiClient ai = new FakeAiClient(turn1, turn2, turn3);
        FakeTool replay = new FakeTool("replay_request", ToolOutcome.success("ok1"));
        FakeTool decoder = new FakeTool("decode", ToolOutcome.success("ok2"));
        ToolLoopOrchestrator orch = newOrchestrator(ai, replay, decoder, 3, () -> "STUB");
        orch.run(null);

        List<ToolLoopOrchestrator.ToolTrace> trace = orch.trace();
        assertEquals(2, trace.size());
        assertEquals("replay_request", trace.get(0).call().toolName());
        assertEquals("decode", trace.get(1).call().toolName());
        assertEquals("ok1", trace.get(0).outcome().userPromptFragment());
        assertEquals("ok2", trace.get(1).outcome().userPromptFragment());
        // callId 应是 "tc-N-XXXXXXXX" 形式
        assertTrue(trace.get(0).callId().startsWith("tc-1-"), "callId 格式: " + trace.get(0).callId());
    }

    /**
     * 工具分发循环内的取消检查：用户在一次工具执行期间点 Cancel 后，
     * 本轮剩余的工具调用必须被跳过（不能把剩余的阻塞 HTTP 发送全打完）。
     */
    @Test
    void cancelDuringDispatch_skipsRemainingToolCalls() {
        String turn1 = wrapup("r1",
                mkToolCall("replay_request", "{\"reason\":\"a\",\"replace_query_params\":{\"id\":\"a\"}}")
                        + "," + mkToolCall("replay_request", "{\"reason\":\"b\",\"replace_query_params\":{\"id\":\"b\"}}"));
        String turn2 = "{\"analysis\":\"done\",\"tool_calls\":[],\"risk\":\"none\",\"findings\":[]}";
        FakeAiClient ai = new FakeAiClient(turn1, turn2);
        // 第一次执行后就置位"已取消"，模拟"用户在重放进行中点 Cancel"
        java.util.concurrent.atomic.AtomicBoolean cancelled =
                new java.util.concurrent.atomic.AtomicBoolean(false);
        FakeTool tool = new FakeTool("replay_request", ToolOutcome.success("first")) {
            @Override
            public ToolOutcome execute(ToolCall call) {
                ToolOutcome outcome = super.execute(call);
                cancelled.set(true);
                return outcome;
            }
        };
        ToolLoopOrchestrator orch = newOrchestrator(ai, tool, 3, () -> "STUB");

        // 取消会在下一轮循环开头以 AiException.cancelled() 结束
        assertThrows(com.auditai.burp.ai.AiException.class, () -> orch.run(cancelled::get));
        assertEquals(1, tool.executed.size(),
                "本轮第 2 个工具调用必须被取消检查跳过，实际执行=" + tool.executed.size());
        assertEquals(1, orch.usedBudget(), "被跳过的调用不应消耗预算");
    }

    // —— helpers ——

    private static ToolLoopOrchestrator newOrchestrator(FakeAiClient ai, FakeTool tool, int budget,
                                                        Supplier<String> userSupplier) {
        return newOrchestrator(ai, List.of(tool), budget, userSupplier);
    }
    private static ToolLoopOrchestrator newOrchestrator(FakeAiClient ai, FakeTool tool1, FakeTool tool2,
                                                        int budget, Supplier<String> userSupplier) {
        return newOrchestrator(ai, List.of(tool1, tool2), budget, userSupplier);
    }

    private static ToolLoopOrchestrator newOrchestrator(FakeAiClient ai, List<FakeTool> tools, int budget,
                                                        Supplier<String> userSupplier) {
        Map<String, Tool> map = new LinkedHashMap<>();
        for (FakeTool t : tools) {
            map.put(t.name, t);
        }
        return new ToolLoopOrchestrator(
                null, ai, new PromptBuilder(() -> null, () -> PromptBuilder.Lang.ZH),
                map, List.of(), null, null, budget, userSupplier);
    }

    private static String wrapup(String analysis, String toolCallJsonLiteral) {
        return "{\"analysis\":\"" + analysis + "\","
                + "\"tool_calls\":[" + toolCallJsonLiteral + "],"
                + "\"risk\":\"none\",\"findings\":[]}";
    }

    private static String mkToolCall(String name, String argsJsonLiteral) {
        return "{\"name\":\"" + name + "\",\"arguments\":" + argsJsonLiteral + "}";
    }

    /**
     * 假 Tool：按预置结果列表依次返回（不真做 HTTP 也不抛异常——除非测试刻意 override）。
     */
    static class FakeTool implements Tool {
        final String name;
        final List<ToolOutcome> queued = new java.util.ArrayList<>();
        final List<ToolCall> executed = new java.util.ArrayList<>();
        private final AtomicInteger idx = new AtomicInteger(0);

        FakeTool(String name, ToolOutcome... results) {
            this.name = name;
            for (ToolOutcome r : results) queued.add(r);
        }

        @Override
        public String name() { return name; }

        @Override
        public ToolOutcome execute(ToolCall call) {
            executed.add(call);
            if (queued.isEmpty()) {
                return ToolOutcome.failure("FakeTool: 预置结果已用尽",
                        "[工具失败] " + name + "：预置结果已用尽");
            }
            return queued.get(idx.getAndIncrement() % queued.size());
        }
    }
}
