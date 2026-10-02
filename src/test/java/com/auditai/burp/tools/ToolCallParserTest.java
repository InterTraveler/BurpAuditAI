package com.auditai.burp.tools;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link ToolCallParser} 的单元测试。
 *
 * <p>重点覆盖（解析器现在是通用的，支持任意 tool name）：</p>
 * <ul>
 *   <li>任意 tool_name（含 "replay_request" / "brute_force" 等）都能正确解析；</li>
 *   <li>arguments JSON 原样传给工具（解析器不解析 tool-specific schema）；</li>
 *   <li>容错：模型输出 markdown 围栏 / 缺字段 / 缺 name 时不抛错；</li>
 *   <li>非数组 tool_calls / 完全不是 JSON 时返回 empty 不抛异常。</li>
 * </ul>
 */
class ToolCallParserTest {

    @Test
    void parsesReplayRequest() {
        String raw = "{\n"
                + "  \"analysis\": \"试试闭合引号\",\n"
                + "  \"tool_calls\": [{\n"
                + "    \"name\": \"replay_request\",\n"
                + "    \"arguments\": {\n"
                + "      \"reason\": \"闭合单引号\",\n"
                + "      \"replace_query_params\": {\"id\": \"1'\"},\n"
                + "      \"replace_header_params\": {\"X-User-Id\": \"admin\"}\n"
                + "    }\n"
                + "  }],\n"
                + "  \"risk\": \"none\",\n"
                + "  \"findings\": []\n"
                + "}";
        ToolCallParser.Parsed p = ToolCallParser.parse(raw);
        assertTrue(p.hasToolCalls());
        assertEquals(1, p.toolCalls().size());
        ToolCall call = p.toolCalls().get(0);
        assertEquals("replay_request", call.toolName());
        assertEquals("闭合单引号", call.reason());
        // arguments 是原 JSON 字符串（解析器不解析 tool-specific schema）
        assertTrue(call.argumentsJson().contains("replace_query_params"),
                "应保留原 arguments JSON");
        assertTrue(call.argumentsJson().contains("replace_header_params"),
                "应保留原 arguments JSON");
        assertTrue(call.argumentsJson().contains("1'"));
        assertEquals("试试闭合引号", p.analysis());
        assertTrue(p.errors().isEmpty(), "无错误，实际：" + p.errors());
    }

    @Test
    void parsesBruteForceTool() {
        // 演示：解析器对任何 tool_name 一视同仁——具体 schema 由 Tool 实现自己解析
        String raw = "{\n"
                + "  \"tool_calls\": [{\n"
                + "    \"name\": \"brute_force\",\n"
                + "    \"arguments\": {\n"
                + "      \"target\": \"/login\",\n"
                + "      \"username_field\": \"user\",\n"
                + "      \"password_field\": \"pass\",\n"
                + "      \"wordlist\": [\"admin\", \"root\", \"test\"]\n"
                + "    }\n"
                + "  }]\n"
                + "}";
        ToolCallParser.Parsed p = ToolCallParser.parse(raw);
        assertEquals(1, p.toolCalls().size());
        assertEquals("brute_force", p.toolCalls().get(0).toolName());
        // arguments JSON 原样保留
        assertTrue(p.toolCalls().get(0).argumentsJson().contains("\"target\":\"/login\""));
    }

    @Test
    void handlesMarkdownCodeFence() {
        String raw = "```json\n"
                + "{\"tool_calls\":[{\"name\":\"replay_request\",\"arguments\":"
                + "{\"replace_query_params\":{\"id\":\"1'\"}}}]}\n"
                + "```";
        ToolCallParser.Parsed p = ToolCallParser.parse(raw);
        assertEquals(1, p.toolCalls().size());
        // 解析器不解析 tool-specific schema，但 argumentsJson 原样保留——上层能拿到 replace_query_params
        assertTrue(p.toolCalls().get(0).argumentsJson().contains("1'"));
    }

    @Test
    void ignoresUnknownToolNames() {
        // 解析器不识别"未注册工具"——它只是如实解析 name 字段。ToolLoopOrchestrator
        // 在 dispatch 时才会判定"未注册"并返回失败。这是单一职责分工。
        String raw = "{\n"
                + "  \"tool_calls\": [\n"
                + "    {\"name\": \"send_email\", \"arguments\": {\"to\": \"x\"}},\n"
                + "    {\"name\": \"replay_request\", \"arguments\": {\"replace_query_params\": {\"id\": \"1'\"}}}\n"
                + "  ]\n"
                + "}";
        ToolCallParser.Parsed p = ToolCallParser.parse(raw);
        // 两个都解析出（name 都非空），由 orchestrator 决定怎么处理未知 tool
        assertEquals(2, p.toolCalls().size());
        assertEquals("send_email", p.toolCalls().get(0).toolName());
        assertEquals("replay_request", p.toolCalls().get(1).toolName());
    }

    @Test
    void returnsEmptyForInvalidJson() {
        ToolCallParser.Parsed p = ToolCallParser.parse("not a json at all");
        assertFalse(p.hasToolCalls());
        assertTrue(p.toolCalls().isEmpty());
        assertFalse(p.errors().isEmpty());
    }

    @Test
    void returnsEmptyForNullAndBlank() {
        assertFalse(ToolCallParser.parse(null).hasToolCalls());
        assertFalse(ToolCallParser.parse("").hasToolCalls());
        assertFalse(ToolCallParser.parse("   \n  ").hasToolCalls());
    }

    @Test
    void missingArgumentsSkipsThatCall() {
        String raw = "{\n"
                + "  \"tool_calls\": [\n"
                + "    {\"name\": \"replay_request\"},\n"
                + "    {\"name\": \"replay_request\", \"arguments\": {\"replace_query_params\": {\"id\": \"1'\"}}}\n"
                + "  ]\n"
                + "}";
        ToolCallParser.Parsed p = ToolCallParser.parse(raw);
        assertEquals(1, p.toolCalls().size(), "缺 arguments 的应被跳过");
        assertTrue(p.toolCalls().get(0).argumentsJson().contains("1'"));
    }

    @Test
    void wrapsUpWhenNoToolCalls() {
        String raw = "{\"analysis\":\"最终结论\",\"tool_calls\":[],\"risk\":\"high\",\"findings\":[]}";
        ToolCallParser.Parsed p = ToolCallParser.parse(raw);
        assertFalse(p.hasToolCalls());
        assertEquals("最终结论", p.analysis());
    }

    @Test
    void multipleMixedToolCallsPreserveOrder() {
        String raw = "{\n"
                + "  \"tool_calls\": [\n"
                + "    {\"name\": \"replay_request\", \"arguments\": {\"replace_query_params\": {\"id\": \"r1\"}}},\n"
                + "    {\"name\": \"decode\", \"arguments\": {\"encoding\": \"base64\"}},\n"
                + "    {\"name\": \"brute_force\", \"arguments\": {\"target\": \"/login\"}}\n"
                + "  ]\n"
                + "}";
        ToolCallParser.Parsed p = ToolCallParser.parse(raw);
        assertEquals(3, p.toolCalls().size());
        assertEquals("replay_request", p.toolCalls().get(0).toolName());
        assertEquals("decode", p.toolCalls().get(1).toolName());
        assertEquals("brute_force", p.toolCalls().get(2).toolName());
    }

    /** 推理模型常用 thoughts+response 结构：用 response 兜底为 analysis。 */
    @Test
    void fallsBackToResponseFieldForReasoningModels() {
        String raw = "{\"thoughts\": \"The provided text appears to be a base64 encoded image...\","
                + " \"response\": \"I'm sorry, but I can't assist with that.\"}";
        ToolCallParser.Parsed p = ToolCallParser.parse(raw);
        assertFalse(p.hasToolCalls(), "thoughts+response 结构无 tool_calls");
        assertEquals("I'm sorry, but I can't assist with that.", p.analysis());
    }

    /** 协议字段 analysis 优先于 response 等兜底字段。 */
    @Test
    void analysisFieldWinsOverResponseField() {
        String raw = "{\"analysis\": \"协议结论\", \"response\": \"兜底结论\"}";
        ToolCallParser.Parsed p = ToolCallParser.parse(raw);
        assertEquals("协议结论", p.analysis());
    }

    /** analysis 为空字符串时走 response 兜底。 */
    @Test
    void emptyAnalysisFallsBackToResponse() {
        String raw = "{\"analysis\": \"\", \"response\": \"real response\"}";
        ToolCallParser.Parsed p = ToolCallParser.parse(raw);
        assertEquals("real response", p.analysis());
    }

    /** 兜底字段 text / content / output 同样有效。 */
    @Test
    void fallsBackToTextAndContentAndOutputFields() {
        assertEquals("from text",
                ToolCallParser.parse("{\"text\": \"from text\"}").analysis());
        assertEquals("from content",
                ToolCallParser.parse("{\"content\": \"from content\"}").analysis());
        assertEquals("from output",
                ToolCallParser.parse("{\"output\": \"from output\"}").analysis());
    }

    /** 兜底字段都是空时 analysis 仍为 null（不强行制造假数据）。 */
    @Test
    void allFallbacksBlankLeavesAnalysisNull() {
        ToolCallParser.Parsed p = ToolCallParser.parse("{\"response\": \"\", \"text\": \"   \"}");
        assertNull(p.analysis());
    }

    /** thoughts+response + 正常 tool_calls：analysis 走 response 兜底，tool_calls 照常解析。 */
    @Test
    void thoughtsResponseWithToolCallsExtractsBoth() {
        String raw = "{\"thoughts\": \"verify SQL injection...\","
                + " \"response\": \"let me test with single quote\","
                + " \"tool_calls\": [{\"name\": \"replay_request\","
                + "   \"arguments\": {\"replace_query_params\": {\"id\": \"1'\"}}}]}";
        ToolCallParser.Parsed p = ToolCallParser.parse(raw);
        assertTrue(p.hasToolCalls());
        assertEquals(1, p.toolCalls().size());
        assertEquals("let me test with single quote", p.analysis());
    }

    /** {@code name} 是数组时同样只跳过，不抛异常。 */
    @Test
    void nameIsArray_skipsItemWithoutThrowing() {
        String raw = "{\"tool_calls\": [{\"name\": [\"a\"], \"arguments\": {}}]}";
        ToolCallParser.Parsed p = ToolCallParser.parse(raw);
        assertFalse(p.hasToolCalls());
        assertTrue(p.errors().stream().anyMatch(e -> e.contains("name")));
    }

    /** 一个 name 合法、一个 name 是对象时：合法的保留，脏的跳过。 */
    @Test
    void mixedGoodAndDirtyNames_keepsGoodOnes() {
        String raw = "{\"tool_calls\": ["
                + "{\"name\": \"replay_request\", \"arguments\": {\"replace_query_params\": {\"id\": \"1\"}}},"
                + "{\"name\": {\"bad\": true}, \"arguments\": {}}"
                + "]}";
        ToolCallParser.Parsed p = ToolCallParser.parse(raw);
        assertEquals(1, p.toolCalls().size());
        assertEquals("replay_request", p.toolCalls().get(0).toolName());
        assertFalse(p.errors().isEmpty());
    }
}
