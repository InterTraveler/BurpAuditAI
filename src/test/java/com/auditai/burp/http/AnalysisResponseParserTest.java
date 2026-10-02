package com.auditai.burp.http;

import com.auditai.burp.skills.Skill;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link AnalysisResponseParser#tryParseSelection} /
 * {@link AnalysisResponseParser#resolveSelection} 的协议兼容单元测试。
 *
 * <p>重点覆盖"非协议格式"——某些推理模型（o1 / o3 / DeepSeek-R1 / Gemini Thinking 等）习惯用
 * {@code {"thoughts": "...", "response": "..."}} 表达"思考 + 回答"，
 * 而不是协议字段 {@code analysis}。如果解析器不兼容这种格式，会导致：</p>
 * <ol>
 *   <li>阶段 1 解析时 {@code analysis} 字段取不到 → 走阶段 2 兜底；</li>
 *   <li>阶段 2 工具循环又拿到同样格式 → 收尾时 {@code lastAnalysis=""}；
 *       用户既看不到 analysis，也看不到任何 finding，分析结果"丢失"。</li>
 * </ol>
 *
 * <p>本测试套件确保上述场景下用户至少能看到模型说了什么。</p>
 */
class AnalysisResponseParserTest {

    /** 推理模型的典型输出：thoughts + response，应从 response 兜底提取 analysis。 */
    @Test
    void parsesThoughtsAndResponseShape() {
        String raw = "{\"thoughts\": \"The provided text appears to be a base64 encoded image, "
                + "likely the logo or icon of the website. The content is not readable as plain text.\","
                + " \"response\": \"I'm sorry, but I can't assist with that.\"}";
        AnalysisResponseParser.ParsedSelection parsed = AnalysisResponseParser.tryParseSelection(raw);
        assertNotNull(parsed, "JSON 合法就不应返回 null");
        assertTrue(parsed.activeIds().isEmpty());
        assertEquals("I'm sorry, but I can't assist with that.", parsed.analysis());
    }

    /** 兜底字段 response 触发 skipPhase2：避免阶段 2 重复调用同一个被拒答的请求。 */
    @Test
    void responseFallbackSkipsPhase2() {
        String raw = "{\"thoughts\": \"...\", \"response\": \"I cannot help with that.\"}";
        AnalysisResponseParser.ParsedSelection parsed = AnalysisResponseParser.tryParseSelection(raw);
        AnalysisResponseParser.SelectionResult result = AnalysisResponseParser.resolveSelection(parsed, List.of());
        assertFalse(result.tookPhase2(), "response 兜底非空时应直接收尾，不进 phase 2");
        assertEquals("I cannot help with that.", result.analysis());
    }

    /**
     * response / analysis 都是空、且 active_skill_ids=[] 时——
     * 模型主动"啥都没说"，<b>不</b>走 phase 2，更不扩张到全量启用。
     * 走 {@code needPhase2(enabledSkills, "")} 会把 phase 2 调起来但没有任何
     * 技能提示，浪费一次模型调用。
     */
    @Test
    void emptyResponseDoesNotFallBackToPhase2() {
        String raw = "{\"thoughts\": \"...\", \"response\": \"\"}";
        AnalysisResponseParser.ParsedSelection parsed = AnalysisResponseParser.tryParseSelection(raw);
        // response 空 → 兜底字段全空 → readAnalysisField 返回 null → analysis 字段为 ""
        assertEquals("", parsed.analysis());
        // 没有 skill 且 analysis 为空 → 不扩张到全量兜底，skipPhase2 让上层按空结论收尾
        AnalysisResponseParser.SelectionResult result = AnalysisResponseParser.resolveSelection(parsed, List.of());
        assertFalse(result.tookPhase2(),
                "active_skill_ids=[] + analysis 空 必须 skipPhase2，不再调一次没意义的 phase 2");
        assertTrue(result.activeSkills().isEmpty());
        assertEquals("", result.analysis());
    }

    /** 兜底字段 text / content / output 同样有效。 */
    @Test
    void fallsBackToTextContentOutput() {
        assertEquals("from text",
                AnalysisResponseParser.tryParseSelection("{\"text\": \"from text\"}").analysis());
        assertEquals("from content",
                AnalysisResponseParser.tryParseSelection("{\"content\": \"from content\"}").analysis());
        assertEquals("from output",
                AnalysisResponseParser.tryParseSelection("{\"output\": \"from output\"}").analysis());
    }

    /** 协议字段 analysis 优先于所有兜底字段。 */
    @Test
    void protocolAnalysisWinsOverFallbacks() {
        String raw = "{\"analysis\": \"协议字段\","
                + " \"response\": \"兜底字段\","
                + " \"text\": \"兜底字段 text\"}";
        assertEquals("协议字段", AnalysisResponseParser.tryParseSelection(raw).analysis());
    }

    /** analysis 为空字符串 + response 非空 → 用 response 兜底（拒答不被吞）。 */
    @Test
    void emptyAnalysisStillFallsBackToResponse() {
        String raw = "{\"analysis\": \"\", \"response\": \"real response\"}";
        assertEquals("real response", AnalysisResponseParser.tryParseSelection(raw).analysis());
    }

    /** 完全不是 JSON → tryParseSelection 返回 null（走"全量启用兜底"）。 */
    @Test
    void nonJsonReturnsNull() {
        assertNull(AnalysisResponseParser.tryParseSelection("not a json at all"));
    }

    /** 空 / null 同样返回 null。 */
    @Test
    void nullAndEmptyReturnNull() {
        assertNull(AnalysisResponseParser.tryParseSelection(null));
        assertNull(AnalysisResponseParser.tryParseSelection(""));
    }

    /** 协议字段 active_skill_ids + response 兜底 analysis：selected 非空，强制走 phase 2。 */
    @Test
    void activeSkillIdsWithResponseFallbackGoesToPhase2() {
        Skill skillA = new Skill("a", "A", "A", "");
        Skill skillB = new Skill("b", "B", "B", "");
        String raw = "{\"thoughts\": \"...\", \"response\": \"check XSS\","
                + " \"active_skill_ids\": [\"a\", \"c-not-enabled\"]}";
        AnalysisResponseParser.ParsedSelection parsed = AnalysisResponseParser.tryParseSelection(raw);
        assertEquals(List.of("a", "c-not-enabled"), parsed.activeIds());
        assertEquals("check XSS", parsed.analysis());

        AnalysisResponseParser.SelectionResult result =
                AnalysisResponseParser.resolveSelection(parsed, List.of(skillA, skillB));
        assertTrue(result.tookPhase2());
        assertEquals(List.of(skillA), result.activeSkills(), "未启用的 id 应被过滤");
        assertSame(Skill.class, result.activeSkills().get(0).getClass());
    }

    /** 解析失败 → resolveSelection 走 needPhase2(enabledSkills, "")。 */
    @Test
    void resolveSelectionNullParsedUsesAllEnabledSkills() {
        Skill skillA = new Skill("a", "A", "A", "");
        Skill skillB = new Skill("b", "B", "B", "");
        AnalysisResponseParser.SelectionResult result =
                AnalysisResponseParser.resolveSelection(null, List.of(skillA, skillB));
        assertTrue(result.tookPhase2());
        assertEquals(List.of(skillA, skillB), result.activeSkills());
        assertEquals("", result.analysis());
    }

    /**
     * 模型挑了至少一个 id，但全部拼写错 / 不在 enabled 列表里——
     * 不应降级到全量兜底（那会把所有启用的技能 prompt 都塞进 phase 2 的 system 段，
     * 轻松吃掉几万 token 触发模型拒答 / 上下文溢出）。
     *
     * <p>预期行为：</p>
     * <ul>
     *   <li>若模型同时给了 {@code analysis}，按用户实际意图收尾（skipPhase2 + 用其 analysis）；</li>
     *   <li>若没给，按"模型没结论"兜底（skipPhase2 + 空 analysis）；</li>
     *   <li>非法 id 列表通过 {@link AnalysisResponseParser.SelectionResult#unknownIds()} 透传给上层记日志。</li>
     * </ul>
     */
    @Test
    void allUnknownSkillIdsDoNotTriggerFullFallback() {
        Skill sqlInjection = new Skill("sql-injection", "SQL 注入", "💉", "");
        Skill xssDetector = new Skill("xss-detector", "XSS 检测", "🛡️", "");
        String raw = "{\"active_skill_ids\": [\"file-upload-vulnerability\"], "
                + "\"analysis\": \"无文件上传迹象\"}";
        AnalysisResponseParser.ParsedSelection parsed = AnalysisResponseParser.tryParseSelection(raw);
        assertEquals(List.of("file-upload-vulnerability"), parsed.activeIds());

        AnalysisResponseParser.SelectionResult result = AnalysisResponseParser.resolveSelection(
                parsed, List.of(sqlInjection, xssDetector));

        assertFalse(result.tookPhase2(),
                "全部非法 id 必须拒绝降级到全量兜底——否则会把 sql-injection + xss-detector "
                        + "等所有启用技能都拼进 phase 2 system 段，prompt 爆炸");
        assertTrue(result.activeSkills().isEmpty(), "选了非法 id 时 activeSkills 必须为空");
        assertEquals(List.of("file-upload-vulnerability"), result.unknownIds(),
                "unknownIds 必须透传给上层记 warn 日志");
        assertEquals("无文件上传迹象", result.analysis(),
                "模型同时给了 analysis 时，按其内容收尾");
    }

    /**
     * 模型挑了非法 id 但没给 analysis —— 按"模型没结论"处理，
     * 不允许 fallback 到全量启用（仍可能让 prompt 爆炸）。
     */
    @Test
    void allUnknownSkillIdsWithEmptyAnalysisStillSkipPhase2() {
        Skill sqlInjection = new Skill("sql-injection", "SQL 注入", "💉", "");
        String raw = "{\"active_skill_ids\": [\"file-upload-vulnerability\"], "
                + "\"analysis\": \"\"}";
        AnalysisResponseParser.ParsedSelection parsed = AnalysisResponseParser.tryParseSelection(raw);

        AnalysisResponseParser.SelectionResult result = AnalysisResponseParser.resolveSelection(
                parsed, List.of(sqlInjection));

        assertFalse(result.tookPhase2(),
                "模型尝试挑选但没给 analysis → 仍 skipPhase2（让上层按空结论兜底），不能降级到全量兜底");
        assertTrue(result.activeSkills().isEmpty());
        assertEquals(List.of("file-upload-vulnerability"), result.unknownIds());
        assertEquals("", result.analysis());
    }

    /**
     * 边界：模型挑了 ids，其中部分合法部分非法 —— 只用合法部分，未知 id 仍要通过
     * unknownIds 透传给上层（方便排查模型为啥会拼错这一项）。
     */
    @Test
    void mixedKnownAndUnknownSkillIdsKeepsTheKnownOnesAndReportsUnknown() {
        Skill sqlInjection = new Skill("sql-injection", "SQL 注入", "💉", "");
        String raw = "{\"active_skill_ids\": [\"sql-injection\", \"file-upload-vulnerability\"], "
                + "\"analysis\": \"\"}";
        AnalysisResponseParser.ParsedSelection parsed = AnalysisResponseParser.tryParseSelection(raw);

        AnalysisResponseParser.SelectionResult result = AnalysisResponseParser.resolveSelection(
                parsed, List.of(sqlInjection));

        assertTrue(result.tookPhase2(), "有合法 id 时仍走 phase 2");
        assertEquals(List.of(sqlInjection), result.activeSkills());
        assertEquals(List.of("file-upload-vulnerability"), result.unknownIds(),
                "未知 id 仍要透传给上层排查");
    }

    /**
     * 模型主动返回 {@code active_skill_ids=[]} + 空 analysis
     * —— 这是"模型主动不要技能、且啥都没说"的语义，<b>必须</b>尊重——不允许扩张到全量
     * 启用兜底，否则 phase 2 会在用户没要求的情况下偷偷塞所有启用技能的 prompt，
     * 单次分析轻松吃掉几万个 token。
     *
     * <p>这条路径与"全部非法 id 触发全量兜底"是同源问题——两条路径都是
     * "模型明确表达了'不要技能'"但被偷偷扩张。</p>
     */
    @Test
    void emptyActiveIdsWithEmptyAnalysisDoesNotFallBackToAllEnabled() {
        Skill skillA = new Skill("a", "A", "A", "");
        Skill skillB = new Skill("b", "B", "B", "");
        String raw = "{\"active_skill_ids\": [], \"analysis\": \"\"}";
        AnalysisResponseParser.ParsedSelection parsed = AnalysisResponseParser.tryParseSelection(raw);

        AnalysisResponseParser.SelectionResult result = AnalysisResponseParser.resolveSelection(
                parsed, List.of(skillA, skillB));

        assertFalse(result.tookPhase2(),
                "模型说'不要技能 + 没说结论' 必须 skipPhase2——不允许扩张到全量启用，"
                        + "否则 phase 2 的 system 段会被全部启用技能 prompt 灌爆");
        assertTrue(result.activeSkills().isEmpty(), "activeSkills 必须为空，不允许偷塞任何技能");
        assertTrue(result.unknownIds().isEmpty());
        assertEquals("", result.analysis(),
                "analysis 为空时返回空字符串，让上层按'模型没结论'兜底而不是再调一次模型");
    }

    // ===== 宽松解析 fallback：覆盖"模型返回内容被破坏"的场景 =====

    /** markdown 围栏 + 完整 JSON：去围栏后能正常解析。 */
    @Test
    void stripsMarkdownFenceBeforeParsing() {
        String raw = "```json\n{\"active_skill_ids\": [], \"analysis\": \"围栏内结论\", \"risk\": \"none\"}\n```";
        AnalysisResponseParser.ParsedSelection parsed = AnalysisResponseParser.tryParseSelection(raw);
        assertNotNull(parsed);
        assertEquals("围栏内结论", parsed.analysis());
        assertTrue(parsed.activeIds().isEmpty());
    }

    /** 文本前后夹杂说明文字：截取顶层 {} 范围后能正常解析。 */
    @Test
    void trimsSurroundingNoiseBeforeParsing() {
        String raw = "下面是分析：\n{\"active_skill_ids\": [\"a\"], \"analysis\": \"夹缝里\"}\n分析完毕。";
        AnalysisResponseParser.ParsedSelection parsed = AnalysisResponseParser.tryParseSelection(raw);
        assertNotNull(parsed);
        assertEquals("夹缝里", parsed.analysis());
        assertEquals(List.of("a"), parsed.activeIds());
    }

    /** 合法转义的英文双引号：标准严格解析应能正确处理（不影响新加的 fallback 路径）。 */
    @Test
    void escapedDoubleQuoteInAnalysisIsParsedCorrectly() {
        String raw = "{\"active_skill_ids\": [], \"analysis\": \"他说\\\"hi\\\"后走了\"}";
        AnalysisResponseParser.ParsedSelection parsed = AnalysisResponseParser.tryParseSelection(raw);
        assertNotNull(parsed);
        assertEquals("他说\"hi\"后走了", parsed.analysis());
    }

    /**
     * findProtocolBoundary 的转义边界识别：分析字段内出现 {@code \"risk\"} 这种字面量时
     * 不应被误判为协议边界。{@code indexOfUnescaped} 的设计就是为了兜这个 corner case。
     */
    @Test
    void escapedQuoteInAnalysisDoesNotTriggerProtocolBoundary() {
        // 标准严格解析会正确处理 \" → 不会进 fallback
        String raw = "{\"active_skill_ids\": [], \"analysis\": \"术语\\\"risk\\\"指风险等级\"}";
        AnalysisResponseParser.ParsedSelection parsed = AnalysisResponseParser.tryParseSelection(raw);
        assertNotNull(parsed);
        assertEquals("术语\"risk\"指风险等级", parsed.analysis());
    }
}
