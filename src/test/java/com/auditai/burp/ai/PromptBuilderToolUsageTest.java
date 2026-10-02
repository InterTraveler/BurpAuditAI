package com.auditai.burp.ai;

import com.auditai.burp.ai.PromptBuilder.Lang;
import com.auditai.burp.skills.Skill;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 单独验证 {@link PromptBuilder#buildSystemPromptForReplay} 真的把"可用工具"说明
 * 拼到了 system 段。
 */
class PromptBuilderToolUsageTest {

    @Test
    void systemPromptForReplay_zh_containsToolUsageGuide() {
        PromptBuilder builder = new PromptBuilder(() -> "你是一名安全测试专家", () -> Lang.ZH);
        String prompt = builder.buildSystemPromptForReplay(List.of(), 3);
        assertTrue(prompt.contains("重放工具"),
                "应包含「重放工具」说明头，实际：" + truncate(prompt, 300));
        assertTrue(prompt.contains("replay_request"),
                "应明确提到工具名 replay_request");
        assertTrue(prompt.contains("何时用") || prompt.contains("何时"),
                "应说明何时使用重放");
        assertTrue(prompt.contains("tool_calls"),
                "应包含 tool_calls 输出格式说明");
    }

    @Test
    void systemPromptForReplay_en_containsToolUsageGuide() {
        PromptBuilder builder = new PromptBuilder(() -> null, () -> Lang.EN);
        String prompt = builder.buildSystemPromptForReplay(List.of(), 3);
        assertTrue(prompt.contains("Replay tool"),
                "EN: should contain replay tool guide header");
        assertTrue(prompt.contains("replay_request"));
        assertTrue(prompt.contains("When to call"));
        assertTrue(prompt.contains("tool_calls"));
    }

    @Test
    void systemPromptForReplay_includesSkills() {
        // 验证 skills 也在 system 段里——确认 buildSystemPromptForReplay 不只是工具段
        Skill fakeSkill = new Skill(
                "sql-injection", "SQL", "💉", "SQL 注入",
                "本技能专注于 SQL 注入", null, 0, "sql-injection");
        PromptBuilder builder = new PromptBuilder(() -> null, () -> Lang.ZH);
        String prompt = builder.buildSystemPromptForReplay(List.of(fakeSkill), 3);
        assertTrue(prompt.contains("SQL 注入") || prompt.contains("SQL"));
        assertTrue(prompt.contains("重放工具"));
    }

    /** 工具使用指南必须在技能 prompt 之前——锁住"基础设施层先于场景精化"的拼装顺序。 */
    @Test
    void systemPromptForReplay_toolGuideAppearsBeforeSkills_zh() {
        Skill fakeSkill = new Skill(
                "sql-injection", "SQL", "💉", "SQL 注入",
                "本技能专注于 SQL 注入", null, 0, "sql-injection");
        PromptBuilder builder = new PromptBuilder(() -> null, () -> Lang.ZH);
        String prompt = builder.buildSystemPromptForReplay(List.of(fakeSkill), 3);
        int posToolGuide = prompt.indexOf("重放工具");
        int posSkill = prompt.indexOf("【技能：");
        assertTrue(posToolGuide > 0 && posSkill > 0,
                "工具说明和技能 prompt 都应存在，实际：" + truncate(prompt, 400));
        assertTrue(posToolGuide < posSkill,
                "工具使用指南应在【技能：】段之前（基础设施层先于场景精化），"
                        + "实际 toolGuide=" + posToolGuide + ", skill=" + posSkill);
    }

    @Test
    void systemPromptForReplay_toolGuideAppearsBeforeSkills_en() {
        Skill fakeSkill = new Skill(
                "sql-injection", "SQLi", "💉", "SQL Injection",
                "SQL injection focus", null, 0, "sql-injection");
        PromptBuilder builder = new PromptBuilder(() -> null, () -> Lang.EN);
        String prompt = builder.buildSystemPromptForReplay(List.of(fakeSkill), 3);
        int posToolGuide = prompt.indexOf("Replay tool");
        int posSkill = prompt.indexOf("[Skill: ");
        assertTrue(posToolGuide > 0 && posSkill > 0,
                "EN: tool guide and skill prompt should both exist, actual: " + truncate(prompt, 400));
        assertTrue(posToolGuide < posSkill,
                "EN: tool guide should appear before [Skill: ] section, actual toolGuide="
                        + posToolGuide + ", skill=" + posSkill);
    }

    private static String truncate(String s, int n) {
        return s.length() <= n ? s : s.substring(0, n) + "...";
    }
}
