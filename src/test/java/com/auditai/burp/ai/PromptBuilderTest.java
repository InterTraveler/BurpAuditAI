package com.auditai.burp.ai;

import com.auditai.burp.ai.PromptBuilder.Lang;
import com.auditai.burp.skills.Skill;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link PromptBuilder} 系统提示词取值与技能片段拼装单元测试。
 *
 * <p>验证：</p>
 * <ul>
 *   <li>"自定义 → 默认（资源文件 / 内置）"的优先级与回退；</li>
 *   <li>输出格式后缀（强制 JSON）始终追加，不被用户内容覆盖；</li>
 *   <li>{@code buildSystemPromptWithSkills} 按入参顺序拼接技能 prompt 片段，缺省跳过空 prompt；</li>
 *   <li><b>语言一致性</b>：EN 模式下基础提示词、输出格式后缀与技能目录/片段指令
 *       应全部为英文，输出指令保持语言一致。</li>
 * </ul>
 */
class PromptBuilderTest {

    /** 设置了自定义提示词时，应优先返回自定义内容，并追加输出格式后缀（强制 JSON）。 */
    @Test
    void systemPrompt_prefersCustom() {
        PromptBuilder builder = new PromptBuilder(() -> "这是一条自定义系统提示词", () -> Lang.ZH);

        String prompt = builder.buildSystemPrompt();
        // 1. 自定义内容必须保留（不能被后缀覆盖）。
        assertTrue(prompt.startsWith("这是一条自定义系统提示词"),
                "系统提示词应以自定义内容开头，实际为：" + prompt);
        // 2. 输出格式后缀必须追加（约束 JSON 输出），不能漏。
        assertTrue(prompt.contains("强制 JSON") && prompt.contains("\"analysis\""),
                "系统提示词应追加『输出格式 JSON』后缀，实际为：" + prompt);
    }

    /** 未设置自定义（默认空）时，应回退到默认提示词（资源文件或内置兜底）。 */
    @Test
    void systemPrompt_fallsBackToDefault() {
        PromptBuilder builder = new PromptBuilder(() -> null, () -> Lang.ZH);

        String prompt = builder.buildSystemPrompt();
        // 默认提示词是面向 Web 安全分析的专家指令，应包含安全分析关键词
        assertTrue(prompt.contains("Web 应用安全"), "默认提示词应包含安全分析定位，实际为：" + prompt);
    }

    /** 技能 prompt 片段按入参顺序拼到 system 段，输出格式后缀始终在最后。 */
    @Test
    void systemPromptWithSelectedSkills_appendsInOrder() {
        PromptBuilder builder = new PromptBuilder(() -> "基础提示词", () -> Lang.ZH);

        Skill first = new Skill("sql-injection", "SQL 注入", "💉", "", "关注 UNION SELECT", null, 0);
        Skill second = new Skill("xss-detector", "XSS 检测", "🧨", "", "关注未转义回显", null, 0);
        String prompt = builder.buildSystemPromptWithSelectedSkills(List.of(first, second));

        int posFirst = prompt.indexOf("关注 UNION SELECT");
        int posSecond = prompt.indexOf("关注未转义回显");
        int posSuffix = prompt.indexOf("强制 JSON");
        assertTrue(posFirst > 0 && posSecond > 0, "两个技能 prompt 都应拼到 system 段");
        assertTrue(posFirst < posSecond, "技能片段应按入参顺序拼接");
        assertTrue(posSecond < posSuffix, "输出格式后缀应始终在最后");
    }

    /** 选中的技能没有 prompt（只有 userContext）→ system 段不引入噪声。 */
    @Test
    void systemPromptWithSelectedSkills_skipsEmptyPrompt() {
        PromptBuilder builder = new PromptBuilder(() -> "基础", () -> Lang.ZH);

        Skill noPrompt = new Skill("a", "A", "❓", "", "", "仅 userContext", 0);
        Skill withPrompt = new Skill("b", "B", "🅱", "", "B 的关注点", null, 0);
        String prompt = builder.buildSystemPromptWithSelectedSkills(List.of(noPrompt, withPrompt));

        assertTrue(!prompt.contains("【技能：A】"),
                "无 prompt 的技能不应在 system 段出现片段");
        assertTrue(prompt.contains("【技能：B】") && prompt.contains("B 的关注点"),
                "有 prompt 的技能正常出现");
    }

    /** 阶段 1：技能选择 system 提示词应包含候选技能的 catalog（id + name + 用途），
     *  且不包含任何技能的具体 prompt 片段。 */
    @Test
    void systemPromptForSkillSelection_includesCatalog() {
        PromptBuilder builder = new PromptBuilder(() -> "基础", () -> Lang.ZH);

        Skill skill = new Skill("sql-injection", "SQL 注入", "💉", "检测 SQL 注入痕迹", "不应被注入到 system", null, 0);
        String prompt = builder.buildSystemPromptForSkillSelection(List.of(skill));

        assertTrue(prompt.contains("【可选技能】"), "应包含『可选技能』catalog 段");
        assertTrue(prompt.contains("id: sql-injection") && prompt.contains("name: SQL 注入"),
                "应列出候选技能 id + name");
        assertTrue(prompt.contains("用途: 检测 SQL 注入痕迹"),
                "应使用 description 作为『用途』");
        assertTrue(!prompt.contains("不应被注入到 system"),
                "阶段 1 不应注入技能的具体 prompt 片段（那是阶段 2 的事）");
        assertTrue(prompt.contains("active_skill_ids"),
                "阶段 1 输出格式应明确要求 active_skill_ids 字段");
    }

    /**
     * {@link PromptBuilder} 应在每次调用时实时读 Supplier：便于设置界面
     * 改完提示词后无需重建分析器即可生效。
     */
    @Test
    void customPromptSupplierIsCalledEachTime() {
        AtomicReference<String> holder = new AtomicReference<>("第一版提示词");
        PromptBuilder builder = new PromptBuilder(holder::get, () -> Lang.ZH);

        assertTrue(builder.buildSystemPrompt().startsWith("第一版提示词"));
        holder.set("第二版提示词");
        assertTrue(builder.buildSystemPrompt().startsWith("第二版提示词"));
    }

    // ========== EN 模式语言一致性 ==========

    /** EN 模式下，基础默认提示词与输出格式后缀应全为英文，下发指令保持语言一致。 */
    @Test
    void englishMode_usesEnglishDefaultAndFormat() {
        PromptBuilder builder = new PromptBuilder(() -> null, () -> Lang.EN);

        String prompt = builder.buildSystemPrompt();
        assertTrue(prompt.contains("Reply in English"),
                "EN 模式默认提示词应要求英文回答，实际：" + prompt);
        assertTrue(prompt.contains("[Risk points]"),
                "EN 模式段落结构应为 [Risk points]，实际：" + prompt);
        assertTrue(prompt.contains("[Output format (strict JSON)]")
                        || prompt.contains("Output one and only one valid JSON object"),
                "EN 模式应追加英文输出格式后缀，实际：" + prompt);
        assertFalse(prompt.contains("【风险点】") || prompt.contains("强制 JSON"),
                "EN 模式不应残留中文结构指令/中文格式后缀，实际：" + prompt);
    }

    /** EN 模式下自定义提示词同样追加英文输出格式后缀。 */
    @Test
    void englishMode_customPromptStillGetsEnglishFormatSuffix() {
        PromptBuilder builder = new PromptBuilder(() -> "Custom English system prompt", () -> Lang.EN);

        String prompt = builder.buildSystemPrompt();
        assertTrue(prompt.startsWith("Custom English system prompt"), "自定义内容应保留：" + prompt);
        assertTrue(prompt.contains("strict JSON"), "应追加英文 JSON 格式约束，实际：" + prompt);
        assertFalse(prompt.contains("强制 JSON"), "英文模式不应出现中文格式后缀，实际：" + prompt);
    }

    /** EN 模式下阶段 1 技能目录与说明指令应为英文。 */
    @Test
    void englishMode_skillSelectionHeaderAndUsageInEnglish() {
        PromptBuilder builder = new PromptBuilder(() -> "基础", () -> Lang.EN);

        Skill skill = new Skill("sql-injection", "SQL Injection", "💉", "detect SQL injection traces", "", null, 0);
        String prompt = builder.buildSystemPromptForSkillSelection(List.of(skill));

        assertTrue(prompt.contains("[Optional skills]"),
                "EN 模式技能目录标题应为 [Optional skills]，实际：" + prompt);
        assertTrue(prompt.contains("purpose: detect SQL injection traces"),
                "EN 模式用途字段应为 purpose:，实际：" + prompt);
        assertTrue(prompt.contains("active_skill_ids"), "阶段 1 输出格式仍要求 active_skill_ids：" + prompt);
        assertFalse(prompt.contains("【可选技能】") || prompt.contains("用途:"),
                "EN 模式不应残留中文目录标题/用途标签，实际：" + prompt);
    }

    /** EN 模式下阶段 2 技能片段标题应为 [Skill: xxx]。 */
    @Test
    void englishMode_selectedSkillHeaderInEnglish() {
        PromptBuilder builder = new PromptBuilder(() -> "基础", () -> Lang.EN);

        Skill withPrompt = new Skill("b", "B", "🅱", "", "B 的关注点", null, 0);
        String prompt = builder.buildSystemPromptWithSelectedSkills(List.of(withPrompt));

        assertTrue(prompt.contains("[Skill: B]"),
                "EN 模式技能片段标题应为 [Skill: B]，实际：" + prompt);
        assertFalse(prompt.contains("【技能："), "EN 模式不应残留中文技能片段标题，实际：" + prompt);
    }

    /** languageSupplier 在每次构造时实时取,模拟"用户切语言后下次分析按新语言"的核心场景。 */
    @Test
    void languageSupplierIsCalledEachTime() {
        AtomicReference<Lang> holder = new AtomicReference<>(Lang.ZH);
        PromptBuilder builder = new PromptBuilder(() -> null, holder::get);

        assertTrue(builder.buildSystemPrompt().contains("【风险点】"),
                "ZH 模式应输出中文结构指令");
        holder.set(Lang.EN);
        assertTrue(builder.buildSystemPrompt().contains("[Risk points]"),
                "EN 模式应输出英文结构指令");
    }
}
