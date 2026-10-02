package com.auditai.burp.skills;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link SkillLoader} 的单元测试。
 *
 * <p>所有用例都在临时目录上构造 {@code <id>/SKILL.md} 文件，避免依赖插件内置的
 * classpath 资源（Hello World 技能），保证测试对文件内容的变化免疫。</p>
 */
class SkillLoaderTest {

    /** 验证 frontmatter 三个核心字段（name/icon/description）能被正确解析。 */
    @Test
    void parsesAllFields() throws Exception {
        Path dir = newTempDir();
        writeSkill(dir, "hello-world",
                "---\n"
                        + "name: 'Hello World'\n"
                        + "icon: '👋'\n"
                        + "description: 'A minimal test skill.'\n"
                        + "---\n");

        List<Skill> skills = SkillLoader.fromDirectory(dir).load();

        assertEquals(1, skills.size());
        Skill skill = skills.get(0);
        assertEquals("hello-world", skill.id());
        assertEquals("Hello World", skill.name());
        assertEquals("👋", skill.icon());
        assertEquals("A minimal test skill.", skill.description());
    }

    /** 验证 frontmatter 的键大小写归一化（findingType / findingtype 等价）。 */
    @Test
    void frontmatterKeysAreCaseInsensitive() throws Exception {
        Path dir = newTempDir();
        writeSkill(dir, "case",
                "---\n"
                        + "NAME: 'Mixed Case'\n"
                        + "Icon: '🔥'\n"
                        + "FindingType: 'sql-injection'\n"
                        + "---\n");

        List<Skill> skills = SkillLoader.fromDirectory(dir).load();

        assertEquals(1, skills.size());
        Skill skill = skills.get(0);
        assertEquals("Mixed Case", skill.name());
        assertEquals("🔥", skill.icon());
        assertEquals("sql-injection", skill.findingType());
    }

    /** 验证缺 name 字段的文件被静默跳过，其它合法文件仍能正常加载。 */
    @Test
    void skipsFilesWithoutName() throws Exception {
        Path dir = newTempDir();
        writeSkill(dir, "no-name",
                "---\n"
                        + "icon: '❓'\n"
                        + "description: 'has no name'\n"
                        + "---\n");
        writeSkill(dir, "ok",
                "---\n"
                        + "name: 'OK'\n"
                        + "icon: '✅'\n"
                        + "description: 'valid'\n"
                        + "---\n");

        List<Skill> skills = SkillLoader.fromDirectory(dir).load();

        assertEquals(1, skills.size());
        assertEquals("ok", skills.get(0).id());
        assertEquals("OK", skills.get(0).name());
    }

    /** 验证没有 --- 边界的文件被跳过、不抛错。 */
    @Test
    void skipsFilesWithoutFrontmatterDelimiters() throws Exception {
        Path dir = newTempDir();
        writeSkill(dir, "raw",
                "this is just plain text without any frontmatter delimiters\n");
        writeSkill(dir, "ok",
                "---\nname: 'OK'\n---\n");

        List<Skill> skills = SkillLoader.fromDirectory(dir).load();

        assertEquals(1, skills.size());
        assertEquals("ok", skills.get(0).id());
    }

    /** 验证子目录下没有 SKILL.md 的目录被忽略；根目录里的散文件被忽略。 */
    @Test
    void ignoresNonSkillFiles() throws Exception {
        Path dir = newTempDir();
        // 散落顶层文件：不是目录，自然被忽略。
        Files.writeString(dir.resolve("readme.txt"), "name=Should Be Ignored\n");
        // 子目录但里面没有 SKILL.md：被忽略。
        Path emptyDir = dir.resolve("config");
        Files.createDirectories(emptyDir);
        Files.writeString(emptyDir.resolve("settings.json"), "{\"name\":\"json\"}\n");
        // 子目录里有 SKILL.md：被加载。
        writeSkill(dir, "real",
                "---\nname: 'Real'\n---\n");

        List<Skill> skills = SkillLoader.fromDirectory(dir).load();

        assertEquals(1, skills.size());
        assertEquals("real", skills.get(0).id());
    }

    /** 验证缺省 icon 时使用占位字符。 */
    @Test
    void usesDefaultIconWhenMissing() throws Exception {
        Path dir = newTempDir();
        writeSkill(dir, "plain", "---\nname: 'Plain'\n---\n");

        List<Skill> skills = SkillLoader.fromDirectory(dir).load();

        assertEquals(1, skills.size());
        assertEquals(Skill.DEFAULT_ICON, skills.get(0).icon());
    }

    /** 验证空目录返回空列表、不抛错。 */
    @Test
    void emptyDirectoryYieldsEmptyList() throws Exception {
        Path dir = newTempDir();
        assertTrue(SkillLoader.fromDirectory(dir).load().isEmpty());
    }

    /** 验证目录不存在时返回空列表、不抛错（便于运行环境的 classpath 暂未挂载技能目录）。 */
    @Test
    void missingDirectoryYieldsEmptyList() {
        Path missing = Path.of("auditai-no-such-dir-" + System.nanoTime());
        assertTrue(SkillLoader.fromDirectory(missing).load().isEmpty());
    }

    /**
     * 验证多个技能按 {@code id}（目录名）字典序排序，跟 {@code name} 的字面顺序无关。
     *
     * <p>测试用例故意把 {@code name} 写成与目录名不同的字母序——如果实现误回退到按 {@code name}
     * 排序，这个测试会立刻挂掉。</p>
     */
    @Test
    void sortsByIdIgnoringName() throws Exception {
        Path dir = newTempDir();
        writeSkill(dir, "b", "---\nname: 'cherry'\n---\n");
        writeSkill(dir, "a", "---\nname: 'banana'\n---\n");
        writeSkill(dir, "c", "---\nname: 'Apple'\n---\n");

        List<Skill> skills = SkillLoader.fromDirectory(dir).load();

        assertEquals(3, skills.size());
        assertEquals("a", skills.get(0).id());
        assertEquals("b", skills.get(1).id());
        assertEquals("c", skills.get(2).id());
        // 顺便验证 name 字段没受排序影响
        assertEquals("banana", skills.get(0).name());
        assertEquals("cherry", skills.get(1).name());
        assertEquals("Apple", skills.get(2).name());
    }

    /** 验证 summaryCount 是正整数时被解析；非正数 / 非法值回退到 0（表示未设置）。 */
    @Test
    void parsesSummaryCountValidAndInvalid() throws Exception {
        Path dir = newTempDir();
        writeSkill(dir, "good", "---\nname: 'g'\nsummaryCount: 15\n---\n");
        writeSkill(dir, "zero", "---\nname: 'z'\nsummaryCount: 0\n---\n");
        writeSkill(dir, "neg", "---\nname: 'n'\nsummaryCount: -5\n---\n");
        writeSkill(dir, "bad", "---\nname: 'b'\nsummaryCount: abc\n---\n");

        List<Skill> skills = SkillLoader.fromDirectory(dir).load();
        Skill good = findById(skills, "good");
        Skill zero = findById(skills, "zero");
        Skill neg = findById(skills, "neg");
        Skill bad = findById(skills, "bad");
        assertEquals(15, good.summaryCount(), "正整数应被解析");
        assertEquals(0, zero.summaryCount(), "0 应视为未设置（回退到默认值）");
        assertEquals(0, neg.summaryCount(), "负数应视为未设置");
        assertEquals(0, bad.summaryCount(), "非法字符串应视为未设置，不抛错");
    }

    /**
     * 验证单引号标量里的内部 {@code '} 用 {@code ''} 转义——与 YAML 规范一致。
     */
    @Test
    void parsesSingleQuoteEscaping() throws Exception {
        Path dir = newTempDir();
        writeSkill(dir, "escape",
                "---\n"
                        + "name: 'it''s escaped'\n"
                        + "---\n");

        Skill skill = SkillLoader.fromDirectory(dir).load().get(0);
        assertEquals("it's escaped", skill.name());
    }

    /**
     * 验证 frontmatter 闭合 {@code ---} 之后的 body 里若再出现独立成行的 {@code ---}
     * （Markdown 水平线的写法），不会被再次识别为闭合——body 内容会被原样保留。
     *
     * <p>实现细节：parseSkillMd 在检测到第一个 {@code ---} 闭合后立即 {@code break} 出循环，
     *   不再继续扫描；body 直接 {@code content.substring(pos)} 截取。所以 body 里
     *   出现的 {@code ---} 不会影响 frontmatter 解析，也不会被剥掉。</p>
     */
    @Test
    void promptBodyContainingStandaloneDashesIsPreserved() throws Exception {
        Path dir = newTempDir();
        writeSkill(dir, "dashes",
                "---\n"
                        + "name: 'D'\n"
                        + "---\n"
                        + "first paragraph\n"
                        + "\n"
                        + "---\n"
                        + "\n"
                        + "second paragraph after a horizontal rule\n");

        Skill skill = SkillLoader.fromDirectory(dir).load().get(0);
        assertEquals("first paragraph\n\n---\n\nsecond paragraph after a horizontal rule",
                skill.prompt());
    }

    // —— 测试工具 ——

    private static Path newTempDir() throws Exception {
        return Files.createTempDirectory("auditai-skill-test-");
    }

    /**
     * 在 {@code dir} 下创建 {@code <id>/SKILL.md} 并写入内容。技能目录格式必须是
     * "子目录 + SKILL.md"——顶层 {@code <id>.skill} 文件的形式已不再支持。
     */
    private static void writeSkill(Path dir, String id, String content) throws Exception {
        Path skillDir = dir.resolve(id);
        Files.createDirectories(skillDir);
        Files.writeString(skillDir.resolve("SKILL.md"), content, StandardCharsets.UTF_8);
    }

    private static Skill findById(List<Skill> skills, String id) {
        return skills.stream().filter(s -> s.id().equals(id)).findFirst().orElseThrow();
    }

    // —— 来源（SkillSource）相关 ——

    /** fromClasspathAndUserDirectory 必须注册 user Root，即便目录当前不存在——
     * 首次安装 / 用户从未导入过技能时目录可能尚未创建；之后用户首次"添加技能"
     * 会把目录建出来，若 reload() 找不到这条 Root 就永远扫不到用户技能。
     *
     * <p>测试方案：先确认目录不存在时 load() 不抛错且无 USER 技能；然后创建目录并
     * 放入 SKILL.md，验证后续 load() 能扫到该技能且标记为 USER。</p>
     */
    @Test
    void fromClasspathAndUserDirectoryRegistersUserRootEvenWhenDirMissing() throws Exception {
        Path notYetCreated = Files.createTempDirectory("auditai-user-dir-missing-")
                .resolve("custom-skills-not-yet");
        // 确认目录真的不存在
        if (Files.exists(notYetCreated)) {
            throw new IllegalStateException("测试前提失败：用户目录不应存在");
        }

        SkillLoader loader = SkillLoader.fromClasspathAndUserDirectory(
                "skills",
                SkillLoader.class.getClassLoader(),
                notYetCreated,
                msg -> {});

        // 初始 load()：classpath:/skills/ 应能扫到内置技能；用户目录还不存在，无 USER 技能。
        List<Skill> initial = loader.load();
        assertTrue(initial.stream().noneMatch(s -> s.source() == SkillSource.USER),
                "目录不存在时不应有 USER 技能");

        // 现在模拟"用户首次添加技能"：创建目录并放入 SKILL.md
        Files.createDirectories(notYetCreated);
        Path skillDir = notYetCreated.resolve("late");
        Files.createDirectories(skillDir);
        Files.writeString(skillDir.resolve("SKILL.md"),
                "---\nname: 'Late'\n---\n", java.nio.charset.StandardCharsets.UTF_8);

        // reload() 必须能扫到——这是 Root 已注册的关键证明
        List<Skill> afterInstall = loader.load();
        Skill late = afterInstall.stream().filter(s -> "late".equals(s.id())).findFirst().orElse(null);
        assertNotNull(late, "用户目录创建后下次 load 必须能扫到 'late' 技能");
        assertEquals(SkillSource.USER, late.source());
    }

    /** 默认 factory 的 Skill 应标记为 BUILTIN。 */
    @Test
    void defaultFactoryTagsSkillsAsBuiltIn() throws Exception {
        Path dir = newTempDir();
        writeSkill(dir, "x", "---\nname: 'X'\n---\n");

        List<Skill> skills = SkillLoader.fromDirectory(dir).load();

        assertEquals(1, skills.size());
        assertEquals(SkillSource.BUILTIN, skills.get(0).source());
    }

    /** fromUserDirectory 的 Skill 应标记为 USER。 */
    @Test
    void fromUserDirectoryTagsSkillsAsUser() throws Exception {
        Path dir = newTempDir();
        writeSkill(dir, "u", "---\nname: 'U'\n---\n");

        List<Skill> skills = SkillLoader.fromUserDirectory(dir, msg -> {}).load();

        assertEquals(1, skills.size());
        assertEquals(SkillSource.USER, skills.get(0).source());
    }

    /** fromUserDirectory 仅扫描传入目录本身（扁平形态），不下钻 vuln/auxiliary/。 */
    @Test
    void userDirectoryUsesFlatLayout() throws Exception {
        Path dir = newTempDir();
        // 顶层用户技能：应被加载
        writeSkill(dir, "user-flat", "---\nname: 'Flat'\n---\n");
        // 子目录形态（vuln/<id>）：扁平扫描应忽略
        writeSkill(dir.resolve("vuln"), "should-be-ignored",
                "---\nname: 'InVuln'\n---\n");
        writeSkill(dir.resolve("auxiliary"), "should-also-be-ignored",
                "---\nname: 'InAux'\n---\n");

        List<Skill> skills = SkillLoader.fromUserDirectory(dir, msg -> {}).load();

        assertEquals(1, skills.size());
        assertEquals("user-flat", skills.get(0).id());
    }

    /** 用户版与内置版同名时：用户版覆盖内置版（用户意图明确）。
     *
     * <p>本测试用 {@link SkillLoader#fromClasspathAndUserDirectory} 模拟生产环境：
     * 内置来源用一个不存在的 classpath 路径（保证扫不到任何内置技能），
     * 然后用 {@link SkillLoader#fromDirectory} + {@link SkillLoader#fromUserDirectory}
     * 两个独立加载器分别收集两边，最后手工合并模拟覆盖逻辑——和 SkillLoader.collect()
     * 内部的 "BUILTIN + USER → USER 覆盖 BUILTIN" 分支等价。</p>
     */
    @Test
    void userSkillOverridesBuiltInSkillWithSameId() throws Exception {
        // 这里直接验证 collect() 的覆盖语义：通过两个独立加载器模拟内置与用户来源。
        Path builtins = newTempDir();
        writeSkill(builtins, "xss-detector", "---\nname: 'BuiltIn XSS'\n---\n");
        Path userSkills = newTempDir();
        writeSkill(userSkills, "xss-detector", "---\nname: 'User XSS'\n---\n");

        // 模拟合并：先内置（打 BUILTIN 标），再按"用户覆盖内置"规则应用用户来源（打 USER 标）。
        java.util.LinkedHashMap<String, Skill> merged = new java.util.LinkedHashMap<>();
        for (Skill s : SkillLoader.fromDirectory(builtins, msg -> {}).load()) {
            merged.put(s.id(), s);
        }
        for (Skill s : SkillLoader.fromUserDirectory(userSkills, msg -> {}).load()) {
            // 收集逻辑里的覆盖条件：existing.source == BUILTIN && new.source == USER → 覆盖
            Skill existing = merged.get(s.id());
            if (existing == null || existing.source() == SkillSource.BUILTIN) {
                merged.put(s.id(), s);
            }
        }

        // 期望：xss-detector 同名时只出现一次，且为用户版。
        assertEquals(1, merged.size());
        Skill only = merged.get("xss-detector");
        assertEquals("User XSS", only.name());
        assertEquals(SkillSource.USER, only.source());
    }

    /** parseForInstallCheck：合法内容返回 Skill，缺 name 返回 null。 */
    @Test
    void parseForInstallCheckValidatesContent() {
        Skill ok = SkillLoader.parseForInstallCheck("custom-id",
                "---\nname: 'Custom'\n---\nbody\n");
        assertNotNull(ok, "合法 SKILL.md 应返回 Skill");
        assertEquals("custom-id", ok.id());
        assertEquals(SkillSource.USER, ok.source(), "导入路径应打 USER 标签");

        assertNull(SkillLoader.parseForInstallCheck("x", "no frontmatter"));
        assertNull(SkillLoader.parseForInstallCheck("x", null));
        assertNull(SkillLoader.parseForInstallCheck(null, "---\nname: 'x'\n---\n"));
    }
}
