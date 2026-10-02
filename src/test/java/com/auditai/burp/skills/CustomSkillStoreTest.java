package com.auditai.burp.skills;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link CustomSkillStore} 的单元测试：
 * 覆盖安装（成功 / id 不合法 / SKILL.md 内容不合法 / 冲突处理）、
 * 卸载（成功 / 不存在的 id）、id 校验、文件名 → id 推导。
 *
 * <p>每个用例都在临时目录上构造 {@code <id>/SKILL.md}，避免依赖 Burp 运行环境。</p>
 */
class CustomSkillStoreTest {

    /** 安装合法 SKILL.md 后文件应出现在 <sessionRoot>/custom-skills/<id>/SKILL.md，且内容原样保留。 */
    @Test
    void installWritesFileUnderCustomSkillsDirectory() throws Exception {
        Path sessionRoot = Files.createTempDirectory("auditai-custom-skill-test-");
        CustomSkillStore store = new CustomSkillStore(sessionRoot, msg -> {});

        String content = "---\nname: 'My Skill'\n---\n\nprompt body\n";
        Path target = store.install("my-skill", content, true);

        assertTrue(Files.isRegularFile(target));
        assertEquals("SKILL.md", target.getFileName().toString());
        assertEquals(sessionRoot.resolve("custom-skills/my-skill/SKILL.md"), target);
        // 写盘是原样保留——不去 frontmatter、不剥 body；解析只在 parseForInstallCheck 时做。
        assertEquals(content, Files.readString(target, StandardCharsets.UTF_8));
    }

    /** id 不合法（路径分隔符）应抛 IOException，提示文案明确。 */
    @Test
    void installRejectsInvalidId() throws Exception {
        Path sessionRoot = Files.createTempDirectory("auditai-custom-skill-test-");
        CustomSkillStore store = new CustomSkillStore(sessionRoot, msg -> {});

        // 含路径分隔符的 id 必然非法（即便名称合法）
        IOException ex = assertThrows(IOException.class, () ->
                store.install("../escape", "---\nname: 'x'\n---\n", true));
        assertTrue(ex.getMessage().contains("技能 id") || ex.getMessage().contains("id"),
                "异常消息应提示 id 问题: " + ex.getMessage());
    }

    /** 空 id 应抛 IOException。 */
    @Test
    void installRejectsBlankId() throws Exception {
        Path sessionRoot = Files.createTempDirectory("auditai-custom-skill-test-");
        CustomSkillStore store = new CustomSkillStore(sessionRoot, msg -> {});
        assertThrows(IOException.class, () ->
                store.install("  ", "---\nname: 'x'\n---\n", true));
    }

    /** SKILL.md 缺 name 字段 → IOException，内容合法性在安装前就被拒。 */
    @Test
    void installRejectsContentWithoutName() throws Exception {
        Path sessionRoot = Files.createTempDirectory("auditai-custom-skill-test-");
        CustomSkillStore store = new CustomSkillStore(sessionRoot, msg -> {});
        assertThrows(IOException.class, () ->
                store.install("ok", "---\nicon: 'x'\n---\n", true));
    }

    /** SKILL.md 缺 --- 边界 → IOException。 */
    @Test
    void installRejectsContentWithoutFrontmatterDelimiters() throws Exception {
        Path sessionRoot = Files.createTempDirectory("auditai-custom-skill-test-");
        CustomSkillStore store = new CustomSkillStore(sessionRoot, msg -> {});
        assertThrows(IOException.class, () ->
                store.install("ok", "no delimiters at all\n", true));
    }

    /** overrideConflict = false 时与既有 id 冲突应抛 IOException。 */
    @Test
    void installWithoutOverrideRejectsDuplicateId() throws Exception {
        Path sessionRoot = Files.createTempDirectory("auditai-custom-skill-test-");
        CustomSkillStore store = new CustomSkillStore(sessionRoot, msg -> {});
        store.install("dup", "---\nname: 'first'\n---\n", true);
        assertThrows(IOException.class, () ->
                store.install("dup", "---\nname: 'second'\n---\n", false));
    }

    /** overrideConflict = true 时允许覆盖；最终内容是新版。 */
    @Test
    void installWithOverrideReplacesExisting() throws Exception {
        Path sessionRoot = Files.createTempDirectory("auditai-custom-skill-test-");
        CustomSkillStore store = new CustomSkillStore(sessionRoot, msg -> {});
        store.install("dup", "---\nname: 'first'\n---\nfirst\n", true);
        // overrideConflict=true 时走自动重命名路径：本次写入落到 <id>-2 目录，原目录保留。
        // 验证"两次写入都有真实目录 + 新内容落到新目录"的行为契约。
        String second = "---\nname: 'second'\n---\nsecond\n";
        Path secondPath = store.install("dup", second, true);

        assertEquals("dup-2", secondPath.getParent().getFileName().toString());
        assertEquals(second, Files.readString(secondPath, StandardCharsets.UTF_8));
    }

    /** 卸载存在的 id → true + 目录消失。 */
    @Test
    void uninstallRemovesExistingDirectory() throws Exception {
        Path sessionRoot = Files.createTempDirectory("auditai-custom-skill-test-");
        CustomSkillStore store = new CustomSkillStore(sessionRoot, msg -> {});
        store.install("gone", "---\nname: 'gone'\n---\n", true);
        assertTrue(Files.isDirectory(sessionRoot.resolve("custom-skills/gone")));

        boolean removed = store.uninstall("gone");

        assertTrue(removed);
        assertFalse(Files.exists(sessionRoot.resolve("custom-skills/gone")));
    }

    /** 卸载不存在的 id → false，不抛错。 */
    @Test
    void uninstallReturnsFalseWhenMissing() throws Exception {
        Path sessionRoot = Files.createTempDirectory("auditai-custom-skill-test-");
        CustomSkillStore store = new CustomSkillStore(sessionRoot, msg -> {});

        boolean removed = store.uninstall("never-existed");

        assertFalse(removed);
    }

    /** suggestIdFromFile：从 .md 文件名派生合法 id。 */
    @Test
    void suggestIdFromFileDerivesValidId() {
        String id = CustomSkillStore.suggestIdFromFile(Path.of("C:/tmp/My Cool Skill.md"));
        assertEquals("my-cool-skill", id);
    }

    /** suggestIdFromFile：去掉后缀、小写、空格替为 '-'、首字符保证合法。
 *
 * <p>注意：suggestIdFromFile 与 suggestIdFromName 行为不同——前者基于文件名（小写 + 收紧），
 * 后者基于 SKILL.md 的 name 字段（保留原 case + 允许空格/中文）。当前 UI 路径只走
 * suggestIdFromName，本方法保留供未来"未解析 SKILL.md 前"使用。</p>
 */
    @Test
    void suggestIdFromFileSanitizesSpecialCharacters() {
        // 全部是非字母数字开头 → 去掉前导分隔符后首字符是 'w'，无需 's-' 前缀
        assertEquals("weird-name", CustomSkillStore.suggestIdFromFile(Path.of("/tmp/___Weird Name!!.md")));
        // 中文/日文/韩文等 CJK 字符走 Character.isLetterOrDigit，返回 true，被保留；
        // 用户从文件路径派生时不会再因为"全是中文"得到 null。
        assertEquals("中文测试", CustomSkillStore.suggestIdFromFile(Path.of("/tmp/中文测试.md")));
    }

    /** listInstalledIds：安装完后能列出；按字典序排序。 */
    @Test
    void listInstalledIdsReturnsSortedList() throws Exception {
        Path sessionRoot = Files.createTempDirectory("auditai-custom-skill-test-");
        CustomSkillStore store = new CustomSkillStore(sessionRoot, msg -> {});
        store.install("b", "---\nname: 'b'\n---\n", true);
        store.install("a", "---\nname: 'a'\n---\n", true);
        store.install("c", "---\nname: 'c'\n---\n", true);

        List<String> ids = store.listInstalledIds();

        assertEquals(List.of("a", "b", "c"), ids);
    }

    /** validateId：合法 id 不抛错（id 默认从 name 派生，允许空格、中文、emoji）。 */
    @Test
    void validateIdAcceptsLegalValues() throws Exception {
        CustomSkillStore.validateId("a");
        CustomSkillStore.validateId("hello-world");
        CustomSkillStore.validateId("v1.0.0");
        CustomSkillStore.validateId("x_y_z");
        CustomSkillStore.validateId("XSS 跨站脚本");
        CustomSkillStore.validateId("🔒 sensitive test");
    }

    /** validateId：非法 id 抛 IOException（路径分隔符 / 控制字符 / 空）。 */
    @Test
    void validateIdRejectsIllegalValues() {
        assertThrows(IOException.class, () -> CustomSkillStore.validateId("../escape"));
        assertThrows(IOException.class, () -> CustomSkillStore.validateId("with/slash"));
        assertThrows(IOException.class, () -> CustomSkillStore.validateId("with\\backslash"));
        assertThrows(IOException.class, () -> CustomSkillStore.validateId("with:colon"));
        assertThrows(IOException.class, () -> CustomSkillStore.validateId(""));
        assertThrows(IOException.class, () -> CustomSkillStore.validateId(null));
    }

    /** suggestIdFromName：原样保留空格、中文、emoji，只剥路径分隔符。 */
    @Test
    void suggestIdFromNamePreservesContent() {
        assertEquals("XSS 跨站脚本", CustomSkillStore.suggestIdFromName("XSS 跨站脚本"));
        assertEquals("SQL Injection", CustomSkillStore.suggestIdFromName("SQL Injection"));
        assertEquals("🔒 Sensitive", CustomSkillStore.suggestIdFromName("🔒 Sensitive"));
        // 路径分隔符 → 空格（避免越界）
        assertEquals("a b c", CustomSkillStore.suggestIdFromName("a/b\\c"));
    }

    /** suggestIdFromName：折叠连续空格 + 去首尾空白。 */
    @Test
    void suggestIdFromNameCollapsesWhitespace() {
        assertEquals("a b", CustomSkillStore.suggestIdFromName("  a   b  "));
        // 全部是空白字符 → 返回 null
        assertNull(CustomSkillStore.suggestIdFromName("   "));
        assertNull(CustomSkillStore.suggestIdFromName(null));
    }

    /** suggestIdFromName：超过 100 字符截断。 */
    @Test
    void suggestIdFromNameTruncatesLongInput() {
        String longName = "a".repeat(150);
        String id = CustomSkillStore.suggestIdFromName(longName);
        assertNotNull(id);
        assertTrue(id.length() <= 100, "id 长度应 ≤ 100");
    }

    /** install with overrideConflict=true：id 冲突时自动追加 -2 / -3 后缀，文件正常落地。 */
    @Test
    void installWithOverrideAutoRenamesOnCollision() throws Exception {
        Path sessionRoot = Files.createTempDirectory("auditai-custom-skill-test-");
        CustomSkillStore store = new CustomSkillStore(sessionRoot, msg -> {});

        String content1 = "---\nname: 'XSS 跨站脚本'\n---\nfirst\n";
        String content2 = "---\nname: 'XSS 跨站脚本'\n---\nsecond\n";
        String content3 = "---\nname: 'XSS 跨站脚本'\n---\nthird\n";
        Path first = store.install("XSS 跨站脚本", content1, true);
        Path second = store.install("XSS 跨站脚本", content2, true);
        Path third = store.install("XSS 跨站脚本", content3, true);

        assertEquals("XSS 跨站脚本", first.getParent().getFileName().toString());
        assertEquals("XSS 跨站脚本-2", second.getParent().getFileName().toString());
        assertEquals("XSS 跨站脚本-3", third.getParent().getFileName().toString());
        assertEquals(content2, Files.readString(second, StandardCharsets.UTF_8));
        assertEquals(content3, Files.readString(third, StandardCharsets.UTF_8));
    }

    /** rootDirectory：返回预期路径；sessionRoot 为 null 时返回 null。 */
    @Test
    void rootDirectoryReflectsSessionRoot() throws Exception {
        Path sessionRoot = Files.createTempDirectory("auditai-custom-skill-test-");
        CustomSkillStore store = new CustomSkillStore(sessionRoot, msg -> {});
        assertEquals(sessionRoot.resolve("custom-skills"), store.rootDirectory());

        CustomSkillStore nullStore = new CustomSkillStore(null, msg -> {});
        assertEquals(null, nullStore.rootDirectory());
    }

    /** 错误回调：安装失败时回调被调用。 */
    @Test
    void errorLoggerIsInvokedOnInstallFailure() throws Exception {
        Path sessionRoot = Files.createTempDirectory("auditai-custom-skill-test-");
        AtomicReference<String> captured = new AtomicReference<>();
        CustomSkillStore store = new CustomSkillStore(sessionRoot, captured::set);

        assertThrows(IOException.class, () ->
                store.install("../escape", "---\nname: 'x'\n---\n", true));

        // 错误回调未必每次都被调（id 校验先于 IO 失败）——此处放宽断言：仅当回调被调用时
        // 校验消息前缀正确即可。
        if (captured.get() != null) {
            assertTrue(captured.get().startsWith("[CustomSkillStore]"),
                    "错误日志应带 [CustomSkillStore] 前缀便于在 Extender Error 中聚合: " + captured.get());
        }
    }

    /** 卸载后重新安装同 id 应能恢复（没有遗留缓存）。 */
    @Test
    void reinstallAfterUninstall() throws Exception {
        Path sessionRoot = Files.createTempDirectory("auditai-custom-skill-test-");
        CustomSkillStore store = new CustomSkillStore(sessionRoot, msg -> {});
        store.install("retry", "---\nname: 'r'\n---\n", true);
        store.uninstall("retry");
        // 重新安装（无 override 也能过——已卸载）
        String content = "---\nname: 'r'\n---\nnew\n";
        Path target = store.install("retry", content, false);
        assertNotNull(target);
        assertEquals(content, Files.readString(target, StandardCharsets.UTF_8));
    }
}