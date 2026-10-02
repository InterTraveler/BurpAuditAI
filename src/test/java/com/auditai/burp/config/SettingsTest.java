package com.auditai.burp.config;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link Settings} 单元测试：多配置列表、激活项切换、增删、共享引用语义。
 *
 * <p>所有配置都是用户自己新建的；本测试覆盖的是
 * 在这种"纯用户配置"模型下的 Settings 行为。</p>
 */
final class SettingsTest {

    /** 构造时使用合法激活名：activeConfig 的字段应与该条目一致。 */
    @Test
    void constructorAppliesActiveConfig() {
        AiConfig deepseek = new AiConfig("DeepSeek", "https://api.deepseek.com", "", "deepseek-v4-flash", 60, 2048);
        AiConfig ollama = new AiConfig("Ollama", "http://localhost:11434/v1", "", "", 60, 2048);
        Settings s = new Settings(List.of(deepseek, ollama), "DeepSeek", "my prompt");

        assertEquals("DeepSeek", s.activeName());
        assertEquals("my prompt", s.customPrompt());
        // activeConfig 是独立副本（共享引用语义），不是 deepseek 本身；只校验字段值。
        assertEquals(deepseek.getName(), s.activeConfig().getName());
        assertEquals(deepseek.getBaseUrl(), s.activeConfig().getBaseUrl());
        assertEquals(deepseek.getModel(), s.activeConfig().getModel());
        assertEquals(deepseek.getTimeoutSeconds(), s.activeConfig().getTimeoutSeconds());
        assertEquals(deepseek.getMaxTokens(), s.activeConfig().getMaxTokens());
    }

    /** 找不到激活名时回退到"无激活"状态。 */
    @Test
    void activeNameUnknownMeansNoActive() {
        AiConfig a = new AiConfig("A", "u1", "", "m1", 30, 1024);
        AiConfig b = new AiConfig("B", "u2", "", "m2", 30, 1024);
        Settings s = new Settings(List.of(a, b), "non-existent", "");
        assertNull(s.activeName());
        assertNull(s.activeConfig());
    }

    /** 列表为空是合法状态——首次安装 + 用户清空 都属于此情形。 */
    @Test
    void emptyListIsAllowed() {
        Settings s = new Settings(new ArrayList<>(), null, "");
        assertTrue(s.configs().isEmpty());
        assertNull(s.activeName());
        assertNull(s.activeConfig());
    }

    /**
     * 切换到另一条配置：{@link Settings#activeConfig()} 的引用被<b>整体替换</b>为新对象
     * ——读线程要么看到旧对象、要么看到新对象，永远不会"半新半旧"；
     * 旧对象在替换后不再被修改（这是避免撕裂读的核心保证）。
     */
    @Test
    void switchToReplacesActiveConfigReference() {
        AiConfig a = new AiConfig("A", "u1", "k1", "m1", 30, 1024);
        AiConfig b = new AiConfig("B", "u2", "k2", "m2", 60, 2048);
        Settings s = new Settings(List.of(a, b), "A", "");

        AiConfig beforeSwitch = s.activeConfig();
        s.switchTo("B");

        // 引用已被替换（不再是旧对象）
        assertNotSame(beforeSwitch, s.activeConfig());
        // 新对象字段为 B 的
        assertEquals("B", s.activeConfig().getName());
        assertEquals("u2", s.activeConfig().getBaseUrl());
        assertEquals("k2", new String(s.activeConfig().getApiKey()));
        assertEquals("m2", s.activeConfig().getModel());
        assertEquals(60, s.activeConfig().getTimeoutSeconds());
        assertEquals(2048, s.activeConfig().getMaxTokens());
        // 旧对象不再被修改：仍是 A 的字段（整体替换语义的天然保证）
        assertEquals("A", beforeSwitch.getName());
        assertEquals("u1", beforeSwitch.getBaseUrl());
    }

    /** 切换到不存在的名称：no-op，激活项不变。 */
    @Test
    void switchToUnknownIsNoOp() {
        Settings s = newSettings();
        String originalName = s.activeName();
        s.switchTo("不存在的配置");
        assertEquals(originalName, s.activeName());
    }

    /** addAndSwitchTo：把新配置加入列表并立即激活。 */
    @Test
    void addAndSwitchToActivatesNew() {
        Settings s = newSettings();
        int sizeBefore = s.configs().size();
        AiConfig fresh = new AiConfig("Fresh", "u", "k", "m", 30, 1024);
        s.addAndSwitchTo(fresh);

        assertEquals(sizeBefore + 1, s.configs().size());
        assertEquals("Fresh", s.activeName());
        assertEquals("u", s.activeConfig().getBaseUrl());
    }

    /** removeActive：删除当前激活，自动切到剩余第一条。 */
    @Test
    void removeActivePicksFirstRemaining() {
        AiConfig a = new AiConfig("A", "u1", "", "m1", 30, 1024);
        AiConfig b = new AiConfig("B", "u2", "", "m2", 30, 1024);
        AiConfig c = new AiConfig("C", "u3", "", "m3", 30, 1024);
        Settings s = new Settings(new ArrayList<>(List.of(a, b, c)), "B", "");

        boolean removed = s.removeActive();
        assertTrue(removed);
        assertEquals(2, s.configs().size());
        assertEquals("A", s.activeName());
        // 共享引用字段应已替换为 A 的字段
        assertEquals("u1", s.activeConfig().getBaseUrl());
    }

    /** removeActive：删掉最后一条时进入"无激活"状态，列表为空。 */
    @Test
    void removeActiveAllowsLastItem() {
        Settings s = new Settings(
                new ArrayList<>(List.of(new AiConfig("only", "u", "k", "m", 30, 1024))),
                "only", "");
        boolean removed = s.removeActive();
        assertTrue(removed);
        assertTrue(s.configs().isEmpty());
        assertNull(s.activeName());
        assertNull(s.activeConfig());
    }

    /** setCustomPrompt：null 应被规范化为空串。 */
    @Test
    void setCustomPromptNullNormalizesToEmpty() {
        Settings s = newSettings();
        s.setCustomPrompt(null);
        assertEquals("", s.customPrompt());
    }

    /** existingNames：UI 校验"重命名是否重名"时使用，应只含非空名称。 */
    @Test
    void existingNamesSkipsEmptyNames() {
        Settings s = new Settings(
                List.of(new AiConfig("A", "u", "", "m", 30, 1024),
                        new AiConfig("", "u", "", "m", 30, 1024),
                        new AiConfig("B", "u", "", "m", 30, 1024)),
                "A", "");
        assertTrue(s.existingNames().contains("A"));
        assertTrue(s.existingNames().contains("B"));
        assertFalse(s.existingNames().contains(""));
    }

    /** createDefault：首次安装 = 空列表、无激活项。 */
    @Test
    void createDefaultIsEmpty() {
        Settings s = Settings.createDefault();
        assertTrue(s.configs().isEmpty());
        assertNull(s.activeName());
        assertNull(s.activeConfig());
    }

    /** 构造时 activeConfig 是独立副本（不是列表里某个条目的引用）——
     *  这是"整体替换引用"语义的基础：列表条目与激活项是两个对象，
     *  切换/保存时通过构造新对象整体替换激活项引用，旧对象不再被修改。 */
    @Test
    void activeConfigIsStableIndependentReference() {
        AiConfig a = new AiConfig("A", "u", "", "m", 30, 1024);
        Settings s = new Settings(new ArrayList<>(List.of(a)), "A", "");
        AiConfig ref = s.activeConfig();
        assertNotSame(a, ref);
        // 字段初始拷贝自 a
        assertEquals(a.getName(), ref.getName());
        // 修改列表里的 a 不应影响 activeConfig（它们已经是不同对象）
        a.setBaseUrl("changed");
        assertEquals("u", ref.getBaseUrl());
    }

    /**
     * 切换 → 整体替换引用 → syncActiveEntry：保存前应保证列表条目和共享引用一致，
     * 避免"用户改了字段但保存时列表里仍是旧值"。
     */
    @Test
    void syncActiveEntryAlignsListAndActive() {
        AiConfig a = new AiConfig("A", "u1", "k1", "m1", 30, 1024);
        AiConfig b = new AiConfig("B", "u2", "k2", "m2", 60, 2048);
        Settings s = new Settings(new ArrayList<>(List.of(a, b)), "A", "");

        s.switchTo("B");
        // 新契约：整体替换引用，而不是原地改 activeConfig 字段
        s.replaceActive(new AiConfig("B", "u2", "newKeyForB", "m2", 60, 2048));

        s.syncActiveEntry();

        // 列表里 "B" 条目（不再是原 b 引用，syncActiveEntry 物化了一个新条目）
        // 的 apiKey 应已被更新为 "newKeyForB"
        AiConfig bEntryInList = s.configs().stream()
                .filter(c -> c.getName().equals("B"))
                .findFirst().orElseThrow();
        assertEquals("newKeyForB", new String(bEntryInList.getApiKey()));
        // 列表里 a 应当保持原样
        assertEquals("k1", new String(a.getApiKey()));
    }

    /** renameActive：列表中旧名条目被替换为新名条目，且共享引用字段保持不变。 */
    @Test
    void renameActiveReplacesListEntry() {
        AiConfig a = new AiConfig("OldName", "u", "k", "m", 30, 1024);
        AiConfig b = new AiConfig("B", "u2", "k2", "m2", 60, 2048);
        Settings s = new Settings(new ArrayList<>(List.of(a, b)), "OldName", "");

        // 新契约：整体替换引用（模拟 tryApplyFormToSettings 的 replaceActive 步骤）
        s.replaceActive(new AiConfig("OldName", "newUrl", "k", "m", 30, 1024));
        s.renameActive("NewName");

        assertEquals("NewName", s.activeName());
        // 列表里应只有一条 "NewName"，原 "OldName" 已消失
        assertEquals(2, s.configs().size());
        assertTrue(s.configs().stream().anyMatch(c -> c.getName().equals("NewName")));
        assertTrue(s.configs().stream().noneMatch(c -> c.getName().equals("OldName")));
        // 共享引用的字段应保留（重命名只改 name，不丢 baseUrl / apiKey 等）
        assertEquals("newUrl", s.activeConfig().getBaseUrl());
        assertEquals("NewName", s.activeConfig().getName());
    }

    /**
     * tryApplyFormToSettings 改名场景的回归测试：
     * replaceActive 会把 activeName 一并替换为新名，之后必须显式 removeConfigByName(旧名)，
     * 否则列表里残留旧名条目（"幽灵配置"，选中会复活旧字段）。syncActiveEntry 模拟
     * SettingsStore.save 内部的行为，把新名条目物化进列表。
     */
    @Test
    void replaceActiveThenRemoveOldNameClearsGhostEntry() {
        AiConfig a = new AiConfig("OldName", "u1", "k1", "m1", 30, 1024);
        AiConfig b = new AiConfig("B", "u2", "k2", "m2", 60, 2048);
        Settings s = new Settings(new ArrayList<>(List.of(a, b)), "OldName", "");

        // 模拟 SettingsPanel.tryApplyFormToSettings：buildAiConfigFromForm(newName) → replaceActive
        s.replaceActive(new AiConfig("NewName", "u1", "k1", "m1", 30, 1024));
        assertEquals("NewName", s.activeName());
        // 旧名条目必须被显式移除
        s.removeConfigByName("OldName");
        s.syncActiveEntry();

        assertEquals(2, s.configs().size());
        assertTrue(s.configs().stream().noneMatch(c -> c.getName().equals("OldName")));
        assertTrue(s.configs().stream().anyMatch(c -> c.getName().equals("NewName")));
        assertEquals("NewName", s.activeConfig().getName());
        assertEquals("u1", s.activeConfig().getBaseUrl());
    }

    // === 工具方法 ===

    /** 构造一个标准的、含 A/B 两条配置 + A 激活的 Settings。 */
    private static Settings newSettings() {
        return new Settings(
                new ArrayList<>(List.of(
                        new AiConfig("A", "u1", "k1", "m1", 30, 1024),
                        new AiConfig("B", "u2", "k2", "m2", 60, 2048))),
                "A", "");
    }
}
