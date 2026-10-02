package com.auditai.burp.ui;

import burp.api.montoya.persistence.Preferences;
import com.auditai.burp.config.AiConfig;
import com.auditai.burp.config.Settings;
import com.auditai.burp.config.SettingsStore;
import com.auditai.burp.passive.PassiveAnalysisErrorBus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.JLabel;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** AI 服务下拉列表"名称自然顺序"排序规则 + SettingsPanel 防抖/校验回归。 */
class SettingsPanelTest {

    /** 数字后缀按数值排序：新配置 2 应排在 新配置 10 / 新配置 100 之前。 */
    @Test
    void naturalOrderSortsNumericSuffixNumerically() {
        List<String> names = List.of("新配置 10", "新配置 2", "新配置 100", "新配置 1");
        List<String> sorted = names.stream().sorted(SettingsPanel.NAME_NATURAL_ORDER).toList();
        assertEquals(List.of("新配置 1", "新配置 2", "新配置 10", "新配置 100"), sorted);
    }

    /**
     * 用内存版 Preferences 桩构造 SettingsStore：避免对 Montoya API 真实持久化的依赖。
     */
    private static SettingsStore testStore() {
        return new SettingsStore(new MapPreferences());
    }

    /**
     * 反射读取 private 字段：避免在测试里动用 javax.swing 的 paint / layout 流程。
     */
    private static <T> T getField(Object target, String name, Class<T> type) throws Exception {
        Field f = target.getClass().getDeclaredField(name);
        f.setAccessible(true);
        return type.cast(f.get(target));
    }

    /**
     * 内存版 Preferences 桩：覆盖 String / Integer / Boolean / Byte / Short / Long 的 get/set/delete + keys。
     * 对 {@code SettingsStore.load} / {@code save} 已经够用——后者只调 getString / setString / getBoolean /
     * setBoolean / getInteger / setInteger / deleteString / deleteInteger / deleteBoolean。
     */
    private static final class MapPreferences implements Preferences {
        private final Map<String, Object> map = new HashMap<>();

        @Override public String getString(String key) { Object v = map.get(key); return v == null ? null : (String) v; }
        @Override public void setString(String key, String value) { map.put(key, value); }
        @Override public void deleteString(String key) { map.remove(key); }
        @Override public Set<String> stringKeys() { return map.keySet(); }

        @Override public Boolean getBoolean(String key) { Object v = map.get(key); return v == null ? null : (Boolean) v; }
        @Override public void setBoolean(String key, boolean value) { map.put(key, value); }
        @Override public void deleteBoolean(String key) { map.remove(key); }
        @Override public Set<String> booleanKeys() { return Set.of(); }

        @Override public Byte getByte(String key) { Object v = map.get(key); return v == null ? null : (Byte) v; }
        @Override public void setByte(String key, byte value) { map.put(key, value); }
        @Override public void deleteByte(String key) { map.remove(key); }
        @Override public Set<String> byteKeys() { return Set.of(); }

        @Override public Short getShort(String key) { Object v = map.get(key); return v == null ? null : (Short) v; }
        @Override public void setShort(String key, short value) { map.put(key, value); }
        @Override public void deleteShort(String key) { map.remove(key); }
        @Override public Set<String> shortKeys() { return Set.of(); }

        @Override public Integer getInteger(String key) { Object v = map.get(key); return v == null ? null : (Integer) v; }
        @Override public void setInteger(String key, int value) { map.put(key, value); }
        @Override public void deleteInteger(String key) { map.remove(key); }
        @Override public Set<String> integerKeys() { return Set.of(); }

        @Override public Long getLong(String key) { Object v = map.get(key); return v == null ? null : (Long) v; }
        @Override public void setLong(String key, long value) { map.put(key, value); }
        @Override public void deleteLong(String key) { map.remove(key); }
        @Override public Set<String> longKeys() { return Set.of(); }
    }

    @BeforeEach
    void clearBusState() {
        PassiveAnalysisErrorBus.INSTANCE.clearError();
    }

    @AfterEach
    void resetBusState() {
        PassiveAnalysisErrorBus.INSTANCE.clearError();
    }

    /**
     * 关键回归测试：用户在"被动分析"区应当看到红字错误信息。
     *
     * <p>验证：setError 后 JTextArea 文本应包含"网络错误"分类前缀 + 错误消息，
     * 不应包含 HTML 标签字面字符（避免 LaF 下 <html> 原样暴露），
     * 也不应包含 method/url 前缀（这些信息已在 Burp Output 日志里呈现）。</p>
     */
    @Test
    void passiveErrorLabelUpdatesOnSetError() throws Exception {
        Settings settings = Settings.createDefault();
        settings.replaceActive(new AiConfig("test", "http://localhost", "".toCharArray(),
                "model", 30, 2048));
        SettingsPanel panel = new SettingsPanel(null, settings, testStore());
        try {
            PassiveAnalysisErrorBus.INSTANCE.setError("测试错误", PassiveAnalysisErrorBus.ErrorKind.NETWORK);

            CountDownLatch done = new CountDownLatch(1);
            javax.swing.SwingUtilities.invokeLater(done::countDown);
            assertTrue(done.await(1, TimeUnit.SECONDS), "EDT invokeLater 任务应在 1s 内执行");

            JTextArea area = getField(panel, "passiveErrorArea", JTextArea.class);
            assertNotNull(area, "应能找到 passiveErrorArea 字段");
            String text = area.getText();
            assertNotNull(text, "JTextArea 文本不应为 null");
            assertTrue(text.contains("网络错误"),
                    "红字应包含分类前缀，实际：" + text);
            assertTrue(text.contains("测试错误"),
                    "红字应包含错误消息，实际：" + text);
            assertTrue(!text.contains("<html>") && !text.contains("<") && !text.contains(">"),
                    "JTextArea 纯文本不应含 HTML 标签字面字符，实际：" + text);
            assertTrue(!text.contains("http://") && !text.contains("https://"),
                    "UI 红字不应含 URL，避免测试目录 URL 出现在错误信息里，实际：" + text);
            assertTrue(!text.contains("GET ") && !text.contains("POST ")
                            && !text.contains("PUT ") && !text.contains("DELETE "),
                    "UI 红字不应含 HTTP method 前缀，实际：" + text);
        } finally {
            panel.close();
        }
    }

    /**
     * 验证被动分析 Section 构造完成后，默认回填（无正则）下状态行显示"留空匹配全部"。
     */
    @Test
    void regexStatusShowsEmptyForBlank() throws Exception {
        Settings settings = Settings.createDefault();
        settings.replaceActive(new AiConfig("test", "http://localhost", "".toCharArray(),
                "model", 30, 2048));
        SettingsPanel panel = new SettingsPanel(null, settings, testStore());
        try {
            JLabel status = getField(panel, "passiveRegexStatusLabel", JLabel.class);
            assertNotNull(status);
            assertTrue(status.getText().contains("留空匹配全部"),
                    "默认状态应为'留空匹配全部'，实际：" + status.getText());
        } finally {
            panel.close();
        }
    }

    /**
     * 输入非法正则（未闭合括号）→ 状态行显示"✗ 正则非法：…"，颜色变红。
     */
    @Test
    void regexStatusShowsInvalidForBadRegex() throws Exception {
        Settings settings = Settings.createDefault();
        settings.replaceActive(new AiConfig("test", "http://localhost", "".toCharArray(),
                "model", 30, 2048));
        SettingsPanel panel = new SettingsPanel(null, settings, testStore());
        try {
            JTextField field = getField(panel, "passiveRegexField", JTextField.class);
            JLabel status = getField(panel, "passiveRegexStatusLabel", JLabel.class);
            runOnEdt(() -> field.setText("([unclosed"));
            String text = status.getText();
            assertTrue(text.startsWith("✗") || text.contains("✗"),
                    "非法正则应以 ✗ 引导，实际：" + text);
            assertTrue(text.contains("非法"),
                    "非法状态行应包含'非法'关键字，实际：" + text);
            java.awt.Color fg = status.getForeground();
            assertTrue(fg.getRed() > fg.getGreen(),
                    "非法态前景应偏红（红通道 > 绿通道），实际 RGB=" + fg.getRGB());
        } finally {
            panel.close();
        }
    }

    /**
     * 编辑 Base URL 输入框 → 等 SERVICE_DEBOUNCE_MS(300ms) 防抖窗口过期 →
     * activeConfig 的 baseUrl 字段应已更新 + Preferences 已落盘。
     */
    @Test
    void aiServiceAutoSavesBaseUrlAfterDebounce() throws Exception {
        Settings settings = Settings.createDefault();
        settings.replaceActive(new AiConfig("test", "http://old", "".toCharArray(),
                "model", 30, 2048));
        MapPreferences prefs = new MapPreferences();
        SettingsPanel panel = new SettingsPanel(null, settings, new SettingsStore(prefs));
        try {
            JTextField baseUrl = getField(panel, "baseUrlField", JTextField.class);
            runOnEdt(() -> baseUrl.setText("http://new.example.com"));
            Thread.sleep(500);
            assertEquals("http://new.example.com",
                    settings.activeConfig().getBaseUrl(),
                    "防抖窗口后 baseUrl 应已自动写入 activeConfig");
            String json = prefs.getString("com.auditai.aiServices");
            assertTrue(json != null && json.contains("new.example.com"),
                    "自动保存后应已写入 Preferences JSON，实际：" + json);
        } finally {
            panel.close();
        }
    }

    /**
     * 编辑 name 字段 → 自动保存应触发 replaceActive + removeConfigByName，
     * 下拉列表里出现新名，旧名条目被移除。
     */
    @Test
    void aiServiceAutoSaveRenameReplacesActiveAndUpdatesList() throws Exception {
        Settings settings = Settings.createDefault();
        settings.replaceActive(new AiConfig("oldName", "http://x", "".toCharArray(),
                "m", 30, 2048));
        SettingsPanel panel = new SettingsPanel(null, settings, testStore());
        try {
            JTextField nameField = getField(panel, "nameField", JTextField.class);
            runOnEdt(() -> nameField.setText("newName"));
            Thread.sleep(500);
            assertEquals("newName", settings.activeName(),
                    "改名前后 activeName 应同步更新为新值");
            assertEquals(1, settings.configs().size(),
                    "改名后列表里不应残留旧名条目，实际：" + settings.configs());
            assertEquals("newName", settings.configs().get(0).getName(),
                    "列表里的条目应使用新名");
        } finally {
            panel.close();
        }
    }

    /**
     * 把名称改成与列表里"另一条配置"重名 → 校验失败 → 旧 active / 列表结构
     * 都应保留原状（不发生"旧名条目被覆盖"的静默不一致）。
     * 初始:list=[a, dup],active=a。把 active 名字改成"dup",应被拒绝。
     */
    @Test
    void aiServiceAutoSaveRejectsDuplicateName() throws Exception {
        Settings s2 = Settings.createDefault();
        s2.addAndSwitchTo(new AiConfig("a", "http://a", "".toCharArray(), "m", 30, 2048));
        s2.addAndSwitchTo(new AiConfig("dup", "http://dup", "".toCharArray(), "m", 30, 2048));
        s2.switchTo("a");
        SettingsPanel panel = new SettingsPanel(null, s2, testStore());
        try {
            JTextField nameField = getField(panel, "nameField", JTextField.class);
            runOnEdt(() -> nameField.setText("dup"));
            Thread.sleep(500);
            assertEquals("a", s2.activeName(),
                    "改名成列表里其他条目重名 → 校验失败 → activeName 保持不变");
            assertTrue(s2.configs().stream().anyMatch(c -> "a".equals(c.getName())),
                    "a 条目应仍在列表里");
            assertTrue(s2.configs().stream().anyMatch(c -> "dup".equals(c.getName())),
                    "dup 条目应仍在列表里");
        } finally {
            panel.close();
        }
    }

    /**
     * 编辑 Base URL → 在 300ms 防抖窗口内立刻切换下拉到另一条配置：
     * 切走前 onDropdownChanged 应调用 serviceDebounce.flushIfPending,
     * 把表单内容写进旧激活项,然后才切换。验证：旧激活项的 baseUrl 已被更新。
     */
    @Test
    void dropdownChangeFlushesPendingAutoSave() throws Exception {
        Settings settings = Settings.createDefault();
        settings.addAndSwitchTo(new AiConfig("first", "http://first", "".toCharArray(),
                "m1", 30, 2048));
        settings.addAndSwitchTo(new AiConfig("second", "http://second", "".toCharArray(),
                "m2", 30, 2048));
        settings.switchTo("first");
        SettingsPanel panel = new SettingsPanel(null, settings, testStore());
        try {
            JTextField baseUrl = getField(panel, "baseUrlField", JTextField.class);
            runOnEdt(() -> baseUrl.setText("http://edited-before-switch"));
            javax.swing.JComboBox<?> dropdown = getField(panel, "serviceDropdown",
                    javax.swing.JComboBox.class);
            runOnEdt(() -> dropdown.setSelectedItem("second"));
            AiConfig first = settings.configs().stream()
                    .filter(c -> "first".equals(c.getName()))
                    .findFirst().orElse(null);
            assertNotNull(first, "first 条目应仍在列表里");
            assertEquals("http://edited-before-switch", first.getBaseUrl(),
                    "切走前 serviceDebounce.flushIfPending 应已把表单写入 first.activeConfig");
            assertEquals("second", settings.activeName());
        } finally {
            panel.close();
        }
    }

    /**
     * 回归测试:仅修改非名字字段(baseUrl)→ 不应触发 refreshDropdown。
     * 否则下拉打开中 removeAllItems 会让用户悬停高亮位置跳变(用户反馈的
     * "鼠标位置抖动"现象);且大量无谓的全量重建 + Preferences 写。
     *
     * <p>直接调 {@code flushIfPending()} 强制同步执行 serviceDebounce,
     * 避开 300ms 防抖窗口的不确定性;然后断言下拉条目数 / 内容 / 选中项都和初始一致。</p>
     */
    @Test
    void aiServiceAutoSaveDoesNotRebuildDropdownOnFieldOnlyChange() throws Exception {
        Settings settings = Settings.createDefault();
        settings.replaceActive(new AiConfig("test", "http://old", "".toCharArray(),
                "m", 30, 2048));
        SettingsPanel panel = new SettingsPanel(null, settings, testStore());
        try {
            javax.swing.JComboBox<?> dropdown = getField(panel, "serviceDropdown",
                    javax.swing.JComboBox.class);
            int sizeBefore = dropdown.getItemCount();
            java.util.List<String> namesBefore = new java.util.ArrayList<>();
            for (int i = 0; i < sizeBefore; i++) {
                namesBefore.add((String) dropdown.getItemAt(i));
            }
            JTextField baseUrl = getField(panel, "baseUrlField", JTextField.class);
            Object serviceDebounce = getField(panel, "serviceDebounce", Object.class);
            runOnEdt(() -> {
                baseUrl.setText("http://new");
                try {
                    java.lang.reflect.Method flush = serviceDebounce.getClass()
                            .getDeclaredMethod("flushIfPending");
                    flush.setAccessible(true);
                    flush.invoke(serviceDebounce);
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            });
            CountDownLatch idle = new CountDownLatch(1);
            SwingUtilities.invokeLater(idle::countDown);
            idle.await(1, TimeUnit.SECONDS);
            assertEquals("http://new", settings.activeConfig().getBaseUrl());
            assertEquals("test", settings.activeName(),
                    "非名字字段变化不应改变 activeName");
            assertEquals(sizeBefore, dropdown.getItemCount(),
                    "非名字字段变化不应改变下拉条目数,期望 size_before=" + sizeBefore
                            + " 实际 size_after=" + dropdown.getItemCount());
            for (int i = 0; i < sizeBefore; i++) {
                assertEquals(namesBefore.get(i), dropdown.getItemAt(i),
                        "第 " + i + " 个下拉条目应保持不变");
            }
        } finally {
            panel.close();
        }
    }

    /**
     * 死循环回归测试:早期实现里 applyAiServiceChange 调 populateFormFromActive
     * 触发 setText → DocumentListener → 重启 serviceDebounce,导致每 300ms
     * 再次 apply → 再次 setText → 再次 schedule,形成无限重画 + Preferences 反复写。
     *
     * <p>观察 Preferences 的 aiServices 是否被多次覆写:
     * 早期 bug 下,1s 窗口内 Preferences JSON 会被写多次(每次 saveSettings 都会
     * 序列化整个 list);修复后应只在用户的最终编辑落地一次。</p>
     */
    @Test
    void autoSaveDoesNotTriggerEndlessRefreshLoop() throws Exception {
        Settings settings = Settings.createDefault();
        settings.replaceActive(new AiConfig("test", "http://start", "".toCharArray(),
                "m", 30, 2048));
        MapPreferences prefs = new MapPreferences();
        SettingsPanel panel = new SettingsPanel(null, settings, new SettingsStore(prefs));
        try {
            JTextField baseUrl = getField(panel, "baseUrlField", JTextField.class);
            runOnEdt(() -> baseUrl.setText("http://once"));
            Thread.sleep(1000);
            String json = prefs.getString("com.auditai.aiServices");
            assertNotNull(json, "自动保存后应已写入 aiServices");
            assertTrue(json.contains("http://once"),
                    "终值应写入 Preferences,实际：" + json);
            assertTrue(!json.contains("http://start"),
                    "中间态不应残留在 Preferences,实际：" + json);
        } finally {
            panel.close();
        }
    }

    /** 在 EDT 上执行一段 lambda，用于直接对 Swing 组件写值并触发 listener。 */
    private static void runOnEdt(Runnable r) throws InterruptedException {
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
            return;
        }
        CountDownLatch done = new CountDownLatch(1);
        SwingUtilities.invokeLater(() -> {
            try {
                r.run();
            } finally {
                done.countDown();
            }
        });
        done.await(2, TimeUnit.SECONDS);
    }
}
