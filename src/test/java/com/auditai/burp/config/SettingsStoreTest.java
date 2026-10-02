package com.auditai.burp.config;

import burp.api.montoya.persistence.Preferences;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link SettingsStore} 单元测试：JSON 序列化、新格式读写、v0.2 旧键迁移、出厂默认。
 *
 * <p>使用 {@link InMemoryPreferences} 桩，避免对 Montoya API 的真实依赖；其读写语义
 * 与 Montoya {@code Preferences} 一致：读不到返回 {@code null}，写入按键覆盖。</p>
 */
final class SettingsStoreTest {

    /** 没有任何持久化数据 → 返回空配置集。 */
    @Test
    void loadFromEmptyGivesEmptySettings() {
        SettingsStore store = new SettingsStore(new InMemoryPreferences());
        Settings s = store.load();
        assertTrue(s.configs().isEmpty());
        assertNull(s.activeName());
        assertNull(s.activeConfig());
    }

    /** 新格式 → 写盘后能完整读回（顺序、字段、激活项、自定义提示词）。 */
    @Test
    void saveAndLoadRoundTrip() {
        InMemoryPreferences prefs = new InMemoryPreferences();
        SettingsStore store = new SettingsStore(prefs);

        AiConfig deepseek = new AiConfig("DeepSeek", "https://api.deepseek.com", "sk-xxx",
                "deepseek-v4-flash", 30, 4096);
        AiConfig ollama = new AiConfig("Ollama", "http://localhost:11434/v1", "", "llama3", 60, 2048);
        Settings original = new Settings(java.util.List.of(deepseek, ollama), "Ollama", "my prompt");

        store.save(original);

        Settings loaded = store.load();
        assertEquals(2, loaded.configs().size());
        assertEquals("Ollama", loaded.activeName());
        assertEquals("my prompt", loaded.customPrompt());

        AiConfig deepseekLoaded = loaded.configs().stream()
                .filter(c -> c.getName().equals("DeepSeek")).findFirst().orElseThrow();
        assertEquals("https://api.deepseek.com", deepseekLoaded.getBaseUrl());
        assertEquals("sk-xxx", new String(deepseekLoaded.getApiKey()));
        assertEquals("deepseek-v4-flash", deepseekLoaded.getModel());
        assertEquals(30, deepseekLoaded.getTimeoutSeconds());
        assertEquals(4096, deepseekLoaded.getMaxTokens());

        AiConfig ollamaLoaded = loaded.configs().stream()
                .filter(c -> c.getName().equals("Ollama")).findFirst().orElseThrow();
        assertEquals("http://localhost:11434/v1", ollamaLoaded.getBaseUrl());
        assertEquals("llama3", ollamaLoaded.getModel());
    }

    /** v0.2 旧键迁移：仅有 baseUrl + model 时应能恢复出一条配置。 */
    @Test
    void migrateLegacyBaseUrlAndModel() {
        InMemoryPreferences prefs = new InMemoryPreferences();
        prefs.strings.put("com.auditai.baseUrl", "https://api.deepseek.com");
        prefs.strings.put("com.auditai.model", "deepseek-chat");
        // 注意：没有 v0.3 新格式键

        SettingsStore store = new SettingsStore(prefs);
        Settings s = store.load();

        assertEquals(1, s.configs().size());
        // 名称与 URL 独立——不做"看 URL 猜厂商"推断，统一用通用名让用户在 UI 改名
        assertEquals("默认配置", s.configs().get(0).getName());
        assertEquals("https://api.deepseek.com", s.configs().get(0).getBaseUrl());
        assertEquals("deepseek-chat", s.configs().get(0).getModel());
    }

    /** v0.2 旧键迁移：baseUrl + apiKey + timeout + maxTokens 都应有。 */
    @Test
    void migrateLegacyAllFieldsPreserved() {
        InMemoryPreferences prefs = new InMemoryPreferences();
        prefs.strings.put("com.auditai.baseUrl", "https://api.openai.com");
        prefs.strings.put("com.auditai.apiKey", "sk-openai");
        prefs.strings.put("com.auditai.model", "gpt-4");
        prefs.integers.put("com.auditai.timeoutSeconds", 120);
        prefs.integers.put("com.auditai.maxTokens", 8192);

        SettingsStore store = new SettingsStore(prefs);
        Settings s = store.load();

        assertEquals(1, s.configs().size());
        AiConfig cfg = s.configs().get(0);
        // 名称始终是通用名"默认配置"
        assertEquals("默认配置", cfg.getName());
        assertEquals("https://api.openai.com", cfg.getBaseUrl());
        assertEquals("sk-openai", new String(cfg.getApiKey()));
        assertEquals("gpt-4", cfg.getModel());
        assertEquals(120, cfg.getTimeoutSeconds());
        assertEquals(8192, cfg.getMaxTokens());
    }

    /** JSON 损坏时应回退到空配置集（不让插件因为一条坏数据起不来）。 */
    @Test
    void corruptJsonFallsBackToEmpty() {
        InMemoryPreferences prefs = new InMemoryPreferences();
        prefs.strings.put("com.auditai.aiServices", "{not valid json");
        SettingsStore store = new SettingsStore(prefs);
        Settings s = store.load();
        assertTrue(s.configs().isEmpty());
        assertNull(s.activeName());
    }

    /** JSON 合法但元素缺 name → 跳过脏数据（不让空名条目污染下拉列表）。 */
    @Test
    void jsonWithoutNameIsSkipped() {
        InMemoryPreferences prefs = new InMemoryPreferences();
        // 故意只放一条"有 name"的 + 一条"没 name"的
        prefs.strings.put("com.auditai.aiServices",
                "[{\"name\":\"good\",\"baseUrl\":\"u\",\"apiKey\":\"\",\"model\":\"m\","
                        + "\"timeoutSeconds\":30,\"maxTokens\":4096},"
                        + "{\"baseUrl\":\"u2\",\"model\":\"m2\"}]");
        SettingsStore store = new SettingsStore(prefs);
        Settings s = store.load();
        assertEquals(1, s.configs().size());
        assertEquals("good", s.configs().get(0).getName());
    }

    /** saveCustomPrompt：单独写提示词，不影响其他字段。 */
    @Test
    void saveCustomPromptDoesNotTouchOtherFields() {
        InMemoryPreferences prefs = new InMemoryPreferences();
        SettingsStore store = new SettingsStore(prefs);
        store.saveCustomPrompt("新的提示词");
        assertEquals("新的提示词", prefs.strings.get("com.auditai.customPrompt"));
        // aiServices 键不应被设置
        assertNull(prefs.strings.get("com.auditai.aiServices"));
    }

    /** 保存时应清掉旧版单配置键（避免后续误读 / 占位数据）。 */
    @Test
    void saveClearsLegacyKeys() {
        InMemoryPreferences prefs = new InMemoryPreferences();
        // 先模拟"之前 v0.2 写入的旧键"
        prefs.strings.put("com.auditai.baseUrl", "https://api.deepseek.com");
        prefs.strings.put("com.auditai.model", "deepseek-chat");
        prefs.strings.put("com.auditai.apiKey", "sk-xxx");
        prefs.integers.put("com.auditai.timeoutSeconds", 60);
        prefs.integers.put("com.auditai.maxTokens", 2048);

        SettingsStore store = new SettingsStore(prefs);
        store.save(Settings.createDefault());

        // 旧键应被物理删除（下次 getString 返回 null，便于迁移逻辑判定"无旧数据"）
        assertNull(prefs.strings.get("com.auditai.baseUrl"));
        assertNull(prefs.strings.get("com.auditai.model"));
        assertNull(prefs.strings.get("com.auditai.apiKey"));
        assertNull(prefs.integers.get("com.auditai.timeoutSeconds"));
        assertNull(prefs.integers.get("com.auditai.maxTokens"));
    }

    /**
     * InMemoryPreferences：内存版 Preferences 桩，模拟 Montoya 持久化语义。
     * 读不到返回 null，写入按键覆盖，删除按键后回到读不到。
     */
    private static final class InMemoryPreferences implements Preferences {
        final Map<String, String> strings = new HashMap<>();
        final Map<String, Integer> integers = new HashMap<>();
        final Map<String, Boolean> booleans = new HashMap<>();
        final Map<String, Byte> bytes = new HashMap<>();
        final Map<String, Short> shorts = new HashMap<>();
        final Map<String, Long> longs = new HashMap<>();

        @Override
        public String getString(String key) {
            return strings.get(key);
        }

        @Override
        public void setString(String key, String value) {
            strings.put(key, value);
        }

        @Override
        public void deleteString(String key) {
            strings.remove(key);
        }

        @Override
        public java.util.Set<String> stringKeys() {
            return strings.keySet();
        }

        @Override
        public Boolean getBoolean(String key) {
            return booleans.get(key);
        }

        @Override
        public void setBoolean(String key, boolean value) {
            booleans.put(key, value);
        }

        @Override
        public void deleteBoolean(String key) {
            booleans.remove(key);
        }

        @Override
        public java.util.Set<String> booleanKeys() {
            return booleans.keySet();
        }

        @Override
        public Byte getByte(String key) {
            return bytes.get(key);
        }

        @Override
        public void setByte(String key, byte value) {
            bytes.put(key, value);
        }

        @Override
        public void deleteByte(String key) {
            bytes.remove(key);
        }

        @Override
        public java.util.Set<String> byteKeys() {
            return bytes.keySet();
        }

        @Override
        public Short getShort(String key) {
            return shorts.get(key);
        }

        @Override
        public void setShort(String key, short value) {
            shorts.put(key, value);
        }

        @Override
        public void deleteShort(String key) {
            shorts.remove(key);
        }

        @Override
        public java.util.Set<String> shortKeys() {
            return shorts.keySet();
        }

        @Override
        public Integer getInteger(String key) {
            return integers.get(key);
        }

        @Override
        public void setInteger(String key, int value) {
            integers.put(key, value);
        }

        @Override
        public void deleteInteger(String key) {
            integers.remove(key);
        }

        @Override
        public java.util.Set<String> integerKeys() {
            return integers.keySet();
        }

        @Override
        public Long getLong(String key) {
            return longs.get(key);
        }

        @Override
        public void setLong(String key, long value) {
            longs.put(key, value);
        }

        @Override
        public void deleteLong(String key) {
            longs.remove(key);
        }

        @Override
        public java.util.Set<String> longKeys() {
            return longs.keySet();
        }
    }

    /** 保存到磁盘的 API Key 应当是密文（enc:v1: 前缀），不是明文 sk-xxx。 */
    @Test
    void savedApiKeyIsEncryptedOnDisk() {
        InMemoryPreferences prefs = new InMemoryPreferences();
        SettingsStore store = new SettingsStore(prefs);
        store.save(new Settings(
                new ArrayList<>(List.of(
                        new AiConfig("X", "u", "sk-secret-plaintext", "m", 30, 1024))),
                "X", ""));
        String stored = prefs.strings.get("com.auditai.aiServices");
        assertNotNull(stored);
        org.junit.jupiter.api.Assertions.assertFalse(stored.contains("sk-secret-plaintext"),
                "明文 API Key 不应出现在磁盘 JSON 中");
        org.junit.jupiter.api.Assertions.assertTrue(stored.contains("enc:v1:"),
                "磁盘应保存 enc:v1: 前缀的密文");
    }

    /** 旧版明文格式 API Key 在加载时应能正常读回（向后兼容），下次保存时自动转密文。 */
    @Test
    void legacyPlaintextApiKeyIsReadAndReencryptedOnSave() {
        InMemoryPreferences prefs = new InMemoryPreferences();
        prefs.strings.put("com.auditai.aiServices",
                "[{\"name\":\"legacy\",\"baseUrl\":\"u\",\"apiKey\":\"sk-legacy-plain\","
                        + "\"model\":\"m\",\"timeoutSeconds\":30,\"maxTokens\":4096}]");
        SettingsStore store = new SettingsStore(prefs);

        // 第一次加载：仍是明文，getApiKey() 能读出原值
        Settings loaded = store.load();
        assertEquals("sk-legacy-plain", new String(loaded.configs().get(0).getApiKey()));

        // 触发保存：磁盘上应被改写为密文
        store.save(loaded);
        String stored = prefs.strings.get("com.auditai.aiServices");
        org.junit.jupiter.api.Assertions.assertFalse(stored.contains("sk-legacy-plain"),
                "save 后磁盘不应再保留明文");
        org.junit.jupiter.api.Assertions.assertTrue(stored.contains("enc:v1:"));
    }

}
