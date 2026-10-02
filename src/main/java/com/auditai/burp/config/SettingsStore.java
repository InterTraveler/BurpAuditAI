package com.auditai.burp.config;

import burp.api.montoya.persistence.Preferences;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import java.util.ArrayList;
import java.util.List;

/**
 * 配置持久化仓库：把 {@link Settings} 读写到 Burp 的持久化存储中。
 *
 * <p>Burp 的 {@link Preferences} 是一个 KV 存储，数据随 Burp 用户配置目录保存，
 * 卸载重装插件后依然保留——这正是"配置不随插件重载而丢失"的标准做法。</p>
 *
 * <p>2026.7 的 Preferences 接口约定：</p>
 * <ul>
 *   <li>读取方法返回<b>装箱类型</b>（{@code Boolean}/{@code String}/{@code Integer}…），
 *       键不存在时返回 {@code null}——因此读取时要用默认值回退；</li>
 *   <li>键名统一加 {@code com.auditai.} 前缀（反向域名风格，避免与其他扩展的键冲突），
 *       注：此 key 前缀刻意不与 Java 包路径（{@code com.auditai.burp.*}）绑定，
 *       以保留未来调整包结构时的数据兼容性。</li>
 * </ul>
 *
 * <p>当前存储布局（多 AI 服务配置 + 当前激活项 + 全局提示词）：</p>
 * <ul>
 *   <li>{@code aiServices}：JSON 数组，元素为完整 {@link AiConfig} 字段；</li>
 *   <li>{@code activeAiService}：当前激活项的 {@code name}；</li>
 *   <li>{@code customPrompt}：全局自定义系统提示词。</li>
 * </ul>
 *
 * <p>兼容 v0.2 的单配置存储：若 {@code aiServices} 键不存在但存在
 * {@code baseUrl}/{@code model} 等旧键，则按旧键构造一条配置迁入新结构，
 * 避免升级后老用户的设置被丢失。</p>
 */
public final class SettingsStore {

    /** 键前缀：用于在 Burp 全局持久化存储中隔离本插件的配置项。 */
    private static final String KEY_PREFIX = "com.auditai.";

    /** 多 AI 服务配置列表（JSON 数组，元素为 AiConfig 字段）。 */
    private static final String KEY_AI_SERVICES = KEY_PREFIX + "aiServices";

    /** 当前激活 AI 服务配置项的名称。 */
    private static final String KEY_ACTIVE_AI_SERVICE = KEY_PREFIX + "activeAiService";

    /** 全局自定义系统提示词。 */
    private static final String KEY_CUSTOM_PROMPT = KEY_PREFIX + "customPrompt";

    /** 是否启用"被动流量分析"——Proxy 流量自动送 AI 分析。 */
    private static final String KEY_PASSIVE_ANALYSIS_ENABLED = KEY_PREFIX + "passiveAnalysisEnabled";

    /** 被动分析的 URL 过滤正则；空串 = 匹配全部。 */
    private static final String KEY_PASSIVE_ANALYSIS_URL_REGEX = KEY_PREFIX + "passiveAnalysisUrlRegex";

    // v0.2 老格式单配置键（用于迁移）
    private static final String LEGACY_KEY_BASE_URL = KEY_PREFIX + "baseUrl";
    private static final String LEGACY_KEY_API_KEY = KEY_PREFIX + "apiKey";
    private static final String LEGACY_KEY_MODEL = KEY_PREFIX + "model";
    private static final String LEGACY_KEY_TIMEOUT = KEY_PREFIX + "timeoutSeconds";
    private static final String LEGACY_KEY_MAX_TOKENS = KEY_PREFIX + "maxTokens";

    /** Burp 提供的持久化存储门面。 */
    private final Preferences preferences;

    /**
     * @param preferences Burp 的持久化存储（取自 {@code api.persistence().preferences()}）。
     */
    public SettingsStore(Preferences preferences) {
        this.preferences = preferences;
    }

    /**
     * 读取完整设置：先尝试新格式（多配置 + 激活项），失败/缺失时按 v0.2 旧格式迁移，
     * 旧格式也没有时回退到出厂默认（当前为"空配置集"，由用户在设置页添加 AI 服务）。
     *
     * @return 合并了持久化值与默认值的完整 {@link Settings}。
     */
    public Settings load() {
        String customPrompt = readString(KEY_CUSTOM_PROMPT, "");
        boolean passiveEnabled = readBoolean(KEY_PASSIVE_ANALYSIS_ENABLED, false);
        String passiveRegex = readString(KEY_PASSIVE_ANALYSIS_URL_REGEX, "");

        // 1) 优先尝试新格式：JSON 列表 + 激活项名称。
        String json = preferences.getString(KEY_AI_SERVICES);
        List<AiConfig> parsed = parseAiServicesJson(json);
        if (parsed != null && !parsed.isEmpty()) {
            String activeName = readString(KEY_ACTIVE_AI_SERVICE, parsed.get(0).getName());
            return new Settings(parsed, activeName, customPrompt, passiveEnabled, passiveRegex);
        }

        // 2) 新格式缺失/解析失败 → 尝试从 v0.2 单配置键迁移。
        AiConfig migrated = tryMigrateLegacy();
        if (migrated != null) {
            List<AiConfig> list = new ArrayList<>();
            list.add(migrated);
            return new Settings(list, migrated.getName(), customPrompt, passiveEnabled, passiveRegex);
        }

        // 3) 完全没有持久化数据 → 返回出厂默认（包含被动分析默认配置）。
        Settings defaults = Settings.createDefault();
        defaults.setPassiveAnalysisEnabled(passiveEnabled);
        defaults.setPassiveAnalysisUrlRegex(passiveRegex);
        return defaults;
    }

    /**
     * 保存完整设置：把所有 AI 服务配置序列化为 JSON 写入一个键，把激活项名称和
     * 提示词写入独立键。
     *
     * <p>设计权衡：把整个列表写成一个 JSON 比"每条配置一组键"更紧凑、易于手工编辑，
     * 键更少也让"读到一半"的窗口更小（Burp Preferences 的每次写入本身不是原子的，
     * 真正的兜底是 {@link #load()} 的多级回退与单条容错）。</p>
     *
     * @param settings 要持久化的配置集。
     */
    public void save(Settings settings) {
        // 列表中可能含 v0.2 升级遗留的临时脏数据：保存前先把激活项的字段同步回列表。
        settings.syncActiveEntry();

        JsonArray array = new JsonArray();
        for (AiConfig c : settings.configs()) {
            JsonObject obj = new JsonObject();
            obj.addProperty("name", c.getName());
            obj.addProperty("baseUrl", c.getBaseUrl());
            // API Key 走 ApiKeyCipher 加密后写盘；空配置写出空串而非密文（"无密钥"不套壳）。
            obj.addProperty("apiKey", ApiKeyCipher.encrypt(c.getApiKey()));
            obj.addProperty("model", c.getModel());
            obj.addProperty("timeoutSeconds", c.getTimeoutSeconds());
            obj.addProperty("maxTokens", c.getMaxTokens());
            array.add(obj);
        }
        preferences.setString(KEY_AI_SERVICES, GSON.toJson(array));
        if (settings.activeName() != null) {
            preferences.setString(KEY_ACTIVE_AI_SERVICE, settings.activeName());
        } else {
            // 无激活项（例如出厂默认的空配置集）：删除旧键而不是写 null，
            // 避免 Preferences 对 null 值语义差异导致读回脏状态。
            preferences.deleteString(KEY_ACTIVE_AI_SERVICE);
        }
        preferences.setString(KEY_CUSTOM_PROMPT, settings.customPrompt());
        preferences.setBoolean(KEY_PASSIVE_ANALYSIS_ENABLED, settings.isPassiveAnalysisEnabled());
        preferences.setString(KEY_PASSIVE_ANALYSIS_URL_REGEX, settings.getPassiveAnalysisUrlRegex());

        // 旧格式单配置键不再需要：清掉避免未来误读（特别是迁移完成后）。
        clearLegacyKeys();
    }

    /**
     * 把"自定义系统提示词"独立写盘——{@code SettingsPanel} 的"保存提示词"按钮调用，
     * 不需要把整个 AI 服务列表重写一遍。
     */
    public void saveCustomPrompt(String customPrompt) {
        preferences.setString(KEY_CUSTOM_PROMPT, customPrompt == null ? "" : customPrompt);
    }

    /**
     * 把"被动分析开关 + URL 正则"独立写盘——{@code SettingsPanel} 的"保存被动分析"按钮调用，
     * 避免改一下过滤正则就触发整张 AI 服务列表的 JSON 重写。
     */
    public void savePassiveAnalysis(boolean enabled, String urlRegex) {
        preferences.setBoolean(KEY_PASSIVE_ANALYSIS_ENABLED, enabled);
        preferences.setString(KEY_PASSIVE_ANALYSIS_URL_REGEX, urlRegex == null ? "" : urlRegex);
    }

    // ========== 内部工具 ==========

    /** 用于写入/解析 JSON 列表的 Gson 实例；关闭 HTML 转义避免 baseUrl 里的 & 被写成 \u0026。 */
    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();

    private String readString(String key, String fallback) {
        String value = preferences.getString(key);
        return value != null ? value : fallback;
    }

    /** 读取布尔键：键不存在时返回 fallback。Burp Boolean 类型装箱返回，可能为 null。 */
    private boolean readBoolean(String key, boolean fallback) {
        Boolean value = preferences.getBoolean(key);
        return value != null ? value : fallback;
    }

    /**
     * 解析新格式 JSON 列表；解析失败/空列表返回 null（由调用方决定回退策略）。
     * 跳过缺 {@code name} 字段的脏数据，避免污染 UI。
     */
    private List<AiConfig> parseAiServicesJson(String json) {
        if (json == null || json.isBlank()) {
            return null;
        }
        try {
            JsonElement root = JsonParser.parseString(json);
            if (!root.isJsonArray()) {
                return null;
            }
            JsonArray array = root.getAsJsonArray();
            List<AiConfig> result = new ArrayList<>();
            for (JsonElement el : array) {
                if (!el.isJsonObject()) {
                    continue;
                }
                AiConfig cfg;
                try {
                    cfg = jsonObjectToConfig(el.getAsJsonObject());
                } catch (RuntimeException ex) {
                    // 单条配置损坏（例如 apiKey 密文被手工改坏导致解密抛异常）：
                    // 跳过该条，避免整张配置表加载失败 / 扩展启动崩溃，其余配置照常可用。
                    continue;
                }
                if (cfg != null && cfg.getName() != null && !cfg.getName().isEmpty()) {
                    result.add(cfg);
                }
            }
            return result.isEmpty() ? null : result;
        } catch (JsonSyntaxException ex) {
            // 解析失败视为无持久化数据（最坏情况退到默认值，比让插件起不来好）。
            return null;
        }
    }

    private AiConfig jsonObjectToConfig(JsonObject obj) {
        String name = optString(obj, "name", null);
        if (name == null) {
            return null;
        }
        // API Key：智能识别密文/明文，老数据首次加载时按明文读，下次保存自动转密文。
        char[] apiKey = ApiKeyCipher.tryDecrypt(optString(obj, "apiKey", ""));
        return new AiConfig(
                name,
                optString(obj, "baseUrl", ""),
                apiKey,
                optString(obj, "model", ""),
                optInt(obj, "timeoutSeconds", AiConfig.DEFAULT_TIMEOUT_SECONDS),
                optInt(obj, "maxTokens", AiConfig.DEFAULT_MAX_TOKENS));
    }

    private static String optString(JsonObject obj, String key, String fallback) {
        JsonElement el = obj.get(key);
        if (el == null || el.isJsonNull() || !el.isJsonPrimitive()) {
            return fallback;
        }
        try {
            return el.getAsString();
        } catch (RuntimeException ex) {
            // 字段类型与预期不符（如 baseUrl 位置存了对象/数组）：回退默认值
            return fallback;
        }
    }

    private static int optInt(JsonObject obj, String key, int fallback) {
        JsonElement el = obj.get(key);
        if (el == null || el.isJsonNull() || !el.isJsonPrimitive()) {
            return fallback;
        }
        try {
            return el.getAsInt();
        } catch (NumberFormatException ex) {
            return fallback;
        }
    }

    /**
     * 从 v0.2 的单配置键迁移出 {@link AiConfig}；旧键全空时返回 null。
     *
     * <p>迁移出来的配置用通用名"默认配置"——名称与 baseUrl 完全独立，
     * 不去做"看 URL 猜厂商"这种推断；用户看到列表里这条后可以立刻在
     * 设置界面改名 / 删除 / 改 baseUrl。</p>
     */
    private AiConfig tryMigrateLegacy() {
        String baseUrl = preferences.getString(LEGACY_KEY_BASE_URL);
        String apiKey = preferences.getString(LEGACY_KEY_API_KEY);
        String model = preferences.getString(LEGACY_KEY_MODEL);
        Integer timeout = preferences.getInteger(LEGACY_KEY_TIMEOUT);
        Integer maxTokens = preferences.getInteger(LEGACY_KEY_MAX_TOKENS);

        // 没有任何旧键 → 没有可迁移内容。
        if (baseUrl == null && apiKey == null && model == null
                && timeout == null && maxTokens == null) {
            return null;
        }
        return new AiConfig(
                "默认配置",
                baseUrl == null ? "" : baseUrl,
                apiKey == null ? "" : apiKey,
                model == null ? "" : model,
                timeout == null ? AiConfig.DEFAULT_TIMEOUT_SECONDS : timeout,
                maxTokens == null ? AiConfig.DEFAULT_MAX_TOKENS : maxTokens);
    }

    /** 清掉 v0.2 旧键，避免后续误读或在新格式下还看到旧值。 */
    private void clearLegacyKeys() {
        preferences.deleteString(LEGACY_KEY_BASE_URL);
        preferences.deleteString(LEGACY_KEY_API_KEY);
        preferences.deleteString(LEGACY_KEY_MODEL);
        preferences.deleteInteger(LEGACY_KEY_TIMEOUT);
        preferences.deleteInteger(LEGACY_KEY_MAX_TOKENS);
    }
}
