package com.auditai.burp.skills;

import burp.api.montoya.persistence.Preferences;
import org.junit.jupiter.api.Test;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link SkillStateStore} 的单元测试。
 *
 * <p>{@link Preferences} 是 Montoya API 接口，没有内存版实现——本测试用
 * {@link java.lang.reflect.Proxy} 动态实现一个"内存 Preferences"，行为尽量贴近
 * 真实 API（默认值的取用、写入覆盖、未设置时返回默认）。</p>
 */
class SkillStateStoreTest {

    /** 首次安装：未写入过任何偏好，loadEnabledIds 应返回 {@link DefaultEnabledSkill#ids()}。 */
    @Test
    void firstInstallReturnsDefaultEnum() {
        SkillStateStore store = new SkillStateStore(stub(new HashMap<>()));

        Set<String> loaded = store.loadEnabledIds();

        assertEquals(DefaultEnabledSkill.ids(), loaded);
    }

    /** 模拟"用户在 UI 里禁用某个默认启用的技能"后：loadEnabledIds 应只返回用户实际启用的。 */
    @Test
    void afterSaveReturnsPersistedStateNotDefaults() {
        Map<String, Object> data = new HashMap<>();
        SkillStateStore store = new SkillStateStore(stub(data));

        Set<String> userChoice = new LinkedHashSet<>();
        userChoice.add("xss-detector"); // 只保留 XSS
        store.saveEnabledIds(userChoice);

        Set<String> loaded = store.loadEnabledIds();
        assertEquals(userChoice, loaded);
        assertFalse(loaded.contains("sql-injection"),
                "首次安装默认启用 sql-injection，但用户已禁用 → 不应再出现");
    }

    /** 持久化与读取的往返不应破坏集合内容。 */
    @Test
    void saveAndLoadRoundTrip() {
        Map<String, Object> data = new HashMap<>();
        SkillStateStore store = new SkillStateStore(stub(data));

        Set<String> input = new LinkedHashSet<>();
        input.add("sql-injection");
        input.add("jwt-analyzer");
        input.add("custom-thing"); // 不在枚举里
        store.saveEnabledIds(input);

        assertEquals(input, store.loadEnabledIds());
    }

    /** saveEnabledIds 会写入 initialized 标志，使后续 load 走持久化路径（即使传入空集合）。 */
    @Test
    void saveWithEmptySetStillMarksInitialized() {
        Map<String, Object> data = new HashMap<>();
        SkillStateStore store = new SkillStateStore(stub(data));

        store.saveEnabledIds(new LinkedHashSet<>());

        // 即使没有技能被启用，已初始化标志也应置 true——避免"用户全部禁用"被下次启动的默认值覆盖
        assertTrue((Boolean) data.get("com.auditai.skills.initialized"));
        Set<String> loaded = store.loadEnabledIds();
        assertTrue(loaded.isEmpty());
    }

    /** 持久化的 CSV 容忍空白字符与空字段。 */
    @Test
    void loadToleratesWhitespaceAndEmptyEntries() {
        Map<String, Object> data = new HashMap<>();
        data.put("com.auditai.skills.initialized", Boolean.TRUE);
        data.put("com.auditai.skills.enabledIds", " sql-injection ,, xss-detector , ");

        SkillStateStore store = new SkillStateStore(stub(data));
        Set<String> loaded = store.loadEnabledIds();

        assertEquals(Set.of("sql-injection", "xss-detector"), loaded);
    }

    /** 首次安装时 loadPinnedIds 应返回空集——与 enabledIds 不同，自动激活无"新手套装"概念。 */
    @Test
    void pinnedDefaultsToEmptyOnFirstInstall() {
        SkillStateStore store = new SkillStateStore(stub(new HashMap<>()));

        assertTrue(store.loadPinnedIds().isEmpty(),
                "首次安装不应自动启用任何自动激活技能（避免与 enabledIds 首次安装语义混淆）");
    }

    /** savePinnedIds 写盘后 loadPinnedIds 应还原，不影响 enabledIds / initialized。 */
    @Test
    void pinnedSaveAndLoadRoundTrip() {
        Map<String, Object> data = new HashMap<>();
        SkillStateStore store = new SkillStateStore(stub(data));

        Set<String> pinned = new LinkedHashSet<>();
        pinned.add("replay");
        pinned.add("sql-injection");
        store.savePinnedIds(pinned);

        assertEquals(pinned, store.loadPinnedIds());
        // pinned 操作不应该影响 enabledIds / initialized 标志——它们是独立的状态。
        assertFalse(data.containsKey("com.auditai.skills.initialized"),
                "savePinnedIds 不应联动 initialized 标志");
    }

    /** savePinnedIds 写入空集是合法状态（用户已全部解除自动激活）。 */
    @Test
    void pinnedEmptySetIsAllowed() {
        Map<String, Object> data = new HashMap<>();
        SkillStateStore store = new SkillStateStore(stub(data));

        store.savePinnedIds(new LinkedHashSet<>());

        assertTrue(store.loadPinnedIds().isEmpty());
    }

    /** 持久化的 pinned CSV 同样容忍空白字符与空字段。 */
    @Test
    void loadPinnedToleratesWhitespaceAndEmptyEntries() {
        Map<String, Object> data = new HashMap<>();
        data.put("com.auditai.skills.pinnedIds", " sql-injection ,, jwt-analyzer , ");

        SkillStateStore store = new SkillStateStore(stub(data));
        Set<String> loaded = store.loadPinnedIds();

        assertEquals(Set.of("sql-injection", "jwt-analyzer"), loaded);
    }

    // —— 内存 Preferences 桩 ——

    /**
     * 用 {@link Proxy} 动态实现 {@link Preferences}：底层是普通 {@link Map}。
     * 只覆盖本测试用到的 {@code getString / setString / getBoolean / setBoolean}，
     * 其余方法返回默认值（数字 0、字符串 null、空 Set 等），与 Montoya 真实实现
     * 在"未调用"场景下行为一致。
     */
    private static Preferences stub(Map<String, Object> data) {
        return (Preferences) Proxy.newProxyInstance(
                SkillStateStoreTest.class.getClassLoader(),
                new Class<?>[]{Preferences.class},
                new InvocationHandler() {
                    @Override
                    public Object invoke(Object proxy, Method method, Object[] args) {
                        switch (method.getName()) {
                            case "getString": {
                                String key = (String) args[0];
                                Object v = data.get(key);
                                return v != null ? v : null;
                            }
                            case "setString": {
                                data.put((String) args[0], (String) args[1]);
                                return null;
                            }
                            case "getBoolean": {
                                String key = (String) args[0];
                                Object v = data.get(key);
                                return v != null ? v : null;
                            }
                            case "setBoolean": {
                                data.put((String) args[0], (Boolean) args[1]);
                                return null;
                            }
                            case "toString":
                                return "test-Preferences-stub";
                            default:
                                // 未覆盖的方法：原始类型返回 0/假，引用类型返回 null
                                Class<?> rt = method.getReturnType();
                                if (rt == boolean.class) return false;
                                if (rt == int.class) return 0;
                                if (rt == long.class) return 0L;
                                if (rt == short.class) return (short) 0;
                                if (rt == double.class) return 0d;
                                if (rt == float.class) return 0f;
                                if (rt == byte.class) return (byte) 0;
                                if (rt == char.class) return (char) 0;
                                return null;
                        }
                    }
                });
    }
}
