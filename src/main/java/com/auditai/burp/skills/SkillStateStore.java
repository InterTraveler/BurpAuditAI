package com.auditai.burp.skills;

import burp.api.montoya.persistence.Preferences;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 技能启用态的持久化仓库（类似 {@code com.auditai.burp.config.SettingsStore} 的定位）。
 *
 * <p>持久化策略：</p>
 * <ul>
 *   <li><b>首次安装</b>（{@code initialized} 标志为 false 或缺失）：
 *       返回 {@link DefaultEnabledSkill#ids()} 的副本，让"新手套装"自动启用；</li>
 *   <li><b>后续启动</b>（{@code initialized} 为 true）：从 CSV 字符串恢复，
 *       即使结果与 {@link DefaultEnabledSkill} 完全不同也不覆盖——尊重用户选择；</li>
 *   <li>每次 {@link #saveEnabledIds(Set)} 都同步把 {@code initialized} 置 true，
 *       确保"用户在 UI 改动一次"就永久脱离"首次安装"分支。</li>
 * </ul>
 *
 * <p>CSV 格式：以半角逗号分隔、按 {@link DefaultEnabledSkill#ids()} 同一顺序写入；
 * 读取时容忍空白字符与空字段，便于手工编辑偏好文件（理论上 Montoya Preferences
 * 也支持手工改动）。</p>
 *
 * <p><b>"自动激活"（pinned）</b>：除普通启用态外，另存一份
 * {@link #loadPinnedIds() pinned id 集合}。pinned ⊆ enabled——被"自动激活"的技能一定处于
 * 启用态，但启用态不必是自动激活。"自动激活"的技能不进 phase 1 的"可选"列表，模型不会被
 * 问到"是否启用"，但每次分析都会自动注入到 phase 2 的 system 段。CSV 存储、错误容忍
 * 策略与 enabled 平行。</p>
 *
 * <p><b>可扩展性：</b>本类是非 {@code final} 的——{@code TrafficFlowWalkthroughTest}
 * 等集成测试需要继承并覆盖 {@link #loadEnabledIds()} 提供内存版实现，避开
 * {@code Montoya Preferences} 的工厂依赖。生产代码不应继承本类。</p>
 */
public class SkillStateStore {

    /** "已初始化"标志 key。一旦为 true，{@link #loadEnabledIds()} 不再走默认值。 */
    private static final String INITIALIZED_KEY = "com.auditai.skills.initialized";

    /** 启用 id 列表的 CSV 存储 key。 */
    private static final String ENABLED_IDS_KEY = "com.auditai.skills.enabledIds";

    /** "自动激活" id 列表的 CSV 存储 key。 */
    private static final String PINNED_IDS_KEY = "com.auditai.skills.pinnedIds";

    private static final String CSV_SEPARATOR = ",";

    private final Preferences preferences;

    /**
     * @param preferences Montoya 持久化偏好对象；通常取
     *                    {@code api.persistence().preferences()}。本类不持有其它资源，
     *                    无需 {@code close}。
     */
    public SkillStateStore(Preferences preferences) {
        this.preferences = preferences;
    }

    /**
     * 加载启用的技能 id 集合。
     *
     * <p>注意：本方法可能在构造期被调用，每次返回新集合，调用方可以安全地修改返回结果
     * 而不影响持久化层。</p>
     *
     * @return 不可保证顺序（当前实现按枚举声明顺序 / CSV 写入顺序）。
     */
    public Set<String> loadEnabledIds() {
        if (!Boolean.TRUE.equals(preferences.getBoolean(INITIALIZED_KEY))) {
            // 首次安装：直接返回默认启用集的副本，不写回持久化——
            // 真正的"持久化首次化"要等用户第一次改动（或插件第一次主动保存）才发生。
            return new LinkedHashSet<>(DefaultEnabledSkill.ids());
        }
        String csv = preferences.getString(ENABLED_IDS_KEY);
        if (csv == null || csv.isBlank()) {
            return new LinkedHashSet<>();
        }
        return Arrays.stream(csv.split(CSV_SEPARATOR))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    /**
     * 把当前启用的技能 id 集合写回持久化，并同步把 {@code initialized} 置 true。
     *
     * <p>下次 {@link #loadEnabledIds()} 会走持久化路径，<b>不再</b>回退到
     * {@link DefaultEnabledSkill}——这是"尊重用户选择"的关键点。</p>
     */
    public void saveEnabledIds(Set<String> enabledIds) {
        String csv = String.join(CSV_SEPARATOR, enabledIds);
        preferences.setString(ENABLED_IDS_KEY, csv);
        preferences.setBoolean(INITIALIZED_KEY, true);
    }

    /**
     * 加载"自动激活"的技能 id 集合。
     *
     * <p>未持久化过（首次安装）时返回空集——"自动激活"是一个明确的用户意图，
     * 不应该像 {@link #loadEnabledIds()} 那样回退到默认集混淆"用户的选择"。</p>
     *
     * <p>同样每次返回新集合，调用方可安全修改。</p>
     */
    public Set<String> loadPinnedIds() {
        String csv = preferences.getString(PINNED_IDS_KEY);
        if (csv == null || csv.isBlank()) {
            return new LinkedHashSet<>();
        }
        return Arrays.stream(csv.split(CSV_SEPARATOR))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    /**
     * 把"自动激活"的技能 id 集合写回持久化。
     *
     * <p>本方法不联动 {@code initialized} 标志——"自动激活"集合为空是合法状态
     * （用户从未把任何技能设为自动激活），与"已初始化"无关。</p>
     */
    public void savePinnedIds(Set<String> pinnedIds) {
        String csv = String.join(CSV_SEPARATOR, pinnedIds);
        preferences.setString(PINNED_IDS_KEY, csv);
    }
}
