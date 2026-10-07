package com.auditai.burp.skills;

import burp.api.montoya.persistence.Preferences;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 技能启用态与"自动激活"（pinned）集合的持久化仓库。
 *
 * <p>首次启动（{@code initialized} 缺失）：返回 DefaultEnabledSkill#ids() 副本；
 * 后续启动：从 CSV 恢复，pinned 集合走平行键。
 * 任何一次 #saveEnabledIds(Set) 都会把 {@code initialized} 置 true，
 * 永久脱离默认分支。</p>
 *
 * <p>本类非 {@code final}：{@code TrafficFlowWalkthroughTest} 等集成测试需要继承
 * 覆盖 #loadEnabledIds() 提供内存版实现。</p>
 */
public class SkillStateStore {

    /** "已初始化"标志 key。一旦为 true，#loadEnabledIds() 不再走默认值。 */
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
     * 加载启用的技能 id 集合。每次返回新集合，调用方可安全修改。
     *
     * @return 不可保证顺序（按枚举声明顺序 / CSV 写入顺序）。
     */
    public Set<String> loadEnabledIds() {
        if (!Boolean.TRUE.equals(preferences.getBoolean(INITIALIZED_KEY))) {
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
     * 不应该像 #loadEnabledIds() 那样回退到默认集混淆"用户的选择"。</p>
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
