package com.auditai.burp.config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * 完整设置：所有 AI 服务配置 + 当前激活项 + 全局自定义系统提示词 + 被动分析配置。
 *
 * <p>当前激活项用一份独立的 {@link #activeConfig} 引用持有，切换时整体替换引用
 * （构造新 {@link AiConfig} 一次性发布）——下游组件读到的是"全旧"或"全新"的完整对象，
 * 不会出现"新 baseUrl + 旧 model"的撕裂读。</p>
 *
 * <p>列表可以为空（首次安装 / 用户清空）；配置名不能重名（UI 侧新增按钮保证）。</p>
 */
public final class Settings {

    private final List<AiConfig> configs;

    // 下游组件持这三个引用。activeConfig 是 AiConfig 多字段对象必须整体替换，
    // activeName 和 customPrompt 是 String 整体替换。EDT 写、TrafficAnalyzer
    // 单线程池读，volatile 保证可见性。

    /** 当前激活项的名称，列表为空时为 null。 */
    private volatile String activeName;

    /** 全局自定义系统提示词，所有 AI 配置共用。 */
    private volatile String customPrompt;

    /**
     * 当前激活项的稳定共享引用。下游组件（AI 客户端、分析器）持有它。
     * AiConfig 字段非 volatile，必须"整体替换引用"才不出现半新半旧。
     */
    private volatile AiConfig activeConfig;

    /** 是否启用被动流量分析；EDT 改、被动手 hook 读。 */
    private volatile boolean passiveAnalysisEnabled;

    /** 被动分析 URL 过滤正则；空串匹配全部。 */
    private volatile String passiveAnalysisUrlRegex;

    /** 构造配置集（兼容旧调用方，不携带被动分析配置）。 */
    public Settings(List<AiConfig> configs, String activeName, String customPrompt) {
        this(configs, activeName, customPrompt, false, "");
    }

    /**
     * @param configs                 所有 AI 服务配置；可为空，构造时复制为可变副本。
     * @param activeName             期望激活的配置名；找不到或 configs 为空时按"无激活"处理。
     * @param customPrompt           全局自定义系统提示词；null 时按空串处理。
     * @param passiveAnalysisEnabled 是否启用被动流量分析。
     * @param passiveAnalysisUrlRegex 被动分析的 URL 过滤正则；null 时按空串处理。
     */
    public Settings(List<AiConfig> configs, String activeName, String customPrompt,
                    boolean passiveAnalysisEnabled, String passiveAnalysisUrlRegex) {
        Objects.requireNonNull(configs, "configs");
        this.configs = new ArrayList<>(configs);
        this.customPrompt = customPrompt == null ? "" : customPrompt;
        this.passiveAnalysisEnabled = passiveAnalysisEnabled;
        this.passiveAnalysisUrlRegex = passiveAnalysisUrlRegex == null ? "" : passiveAnalysisUrlRegex;
        setActiveFrom(findByName(activeName));
    }

    /** 只读访问所有配置（UI 下拉列表与持久化的数据源）。 */
    public List<AiConfig> configs() {
        return Collections.unmodifiableList(configs);
    }

    /**
     * 切换 / 保存 / 重命名 / 删除时唯一入口：构造新 AiConfig 替换 activeConfig 引用。
     * AiConfig 字段非 volatile，必须"整体替换"才不会出现半新半旧。
     *
     * <p>两次独立 volatile 写（先 config 后 name）——目前没有同时读两者的跨线程路径，
     * 顺序保留；未来需要可收敛成不可变快照对象。</p>
     *
     * @param source 数据源（列表条目或临时构造的新 AiConfig）；null 时清空激活项。
     */
    private void setActiveFrom(AiConfig source) {
        if (source == null) {
            this.activeConfig = null;
            this.activeName = null;
            return;
        }
        this.activeConfig = new AiConfig(
                source.getName(),
                source.getBaseUrl(),
                source.getApiKey(),
                source.getModel(),
                source.getTimeoutSeconds(),
                source.getMaxTokens());
        this.activeName = source.getName();
    }

    /**
     * 公共入口：{@code SettingsPanel.tryApplyFormToSettings} 用表单字段构造新 AiConfig 后调用，
     * 取代旧实现里原地改 activeConfig 字段的多字段非原子写。
     */
    public void replaceActive(AiConfig newActive) {
        setActiveFrom(newActive);
    }

    /** 当前激活项的名称。列表为空时返回 null。 */
    public String activeName() {
        return activeName;
    }

    /** 当前激活项的稳定引用（切换时整体替换为新对象），列表为空时返回 null。 */
    public AiConfig activeConfig() {
        return activeConfig;
    }

    public String customPrompt() {
        return customPrompt;
    }

    /**
     * @param customPrompt 自定义系统提示词；null 当空串处理。
     */
    public void setCustomPrompt(String customPrompt) {
        this.customPrompt = customPrompt == null ? "" : customPrompt;
    }

    public boolean isPassiveAnalysisEnabled() {
        return passiveAnalysisEnabled;
    }

    public void setPassiveAnalysisEnabled(boolean passiveAnalysisEnabled) {
        this.passiveAnalysisEnabled = passiveAnalysisEnabled;
    }

    public String getPassiveAnalysisUrlRegex() {
        return passiveAnalysisUrlRegex;
    }

    /**
     * @param passiveAnalysisUrlRegex URL 过滤正则；null 当空串（匹配全部）。
     */
    public void setPassiveAnalysisUrlRegex(String passiveAnalysisUrlRegex) {
        this.passiveAnalysisUrlRegex = passiveAnalysisUrlRegex == null ? "" : passiveAnalysisUrlRegex;
    }

    /**
     * 切换激活项到指定名称。name 为空 / 找不到 / 与当前同名时 no-op。
     * 列表非空但"无激活项"（持久化的 activeName 是幽灵名）时允许选中列表条目恢复激活状态。
     *
     * @param name 目标配置名。
     */
    public void switchTo(String name) {
        if (name == null || name.isEmpty() || name.equals(activeName)) {
            return;
        }
        AiConfig target = findByName(name);
        if (target == null) {
            return;
        }
        setActiveFrom(target);
    }

    /**
     * 重命名当前激活项。调用前需校验：newName 非空、不与列表里"非当前激活项"的其他条目同名。
     * 不修改 activeConfig 的非名字段——调用方应在此之前把表单字段写到 activeConfig。
     *
     * @param newName 新名字。
     */
    public void renameActive(String newName) {
        if (newName == null || newName.isEmpty() || newName.equals(activeName) || activeName == null) {
            return;
        }
        configs.removeIf(c -> c.getName().equals(activeName));
        AiConfig renamed = cloneActive();
        if (renamed == null) {
            return;
        }
        renamed.setName(newName);
        configs.add(renamed);
        setActiveFrom(renamed);
    }

    /**
     * 按名移除列表条目（不改 activeConfig / activeName）。
     * 配合 {@link #replaceActive} 使用——改名后旧名条目不再被引用，需显式移除，
     * 否则下拉列表会残留"幽灵配置"。
     *
     * @param name 要移除的配置名；null / 空串时为 no-op。
     */
    public void removeConfigByName(String name) {
        if (name == null || name.isEmpty()) {
            return;
        }
        configs.removeIf(c -> Objects.equals(c.getName(), name));
    }

    /**
     * 把激活项按当前名称重新物化进列表（覆盖同名条目）。
     * 构造期已保证一致性，列在这里是给 {@code SettingsStore} 保存前做一次防御性同步。
     */
    public void syncActiveEntry() {
        if (activeName == null || activeConfig == null) {
            return;
        }
        configs.removeIf(c -> Objects.equals(c.getName(), activeName));
        configs.add(cloneActive());
    }

    /**
     * 添加新配置并切换到它。调用前确保 name 不重名（UI 侧新增按钮保证）。
     *
     * @param newConfig 新配置；null 时为 no-op。
     */
    public void addAndSwitchTo(AiConfig newConfig) {
        if (newConfig == null) {
            return;
        }
        configs.add(newConfig);
        setActiveFrom(newConfig);
    }

    /**
     * 删除当前激活项；列表还有其它配置时自动切到第一条，全删完则进入"无激活"。
     *
     * @return 删除成功返回 true；列表已经为空时返回 false。
     */
    public boolean removeActive() {
        if (configs.isEmpty() || activeName == null) {
            return false;
        }
        configs.removeIf(c -> Objects.equals(c.getName(), activeName));
        if (configs.isEmpty()) {
            setActiveFrom(null);
        } else {
            setActiveFrom(configs.get(0));
        }
        return true;
    }

    /** 首次安装的空配置集。 */
    public static Settings createDefault() {
        return new Settings(new ArrayList<>(), null, "");
    }

    /** 用 activeConfig 字段深拷贝一份独立 AiConfig；无激活项时返回 null。 */
    private AiConfig cloneActive() {
        if (activeConfig == null) {
            return null;
        }
        // 走 char[] 形式的 6 参构造器（getApiKey() 返回 char[]，匹配不到 String 重载）。
        return new AiConfig(activeConfig.getName(), activeConfig.getBaseUrl(),
                activeConfig.getApiKey(), activeConfig.getModel(),
                activeConfig.getTimeoutSeconds(), activeConfig.getMaxTokens());
    }

    private AiConfig findByName(String name) {
        if (name == null) {
            return null;
        }
        for (AiConfig c : configs) {
            if (name.equals(c.getName())) {
                return c;
            }
        }
        return null;
    }

    /** 已存在的所有配置名（只读快照），用于 UI 校验重名。 */
    public Set<String> existingNames() {
        Set<String> names = new LinkedHashSet<>();
        for (AiConfig c : configs) {
            if (c.getName() != null && !c.getName().isEmpty()) {
                names.add(c.getName());
            }
        }
        return names;
    }
}
