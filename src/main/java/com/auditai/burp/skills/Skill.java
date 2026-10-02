package com.auditai.burp.skills;

import java.util.Objects;

/**
 * 一个技能（SKILL）的不可变数据模型。
 *
 * <p>来源：{@link SkillLoader} 扫描项目内
 * <code>src/main/resources/skills/</code> 目录（按用途分两类子目录
 * <code>vuln/</code>、<code>auxiliary/</code>），按 <code>key=value</code>
 * 文本格式解析出以下字段。技能在分析时被注入到 {@code TrafficAnalyzer}
 * 的 system 提示词与 user 段。</p>
 *
 * <p>字段约定：</p>
 * <ul>
 *   <li><b>id</b>：技能唯一标识，由文件名（去后缀）派生；</li>
 *   <li><b>name</b>：技能显示名（必填，UI 主标题），缺该字段的文件会被加载器视为非法并跳过；</li>
 *   <li><b>icon</b>：技能图标，使用一个字符（emoji 或汉字）渲染为左侧正方形图标；
 *       缺省时显示默认占位符 {@link #DEFAULT_ICON}；</li>
 *   <li><b>description</b>：技能描述（可选），用于悬停提示与点击详情弹窗；</li>
 *   <li><b>prompt</b>：附加到 system 提示词的片段（可选），启用时被拼到
 *       {@code TrafficAnalyzer} 构造的 system 段末尾；</li>
 *   <li><b>userContext</b>：附加到 user 段的模板（可选），启用时被拼到 user 段；
 *       模板里支持占位符 {@code {related}} / {@code {summaryCount}}，由
 *       {@code TrafficAnalyzer} 填实际数据；</li>
 *   <li><b>summaryCount</b>：同域历史摘要条数上限（可选，{@code userContext} 不为空时生效），
 *       0 表示未设置，由 {@code TrafficAnalyzer} 决定默认值。</li>
 *   <li><b>findingType</b>：本技能负责产出的 finding 类型标识（可选），如 {@code sql-injection} /
 *       {@code xss}。声明后，{@code PromptBuilder} 会在阶段 2 的 system 段把该标识告诉模型，
 *       让模型把同类发现归到本技能下、避免多个并发技能抢同一类问题。多个技能
 *       findingType 不应重复；未声明时表示本技能不绑定具体 finding type。</li>
 *   <li><b>source</b>：技能来源标签（{@link SkillSource#BUILTIN} /
 *       {@link SkillSource#USER}），决定 UI 上的分组（内置 vs 自定义）与"卸载"权限。
 *       由 {@link SkillLoader} 在装载时根据 root 来源标记；调用方读
 *       {@link #source()} 即可判断当前技能是内置还是用户导入。</li>
 * </ul>
 */
public final class Skill {

    /**
     * 缺省图标：渲染为正方形内的单字符占位。
     */
    public static final String DEFAULT_ICON = "◆";

    /**
     * 摘要条数默认值：当 skill 声明了 userContext 但没写 summaryCount 时使用。
     */
    public static final int DEFAULT_SUMMARY_COUNT = 30;

    private final String id;
    private final String name;
    private final String icon;
    private final String description;
    private final String prompt;
    private final String userContext;
    private final int summaryCount;
    private final String findingType;
    private final SkillSource source;

    /**
     * 全字段构造器（用于按需构造；通常由 {@link SkillLoader} 调用）。
     *
     * @param id           技能唯一标识（由文件名派生）。
     * @param name         技能显示名（必填）。
     * @param icon         技能图标字符（可空，缺省为 {@link #DEFAULT_ICON}）。
     * @param description  技能描述（可空）。
     * @param prompt       附加到 system 提示词的片段（可空）。
     * @param userContext  附加到 user 段的模板（可空）。
     * @param summaryCount 同域历史摘要条数上限（&lt;1 表示未设置，使用 {@link #DEFAULT_SUMMARY_COUNT}）。
     * @param findingType  本技能负责的 finding type（可空）。空白字符串与 null 等价。
     * @param source       技能来源（{@link SkillSource#BUILTIN} / {@link SkillSource#USER}）。
     *                     不可为 null，缺省视为 {@link SkillSource#BUILTIN}。
     */
    public Skill(String id, String name, String icon, String description,
                 String prompt, String userContext, int summaryCount, String findingType,
                 SkillSource source) {
        this.id = Objects.requireNonNull(id, "id");
        this.name = Objects.requireNonNull(name, "name");
        this.icon = (icon == null || icon.isBlank()) ? DEFAULT_ICON : icon;
        this.description = description == null ? "" : description;
        this.prompt = prompt == null ? "" : prompt;
        this.userContext = userContext == null ? "" : userContext;
        this.summaryCount = Math.max(summaryCount, 0);
        this.findingType = (findingType == null || findingType.isBlank()) ? "" : findingType.trim();
        this.source = source == null ? SkillSource.BUILTIN : source;
    }

    /**
     * 兼容旧构造（不含 source / findingType）。保留供旧调用方与占位场景使用，
     * 新代码应优先用 9 参构造器。
     */
    public Skill(String id, String name, String icon, String description,
                 String prompt, String userContext, int summaryCount, String findingType) {
        this(id, name, icon, description, prompt, userContext, summaryCount, findingType,
                SkillSource.BUILTIN);
    }

    /**
     * 兼容旧构造（不含 findingType / source）。保留供旧调用方与占位场景使用。
     */
    public Skill(String id, String name, String icon, String description,
                 String prompt, String userContext, int summaryCount) {
        this(id, name, icon, description, prompt, userContext, summaryCount, null,
                SkillSource.BUILTIN);
    }

    /**
     * 兼容旧构造（仅元数据，不含 prompt / userContext / findingType / source），用于测试与占位场景。
     */
    public Skill(String id, String name, String icon, String description) {
        this(id, name, icon, description, null, null, 0, null, SkillSource.BUILTIN);
    }

    public String id() {
        return id;
    }

    public String name() {
        return name;
    }

    public String icon() {
        return icon;
    }

    public String description() {
        return description;
    }

    /**
     * 附加到 system 提示词的片段；可能为空串。
     */
    public String prompt() {
        return prompt;
    }

    /**
     * 附加到 user 段的模板；可能为空串。
     */
    public String userContext() {
        return userContext;
    }

    /**
     * 同域历史摘要条数上限。返回 0 表示"未设置"，调用方应回退到 {@link #DEFAULT_SUMMARY_COUNT}。
     */
    public int summaryCount() {
        return summaryCount;
    }

    /**
     * 本技能负责的 finding type（用于多技能并行时明确归类边界），可能为空串。
     */
    public String findingType() {
        return findingType;
    }

    /**
     * 技能来源：{@link SkillSource#BUILTIN} 为内置，
     * {@link SkillSource#USER} 为用户导入。UI 据此决定分组展示与"卸载"项可用性。
     */
    public SkillSource source() {
        return source;
    }

    /**
     * 是否声明了非空 finding type。
     */
    public boolean hasFindingType() {
        return !findingType.isEmpty();
    }

    /**
     * 是否声明了非空的 userContext（决定要不要把它拼到 user 段）。
     */
    public boolean hasUserContext() {
        return !userContext.isEmpty();
    }

    /**
     * 是否声明了非空的 system prompt 片段。
     */
    public boolean hasPrompt() {
        return !prompt.isEmpty();
    }

    @Override
    public String toString() {
        return "Skill{" + id + ":" + name + "}";
    }
}
