package com.auditai.burp.skills;

/**
 * 技能来源标签：决定 UI 上的视觉分组与"卸载"权限。
 *
 * <p>两类来源：</p>
 * <ul>
 *   <li>{@link #BUILTIN}——打包进插件 JAR 的内置技能（位于
 *       <code>src/main/resources/skills/</code>），用户不可卸载；</li>
 *   <li>{@link #USER}——用户从本地导入的自定义技能（位于
 *       {@code AuditAIData/<project>/custom-skills/<id>/SKILL.md}），
 *       用户可在 UI 上"卸载"。</li>
 * </ul>
 *
 * <p>同名 ID 同时出现在两类来源时，{@link SkillLoader} 让
 * {@link #USER} 覆盖 {@link #BUILTIN}——用户导入意图明确，"我用我自己的"。</p>
 */
public enum SkillSource {

    /** 内置技能（随插件发布，不可卸载）。 */
    BUILTIN,

    /** 用户导入的自定义技能（来自 AuditAIData，可卸载）。 */
    USER
}