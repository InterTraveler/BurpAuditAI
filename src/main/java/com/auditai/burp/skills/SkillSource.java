package com.auditai.burp.skills;

/**
 * 技能来源标签：决定 UI 上的视觉分组与"卸载"权限。
 *
 * <p>同名 ID 在 BUILTIN 和 USER 都出现时，SkillLoader 让 USER 覆盖 BUILTIN。</p>
 */
public enum SkillSource {

    /** 内置技能（{@code src/main/resources/skills/}），不可卸载。 */
    BUILTIN,

    /** 用户导入的自定义技能（{@code <数据根>/projects/<id>/custom-skills/}，数据根见 SessionPaths 类），可卸载。 */
    USER
}