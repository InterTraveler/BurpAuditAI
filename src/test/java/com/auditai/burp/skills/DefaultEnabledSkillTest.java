package com.auditai.burp.skills;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link DefaultEnabledSkill} 的单元测试。
 *
 * <p>枚举值 id 必须与 {@code src/main/resources/skills/} 下的子目录名
 * 一一对应——否则首次安装后卡片不会被启用，浪费白名单位置。</p>
 */
class DefaultEnabledSkillTest {

    /** 验证 ids() 包含枚举里所有值、且按声明顺序。 */
    @Test
    void idsReturnsAllEnumValuesInDeclarationOrder() {
        Set<String> ids = DefaultEnabledSkill.ids();

        assertEquals(DefaultEnabledSkill.values().length, ids.size(),
                "ids() 数量应等于枚举值数量");

        // LinkedHashSet 保留插入顺序
        DefaultEnabledSkill[] values = DefaultEnabledSkill.values();
        int index = 0;
        for (String id : ids) {
            assertEquals(values[index].skillId(), id,
                    "ids() 顺序应与枚举声明顺序一致");
            index++;
        }
    }

    /** 验证 ids() 返回新集合，外部修改不影响枚举。 */
    @Test
    void idsReturnsMutableCopy() {
        Set<String> first = DefaultEnabledSkill.ids();
        first.add("rogue-id");
        Set<String> second = DefaultEnabledSkill.ids();
        assertFalse(second.contains("rogue-id"),
                "ids() 应返回新集合，外部修改不应污染枚举状态");
    }

    /** 验证每个枚举值的 id 都不为空、不含逗号（CSV 序列化要求）。 */
    @Test
    void allSkillIdsAreCsvSafe() {
        for (DefaultEnabledSkill value : DefaultEnabledSkill.values()) {
            String id = value.skillId();
            assertNotNull(id);
            assertFalse(id.isBlank(), "id 不能为空：" + value.name());
            assertFalse(id.contains(","), "id 不能含逗号（CSV 分隔符）：" + id);
        }
    }

    /** 验证每个枚举 id 都能在打包后的 classpath:/skills/ 资源下找到对应 SKILL.md 文件。 */
    @Test
    void everyDefaultEnabledSkillHasABackingFile() {
        Set<String> loadedIds = SkillLoader
                .fromClasspath("skills", getClass().getClassLoader())
                .load()
                .stream()
                .map(Skill::id)
                .collect(java.util.stream.Collectors.toSet());
        for (DefaultEnabledSkill value : DefaultEnabledSkill.values()) {
            assertTrue(loadedIds.contains(value.skillId()),
                    "枚举 " + value.name() + " 指向 " + value.skillId()
                            + "，但 classpath:/skills/ 下没有对应的 SKILL.md");
        }
    }
}
