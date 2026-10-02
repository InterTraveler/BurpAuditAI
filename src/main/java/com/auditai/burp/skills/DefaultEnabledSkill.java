package com.auditai.burp.skills;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * 用户<b>首次安装</b> AuditAI 时默认启用的技能白名单。
 *
 * <p>设计意图：插件一上来不要"啥都没开"，挑几个新手最常用、最有价值的技能默认开启，
 * 让用户立刻能看到 SKILLS 页签启用态的差异；其余技能留给用户在页签里手动启用。</p>
 *
 * <p><b>生效范围</b>：本枚举里的 id 只在用户<b>从未持久化过技能状态</b>时生效
 * （即首次安装）。一旦用户在 UI 里点过"启用 / 禁用"，后续启动完全由持久化数据
 * 决定，本枚举不会"覆盖"用户的选择——避免用户辛苦调好的状态被某次升级
 * 重置回默认值。</p>
 *
 * <p><b>添加新条目</b>：仅当 {@code src/main/resources/skills/}
 * （或约定的子目录 {@code skills/vuln/}、{@code skills/auxiliary/}）下
 * 确实有同名 {@code <id>/SKILL.md} 时再加进去；加载器找不到对应文件时会
 * 自动跳过，不会报错（参见 {@link SkillLoader#load}）。</p>
 */
public enum DefaultEnabledSkill {

    /** SQL 注入分析。 */
    SQL_INJECTION("sql-injection"),

    /** XSS 跨站脚本分析。 */
    XSS_DETECTOR("xss-detector"),

    /** SSRF 服务端请求伪造分析。 */
    SSRF_DETECTOR("ssrf-detector"),

    /** JWT 令牌分析。 */
    JWT_ANALYZER("jwt-analyzer"),

    /** 认证与授权绕过分析。 */
    AUTH_BYPASS("auth-bypass"),

    /** 敏感数据泄露分析。 */
    SENSITIVE_DATA("sensitive-data"),

    /** 命令注入分析（命中即 RCE，Web 渗透核心面）。 */
    COMMAND_INJECTION("command-injection"),

    /** 服务端模板注入分析（命中即 RCE）。 */
    SSTI("ssti"),

    /** 本地文件包含 / 路径穿越分析（信息泄露 / RCE 跳板）。 */
    LFI("lfi"),

    /** XML 外部实体注入分析。 */
    XXE("xxe"),

    /** CORS 跨域配置错误分析。 */
    CORS_MISCONFIG("cors-misconfig"),

    /** 反序列化漏洞分析（命中即 RCE）。 */
    DESERIALIZATION("deserialization");

    private final String skillId;

    DefaultEnabledSkill(String skillId) {
        this.skillId = skillId;
    }

    /** 关联的技能 id（即技能子目录名）。 */
    public String skillId() {
        return skillId;
    }

    /**
     * 当前枚举值对应的所有技能 id（不可变快照，按枚举声明顺序）。
     *
     * <p>返回的是新集合，调用方修改不会影响枚举内部状态。</p>
     */
    public static Set<String> ids() {
        Set<String> result = new LinkedHashSet<>();
        for (DefaultEnabledSkill value : values()) {
            result.add(value.skillId);
        }
        return result;
    }
}
