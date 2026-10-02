package com.auditai.burp.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * {@link AiConfig} 单元测试：{@code AiConfig} 只承载"单条 AI 服务配置"
 * （name / baseUrl / apiKey / model / timeout / maxTokens），全局提示词由 {@link Settings}
 * 持有。本测试覆盖字段读写、{@link AiConfig#copyFrom} 的"原地替换字段"语义。
 */
final class AiConfigTest {

    /** 无参构造应给出一份"空白但合法"配置（合理默认超时 / token 数）。 */
    @Test
    void noArgConstructorGivesBlankConfig() {
        AiConfig cfg = new AiConfig();
        assertNotNull(cfg);
        assertEquals("", cfg.getName());
        assertEquals("", cfg.getBaseUrl());
        assertEquals("", new String(cfg.getApiKey()));
        assertEquals("", cfg.getModel());
        assertEquals(60, cfg.getTimeoutSeconds());
        assertEquals(AiConfig.DEFAULT_MAX_TOKENS, cfg.getMaxTokens());
    }

    /**
     * {@link AiConfig#copyFrom} 应原地替换所有字段、不改变 Java 引用：
     * Settings 切换激活项时复用同一个共享对象，下游组件（AI 客户端）继续持有
     * 原引用但立刻读到新字段。
     */
    @Test
    void copyFromReplacesAllFieldsInPlace() {
        AiConfig target = new AiConfig("Original", "url1", "k1", "m1", 10, 1024);
        AiConfig source = new AiConfig("Updated", "url2", "k2", "m2", 99, 4096);

        AiConfig ref = target;
        target.copyFrom(source);

        // 引用未变
        assertEquals(ref, target);
        // 字段已全部替换
        assertEquals("Updated", target.getName());
        assertEquals("url2", target.getBaseUrl());
        assertEquals("k2", new String(target.getApiKey()));
        assertEquals("m2", target.getModel());
        assertEquals(99, target.getTimeoutSeconds());
        assertEquals(4096, target.getMaxTokens());
    }

    /** copyFrom(null) 应为安全 no-op，避免上游传 null 时崩溃。 */
    @Test
    void copyFromNullIsNoOp() {
        AiConfig cfg = new AiConfig("X", "u", "k", "m", 30, 1024);
        cfg.copyFrom(null);
        assertEquals("X", cfg.getName());
        assertEquals("u", cfg.getBaseUrl());
    }

}
