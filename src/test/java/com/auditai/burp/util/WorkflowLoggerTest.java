package com.auditai.burp.util;

import com.auditai.burp.ai.AiClient;
import com.auditai.burp.config.AiConfig;
import com.auditai.burp.util.WorkflowLogger.Source;
import com.auditai.burp.util.WorkflowLogger.TrailMessage;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * {@link WorkflowLogger} 的契约测试。
 *
 * <p>核心契约：</p>
 * <ul>
 *   <li><b>实例 API</b>（{@code appendAgent/appendAi/appendError}）不依赖 ThreadLocal，
 *       在任意线程上调用都能写到同一个 logger 的 buffer；</li>
 *   <li><b>静态 API</b>（{@code logRequest}）仅在绑定的"分析线程"上生效，跨线程调用
 *       静默丢弃（保持旧行为，避免回归）；</li>
 *   <li>{@code buffer} 在并发 append 下不丢数据也不破坏 XML 结构；</li>
 *   <li>{@link WorkflowLogger#readTrail(Path)} 能解析 instance API 写出的 XML，包括
 *       AI 响应里嵌套的 message（choices[0].message）。</li>
 * </ul>
 */
class WorkflowLoggerTest {

    @AfterEach
    void cleanupBinding() {
        // 防止跨测试用例遗留 ThreadLocal 绑定。
        WorkflowLogger.unbindFromCurrentThread();
    }

    // ============ 实例 API：写入与读出 ============

    @Test
    void instanceApiWritesAndRoundTripsThroughReadTrail() throws IOException {
        WorkflowLogger logger = WorkflowLogger.openForAnalysis();
        AiConfig config = stubConfig();

        logger.appendAgent(config, List.of(
                new AiClient.ChatMessage("system", "sys-prompt"),
                new AiClient.ChatMessage("user", "user-prompt")
        ), true);
        logger.appendAi("{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"hi\"}}],\"usage\":{\"prompt_tokens\":10}}");
        logger.appendError("oops");

        Path xml = Files.createTempFile("workflowlogger-", ".xml");
        try {
            logger.writeTo(xml);
            List<TrailMessage> messages = WorkflowLogger.readTrail(xml);
            // 期望 4 条：agent(system + user) + ai(choices 嵌套的 assistant message) +
            //          ai(error 块触发的兜底 message：<error>...</error> 无 message 子节点
            //          时 readTrail 补一条 role=error 的消息，避免 UI "有 ai 块却无内容"）
            assertEquals(4, messages.size(), "agent 两条 + ai 块嵌套 message 一条 + error 兜底一条");

            assertEquals("system", messages.get(0).role());
            assertEquals(Source.AGENT, messages.get(0).source());

            assertEquals("user", messages.get(1).role());
            assertEquals(Source.AGENT, messages.get(1).source());

            TrailMessage assistant = messages.get(2);
            assertEquals("assistant", assistant.role());
            assertEquals(Source.AI, assistant.source(),
                    "AI 响应的嵌套 message 必须通过 nearestSourceAncestor 解析到 <ai>");

            TrailMessage error = messages.get(3);
            assertEquals("error", error.role());
            assertEquals("oops", error.content());
            assertEquals(Source.AI, error.source());
        } finally {
            Files.deleteIfExists(xml);
        }
    }

    // ============ 实例 API 在异步线程上仍能写入 ============

    @Test
    void instanceApiIgnoresThreadLocalOnDifferentThread() throws IOException, InterruptedException {
        // 模拟"分析线程 bind 了 logger，但响应解析跑在异步回调线程上"的真实场景：
        // 静态入口在那个线程上 CURRENT.get() == null → 静默丢弃；
        // 实例入口直接把内容写到传入的 logger.buffer，无视 ThreadLocal。
        WorkflowLogger logger = WorkflowLogger.openForAnalysis();
        logger.bindToCurrentThread();   // 主线程 bind
        AiConfig config = stubConfig();

        CountDownLatch done = new CountDownLatch(1);
        AtomicInteger seen = new AtomicInteger();
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            CompletableFuture.runAsync(() -> {
                try {
                    // 1) 验证静态入口在异步线程上被静默丢弃（保持旧契约，不回归）
                    WorkflowLogger.logRequest(config, List.of(
                            new AiClient.ChatMessage("user", "ignored")), false);
                    // 2) 验证实例入口即使在异步线程上也能正确写入
                    logger.appendAi("{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"async-ok\"}}]}");
                    seen.incrementAndGet();
                } finally {
                    done.countDown();
                }
            }, pool).join();
            assertTrue(done.await(5, TimeUnit.SECONDS), "async task did not finish");
        } finally {
            pool.shutdownNow();
        }
        assertEquals(1, seen.get(), "async task should run exactly once");

        Path xml = Files.createTempFile("workflowlogger-async-", ".xml");
        try {
            logger.writeTo(xml);
            String content = Files.readString(xml);
            // 实例入口写入的 ai 块必须出现
            assertTrue(content.contains("async-ok"),
                    "instance appendAi on async thread must persist; got: " + content);
            // 静态 logRequest 在异步线程上被丢弃：XML 里不应出现该 user 段
            assertTrue(!content.contains("ignored"),
                    "static logRequest on async thread must be dropped");
        } finally {
            Files.deleteIfExists(xml);
        }
    }

    // ============ 并发安全：StringBuffer 保证 buffer 不被破坏 ============

    @Test
    void concurrentAppendAiDoesNotCorruptBuffer() throws IOException, InterruptedException {
        WorkflowLogger logger = WorkflowLogger.openForAnalysis();
        int threads = 16;
        int perThread = 50;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        try {
            for (int i = 0; i < threads; i++) {
                int id = i;
                pool.submit(() -> {
                    try {
                        start.await();
                        for (int j = 0; j < perThread; j++) {
                            // 写一个能识别的 payload：包含 thread id + 序号
                            logger.appendAi("{\"choices\":[{\"message\":{\"role\":\"assistant\","
                                    + "\"content\":\"t" + id + "-" + j + "\"}}]}");
                        }
                    } catch (InterruptedException ignored) {
                        Thread.currentThread().interrupt();
                    } finally {
                        done.countDown();
                    }
                });
            }
            start.countDown();
            assertTrue(done.await(10, TimeUnit.SECONDS), "concurrent appendAi did not finish");
        } finally {
            pool.shutdownNow();
        }

        Path xml = Files.createTempFile("workflowlogger-concurrent-", ".xml");
        try {
            logger.writeTo(xml);
            List<TrailMessage> messages = WorkflowLogger.readTrail(xml);
            assertEquals(threads * perThread, messages.size(),
                    "every async appendAi must survive (StringBuffer is thread-safe)");
            // 每个 (id, j) 组合都应能在 content 里找到一次（验证顺序拼接没乱）
            String content = Files.readString(xml);
            for (int i = 0; i < threads; i++) {
                for (int j = 0; j < perThread; j++) {
                    String token = "t" + i + "-" + j;
                    assertTrue(content.contains(token),
                            "missing payload for thread " + i + " seq " + j);
                }
            }
        } finally {
            Files.deleteIfExists(xml);
        }
    }

    // ============ 静态入口回归：在未绑定线程上仍是 no-op ============

    @Test
    void staticApiOnUnboundThreadIsNoOp() throws IOException {
        // 不 bind —— 模拟"调用方忘了 bind / 跨线程"。
        WorkflowLogger logger = WorkflowLogger.openForAnalysis();

        WorkflowLogger.logRequest(stubConfig(), List.of(
                new AiClient.ChatMessage("user", "ignored")), false);

        Path xml = Files.createTempFile("workflowlogger-noop-", ".xml");
        try {
            logger.writeTo(xml);
            String content = Files.readString(xml);
            // 仅 <context></context>，不应包含任何 <agent> / <ai> 块
            assertTrue(content.startsWith("<context>"));
            assertTrue(content.endsWith("</context>"));
            assertTrue(!content.contains("<agent>"));
            assertTrue(!content.contains("<ai>"));
        } finally {
            Files.deleteIfExists(xml);
        }
    }

    // ============ 静态入口在绑定线程上正常工作（保证旧行为） ============

    @Test
    void logRequestOnBoundThreadWrites() throws IOException {
        WorkflowLogger logger = WorkflowLogger.openForAnalysis();
        logger.bindToCurrentThread();

        WorkflowLogger.logRequest(stubConfig(), List.of(
                new AiClient.ChatMessage("user", "u")), false);

        Path xml = Files.createTempFile("workflowlogger-static-", ".xml");
        try {
            logger.writeTo(xml);
            List<TrailMessage> messages = WorkflowLogger.readTrail(xml);
            assertEquals(1, messages.size());
            assertEquals("user", messages.get(0).role());
        } finally {
            Files.deleteIfExists(xml);
        }
    }

    // ============ 工具方法 ============

    /**
     * 模型响应里含 C0 控制字符时，写出的 XML 必须仍可解析。
     *
     * <p>回归用例：JSON 转义 {@code "\u0001"} 经 Gson 还原成真实控制字符，而 XML 1.0
     * 既不允许它直接出现、也无法用字符引用表示——原样写盘会让整份 audit-trail 解析失败
     * （{@code readTrail} 抛 SAXException → IOException），UI 表现为"链路追踪打不开"。
     * 这里断言的是"能读回来"这一行为，而不是具体丢弃策略。</p>
     */
    @Test
    void readTrail_survivesControlCharactersInResponse() throws IOException {
        WorkflowLogger logger = WorkflowLogger.openForAnalysis();
        // 走真实响应形状（choices[0].message）：这样 readTrail 能取到 message 节点。
        // content 里放 \u0001 \u0000 \u001F（XML 非法，应被丢弃）+ \t \n（XML 合法，应保留）
        logger.appendAi("{\"choices\":[{\"message\":{\"role\":\"assistant\","
                + "\"content\":\"a\\u0001b\\u0000c\\u001fd\\te\\nf\"}}]}");

        Path xml = Files.createTempFile("workflowlogger-ctrl-", ".xml");
        try {
            logger.writeTo(xml);
            // 不抛异常 = XML 合法（这就是本用例的核心断言）
            List<TrailMessage> messages = WorkflowLogger.readTrail(xml);
            assertEquals(1, messages.size(), "应读回一条 assistant 消息，实际：" + messages);
            String content = messages.get(0).content();
            assertEquals("abcd\te\nf", content, "非法控制字符丢弃、\\t 与 \\n 保留");
        } finally {
            Files.deleteIfExists(xml);
        }
    }

    /**
     * JSON key 不是合法 XML 名时（数字开头、含空格、含 {@code <}），写出的 XML 必须仍可解析。
     *
     * <p>回归用例：{@code writeJsonValue} 直接把 JSON key 当元素名，模型返回
     * {@code {"1st": ...}} / {@code {"user name": ...}} 会产出非法 XML。</p>
     */
    @Test
    void readTrail_survivesInvalidJsonKeysAsElementNames() throws IOException {
        WorkflowLogger logger = WorkflowLogger.openForAnalysis();
        logger.appendAi("{\"1st\":\"v1\",\"user name\":\"v2\",\"a<b\":\"v3\",\"xmlThing\":\"v4\"}");

        Path xml = Files.createTempFile("workflowlogger-key-", ".xml");
        try {
            logger.writeTo(xml);
            WorkflowLogger.readTrail(xml); // 不抛异常即通过
            String content = Files.readString(xml);
            assertTrue(content.contains("<_st>v1</_st>"), "数字开头的 key 应被规范成合法元素名：" + content);
            assertTrue(content.contains("<user_name>v2</user_name>"), "含空格的 key 应被规范化：" + content);
            assertTrue(content.contains("<a_b>v3</a_b>"), "含 < 的 key 应被规范化：" + content);
            assertTrue(content.contains("<k_xmlThing>v4</k_xmlThing>"),
                    "以 xml 开头的 key 应加前缀（XML 保留前缀）：" + content);
        } finally {
            Files.deleteIfExists(xml);
        }
    }

    /**
     * 缓冲超上限后丢弃后续块，但仍写出结构合法、带截断标记的 XML。
     *
     * <p>上限是私有的 4M 字符常量，这里用一个明显超过它的块来触发；断言目标是
     * "XML 仍可解析 + 有截断标记 + 后续块确实被丢弃"，不耦合具体阈值。</p>
     */
    @Test
    void writeTo_truncatesOversizedBufferButKeepsXmlValid() throws IOException {
        WorkflowLogger logger = WorkflowLogger.openForAnalysis();
        // 单个块就超过 4M 字符上限
        logger.appendAi("{\"content\":\"" + "a".repeat(5_000_000) + "\"}");
        // 超限后的块应被整块丢弃
        logger.appendError("SHOULD-BE-DROPPED");

        Path xml = Files.createTempFile("workflowlogger-cap-", ".xml");
        try {
            logger.writeTo(xml);
            WorkflowLogger.readTrail(xml); // 结构必须仍合法
            String content = Files.readString(xml);
            assertTrue(content.contains("remaining blocks omitted"), "应写入截断标记：" + content.substring(0, 200));
            assertTrue(!content.contains("SHOULD-BE-DROPPED"), "超限后的块必须被丢弃");
            assertTrue(content.endsWith("</context>"), "XML 必须正常闭合");
        } finally {
            Files.deleteIfExists(xml);
        }
    }

    private static AiConfig stubConfig() {
        try {
            // 模型名 / max_tokens 都要写入 buffer，AiConfig 校验较严，用合法值。
            AiConfig cfg = new AiConfig();
            cfg.setModel("test-model");
            cfg.setBaseUrl("http://localhost:11434");
            cfg.setMaxTokens(1024);
            cfg.setTimeoutSeconds(60);
            return cfg;
        } catch (Exception e) {
            fail("AiConfig stub failed: " + e.getMessage());
            return null; // unreachable
        }
    }
}