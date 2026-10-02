package com.auditai.burp.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import com.auditai.burp.ai.AiClient;
import com.auditai.burp.ai.FakeAiClient;
import com.auditai.burp.config.Settings;
import com.auditai.burp.history.AnalysisHistoryStore;
import com.auditai.burp.history.AnalysisTrigger;
import com.auditai.burp.skills.SkillLoader;
import com.auditai.burp.skills.SkillStateStore;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 技能驱动两阶段分析的端到端走查（不联网，全程用 {@link FakeAiClient} 脚本响应）。
 *
 * <p>用例覆盖：</p>
 * <ul>
 *   <li>{@link #walkthroughNoSkillsEnabled}：无技能 → 1 次单轮调用；</li>
 *   <li>{@link #walkthroughModelPicksAndProceedsToPhase2}：阶段 1 模型选了 2 个技能 → 阶段 2
 *       用这 2 个技能的 prompt / userContext 完成最终分析，共 2 次调用；</li>
 *   <li>{@link #walkthroughModelSkipsPhase2}：阶段 1 模型选择 0 个技能 + 直接给 analysis →
 *       跳过阶段 2，只 1 次调用；</li>
 *   <li>{@link #walkthroughPhase1JsonInvalidFallsBackToAllSkills}：阶段 1 返回非 JSON →
 *       全量启用兜底，阶段 2 仍执行；</li>
 *   <li>{@link #walkthroughPhase2FailsFallsBackToPhase1Analysis}：阶段 2 失败但阶段 1
 *       有 analysis → 用阶段 1 兜底。</li>
 * </ul>
 */
class TrafficFlowWalkthroughTest {

    @BeforeAll
    static void enableDebugPromptLogs() {
        System.setProperty("auditai.debug.prompt", "true");
    }

    @AfterAll
    static void disableDebugPromptLogs() {
        System.clearProperty("auditai.debug.prompt");
    }

    /** 无任何技能启用：单次调用、user 段纯净。 */
    @Test
    void walkthroughNoSkillsEnabled() throws Exception {
        System.out.println();
        System.out.println("################ 走查开始：单轮无技能 ################");
        FakeAiClient ai = new FakeAiClient(
                "{\"analysis\": \"【风险点】无明显风险\\n【建议】保持现状\"}");
        try {
            InMemorySkillStateStore stateStore = new InMemorySkillStateStore();
            Path skillsDir = Files.createTempDirectory("auditai-skills-empty-");
            try {
                SkillLoader loader = SkillLoader.fromDirectory(skillsDir);
                TrafficAnalyzer analyzer = new TrafficAnalyzer(fakeMontoyaApi(), ai, Settings.createDefault(),
                        null, stateStore, loader);
                try {
                    HttpRequest request = fakeRequest("GET", "/me", "api.noskill.test", "");
                    HttpResponse response = fakeResponse((short) 200, "application/json", "{\"id\":1}");

                    AnalysisResult result = runAndAwait(analyzer, request, response);

                    assertEquals(1, ai.callCount(), "无技能应只调用模型一次");
                    assertNull(result.getError());
                    assertTrue(result.getSummary().startsWith("【风险点】"));
                    String system = ai.lastMessages().get(0).content();
                    assertTrue(!system.contains("【可选技能】"),
                            "无技能时 system 段不应有『可选技能』catalog");
                    assertTrue(!system.contains("【技能："),
                            "无技能时 system 段不应有技能片段");
                } finally {
                    // 守护线程执行器，无需 shutdown
                }
            } finally {
                deleteDirectory(skillsDir);
            }
        } finally {
            // FakeAiClient 不需要关闭
        }
        System.out.println("################ 走查结束：单轮无技能 ################");
    }

    /** 阶段 1 模型选 2 个技能：阶段 2 用选中的技能完成最终分析。 */
    @Test
    void walkthroughModelPicksAndProceedsToPhase2() throws Exception {
        System.out.println();
        System.out.println("################ 走查开始：两阶段，模型选了 2 个技能 ################");
        Path skillsDir = Files.createTempDirectory("auditai-skills-pick-");
        try {
            // 准备 2 个技能
            writeSkillMd(skillsDir, "sql-injection",
                    "---\nname: 'SQL 注入'\nicon: '💉'\n---\n\n关注 SQL 注入\n");
            writeSkillMd(skillsDir, "xss-detector",
                    "---\nname: 'XSS 检测'\nicon: '🧨'\n---\n\n关注 XSS\n");
            writeSkillMd(skillsDir, "auth-bypass",
                    "---\nname: '越权'\nicon: '🛂'\n---\n\n关注越权\n");

            InMemorySkillStateStore stateStore = new InMemorySkillStateStore();
            stateStore.setEnabled("sql-injection");
            stateStore.setEnabled("xss-detector");
            stateStore.setEnabled("auth-bypass");
            SkillLoader loader = SkillLoader.fromDirectory(skillsDir);

            // 脚本：阶段 1 模型选 2 个；阶段 2 给最终结论
            // 4 字段协议（active_skill_ids / analysis / risk / findings）：
            // 阶段 1 选技能 → risk="none", findings=[]
            // 阶段 2 最终结论无问题 → risk="none", findings=[]
            FakeAiClient ai = new FakeAiClient(
                    "{\"active_skill_ids\": [\"sql-injection\", \"xss-detector\"], "
                            + "\"analysis\": \"\", \"risk\": \"none\", \"findings\": []}",
                    "{\"active_skill_ids\": [], "
                            + "\"analysis\": \"【风险点】综合 SQL 注入与 XSS 视角，无明显风险\\n【建议】继续观察\", "
                            + "\"risk\": \"none\", \"findings\": []}");

            TrafficAnalyzer analyzer = new TrafficAnalyzer(fakeMontoyaApi(), ai, Settings.createDefault(),
                    null, stateStore, loader);
            try {
                HttpRequest request = fakeRequest("GET", "/users/1", "api.pick.test", "");
                HttpResponse response = fakeResponse((short) 200, "application/json", "{}");

                AnalysisResult result = runAndAwait(analyzer, request, response);

                assertEquals(2, ai.callCount(), "两阶段流程应调用模型 2 次");
                assertNull(result.getError());
                assertEquals("【风险点】综合 SQL 注入与 XSS 视角，无明显风险\n【建议】继续观察",
                        result.getSummary(), "最终结果应取自阶段 2 的 analysis");

                // 阶段 1 system 段：catalog 应列出 3 个候选（id + name），不含具体 prompt 片段
                List<AiClient.ChatMessage> phase1Messages = ai.callMessages().get(0);
                String phase1System = phase1Messages.get(0).content();
                assertTrue(phase1System.contains("【可选技能】"),
                        "阶段 1 system 段应包含『可选技能』catalog");
                assertTrue(phase1System.contains("id: sql-injection")
                                && phase1System.contains("id: xss-detector")
                                && phase1System.contains("id: auth-bypass"),
                        "catalog 应列出全部 3 个候选");
                assertTrue(!phase1System.contains("关注 SQL 注入"),
                        "阶段 1 不应注入具体 prompt 片段（只有 catalog）");
                assertTrue(phase1System.contains("active_skill_ids"),
                        "阶段 1 输出格式应要求 active_skill_ids");

                // 阶段 2 system 段：只拼接选中的 2 个技能的 prompt，不含未选中的 auth-bypass
                List<AiClient.ChatMessage> phase2Messages = ai.callMessages().get(1);
                String phase2System = phase2Messages.get(0).content();
                assertTrue(phase2System.contains("关注 SQL 注入")
                                && phase2System.contains("关注 XSS"),
                        "阶段 2 应注入选中的 2 个技能的 prompt");
                assertTrue(!phase2System.contains("关注越权"),
                        "阶段 2 不应注入未选中的 auth-bypass 技能");
            } finally {
                // 守护线程执行器，无需 shutdown
            }
        } finally {
            deleteDirectory(skillsDir);
        }
        System.out.println("################ 走查结束：两阶段，模型选了 2 个技能 ################");
    }

    /** 阶段 1 模型主动收尾：选 0 个技能 + 给 analysis → 跳过阶段 2。 */
    @Test
    void walkthroughModelSkipsPhase2() throws Exception {
        System.out.println();
        System.out.println("################ 走查开始：阶段 1 模型主动收尾 ################");
        Path skillsDir = Files.createTempDirectory("auditai-skills-skip-");
        try {
            writeSkillMd(skillsDir, "sql-injection",
                    "---\nname: 'SQL 注入'\nicon: '💉'\n---\n\n关注 SQL 注入\n");
            writeSkillMd(skillsDir, "xss-detector",
                    "---\nname: 'XSS'\nicon: '🧨'\n---\n\n关注 XSS\n");

            InMemorySkillStateStore stateStore = new InMemorySkillStateStore();
            stateStore.setEnabled("sql-injection");
            stateStore.setEnabled("xss-detector");
            SkillLoader loader = SkillLoader.fromDirectory(skillsDir);

            // 模型决定不要任何技能，直接给最终结论（4 字段协议 + risk="none"）
            FakeAiClient ai = new FakeAiClient(
                    "{\"active_skill_ids\": [], "
                            + "\"analysis\": \"【风险点】请求简单，无需专项技能\\n【建议】保持\", "
                            + "\"risk\": \"none\", \"findings\": []}");

            TrafficAnalyzer analyzer = new TrafficAnalyzer(fakeMontoyaApi(), ai, Settings.createDefault(),
                    null, stateStore, loader);
            try {
                HttpRequest request = fakeRequest("GET", "/health", "api.skip.test", "");
                HttpResponse response = fakeResponse((short) 200, "text/plain", "ok");

                AnalysisResult result = runAndAwait(analyzer, request, response);

                assertEquals(1, ai.callCount(), "阶段 1 模型主动收尾时不应触发阶段 2");
                assertNull(result.getError());
                assertEquals("【风险点】请求简单，无需专项技能\n【建议】保持", result.getSummary());
                // 阶段 1 也声明了 risk=none + findings=[]：最终 AnalysisResult 应不含 finding
                assertTrue(result.getFindings().isEmpty(), "无风险时不应入库 finding");
            } finally {
                // 守护线程执行器，无需 shutdown
            }
        } finally {
            deleteDirectory(skillsDir);
        }
        System.out.println("################ 走查结束：阶段 1 模型主动收尾 ################");
    }

    /**
     * 阶段 1 模型判断"无明显风险"时直接给最终结论（含 risk + findings 完整声明） →
     * 跳过阶段 2，且最终 AnalysisResult 正确反映 risk/findings。
     *
     * <p>这条路径验证：当模型在阶段 1 就把最终结论写完（不必再调阶段 2），插件仍能把
     * 结构化 finding 提取出来（而不是只取 analysis 文本、丢 findings）。</p>
     */
    @Test
    void walkthroughModelGivesFinalConclusionInPhase1() throws Exception {
        System.out.println();
        System.out.println("################ 走查开始：阶段 1 直接给最终结论（含 findings） ################");
        Path skillsDir = Files.createTempDirectory("auditai-skills-final-");
        try {
            writeSkillMd(skillsDir, "sql-injection",
                    "---\nname: 'SQL 注入'\nicon: '💉'\n---\n\n关注 SQL 注入\n");

            InMemorySkillStateStore stateStore = new InMemorySkillStateStore();
            stateStore.setEnabled("sql-injection");
            SkillLoader loader = SkillLoader.fromDirectory(skillsDir);

            // 模型在阶段 1 直接给最终结论：包含 risk + findings（不再走阶段 2）
            String phase1Final = "{\"active_skill_ids\": [], "
                    + "\"analysis\": \"【风险点】参数 id 存在注入风险\\n【建议】使用参数化查询\", "
                    + "\"risk\": \"high\", "
                    + "\"findings\": [{\"type\": \"SQL 注入\", \"confidence\": 85, "
                    + "\"description\": \"参数 id 存在注入\"}]}";
            FakeAiClient ai = new FakeAiClient(phase1Final);

            TrafficAnalyzer analyzer = new TrafficAnalyzer(fakeMontoyaApi(), ai, Settings.createDefault(),
                    null, stateStore, loader);
            try {
                HttpRequest request = fakeRequest("GET", "/user?id=1", "api.final.test", "");
                HttpResponse response = fakeResponse((short) 200, "application/json", "{}");

                AnalysisResult result = runAndAwait(analyzer, request, response);

                assertEquals(1, ai.callCount(), "阶段 1 已给最终结论，不应再调阶段 2");
                assertNull(result.getError());
                assertEquals("【风险点】参数 id 存在注入风险\n【建议】使用参数化查询", result.getSummary());
                // 关键断言：阶段 1 声明的 finding 也被正确提取
                assertEquals(1, result.getFindings().size());
                Finding f = result.getFindings().get(0);
                assertEquals("SQL 注入", f.getType());
                assertEquals(85, f.getConfidence());
                assertEquals("参数 id 存在注入", f.getDescription());
                assertEquals(Severity.HIGH, f.getSeverity());
                assertFalse(f.isPlaceholder());
            } finally {
                // 守护线程执行器，无需 shutdown
            }
        } finally {
            deleteDirectory(skillsDir);
        }
        System.out.println("################ 走查结束：阶段 1 直接给最终结论 ################");
    }

    /**
     * 阶段 1 返回非 JSON → fail-fast 跳过阶段 2。
     *
     * <p>阶段 1 解析失败时直接 fail-fast：打 ERROR 日志 + 占位 analysis 收尾，
     * 不进入 phase 2。模型调用次数应等于阶段 1。</p>
     */
    @Test
    void walkthroughPhase1JsonInvalidFailsFastSkipsPhase2() throws Exception {
        System.out.println();
        System.out.println("################ 走查开始：阶段 1 非 JSON → fail-fast ################");
        Path skillsDir = Files.createTempDirectory("auditai-skills-badjson-");
        try {
            writeSkillMd(skillsDir, "sql-injection",
                    "---\nname: 'SQL 注入'\nicon: '💉'\n---\n\n关注 SQL 注入\n");
            writeSkillMd(skillsDir, "xss-detector",
                    "---\nname: 'XSS'\nicon: '🧨'\n---\n\n关注 XSS\n");

            InMemorySkillStateStore stateStore = new InMemorySkillStateStore();
            stateStore.setEnabled("sql-injection");
            stateStore.setEnabled("xss-detector");
            SkillLoader loader = SkillLoader.fromDirectory(skillsDir);

            // 阶段 1 模型返回纯文本（非 JSON，宽松 fallback 也救不了）
            FakeAiClient ai = new FakeAiClient("（模型自由文本，不是 JSON）");

            TrafficAnalyzer analyzer = new TrafficAnalyzer(fakeMontoyaApi(), ai, Settings.createDefault(),
                    null, stateStore, loader);
            try {
                HttpRequest request = fakeRequest("GET", "/x", "api.badjson.test", "");
                HttpResponse response = fakeResponse((short) 200, "text/plain", "ok");

                AnalysisResult result = runAndAwait(analyzer, request, response);

                assertEquals(1, ai.callCount(), "阶段 1 解析完全失败时应直接收尾，仅触发一次模型调用");
                assertNull(result.getError(), "fail-fast 用 success() 工厂，error 字段应为 null");
                String summary = result.getSummary();
                assertNotNull(summary);
                assertTrue(summary.contains("阶段 1 解析失败"),
                        "占位 analysis 应明确告诉用户阶段 1 失败，实际：" + summary);
                assertTrue(summary.contains("不是 JSON 对象"),
                        "占位 analysis 应包含失败原因描述，实际：" + summary);
                assertTrue(result.getFindings().isEmpty(),
                        "阶段 1 失败时不应有 finding（结构化信息源不可信）");
            } finally {
                // 守护线程执行器，无需 shutdown
            }
        } finally {
            deleteDirectory(skillsDir);
        }
        System.out.println("################ 走查结束：阶段 1 非 JSON → fail-fast ################");
    }

    /**
     * 模型在阶段 1 选 "多报文协同" 技能：阶段 2 的 user 段应包含从 store 拉取的同域历史摘要，
     * 且 {related} / {summaryCount} 占位符都已被实际数据替换。
     *
     * <p>这是"技能 = 行为注入"的端到端验证：用户启用一个技能 → 阶段 2 把技能的
     * userContext 模板渲染好塞进 user 段 → 模型拿到的就是带历史摘要的提示词。
     * 同时验证阶段 1 的 user 段<b>不</b>预填摘要（业内做法"两层信息架构"的核心契约）。</p>
     */
    @Test
    void walkthroughModelPicksMultiMessageCorrelationSkill() throws Exception {
        System.out.println();
        System.out.println("################ 走查开始：模型选『多报文协同』技能 ################");
        Path skillsDir = Files.createTempDirectory("auditai-skills-multi-");
        Path storeDir = Files.createTempDirectory("auditai-store-multi-");
        try {
            // 1) 准备技能文件：含 prompt + userContext 模板（{related} / {summaryCount}）+ summaryCount
            writeSkillMd(skillsDir, "multi-message-correlation",
                    "---\n"
                            + "name: '多报文协同分析'\n"
                            + "icon: '🔗'\n"
                            + "description: '把同域名近期 HTTP 请求摘要附加到 user 段。'\n"
                            + "userContext: |\n"
                            + "  以下是同域名近期 {summaryCount} 条历史请求摘要：\n"
                            + "  {related}\n"
                            + "summaryCount: 15\n"
                            + "---\n"
                            + "\n"
                            + "你可以参考同域名的历史请求摘要，但不要把摘要当作分析目标。\n");

            // 2) 准备 store：2 条同域历史 + 1 条不同域历史（确认只取同域）。
            //    历史报文特意写得"真实"——多 headers（部分超长触发截断 / 部分敏感触发脱敏）+
            //    JSON body（部分字段超长触发 value 截断 / 部分数组超 8 元素触发数组截断），
            //    这样 TrafficCompactor 的各类压缩策略都能在测试里被实际触发。
            AnalysisHistoryStore store = new AnalysisHistoryStore(storeDir, 10, 1024L * 1024,
                    msg -> { });
            try {
                // —— 历史 1：GET 用户详情（含鉴权头 + 长 User-Agent + JSON 数组超 8 元素）——
                //    注：响应 body 的 JSON 故意只放 6 个顶层 key（MAX_JSON_OBJECT_KEYS 上限），
                //    让 tags 数组能进入 compactJsonArray 触发"超 8 元素"截断，
                //    同时 bio / createdAt 等超长 value 触发"超 20 字符"截断。
                String req1 = "GET /api/v2/users/12345?include=profile,orders HTTP/1.1\r\n"
                        + "Host: api.multi.test\r\n"
                        + "Accept: application/json, application/xml;q=0.9, */*;q=0.8\r\n"
                        + "Accept-Encoding: gzip, deflate, br\r\n"
                        + "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\r\n"
                        + "X-Request-Id: 7f8e9d6c-5b4a-3210-fedc-ba9876543210\r\n"
                        + "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0\r\n"
                        + "Referer: https://admin.multi.test/dashboard\r\n"
                        + "\r\n";
                String res1 = "HTTP/1.1 200 OK\r\n"
                        + "Content-Type: application/json; charset=utf-8\r\n"
                        + "Cache-Control: no-cache, no-store, must-revalidate\r\n"
                        + "X-RateLimit-Remaining: 99\r\n"
                        + "Set-Cookie: session=abcd1234efgh5678ijkl9012mnop; HttpOnly; Secure; Path=/; SameSite=Strict\r\n"
                        + "\r\n"
                        + "{\"id\":12345,\"name\":\"alice\","
                        + "\"bio\":\"这是一段非常长的个人简介用于触发 JSON value 截断行为验证\","
                        + "\"createdAt\":\"2025-08-31T10:30:00Z\","
                        + "\"role\":\"user\","
                        + "\"tags\":[\"tag1\",\"tag2\",\"tag3\",\"tag4\",\"tag5\",\"tag6\",\"tag7\",\"tag8\",\"tag9\",\"tag10\",\"tag11\"]}";
                seedHistory(store, "GET", "https://api.multi.test/api/v2/users/12345?include=profile,orders",
                        200, req1.getBytes(StandardCharsets.UTF_8), res1.getBytes(StandardCharsets.UTF_8), 1L);
                Thread.sleep(5); // 保证 recordId 2 的 capturedAt 晚于 recordId 1
                // —— 历史 2：POST 登录失败（敏感 CSRF/Cookie 头 + 密码 + Set-Cookie 响应）——
                //    响应 body 也只放 6 个 key，确保 password / lockedUntil / traceId
                //    都能进入 compactJsonValue 触发"超 20 字符"截断。
                String req2 = "POST /api/v1/auth/login HTTP/1.1\r\n"
                        + "Host: api.multi.test\r\n"
                        + "Content-Type: application/json\r\n"
                        + "X-Forwarded-For: 192.168.1.100, 10.0.0.5\r\n"
                        + "X-CSRF-Token: abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567\r\n"
                        + "X-Real-IP: 192.168.1.100\r\n"
                        + "Cookie: tracking=visitor_42; preferences=lang=zh\r\n"
                        + "\r\n"
                        + "{\"username\":\"alice\","
                        + "\"password\":\"super-secret-password-do-not-leak-1234567890\","
                        + "\"rememberMe\":true,\"captcha\":\"a1b2c3\"}";
                String res2 = "HTTP/1.1 401 Unauthorized\r\n"
                        + "Content-Type: application/json; charset=utf-8\r\n"
                        + "WWW-Authenticate: Bearer realm=\"api\", error=\"invalid_token\"\r\n"
                        + "Set-Cookie: failed_attempts=3; Max-Age=900; Path=/\r\n"
                        + "\r\n"
                        + "{\"error\":\"invalid_credentials\","
                        + "\"lockedUntil\":\"2025-08-31T11:00:00Z\","
                        + "\"traceId\":\"abcdef1234567890abcdef1234567890\"}";
                seedHistory(store, "POST", "https://api.multi.test/api/v1/auth/login",
                        401, req2.getBytes(StandardCharsets.UTF_8), res2.getBytes(StandardCharsets.UTF_8), 2L);
                // 跨域：应被排除（host 是 other.test）
                seedHistory(store, "GET", "https://other.test/foo", 200,
                        "GET /foo HTTP/1.1\r\nHost: other.test\r\nAuthorization: Bearer should-not-leak\r\n\r\n"
                                .getBytes(StandardCharsets.UTF_8),
                        new byte[0], 3L);

                // 3) 启用态：只启用 multi-message-correlation
                InMemorySkillStateStore stateStore = new InMemorySkillStateStore();
                stateStore.setEnabled("multi-message-correlation");
                SkillLoader loader = SkillLoader.fromDirectory(skillsDir);

                // 4) 脚本：阶段 1 选了 multi-message-correlation；阶段 2 出最终结论
                //    4 字段协议：阶段 1 选技能 → risk="none", findings=[]；
                //    阶段 2 最终无问题 → risk="none", findings=[]
                FakeAiClient ai = new FakeAiClient(
                        "{\"active_skill_ids\": [\"multi-message-correlation\"], "
                                + "\"analysis\": \"\", \"risk\": \"none\", \"findings\": []}",
                        "{\"active_skill_ids\": [], "
                                + "\"analysis\": \"【风险点】结合历史看当前请求属正常行为\\n【建议】保持\", "
                                + "\"risk\": \"none\", \"findings\": []}");

                TrafficAnalyzer analyzer = new TrafficAnalyzer(fakeMontoyaApi(), ai, Settings.createDefault(),
                        store, stateStore, loader);
                try {
                    HttpRequest request = fakeRequest("GET", "/me", "api.multi.test", "");
                    HttpResponse response = fakeResponse((short) 200, "application/json", "{\"id\":1}");

                    AnalysisResult result = runAndAwait(analyzer, request, response);

                    // —— 基础断言 ——
                    assertEquals(2, ai.callCount(), "选 1 个技能 → 阶段 1 + 阶段 2 共 2 次");
                    assertNull(result.getError());
                    assertEquals("【风险点】结合历史看当前请求属正常行为\n【建议】保持",
                            result.getSummary(), "最终结果应取阶段 2 的 analysis");

                    // —— 阶段 1 契约 ——
                    List<AiClient.ChatMessage> phase1 = ai.callMessages().get(0);
                    String p1System = phase1.get(0).content();
                    String p1User = phase1.get(1).content();

                    // system 段：catalog 应列出 multi-message-correlation，但不含其具体 prompt
                    assertTrue(p1System.contains("id: multi-message-correlation")
                                    && p1System.contains("name: 多报文协同分析"),
                            "阶段 1 catalog 应列出多报文协同技能");
                    assertTrue(p1System.contains("用途:") || p1System.contains("把同域名近期"),
                            "阶段 1 catalog 应展示技能的『用途』描述");
                    assertTrue(!p1System.contains("不要把摘要当作分析目标"),
                            "阶段 1 不应注入多报文协同的具体 prompt 片段");

                    // user 段：含完整报文，但**不**含历史摘要（关键契约）
                    assertTrue(p1User.contains("Host: api.multi.test")
                                    || p1User.contains("GET /me"),
                            "阶段 1 user 段应含完整报文");
                    assertTrue(!p1User.contains("同域名")
                                    && !p1User.contains("历史请求摘要")
                                    && !p1User.contains("ID=1") && !p1User.contains("ID=2"),
                            "阶段 1 user 段不应预填同域历史摘要（业内做法『两层信息架构』契约）");

                    // —— 阶段 2 契约 ——
                    List<AiClient.ChatMessage> phase2 = ai.callMessages().get(1);
                    String p2System = phase2.get(0).content();
                    String p2User = phase2.get(1).content();

                    // system 段：含多报文协同的 prompt 片段
                    assertTrue(p2System.contains("【技能：多报文协同分析】")
                                    && p2System.contains("不要把摘要当作分析目标"),
                            "阶段 2 system 段应注入多报文协同的 prompt 片段");

                    // user 段：含完整报文 + 多报文协同的 userContext 渲染结果
                    assertTrue(p2User.contains("【技能：多报文协同分析】"),
                            "阶段 2 user 段应追加多报文协同的 userContext 段");
                    // 模板里 {related} 应被替换为实际摘要（含 ID=1 / ID=2，按时间倒序：2 在前）
                    assertTrue(p2User.contains("ID=2") && p2User.contains("ID=1"),
                            "user 段应含同域摘要（ID=1、ID=2，按时间倒序：2 在前）");
                    assertTrue(p2User.contains("https://api.multi.test/api/v2/users/12345")
                                    && p2User.contains("https://api.multi.test/api/v1/auth/login"),
                            "user 段应含同域 URL（历史 1 + 历史 2）");
                    // 跨域 other.test 不应出现
                    assertTrue(!p2User.contains("other.test"),
                            "user 段不应含跨域 URL（只取同域）");
                    // 模板里 {summaryCount} 应被替换为实际数字（我们塞了 2 条历史）
                    assertTrue(p2User.contains("以下是同域名近期 2 条历史请求摘要"),
                            "user 段应把 {summaryCount} 替换为实际条数 2");
                    // 占位符已替换完成
                    assertTrue(!p2User.contains("{related}"),
                            "占位符 {related} 应已被替换");
                    assertTrue(!p2User.contains("{summaryCount}"),
                            "占位符 {summaryCount} 应已被替换");
                    // —— 新版"详细摘要"契约：每条历史除了元数据行，还应带 TrafficCompactor
                    // 极致压缩后的 method/URL/headers/极简 body（不只是单行摘要）。
                    // 验证：两条历史都出现【请求】首行 + 截断的 Host 头（业务流必备）+ 响应状态行。
                    // 注：搜 "Host: api.m..."（带省略号 + 截断后特征）而非 "Host: api."，
                    // 避免与基础 user 段里当前请求的完整 Host ("Host: api.multi.test") 撞车。
                    int requestLineCount = 0;
                    int truncatedHostCount = 0;
                    int from = 0;
                    while (true) {
                        int idx = p2User.indexOf("【请求】", from);
                        if (idx < 0) break;
                        requestLineCount++;
                        from = idx + 1;
                    }
                    from = 0;
                    while (true) {
                        int idx = p2User.indexOf("Host: api.m...", from);
                        if (idx < 0) break;
                        truncatedHostCount++;
                        from = idx + 1;
                    }
                    // 两条历史状态码不同（200 / 401），分别验证
                    int resp200Count = countOccurrences(p2User, "【响应 200】");
                    int resp401Count = countOccurrences(p2User, "【响应 401】");
                    assertEquals(2, requestLineCount,
                            "2 条历史都应渲染出 TrafficCompactor 输出的【请求】首行");
                    assertEquals(2, truncatedHostCount,
                            "2 条历史的 Host 头（截断到 5 字符）都应出现");
                    assertEquals(1, resp200Count, "历史 1 应渲染【响应 200】状态行");
                    assertEquals(1, resp401Count, "历史 2 应渲染【响应 401】状态行");

                    // —— 真实压缩效果验证：触发 TrafficCompactor 各类策略 ——

                    // (a) header 截断到前 5 字符：User-Agent: Mozil... / Accept: appli... /
                    //     X-Request-Id: 7f8e9...（这些头名在基础 user 段和跨域历史中都不存在）
                    assertTrue(p2User.contains("User-Agent: Mozil..."),
                            "User-Agent 超 5 字符应被截断: actual-head-see=" + headerLineOf(p2User, "User-Agent"));
                    assertTrue(p2User.contains("Accept: appli..."),
                            "Accept 超 5 字符应被截断: actual=" + headerLineOf(p2User, "Accept"));
                    assertTrue(p2User.contains("X-Request-Id: 7f8e9..."),
                            "X-Request-Id 超 5 字符应被截断: actual=" + headerLineOf(p2User, "X-Request-Id"));
                    // WWW-Authenticate 头名含 "auth" → 命中敏感关键字正则
                    // (authorization|auth|cookie|...)，按规则整体脱敏，不走截断分支。
                    assertTrue(p2User.contains("WWW-Authenticate: （已脱敏）"),
                            "WWW-Authenticate 应被整体脱敏（头名含 'auth'）: actual=" + headerLineOf(p2User, "WWW-Authenticate"));
                    assertTrue(p2User.contains("Cache-Control: no-ca..."),
                            "Cache-Control 超 5 字符应被截断: actual=" + headerLineOf(p2User, "Cache-Control"));

                    // (b) 敏感头脱敏：Authorization / X-CSRF-Token / Cookie / Set-Cookie
                    //     原文 token 字符串必须彻底消失
                    assertTrue(p2User.contains("Authorization: （已脱敏）"),
                            "Authorization 应整体脱敏: actual=" + headerLineOf(p2User, "Authorization"));
                    assertFalse(p2User.contains("eyJhbGciOiJIUzI1NiJ9"),
                            "Bearer token 原文不得泄漏");
                    assertTrue(p2User.contains("X-CSRF-Token: （已脱敏）"),
                            "X-CSRF-Token 名字含 token → 整体脱敏: actual=" + headerLineOf(p2User, "X-CSRF-Token"));
                    assertFalse(p2User.contains("abc123def456ghi789jkl"),
                            "CSRF token 原文不得泄漏");
                    assertTrue(p2User.contains("Set-Cookie: （已脱敏）"),
                            "Set-Cookie 名字含 cookie → 整体脱敏");
                    assertTrue(p2User.contains("Cookie: （已脱敏）"),
                            "Cookie 名字含 cookie → 整体脱敏: actual=" + headerLineOf(p2User, "Cookie"));

                    // (c) JSON body 极致压缩：value 截断 + 数组超 8 元素占位
                    //     bio / password / lockedUntil 都是 20+ 字符超长 value
                    assertTrue(p2User.contains("共 11 元素"),
                            "tags 数组 11 元素 > 8 应触发\"共 11 元素\"占位");
                    assertFalse(p2User.contains("tag9\",\"tag10\",\"tag11"),
                            "tags 数组超出 8 元素的部分应被截掉");
                    // password value 是 44 字符，截到 20 字符 "super-secret-passwor..."
                    assertFalse(p2User.contains("super-secret-password-do-not-leak-1234567890"),
                            "超长 password value 不应完整出现");
                    // bio 中文 30+ 字符，截到 20 字符（注意包含"...（已截断）" marker）
                    assertTrue(p2User.contains("...（已截断）"),
                            "JSON 超长 value 应出现截断 marker");

                    // (d) 跨域历史确实被排除：other.test 域名 / "should-not-leak" token 都不应出现
                    assertTrue(!p2User.contains("other.test"),
                            "跨域 other.test 不应出现在 user 段");
                    assertFalse(p2User.contains("should-not-leak"),
                            "跨域历史里写入的 token 也不应泄漏（防 fixture 串台）");
                } finally {
                    // 守护线程执行器，无需 shutdown
                }
            } finally {
                store.close();
            }
        } finally {
            deleteDirectory(skillsDir);
            deleteDirectory(storeDir);
        }
        System.out.println("################ 走查结束：模型选『多报文协同』技能 ################");
    }

    /**
     * 阶段 2 模型返回空内容 → 结果保留为空，流程不抛错。
     *
     * <p>"重放"在 phase 2 是常驻能力，由 {@link com.auditai.burp.tools.ToolLoopOrchestrator} 驱动：
     * 阶段 1 的 analysis 不会自动使用，只有模型在 phase 2 主动重放或直接给结论才会结束循环。
     * 空响应被解析为"没给结论"，结果保留为空。</p>
     */
    @Test
    void walkthroughPhase2EmptyResponseYieldsEmptyResult() throws Exception {
        System.out.println();
        System.out.println("################ 走查开始：阶段 2 空响应 → 结果为空 ################");
        Path skillsDir = Files.createTempDirectory("auditai-skills-p2fail-");
        try {
            writeSkillMd(skillsDir, "sql-injection",
                    "---\nname: 'SQL'\nicon: '💉'\n---\n\n关注 SQL\n");

            InMemorySkillStateStore stateStore = new InMemorySkillStateStore();
            stateStore.setEnabled("sql-injection");
            SkillLoader loader = SkillLoader.fromDirectory(skillsDir);

            // 阶段 1：模型选了技能（analysis 字段不影响 phase 2）
            // 阶段 2（重放 orchestrator 首轮）：返回空内容 → 解析不出 tool_calls、也拿不到 analysis
            //   → orchestrator 立即 wrap-up 返回 Outcome("", "", false) → analyzeWithReplay 走通路径
            FakeAiClient ai = new FakeAiClient(
                    "{\"active_skill_ids\": [\"sql-injection\"], "
                            + "\"analysis\": \"\", "
                            + "\"risk\": \"none\", \"findings\": []}",
                    "");

            TrafficAnalyzer analyzer = new TrafficAnalyzer(fakeMontoyaApi(), ai, Settings.createDefault(),
                    null, stateStore, loader);
            try {
                HttpRequest request = fakeRequest("GET", "/x", "api.p2fail.test", "");
                HttpResponse response = fakeResponse((short) 200, "text/plain", "ok");

                AnalysisResult result = runAndAwait(analyzer, request, response);

                // 1 次 phase 1 + 1 次 phase 2（orchestrator 首轮）= 2 次模型调用
                assertEquals(2, ai.callCount());
                assertNull(result.getError(), "不应有错误（只是空结论）");
                // 阶段 2 空响应 → orchestrator 返回"无结论"，调用方决定后续处理
                assertTrue(result.getSummary() == null || result.getSummary().isEmpty(),
                        "空响应 → 结果 summary 应为空，实际：'" + result.getSummary() + "'");
            } finally {
                // 守护线程执行器，无需 shutdown
            }
        } finally {
            deleteDirectory(skillsDir);
        }
        System.out.println("################ 走查结束：阶段 2 空响应 → 结果为空 ################");
    }

    /**
     * <b>回归：仅自动激活 → 短路 A 跳过 phase 1。</b>
     *
     * <p>用户<b>只</b>勾选了"自动激活"技能，没有普通启用任何技能。
     * phase1Candidates 为空、pinned 非空 → <b>短路 A</b> 直接进入 phase 2 把 pinned 注入，
     * 跳过 phase 1 节省一次调用。</p>
     *
     * <p>关键不变量：</p>
     * <ul>
     *   <li>callCount = 1（短路 A 跳过了 phase 1）；</li>
     *   <li>phase 2 system 必须包含 pinned 技能的 prompt；</li>
     *   <li>phase 2 system 也不应出现『可选技能』目录（phase 1 跳过，phase 2 拼的是 replay system）。</li>
     * </ul>
     */
    @Test
    void walkthroughPinnedOnlySkipsPhase1() throws Exception {
        System.out.println();
        System.out.println("################ 走查开始：仅自动激活 → 短路 A 跳过 phase 1 ################");
        Path skillsDir = Files.createTempDirectory("auditai-skills-pinonly-");
        try {
            writeSkillMd(skillsDir, "sql-injection",
                    "---\nname: 'SQL 注入'\nicon: '💉'\n---\n\nPinned SQL 注入 prompt 内容\n");
            writeSkillMd(skillsDir, "xss-detector",
                    "---\nname: 'XSS'\nicon: '🧨'\n---\n\nPinned XSS prompt 内容\n");

            InMemorySkillStateStore stateStore = new InMemorySkillStateStore();
            stateStore.setPinned("sql-injection");
            stateStore.setPinned("xss-detector");
            SkillLoader loader = SkillLoader.fromDirectory(skillsDir);

            String phase2WrapUp = "{\"analysis\": \"仅凭自动激活技能已收尾。\", \"tool_calls\": []}";
            FakeAiClient ai = new FakeAiClient(phase2WrapUp);

            TrafficAnalyzer analyzer = new TrafficAnalyzer(fakeMontoyaApi(), ai, Settings.createDefault(),
                    null, stateStore, loader);
            try {
                HttpRequest request = fakeRequest("GET", "/x", "api.pinonly.test", "");
                HttpResponse response = fakeResponse((short) 200, "text/plain", "ok");

                runAndAwait(analyzer, request, response);

                assertEquals(1, ai.callCount(),
                        "phase1Candidates 空 + pinned 非空 → 短路 A 跳过 phase 1，仅 phase 2 调一次");
                List<AiClient.ChatMessage> phase2Messages = ai.callMessages().get(0);
                String phase2System = phase2Messages.get(0).content();
                assertTrue(phase2System.contains("Pinned SQL 注入 prompt 内容"),
                        "phase 2 system 应包含 sql-injection 的 prompt，实际：" + phase2System);
                assertTrue(phase2System.contains("Pinned XSS prompt 内容"),
                        "phase 2 system 应包含 xss-detector 的 prompt，实际：" + phase2System);
                assertFalse(phase2System.contains("【可选技能】"),
                        "phase 2 是 replay system，不应出现『可选技能』目录，实际：" + phase2System);
            } finally {
                // 守护线程执行器，无需 shutdown
            }
        } finally {
            deleteDirectory(skillsDir);
        }
        System.out.println("################ 走查结束：仅自动激活 → 短路 A 跳过 phase 1 ################");
    }

    /**
     * <b>回归：短路 B 路径下 pinned 必选仍然生效 + phase 2 user 不含草稿。</b>
     *
     * <p>用户既普通启用了一些技能，又把另一些设为"自动激活（必选）"。模型在 phase 1
     * 选了 0 个 skill + 给 analysis——即便模型没遵守"必选"规则把 pinned id 写到
     * {@code active_skill_ids}，pinned 仍然要被强制注入到 phase 2 system 段。</p>
     *
     * <p>期望行为：</p>
     * <ul>
     *   <li>phase 1 system【可选技能】目录<b>同时列出</b>普通启用（sql-injection）和 pinned
     *       （xss-detector），pinned 标"必选"；</li>
     *   <li>phase 1 system 包含说明：必选技能"phase 2 一定会注入，无需写到 active_skill_ids"；</li>
     *   <li>phase 1 system <b>不</b>直接拼 pinned 的 prompt 内容；</li>
     *   <li>phase 2 system 含 pinned 的 prompt；</li>
     *   <li>phase 2 user 段<b>不</b>拼 phase 1 的 analysis（无草稿逻辑）——避免误导模型。</li>
     * </ul>
     */
    @Test
    void walkthroughMixedPinnedPhase2ForcedNoDraft() throws Exception {
        System.out.println();
        System.out.println("################ 走查开始：短路 B 路径下 pinned 必选 + 无草稿 ################");
        Path skillsDir = Files.createTempDirectory("auditai-skills-mixed-");
        try {
            writeSkillMd(skillsDir, "sql-injection",
                    "---\nname: 'SQL 注入'\nicon: '💉'\n---\n\n普通 SQL prompt 内容\n");
            writeSkillMd(skillsDir, "xss-detector",
                    "---\nname: 'XSS'\nicon: '🧨'\n---\n\nPinned XSS prompt 内容\n");

            InMemorySkillStateStore stateStore = new InMemorySkillStateStore();
            stateStore.setEnabled("sql-injection"); // 普通启用
            stateStore.setPinned("xss-detector");  // 自动激活（必选）
            SkillLoader loader = SkillLoader.fromDirectory(skillsDir);

            // phase 1：模型没遵守"必选"——active_skill_ids=[]，给一段最终 analysis（应被丢弃）
            // phase 2：用空 tool_calls 收尾
            String phase1Response = "{\"active_skill_ids\": [], "
                    + "\"analysis\": \"phase1 模型没遵守必选，给一段最终 analysis。\", "
                    + "\"risk\": \"low\", \"findings\": []}";
            String phase2Response = "{\"analysis\": \"OK\", \"tool_calls\": []}";
            FakeAiClient ai = new FakeAiClient(phase1Response, phase2Response);

            TrafficAnalyzer analyzer = new TrafficAnalyzer(fakeMontoyaApi(), ai, Settings.createDefault(),
                    null, stateStore, loader);
            try {
                HttpRequest request = fakeRequest("GET", "/x", "api.mixedpin.test", "");
                HttpResponse response = fakeResponse((short) 200, "text/plain", "ok");

                runAndAwait(analyzer, request, response);

                assertEquals(2, ai.callCount(),
                        "短路 B 路径：phase 1 + phase 2 各调一次，实际 " + ai.callCount() + " 次");

                // phase 1 system：分两段——【可选技能】列普通启用，【必选技能】列 pinned。
                List<AiClient.ChatMessage> phase1Messages = ai.callMessages().get(0);
                String phase1System = phase1Messages.get(0).content();
                assertTrue(phase1System.contains("【可选技能】"),
                        "phase 1 system 应包含『可选技能』目录，实际：" + phase1System);
                assertTrue(phase1System.contains("id: sql-injection"),
                        "phase 1 可选目录应列出普通 sql-injection，实际：" + phase1System);
                // 必须独立成段——【必选技能】标题
                assertTrue(phase1System.contains("【必选技能】"),
                        "phase 1 system 应有独立的【必选技能】标题（与可选技能分离），实际：" + phase1System);
                assertTrue(phase1System.contains("id: xss-detector"),
                        "phase 1 必选目录应列出 pinned 的 xss-detector，实际：" + phase1System);
                // 必选标题里应说明"phase 2 一定注入 / 不需要写"——而不是"必须写"，
                // 与选择指令的"可选可以空数组"自洽。
                assertTrue(phase1System.contains("phase 2")
                                || phase1System.contains("无需写到")
                                || phase1System.contains("regardless"),
                        "phase 1 必选标题应说明『phase 2 一定注入 / 无需写到』，实际：" + phase1System);
                // 旧的"必须写到"措辞不应再出现
                assertFalse(phase1System.contains("必须写到 active_skill_ids"),
                        "必选不应再要求模型必须写到 active_skill_ids（与可选空数组指令冲突），实际：" + phase1System);
                // 旧的行尾标签方式不应再出现
                assertFalse(phase1System.contains("（必选）"),
                        "行尾括号『必选』标签已废弃，目录靠独立标题区分，实际：" + phase1System);
                // pinned 的 prompt 内容不应拼到 phase 1
                assertFalse(phase1System.contains("Pinned XSS prompt 内容"),
                        "phase 1 system 不应包含 pinned 的 prompt 内容（phase 2 才有），实际：" + phase1System);

                // phase 2 system 含 pinned prompt（即便模型没遵守必选）
                List<AiClient.ChatMessage> phase2Messages = ai.callMessages().get(1);
                String phase2System = phase2Messages.get(0).content();
                assertTrue(phase2System.contains("Pinned XSS prompt 内容"),
                        "phase 2 system 应包含 pinned 的 xss-detector prompt（短路 B 强制注入），实际：" + phase2System);
                assertFalse(phase2System.contains("普通 SQL prompt 内容"),
                        "phase 2 system 不应包含未被选中的普通 sql-injection，实际：" + phase2System);

                // phase 2 user 段不应拼 phase 1 的 analysis 草稿
                String phase2User = phase2Messages.get(1).content();
                assertFalse(phase2User.contains("Phase 1 草稿"),
                        "phase 2 user 段不应再含『Phase 1 草稿』标注，实际：" + phase2User);
                assertFalse(phase2User.contains("phase1 模型没遵守必选"),
                        "phase 2 user 段不应再含 phase 1 analysis 文字，实际：" + phase2User);
            } finally {
                // 守护线程执行器，无需 shutdown
            }
        } finally {
            deleteDirectory(skillsDir);
        }
        System.out.println("################ 走查结束：短路 B 路径下 pinned 必选 + 无草稿 ################");
    }

    // ===== 测试工具 =====

    private static AnalysisResult runAndAwait(TrafficAnalyzer analyzer, HttpRequest request,
                                              HttpResponse response) throws Exception {
        CompletableFuture<AnalysisResult> future = new CompletableFuture<>();
        analyzer.analyzeAsync(request, response, future::complete);
        AnalysisResult result = future.get(30, TimeUnit.SECONDS);
        assertNotNull(result);
        return result;
    }

    private static MontoyaApi fakeMontoyaApi() {
        Logging logging = (Logging) Proxy.newProxyInstance(
                TrafficFlowWalkthroughTest.class.getClassLoader(),
                new Class<?>[]{Logging.class},
                (InvocationHandler) (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "logToOutput":
                        case "logToError":
                            System.out.println("[Montoya." + method.getName() + "] "
                                    + (args.length > 0 ? args[0] : ""));
                            return null;
                        default:
                            return null;
                    }
                });
        return (MontoyaApi) Proxy.newProxyInstance(
                TrafficFlowWalkthroughTest.class.getClassLoader(),
                new Class<?>[]{MontoyaApi.class},
                (InvocationHandler) (proxy, method, args) -> {
                    if ("logging".equals(method.getName())) {
                        return logging;
                    }
                    return defaultValue(method.getReturnType());
                });
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) {
            return null;
        }
        if (type == boolean.class) return false;
        if (type == int.class) return 0;
        if (type == short.class) return (short) 0;
        if (type == long.class) return 0L;
        if (type == double.class) return 0d;
        if (type == float.class) return 0f;
        return null;
    }

    private static HttpRequest fakeRequest(String method, String url, String host, String rawBody) {
        List<HttpHeader> headers = List.of(
                fakeHeader("Host", host),
                fakeHeader("Content-Type", "text/plain"));
        return (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(),
                new Class<?>[]{HttpRequest.class},
                (InvocationHandler) (proxy, m, a) -> {
                    switch (m.getName()) {
                        case "method":
                            return method;
                        case "url":
                            return url;
                        case "header": {
                            String wanted = (String) a[0];
                            for (HttpHeader h : headers) {
                                if (h.name().equalsIgnoreCase(wanted)) {
                                    return h;
                                }
                            }
                            return null;
                        }
                        case "headers":
                            return headers;
                        case "body":
                            return fakeBytes(rawBody.getBytes(StandardCharsets.UTF_8));
                        default:
                            return defaultValue(m.getReturnType());
                    }
                });
    }

    private static HttpResponse fakeResponse(short statusCode, String contentType, String rawBody) {
        List<HttpHeader> headers = List.of(fakeHeader("Content-Type", contentType));
        return (HttpResponse) Proxy.newProxyInstance(
                HttpResponse.class.getClassLoader(),
                new Class<?>[]{HttpResponse.class},
                (InvocationHandler) (proxy, m, a) -> {
                    switch (m.getName()) {
                        case "statusCode":
                            return statusCode;
                        case "headers":
                            return headers;
                        case "body":
                            return fakeBytes(rawBody.getBytes(StandardCharsets.UTF_8));
                        default:
                            return defaultValue(m.getReturnType());
                    }
                });
    }

    private static HttpHeader fakeHeader(String name, String value) {
        return (HttpHeader) Proxy.newProxyInstance(
                HttpHeader.class.getClassLoader(),
                new Class<?>[]{HttpHeader.class},
                (InvocationHandler) (proxy, m, a) -> {
                    switch (m.getName()) {
                        case "name": return name;
                        case "value": return value;
                        default: return defaultValue(m.getReturnType());
                    }
                });
    }

    private static ByteArray fakeBytes(byte[] data) {
        return (ByteArray) Proxy.newProxyInstance(
                ByteArray.class.getClassLoader(),
                new Class<?>[]{ByteArray.class},
                (InvocationHandler) (proxy, m, a) -> {
                    if ("getBytes".equals(m.getName())) return data;
                    if ("length".equals(m.getName())) return data.length;
                    return defaultValue(m.getReturnType());
                });
    }

    /**
     * 在测试临时目录下创建 {@code <id>/SKILL.md}（新格式），并写入 YAML frontmatter +
     * Markdown body 的纯文本。旧版的 {@code Files.writeString(skillsDir.resolve("<id>.skill"), ...)}
     * 不再被新的 {@link SkillLoader} 识别。
     */
    private static void writeSkillMd(Path skillsDir, String id, String content) throws IOException {
        Path skillDir = skillsDir.resolve(id);
        Files.createDirectories(skillDir);
        Files.writeString(skillDir.resolve("SKILL.md"), content, StandardCharsets.UTF_8);
    }

    private static void deleteDirectory(Path directory) throws IOException {
        if (Files.exists(directory)) {
            try (var paths = Files.walk(directory)) {
                for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) {
                    Files.deleteIfExists(path);
                }
            }
        }
    }

    /** 统计 needle 在 haystack 中出现的次数（不重叠）。 */
    private static int countOccurrences(String haystack, String needle) {
        int count = 0;
        int from = 0;
        while (true) {
            int idx = haystack.indexOf(needle, from);
            if (idx < 0) break;
            count++;
            from = idx + needle.length();
        }
        return count;
    }

    /**
     * 从 p2User 中提取指定 header 行的渲染结果，便于断言失败时一眼看清实际输出。
     * 没找到时返回 "(none)"。
     */
    private static String headerLineOf(String p2User, String headerName) {
        int from = 0;
        while (true) {
            int idx = p2User.indexOf(headerName + ":", from);
            if (idx < 0) return "(none)";
            // 取这一行的内容（到换行符为止）
            int lineEnd = p2User.indexOf('\n', idx);
            return lineEnd < 0 ? p2User.substring(idx) : p2User.substring(idx, lineEnd);
        }
    }

    /**
     * 内存版 {@link SkillStateStore}，避免每个测试都构造 Montoya Preferences 桩。
     */
    private static final class InMemorySkillStateStore extends SkillStateStore {
        private final Set<String> enabled = new java.util.LinkedHashSet<>();
        private final Set<String> pinned = new java.util.LinkedHashSet<>();
        private boolean initialized = false;

        InMemorySkillStateStore() {
            super(stubPreferences());
        }

        void setEnabled(String id) {
            enabled.add(id);
            initialized = true;
        }

        void setPinned(String id) {
            // 测试层等价物把 pinned ⊆ enabled 这条业务约束也一起维护，避免
            // 测试构造的状态在 TrafficAnalyzer 里走"自动激活但未启用"的边角。
            pinned.add(id);
            enabled.add(id);
            initialized = true;
        }

        @Override
        public Set<String> loadEnabledIds() {
            if (!initialized) {
                return new java.util.LinkedHashSet<>();
            }
            return new java.util.LinkedHashSet<>(enabled);
        }

        @Override
        public void saveEnabledIds(Set<String> enabledIds) {
            enabled.clear();
            enabled.addAll(enabledIds);
            initialized = true;
        }

        @Override
        public Set<String> loadPinnedIds() {
            return new java.util.LinkedHashSet<>(pinned);
        }

        @Override
        public void savePinnedIds(Set<String> pinnedIds) {
            pinned.clear();
            pinned.addAll(pinnedIds);
        }
    }

    private static burp.api.montoya.persistence.Preferences stubPreferences() {
        return (burp.api.montoya.persistence.Preferences) Proxy.newProxyInstance(
                TrafficFlowWalkthroughTest.class.getClassLoader(),
                new Class<?>[]{burp.api.montoya.persistence.Preferences.class},
                (proxy, method, args) -> null);
    }

    /**
     * 把"已经分析过的历史"塞进 AnalysisHistoryStore：构造一个成功的 AnalysisResult
     * 调 historyStore.add；statusCode=-1 时表示无响应（respBytes 忽略）。
     *
     * <p>原 ProxyTrafficStore.captureRequest/Response 是"未分析"的代理流量，
     * 现在 AnalysisHistoryStore 只接受"已分析"快照——所以这里直接走 add 路径，
     * 模拟"历史上分析过这条报文"的状态。</p>
     */
    private static void seedHistory(AnalysisHistoryStore store, String method, String url,
                                    int statusCode, byte[] reqBytes, byte[] respBytes,
                                    long timestamp) {
        AnalysisResult result = AnalysisResult.success(
                timestamp, method, url, statusCode, "seeded", 0L, java.util.Collections.emptyList());
        try {
            store.add(result, AnalysisTrigger.MANUAL, reqBytes, respBytes, null);
        } catch (java.io.IOException ioe) {
            throw new RuntimeException("seedHistory failed", ioe);
        }
    }
}
