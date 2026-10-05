package com.auditai.burp.util;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.Version;
import burp.api.montoya.project.Project;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@link SessionPaths} 的路径解析单元测试（专业版分支用代理伪造 {@link MontoyaApi} 覆盖）。 */
class SessionPathsTest {

    // ---------- 项目标识解析（专业版 / 社区版分流） ----------

    @Test
    void resolveProjectIdProfessionalDiskProject() {
        MontoyaApi api = fakeApi(BurpSuiteEdition.PROFESSIONAL, List.of("--project-file=x.burp"), "proj-123");
        assertEquals("proj-123", SessionPaths.resolveProjectId(api));
    }

    @Test
    void resolveProjectIdProfessionalTemporaryProjectFallsBackToTemporary() {
        // 专业版未带 --project-file（临时项目）→ temporary
        MontoyaApi api = fakeApi(BurpSuiteEdition.PROFESSIONAL, List.of(), "proj-123");
        assertEquals(SessionPaths.TEMPORARY_PROJECT_ID, SessionPaths.resolveProjectId(api));
    }

    @Test
    void resolveProjectIdProfessionalBlankIdFallsBackToTemporary() {
        // 磁盘项目但 id 为空 → temporary
        MontoyaApi api = fakeApi(BurpSuiteEdition.PROFESSIONAL, List.of("--project-file=x.burp"), "");
        assertEquals(SessionPaths.TEMPORARY_PROJECT_ID, SessionPaths.resolveProjectId(api));
    }

    @Test
    void resolveProjectIdCommunityAlwaysTemporary() {
        // 社区版即使带 --project-file 也走 temporary
        MontoyaApi api = fakeApi(BurpSuiteEdition.COMMUNITY_EDITION, List.of("--project-file=x.burp"), "proj-123");
        assertEquals(SessionPaths.TEMPORARY_PROJECT_ID, SessionPaths.resolveProjectId(api));
    }

    @Test
    void resolveProjectIdEnterpriseFallsBackToTemporary() {
        MontoyaApi api = fakeApi(BurpSuiteEdition.ENTERPRISE_EDITION, List.of("--project-file=x.burp"), "proj-123");
        assertEquals(SessionPaths.TEMPORARY_PROJECT_ID, SessionPaths.resolveProjectId(api));
    }

    @Test
    void isProfessionalEditionDetectsEdition() {
        assertTrue(SessionPaths.isProfessionalEdition(fakeApi(BurpSuiteEdition.PROFESSIONAL, List.of(), null)));
        assertFalse(SessionPaths.isProfessionalEdition(fakeApi(BurpSuiteEdition.COMMUNITY_EDITION, List.of(), null)));
        assertFalse(SessionPaths.isProfessionalEdition(fakeApi(BurpSuiteEdition.ENTERPRISE_EDITION, List.of(), null)));
    }

    @Test
    void isDiskProjectMatchesFlagForms() {
        assertTrue(SessionPaths.isDiskProject(fakeApi(BurpSuiteEdition.PROFESSIONAL, List.of("--project-file"), null)));
        assertTrue(SessionPaths.isDiskProject(fakeApi(BurpSuiteEdition.PROFESSIONAL, List.of("--project-file=a.burp"), null)));
        assertFalse(SessionPaths.isDiskProject(fakeApi(BurpSuiteEdition.PROFESSIONAL, List.of("--config-file=a.json"), null)));
    }

    // ---------- 目录解析（createProjectDirectory） ----------

    @Test
    void createProjectDirectoryTemporary(@TempDir Path tempDir) throws Exception {
        Path jar = tempDir.resolve("plugin.jar");
        Path dir = SessionPaths.createProjectDirectory(jar.toString(), SessionPaths.TEMPORARY_PROJECT_ID);
        assertEquals("temporary", dir.getFileName().toString());
        assertEquals("AuditAIData", dir.getParent().getFileName().toString());
        assertTrue(Files.isDirectory(dir));
    }

    @Test
    void createProjectDirectoryProjectsSanitizesId(@TempDir Path tempDir) throws Exception {
        Path jar = tempDir.resolve("plugin.jar");
        Path dir = SessionPaths.createProjectDirectory(jar.toString(), "a/b:c");
        assertEquals("a_b_c", dir.getFileName().toString());
        assertEquals("projects", dir.getParent().getFileName().toString());
        assertTrue(Files.isDirectory(dir));
    }

    @Test
    void createProjectDirectoryNullIdFallsBackToTemporary(@TempDir Path tempDir) throws Exception {
        Path jar = tempDir.resolve("plugin.jar");
        Path dir = SessionPaths.createProjectDirectory(jar.toString(), null);
        assertEquals("temporary", dir.getFileName().toString());
    }

    // ---------- 路径段清洗（safePathPart） ----------

    @Test
    void safePathPartKeepsPlainId() {
        assertEquals("abc-123", SessionPaths.safePathPart("abc-123"));
    }

    @Test
    void safePathPartSanitizesIllegalChars() {
        assertEquals("a_b_c_d", SessionPaths.safePathPart("a/b\\c:d"));
    }

    @Test
    void safePathPartPrefixesWindowsReservedName() {
        assertEquals("_CON", SessionPaths.safePathPart("CON"));
        assertEquals("_con.txt", SessionPaths.safePathPart("con.txt"));
        assertEquals("_LPT1", SessionPaths.safePathPart("LPT1"));
    }

    @Test
    void safePathPartStripsTrailingDotAndSpace() {
        assertEquals("foo", SessionPaths.safePathPart("foo. "));
        assertEquals("foo", SessionPaths.safePathPart("foo..."));
    }

    @Test
    void safePathPartBlankOrNullFallsBackToTemporary() {
        assertEquals("temporary", SessionPaths.safePathPart(""));
        assertEquals("temporary", SessionPaths.safePathPart("   "));
        assertEquals("temporary", SessionPaths.safePathPart(null));
    }

    @Test
    void safePathPartTruncatesTo80Chars() {
        assertEquals(80, SessionPaths.safePathPart("x".repeat(100)).length());
    }

    @Test
    void safePathPartDoesNotSplitSurrogatePair() {
        // 79 个 'x' + 1 个 emoji（代理对）。截断边界恰落在高代理项时须回退一位，避免切半。
        String result = SessionPaths.safePathPart("x".repeat(79) + "\uD83D\uDE00");
        assertEquals("x".repeat(79), result);
    }

    // ---------- Burp 产物名识别（isBurpArtifact） ----------

    @Test
    void isBurpArtifactRecognizesModernLaunchersAndJars() {
        assertTrue(SessionPaths.isBurpArtifact("BurpSuitePro.exe"));
        assertTrue(SessionPaths.isBurpArtifact("BurpSuiteCommunity.exe"));
        assertTrue(SessionPaths.isBurpArtifact("BurpSuite.exe"));
        assertTrue(SessionPaths.isBurpArtifact("burpsuite_pro.jar"));
        assertTrue(SessionPaths.isBurpArtifact("burpsuite_community.jar"));
        assertTrue(SessionPaths.isBurpArtifact("burpsuite.jar"));
        // 大小写不敏感
        assertTrue(SessionPaths.isBurpArtifact("burpsuitepro.EXE"));
        // 兼容带版本后缀的旧版 JAR
        assertTrue(SessionPaths.isBurpArtifact("burpsuite_pro_v1.7.37.jar"));
        assertTrue(SessionPaths.isBurpArtifact("burpsuite_community_v2022.9.1.jar"));
    }

    @Test
    void isBurpArtifactRejectsUnrelatedFiles() {
        assertFalse(SessionPaths.isBurpArtifact("java.exe"));
        assertFalse(SessionPaths.isBurpArtifact("javaw.exe"));
        assertFalse(SessionPaths.isBurpArtifact("burp.jar"));
        assertFalse(SessionPaths.isBurpArtifact(""));
        assertFalse(SessionPaths.isBurpArtifact(null));
    }

    // ---------- 代理伪造 MontoyaApi ----------

    private static MontoyaApi fakeApi(BurpSuiteEdition edition, List<String> args, String projectId) {
        Version version = proxy(Version.class,
                (p, m, a) -> "edition".equals(m.getName()) ? edition : defaultValue(m.getReturnType()));
        BurpSuite burpSuite = proxy(BurpSuite.class, (p, m, a) -> {
            if ("version".equals(m.getName())) {
                return version;
            }
            if ("commandLineArguments".equals(m.getName())) {
                return args;
            }
            return defaultValue(m.getReturnType());
        });
        Project project = proxy(Project.class,
                (p, m, a) -> "id".equals(m.getName()) ? projectId : defaultValue(m.getReturnType()));
        return proxy(MontoyaApi.class, (p, m, a) -> {
            if ("burpSuite".equals(m.getName())) {
                return burpSuite;
            }
            if ("project".equals(m.getName())) {
                return project;
            }
            return defaultValue(m.getReturnType());
        });
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> iface, InvocationHandler handler) {
        return (T) Proxy.newProxyInstance(iface.getClassLoader(), new Class<?>[]{iface}, handler);
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
        if (type == byte.class) return (byte) 0;
        if (type == char.class) return (char) 0;
        return null;
    }
}
