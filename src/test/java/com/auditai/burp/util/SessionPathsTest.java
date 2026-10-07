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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** SessionPaths 的路径解析单元测试（专业版分支用代理伪造 MontoyaApi 覆盖）。 */
class SessionPathsTest {

    // ---------- 项目标识解析（专业版 / 社区版分流） ----------

    @Test
    void resolveProjectIdProfessionalDiskProject() {
        MontoyaApi api = fakeApi(BurpSuiteEdition.PROFESSIONAL, List.of("--project-file=x.burp"), "proj-123");
        assertEquals("proj-123", SessionPaths.resolveProjectId(api));
    }

    @Test
    void resolveProjectIdProfessionalWithoutProjectFileUsesId() {
        // 专业版即使不挂 --project-file，Burp 也会分配稳定 ID——直接落到 projects/<id>/，
        // 避免不同会话挤到同一个 temporary/。
        MontoyaApi api = fakeApi(BurpSuiteEdition.PROFESSIONAL, List.of(), "proj-123");
        assertEquals("proj-123", SessionPaths.resolveProjectId(api));
    }

    @Test
    void resolveProjectIdProfessionalBlankIdFallsBackToTemporary() {
        // 专业版但项目 id 为空（极少数场景）→ temporary
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

    // ---------- 目录解析（createProjectDirectory） ----------

    @Test
    void createProjectDirectoryTemporary(@TempDir Path tempDir) throws Exception {
        SessionPaths.DataRootResolution resolution = SessionPaths.createProjectDirectoryAtRoot(
                tempDir.resolve("AuditAI Data"), SessionPaths.TEMPORARY_PROJECT_ID, null);
        Path dir = resolution.path();
        assertEquals("temporary", dir.getFileName().toString());
        assertEquals("AuditAI Data", dir.getParent().getFileName().toString());
        assertTrue(Files.isDirectory(dir));
        // 测试 / 调用方显式传入根目录 → 来源 = DIRECT。
        assertEquals(SessionPaths.DataRootSource.DIRECT, resolution.source());
    }

    @Test
    void createProjectDirectoryProjectsSanitizesId(@TempDir Path tempDir) throws Exception {
        SessionPaths.DataRootResolution resolution = SessionPaths.createProjectDirectoryAtRoot(
                tempDir.resolve("AuditAI Data"), "a/b:c", null);
        Path dir = resolution.path();
        assertEquals("a_b_c", dir.getFileName().toString());
        assertEquals("projects", dir.getParent().getFileName().toString());
        assertTrue(Files.isDirectory(dir));
        assertEquals(SessionPaths.DataRootSource.DIRECT, resolution.source());
    }

    @Test
    void createProjectDirectoryNullIdFallsBackToTemporary(@TempDir Path tempDir) throws Exception {
        SessionPaths.DataRootResolution resolution = SessionPaths.createProjectDirectoryAtRoot(
                tempDir.resolve("AuditAI Data"), null, null);
        assertEquals("temporary", resolution.path().getFileName().toString());
        assertEquals(SessionPaths.DataRootSource.DIRECT, resolution.source());
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

    // ---------- 数据根解析（resolveEnvOverride / resolveBurpSiblingRoot） ----------

    @Test
    void resolveEnvOverrideUnsetReturnsNull() {
        assertEquals(null, SessionPaths.resolveEnvOverride(null));
        assertEquals(null, SessionPaths.resolveEnvOverride(""));
        assertEquals(null, SessionPaths.resolveEnvOverride("   "));
    }

    @Test
    void resolveEnvOverrideAppendsDataDirNameWhenLastSegmentDiffers() {
        // 用户指向父目录（最常用）
        Path root = SessionPaths.resolveEnvOverride("parent-dir");
        assertEquals("AuditAI Data", root.getFileName().toString());
        assertEquals("parent-dir", root.getParent().getFileName().toString());
    }

    @Test
    void resolveEnvOverrideUsesAsIsWhenLastSegmentMatches() {
        // 用户已经指到数据根目录本身（精细控制），不再追加一层
        Path root = SessionPaths.resolveEnvOverride("AuditAI Data");
        assertEquals("AuditAI Data", root.getFileName().toString());
        assertNull(root.getParent());
    }

    @Test
    void resolveEnvOverrideTrimsWhitespace() {
        Path root = SessionPaths.resolveEnvOverride("  parent-dir  ");
        assertEquals("AuditAI Data", root.getFileName().toString());
        assertEquals("parent-dir", root.getParent().getFileName().toString());
    }

    @Test
    void resolveEnvOverrideMatchesCaseInsensitively() {
        // Windows 文件系统大小写不敏感：末段大小写不同也应命中，避免多套一层。
        Path root = SessionPaths.resolveEnvOverride("parent-dir/AUDITAI DATA");
        assertEquals("AUDITAI DATA", root.getFileName().toString());
        assertEquals("parent-dir", root.getParent().getFileName().toString());
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
