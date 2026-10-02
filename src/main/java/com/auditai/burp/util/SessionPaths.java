package com.auditai.burp.util;

import burp.api.montoya.MontoyaApi;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * 定位当前 Burp 项目的会话目录：专业版 {@code Burp安装目录\AuditAIData\projects\<id>\}，
 * 社区版 {@code Burp安装目录\AuditAIData\temporary\}。回退顺序：Burp 安装目录 →
 * 插件 JAR 所在目录 → 用户数据目录（%APPDATA% / ~/.local/share）。
 */
public final class SessionPaths {

    /** 顶级数据目录名（与早期 store 命名保持一致）。 */
    public static final String DATA_DIRECTORY_NAME = "AuditAIData";

    /** 临时项目目录名（社区版 Burp）。 */
    public static final String TEMPORARY_PROJECT_ID = "temporary";

    /** 项目 ID 子目录名（专业版 Burp）。 */
    public static final String PROJECTS_DIRECTORY_NAME = "projects";

    private SessionPaths() {
    }

    /**
     * @param api Montoya API 门面。
     * @return 当前 Burp 是否以磁盘项目（--project-file）启动。
     */
    public static boolean isDiskProject(MontoyaApi api) {
        return api.burpSuite().commandLineArguments().stream()
                .anyMatch(argument -> argument.equals("--project-file")
                        || argument.startsWith("--project-file="));
    }

    /**
     * 取当前项目的会话根目录：{@code projects/<id>/}（专业版）或 {@code temporary/}（社区版）。
     * 任意一个候选根目录可写即返回；全部失败抛 IOException。
     */
    public static Path createProjectDirectory(String extensionFilename, String projectId) throws IOException {
        List<Path> roots = new ArrayList<>();
        Path burpHome = burpInstallationDirectory();
        if (burpHome != null) {
            roots.add(burpHome.resolve(DATA_DIRECTORY_NAME));
        }
        Path extensionRoot = extensionDataRoot(extensionFilename);
        if (!roots.contains(extensionRoot)) {
            roots.add(extensionRoot);
        }
        roots.add(fallbackDataRoot());
        IOException failure = null;
        String safeProjectId = safePathPart(projectId == null || projectId.isBlank()
                ? UUID.randomUUID().toString() : projectId);
        for (Path root : roots) {
            try {
                Path directory = TEMPORARY_PROJECT_ID.equals(safeProjectId)
                        ? root.resolve(TEMPORARY_PROJECT_ID)
                        : root.resolve(PROJECTS_DIRECTORY_NAME).resolve(safeProjectId);
                Files.createDirectories(directory);
                return directory;
            } catch (IOException e) {
                failure = e;
            }
        }
        throw failure != null ? failure : new IOException("无法创建数据目录：所有候选根均不可写");
    }

    /**
     * 推断当前 JVM 进程对应的 Burp 安装根目录。
     *
     * <p>Montoya 没有直接暴露 Burp 安装目录。本方法用 {@link ProcessHandle} 拿当前
     * 进程命令行起点（{@code java} / {@code BurpSuite.exe}），向上回溯找
     * {@code BurpSuite.exe} 或 {@code burpsuite.jar} 推断——这条逻辑与
     * {@code FindingStore} 保持一致，避免同一 Burp 实例下"两个 store 写到不同
     * 目录"的诡异分叉。</p>
     *
     * @return Burp 安装目录的绝对路径；推断不到（极端环境：进程命令行异常、文件布局
     *         非标准）时返回 null。
     */
    private static Path burpInstallationDirectory() {
        java.util.Optional<String> command = ProcessHandle.current().info().command();
        if (command.isEmpty()) {
            return null;
        }
        Path current = Paths.get(command.get()).toAbsolutePath().normalize().getParent();
        while (current != null) {
            if (Files.isRegularFile(current.resolve("BurpSuite.exe"))
                    || Files.isRegularFile(current.resolve("burpsuite.jar"))) {
                return current;
            }
            current = current.getParent();
        }
        return null;
    }

    private static Path extensionDataRoot(String extensionFilename) {
        if (extensionFilename == null || extensionFilename.isBlank()) {
            return Paths.get(System.getProperty("user.home"), ".auditai");
        }
        Path jarPath = Paths.get(extensionFilename);
        Path parent = jarPath.toAbsolutePath().getParent();
        return parent != null ? parent.resolve(DATA_DIRECTORY_NAME) : Paths.get(System.getProperty("user.home"), ".auditai");
    }

    private static Path fallbackDataRoot() {
        // 与 FindingStore 行为对齐：Windows 优先 LOCALAPPDATA，缺失时回退到
        // ~/.local/share（XDG_DATA_HOME 习惯）；避免与 SessionPaths 旧实现的
        // APPDATA（Roaming）行为分叉——fallback 路径应只用于"前面两个候选都不可写"
        // 的极端场景，行为差异不影响主流程，但保持两 store 路径一致便于排错。
        String localAppData = System.getenv("LOCALAPPDATA");
        Path baseDirectory = localAppData == null || localAppData.isBlank()
                ? Paths.get(System.getProperty("user.home"), ".local", "share")
                : Paths.get(localAppData);
        return baseDirectory.resolve("AuditAI");
    }

    /** 去掉路径分隔符 / 非法字符，限制单段长度。 */
    private static String safePathPart(String input) {
        String trimmed = input.trim();
        if (trimmed.isEmpty()) {
            return UUID.randomUUID().toString();
        }
        String cleaned = trimmed.replaceAll("[\\\\/:*?\"<>|]", "_");
        if (cleaned.length() > 80) {
            cleaned = cleaned.substring(0, 80);
        }
        return cleaned;
    }
}
