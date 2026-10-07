package com.auditai.burp.util;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * 定位当前 Burp 项目的会话目录：专业版 {@code <数据根>/projects/<id>/}，
 * 社区版 {@code <数据根>/temporary/}。
 *
 * <p>数据根解析优先级：</p>
 * <ol>
 *   <li>环境变量 {@value #AUDITAI_HOME_ENV_VAR}。末尾（大小写不敏感）等于 #DATA_DIRECTORY_NAME
 *       时原样使用（如 {@code E:\AuditAI Data}），否则追加一层（如 {@code AUDITAI_HOME=E:\aa} → {@code E:\aa\AuditAI Data}）。
 *       设了但写不动不回退（视为用户显式意图）。</li>
 *   <li>Burp 安装目录的同级（便携安装下便于整包备份；系统级安装通常不可写，自动下一档）。</li>
 *   <li>OS 标准用户数据目录：Windows {@code %LOCALAPPDATA%\AuditAI Data}，
 *       Unix {@code $HOME/.local/share/AuditAI Data}。</li>
 * </ol>
 */
public final class SessionPaths {

    /** 顶级数据目录名（同时作为环境变量 {@value #AUDITAI_HOME_ENV_VAR} 末段匹配的判定值）。 */
    public static final String DATA_DIRECTORY_NAME = "AuditAI Data";

    /** 用户重定向数据根目录的环境变量名。 */
    public static final String AUDITAI_HOME_ENV_VAR = "AUDITAI_HOME";

    /** 临时项目目录名（社区版 Burp / 专业版临时项目）。 */
    public static final String TEMPORARY_PROJECT_ID = "temporary";

    /** 项目 ID 子目录名（专业版 Burp）。 */
    public static final String PROJECTS_DIRECTORY_NAME = "projects";

    /** 各版本 Burp 的启动器 / JAR 文件名（大小写不敏感），用于推断安装目录。 */
    private static final List<String> BURP_ARTIFACT_NAMES = List.of(
            "BurpSuitePro.exe", "BurpSuiteCommunity.exe", "BurpSuite.exe",
            "burpsuite_pro.jar", "burpsuite_community.jar", "burpsuite.jar");

    /** Windows 保留设备名（作为单个路径段时非法）。 */
    private static final Set<String> WINDOWS_RESERVED_NAMES = Set.of(
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9");

    private SessionPaths() {
    }

    /**
     * @param api Montoya API 门面。
     * @return 当前 Burp 是否为专业版（BurpSuiteEdition#PROFESSIONAL）。
     */
    public static boolean isProfessionalEdition(MontoyaApi api) {
        return api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL;
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
     * 解析当前会话应使用的项目标识：专业版 + 磁盘项目 + 存在稳定项目 ID → 返回项目 ID
     * （落到 {@code projects/<id>/}）；其余（社区版 / 企业版 / 专业版临时项目 / 项目 ID
     * 为空）→ 返回 #TEMPORARY_PROJECT_ID（落到 {@code temporary/}）。
     */
    public static String resolveProjectId(MontoyaApi api) {
        if (isProfessionalEdition(api) && isDiskProject(api)) {
            String id = api.project().id();
            if (id != null && !id.isBlank()) {
                return id;
            }
        }
        return TEMPORARY_PROJECT_ID;
    }

    /**
     * 取当前项目的会话根目录：{@code <数据根>/projects/<id>/}（专业版磁盘项目）或
     * {@code <数据根>/temporary/}（社区版 / 临时项目）。
     *
     * @param extensionFilename 保留参数，当前未使用。
     * @param projectId         #resolveProjectId(MontoyaApi) 的输出。
     * @throws IOException 数据根不可写。
     */
    public static Path createProjectDirectory(String extensionFilename, String projectId) throws IOException {
        return createProjectDirectoryAtRoot(null, projectId);
    }

    /**
     * 仅测试用：给定数据根直接创建会话目录，绕过 env / Burp 同级 / 兜底三级解析；
     * {@code dataRoot} 为 null 时等价于 #createProjectDirectory(String, String)。
     */
    static Path createProjectDirectoryAtRoot(Path dataRoot, String projectId) throws IOException {
        String safeProjectId = safePathPart(projectId == null || projectId.isBlank()
                ? TEMPORARY_PROJECT_ID : projectId);
        if (dataRoot != null) {
            return resolveProjectDirectory(dataRoot, safeProjectId);
        }

        Path envRoot = resolveEnvOverride();
        if (envRoot != null) {
            return resolveProjectDirectory(envRoot, safeProjectId);
        }

        Path burpSibling = resolveBurpSiblingRoot();
        if (burpSibling != null) {
            try {
                return resolveProjectDirectory(burpSibling, safeProjectId);
            } catch (IOException ignored) {
                // 同级不可写 → 下一档。
            }
        }

        return resolveProjectDirectory(fallbackDataRoot(), safeProjectId);
    }

    /** 把 {@code <数据根>[/projects/<id> | /temporary]} 这条路径真实创建出来。 */
    private static Path resolveProjectDirectory(Path root, String safeProjectId) throws IOException {
        Path directory = TEMPORARY_PROJECT_ID.equals(safeProjectId)
                ? root.resolve(TEMPORARY_PROJECT_ID)
                : root.resolve(PROJECTS_DIRECTORY_NAME).resolve(safeProjectId);
        Files.createDirectories(directory);
        return directory;
    }

    /**
     * 解析 {@value #AUDITAI_HOME_ENV_VAR}：空 / 未设置 → null；末尾（大小写不敏感）等于
     * #DATA_DIRECTORY_NAME → 原样返回；否则追加一层 #DATA_DIRECTORY_NAME。
     */
    static Path resolveEnvOverride() {
        return resolveEnvOverride(System.getenv(AUDITAI_HOME_ENV_VAR));
    }

    /** #resolveEnvOverride() 的可注入版，便于单元测试不污染 JVM 全局环境变量。 */
    static Path resolveEnvOverride(String envValue) {
        if (envValue == null || envValue.isBlank()) {
            return null;
        }
        Path base = Paths.get(envValue.trim());
        Path lastSegment = base.getFileName();
        if (lastSegment != null && DATA_DIRECTORY_NAME.equalsIgnoreCase(lastSegment.toString())) {
            return base;
        }
        return base.resolve(DATA_DIRECTORY_NAME);
    }

    /**
     * Burp 安装目录的"父级"（即与 Burp 同级）作为数据根。Burp 安装目录无法推断时返回 null。
     */
    static Path resolveBurpSiblingRoot() {
        Path burpHome = burpInstallationDirectory();
        if (burpHome == null) {
            return null;
        }
        Path parent = burpHome.getParent();
        if (parent == null) {
            return null;
        }
        return parent.resolve(DATA_DIRECTORY_NAME);
    }

    /**
     * 推断当前 JVM 进程对应的 Burp 安装根目录。
     *
     * <p>Montoya 没有直接暴露 Burp 安装目录。本方法用 ProcessHandle 拿当前
     * 进程命令行起点（{@code java} / {@code javaw} / {@code BurpSuitePro.exe} 等），
     * 先判断起点本身是否为 Burp 启动器（原生启动器内嵌 JVM 的场景），再向上回溯找
     * Burp 的启动器 / JAR。识别名单见 #BURP_ARTIFACT_NAMES。</p>
     *
     * @return Burp 安装目录的绝对路径；推断不到（极端环境：进程命令行异常、文件布局
     *         非标准）时返回 null。
     */
    private static Path burpInstallationDirectory() {
        java.util.Optional<String> command = ProcessHandle.current().info().command();
        if (command.isEmpty()) {
            return null;
        }
        Path executable = Paths.get(command.get()).toAbsolutePath().normalize();
        // 起点本身可能就是 Burp 启动器（原生启动器内嵌 JVM）。
        if (isBurpArtifact(executable.getFileName().toString())) {
            return executable.getParent();
        }
        // 独立 JVM 场景：起点是 jre\bin\java.exe / javaw.exe，向上回溯找 Burp 安装目录。
        Path current = executable.getParent();
        while (current != null) {
            for (String name : BURP_ARTIFACT_NAMES) {
                if (Files.isRegularFile(current.resolve(name))) {
                    return current;
                }
            }
            current = current.getParent();
        }
        return null;
    }

    /** 文件名是否为 Burp 启动器 / JAR（大小写不敏感，兼容带版本后缀的旧版 JAR）。 */
    static boolean isBurpArtifact(String fileName) {
        if (fileName == null || fileName.isEmpty()) {
            return false;
        }
        for (String name : BURP_ARTIFACT_NAMES) {
            if (name.equalsIgnoreCase(fileName)) {
                return true;
            }
        }
        String lower = fileName.toLowerCase(Locale.ROOT);
        return (lower.startsWith("burpsuite_pro") || lower.startsWith("burpsuite_community")
                || lower.startsWith("burpsuite_free")) && lower.endsWith(".jar");
    }

    private static Path fallbackDataRoot() {
        // Windows 优先 LOCALAPPDATA，缺失时回退到 ~/.local/share（XDG_DATA_HOME 习惯）。
        String localAppData = System.getenv("LOCALAPPDATA");
        Path baseDirectory = localAppData == null || localAppData.isBlank()
                ? Paths.get(System.getProperty("user.home"), ".local", "share")
                : Paths.get(localAppData);
        return baseDirectory.resolve(DATA_DIRECTORY_NAME);
    }

    /** 去掉路径分隔符 / 非法字符、Windows 保留设备名、尾随点 / 空格，限制单段长度。空输入退化为 temporary。 */
    static String safePathPart(String input) {
        if (input == null || input.trim().isEmpty()) {
            return TEMPORARY_PROJECT_ID;
        }
        String cleaned = input.trim().replaceAll("[\\\\/:*?\"<>|]", "_");
        if (isWindowsReservedName(cleaned)) {
            cleaned = "_" + cleaned;
        }
        // Windows 不允许尾随点 / 空格。
        int end = cleaned.length();
        while (end > 0 && (cleaned.charAt(end - 1) == '.' || cleaned.charAt(end - 1) == ' ')) {
            end--;
        }
        cleaned = end == cleaned.length() ? cleaned : cleaned.substring(0, end);
        if (cleaned.isEmpty()) {
            return TEMPORARY_PROJECT_ID;
        }
        if (cleaned.length() > 80) {
            cleaned = truncateWithoutSplittingSurrogate(cleaned, 80);
        }
        return cleaned;
    }

    /** 单个路径段是否为 Windows 保留设备名（去掉扩展名后判断，如 CON / COM1）。 */
    private static boolean isWindowsReservedName(String name) {
        String upper = name.toUpperCase(Locale.ROOT);
        int dot = upper.indexOf('.');
        if (dot > 0) {
            upper = upper.substring(0, dot);
        }
        return WINDOWS_RESERVED_NAMES.contains(upper);
    }

    /** 按 max 截断，避免把 UTF-16 代理对（emoji 等）切半产生非法字符。 */
    private static String truncateWithoutSplittingSurrogate(String s, int max) {
        if (s.length() <= max) {
            return s;
        }
        int cut = max;
        if (Character.isHighSurrogate(s.charAt(cut - 1))) {
            cut--;
        }
        return s.substring(0, cut);
    }
}
