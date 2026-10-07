package com.auditai.burp.util;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;

import java.io.File;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

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

    /**
     * 数据根解析结果：路径 + 来源 + 兜底诊断。{@code diagnostic} 仅在
     * {@link DataRootSource#OS_FALLBACK} 时非空，携带回退原因（未推断到 / 无父目录 /
     * 同级不可写）与回退目标；其余来源为 null。
     */
    public record DataRootResolution(Path path, DataRootSource source, String diagnostic) {
    }

    /**
     * 数据根来源：{@link #AUDITAI_HOME} > {@link #BURP_SIBLING} > {@link #OS_FALLBACK}。
     * {@link #DIRECT} 仅出现在测试或调用方显式传入根目录的场景。
     */
    public enum DataRootSource {
        /** 调用方显式传入根目录（测试或内部代码使用）。 */
        DIRECT,
        /** {@link #AUDITAI_HOME_ENV_VAR} 环境变量指定。 */
        AUDITAI_HOME,
        /** 与 Burp 安装目录同级。 */
        BURP_SIBLING,
        /** 系统标准用户数据目录兜底（Burp 同级不可写等场景）。 */
        OS_FALLBACK
    }

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
     * 解析当前会话应使用的项目标识：专业版且项目 ID 非空 → 返回项目 ID
     * （落到 {@code projects/<id>/}）；其余（社区版 / 企业版 / 专业版但 ID 为空）
     * → 返回 #TEMPORARY_PROJECT_ID（落到 {@code temporary/}）。
     *
     * <p>专业版即使未带 {@code --project-file} 也会拿到稳定 ID，直接落到
     * {@code projects/<id>/}，避免不同会话挤到同一个 {@code temporary/}。</p>
     */
    public static String resolveProjectId(MontoyaApi api) {
        if (isProfessionalEdition(api)) {
            String id = api.project().id();
            if (id != null && !id.isBlank()) {
                return id;
            }
        }
        return TEMPORARY_PROJECT_ID;
    }

    /**
     * 取当前项目的会话根目录：{@code <数据根>/projects/<id>/}（专业版）或
     * {@code <数据根>/temporary/}（社区版 / 企业版 / 专业版无 id）。同时返回数据根来源与
     * 诊断信息，便于 AuditAiExtension 在数据根落到兜底目录时提示用户原因。
     *
     * @param extensionFilename 扩展 JAR 路径，用于 Burp 安装目录探测的兜底分支（native
     *                          launcher 不暴露 {@code arguments()} 时仍能反推）。
     * @param projectId         #resolveProjectId(MontoyaApi) 的输出。
     * @throws IOException 数据根不可写。
     */
    public static DataRootResolution createProjectDirectory(String extensionFilename, String projectId) throws IOException {
        return createProjectDirectoryAtRoot(null, projectId, extensionFilename);
    }

    /**
     * 仅测试用：给定数据根直接创建会话目录，绕过 env / Burp 同级 / 兜底三级解析；
     * {@code dataRoot} 为 null 时等价于 #createProjectDirectory(String, String)。
     */
    static DataRootResolution createProjectDirectoryAtRoot(Path dataRoot, String projectId, String extensionFilename) throws IOException {
        String safeProjectId = safePathPart(projectId == null || projectId.isBlank()
                ? TEMPORARY_PROJECT_ID : projectId);
        if (dataRoot != null) {
            return new DataRootResolution(resolveProjectDirectory(dataRoot, safeProjectId),
                    DataRootSource.DIRECT, null);
        }

        Path envRoot = resolveEnvOverride();
        if (envRoot != null) {
            return new DataRootResolution(resolveProjectDirectory(envRoot, safeProjectId),
                    DataRootSource.AUDITAI_HOME, null);
        }

        Path burpHome = burpInstallationDirectory(extensionFilename);
        if (burpHome != null) {
            Path burpSibling = resolveBurpSiblingRoot(burpHome);
            if (burpSibling != null) {
                try {
                    return new DataRootResolution(resolveProjectDirectory(burpSibling, safeProjectId),
                            DataRootSource.BURP_SIBLING, null);
                } catch (IOException ignored) {
                    // 同级不可写 → 下一档。
                }
            }
        }

        Path fallback = fallbackDataRoot();
        return new DataRootResolution(resolveProjectDirectory(fallback, safeProjectId),
                DataRootSource.OS_FALLBACK, fallbackDiagnostic(burpHome, fallback));
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
     * 由 Burp 安装目录推导同级数据根：{@code <burpHome 的父目录>/AuditAI Data}。
     * {@code burpHome} 为 null 或没有父目录（Burp 装在文件系统根目录）时返回 null。
     */
    static Path resolveBurpSiblingRoot(Path burpHome) {
        if (burpHome == null) {
            return null;
        }
        Path parent = burpHome.getParent();
        return parent == null ? null : parent.resolve(DATA_DIRECTORY_NAME);
    }

    /** OS 兜底时的诊断文案：区分"未推断到 / 无父目录 / 同级不可写"三种原因。 */
    private static String fallbackDiagnostic(Path burpHome, Path fallback) {
        if (burpHome == null) {
            return "未推断到 Burp 安装目录，回退到 " + fallback;
        }
        if (burpHome.getParent() == null) {
            return "Burp 安装目录 " + burpHome + " 无上级目录，回退到 " + fallback;
        }
        return "Burp 安装目录 " + burpHome + " 的同级不可写，回退到 " + fallback;
    }

    /**
     * 推断当前 JVM 进程对应的 Burp 安装根目录。
     *
     * <p>Montoya 没有直接暴露 Burp 安装目录。本方法按以下顺序探测：</p>
     * <ol>
     *   <li>进程命令行起点本身就是 Burp 启动器（{@code BurpSuitePro.exe} 等）；</li>
     *   <li>独立 JVM 场景下沿父目录回溯找 Burp 启动器 / JAR；</li>
     *   <li>JVM 参数里 {@code -jar burpsuite_*.jar}（用户用自定义 JDK 的
     *       {@code java -jar} 启动 Burp 时走这条——{@code arguments()} 是唯一线索）；</li>
     *   <li>{@code java.class.path} 系统属性（native launcher 清空了 {@code arguments()}
     *       时仍保留主类 jar 路径）；</li>
     *   <li>扩展 JAR 路径向上回溯 / 扫 {@code BurpSuite*} 同级目录（扩展和 Burp
     *       不在同一棵目录树时兜底）。</li>
     * </ol>
     *
     * <p>识别名单见 #BURP_ARTIFACT_NAMES。</p>
     *
     * @param extensionFilename Burp 报告的扩展 JAR 路径；null / 空时跳过第 5 档。
     * @return Burp 安装目录的绝对路径；推断不到时返回 null。
     */
    static Path burpInstallationDirectory(String extensionFilename) {
        try {
            return detectBurpInstallationDirectory(extensionFilename);
        } catch (RuntimeException e) {
            // ProcessHandle 的 command()/arguments() 在部分平台 / 启动器下会抛
            // UnsupportedOperationException / SecurityException，平台返回的路径也可能非法
            // （InvalidPathException）。探测失败统一按"推断不到"降级为 null，由上层回退到
            // OS 标准目录，不能让 init 期异常一路抛到插件加载入口。
            return null;
        }
    }

    private static Path detectBurpInstallationDirectory(String extensionFilename) {
        Optional<String> command = ProcessHandle.current().info().command();
        if (command.isPresent()) {
            Path executable = Paths.get(command.get()).toAbsolutePath().normalize();
            // 起点本身就是 Burp 启动器（原生启动器内嵌 JVM）。
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
        }
        Path fromArgs = burpJarFromJvmArguments();
        if (fromArgs != null) {
            return fromArgs;
        }
        Path fromClassPath = burpJarFromJavaClassPath();
        if (fromClassPath != null) {
            return fromClassPath;
        }
        return burpDirFromExtensionFilename(extensionFilename);
    }

    /**
     * 从 JVM 启动参数里找 {@code -jar burpsuite_*.jar}，返回 jar 所在目录。
     * 仅识别 {@code -jar} 后紧跟的 Burp 制品文件名，避免误把其它 -jar 启动当成 Burp。
     */
    private static Path burpJarFromJvmArguments() {
        Optional<String[]> arguments = ProcessHandle.current().info().arguments();
        if (arguments.isEmpty()) {
            return null;
        }
        String[] args = arguments.get();
        for (int i = 0; i < args.length - 1; i++) {
            if ("-jar".equals(args[i])) {
                String jarPath = args[i + 1];
                Path jar = Paths.get(jarPath).toAbsolutePath().normalize();
                if (isBurpArtifact(jar.getFileName().toString())) {
                    return jar.getParent();
                }
            }
        }
        return null;
    }

    /**
     * 从 {@code java.class.path} 系统属性里找 {@code burpsuite_*.jar}，返回 jar 所在目录。
     * 覆盖 {@code ProcessHandle.arguments()} 被 native launcher 清空、却还能从 classpath
     * 拿到主类 jar 的极端场景。
     */
    private static Path burpJarFromJavaClassPath() {
        String classPath = System.getProperty("java.class.path");
        if (classPath == null || classPath.isEmpty()) {
            return null;
        }
        String separator = Pattern.quote(File.pathSeparator);
        for (String entry : classPath.split(separator)) {
            if (entry.isEmpty()) {
                continue;
            }
            Path jar = Paths.get(entry).toAbsolutePath().normalize();
            if (isBurpArtifact(jar.getFileName().toString())) {
                return jar.getParent();
            }
        }
        return null;
    }

    /**
     * 从扩展 JAR 路径（{@code api.extension().filename()}）找 Burp 安装目录：先沿父目录
     * 向上回溯；找不到时再从每层父目录的 {@code BurpSuite*} 同级目录里找——扩展 JAR 跟 Burp
     * 装在并列的兄弟目录下时必须看同级。仍找不到时返回 null，由上层兜底到 LOCALAPPDATA。
     */
    private static Path burpDirFromExtensionFilename(String extensionFilename) {
        if (extensionFilename == null || extensionFilename.isBlank()) {
            return null;
        }
        Path jar = Paths.get(extensionFilename).toAbsolutePath().normalize();
        // 1) 向上回溯。
        Path current = jar.getParent();
        while (current != null) {
            for (String name : BURP_ARTIFACT_NAMES) {
                if (Files.isRegularFile(current.resolve(name))) {
                    return current;
                }
            }
            current = current.getParent();
        }
        // 2) 每层父目录下扫 "BurpSuite*" 同级目录里的 Burp 产物。
        Path anchor = jar.getParent();
        while (anchor != null) {
            Path parent = anchor.getParent();
            if (parent == null) {
                break;
            }
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(parent)) {
                for (Path sibling : stream) {
                    if (!Files.isDirectory(sibling)) {
                        continue;
                    }
                    String name = sibling.getFileName().toString();
                    if (!name.toLowerCase(Locale.ROOT).startsWith("burpsuite")) {
                        continue;
                    }
                    for (String artifact : BURP_ARTIFACT_NAMES) {
                        if (Files.isRegularFile(sibling.resolve(artifact))) {
                            return sibling;
                        }
                    }
                }
            } catch (IOException ignored) {
                // 父目录不可读 / 受 ACL 限制 → 这一层扫不到，继续上一层。
            }
            anchor = parent;
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

    /**
     * DEBUG-only：把数据根解析的关键环境值摊到 Output，便于排查"为什么没落在 Burp 同级"。
     * 仅在 {@code -Dauditai.debug.prompt=true} 时调用；不修改磁盘，只读进程 / 平台属性。
     */
    public static String describeResolutionAttempt(MontoyaApi api, String extensionFilename) {
        StringBuilder sb = new StringBuilder();
        sb.append("[DEBUG] 数据根解析追踪：").append(System.lineSeparator());

        sb.append("  [1] Burp 环境：");
        if (api == null) {
            sb.append("(api 未注入)");
        } else {
            sb.append("版本=").append(api.burpSuite().version().edition())
                    .append("；项目名=").append(api.project().name())
                    .append("；项目ID=").append(api.project().id())
                    .append("；CLI 参数=").append(api.burpSuite().commandLineArguments())
                    .append("；扩展 JAR=").append(extensionFilename);
        }
        sb.append(System.lineSeparator());

        sb.append("  [2] 进程起点 (ProcessHandle.command())：");
        Optional<String> cmd = ProcessHandle.current().info().command();
        if (cmd.isEmpty()) {
            sb.append("(未提供)");
        } else {
            Path exe = Paths.get(cmd.get()).toAbsolutePath().normalize();
            String fileName = exe.getFileName() == null ? null : exe.getFileName().toString();
            sb.append(exe).append(System.lineSeparator());
            sb.append("      fileName=").append(fileName)
                    .append("，isBurpArtifact=").append(isBurpArtifact(fileName));
        }
        return sb.toString();
    }
}
