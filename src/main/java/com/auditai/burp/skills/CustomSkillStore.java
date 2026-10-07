package com.auditai.burp.skills;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * 用户自定义技能的本地文件仓库。
 *
 * <p>扁平形态：{@code <数据根>/projects/<id>/custom-skills/<id>/SKILL.md}，
 * 目录名即技能 id，不分 vuln/auxiliary 子层。#install 用 {@code .tmp} +
 * ATOMIC_MOVE 写入，避免半写文件被扫描到。</p>
 */
public final class CustomSkillStore {

    /** 用户自定义技能目录名（与 SkillLoader 配合识别）。 */
    public static final String CUSTOM_SKILLS_DIRECTORY_NAME = "custom-skills";

    /** id 最大允许长度（与文件系统路径长度限制 + UI 可读性折中）。 */
    private static final int MAX_ID_LENGTH = 100;

    private final Path root;
    private final java.util.function.Consumer<String> errorLogger;

    /**
     * @param sessionRoot 会话根目录（{@code SessionPaths.createProjectDirectory(...).path()}
     *                    的输出，{@code projects/<id>/} 或 {@code temporary/}）。若为 null
     *                    或不可写时，#install / #uninstall 会抛
     *                    IOException，调用方降级提示"无法写入用户数据目录"。
     * @param errorLogger 落盘失败时的日志回调；生产路径由
     *                    {@code AuditAiExtension} 注入 {@code api.logging().logToError}。
     */
    public CustomSkillStore(Path sessionRoot, java.util.function.Consumer<String> errorLogger) {
        Objects.requireNonNull(errorLogger, "errorLogger");
        this.errorLogger = errorLogger;
        this.root = sessionRoot == null ? null : sessionRoot.resolve(CUSTOM_SKILLS_DIRECTORY_NAME);
    }

    /** 用户技能存储根目录（{@code <sessionRoot>/custom-skills/}）；会话根为 null 时为 null。 */
    public Path rootDirectory() {
        return root;
    }

    /**
     * 把用户提供的 {@code SKILL.md} 内容落地为 {@code <root>/<id>/SKILL.md}。
     *
     * @param id          技能 id（最终落到 <code>&lt;id&gt;</code> 子目录名）。
     * @param content     SKILL.md 文本（必须含 {@code ---} 边界 + {@code name} 字段）。
     * @param overrideConflict true 时与既有同 id 冲突会追加 {@code -2/-3...} 后缀；
     *                        false 时直接抛 IOException。
     * @return 实际写入的 SKILL.md 路径。
     * @throws IOException 文件 IO 失败、id 不合法或 SKILL.md 内容不合法时。
     */
    public Path install(String id, String content, boolean overrideConflict) throws IOException {
        if (root == null) {
            throw new IOException("用户技能目录不可用：sessionRoot 为 null");
        }
        validateId(id);
        Skill parsed = SkillLoader.parseForInstallCheck(id, content);
        if (parsed == null) {
            throw new IOException("SKILL.md 内容不合法：缺 --- 边界或缺 name 字段");
        }
        String actualId = id;
        Path skillDir = root.resolve(actualId);
        if (Files.exists(skillDir)) {
            if (!overrideConflict) {
                throw new IOException("技能 id 已存在：" + id);
            }
            actualId = findNonCollidingId(id);
            skillDir = root.resolve(actualId);
        }
        Files.createDirectories(skillDir);
        Path target = skillDir.resolve(SkillLoader.SKILL_FILENAME);
        Path temp = Files.createTempFile(skillDir, ".SKILL-", ".tmp");
        try {
            Files.writeString(temp, content, StandardCharsets.UTF_8);
            try {
                Files.move(temp, target, java.nio.file.StandardCopyOption.ATOMIC_MOVE);
            } catch (java.nio.file.AtomicMoveNotSupportedException e) {
                // FAT / 跨盘符等极端环境下 ATOMIC_MOVE 不可用，回退到普通 move。
                Files.move(temp, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temp);
        }
        return target;
    }

    /**
     * 卸载指定 id 的用户技能：递归删除 {@code <root>/<id>/} 目录。
     *
     * <p>仅作用于 SkillSource#USER 来源——调用方负责前置校验（内置技能不可卸载）。
     * 若 id 对应的目录不存在（已被外部删除、并发卸载），不抛错、返回 false。</p>
     *
     * @return true 表示本次调用实际删除了目录；false 表示目录本就不存在。
     */
    public boolean uninstall(String id) throws IOException {
        if (root == null) {
            throw new IOException("用户技能目录不可用：sessionRoot 为 null");
        }
        validateId(id);
        Path skillDir = root.resolve(id);
        if (!Files.exists(skillDir)) {
            return false;
        }
        deleteRecursively(skillDir);
        return true;
    }

    /**
     * 校验 id 合法性：允许字母/数字/连字符/下划线/点/空格（含中文），长度 1-100；
     * 首尾不能是空格；禁止路径分隔符、Windows 保留字符、控制字符。
     *
     * @throws IOException 不合法时抛错，错误消息给上层直接展示给用户。
     */
    public static void validateId(String id) throws IOException {
        if (id == null || id.isBlank()) {
            throw new IOException("技能 id 不能为空");
        }
        String trimmed = id.trim();
        if (trimmed.length() > 100) {
            throw new IOException("技能 id 长度不能超过 100 个字符");
        }
        // 禁止路径分隔符、Windows 保留字符、控制字符
        for (int i = 0; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);
            if (c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"'
                    || c == '<' || c == '>' || c == '|' || c < 0x20) {
                throw new IOException("技能 id 不能包含路径分隔符或控制字符：" + describeChar(c));
            }
        }
        // 首尾不能是空格（trim 后已处理，但保留防御）
        if (trimmed.charAt(0) == ' ' || trimmed.charAt(trimmed.length() - 1) == ' ') {
            throw new IOException("技能 id 首尾不能是空格");
        }
    }

    /** 把不可见字符翻译成可读形式给用户看。 */
    private static String describeChar(char c) {
        if (c < 0x20) {
            return String.format("\\u%04x", (int) c);
        }
        return "'" + c + "'";
    }

    /**
     * 从技能 name 派生默认 id：保留空格、中文、emoji 等；只剔除路径分隔符与控制字符；
     * 大小写敏感（不改写），派生为空时返回 null。
     */
    public static String suggestIdFromName(String name) {
        if (name == null) {
            return null;
        }
        String trimmed = name.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        // 仅剥路径分隔符与控制字符，其它（含空格、中文、emoji）原样保留
        StringBuilder sb = new StringBuilder(trimmed.length());
        for (int i = 0; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);
            if (c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"'
                    || c == '<' || c == '>' || c == '|' || c < 0x20) {
                sb.append(' ');
            } else {
                sb.append(c);
            }
        }
        // 折叠连续空格 + 去首尾空格（Windows 不允许尾随空格/点的目录名）
        String result = sb.toString().replaceAll(" {2,}", " ").trim();
        // 末尾的 '.' 在 Windows 下是非法的，替成空格
        while (result.endsWith(".")) {
            result = result.substring(0, result.length() - 1) + " ";
            result = result.trim();
        }
        if (result.isEmpty()) {
            return null;
        }
        if (result.length() > 100) {
            result = result.substring(0, 100).trim();
        }
        return result;
    }

    /**
     * 从用户挑选的文件路径派生默认 id：去后缀、空格替为 '-'、非法字符替为 '-'、全部小写；
     * 派生为空或不合法返回 null。
     */
    public static String suggestIdFromFile(Path file) {
        if (file == null) {
            return null;
        }
        String name = file.getFileName().toString();
        int dot = name.lastIndexOf('.');
        if (dot > 0) {
            name = name.substring(0, dot);
        }
        name = name.trim().toLowerCase(Locale.ROOT);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (Character.isLetterOrDigit(c) || c == '-' || c == '_' || c == '.') {
                sb.append(c);
            } else {
                sb.append('-');
            }
        }
        String result = sb.toString();
        // 去掉首尾的分隔符；若首字符不是字母/数字则前置 's-'
        int start = 0;
        while (start < result.length() && (result.charAt(start) == '-' || result.charAt(start) == '_' || result.charAt(start) == '.')) {
            start++;
        }
        int end = result.length();
        while (end > start && (result.charAt(end - 1) == '-' || result.charAt(end - 1) == '_' || result.charAt(end - 1) == '.')) {
            end--;
        }
        result = start == 0 && end == result.length() ? result : result.substring(start, end);
        if (result.isEmpty()) {
            return null;
        }
        char first = result.charAt(0);
        if (!Character.isLetterOrDigit(first)) {
            result = "s-" + result;
        }
        if (result.length() > 64) {
            result = result.substring(0, 64);
        }
        try {
            validateId(result);
            return result;
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * 找首个不冲突的 id：baseId 不存在直接返回，存在则尝试 {@code baseId-2}、{@code baseId-3}…
     * 上限 999 后缀，超出抛错（避免无限循环）。
     */
    String findNonCollidingId(String baseId) throws IOException {
        if (root == null) {
            throw new IOException("用户技能目录不可用：sessionRoot 为 null");
        }
        Path base = root.resolve(baseId);
        if (!Files.exists(base)) {
            return baseId;
        }
        for (int i = 2; i < 1000; i++) {
            String candidate = baseId + "-" + i;
            if (!Files.exists(root.resolve(candidate))) {
                return candidate;
            }
        }
        throw new IOException("技能 id 冲突次数过多：" + baseId);
    }

    /** 检查当前 store 根目录里已经存在哪些用户技能 id（用于冲突检测）。 */
    public List<String> listInstalledIds() throws IOException {
        if (root == null || !Files.isDirectory(root)) {
            return List.of();
        }
        List<String> ids = new java.util.ArrayList<>();
        try (var stream = Files.list(root)) {
            stream.filter(Files::isDirectory).forEach(p -> ids.add(p.getFileName().toString()));
        }
        java.util.Collections.sort(ids);
        return ids;
    }

    private static void deleteRecursively(Path path) throws IOException {
        if (Files.isDirectory(path)) {
            try (var stream = Files.list(path)) {
                List<Path> children = stream.toList();
                for (Path child : children) {
                    deleteRecursively(child);
                }
            }
        }
        Files.deleteIfExists(path);
    }

    /** 写一条诊断日志（生产路径转 Burp Extender Error 面板）。 */
    void logError(String message) {
        try {
            errorLogger.accept("[CustomSkillStore] " + message);
        } catch (RuntimeException ignored) {
            // 错误回调自身异常不应阻断主流程。
        }
    }
}