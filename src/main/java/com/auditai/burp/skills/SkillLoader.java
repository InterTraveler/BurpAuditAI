package com.auditai.burp.skills;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Stream;

/**
 * 技能目录扫描与解析器。
 *
 * <p>每个技能以一个独立目录呈现，目录名即技能 id；目录下必须有且仅有一个
 * {@code SKILL.md} 文件（大小写敏感）。文件格式：</p>
 *
 * <pre>{@code
 * ---
 * name: <必填，显示名>
 * icon: <可选，单字符>
 * description: <可选>
 * findingType: <可选>
 * userContext: <可选，多行请用 | 块标量>
 * summaryCount: <可选，正整数>
 * ---
 *
 * <Markdown 正文 = Skill.prompt() 内容>
 * }</pre>
 *
 * <p>YAML 标量风格支持：</p>
 * <ul>
 *   <li>{@code |} 字面块标量——保留换行，块内容缩进 ≥ 2 空格；</li>
 *   <li>{@code '...'} 单引号标量——内部 {@code '} 用 {@code ''} 转义；</li>
 *   <li>{@code "..."} 双引号标量——不做转义解析；</li>
 *   <li>裸标量——用于不含特殊字符的短标识。</li>
 * </ul>
 *
 * <p>键名归一化为小写后查找（{@code findingType} 与 {@code findingtype} 等价）。
 * frontmatter 之外的 YAML 概念（嵌套、引用、tag 等）不支持——本项目的元数据
 * 需求被刻意收窄到上面 6 个字段。</p>
 *
 * <p>本类同时支持两种来源、两种目录形态：</p>
 * <ul>
 *   <li><b>来源</b>：内置（SkillSource#BUILTIN，classpath:/skills/）/
 *       用户自定义（SkillSource#USER，<code><数据根>/.../custom-skills/</code>，数据根见 SessionPaths 类）；</li>
 *   <li><b>形态</b>：分层（{@code <root>/<category>/<id>/SKILL.md}，
 *       category ∈ {vuln, auxiliary}）/ 扁平（{@code <root>/<id>/SKILL.md}，
 *       用户自定义技能专用）。</li>
 * </ul>
 *
 * <p><b>分层目录约定</b>（内置）：技能根目录下按用途分两类子目录——</p>
 * <ul>
 *   <li><code>skills/vuln/&lt;id&gt;/SKILL.md</code>：漏洞检测类技能；</li>
 *   <li><code>skills/auxiliary/&lt;id&gt;/SKILL.md</code>：辅助类技能（不直接产出 finding）。</li>
 * </ul>
 *
 * <p>为了兼容历史布局，<b>顶层 <code>skills/&lt;id&gt;/SKILL.md</code></b> 也会被加载
 * （视为"未分类"）。其它任意命名的子目录（如 {@code _deprecated/}、{@code experimental/}）
 * 会被自动跳过；超过两层的嵌套一律忽略——便于做下架 / 实验而不必删文件。</p>
 *
 * <p><b>扁平目录约定</b>（用户）：<code>custom-skills/&lt;id&gt;/SKILL.md</code>，
 * 直接以目录名作为 id，不区分分类。</p>
 *
 * <p>解析失败（IO 错误、缺 {@code ---} 边界、缺 {@code name} 字段）的文件会被跳过。
 * 同名 id 时 SkillSource#USER 覆盖 SkillSource#BUILTIN；同来源重复只保留第一次。</p>
 */
public final class SkillLoader {

    /** 技能文件名：固定大小写敏感，位于每个技能目录内。 */
    public static final String SKILL_FILENAME = "SKILL.md";

    /**
     * 单个扫描根：URL + 来源标签 + 形态（分层 / 扁平）。
     * 分层：扫描 <code>root</code> 本身 + <code>root/vuln/</code> + <code>root/auxiliary/</code>；
     * 扁平：仅扫描 <code>root</code> 本身（用户自定义技能无分类下放）。
     */
    private record Root(URL url, SkillSource source, boolean flat) { }

    private final List<Root> roots;

    /** 错误/诊断日志回调（生产路径由 {@code AuditAiExtension} 注入 {@code api.logging().logToError}）。 */
    private final Consumer<String> errorLogger;

    private SkillLoader(List<Root> roots, Consumer<String> errorLogger) {
        this.roots = List.copyOf(roots);
        this.errorLogger = Objects.requireNonNull(errorLogger, "errorLogger");
    }

    /** no-op 错误回调：仅用于纯测试场景。 */
    private static Consumer<String> noopErrorLogger() {
        return msg -> { };
    }

    /** 创建 classpath 来源的加载器（仅测试用，无错误日志）。生产路径请用三参重载。 */
    public static SkillLoader fromClasspath(String directoryName, ClassLoader classLoader) {
        return fromClasspath(directoryName, classLoader, noopErrorLogger());
    }

    /**
     * 创建 classpath 来源的加载器。
     *
     * @param directoryName classpath 中的目录名（如 {@code "skills"}，不能以 {@code /} 开头）。
     * @param classLoader   用于查找资源的类加载器；null 时用当前线程的上下文类加载器。
     * @param errorLogger   错误/诊断日志回调（不允许 null）。
     */
    public static SkillLoader fromClasspath(String directoryName, ClassLoader classLoader,
                                            Consumer<String> errorLogger) {
        Objects.requireNonNull(directoryName, "directoryName");
        Objects.requireNonNull(errorLogger, "errorLogger");
        ClassLoader cl = classLoader != null ? classLoader : Thread.currentThread().getContextClassLoader();
        if (cl == null) {
            throw new IllegalStateException("无法确定用于扫描 classpath 的类加载器：传入与线程上下文都为 null");
        }
        List<Root> roots = new ArrayList<>();
        try {
            Enumeration<URL> resources = cl.getResources(directoryName);
            while (resources.hasMoreElements()) {
                roots.add(new Root(resources.nextElement(), SkillSource.BUILTIN, false));
            }
        } catch (IOException e) {
            throw new IllegalStateException("无法扫描 classpath 目录：" + directoryName, e);
        }
        return new SkillLoader(roots, errorLogger);
    }

    /** 创建文件系统目录来源的加载器（仅测试用，无错误日志）。生产路径请用两参重载。 */
    public static SkillLoader fromDirectory(Path directory) {
        return fromDirectory(directory, noopErrorLogger());
    }

    /**
     * 创建文件系统目录来源的加载器，注入自定义日志回调。
     *
     * @param directory    本地目录路径；不存在或不是目录时返回空列表（不抛错）。
     * @param errorLogger  错误/诊断日志回调（不允许 null）。
     */
    public static SkillLoader fromDirectory(Path directory, Consumer<String> errorLogger) {
        Objects.requireNonNull(directory, "directory");
        Objects.requireNonNull(errorLogger, "errorLogger");
        List<Root> roots = new ArrayList<>();
        if (Files.isDirectory(directory)) {
            try {
                roots.add(new Root(directory.toUri().toURL(), SkillSource.BUILTIN, false));
            } catch (IOException e) {
                throw new IllegalStateException("无法转换目录为 URL：" + directory, e);
            }
        }
        return new SkillLoader(roots, errorLogger);
    }

    /**
     * 创建扁平形态的文件系统目录加载器，专用于扫描用户自定义技能目录（来源标记为
     * SkillSource#USER，只扫一层）。
     *
     * @param directory    本地目录路径；不存在或不是目录时返回空列表（不抛错）。
     * @param errorLogger  错误/诊断日志回调（不允许 null）。
     */
    public static SkillLoader fromUserDirectory(Path directory, Consumer<String> errorLogger) {
        Objects.requireNonNull(directory, "directory");
        Objects.requireNonNull(errorLogger, "errorLogger");
        List<Root> roots = new ArrayList<>();
        if (Files.isDirectory(directory)) {
            try {
                roots.add(new Root(directory.toUri().toURL(), SkillSource.USER, true));
            } catch (IOException e) {
                throw new IllegalStateException("无法转换目录为 URL：" + directory, e);
            }
        }
        return new SkillLoader(roots, errorLogger);
    }

    /**
     * 创建 classpath + 用户目录的合并加载器。先内置再用户——同名 id 时用户版覆盖内置版。
     * 任一来源为空 / 不存在时降级为单来源，不抛错。
     *
     * @param directoryName  classpath 中的内置技能目录名（如 {@code "skills"}）。
     * @param classLoader    用于查找 classpath 资源的类加载器；null 时使用上下文类加载器。
     * @param userDirectory  用户自定义技能目录（<code>custom-skills/</code>），可为 null；
     *                       不存在时降级为仅 classpath。
     * @param errorLogger    错误/诊断日志回调（不允许 null）。
     */
    public static SkillLoader fromClasspathAndUserDirectory(String directoryName, ClassLoader classLoader,
                                                            Path userDirectory, Consumer<String> errorLogger) {
        SkillLoader classpathOnly = fromClasspath(directoryName, classLoader, errorLogger);
        List<Root> roots = new ArrayList<>(classpathOnly.roots);
        if (userDirectory != null) {
            // 即使目录当前不存在也注册 Root：用户首次"添加技能"会建目录，reload 时才跟得上。
            // collectFromFile 内部再次 Files.isDirectory 检查，目录缺失时自然跳过。
            try {
                roots.add(new Root(userDirectory.toUri().toURL(), SkillSource.USER, true));
            } catch (IOException e) {
                throw new IllegalStateException("无法转换用户技能目录为 URL：" + userDirectory, e);
            }
        }
        return new SkillLoader(roots, errorLogger);
    }

    /** 输出诊断日志：直接走注入的回调（构造期已校验非 null）。 */
    private void logError(String message) {
        errorLogger.accept("[SkillLoader] " + message);
    }

    /**
     * 扫描所有已注册来源，按 {@code id}（即技能目录名）字典序排序后返回。
     * 解析失败的文件会被跳过；同名 id 处理规则见类级 Javadoc。
     *
     * @return 技能列表（可能为空，但永远非 null）。
     */
    public List<Skill> load() {
        Map<String, Skill> byId = new LinkedHashMap<>();
        Map<String, SkillSource> sourceById = new LinkedHashMap<>();
        for (Root root : roots) {
            collect(root, byId, sourceById);
        }
        List<Skill> result = new ArrayList<>(byId.values());
        result.sort(Comparator.comparing(Skill::id));
        return result;
    }

    /** 从单个 classpath 根（{@code file:} 或 {@code jar:}）收集技能。 */
    private void collect(Root root, Map<String, Skill> sink, Map<String, SkillSource> sourceById) {
        String protocol = root.url().getProtocol();
        if ("file".equals(protocol)) {
            try {
                collectFromFile(Paths.get(root.url().toURI()), root, sink, sourceById);
            } catch (URISyntaxException e) {
                logError("无法解析 file URL：" + root.url() + "：" + e.getMessage());
            }
        } else if ("jar".equals(protocol)) {
            collectFromJar(root.url(), root.source(), sink, sourceById);
        } else {
            logError("不支持的 classpath 协议，已跳过：" + protocol);
        }
    }

    /** 扫描本地目录中各技能子目录里的 #SKILL_FILENAME。 */
    private void collectFromFile(Path directory, Root root, Map<String, Skill> sink,
                                  Map<String, SkillSource> sourceById) {
        if (!Files.isDirectory(directory)) {
            return;
        }
        List<Path> scanTargets = root.flat() ? List.of(directory) : scanRootsFor(directory);
        for (Path scanRoot : scanTargets) {
            try (Stream<Path> stream = Files.list(scanRoot)) {
                stream
                        .filter(Files::isDirectory)
                        .forEach(dir -> {
                            Path md = dir.resolve(SKILL_FILENAME);
                            if (Files.isRegularFile(md)) {
                                parseInto(dir.getFileName().toString(), root.source(),
                                        () -> Files.newInputStream(md), sink, sourceById);
                            }
                        });
            } catch (IOException e) {
                logError("扫描目录失败：" + scanRoot + "：" + e.getMessage());
            }
        }
    }

    /**
     * 列出本地目录模式下要扫描的根：传入目录本身 + 约定的 {@code vuln/} + {@code auxiliary/} 子目录
     * （子目录不存在时跳过）。其它子目录不收——白名单约定，避免下架目录里的内容被误加载。
     */
    private static List<Path> scanRootsFor(Path directory) {
        List<Path> roots = new ArrayList<>(3);
        roots.add(directory);
        Path vuln = directory.resolve("vuln");
        if (Files.isDirectory(vuln)) {
            roots.add(vuln);
        }
        Path auxiliary = directory.resolve("auxiliary");
        if (Files.isDirectory(auxiliary)) {
            roots.add(auxiliary);
        }
        return roots;
    }

    /** 扫描 JAR 内部 {@code /<root>/<category>/<id>/SKILL.md} 形式的技能条目。 */
    private void collectFromJar(URL root, SkillSource source, Map<String, Skill> sink,
                                 Map<String, SkillSource> sourceById) {
        // jar URL 形如：jar:file:/path/to.jar!/skills
        String spec = root.getPath();
        int separator = spec.indexOf("!/");
        if (separator < 0) {
            logError("无法解析 jar URL：" + root);
            return;
        }
        String jarSpec = spec.substring(0, separator);
        String entryPrefix = spec.substring(separator + 2);
        if (!entryPrefix.isEmpty() && !entryPrefix.endsWith("/")) {
            entryPrefix = entryPrefix + "/";
        }
        Path jarPath;
        try {
            jarPath = Paths.get(URI.create(jarSpec));
        } catch (Exception e) {
            logError("无法解析 jar 路径：" + jarSpec);
            return;
        }
        try (JarFile jar = new JarFile(jarPath.toFile())) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.isDirectory()) {
                    continue;
                }
                String name = entry.getName();
                if (!name.startsWith(entryPrefix) || !name.endsWith("/" + SKILL_FILENAME)) {
                    continue;
                }
                // relative = "vuln/sql-injection/SKILL.md" 或 "sql-injection/SKILL.md"
                String relative = name.substring(entryPrefix.length());
                String trimmed = relative.substring(0, relative.length() - SKILL_FILENAME.length() - 1);
                // trimmed = "vuln/sql-injection" 或 "sql-injection"
                String[] parts = trimmed.split("/", -1);
                String id;
                if (parts.length == 1) {
                    // 顶层单层目录：未分类（如 "sql-injection/SKILL.md"）。
                    if (parts[0].isEmpty()) {
                        continue;
                    }
                    id = parts[0];
                } else if (parts.length == 2) {
                    // 两层：vuln/<id> 或 auxiliary/<id>，其它分类目录直接跳过。
                    if (!"vuln".equals(parts[0]) && !"auxiliary".equals(parts[0])) {
                        continue;
                    }
                    id = parts[1];
                } else {
                    // 三层及以上：跳过。
                    continue;
                }
                final String finalName = name;
                final String finalId = id;
                parseInto(finalId, source, () -> {
                    try {
                        return jar.getInputStream(jar.getEntry(finalName));
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }
                }, sink, sourceById);
            }
        } catch (IOException e) {
            logError("扫描 jar 失败：" + jarPath + "：" + e.getMessage());
        } catch (IllegalArgumentException e) {
            // Paths.get(URI) 解析失败时（jar URL 路径非法）会抛 IllegalArgumentException
            logError("无法打开 jar：" + jarPath + "：" + e.getMessage());
        }
    }

    /**
     * 读取并解析单个 {@code SKILL.md} 文件：目录名作 ID，正文按 YAML frontmatter +
     * Markdown body 解析。缺 {@code ---} 边界或缺 {@code name} 字段时跳过并写日志；
     * 同 ID 冲突解决：SkillSource#USER 覆盖 SkillSource#BUILTIN；
     * 同来源重复时只保留首次扫描到的。
     */
    private void parseInto(String id, SkillSource source, IOSupplier input, Map<String, Skill> sink,
                          Map<String, SkillSource> sourceById) {
        String content;
        try (InputStream raw = input.open();
             BufferedReader reader = new BufferedReader(new InputStreamReader(raw, StandardCharsets.UTF_8))) {
            content = readAll(reader);
        } catch (IOException e) {
            logError("读取失败：" + id + "：" + e.getMessage());
            return;
        } catch (UncheckedIOException e) {
            // jar entry 的 InputStream 供给 lambda 只能抛未受检异常——这里接住，
            // 不让单个 entry 失败拖垮整次扫描。
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            logError("读取失败：" + id + "：" + cause.getMessage());
            return;
        }
        Skill skill = parseSkillMd(id, content, source);
        if (skill == null) {
            logError("无法解析 SKILL.md（缺 --- 边界或缺 name 字段）：" + id);
            return;
        }
        SkillSource existing = sourceById.get(id);
        if (existing == null) {
            sink.put(id, skill);
            sourceById.put(id, source);
            return;
        }
        if (existing == SkillSource.BUILTIN && source == SkillSource.USER) {
            // 用户版覆盖内置版——用户导入意图明确，"我用我自己的"。原内置版保留在 jar
            // 里下次仍会被扫描到，但只要当前会话中用户版存在就以用户版为准。
            logError("用户版技能覆盖内置同名项：" + id);
            sink.put(id, skill);
            sourceById.put(id, source);
            return;
        }
        logError("重复的技能 id，已保留先扫描到的实例：" + id);
    }

    /**
     * 把 BufferedReader 全部读成字符串。UTF-8 编码（InputStreamReader
     * 构造时已声明），无 BOM 处理——SKILL.md 不写 BOM。
     */
    private static String readAll(BufferedReader reader) throws IOException {
        StringBuilder sb = new StringBuilder();
        char[] buf = new char[4096];
        int n;
        while ((n = reader.read(buf)) > 0) {
            sb.append(buf, 0, n);
        }
        return sb.toString();
    }

    /**
     * 把 SKILL.md 文本拆成 frontmatter 字符串 + body 字符串，再做后续解析。
     *
     * <p>行尾容错：Windows 上写出的文件是 {@code \r\n}，剥离每个被切出行的尾随 {@code \r}
     * 再做 {@code line.equals("---")} 等字面比较——避免 CRLF 平台下的
     * "永远匹配不上 {@code ---}" 假阴性。</p>
     *
     * <p>块标量（{@code key: |}）的内容会"透传"到 frontmatter 字符串里——避免把块内的
     * 缩进行误识别为新字段或闭合 {@code ---}。具体做法：扫描到 {@code key: |} 行后，
     * 继续吞下所有缩进 ≥ 块缩进的行（含空行）追加到 frontmatter；遇到 {@code ---} 行时
     * 回退一格，把 {@code ---} 留给外层循环识别为 frontmatter 闭合。</p>
     */
    private static Skill parseSkillMd(String id, String content, SkillSource source) {
        if (!content.startsWith("---")) {
            return null;
        }
        int openEnd = content.indexOf('\n', 3);
        if (openEnd < 0) {
            return null;
        }
        StringBuilder front = new StringBuilder();
        int pos = openEnd + 1;
        boolean foundClose = false;
        while (pos < content.length()) {
            int lineEnd = content.indexOf('\n', pos);
            String line;
            if (lineEnd < 0) {
                line = content.substring(pos);
                pos = content.length();
            } else {
                line = content.substring(pos, lineEnd);
                pos = lineEnd + 1;
            }
            line = stripTrailingCarriageReturn(line);
            if (line.equals("---")) {
                foundClose = true;
                break;
            }
            front.append(line).append('\n');
            if (isBlockScalarStart(line)) {
                // 块标量：吞下缩进行直到遇到缩进 ≤ 0 或文件结尾。
                int blockIndent = -1;
                int scanPos = pos;
                while (scanPos < content.length()) {
                    int blEnd = content.indexOf('\n', scanPos);
                    String bl;
                    if (blEnd < 0) {
                        bl = content.substring(scanPos);
                    } else {
                        bl = content.substring(scanPos, blEnd);
                    }
                    bl = stripTrailingCarriageReturn(bl);
                    // 先判定是否结束块——避免块外行（如闭合 ---）被吞掉。
                    if (!bl.isEmpty()) {
                        int indent = countLeadingSpaces(bl);
                        if (blockIndent < 0) {
                            if (indent == 0) {
                                break;
                            }
                            blockIndent = indent;
                        } else if (indent < blockIndent) {
                            break;
                        }
                    }
                    // 提交本行：包含到 frontmatter，scanPos 推进。
                    front.append(bl).append('\n');
                    scanPos = blEnd < 0 ? content.length() : blEnd + 1;
                }
                pos = scanPos;
            }
        }
        if (!foundClose) {
            return null;
        }
        String body = content.substring(pos);
        // 规范：--- 后通常紧跟一个空行再开始 Markdown body；剥离该单一换行。
        if (!body.isEmpty() && body.charAt(0) == '\n') {
            body = body.substring(1);
        }
        // 对齐旧 key=value 续行格式的语义——旧版本不留尾部换行，新格式也不留，
        // 否则 PromptBuilder 拼到 system 段时会多一个空行。
        while (!body.isEmpty() && body.charAt(body.length() - 1) == '\n') {
            body = body.substring(0, body.length() - 1);
        }
        Map<String, String> fields = parseFrontmatter(front.toString());
        return assemble(id, body, fields, source);
    }

    /**
     * 去掉行尾的单个 {@code \r}——CRLF 容错。{@code \r\n} 文件的每一行（除最后一行外）
     * 切出来都会带一个 {@code \r}，字面比较 {@code "---"} 之前必须剥掉。
     */
    private static String stripTrailingCarriageReturn(String line) {
        if (!line.isEmpty() && line.charAt(line.length() - 1) == '\r') {
            return line.substring(0, line.length() - 1);
        }
        return line;
    }

    /**
     * 判断一行是否是 {@code key: |} / {@code key: >} 形式的块标量声明行。
     * 只识别最简单的形式——不处理 chomping 指示符（{@code |-} / {@code |+}）与显式缩进提示符。
     */
    private static boolean isBlockScalarStart(String line) {
        int colon = line.indexOf(':');
        if (colon <= 0) {
            return false;
        }
        String after = line.substring(colon + 1).trim();
        return after.equals("|") || after.equals(">");
    }

    /**
     * 把 frontmatter 字符串解析成 {@code key → value} 映射。键统一小写；值保留原文。
     *
     * <p>支持：块标量（{@code key: |} 或 {@code key: >}）、单引号标量
     * （{@code key: 'value'}）、双引号标量（{@code key: "value"}，不做转义解析）、
     * 裸标量（{@code key: value}）。其它 YAML 特性（嵌套、列表、tag）不支持——
     * 本项目的元数据需求被刻意收窄。</p>
     */
    private static Map<String, String> parseFrontmatter(String text) {
        Map<String, String> result = new LinkedHashMap<>();
        String[] lines = text.split("\n", -1);
        int i = 0;
        while (i < lines.length) {
            String line = lines[i];
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                i++;
                continue;
            }
            int colon = line.indexOf(':');
            if (colon < 0) {
                i++;
                continue;
            }
            String key = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
            String rest = line.substring(colon + 1).trim();
            if (rest.equals("|") || rest.equals(">")) {
                // 块标量：收集缩进行直到脱缩进。空行作为段落分隔保留（开头/结尾的空行剥掉）。
                StringBuilder body = new StringBuilder();
                int blockIndent = -1;
                boolean startedContent = false;
                i++;
                while (i < lines.length) {
                    String next = lines[i];
                    if (next.isEmpty()) {
                        if (startedContent) {
                            body.append('\n');
                        }
                        i++;
                        continue;
                    }
                    int indent = countLeadingSpaces(next);
                    if (blockIndent < 0) {
                        blockIndent = indent;
                        if (blockIndent == 0) {
                            break;
                        }
                    }
                    if (indent < blockIndent) {
                        break;
                    }
                    body.append(next, blockIndent, next.length()).append('\n');
                    startedContent = true;
                    i++;
                }
                while (!body.isEmpty() && body.charAt(body.length() - 1) == '\n') {
                    body.setLength(body.length() - 1);
                }
                result.put(key, body.toString());
            } else if (rest.length() >= 2 && rest.charAt(0) == '\''
                    && rest.charAt(rest.length() - 1) == '\'') {
                String inner = rest.substring(1, rest.length() - 1);
                result.put(key, inner.replace("''", "'"));
                i++;
            } else if (rest.length() >= 2 && rest.charAt(0) == '"'
                    && rest.charAt(rest.length() - 1) == '"') {
                result.put(key, rest.substring(1, rest.length() - 1));
                i++;
            } else {
                result.put(key, rest);
                i++;
            }
        }
        return result;
    }

    /** 把 frontmatter 字段 + body 拼成 Skill；缺 name 时返回 null 让上层记日志。 */
    private static Skill assemble(String id, String body, Map<String, String> fields,
                                  SkillSource source) {
        String name = fields.get("name");
        if (name == null || name.isBlank()) {
            return null;
        }
        int summaryCount = parsePositiveInt(fields.get("summarycount"));
        String userContext = fields.getOrDefault("usercontext", "");
        return new Skill(
                id,
                name,
                fields.get("icon"),
                fields.getOrDefault("description", ""),
                body,
                userContext,
                summaryCount,
                fields.get("findingtype"),
                source);
    }

    private static int countLeadingSpaces(String s) {
        int n = 0;
        while (n < s.length() && s.charAt(n) == ' ') {
            n++;
        }
        return n;
    }

    /** lambda 友好版的 java.io.InputStream 供给器；规避把 throws IOException 写进函数式接口。 */
    @FunctionalInterface
    private interface IOSupplier {
        InputStream open() throws IOException;
    }

    /**
     * 把一份 SKILL.md 字符串解析成 Skill，仅用于"导入前的内容校验"。
     *
     * <p>本方法暴露 #parseSkillMd 的核心解析能力——CustomSkillStore
     * 在把用户选中的文件落盘前先调一次，确保内容本身可解析（避免写入后下次扫描报
     * "无法解析 SKILL.md"）。返回的 Skill 仅用于判定合法性，不参与实际渲染。</p>
     *
     * <p>来源固定为 SkillSource#USER（导入路径默认就是用户技能）；
     * 测试或内置路径请直接调 #load()。</p>
     *
     * @param id      技能 id（仅参与解析，不读文件）。
     * @param content SKILL.md 文本。
     * @return 解析后的 Skill；缺 {@code ---} 边界或 {@code name} 字段时返回 null。
     */
    public static Skill parseForInstallCheck(String id, String content) {
        if (id == null || content == null) {
            return null;
        }
        return parseSkillMd(id, content, SkillSource.USER);
    }

    /**
     * 把字符串解析成正整数；解析失败或非正数返回 0（表示"未设置"，由调用方回退到默认值）。
     * 不抛错——技能文件里写错数字不应让整个文件加载失败。
     */
    private static int parsePositiveInt(String value) {
        if (value == null || value.isBlank()) {
            return 0;
        }
        try {
            int n = Integer.parseInt(value.trim());
            return Math.max(n, 0);
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}