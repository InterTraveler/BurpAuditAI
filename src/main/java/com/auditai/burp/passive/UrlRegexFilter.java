package com.auditai.burp.passive;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * URL 过滤正则：仅放行 URL（含 query）匹配该正则的请求，留空匹配全部。
 *
 * <p>线程安全：内部使用 {@link Pattern}，{@code Pattern.matcher} 是线程安全的；
 * 因此本类实例可被多线程共享调用 {@link #matches(String)}。</p>
 *
 * <p><b>伪正则语法（用户友好）：</b>不熟悉正则语法的用户可以在常规位置用 {@code *}
 * 表示"任意字符"——{@link #expandPseudoRegex(String)} 会把字符类 {@code [...]} 之外的
 * {@code *} 翻译成 {@code .*}。例如 {@code api.example*} 实际编译为
 * {@code api\.example.*}；{@code *api*} 编译为 {@code .*api.*}。</p>
 *
 * <p><b>非法正则兜底：</b>构造时如果正则不合法（例如未闭合的括号），
 * 实例会回退为"匹配全部"行为，并通过 {@code errorLogger} 写一条告警日志——
 * 这是有意为之：被动分析开启后用户多半想"先看看效果"，正则填错静默丢流量
 * 会让人误以为整个功能挂了；统一兜底 + 告警更直观。UI 层在输入时调用
 * {@link #validate(String)} 给出实时提示。</p>
 *
 * <p><b>灾难性回溯防御</b>：</p>
 * <ul>
 *   <li>匹配输入（URL）截断到 {@link #MAX_MATCH_INPUT_LENGTH} 字符——回溯复杂度随输入
 *       长度爆炸，截断输入能显著缩小最坏情况；</li>
 *   <li>单次匹配耗时超过 {@link #SLOW_MATCH_WARN_MS} 毫秒时输出一次告警（每个过滤器
 *       实例只告警一次，避免刷屏），提醒用户正则是病态模式。</li>
 * </ul>
 * 注意：Java 正则引擎没有超时机制，真正的灾难性回溯仍可能长时间占用<b>调用线程</b>
 * （被动分析工作线程）。调用方应确保匹配发生在非 Proxy 回调线程（本插件已把匹配
 * 移到 {@link PassiveAnalysisHandler} 的工作线程），避免卡住 Burp 代理转发。
 */
public final class UrlRegexFilter {

    /** 参与匹配的 URL 最大长度：超过则截断（过滤语义保持"子串匹配"，截断影响可忽略）。 */
    static final int MAX_MATCH_INPUT_LENGTH = 4_096;

    /** 单次匹配超过该毫秒数视为"疑似灾难性回溯"，输出告警（每实例一次）。 */
    static final long SLOW_MATCH_WARN_MS = 200L;

    /**
     * 编译后的正则；构造失败 / 留空时为 null，对应"匹配全部"。
     *
     * <p>非 final：构造器里"留空 / 非法正则"两条路径都需要把字段设为 null，
     * 改用 try-catch 互斥结构后 javac 不再允许对 final 字段"两次赋值"（即便实际互斥）；
     * 由于本类实例本身不可变（构造后字段不再被改），用普通字段即可，
     * {@link #matches} 只在构造完成后被调用，没有并发赋值问题。</p>
     */
    private Pattern pattern;

    /** 慢匹配告警只打一次（AtomicBoolean 保证并发下也只会有一个线程打出）。 */
    private final AtomicBoolean slowMatchWarned = new AtomicBoolean(false);

    /** 编译失败 / 慢匹配告警回调；可为 null（null 时静默）。 */
    private final Consumer<String> errorLogger;

    /**
     * @param regex       正则表达式；null / 空串 / 全空白 → 匹配全部。
     *                    支持伪正则语法（{@code *} → {@code .*}，字符类内无效）。
     * @param errorLogger 编译失败时的告警回调；可为 null（null 时静默回退）。
     */
    public UrlRegexFilter(String regex, Consumer<String> errorLogger) {
        this.errorLogger = errorLogger;
        if (regex == null || regex.isBlank()) {
            this.pattern = null;
            return;
        }
        String compiledRegex = expandPseudoRegex(regex);
        try {
            this.pattern = Pattern.compile(compiledRegex);
        } catch (PatternSyntaxException ex) {
            // 非法正则：兜底为匹配全部，并写告警。运行期不再抛异常（避免被动分析线程被反复中断）。
            logError("被动分析 URL 正则非法（" + ex.getDescription() + "），回退为匹配全部："
                    + ex.getPattern());
            this.pattern = null;
        }
    }

    /**
     * 测试 URL 是否通过过滤。pattern 为 null 时一律放行。
     *
     * @param url 完整 URL（含 query）；null/空串按不匹配处理。
     * @return true → 放行。
     */
    public boolean matches(String url) {
        if (pattern == null) {
            return true;
        }
        if (url == null || url.isEmpty()) {
            return false;
        }
        // 截断输入：限制灾难性回溯正则的最坏情况（截断只影响"锚定在末尾"的正则，过滤场景可接受）。
        String input = url.length() > MAX_MATCH_INPUT_LENGTH
                ? url.substring(0, MAX_MATCH_INPUT_LENGTH)
                : url;
        long start = System.nanoTime();
        boolean matched = pattern.matcher(input).find();
        long elapsedMs = (System.nanoTime() - start) / 1_000_000L;
        if (elapsedMs > SLOW_MATCH_WARN_MS && slowMatchWarned.compareAndSet(false, true)) {
            logError("URL 正则匹配耗时 " + elapsedMs + " ms（疑似灾难性回溯：'"
                    + pattern.pattern() + "'），输入已截断到前 " + MAX_MATCH_INPUT_LENGTH
                    + " 字符。建议简化正则，避免阻塞被动分析线程。");
        }
        return matched;
    }

    /**
     * 把"伪正则"翻译成标准正则：处于字符类 {@code [...]} 之外的孤立 {@code *}
     * 替换为 {@code .*}。状态机扫描 {@code [...]} 嵌套，字符类内的 {@code *}
     * 视为字面字符。
     *
     * <p>仅对 {@code *} 做翻译（glob 风格最简单的子集）：{@code ?}、{@code |}、
     * {@code ^} 之类 glob 元字符暂不支持——审查权衡"伪正则应当越简单越好"。
     * 进阶用户继续写标准正则即可，伪正则语法不会改写已存在的 {@code .*} 等结构。</p>
     *
     * <p>连续 {@code **} 也照常翻译成 {@code .*.*}——按 find() 语义展开后等价于
     * {@code .*}，不构成安全风险；保留原汁原味的输出便于 UI 显示"展开前 → 展开后"。</p>
     *
     * @param regex 用户原文（可能含伪正则语法）；null / 空串原样返回。
     * @return 翻译后的正则；无 {@code *} 或都在字符类内时 = 原串。
     */
    public static String expandPseudoRegex(String regex) {
        if (regex == null || regex.isEmpty()) {
            return regex;
        }
        StringBuilder out = new StringBuilder(regex.length() + 8);
        int depth = 0;
        boolean escaped = false;
        for (int i = 0; i < regex.length(); i++) {
            char c = regex.charAt(i);
            if (escaped) {
                out.append(c);
                escaped = false;
                continue;
            }
            if (c == '\\') {
                out.append(c);
                escaped = true;
                continue;
            }
            if (c == '[') {
                // 字符类开始（depth 进入 1），里面所有字符字面看待。
                depth++;
                out.append(c);
                continue;
            }
            if (c == ']' && depth > 0) {
                depth--;
                out.append(c);
                continue;
            }
            if (depth == 0 && c == '*') {
                // 已形成的 .* 不再翻译：上一个输出字符是 . 时，仅追加 *；
                // 其它情形（开头 / 紧跟字母 / 紧跟空格）才补 .* 前缀。
                if (out.length() > 0 && out.charAt(out.length() - 1) == '.') {
                    out.append('*');
                } else {
                    out.append(".*");
                }
                continue;
            }
            out.append(c);
        }
        return out.toString();
    }

    /**
     * 校验用户输入的正则（含伪正则翻译）。
     *
     * <p>用于 UI 实时反馈：在用户键入过程中告诉用户"是合法 / 非法 / 需要翻译"，
     * 避免运行时才被 {@link UrlRegexFilter} 兜底回 match-all——后者用户难以感知。</p>
     *
     * <p>空串 / 全空白 → {@link ValidationResult#empty()}；合法 → {@link ValidationResult#valid}；
     * 翻译后仍非法 → {@link ValidationResult#invalid(String)}，
     * 其中 message 取 {@link PatternSyntaxException#getDescription()}
     * （Java 风格，例如 {@code "Unclosed character class"}）。</p>
     *
     * @param regex 用户原文（未翻译）。null 按空串处理。
     */
    public static ValidationResult validate(String regex) {
        if (regex == null || regex.isBlank()) {
            return ValidationResult.EMPTY;
        }
        String translated = expandPseudoRegex(regex);
        try {
            Pattern.compile(translated);
        } catch (PatternSyntaxException ex) {
            String desc = ex.getDescription();
            return ValidationResult.invalid(translated,
                    "正则非法：" + (desc == null ? "未知错误" : desc));
        }
        boolean translatedDiffers = !translated.equals(regex);
        if (translatedDiffers) {
            return new ValidationResult(ValidationStatus.VALID_EXPANDED, "伪正则已展开", translated);
        }
        return ValidationResult.VALID;
    }

    /**
     * 正则校验的三种状态：空 / 合法 / 合法但含伪正则翻译 / 非法。
     */
    public enum ValidationStatus {
        /** 留空（匹配全部） */
        EMPTY,
        /** 合法正则，无任何翻译 */
        VALID,
        /** 合法正则，但输入含伪正则语法，已翻译成标准正则 */
        VALID_EXPANDED,
        /** 翻译后仍非法 */
        INVALID
    }

    /**
     * {@link #validate(String)} 的结构化结果：状态 + 用户文案 + 翻译后的真实正则。
     *
     * <p>{@link #translatedRegex} 在 {@link ValidationStatus#VALID_EXPANDED} 时
     * 与输入不同，UI 可用它做"展开前 → 展开后"提示；其它状态下与输入相同。</p>
     */
    public static final class ValidationResult {
        /** 留空状态实例（省一次小对象分配）。 */
        public static final ValidationResult EMPTY = new ValidationResult(ValidationStatus.EMPTY, "留空匹配全部", "");

        /** 合法状态实例（与输入相同的简单合法正则共用，省一次分配）。 */
        public static final ValidationResult VALID = new ValidationResult(ValidationStatus.VALID, "正则合法", "");

        private final ValidationStatus status;
        private final String message;
        private final String translatedRegex;

        private ValidationResult(ValidationStatus status, String message, String translatedRegex) {
            this.status = status;
            this.message = message;
            this.translatedRegex = translatedRegex == null ? "" : translatedRegex;
        }

        /** 非法结果（带翻译后的真实正则，便于上层排查：用户原文 vs 翻译后）。 */
        static ValidationResult invalid(String translatedRegex, String message) {
            return new ValidationResult(ValidationStatus.INVALID, message, translatedRegex);
        }

        public ValidationStatus status() {
            return status;
        }

        public String message() {
            return message;
        }

        public String translatedRegex() {
            return translatedRegex;
        }
    }

    private void logError(String message) {
        if (errorLogger != null) {
            errorLogger.accept(message);
        }
    }
}
