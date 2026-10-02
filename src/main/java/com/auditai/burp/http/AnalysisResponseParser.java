package com.auditai.burp.http;

import com.auditai.burp.skills.Skill;
import com.google.gson.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * 模型原始响应的解析器：从 {@code choices[0].message.content} 返回的文本中抽出
 * 业务字段（active_skill_ids / analysis / risk / findings）。
 *
 * <p>把这段逻辑从 {@link TrafficAnalyzer} 拆出来有两点好处：</p>
 * <ul>
 *   <li>TrafficAnalyzer 专注编排（执行器 / 阶段切换 / 占位符替换），不再夹杂 JSON 解析；</li>
 *   <li>本类每个方法都是纯函数式的（输入 rawText + context，输出解析结果），
 *       单测覆盖极其便宜（见 TrafficAnalyzerFindingsTest / TrafficAnalyzerJsonTest）。</li>
 * </ul>
 *
 * <p>容错约定：所有方法都不抛业务异常（除调用方传 null），统一降级为
 * "无 findings / hasIssue=false" 或 "返回原文当 analysis"。这与原
 * {@code TrafficAnalyzer} 行为一致——任何解析失败都不能阻塞"模型给回答"的主流程。</p>
 */
public final class AnalysisResponseParser {

    private AnalysisResponseParser() {}

    /**
     * 结构化 finding 入库所需的最低可信度（{@code 0–100} 整数）。
     *
     * <p>取值依据：{@link Finding} 注释定义"80+ 高 / 60–80 中 / <60 偏可疑"，
     * 10 处于"偏可疑"档下沿；{@code confidence} 字段缺失或低于此值的 finding
     * 视为噪声、不进入问题列表。</p>
     */
    public static final int DEFAULT_MIN_CONFIDENCE = 10;

    /**
     * 阶段 1 协议字段 {@code analysis} 的兜底字段名（按优先级排列）。
     *
     * <p>某些推理模型（o1 / o3 / DeepSeek-R1 / Gemini Thinking 等）习惯用
     * {@code {"thoughts": "...", "response": "..."}} 这种"思考 + 回答"的结构。
     * 如果模型没用协议字段 {@code analysis}，而用了 {@code response} / {@code text} /
     * {@code content} / {@code output} 之一表达"最终回答"，解析器会按这个顺序兜底
     * 抽取，避免把这类有效输出误判为"模型未返回结论"导致阶段 2 重复调用却拿到同样拒答。</p>
     */
    private static final List<String> ANALYSIS_FALLBACK_KEYS =
            List.of("response", "text", "content", "output");

    /**
     * 阶段 1：把模型原始响应解析为阶段 1 协议字段（active_skill_ids + analysis）。
     * 解析失败返回 null，调用方应走"全量启用兜底"。
     *
     * <p><b>容错策略</b>：本方法对外语义不变，仍是"尽力解析；全部失败返 null"。
     * 但内部采用三级 fallback，避免小模型在 {@code analysis} 字段里写未转义英文双引号
     * 破坏 JSON 结构时被错判成"解析失败"，进而触发无意义的阶段 2 重放：</p>
     * <ol>
     *   <li><b>标准严格解析</b>：直接 {@link JsonParser#parseString}（最常见路径，
     *       OpenAI / DeepSeek / 强制 {@code response_format=json_object} 的厂商都走这条）；</li>
     *   <li><b>宽松预处理</b>：去 markdown 围栏（```json ... ```）+ 截取顶层
     *       {@code {...}} 范围（处理"模型在 JSON 前后夹杂说明文字"）；</li>
     *   <li><b>字符级字段 fallback</b>：当 JSON 整体无法被 gson 解析时（典型场景：
     *       {@code analysis} 字段值内含未转义英文双引号破坏了字符串边界），
     *       用字符级扫描定位 {@code "analysis"} 字段，并以"协议约定的下一个字段边界"
     *       （{@code ", "risk"} / {@code ", "findings"} / {@code "} / {@code "]"}）
     *       作为右边界直接提取字符串值——能容忍字段值内的任意裸引号。
     *       这种"基于协议边界的启发式"对遵守协议的模型 100% 准确，对破坏协议的模型
     *       仍能挽救绝大多数有效结论。</li>
     * </ol>
     */
    public static ParsedSelection tryParseSelection(String rawText) {
        if (rawText == null || rawText.isEmpty()) {
            return null;
        }
        // 路径 1：标准严格解析（最常见，命中即返回）
        ParsedSelection strict = tryParseSelectionStrict(rawText);
        if (strict != null) {
            return strict;
        }
        // 路径 2：宽松 + 字段级 fallback（处理"模型返回内容被破坏"的场景）
        return tryParseSelectionLenient(rawText);
    }

    /**
     * 阶段 1 解析"带失败原因"版：与 {@link #tryParseSelection} 解析结果一致，但失败时
     * 额外返回 {@link ParseAttempt#failureReason()}，供调用方打 ERROR 日志或走 fail-fast 路径。
     *
     * <p>设计动机：当三级 fallback 全部失败（即模型返回的文本根本不是 JSON 对象、且宽松
     * 字段提取也找不到 analysis 字段）时，仅靠"返回 null"对调用方而言很难判断是该走
     * "全量启用兜底 → 进 phase 2"还是"fail-fast 跳过 phase 2"——前者会让阶段 2 在已知
     * 模型会乱返的情况下又访问一次模型，浪费 token + 延迟 + 误导后续调试。
     * 本方法暴露失败原因，让 {@code TrafficAnalyzer} 能在 "全量启用兜底" 之外选择
     * "fail-fast 直接收尾" 的新策略。</p>
     */
    public static ParseAttempt tryParseSelectionWithReason(String rawText) {
        if (rawText == null || rawText.isEmpty()) {
            return ParseAttempt.failure("模型返回为空");
        }
        // 路径 1 + 2 + 3（与 tryParseSelection 内部一致）：命中即返回 success
        ParsedSelection strict = tryParseSelectionStrict(rawText);
        if (strict != null) {
            return ParseAttempt.success(strict);
        }
        ParsedSelection lenient = tryParseSelectionLenient(rawText);
        if (lenient != null) {
            return ParseAttempt.success(lenient);
        }
        // 全部失败：构造失败原因（包含原始响应的前若干字符供排错）
        return ParseAttempt.failure(describeFailure(rawText));
    }

    /**
     * 生成可读的失败原因：区分"输入为空 / 不是 JSON / JSON 严重损坏"等不同场景。
     * 输出包含原始响应的前 200 字符（截断）便于排错，但避免日志被巨长响应刷屏。
     */
    private static String describeFailure(String rawText) {
        String trimmed = rawText == null ? "" : rawText.trim();
        if (trimmed.isEmpty()) {
            return "模型返回为空";
        }
        String preview = trimmed.length() > 200 ? trimmed.substring(0, 200) + "..." : trimmed;
        if (!trimmed.startsWith("{")) {
            return "模型返回不是 JSON 对象（首字符：" + (trimmed.isEmpty() ? "空" : String.valueOf(trimmed.charAt(0)))
                    + "），原始响应前 200 字符：" + preview;
        }
        return "模型返回的 JSON 严重损坏（宽松 fallback 也无法提取任何字段），原始响应前 200 字符：" + preview;
    }

    /** 标准严格解析：直接调 gson。失败返回 null。 */
    private static ParsedSelection tryParseSelectionStrict(String rawText) {
        try {
            JsonElement root = JsonParser.parseString(rawText);
            if (root == null || !root.isJsonObject()) {
                return null;
            }
            JsonObject obj = root.getAsJsonObject();
            return extractSelectionFromObject(obj);
        } catch (JsonParseException e) {
            return null;
        }
    }

    /** 从合法 JSON 对象里抽 active_skill_ids + analysis 字段。 */
    private static ParsedSelection extractSelectionFromObject(JsonObject obj) {
        List<String> ids = new ArrayList<>();
        JsonElement idsElem = obj.get("active_skill_ids");
        if (idsElem != null && idsElem.isJsonArray()) {
            for (JsonElement e : idsElem.getAsJsonArray()) {
                if (e != null && e.isJsonPrimitive() && e.getAsJsonPrimitive().isString()) {
                    ids.add(e.getAsString());
                }
            }
        }
        String analysis = readAnalysisField(obj);
        return new ParsedSelection(ids, analysis == null ? "" : analysis);
    }

    /**
     * 宽松解析：去 markdown 围栏 + 截取顶层 {@code {...}} 范围 + 字符级字段 fallback。
     *
     * <p>分两步走：</p>
     * <ol>
     *   <li>先尝试截取 {@code {...}} 范围再严格解析（处理"夹杂前后说明文字 + 围栏"场景，
     *       比如本地小模型常输出 {@code 下面是分析：\n{...}\n分析完毕}）；</li>
     *   <li>仍失败则用 {@link #extractAnalysisFieldLenient} 直接抓 {@code analysis}
     *       字段值（处理"分析字段值含内部裸引号"破坏 JSON 结构的场景），
     *       抓得到就当 {@code active_skill_ids=[] + analysis=提取值} 返回——这正好
     *       命中 {@link #resolveSelection} 的 "skipPhase2" 决策，agent 直接收尾。</li>
     * </ol>
     */
    private static ParsedSelection tryParseSelectionLenient(String rawText) {
        String trimmed = stripMarkdownFence(rawText.trim());
        int firstBrace = trimmed.indexOf('{');
        int lastBrace = trimmed.lastIndexOf('}');
        if (firstBrace < 0 || lastBrace <= firstBrace) {
            return null;
        }
        String candidate = trimmed.substring(firstBrace, lastBrace + 1);
        ParsedSelection repaired = tryParseSelectionStrict(candidate);
        if (repaired != null) {
            return repaired;
        }
        // 仍失败：字段级 fallback
        String analysis = extractAnalysisFieldLenient(candidate);
        if (analysis != null) {
            return new ParsedSelection(List.of(), analysis);
        }
        return null;
    }

    /**
     * 字符级从破损 JSON 里提取 {@code analysis} 字段值。
     *
     * <p>关键设计：放弃"逐字符严格 JSON 状态机"，改用"协议约定的字段边界"作为右边界——
     * 即在 {@code "analysis": "..."} 后扫描 {@code ", "risk"} / {@code ", "findings"} /
     * {@code "} / {@code "]"} 之一，避开字段值内部所有引号（包括未转义的）。这样即便
     * 小模型在分析里写 {@code 他说"你好"后走了}，仍能完整提取。</p>
     *
     * <p>corner case：模型在 analysis 里"自己写" {@code ", "risk" / "} 之类的内容时
     * 会截断——但合规模型的 analysis 不会含这些字面量（建议通过提示词约束 analysis
     * 字段内不使用英文双引号来进一步降低概率，详见 skill-selection-format_zh.txt /
     * output-format_zh.txt 的字段说明）。</p>
     */
    private static String extractAnalysisFieldLenient(String s) {
        String key = "\"analysis\"";
        int keyIdx = s.indexOf(key);
        if (keyIdx < 0) {
            return null;
        }
        int colon = findCharAfterWhitespace(s, keyIdx + key.length(), ':');
        if (colon < 0) {
            return null;
        }
        int openQuote = findCharAfterWhitespace(s, colon + 1, '"');
        if (openQuote < 0) {
            return null;
        }
        int valueStart = openQuote + 1;
        int end = findProtocolBoundary(s, valueStart);
        if (end < 0) {
            return null;
        }
        return unescapeJsonString(s.substring(valueStart, end));
    }

    /** 从 {@code from} 起跳过空白字符，找目标字符；找不到返回 -1。 */
    private static int findCharAfterWhitespace(String s, int from, char target) {
        int i = from;
        int n = s.length();
        while (i < n) {
            char c = s.charAt(i);
            if (c == target) {
                return i;
            }
            if (!Character.isWhitespace(c)) {
                return -1;
            }
            i++;
        }
        return -1;
    }

    /**
     * 找 {@code analysis} 字段的协议边界（右边界）。
     *
     * <p>按协议，{@code analysis} 字段值后必是以下之一：</p>
     * <ul>
     *   <li>{@code ", "risk"} —— 后面紧跟 risk 字段；</li>
     *   <li>{@code ", "findings"} —— 后面紧跟 findings 字段（仅当没有 risk 时）；</li>
     *   <li>{@code "} —— analysis 是对象最后一个字段；</li>
     *   <li>{@code "]} —— analysis 是 findings 数组里某个对象的字段。</li>
     * </ul>
     * 取以上最早出现的非转义位置作为右边界。{@link #indexOfUnescaped} 保证
     * {@code \"} 不被误判为边界。
     */
    private static int findProtocolBoundary(String s, int from) {
        int best = -1;
        for (String t : new String[]{"\", \"risk\"", "\", \"findings\"", "\"}", "\"]"}) {
            int idx = indexOfUnescaped(s, t, from);
            if (idx >= 0 && (best < 0 || idx < best)) {
                best = idx;
            }
        }
        return best;
    }

    /**
     * {@link String#indexOf(String, int)} 的"非转义"版：跳过前面有奇数个
     * {@code \} 的命中位置，避免把 {@code \"} 误判为字符串边界。
     */
    private static int indexOfUnescaped(String s, String t, int from) {
        int idx = s.indexOf(t, from);
        while (idx >= 0) {
            int backslashes = 0;
            for (int k = idx - 1; k >= 0 && s.charAt(k) == '\\'; k--) {
                backslashes++;
            }
            if (backslashes % 2 == 0) {
                return idx;
            }
            idx = s.indexOf(t, idx + 1);
        }
        return -1;
    }

    /** 简单 JSON 字符串反转义：覆盖 {@code " \\ / \n \r \t \b \f} 及 {@code \}{@code uXXXX}（4 位 hex）；其他 {@code \X} 原样保留。 */
    private static String unescapeJsonString(String s) {
        if (s == null) {
            return null;
        }
        if (s.indexOf('\\') < 0) {
            return s;
        }
        StringBuilder out = new StringBuilder(s.length());
        int i = 0;
        int n = s.length();
        while (i < n) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < n) {
                char next = s.charAt(i + 1);
                switch (next) {
                    case '"': out.append('"'); i += 2; break;
                    case '\\': out.append('\\'); i += 2; break;
                    case '/': out.append('/'); i += 2; break;
                    case 'n': out.append('\n'); i += 2; break;
                    case 'r': out.append('\r'); i += 2; break;
                    case 't': out.append('\t'); i += 2; break;
                    case 'b': out.append('\b'); i += 2; break;
                    case 'f': out.append('\f'); i += 2; break;
                    case 'u':
                        if (i + 5 < n) {
                            try {
                                out.append((char) Integer.parseInt(s.substring(i + 2, i + 6), 16));
                                i += 6;
                            } catch (NumberFormatException ex) {
                                out.append(c);
                                i++;
                            }
                        } else {
                            out.append(c);
                            i++;
                        }
                        break;
                    default:
                        out.append(c);
                        i++;
                        break;
                }
            } else {
                out.append(c);
                i++;
            }
        }
        return out.toString();
    }

    /** 去掉 markdown 围栏 {@code ```json ... ```}；不是围栏格式则原样返回。 */
    private static String stripMarkdownFence(String s) {
        if (!s.startsWith("```")) {
            return s;
        }
        int firstNewline = s.indexOf('\n');
        if (firstNewline > 0) {
            s = s.substring(firstNewline + 1);
        }
        if (s.endsWith("```")) {
            s = s.substring(0, s.length() - 3);
        }
        return s.trim();
    }

    /**
     * 从 JSON 对象里按"analysis → response → text → content → output"的优先级
     * 取一个非空字符串字段。返回 null 表示没有任何字段可用。
     */
    private static String readAnalysisField(JsonObject obj) {
        if (obj == null) {
            return null;
        }
        JsonElement primary = obj.get("analysis");
        String value = readNonBlankString(primary);
        if (value != null) {
            return value;
        }
        for (String key : ANALYSIS_FALLBACK_KEYS) {
            String candidate = readNonBlankString(obj.get(key));
            if (candidate != null) {
                return candidate;
            }
        }
        return null;
    }

    /** 读 JSON 元素的非空字符串值（兼容"字符串是空白时也视为无值"）。非字符串 / null 返回 null。 */
    private static String readNonBlankString(JsonElement elem) {
        if (elem == null || elem.isJsonNull() || !elem.isJsonPrimitive()) {
            return null;
        }
        String value = elem.getAsString();
        if (value == null || value.isBlank()) {
            return null;
        }
        return value;
    }

    /**
     * 阶段 1 解析后的调度决策：把"模型选了什么"转成"下一步要做什么"。
     *
     * <p>决策表（核心原则：除"JSON 真的解析不出来"以外，<b>任何</b>情形都不应扩张到
     * 全量启用兜底——模型明确表达的"不要技能"必须被尊重）：</p>
     * <ul>
     *   <li>{@code parsed == null}（JSON 完全无法解析）→ 全量启用 enabledSkills 兜底，
     *       需走阶段 2。<b>这是唯一允许"全量扩张"的情形</b>；</li>
     *   <li>active_skill_ids 非空 + 命中至少一个合法 id → 用合法 id 子集，需走阶段 2；</li>
     *   <li>active_skill_ids 非空 + 全部非法 id（模型幻觉 / 拼写错 / 版本不匹配）→
     *       <b>不</b>降级到全量兜底——模型明确说了"我要用 X"，X 不存在就老老实实告诉它不存在，
     *       而不是偷偷把所有技能都塞给它让 prompt 爆炸；
     *       跳阶段 2 直接用模型给出的 analysis 收尾（若有），没有就当解析失败走 fail-fast；</li>
     *   <li>active_skill_ids 空 + analysis 非空 → 模型主动给结论，不走阶段 2；</li>
     *   <li>active_skill_ids 空 + analysis 空 → 模型主动"啥都没说"，尊重这个意图——
     *       <b>不</b>扩张到全量启用，跳阶段 2 返回空 analysis，让上层按"模型没结论"兜底。
     *       这条与"全部非法 id"同源——两类情况都对应"模型明确表达了'不要技能'"的语义，
     *       偷偷扩张只会让单次分析吃满上下文。</li>
     * </ul>
     *
     * <p>原则细节：模型返回 {@code active_skill_ids=[]} 有两种可能——</p>
     * <ol>
     *   <li>模型认为不需要技能辅助（合理收尾路径），用其 analysis 直接结；</li>
     *   <li>模型返回结构合法但啥都没说（bug 或被截断的输出）。</li>
     * </ol>
     *
     * <p>两种都属于"模型没要技能"的语义，<b>都不应该</b>被偷偷扩张到全量启用——后者只会让
     * 一个本就空白的 phase 2 调用白白吃掉几万个 token 的 system 段（所有启用技能 prompt 拼接）。
     * 当前阶段 1 解析失败的兜底走 {@link TrafficAnalyzer} 自身的 fail-fast 路径（详见其
     * {@code analyze} 方法），所以本方法只有在被直接调用时（测试 / 未来重构）才走
     * "JSON 解析失败 → 全量兜底"分支。</p>
     *
     * <p>被拒绝的非法 id 通过 {@link SelectionResult#unknownIds()} 透传给上层记一条
     * info 日志——方便排查"模型为啥挑了不存在的技能"。</p>
     */
    public static SelectionResult resolveSelection(ParsedSelection parsed, List<Skill> enabledSkills) {
        if (parsed == null) {
            // JSON 完全解析不出来——唯一允许"全量扩张"的兜底路径。生产路径上
            // TrafficAnalyzer 已在此之前走 fail-fast，所以这里只是防御性兜底；
            // 仍走"用全部启用技能"是因为此时我们真的不知道模型想干嘛，只能
            // 保守地把可用技能都摆出来，让阶段 2 自己再向模型要一次结论。
            return SelectionResult.needPhase2(enabledSkills, "");
        }
        // 过滤：只保留 enabled 列表里实际存在的 id
        Set<String> enabledIds = new java.util.HashSet<>();
        for (Skill s : enabledSkills) {
            enabledIds.add(s.id());
        }
        List<Skill> selected = new ArrayList<>();
        List<String> unknownIds = new ArrayList<>();
        for (String id : parsed.activeIds) {
            if (id == null) {
                continue;
            }
            if (!enabledIds.contains(id)) {
                unknownIds.add(id);
                continue;
            }
            for (Skill s : enabledSkills) {
                if (s.id().equals(id)) {
                    selected.add(s);
                    break;
                }
            }
        }
        // 情形 A：模型挑了至少一个合法 id —— 按模型意图走阶段 2。
        if (!selected.isEmpty()) {
            return SelectionResult.needPhase2(selected, parsed.analysis == null ? "" : parsed.analysis,
                    unknownIds);
        }
        // 情形 B：模型挑了 ids 但全部非法 —— 不降级到全量兜底。
        // 模型有明确"选择意图"，只是 id 写错了；它"想要"的能力不存在，那就当 phase 2 没活儿可干。
        boolean modelAttemptedPick = !unknownIds.isEmpty();
        if (modelAttemptedPick) {
            return SelectionResult.skipPhase2(
                    parsed.analysis == null ? "" : parsed.analysis,
                    unknownIds);
        }
        // 情形 C：模型压根没挑任何 skill（active_skill_ids=[] 或字段缺失）——
        // 不管 analysis 是否为空，<b>都不</b>扩张到全量启用。
        if (parsed.analysis != null && !parsed.analysis.isEmpty()) {
            // 模型主动给结论 —— 用之收尾。
            return SelectionResult.skipPhase2(parsed.analysis);
        }
        // active_skill_ids=[] + analysis="" 是"模型主动啥都没说"，尊重这个意图，
        // 跳 phase 2 返回空结论，让上层按"模型没结论"兜底。绝不偷偷塞全部启用技能。
        return SelectionResult.skipPhase2("");
    }

    /**
     * 从模型原始响应中提取 {@code analysis} 字段；失败时回退原文。
     *
     * <p>兼容推理模型常用的非协议字段：详见 {@link #ANALYSIS_FALLBACK_KEYS}。
     * 也就是说，当模型用 {@code {"response": "..."}} 而不是 {@code {"analysis": "..."}}
     * 表达"最终回答"时，本方法也会把 {@code response} 的内容提取出来展示给用户。</p>
     */
    public static String extractAnalysis(String rawText) {
        if (rawText == null || rawText.isEmpty()) {
            return "（模型未返回任何内容）";
        }
        try {
            JsonElement root = JsonParser.parseString(rawText);
            if (root != null && root.isJsonObject()) {
                String extracted = readAnalysisField(root.getAsJsonObject());
                if (extracted != null) {
                    return extracted;
                }
            }
        } catch (JsonParseException ignored) {
            // fall through to rawText
        }
        return rawText;
    }

    /**
     * 从模型原始响应中解析"问题元数据 + 结构化 findings"。{@code findings[]} 中
     * 每条 finding 的可信度低于 {@link #DEFAULT_MIN_CONFIDENCE} 时不入库——视为噪声。
     *
     * <p>每条 finding 的严重度优先取自身的 {@code severity} 字段（缺失时回退到
     * 整次分析的 {@code risk}），可信度 / 描述 / method / url 同理按字段回退。</p>
     *
     * @return 三块信息：hasIssue / riskLevel / findings 列表。失败时一律降级为
     *         {@code (false, INFO, [])}。
     */
    public static ExtractedFindings extractFindings(String rawText, String fallbackMethod, String fallbackUrl,
                                                    long capturedAtMillis, long analysisTimestamp) {
        return extractFindings(rawText, fallbackMethod, fallbackUrl,
                capturedAtMillis, analysisTimestamp, DEFAULT_MIN_CONFIDENCE);
    }

    /**
     * 带置信度阈值参数的解析入口。
     *
     * <p>{@code confidence} 字段缺失或低于 {@code minConfidence} 的 finding 直接
     * 跳过，不进入 {@link ExtractedFindings#findings()}。当所有 finding 都被过滤
     * 且整体 {@code risk} 仅为 INFO 时，{@link ExtractedFindings#hasIssue()} 同步
     * 置为 {@code false}。</p>
     *
     * @param minConfidence 入库最低可信度（0–100 整数）。生产链路默认走
     *                      {@link #DEFAULT_MIN_CONFIDENCE}，单测可用更小值排查边界。
     */
    public static ExtractedFindings extractFindings(String rawText, String fallbackMethod, String fallbackUrl,
                                                    long capturedAtMillis, long analysisTimestamp,
                                                    int minConfidence) {
        if (rawText == null || rawText.isEmpty()) {
            return new ExtractedFindings(false, Severity.INFO, List.of());
        }
        try {
            JsonElement root = JsonParser.parseString(rawText);
            if (root == null || !root.isJsonObject()) {
                return new ExtractedFindings(false, Severity.INFO, List.of());
            }
            JsonObject obj = root.getAsJsonObject();
            String riskText = readString(obj, "risk");
            // 风险等级字段是模型输出的英文 token,走 Locale.ROOT 比对更稳
                boolean hasIssue = riskText != null && !"none".equals(riskText.trim().toLowerCase(java.util.Locale.ROOT));
            Severity riskLevel = hasIssue ? Severity.parse(riskText) : Severity.INFO;
            List<Finding> findings = new ArrayList<>();
            JsonElement findingsElem = obj.get("findings");
            if (findingsElem != null && !findingsElem.isJsonNull() && findingsElem.isJsonArray()) {
                JsonArray arr = findingsElem.getAsJsonArray();
                for (JsonElement element : arr) {
                    if (element == null || !element.isJsonObject()) {
                        continue;
                    }
                    JsonObject f = element.getAsJsonObject();
                    Integer confidence = readInt(f, "confidence");
                    if (confidence == null || confidence < minConfidence) {
                        continue;
                    }
                    String type = readString(f, "type");
                    String description = readString(f, "description");
                    String method = readString(f, "method");
                    String url = readString(f, "url");
                    // 严重度：优先使用模型给的单条 finding severity 字段，
                    // 缺失/空白时回退到整次分析的 risk 等级（避免所有 finding 共用一个等级）。
                    String findingSeverity = readString(f, "severity");
                    String effectiveSeverity = (findingSeverity != null && !findingSeverity.isBlank())
                            ? findingSeverity : riskLevel.name();
                    try {
                        findings.add(Finding.create(
                                type,
                                confidence,
                                effectiveSeverity,
                                description,
                                method != null && !method.isBlank() ? method : fallbackMethod,
                                url != null && !url.isBlank() ? url : fallbackUrl,
                                capturedAtMillis,
                                analysisTimestamp));
                    } catch (RuntimeException ignored) {
                        // 单条字段异常时跳过
                    }
                }
            }
            // 所有 finding 都被过滤、且整体 risk 仅为 INFO 时，把 hasIssue 同步降为 false——
            // 这一档位的"问题"本身无直接危害，再造占位 finding 没有价值。
            boolean effectiveHasIssue = hasIssue;
            if (findings.isEmpty() && riskLevel == Severity.INFO) {
                effectiveHasIssue = false;
            }
            return new ExtractedFindings(effectiveHasIssue, riskLevel, findings);
        } catch (JsonParseException ignored) {
            return new ExtractedFindings(false, Severity.INFO, List.of());
        }
    }

    /**
     * 把 {@link ExtractedFindings} 按决策表转成最终入库的 finding 列表：
     * <ol>
     *   <li>findings 非空 → 直接用；</li>
     *   <li>findings 空 + hasIssue=false → 不入库；</li>
     *   <li>findings 空 + hasIssue=true + riskLevel 高于 INFO → 用整段 analysis
     *       截取前若干字作占位 finding；</li>
     *   <li>findings 空 + hasIssue=true + riskLevel == INFO → 不入库——
     *       INFO 是"仅可疑、并无直接危害"档位，给它单造占位行本身就是在制造噪声。</li>
     * </ol>
     */
    public static List<Finding> resolveFindings(ExtractedFindings extracted, String analysis,
                                                String fallbackMethod, String fallbackUrl,
                                                long capturedAtMillis, long analysisTimestamp) {
        if (!extracted.findings().isEmpty()) {
            return extracted.findings();
        }
        if (!extracted.hasIssue()) {
            return List.of();
        }
        // INFO 档位不造占位 finding——该档位的"问题"没有直接危害，造出来也只贡献噪声。
        if (extracted.riskLevel() == null || extracted.riskLevel() == Severity.INFO) {
            return List.of();
        }
        return List.of(Finding.placeholder(
                truncateForPlaceholder(analysis),
                extracted.riskLevel(),
                fallbackMethod,
                fallbackUrl,
                capturedAtMillis,
                analysisTimestamp));
    }

    /** 给占位 finding 用的 description：取 analysis 前若干字（去掉换行）；为空时给最小占位。 */
    public static String truncateForPlaceholder(String analysis) {
        if (analysis == null || analysis.isBlank()) {
            return "（模型未返回分析结论）";
        }
        String compact = analysis.replace('\n', ' ').trim();
        int maxLen = 200;
        if (compact.length() > maxLen) {
            return compact.substring(0, maxLen) + "…";
        }
        return compact;
    }

    // ===== JSON 字段读取工具 =====

    /** 读取 JSON 对象的字符串字段；类型不匹配或 null 时返回 null。 */
    public static String readString(JsonObject obj, String key) {
        JsonElement e = obj.get(key);
        if (e == null || e.isJsonNull() || !e.isJsonPrimitive()) {
            return null;
        }
        return e.getAsString();
    }

    /** 读取 JSON 对象的整数字段；类型不匹配或 null 时返回 null。 */
    public static Integer readInt(JsonObject obj, String key) {
        JsonElement e = obj.get(key);
        if (e == null || e.isJsonNull() || !e.isJsonPrimitive()) {
            return null;
        }
        com.google.gson.JsonPrimitive primitive = e.getAsJsonPrimitive();
        if (primitive.isNumber()) {
            return primitive.getAsInt();
        }
        if (primitive.isString()) {
            try {
                return Integer.parseInt(primitive.getAsString().trim());
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    // ===== 数据类 =====

    /** 阶段 1 解析出的模型选择结果。 */
    public record ParsedSelection(List<String> activeIds, String analysis) {}

    /**
     * 阶段 1 解析后的调度决策：是否需要阶段 2 + 选中的技能 + 阶段 1 的 analysis（兜底用）。
     *
     * <p>{@link #unknownIds()} 是模型尝试挑但不在 enabled 列表里的 id 集合——
     * 非空时说明模型有明确选择意图但拼写错或与版本不匹配，由调用方决定是否打 warn 日志。
     * 默认空（最常见的"模型主动收尾"或"模型成功挑出技能"两条路径都不会填它）。</p>
     */
    public record SelectionResult(List<Skill> activeSkills, String analysis, boolean tookPhase2,
                                  List<String> unknownIds) {
        /** 兼容构造：unknownIds 默认为空——历史调用点（解析失败 / 主动收尾）都不带它。 */
        public SelectionResult(List<Skill> activeSkills, String analysis, boolean tookPhase2) {
            this(activeSkills, analysis, tookPhase2, List.of());
        }
        public static SelectionResult needPhase2(List<Skill> skills, String phase1Analysis) {
            return new SelectionResult(skills, phase1Analysis, true);
        }
        public static SelectionResult needPhase2(List<Skill> skills, String phase1Analysis,
                                                 List<String> unknownIds) {
            return new SelectionResult(skills, phase1Analysis, true, unknownIds);
        }
        public static SelectionResult skipPhase2(String phase1Analysis) {
            return new SelectionResult(List.of(), phase1Analysis, false);
        }
        public static SelectionResult skipPhase2(String phase1Analysis, List<String> unknownIds) {
            return new SelectionResult(List.of(), phase1Analysis, false, unknownIds);
        }
    }

    /** 解析模型原始响应得到的"问题元数据 + 结构化 findings"。 */
    public record ExtractedFindings(boolean hasIssue, Severity riskLevel, List<Finding> findings) {}

    /**
     * 阶段 1 解析尝试的"带失败原因"结果：成功时 {@link #selection} 非空、{@link #failureReason} 为 null；
     * 失败时 {@link #selection} 为 null、{@link #failureReason} 为可读错误描述。
     *
     * <p>见 {@link #tryParseSelectionWithReason} 的方法注释——设计动机是让
     * {@code TrafficAnalyzer} 在阶段 1 完全失败时能拿到失败原因决定走 fail-fast 还是
     * 全量启用兜底，而不是只能"知道失败了但不知道为什么"。</p>
     */
    public record ParseAttempt(ParsedSelection selection, String failureReason) {
        public static ParseAttempt success(ParsedSelection selection) {
            return new ParseAttempt(Objects.requireNonNull(selection, "selection"), null);
        }
        public static ParseAttempt failure(String reason) {
            return new ParseAttempt(null, reason);
        }
        public boolean isSuccess() {
            return selection != null;
        }
    }
}
