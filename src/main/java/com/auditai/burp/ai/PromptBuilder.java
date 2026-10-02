package com.auditai.burp.ai;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.auditai.burp.config.Settings;
import com.auditai.burp.skills.Skill;
import com.auditai.burp.util.TextUtil;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

/**
 * 提示词构造器：把 Burp 报文（请求 / 请求 + 响应）转换为适合大模型分析的文本，
 * 并负责系统提示词的三级取值：<b>用户自定义（设置界面）→ 资源文件 → 内置兜底</b>。
 *
 * <p>设计要点：</p>
 * <ul>
 *   <li>系统提示词优先取设置界面保存的自定义内容（{@link Settings#customPrompt()}），
 *       方便用户不重编译地反复调优分析指令；</li>
 *   <li>未自定义时，按当前界面语言从资源文件 {@code /prompts/analyze-traffic_zh.txt} /
 *       {@code /prompts/analyze-traffic_en.txt} 加载默认提示词；</li>
 *   <li>资源文件缺失时回退到对应语言的内置默认提示词，保证扩展始终可用；</li>
 *   <li><b>输出格式后缀同样按语言分文件</b>（{@code output-format_zh/en.txt}、
 *       {@code skill-selection-format_zh/en.txt}），保证"用中文回答/用英文回答"、
 *       段落结构与 JSON 示例在整个 system 段内自洽，不给模型下发互相矛盾的语言指令；</li>
 *   <li><b>技能 = 两层信息架构</b>（参考 Anthropic Skills / OpenAI Function Calling）：
 *       阶段 1 把"启用的技能"作为可选目录（id + 名称 + 用途）呈现给模型，
 *       模型主动选择要激活的 id；阶段 2 只把模型选中的技能 prompt / userContext
 *       拼到 system / user 段。模型可决定不使用任何技能（直接给 analysis），跳过阶段 2。</li>
 *   <li>用户提示词包含：请求行、请求头（敏感字段脱敏）、请求体（截断）、
 *       响应状态、响应头、响应体（截断）——控制在模型单次可处理的长度内；</li>
 *   <li>2026.7 中 {@code HttpRequest.body()} / {@code HttpResponse.body()} 返回
 *       {@code ByteArray}（字节容器），通过 {@code getBytes()} 取原始字节。</li>
 * </ul>
 */
public final class PromptBuilder {

    /** 默认 system prompt 资源文件路径（classpath 根目录下），按 I18n 语言分两份。 */
    private static final String PROMPT_RESOURCE_ZH = "/prompts/analyze-traffic_zh.txt";
    private static final String PROMPT_RESOURCE_EN = "/prompts/analyze-traffic_en.txt";

    /**
     * 单轮 / 阶段 2 输出格式后缀的 classpath 资源（见 {@code prompts/output-format_zh.txt}
     * 与 {@code prompts/output-format_en.txt}）。按语言各一份，避免中英指令打架。
     */
    private static final String OUTPUT_FORMAT_RESOURCE_ZH = "/prompts/output-format_zh.txt";
    private static final String OUTPUT_FORMAT_RESOURCE_EN = "/prompts/output-format_en.txt";

    /**
     * 阶段 1 技能选择输出格式后缀的 classpath 资源（见 {@code prompts/skill-selection-format_zh.txt}
     * 与 {@code prompts/skill-selection-format_en.txt}）。
     */
    private static final String SKILL_SELECTION_FORMAT_RESOURCE_ZH = "/prompts/skill-selection-format_zh.txt";
    private static final String SKILL_SELECTION_FORMAT_RESOURCE_EN = "/prompts/skill-selection-format_en.txt";

    /**
     * "重放"工具模式下的输出格式后缀资源（见 {@code prompts/replay-output-format_zh.txt}
     * 与 {@code prompts/replay-output-format_en.txt}）。在系统启用了"重放"技能时使用，
     * 把模型输出协议从"单轮给结论"升级为"多轮 tool_calls + 最终结论"。
     */
    private static final String REPLAY_OUTPUT_FORMAT_RESOURCE_ZH = "/prompts/replay-output-format_zh.txt";
    private static final String REPLAY_OUTPUT_FORMAT_RESOURCE_EN = "/prompts/replay-output-format_en.txt";

    /**
     * "可用工具"说明资源（见 {@code prompts/tool-usage_zh.txt} / {@code tool-usage_en.txt}）。
     *
     * <p>关键作用：告诉模型"何时使用重放工具"。这原本是 {@code replay/SKILL.md} 里的
     * {@code description} 字段；现在重放从 skill 提升为常驻能力后，必须由 phase 2
     * 的 system 段承担"何时用"的触发说明——否则模型会跳过重放、直接给结论。</p>
     */
    private static final String TOOL_USAGE_RESOURCE_ZH = "/prompts/tool-usage_zh.txt";
    private static final String TOOL_USAGE_RESOURCE_EN = "/prompts/tool-usage_en.txt";

    /**
     * 工具调用结果回填到 user 段时使用的前缀模板（中英），提示模型"以下是你刚发起
     * 的重放的响应"。占位符 {@code {id}} = 工具调用 id，{@code {ms}} = 耗时（毫秒）。
     * 见 {@link #buildReplayResultUserPrompt}。
     */
    private static final String REPLAY_RESULT_HEADER_TEMPLATE_ZH =
            "\n【重放结果（tool_call_id={id}，{ms}ms）】\n";
    private static final String REPLAY_RESULT_HEADER_TEMPLATE_EN =
            "\n[Replay result (tool_call_id={id}, {ms}ms)]\n";

    /**
     * 输出格式后缀的兜底文本：classpath 资源缺失 / 读取失败时使用，保证插件始终可用。
     * 中文兜底（对应 {@code *_zh.txt} 资源）。
     */
    private static final String DEFAULT_OUTPUT_FORMAT_SUFFIX_ZH =
            "\n\n【输出格式（强制 JSON）】\n1. 你且只能输出一个合法 JSON 对象。\n"
                    + "2. analysis（必出现，字符串）：最终分析结论，用中文，300 字内。\n"
                    + "3. risk（必出现，字符串）：none/info/low/medium/high/critical。\n"
                    + "4. findings（必出现，数组）：0 到 N 个对象，每个含 type/confidence/description。\n"
                    + "5. 你只能输出合法 JSON，不允许包含 JSON 之外的任何文字、Markdown 代码块、注释。";

    /**
     * 输出格式后缀的兜底文本：英文兜底（对应 {@code *_en.txt} 资源）。
     */
    private static final String DEFAULT_OUTPUT_FORMAT_SUFFIX_EN =
            "\n\n[Output format (strict JSON)]\n"
                    + "1. Output one and only one valid JSON object, with no text, Markdown code fences or comments outside it.\n"
                    + "2. analysis (mandatory, string): final analysis in English, within 300 words.\n"
                    + "3. risk (mandatory, string): none/info/low/medium/high/critical.\n"
                    + "4. findings (mandatory, array): 0 to N objects, each with type/confidence/description.\n"
                    + "5. Output valid JSON only; do not include anything outside the JSON.";

    /**
     * 单轮 / 阶段 2 输出格式后缀（中英成对）：{@code [0]=zh, [1]=en}，按
     * {@code isEnglish() ? 1 : 0} 索引。资源缺失时回退到 {@link #DEFAULT_OUTPUT_FORMAT_SUFFIX_ZH} / {@link #DEFAULT_OUTPUT_FORMAT_SUFFIX_EN}。
     */
    private static final String[] OUTPUT_FORMAT_SUFFIX = loadBothLanguages(
            OUTPUT_FORMAT_RESOURCE_ZH, OUTPUT_FORMAT_RESOURCE_EN,
            DEFAULT_OUTPUT_FORMAT_SUFFIX_ZH, DEFAULT_OUTPUT_FORMAT_SUFFIX_EN);

    /**
     * 阶段 1（技能选择）输出格式后缀的兜底文本：classpath 资源缺失 / 读取失败时使用。
     *
     * <p><b>为什么必须与单轮兜底分开</b>：阶段 1 的协议字段是 {@code active_skill_ids}，
     * 而 {@link #DEFAULT_OUTPUT_FORMAT_SUFFIX_ZH} 只讲 analysis/risk/findings。若共用，
     * 一旦 {@code skill-selection-format_*.txt} 没打进包，模型就不会输出技能选择字段，
     * 阶段 1 解析必然失败并退化为"全量启用兜底"——协议与实际下发的提示词脱节。</p>
     */
    private static final String DEFAULT_SKILL_SELECTION_SUFFIX_ZH =
            "\n\n【输出格式（强制 JSON）】\n1. 你且只能输出一个合法 JSON 对象，不允许包含 JSON 之外的任何文字、Markdown 代码块、注释。\n"
                    + "2. active_skill_ids（必出现，字符串数组）：需要技能做二次分析时写技能 id 列表；"
                    + "本轮直接给最终结论时写 []。\n"
                    + "3. analysis（必出现，字符串）：选了技能时写空串 \"\"；直接收尾时写最终结论（中文，300 字内）。\n"
                    + "4. risk（必出现，字符串）：none/info/low/medium/high/critical；选了技能写 \"none\"。\n"
                    + "5. findings（必出现，数组）：选了技能写 []；直接收尾时写 0 到 N 个对象（type/confidence/description）。";

    /** 阶段 1（技能选择）输出格式后缀的英文兜底文本。 */
    private static final String DEFAULT_SKILL_SELECTION_SUFFIX_EN =
            "\n\n[Output format (strict JSON)]\n"
                    + "1. Output one and only one valid JSON object, with no text, Markdown code fences or comments outside it.\n"
                    + "2. active_skill_ids (mandatory, array of strings): list the skill ids to use for a second-pass analysis, "
                    + "or [] to conclude in this turn.\n"
                    + "3. analysis (mandatory, string): empty string \"\" when skills are selected; the final analysis "
                    + "(English, within 300 words) when concluding now.\n"
                    + "4. risk (mandatory, string): none/info/low/medium/high/critical; \"none\" when skills are selected.\n"
                    + "5. findings (mandatory, array): [] when skills are selected; 0..N objects (type/confidence/description) otherwise.";

    /**
     * 阶段 1 技能选择输出格式后缀（中英成对）。资源缺失时回退到
     * {@link #DEFAULT_SKILL_SELECTION_SUFFIX_ZH} / {@link #DEFAULT_SKILL_SELECTION_SUFFIX_EN}
     * （<b>不能</b>复用单轮兜底：那个不含 {@code active_skill_ids} 协议字段）。
     */
    private static final String[] SKILL_SELECTION_OUTPUT_SUFFIX = loadBothLanguages(
            SKILL_SELECTION_FORMAT_RESOURCE_ZH, SKILL_SELECTION_FORMAT_RESOURCE_EN,
            DEFAULT_SKILL_SELECTION_SUFFIX_ZH, DEFAULT_SKILL_SELECTION_SUFFIX_EN);

    /**
     * "重放"模式下的输出格式后缀兜底文本：资源缺失时回退到一份"够用"的硬编码版本，
     * 保证插件始终能跑（不会因为打包漏掉资源而崩溃）。这个 fallback 实际上与
     * 资源文件内容是同质的——只是把同样的语义写到代码里。
     */
    private static final String DEFAULT_REPLAY_OUTPUT_FORMAT_SUFFIX_ZH =
            "\n\n【输出格式（强制 JSON，含\"重放\"工具调用）】\n"
                    + "1. 你且只能输出一个合法 JSON 对象，不允许包含 JSON 之外的任何文字、Markdown 代码块、注释。\n"
                    + "2. analysis（必出现，字符串）：当前对最终结论的中间草稿；中间轮可写进度，收尾时给最终结论。\n"
                    + "3. tool_calls（必出现，数组，0 到 3 个对象）：\n"
                    + "   - 想发起重放 → 写 1～3 个 {\"name\":\"replay_request\",\"arguments\":{\"reason\":\"…\","
                    + "\"replace_query_params\":{…},\"replace_form_params\":{…},"
                    + "\"replace_header_params\":{…},\"replace_json_params\":{…},"
                    + "\"replace_path_params\":{\"<段值>\":\"…\",…},"
                    + "\"replace_multipart_params\":{\"<partName>\":\"…\",…}}}\n"
                    + "     6 类参数按 HTTP 报文中的位置分开：replace_query_params → URL 上的 ?k=v；"
                    + "replace_form_params → form body；replace_header_params → 请求头；"
                    + "replace_json_params → JSON body 字段（支持点号路径如 user.id）；"
                    + "replace_path_params → URL 路径的某段（key = 段的当前字面值，不限于最后一段，仅 path-only 场景）；"
                    + "replace_multipart_params → multipart/form-data body 的 part（key = part 的 Content-Disposition.name，仅 form-data 请求）。\n"
                    + "     value 是新值明文（未编码），由 Burp 负责 URL 编码 / JSON 编码 / Content-Length 重算。\n"
                    + "     每类参数只在自己所属的位置查找（不再有跨位置优先级匹配）——写错位置会直接报错。\n"
                    + "   - 已收尾 → 写 []\n"
                    + "   - 详见\"重放\"技能 prompt 与 user 段【可替换参数】清单。\n"
                    + "4. risk（必出现，字符串）：none / info / low / medium / high / critical；中间轮写 \"none\"，收尾写真实等级。\n"
                    + "5. findings（必出现，数组）：中间轮写 []，收尾写 0～N 个对象（type / confidence / description）。\n"
                    + "6. 单次分析最多调用 3 次重放；服务端会自动追踪预算并拒绝超额调用。\n";

    private static final String DEFAULT_REPLAY_OUTPUT_FORMAT_SUFFIX_EN =
            "\n\n[Output format (strict JSON, with replay tool calls)]\n"
                    + "1. Output one and only one valid JSON object, with no text, Markdown code fences, or comments outside it.\n"
                    + "2. analysis (mandatory, string): intermediate draft; progress notes on intermediate turns, final conclusion on wrap-up.\n"
                    + "3. tool_calls (mandatory, array, 0..3 objects):\n"
                    + "   - To replay: 1..3 {\"name\":\"replay_request\",\"arguments\":{\"reason\":\"…\","
                    + "\"replace_query_params\":{…},\"replace_form_params\":{…},"
                    + "\"replace_header_params\":{…},\"replace_json_params\":{…},"
                    + "\"replace_path_params\":{\"<segValue>\":\"…\",…},"
                    + "\"replace_multipart_params\":{\"<partName>\":\"…\",…}}}\n"
                    + "     6 maps are split by position in the HTTP message: replace_query_params → ?k=v on the URL; "
                    + "replace_form_params → form body; replace_header_params → request headers; "
                    + "replace_json_params → JSON body fields (dot-path supported, e.g. user.id); "
                    + "replace_path_params → URL path segments (key = segment's current literal value; not just last one; path-only requests only); "
                    + "replace_multipart_params → multipart/form-data body parts (key = part's Content-Disposition.name; form-data requests only).\n"
                    + "     Values are raw strings (unencoded); Burp handles URL-encoding / JSON-encoding / Content-Length recomputation.\n"
                    + "     Each map is only looked up in its own position (no cross-position priority matching) — wrong position yields an error.\n"
                    + "   - To wrap up: []\n"
                    + "   - See the replay skill prompt and the [Addressable params] section in the user turn.\n"
                    + "4. risk (mandatory, string): none / info / low / medium / high / critical; \"none\" on intermediate turns, real level on wrap-up.\n"
                    + "5. findings (mandatory, array): [] on intermediate turns, 0..N on wrap-up.\n"
                    + "6. Hard cap of 3 replays per analysis; the server tracks the budget and rejects excess calls.\n";

    /** "重放"模式输出格式后缀（中英成对）。 */
    private static final String[] REPLAY_OUTPUT_FORMAT_SUFFIX = loadBothLanguages(
            REPLAY_OUTPUT_FORMAT_RESOURCE_ZH, REPLAY_OUTPUT_FORMAT_RESOURCE_EN,
            DEFAULT_REPLAY_OUTPUT_FORMAT_SUFFIX_ZH, DEFAULT_REPLAY_OUTPUT_FORMAT_SUFFIX_EN);

    /**
     * "可用工具"说明（中英成对）——告诉模型何时用重放等常驻能力。
     * 资源缺失时回退到一行内嵌提示文案（不另起 DEFAULT_ 常量，避免为两行字符串单开一组）。
     */
    private static final String[] TOOL_USAGE_GUIDE = loadBothLanguages(
            TOOL_USAGE_RESOURCE_ZH, TOOL_USAGE_RESOURCE_EN,
            "（tool-usage_zh.txt 资源缺失；重放工具仍可用，但模型可能不主动调用）",
            "（tool-usage_en.txt resource missing; replay tool still works, but the model may not invoke it proactively）");

    // ===== 技能目录 / 片段的中英指令文本（PromptBuilder 内部拼装用） =====
    private static final String SKILL_LIST_HEADER_ZH = "\n\n【可选技能】\n";
    private static final String SKILL_LIST_HEADER_EN = "\n\n[Optional skills]\n";
    private static final String SKILL_USAGE_ZH = "\n  用途: ";
    private static final String SKILL_USAGE_EN = "\n  purpose: ";
    private static final String SKILL_SELECTION_INSTRUCTION_ZH =
            """

                    请先判断本次分析需要哪些【可选技能】的辅助——把你希望激活的可选技能 id \
                    填到 active_skill_ids；如果你认为当前请求不需要任何【可选技能】\
                    （例如请求内容简单、通用分析足够），把 active_skill_ids 设为\
                    空数组并直接在 analysis 里给出最终结论。\
                    """;
    private static final String SKILL_SELECTION_INSTRUCTION_EN =
            """

                    Decide which of the [optional skills] (if any) should assist this analysis. Put the ids \
                    of the optional skills you want to activate into active_skill_ids. If this request does \
                    not need any optional skill (for example the request is simple and generic analysis is \
                    enough), set active_skill_ids to an empty array and give the final conclusion directly \
                    in analysis. \
                    """;

    /**
     * 当【必选技能】段非空时追加的指令尾巴——明确"必选 phase 2 无论如何注入，无需写到
     * active_skill_ids"。与基础指令的"空数组"路径自洽：模型让 active_skill_ids=[]
     * 时，必选技能仍生效（短路 B 兜底，prompt 里不暴露实现细节）。
     */
    private static final String SKILL_SELECTION_REQUIRED_TAIL_ZH =
            "（【必选技能】phase 2 一定会注入，无需写到 active_skill_ids。）";
    private static final String SKILL_SELECTION_REQUIRED_TAIL_EN =
            "([Required skills] will be injected in phase 2 regardless — do NOT include them in active_skill_ids.)";
    private static final String SKILL_SECTION_HEADER_ZH = "\n\n【技能：";
    private static final String SKILL_SECTION_HEADER_EN = "\n\n[Skill: ";
    private static final String SKILL_SECTION_HEADER_CLOSE_ZH = "】\n";
    private static final String SKILL_SECTION_HEADER_CLOSE_EN = "]\n";

    /**
     * 多技能并行元规则：当阶段 2 实际拼装 system 段时，若被激活的技能数 ≥ 2，
     * 追加到所有 skill 段之后，告知模型多 skill 并行时的 finding 归类约定。
     *
     * <p>设计动机：每个 skill 的 prompt 现在以"我负责 X 类型发现"的正面声明收尾，
     * 但只有元规则才能从根本上消解冲突——它要求模型显式带 type 字段、并由对应技能负责。
     * 单技能场景不会拼这段，避免对简单分析增加无意义噪声。</p>
     */
    private static final String MULTI_SKILL_RULE_ZH =
            """

                    【多技能并行约定】
                    上面同时激活了多个技能。每个技能只负责自己 findingType 范围内的发现\
                    （详见各技能 prompt 末尾的声明）。请遵守：
                    1. 每个 finding 必须显式带 type 字段，且 type 必须落在某个被激活技能\
                    声明的 findingType 内；
                    2. 不要在某个技能下输出其它技能负责的内容，也不要吞掉本该由某个技能\
                    输出的发现；
                    3. 未声明 findingType 的技能按"通用风险观察"处理，与声明了 findingType\
                    的技能互补。
                    """;
    private static final String MULTI_SKILL_RULE_EN =
            """

                    [Multi-skill concurrency rules]
                    Multiple skills are active above. Each skill is only responsible for findings \
                    within its declared findingType (see the end of each skill prompt). Follow these \
                    rules:
                    1. Every finding must carry an explicit type field, and the type must fall within \
                    the findingType of some active skill.
                    2. Do not output findings belonging to other skills under a different skill, and \
                    do not swallow findings that another skill should produce.
                    3. Skills without a declared findingType are treated as "general risk observer" \
                    and complement the typed skills.
                    """;

    /** 单个技能 section 内、prompt 文本之前的"本技能负责的 finding type"声明。 */
    private static final String FINDING_TYPE_DECL_ZH = "本技能负责产出的 finding type：";
    private static final String FINDING_TYPE_DECL_EN = "Finding types this skill is responsible for: ";

    /** 阶段 1 技能目录行：findingType 字段后缀（仅在声明了 findingType 时拼接）。 */
    private static final String SKILL_FINDING_TYPE_ZH = "\n  finding type: ";
    private static final String SKILL_FINDING_TYPE_EN = "\n  finding type: ";

    /**
     * 阶段 1 第二个目录的标题：必选技能列表。独立的标题（与【可选技能】分离），避免模型
     * 把"必选"误读为普通列表项。"phase 2 一定会注入 / 无需写到"的语义说明交给紧随其后的
     * "注"段承担——保持标题简短。
     */
    private static final String SKILL_REQUIRED_HEADER_ZH =
            "\n\n【必选技能】\n";
    private static final String SKILL_REQUIRED_HEADER_EN =
            "\n\n[Required skills]\n";

    /**
     * 阶段 1 指令段尾部的"必选"说明：仅当至少有一个 pinned 时拼接。
     * 强调"phase 2 无论如何都会注入"——这是必选与可选的核心区别。
     */
    private static final String SKILL_REQUIRED_NOTE_ZH =
            "\n\n注：【必选技能】是系统配置的常驻能力，phase 2 一定会注入；"
                    + "无需写到 active_skill_ids（即使不写也会生效）。";
    private static final String SKILL_REQUIRED_NOTE_EN =
            "\n\nNote: 'Required skills' are pre-configured resident capabilities; "
                    + "they will be injected in phase 2 regardless of active_skill_ids.";

    /** 当前是否按英文构造 prompt（随 UI 语言）。 */
    public boolean isEnglish() {
        return currentLang() == Lang.EN;
    }

    /** 按当前语言取单轮 / 阶段 2 输出格式后缀。 */
    private String outputFormatSuffix() {
        return OUTPUT_FORMAT_SUFFIX[isEnglish() ? 1 : 0];
    }

    /** 按当前语言取阶段 1 技能选择输出格式后缀。 */
    private String skillSelectionOutputSuffix() {
        return SKILL_SELECTION_OUTPUT_SUFFIX[isEnglish() ? 1 : 0];
    }

    /** 中文内置兜底系统提示词:资源文件加载失败时使用。 */
    private static final String DEFAULT_SYSTEM_PROMPT_ZH =
            """
                    你是一名资深的 Web 应用安全与渗透测试专家，正在配合 Burp Suite 插件对 HTTP 流量做快速分析。\
                    请针对用户提供的 HTTP 请求/响应报文给出简明、专业、可落地的分析结论，要求：
                    1. 使用中文回答，总篇幅控制在 300 字以内；
                    2. 按以下结构输出：
                       【风险点】……（没有明显风险时写『未发现明显风险』）
                       【疑似漏洞/安全问题】……（列出疑似类型、判断依据、严重程度）
                       【建议】……（可执行的修复或进一步测试建议）
                    3. 只依据报文内容分析，不臆测报文之外的信息；不确定之处要明确说明。""";

    /** 英文内置兜底系统提示词:资源文件加载失败时使用。 */
    private static final String DEFAULT_SYSTEM_PROMPT_EN =
            """
                    You are a senior web application security and penetration testing expert, working \
                    with a Burp Suite extension to perform rapid analysis of HTTP traffic. Analyze the \
                    user-provided HTTP request/response pair and produce a concise, professional, and \
                    actionable report:
                    1. Reply in English, total length within 300 words;
                    2. Strictly follow this structure:
                       [Risk points] ... (write "No obvious risk" when there are no clear issues)
                       [Suspected vulnerability / security issue] ... (list suspected type, evidence, severity)
                       [Recommendation] ... (actionable fix or further testing suggestions)
                    3. Base your analysis strictly on the provided message contents; do not speculate beyond them; \
                    explicitly mark anything you are not certain about.""";

    /**
     * 从 classpath 加载一段纯文本资源（UTF-8），读取失败 / 资源缺失返回 null。
     * 统一入口：后缀常量与"恢复默认"共用，避免两套重复实现。
     */
    private static String loadResource(String resourcePath) {
        try (InputStream in = PromptBuilder.class.getResourceAsStream(resourcePath)) {
            if (in == null) {
                return null;
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            return null;
        }
    }

    /** 加载资源并回退：资源缺失 / 读取失败时返回 {@code fallback}，保证插件始终可用。 */
    private static String loadOrDefault(String resourcePath, String fallback) {
        String loaded = loadResource(resourcePath);
        return loaded != null ? loaded : fallback;
    }

    /**
     * 同时加载中英两份资源（资源缺失时各自回退到对应语言的 fallback），用于压缩
     * "中英成对加载"的样板，保留 {@link #loadOrDefault} 作底层。
     *
     * <p>必须在 class 初始化阶段调用（不依赖实例），故要求 fallback 都是字面量或
     * 已被前面的 static 字段加载的字符串。返回 {@code String[2]{zh, en}}，
     * 调用方按当前语言取 {@code arr[isEnglish() ? 1 : 0]}。</p>
     */
    private static String[] loadBothLanguages(String zhRes, String enRes,
                                              String fallbackZh, String fallbackEn) {
        return new String[]{
                loadOrDefault(zhRes, fallbackZh),
                loadOrDefault(enRes, fallbackEn)
        };
    }

    /**
     * 语言枚举：定义在这里（ai 包），让 {@code PromptBuilder} 不反向依赖 UI 层的
     * {@code I18n}。UI 层注入 {@code () -> I18n.get().current()} 时把
     * {@code I18n.Lang} 转成本枚举即可（{@code ui.I18n} 自己持有本枚举作为唯一规范源）。
     */
    public enum Lang { ZH, EN }

    /**
     * 自定义系统提示词提供方：每次构造系统提示词时实时读取，
     * 保证用户改完提示词后下一次分析立即生效；用 {@link Supplier}
     * 而不是直接传 {@code String}，是为了在多配置切换 / 提示词编辑场景下
     * 始终读到最新值（{@code Settings} 对象本身不可见）。
     */
    private final Supplier<String> customPromptSupplier;

    /**
     * 当前界面语言提供方：调用时实时取，保证用户在"设置"页切语言后下一次分析
     * 立即按新语言构造 prompt。{@code null} 时取枚举默认值 {@link Lang#ZH}（仅供
     * 单测 / 不关心语言切换的内部用法）。
     */
    private final Supplier<Lang> languageSupplier;

    /**
     * 完整构造器。
     *
     * @param customPromptSupplier 自定义系统提示词提供方；返回 {@code null} 或空白
     *                             字符串时回退到内置默认。
     * @param languageSupplier     当前界面语言提供方；{@code null} 时默认取 {@link Lang#ZH}。
     */
    public PromptBuilder(Supplier<String> customPromptSupplier, Supplier<Lang> languageSupplier) {
        this.customPromptSupplier = customPromptSupplier;
        this.languageSupplier = languageSupplier != null ? languageSupplier : () -> Lang.ZH;
    }

    /**
     * 单参便捷构造器：固定中文（{@link Lang#ZH}）。不关心语言切换的旧用法
     * （含单测）保留此入口。
     */
    public PromptBuilder(Supplier<String> customPromptSupplier) {
        this(customPromptSupplier, null);
    }

    /** 实时读取当前语言。 */
    private Lang currentLang() {
        return languageSupplier.get();
    }

    /**
     * 构建"无技能"场景下的单次分析系统提示词：基础 + 单轮输出格式后缀。
     *
     * <p>用于 {@code TrafficAnalyzer} 的"没有任何技能启用"分支——单次调用直接给结论。</p>
     */
    public String buildSystemPrompt() {
        return buildBasePrompt() + "\n\n" + outputFormatSuffix();
    }

    /**
     * 构建"阶段 1：技能选择"的系统提示词：基础 + 候选技能目录（id / 名称 / 用途）+
     * 让模型选择激活哪些技能的指令 + 阶段 1 输出格式后缀。
     *
     * <p>这是"两层信息架构"的描述层——把"有哪些技能可用 + 每个技能做什么"以可读列表
     * 形式告诉模型，让模型根据当前报文判断激活哪些。注意这里<b>不包含任何技能的
     * prompt 片段</b>，技能的详细 prompt 留给阶段 2（"内容层"）。</p>
     *
     * @param candidates 当前启用的技能（即"可选"集），按入参顺序展示
     */
    public String buildSystemPromptForSkillSelection(List<Skill> candidates) {
        return buildSystemPromptForSkillSelection(candidates, List.of());
    }

    /**
     * 构建"阶段 1：技能选择"的系统提示词的完整版：分两段输出——【可选技能】+【必选技能】。
     *
     * <p>把"普通启用"与"pinned"分到两个独立标题下，避免行尾标签混淆（之前的"（必选）"
     * 后缀被模型误判为普通列表内容，导致必选被漏选）。两个目录各带独立标题 + 选择/必选说明，
     * 让模型无法把必选技能当成"可挑可不挑"。</p>
     *
     * <p>为什么不把 pinned 的 prompt 内容也直接拼到 phase 1 system 段：phase 1 是"选 skill"
     * 轮次没有 tool_calls 协议，pinned 的"何时调工具"指令在这一阶段无法执行——让模型"看到"
     * 完整必选列表（标题 + id/name/用途）即可，prompt 内容留到 phase 2 才生效。</p>
     *
     * <p>拼装结构（自上而下）：</p>
     * <ol>
     *   <li>基础提示词（用户自定义 / 资源 / 兜底）；</li>
     *   <li><b>【可选技能】</b>目录：仅 candidates（普通启用，不含 pinned）——按入参顺序展示；</li>
     *   <li><b>【必选技能】</b>目录：仅 pinnedSkills——按入参顺序展示，独立的标题避免与
     *       可选目录混淆；</li>
     *   <li>选择指令（仅当【可选技能】非空时拼——告诉模型"如何挑"）；</li>
     *   <li>必选说明（仅当【必选技能】非空时拼——强调必选语义"phase 2 一定会注入"）；</li>
     *   <li>输出格式后缀（{@code active_skill_ids} 协议字段）。</li>
     * </ol>
     *
     * @param candidates    普通启用技能集（不含 pinned），按入参顺序展示。
     * @param pinnedSkills  自动激活技能集——独立成段，phase 2 强制注入。
     */
    public String buildSystemPromptForSkillSelection(List<Skill> candidates, List<Skill> pinnedSkills) {
        boolean en = isEnglish();
        StringBuilder sb = new StringBuilder(buildBasePrompt());

        // candidates 已经过滤掉 pinned（TrafficAnalyzer 在外层做了）——这里不再去重，
        // 但仍做防御性过滤：以防调用方把 pinned 也传进 candidates。
        Set<String> pinnedIdSet = new HashSet<>();
        if (pinnedSkills != null) {
            for (Skill p : pinnedSkills) {
                pinnedIdSet.add(p.id());
            }
        }
        List<Skill> regularCandidates = new ArrayList<>();
        if (candidates != null) {
            for (Skill c : candidates) {
                if (!pinnedIdSet.contains(c.id())) {
                    regularCandidates.add(c);
                }
            }
        }

        boolean hasRegular = !regularCandidates.isEmpty();
        boolean hasPinned = !pinnedIdSet.isEmpty();

        // —— 段 1：【可选技能】（仅普通启用）——
        if (hasRegular) {
            sb.append(en ? SKILL_LIST_HEADER_EN : SKILL_LIST_HEADER_ZH);
            for (Skill skill : regularCandidates) {
                appendSkillLine(sb, skill, en);
            }
        }

        // —— 段 2：【必选技能】（仅 pinned）——
        if (hasPinned) {
            sb.append(en ? SKILL_REQUIRED_HEADER_EN : SKILL_REQUIRED_HEADER_ZH);
            for (Skill skill : pinnedSkills) {
                appendSkillLine(sb, skill, en);
            }
        }

        // —— 选择 / 必选说明 ——
        if (hasRegular) {
            sb.append(en ? SKILL_SELECTION_INSTRUCTION_EN : SKILL_SELECTION_INSTRUCTION_ZH);
            // 当【必选技能】同时存在时，附加尾巴说明"必选 phase 2 仍生效"——与基础指令
            // 的"空数组 + 直接收尾"自洽（短路 B 兜底，模型无需写到 active_skill_ids）。
            if (hasPinned) {
                sb.append(en ? SKILL_SELECTION_REQUIRED_TAIL_EN : SKILL_SELECTION_REQUIRED_TAIL_ZH);
            }
        }
        if (hasPinned) {
            sb.append(en ? SKILL_REQUIRED_NOTE_EN : SKILL_REQUIRED_NOTE_ZH);
        }

        sb.append("\n\n").append(skillSelectionOutputSuffix());
        return sb.toString();
    }

    /**
     * 拼一个技能的目录块（YAML 风格缩进，每字段独占一行）：
     * <pre>
     * - id: sql-injection
     *   name: SQL 注入
     *   用途: 检测 SQL 注入痕迹
     *   finding type: sqli
     * </pre>
     * 字段用换行 + 缩进做分隔，避免逗号与字段值内部的顿号 / 逗号混淆；同时中英文版结构完全
     * 统一，消除了标点风格漂移。两段目录（【可选技能】+【必选技能】）共用同一格式——
     * 只靠标题区分必选 vs 可选。
     */
    private static void appendSkillLine(StringBuilder sb, Skill skill, boolean en) {
        String usage = skill.description().isEmpty() ? skill.name() : skill.description();
        sb.append("- id: ").append(skill.id())
          .append("\n  name: ").append(skill.name())
          .append(en ? SKILL_USAGE_EN : SKILL_USAGE_ZH).append(usage);
        if (skill.hasFindingType()) {
            sb.append(en ? SKILL_FINDING_TYPE_EN : SKILL_FINDING_TYPE_ZH)
              .append(skill.findingType());
        }
        sb.append('\n');
    }

    /**
     * 构建"阶段 2：最终分析"的系统提示词：基础 + 模型选中的技能 prompt 片段（按入参顺序）
     * + 单轮输出格式后缀。
     *
     * <p>这是"两层信息架构"的内容层——只把模型在阶段 1 选中的技能的具体 prompt 拼到
     * system 段；未选中的技能不进 prompt，节省 token。</p>
     *
     * <p>{@code prompt} 为空的技能会被跳过——一个技能只声明 {@code userContext} 而不写
     * {@code prompt} 时，不会影响 system 提示词（它的内容会通过 userContext 段注入）。</p>
     *
     * @param selectedSkills 模型在阶段 1 选中的技能列表；为空时等同于 {@link #buildSystemPrompt()}。
     */
    public String buildSystemPromptWithSelectedSkills(List<Skill> selectedSkills) {
        boolean en = isEnglish();
        StringBuilder sb = new StringBuilder(buildBasePrompt());
        // 统计被实际拼到 system 段的技能数（仅计有 prompt 的），决定是否追加多技能并行元规则。
        int activeWithPrompt = 0;
        if (selectedSkills != null) {
            for (Skill skill : selectedSkills) {
                if (skill.hasPrompt()) {
                    activeWithPrompt++;
                    sb.append(en ? SKILL_SECTION_HEADER_EN : SKILL_SECTION_HEADER_ZH)
                      .append(skill.name())
                      .append(en ? SKILL_SECTION_HEADER_CLOSE_EN : SKILL_SECTION_HEADER_CLOSE_ZH);
                    if (skill.hasFindingType()) {
                        // 紧贴 prompt 开头声明本技能负责的 finding type，让模型在读完 prompt 后立即看到归类边界。
                        sb.append(en ? FINDING_TYPE_DECL_EN : FINDING_TYPE_DECL_ZH)
                          .append(skill.findingType())
                          .append('\n');
                    }
                    sb.append(skill.prompt());
                }
            }
        }
        // 单技能场景不追加元规则，避免对简单分析加噪声；多技能才需要明确归类约定。
        if (activeWithPrompt >= 2) {
            sb.append(en ? MULTI_SKILL_RULE_EN : MULTI_SKILL_RULE_ZH);
        }
        sb.append("\n\n").append(outputFormatSuffix());
        return sb.toString();
    }

    /**
     * 构建"重放"模式的系统提示词：基础 + 启用的技能 prompt 片段 + "重放"模式输出格式后缀。
     *
     * <p>与 {@link #buildSystemPromptWithSelectedSkills} 的差别是：</p>
     * <ul>
     *   <li>输出格式后缀换成"含 {@code tool_calls}"的版本，让模型在多轮循环里能
     *       选择"再发一次"或"收尾给结论"；</li>
     *   <li>多技能并行元规则仍然生效——"重放"不是单技能独占场景，模型可能同时配合
     *       SQL 注入 / 鉴权绕过等其它技能做重放验证；</li>
     *   <li>"重放"技能的 prompt 里已经写明"重放请求"工具的调用协议，所以这里不再
     *       重复写一段，遵循"技能声明 = 单一信息源"的原则。</li>
     * </ul>
     *
     * @param selectedSkills 启用的技能列表（含"重放"技能时本方法才被调用）。
     * @param remainingBudget 剩余重放预算（0～3），用于在 system 段里向模型汇报"你还能调用 N 次"。
     *                        负数会被当作 0 处理；超过 3 会被夹到 3。
     */
    public String buildSystemPromptForReplay(List<Skill> selectedSkills, int remainingBudget) {
        boolean en = isEnglish();
        StringBuilder sb = new StringBuilder(buildBasePrompt());
        // 工具使用指南：放在技能 prompt 之前——让模型先建立"可调用工具"的全局认知，
        // 再读技能 prompt 时对其中"何时调用 replay"的指引有更明确的落脚点。
        // 缺席时模型会跳过重放直接给结论，故这一段必须出现。
        sb.append("\n\n").append(TOOL_USAGE_GUIDE[en ? 1 : 0]);
        // 剩余预算提示：纯数字告知，不重复讲拒绝逻辑（详见输出格式段）。
        int clamped = Math.max(0, Math.min(remainingBudget, 3));
        if (en) {
            sb.append("\n\n[Replay budget] You have ").append(clamped)
              .append(" replay call(s) remaining.\n");
        } else {
            sb.append("\n\n【重放预算】本阶段你还能调用 ").append(clamped).append(" 次重放。\n");
        }
        int activeWithPrompt = 0;
        if (selectedSkills != null) {
            for (Skill skill : selectedSkills) {
                if (skill.hasPrompt()) {
                    activeWithPrompt++;
                    sb.append(en ? SKILL_SECTION_HEADER_EN : SKILL_SECTION_HEADER_ZH)
                      .append(skill.name())
                      .append(en ? SKILL_SECTION_HEADER_CLOSE_EN : SKILL_SECTION_HEADER_CLOSE_ZH);
                    if (skill.hasFindingType()) {
                        sb.append(en ? FINDING_TYPE_DECL_EN : FINDING_TYPE_DECL_ZH)
                          .append(skill.findingType()).append('\n');
                    }
                    sb.append(skill.prompt());
                }
            }
        }
        // 多技能并行元规则紧贴技能段——约束的是"技能之间的归类行为"，与工具无关。
        if (activeWithPrompt >= 2) {
            sb.append(en ? MULTI_SKILL_RULE_EN : MULTI_SKILL_RULE_ZH);
        }
        sb.append("\n\n").append(replayOutputFormatSuffix());
        return sb.toString();
    }

    /**
     * 把一次"重放"工具调用的结果回填到 user 段。
     *
     * <p>模型在看到这条 user 消息时，能立即定位"我刚才发起的那个 tool_call 的响应
     * 在这里"——避免它在多轮上下文里把"重放 A 的响应"和"重放 B 的响应"搞混。</p>
     *
     * @param toolCallId  本次重放对应的工具调用标识（与解析时构造的 id 对齐）。
     * @param result      重放执行结果。
     * @param userRequest 模型提交的"要重放的请求"原文，方便模型核对"我刚才到底发了什么"。
     * @param elapsedMs   本次重放耗时（毫秒）。
     * @return 追加到 user 消息末尾的纯文本段。
     */
    public String buildReplayResultUserPrompt(String toolCallId, com.auditai.burp.tools.replay.ReplayResult result,
                                              String userRequest, long elapsedMs) {
        boolean en = isEnglish();
        StringBuilder sb = new StringBuilder(512);
        sb.append((en ? REPLAY_RESULT_HEADER_TEMPLATE_EN : REPLAY_RESULT_HEADER_TEMPLATE_ZH)
                .replace("{id}", toolCallId)
                .replace("{ms}", String.valueOf(elapsedMs)));
        if (userRequest != null && !userRequest.isEmpty()) {
            sb.append(en ? "[Your request]\n" : "【你提交的请求】\n")
              .append(userRequest).append('\n');
        }
        if (result.isSuccess()) {
            burp.api.montoya.http.message.responses.HttpResponse resp = result.response();
            // 标准 HTTP 状态行：httpVersion + " " + statusCode + " " + reasonPhrase。
// httpVersion 在 HTTP/2 消息里可能为空——回退到 HTTP/1.1，保持可读。
// 两者在 JDK Proxy mock 下也可能为 null（如测试桩），需要 null-safe 处理。
String version = java.util.Objects.toString(resp.httpVersion(), "");
String reason = java.util.Objects.toString(resp.reasonPhrase(), "");
if (version.isEmpty()) version = "HTTP/1.1";
sb.append(en ? "[Response]\n" : "[响应]\n")
              .append(version).append(' ').append(resp.statusCode())
              .append(' ').append(reason).append('\n');
            for (HttpHeader h : resp.headers()) {
                sb.append(h.name()).append(": ")
                  .append(com.auditai.burp.util.TextUtil.redactHeaderValue(h.name(), h.value()))
                  .append('\n');
            }
            byte[] body = resp.body().getBytes();
            if (body.length > 0) {
                sb.append('\n').append(en ? "[Body " : "[响应体 ")
                  .append(body.length).append(en ? " bytes]\n" : " 字节]\n")
                  .append(com.auditai.burp.util.TextUtil.safeBody(body)).append('\n');
            }
        } else {
            sb.append(en ? "[Replay failed] " : "[重放失败] ")
              .append(result.error()).append('\n');
        }
        return sb.toString();
    }

    /**
     * "可替换参数"清单前的提示文案：v2 重放协议要求模型在调
     * {@code replay_request} 时 key 必须从原请求"可替换参数"清单里选，
     * 否则会被服务端拒绝并浪费预算。
     *
     * <p>把这段 if-else 集中在本类内，{@code ToolLoopOrchestrator} 只负责
     * 决定"是否要追加 guard + 清单"，文案 / 标点 / 语言分支一律走
     * {@link PromptBuilder}——避免工具调度器感知语言细节。</p>
     *
     * <p>该方法不感知"清单是否为空"：是否真的需要插入 guard 由调用方按
     * {@code addrParams.isEmpty()} 决定，避免空清单时仍追加一段无意义
     * 提示打扰模型。</p>
     *
     * @return 醒目前缀，按当前 UI 语言分中英两版。
     */
    public String buildAddressableParamsGuard() {
        if (isEnglish()) {
            return "\n[⚠ Replay param constraint] When calling replay_request, keys MUST be picked from "
                    + "the [Addressable params] list below. Keys not in the list will be rejected and "
                    + "waste a budget slot. If the list is empty (or shows the explicit "
                    + "\"no addressable params\" hint), set tool_calls=[] and give the final conclusion "
                    + "directly — do NOT call replay_request.\n\n";
        }
        return "\n【⚠ 重放参数约束】调 replay_request 时，key 必须从下方【可替换参数】清单里选，"
                + "清单里没列的 key 一律不要写（写了会被服务端拒绝并浪费预算）；"
                + "清单为空（含显式的\"无可替换参数\"提示）时直接 tool_calls=[] 给最终结论，"
                + "不要调。\n\n";
    }

    /**
     * 追加"预算耗尽"的终止信号到 user 段：在第 4 次请求到达时插入。
     *
     * <p>模型必须立即收尾（哪怕只给"高度疑似"也得给结论），不允许再发起任何 tool_call。</p>
     */
    public String buildBudgetExhaustedUserPrompt(int usedBudget) {
        boolean en = isEnglish();
        if (en) {
            return "\n[Replay budget exhausted] You have already used " + usedBudget
                    + "/3 replay calls. The server will reject any further replay_request tool calls. "
                    + "You MUST now wrap up with a final analysis, risk, and findings — even if "
                    + "your conclusion is only \"highly suspected, not fully verified\".\n";
        }
        return "\n【重放预算已耗尽】你已使用 " + usedBudget
                + "/3 次重放。服务端将拒绝任何进一步的 replay_request 调用。"
                + "你必须立即收尾，给出最终 analysis / risk / findings —— 即使结论只是\"高度疑似，未完全验证\"。\n";
    }

    /**
     * 按当前语言取"重放"模式输出格式后缀。供 {@link #buildSystemPromptForReplay} 调用，
     * 公开以便测试断言。
     */
    public String replayOutputFormatSuffix() {
        return REPLAY_OUTPUT_FORMAT_SUFFIX[isEnglish() ? 1 : 0];
    }

    /**
     * 基础提示词（不含输出格式后缀）：自定义 → 资源文件 → 内置兜底。
     */
    private String buildBasePrompt() {
        String custom = customPromptSupplier.get();
        if (custom != null && !custom.isBlank()) {
            return custom;
        }
        return buildDefaultSystemPrompt();
    }

    /**
     * 构建默认系统提示词（忽略用户自定义），按当前界面语言选资源 / 兜底。
     * 供设置界面"恢复默认"按钮 + 切语言时刷新 prompt 框使用。
     */
    public String buildDefaultSystemPrompt() {
        return buildDefaultSystemPrompt(currentLang());
    }

    /**
     * 按指定语言构建默认系统提示词。先尝试对应语言资源文件 → 旧版单文件 →
     * 语言感知内置兜底。供 {@link #buildDefaultSystemPrompt()} 和外部测试使用。
     */
    public String buildDefaultSystemPrompt(Lang lang) {
        String primary = (lang == Lang.EN) ? PROMPT_RESOURCE_EN : PROMPT_RESOURCE_ZH;
        String fromResource = loadResource(primary);
        if (fromResource != null) {
            return fromResource;
        }
        return (lang == Lang.EN) ? DEFAULT_SYSTEM_PROMPT_EN : DEFAULT_SYSTEM_PROMPT_ZH;
    }

    /**
     * 构建用户提示词：请求 + 响应（信息最完整）。
     *
     * @param request  HTTP 请求快照。
     * @param response HTTP 响应快照；为 null 时只输出请求部分。
     */
    public String buildUserPrompt(HttpRequest request, HttpResponse response) {
        StringBuilder sb = new StringBuilder(2048);

        // —— 请求部分 ——
        sb.append("【HTTP 请求】\n");
        sb.append(request.method()).append(' ').append(request.url()).append('\n');
        for (HttpHeader header : request.headers()) {
            sb.append(header.name()).append(": ")
              .append(TextUtil.redactHeaderValue(header.name(), header.value())).append('\n');
        }
        byte[] requestBody = request.body().getBytes();
        if (requestBody.length > 0) {
            sb.append("\n请求体（共 ").append(requestBody.length).append(" 字节）：\n")
              .append(TextUtil.safeBody(requestBody)).append('\n');
        }

        // —— 响应部分 ——
        sb.append("\n【HTTP 响应】\n");
        if (response != null) {
            // 标准 HTTP 状态行：httpVersion + " " + statusCode + " " + reasonPhrase。
            // httpVersion 在 HTTP/2 消息里可能为空——回退到 HTTP/1.1，保持可读。
            // 两者在 JDK Proxy mock 下也可能为 null（如测试桩），需要 null-safe 处理。
            String version = java.util.Objects.toString(response.httpVersion(), "");
            String reason = java.util.Objects.toString(response.reasonPhrase(), "");
            if (version.isEmpty()) version = "HTTP/1.1";
            sb.append(version).append(' ').append(response.statusCode())
              .append(' ').append(reason).append('\n');
            for (HttpHeader header : response.headers()) {
                sb.append(header.name()).append(": ")
                  .append(TextUtil.redactHeaderValue(header.name(), header.value())).append('\n');
            }
            byte[] responseBody = response.body().getBytes();
            if (responseBody.length > 0) {
                sb.append("\n响应体（共 ").append(responseBody.length).append(" 字节）：\n")
                  .append(TextUtil.safeBody(responseBody)).append('\n');
            }
        } else {
            sb.append("（本请求暂无响应）\n");
        }

        return sb.toString();
    }

    /**
     * 构建"调试版"用户提示词：用于 {@code TrafficAnalyzer} 的 DEBUG 日志。
     *
     * <p>与 {@link #buildUserPrompt} 的差异：</p>
     * <ul>
     *   <li>请求 / 响应头：不再逐条展开，统一占位成一行 {@code （请求头：略...）}
     *       / {@code （响应头：略...）}，避免日志里漏出 Authorization / Cookie 等；</li>
     *   <li>请求 / 响应体：不输出正文，只输出一行占位文本
     *       {@code （请求体/响应体：N字节）}——保留体积信息、便于核对"为什么 prompt 那么大"；</li>
     *   <li>响应状态码：DEBUG 日志里不打印（排查状态码用 Burp HTTP 历史更直接）。</li>
     * </ul>
     *
     * <p><b>本方法只影响 DEBUG 日志打印，不影响真实发送给模型的报文</b>——
     * 真实发送仍走 {@link #buildUserPrompt}，原文 / 头 / 体 / 状态码全量到位。</p>
     */
    public String buildUserPromptDebug(HttpRequest request, HttpResponse response) {
        // 走"完整版 → 压缩版"路径：与阶段 2 的 compactMessageText 共用同一压缩器，
        // 保证两处日志输出格式一致（不让两套压缩逻辑各自漂移）。
        String full = buildUserPrompt(request, response);
        return com.auditai.burp.util.TrafficCompactor.compactMessageText(full);
    }
}
