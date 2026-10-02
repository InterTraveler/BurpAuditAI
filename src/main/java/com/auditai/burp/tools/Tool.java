package com.auditai.burp.tools;

/**
 * 一个可被模型在分析过程中自主调用的"工具"（业内标准做法 = OpenAI Function Calling /
 * Anthropic Tool Use / MCP 通用模式）。
 *
 * <p>每个实现代表一个具体的常驻分析能力，模型在 phase 2 多轮循环里通过
 * {@code tool_calls} 触发。实现负责：</p>
 * <ol>
 *   <li>解析模型提交的 {@code arguments} JSON（结构由各工具自己定义）；</li>
 *   <li>执行真正的"动作"（HTTP 发送、字典爆破、编码/解码等）；</li>
 *   <li>把执行结果格式化成"回填到 user 段"的文本片段。</li>
 * </ol>
 *
 * <p><b>设计约束</b>：</p>
 * <ul>
 *   <li>实现必须线程安全——{@link ToolLoopOrchestrator} 会从单一分析线程串行调用，
 *       但未来并发场景下不能出问题；</li>
 *   <li>实现不应抛出异常——所有失败（网络错误、参数非法、目标不可达）必须
 *       通过 {@link ToolOutcome#failure(String, String)} 返回，让多轮循环不会
 *       因为一次工具失败而崩溃；</li>
 *   <li>实现对"调用次数 / 预算"无感知——预算管理统一由 orchestrator 负责，
 *       工具只需要诚实告诉 orchestrator"我成功了"或"我失败了"即可。</li>
 * </ul>
 *
 * <p><b>命名约定</b>：{@link #name()} 必须与模型 JSON 里 {@code tool_calls[].name} 字段
 * 完全一致。当前已注册：</p>
 * <ul>
 *   <li>{@code "replay_request"}：修改参数后重放请求验证漏洞；
 *       见 {@code com.auditai.burp.tools.replay.ReplayTool}。</li>
 * </ul>
 *
 * <p>将来要加"爆破"只需新建 {@code BruteForceTool implements Tool}，{@link #name()}
 * 返回 {@code "brute_force"}（或类似），然后在装配时加入工具列表。
 * {@link ToolLoopOrchestrator} 一行不用改。</p>
 */
public interface Tool {

    /**
     * 工具名：模型在 JSON {@code tool_calls[].name} 里写的标识。
     *
     * <p>必须满足"小写英文 + 下划线"风格，且与 {@code .skill} / 提示词里
     * 描述的工具名完全一致——任何拼写差异都会让模型发起调用时找不到匹配。</p>
     */
    String name();

    /**
     * 执行一次工具调用。
     *
     * <p>本方法<b>绝对不能</b>抛异常：失败必须通过 {@link ToolOutcome#failure} 返回。
     * 这是"多轮循环不因单次工具失败而崩"的关键契约。</p>
     *
     * @param call 模型提交的一次工具调用：含工具名、模型原话、JSON 形式 arguments。
     * @return 执行结果（含成功 / 失败 + 回填到 user 段的文本片段）。
     */
    ToolOutcome execute(ToolCall call);
}
