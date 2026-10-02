package com.auditai.burp.ai;

import java.util.List;

/**
 * AI 客户端抽象接口。
 *
 * <p>只暴露业务真正需要的语义：“给定系统提示词与用户提示词，返回模型补全的文本”。
 * 好处是入口与编排层不依赖任何具体厂商的 SDK，未来可替换实现而不影响上层：
 * 例如换用本地 Ollama、Azure OpenAI、或者国产大模型的私有协议。</p>
 *
 * <p>提供三类入口：</p>
 * <ul>
 *   <li>{@link #complete}：同步单轮调用，适合简单场景（如设置页的“测试连接”）；</li>
 *   <li>{@link #completeAsync}：异步单轮调用，返回可取消句柄（适合分析流程）；</li>
 *   <li>{@link #completeJsonAsync}：异步多轮调用，专供"多报文协同分析"使用，
 *       支持任意条数 messages 与可选的 JSON 模式约束。</li>
 * </ul>
 *
 * <p>实现要求：实现类必须线程安全（会被分析线程串行调用）。</p>
 */
public interface AiClient {

    /**
     * 同步发送一次对话补全请求。
     *
     * @param systemPrompt 系统提示词：定义模型角色与输出要求（见 PromptBuilder）。
     * @param userPrompt   用户提示词：本次要分析的报文内容。
     * @return 模型返回的文本内容。
     * @throws AiException 网络、鉴权、协议或模型自身错误时抛出（带可读信息）。
     */
    String complete(String systemPrompt, String userPrompt) throws AiException;

    /**
     * 异步发起一次对话补全请求，返回<b>可取消</b>的调用句柄。
     *
     * <p>调用方可在任意线程通过 {@link CancellableAiCall#cancel()} 中断进行中的请求，
     * 也可调用 {@link CancellableAiCall#await()} 阻塞等待最终文本。
     * 未配置完整（缺少 Key / Base URL）等前置校验错误仍以 {@link AiException} 同步抛出。</p>
     *
     * @param systemPrompt 系统提示词。
     * @param userPrompt   用户提示词。
     * @return 可取消的调用句柄。
     * @throws AiException 前置校验失败时同步抛出。
     */
    CancellableAiCall completeAsync(String systemPrompt, String userPrompt) throws AiException;

    /**
     * 异步发起一次支持"多轮对话 + JSON 模式"的对话补全请求。
     *
     * <p>用于多报文协同分析：模型在第一轮看到摘要后，可在第二轮拿到完整历史报文。
     * 与 {@link #completeAsync} 的区别在于 messages 列表可任意长度（含 assistant
     * 角色），并且支持 {@code requireJson=true} 时附加
     * {@code response_format: {"type":"json_object"}} 让模型必须输出 JSON。</p>
     *
     * @param messages    完整消息列表，至少一条；按出现顺序组装到 OpenAI 协议的 messages 字段。
     * @param requireJson 是否开启 JSON 模式约束。
     * @return 可取消的调用句柄。
     * @throws AiException 前置校验失败或调用方传错参数时同步抛出。
     */
    CancellableAiCall completeJsonAsync(List<ChatMessage> messages, boolean requireJson) throws AiException;

    /**
     * 异步 JSON 调用，带"远端不支持 json_object"自动降级：先按 JSON 模式发一次，
     * 若返回 4xx 且错误体提示不支持 {@code response_format}，自动重试一次（去掉该字段）。
     *
     * <p>调用方拿到的是最终成功的句柄；如果两次都失败则抛出最后一次的异常。
     * 老版本 ({@link #completeJsonAsync(List, boolean) requireJson=true}) 不带降级，
     * 需自行捕获"不支持 json_object"并重试——新代码应优先使用本入口。</p>
     *
     * @param messages 完整消息列表，至少一条；按出现顺序组装到 OpenAI 协议的 messages 字段。
     *                  本方法默认开启 JSON 模式约束（{@code requireJson=true}）。
     * @return 可取消的调用句柄。
     * @throws AiException 两次请求都失败时抛出最后一次的异常。
     */
    CancellableAiCall completeJsonAsyncWithFallback(List<ChatMessage> messages) throws AiException;

    /**
     * 释放客户端持有的资源（线程池、可关闭连接等）。
     *
     * <p>默认实现为空 —— 多数 AI 客户端 SDK 不暴露可关闭资源；当前唯一的实现
     * {@link OpenAiCompatibleClient} 重写本方法以关闭注入的 HTTP executor，
     * 避免插件卸载后留下 cached thread pool 残留线程。多次调用幂等。</p>
     *
     * <p>调用方应在 {@code registerUnloadingHandler} 兜底调用，避免热重载
     * 后线程持续存在。</p>
     */
    default void close() {
        // no-op:绝大多数 AiClient 实现没有 owned 资源需要释放。
    }

    /**
     * 角色 + 内容的一条对话消息。
     *
     * <p>role 取值参考 OpenAI Chat Completions 协议：{@code system} / {@code user} /
     * {@code assistant}。本接口不做合法性校验，调用方自行负责。</p>
     */
    record ChatMessage(String role, String content) {
    }
}
