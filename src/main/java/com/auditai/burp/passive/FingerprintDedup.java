package com.auditai.burp.passive;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 指纹去重：线程安全的 LRU 结构（{@link Collections#synchronizedMap(Map)} 包装 +
 * 容量阈值），保证同一指纹只分析一次。
 *
 * <p>选型说明：</p>
 * <ul>
 *   <li>使用 {@code Collections.synchronizedMap(new LinkedHashMap<>(capacity, 0.75f, true))}，
 *       accessOrder=true 让 {@code get} 也会更新插入顺序，构造器传入 capacity 触发
 *       {@code removeEldestEntry} 自动淘汰——满足"线程安全 + LRU"两条要求，零额外依赖；</li>
 *   <li>默认容量 5000（与 {@code ProxyTrafficStore} 的记录数上限一致），覆盖一个中大型
 *       渗透测试会话的高频请求；超过容量时按访问顺序淘汰最久未见的指纹，行为可预测；</li>
 *   <li>正常情况下"已分析"状态保留意味着同一指纹不重复分析，避免 AI 暂时不可用时
 *       反复消耗 token；</li>
 *   <li>提供 {@link #remove(String)} / {@link #clear()} 两个<b>手动重置</b>入口，
 *       与 {@code AnalysisHistoryStore} 的用户删除操作对齐（仅在 UI 主动删除时调用，
 *       不开放给被动分析热路径）：
 *       <ul>
 *         <li>"历史"页签删除<b>单条</b>记录 → {@link #remove} 该记录的请求指纹；
 *             该记录删除后，同 URL 的新报文不再被当作"已分析过"，可重新被动分析；</li>
 *         <li>"历史"页签 Clear 全清 → {@link #clear()}，语义为整体重置。</li>
 *       </ul></li>
 * </ul>
 *
 * <p>线程安全：所有方法（{@link #markIfNew} / {@link #primeAll} / {@link #contains} /
 * {@link #size} / {@link #remove} / {@link #clear}）都通过
 * {@link Collections#synchronizedMap} 串行化，可在 Proxy 请求/响应回调线程并发调用。</p>
 */
public final class FingerprintDedup {

    /**
     * 默认容量阈值。超过后按访问顺序淘汰最久未见的指纹。
     */
    public static final int DEFAULT_CAPACITY = 5_000;

    private final Map<String, Boolean> seen;

    /**
     * 使用默认容量 {@value #DEFAULT_CAPACITY} 构造。
     */
    public FingerprintDedup() {
        this(DEFAULT_CAPACITY);
    }

    /**
     * @param capacity LRU 容量阈值；必须为正数（&lt;=0 会被夹到 1，避免创建零容量 map）。
     */
    public FingerprintDedup(int capacity) {
        int cap = Math.max(1, capacity);
        // accessOrder=true 让 get() 也算"访问"——LRU 语义更准（最近见过的请求挤掉最久没见的）。
        this.seen = Collections.synchronizedMap(new LinkedHashMap<String, Boolean>(cap, 0.75f, true) {
            private static final long serialVersionUID = 1L;

            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Boolean> eldest) {
                return size() > cap;
            }
        });
    }

    /**
     * 把指纹标记为"已见过"——若之前未见过则插入并返回 true；否则返回 false。
     *
     * <p>调用方在 true 路径上才真正提交分析任务；false 路径上跳过本次分析。</p>
     *
     * @param fingerprint 请求指纹。
     * @return true → 本次调用是首次见到该指纹，应当触发分析；false → 重复，跳过。
     */
    public boolean markIfNew(String fingerprint) {
        if (fingerprint == null) {
            return false;
        }
        // putIfAbsent 自身是原子的，命中即"重复"、未命中即"首次"并插入占位。
        return seen.putIfAbsent(fingerprint, Boolean.TRUE) == null;
    }

    /**
     * 批量预热：把一批已有指纹塞进 seen map，<b>不</b>触发"是否首次"的判断回值（无返回值）。
     *
     * <p>用途：插件启动时从 {@code AnalysisHistoryStore} 反查"已经分析过的请求"指纹
     * 一次性喂进来，让重启后的 dedup 不会把这些请求当成"首次见到"重新调 AI。</p>
     *
     * <p>行为细节：</p>
     * <ul>
     *   <li>对已存在的指纹是 no-op；</li>
     *   <li>用 {@code putIfAbsent} 插入，<b>不</b>走 {@code get}——预热时这些指纹的
     *       LRU 顺序是"按预热顺序"而不是"按访问时间"，对功能无影响（LRU 只决定淘汰谁）；</li>
     *   <li>空集合 / null 元素跳过（与 {@link #markIfNew} 一致：null 不算合法指纹）。</li>
     * </ul>
     *
     * @param fingerprints 要预热的指纹集合；可为 null 或空（直接返回）。
     */
    public void primeAll(Collection<String> fingerprints) {
        if (fingerprints == null || fingerprints.isEmpty()) {
            return;
        }
        for (String fp : fingerprints) {
            if (fp != null && !fp.isEmpty()) {
                seen.putIfAbsent(fp, Boolean.TRUE);
            }
        }
    }

    /**
     * 测试指纹是否已见过。
     *
     * <p>用 {@link java.util.Map#containsKey} 查询：{@code LinkedHashMap} 在
     * {@code accessOrder=true} 时只有 {@code get} 会更新访问顺序，{@code containsKey}
     * 不会——因此本方法不影响 LRU 淘汰顺序。</p>
     */
    public boolean contains(String fingerprint) {
        return fingerprint != null && seen.containsKey(fingerprint);
    }

    /** 当前已见指纹数（线程安全的快照值，仅供监控/调试用）。 */
    public int size() {
        return seen.size();
    }

    /**
     * 移除单个指纹的"已见过"标记（"历史"页签删除<b>单条</b>记录时同步调用）。
     *
     * <p>与 {@link #clear()} 的分工：删除单条记录 → 移除该记录的请求指纹，其余记录
     * 不受影响；Clear 全清 → 整体清空。移除后 {@link #markIfNew} 对该指纹重新返回
     * true，即"删除该记录后，同 URL 的新报文会被重新被动分析"。</p>
     *
     * <p>null / 空串 / 未见过的指纹均为安全的 no-op。底层是
     * {@link Collections#synchronizedMap}，可在 UI 线程与 Proxy 回调线程并发调用。</p>
     *
     * @param fingerprint 要移除的请求指纹；可为 null（直接忽略）。
     */
    public void remove(String fingerprint) {
        if (fingerprint != null) {
            seen.remove(fingerprint);
        }
    }

    /**
     * 清空全部已见指纹。调用后 {@link #markIfNew} 对任何已知指纹都会重新返回 true，
     * 相当于"重置"去重状态。
     *
     * <p><b>用途：</b>"历史"页签执行 {@code Clear} 时同步调用，让 dedup 与
     * {@code AnalysisHistoryStore} 的状态重新一致——避免"清空了 UI 历史但
     * 被动分析仍把同 URL 视为已分析"的歧义。</p>
     *
     * <p><b>不</b>影响已在执行器队列中 in-flight 的分析任务：它们已经过
     * {@link #markIfNew} 检查才被提交，任务完成后会正常写 history；只是清空
     * 之后新进来的同指纹请求会被重新分析。</p>
     *
     * <p>线程安全：通过 {@link Collections#synchronizedMap} 串行化，
     * 可以在 UI 线程与 Proxy 回调线程并发调用。</p>
     */
    public void clear() {
        seen.clear();
    }
}
