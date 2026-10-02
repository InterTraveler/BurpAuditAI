package com.auditai.burp.passive;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 被动分析错误状态总线：在插件内跨线程共享"被动分析最近一次错误"。
 *
 * <p><b>为什么需要这个类</b>：被动分析在独立线程池里执行，AI 调用失败时用户
 * 通常并不停留在分析页 / 历史页，需要在"设置"页签的"被动分析"区下方持续
 * 展示错误信息 + 在"设置"页签标题右侧加感叹号，让用户即使停留在其他页签
 * 也能立刻感知到问题。</p>
 *
 * <p><b>设计取舍</b>：</p>
 * <ul>
 *   <li>用 <b>单例</b>（{@link #INSTANCE}）暴露：被动分析回调线程（{@code PassiveAnalyzer}）
 *       与 UI 监听线程（{@code SettingsPanel}）天然解耦，无需在装配链中显式注入；</li>
 *   <li>用 {@link AtomicReference} 存错误快照：单字段原子写，读侧无锁，足够应对
 *       "设置一次 + 读很多次"的使用模式；</li>
 *   <li>用 {@link CopyOnWriteArrayList} 存监听器：监听器数量极少（通常 1-2 个 UI 实例），
 *       写时复制避免遍历时并发修改异常，遍历无锁；</li>
 *   <li>监听器在<b>调用线程</b>同步触发：避免另起线程执行 UI 更新造成时序混乱；
 *       UI 监听器需自行判断是否需要 {@code SwingUtilities.invokeLater} 切到 EDT
 *       （本类的 UI 实现就遵守这一点）。</li>
 * </ul>
 *
 * <p><b>错误分类</b>：仅按用户可读的三种根因归类——配置不当、网络不可达、远端错误——
 * 便于在 UI 上提示"该去检查什么"（详见 {@link ErrorKind}）。</p>
 */
public final class PassiveAnalysisErrorBus {

    /**
     * 错误根因分类：决定 UI 提示用户的"该去检查什么"。
     *
     * <p>分类不追求穷尽（异常体系内部原因很多），只追求"对用户下一步动作有指导意义"：</p>
     * <ul>
     *   <li>{@link #CONFIG}：用户输入有问题——Base URL 缺失 / 格式错、模型名缺失等，
     *       修复路径是去"设置"页改正配置；</li>
     *   <li>{@link #NETWORK}：本地/远端网络问题——连接超时、UnknownHost、Connection Refused
     *       等，修复路径是检查网络/服务是否可达；</li>
     *   <li>{@link #REMOTE}：远端服务响应了——HTTP 4xx/5xx 或响应体结构异常，
     *       修复路径是检查 API Key、模型名、配额、模型版本兼容性等。</li>
     * </ul>
     */
    public enum ErrorKind {
        /** 配置不当：Base URL 为空 / 格式不正确 / 尚未配置 AI 服务等。 */
        CONFIG,
        /** 网络不可达：连接超时、DNS 解析失败、连接被拒等。 */
        NETWORK,
        /** 远端 AI 服务响应错误：HTTP 4xx/5xx、响应体结构异常等。 */
        REMOTE
    }

    /**
     * 错误快照：消息文本 + 分类 + 发生时间戳。
     *
     * <p>不可变对象，写入后无法修改；{@link #cleared()} 是"空态"哨兵。</p>
     */
    public static final class ErrorInfo {
        private final String message;
        private final ErrorKind kind;
        private final long timestampMillis;

        public ErrorInfo(String message, ErrorKind kind, long timestampMillis) {
            this.message = message;
            this.kind = kind;
            this.timestampMillis = timestampMillis;
        }

        /** 静态"无错误"哨兵：复用同一对象，避免每次清理都分配新实例。 */
        private static final ErrorInfo NONE = new ErrorInfo("", null, 0L);

        /** "无错误"哨兵：避免空检查时到处用 {@code null}。 */
        public static ErrorInfo cleared() {
            return NONE;
        }

        /** @return true 表示当前没有错误。 */
        public boolean isCleared() {
            return this == NONE;
        }

        public String getMessage() {
            return message;
        }

        public ErrorKind getKind() {
            return kind;
        }

        public long getTimestampMillis() {
            return timestampMillis;
        }
    }

    /** 进程内单例。 */
    public static final PassiveAnalysisErrorBus INSTANCE = new PassiveAnalysisErrorBus();

    private final AtomicReference<ErrorInfo> current = new AtomicReference<>(ErrorInfo.cleared());

    /**
     * CopyOnWriteArrayList：监听器通常只有 1-2 个 UI 实例，写时复制避免遍历修改异常；
     * 遍历在快照上进行，无需加锁。
     */
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();

    private PassiveAnalysisErrorBus() {
    }

    /**
     * 记录一次错误：覆盖当前错误（不是追加）——最近一次的错误对用户最有价值。
     * 触发所有监听器。
     *
     * <p>调用线程：任意（被动分析线程、UI 线程等）。监听器内若操作 Swing 组件，
     * 需自行切到 EDT（{@code SwingUtilities.invokeLater}）。</p>
     *
     * @param message 错误描述（用户可读，UI 直接展示）。
     * @param kind    错误分类。
     */
    public void setError(String message, ErrorKind kind) {
        if (message == null) {
            message = "";
        }
        ErrorInfo info = new ErrorInfo(message, kind, System.currentTimeMillis());
        current.set(info);
        fireListeners();
    }

    /**
     * 清除当前错误：通常由"被动分析下次成功完成"或"用户主动保存了 AI 服务配置"
     * 触发。幂等——重复调用安全。触发所有监听器。
     */
    public void clearError() {
        // 仅在"之前确实有错误"时才发事件：避免每次分析成功都把 UI 唤醒一次空更新。
        ErrorInfo previous = current.getAndSet(ErrorInfo.cleared());
        if (previous != null && !previous.isCleared()) {
            fireListeners();
        }
    }

    /**
     * 当前错误快照：可能为"无错误"（{@link ErrorInfo#isCleared()} == true）。
     * 无锁读，开销可忽略。
     */
    public ErrorInfo getError() {
        return current.get();
    }

    /**
     * 注册一个错误变化监听器：任何 {@link #setError} / {@link #clearError} 都会触发。
     * 监听器在调用线程同步执行。
     *
     * <p>注册后<b>不会</b>立即触发一次回调——调用方如需当前状态请自行
     * {@link #getError()} 后渲染一次。</p>
     */
    public void addListener(Runnable listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    /**
     * 移除监听器：通常在 UI 销毁时调用，避免持有已销毁的对象导致内存泄漏。
     */
    public void removeListener(Runnable listener) {
        if (listener != null) {
            listeners.remove(listener);
        }
    }

    /**
     * 清空所有监听器：插件卸载时调用。
     *
     * <p>本总线是进程内单例（{@link #INSTANCE}）——{@link #listeners} 用
     * {@link CopyOnWriteArrayList} 强引用持有监听器，监听器又强引用持有它的
     * 组件（如 {@code SettingsPanel}）。插件卸载时若不主动清：
     * <ul>
     *   <li>{@code SettingsPanel.close()} 内部会逐个调
     *       {@link #removeListener(Runnable)} 摘自己的 listener（生产路径已
     *       实现），所以正常卸载路径不会泄漏；</li>
     *   <li>但任何"忘注册 close"的子页签 / 中途异常跳过的卸载路径都会留下
     *       强引用 → Burp 重载后旧 MainTab 不会 GC → 切语言时旧组件被刷
     *       出 NPE。</li>
     * </ul>
     *
     * <p>作为最后一道防线，{@code AuditAiExtension.registerUnloadingHandler} 内
     * 调一次本方法，把整个 listener 列表清空。清空后新实例重新注册不受影响
     * （{@code SettingsPanel} 构造时调 {@link #addListener(Runnable)}）。</p>
     */
    public void clearListeners() {
        listeners.clear();
    }

    /**
     * 同步触发所有监听器：异常隔离——单个监听器抛异常不影响其他监听器，
     * 也不影响其他业务线程。
     *
     * <p>总线是 {@link #INSTANCE} 单例、无法注入 Montoya API；监听器回调里抛异常的
     * 极端兜底只能走 stderr——本路径应通过严格的 listener 写法避免（生产代码
     * {@code SettingsPanel} 的回调已用 try-catch 隔离）。</p>
     */
    private void fireListeners() {
        for (Runnable l : listeners) {
            try {
                l.run();
            } catch (RuntimeException ex) {
                // 监听器抛异常不应当影响其他监听器；本总线自身也不抛。
                // 单例总线拿不到 MontoyaApi，兜底到 stderr 是最后手段。
                System.err.println("[AuditAI PassiveAnalysisErrorBus] 监听器抛异常被吞掉："
                        + ex.getMessage());
            }
        }
    }
}
