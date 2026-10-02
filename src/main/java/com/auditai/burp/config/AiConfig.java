package com.auditai.burp.config;

import java.util.Arrays;

/**
 * 单条 AI 服务配置：与设置界面"AI 服务"区的一行输入框一一对应。
 *
 * <p>多配置支持：设置界面允许保存<b>多份</b>AI 服务配置（用户自己新建的），
 * 通过下拉列表切换当前激活项。完整的"配置集"由 {@link Settings} 持有，
 * 本类只承载"单条"配置。切换激活项时 {@link Settings} 采用<b>整体替换 volatile
 * 引用</b>的方式，不做原地 copyFrom（避免下游读到撕裂的中间态）；
 * {@link #copyFrom(AiConfig)} 仅供列表条目编辑/测试场景使用。</p>
 *
 * <p>统一连接方式：所有服务都走 OpenAI Chat Completions 兼容协议。
 * 用户只需配置 Base URL、可选 API Key 与模型名；本地 Ollama / LM Studio 等
 * 可以把 API Key 留空，远程 DeepSeek / OpenAI / 通义等服务则填写对应 Key。</p>
 *
 * <p><b>API Key 安全：</b>内部以 {@code char[]} 存储，避免进入字符串常量池；
 * 持久化到磁盘（{@link SettingsStore}）时由 {@link ApiKeyCipher} 加密为
 * {@code enc:v1:...} 格式，磁盘上不再保留明文。详见 {@link ApiKeyCipher} 的威胁模型说明。</p>
 */
public final class AiConfig {

    /** 单次请求超时的默认值（秒）。 */
    public static final int DEFAULT_TIMEOUT_SECONDS = 60;

    /** 单次回答 max_tokens 的默认值。 */
    public static final int DEFAULT_MAX_TOKENS = 8192;

    /** 单次请求超时的下限（秒）：持久化脏数据可能为 0/负值，使用时需夹取到该下限。 */
    public static final int MIN_TIMEOUT_SECONDS = 1;

    /** 单次请求超时的上限（秒）：与设置面板滑块上限保持一致。 */
    public static final int MAX_TIMEOUT_SECONDS = 300;

    /** 配置名称（设置界面下拉列表中显示的文本）。同一份配置集内不允许重名。 */
    private String name;

    /** AI 服务地址（不含末尾斜杠，不含路径）。 */
    private String baseUrl;

    /**
     * 调用 AI 接口的密钥，{@code char[]} 形式避免进入字符串常量池。
     * 调用方<b>不得</b>修改 / 置空 / 长期持有返回的数组（共享引用语义）。
     */
    private char[] apiKey = new char[0];

    /** 模型名称。 */
    private String model;

    /** 单次请求超时（秒），防止模型接口长时间无响应拖住分析线程。 */
    private int timeoutSeconds;

    /** 单次回答的最大 token 数，用于控制成本与响应长度。 */
    private int maxTokens;

    /** 构造空白配置：所有字段取空或合理默认（仅供测试/桩场景使用，正式配置从 {@link SettingsStore} 加载）。 */
    public AiConfig() {
        this("", "", new char[0], "", DEFAULT_TIMEOUT_SECONDS, DEFAULT_MAX_TOKENS);
    }

    /**
     * 构造完整配置（一般用于创建新条目；API Key 接收 String，内部转为 char[]）。
     *
     * @param name           配置名（用户视角下唯一标识）。
     * @param baseUrl        服务 Base URL（OpenAI 兼容协议根地址）。
     * @param apiKey         API Key 明文；null 视作空串。
     * @param model          模型名。
     * @param timeoutSeconds 单次请求超时（秒）。
     * @param maxTokens      单次回答的最大 token 数。
     */
    public AiConfig(String name, String baseUrl, String apiKey, String model,
                    int timeoutSeconds, int maxTokens) {
        this(name, baseUrl, apiKey == null ? new char[0] : apiKey.toCharArray(),
                model, timeoutSeconds, maxTokens);
    }

    /**
     * 构造完整配置（{@code char[]} 形式的 API Key，持久化层与测试使用）。
     *
     * @param name           配置名（用户视角下唯一标识）。
     * @param baseUrl        服务 Base URL（OpenAI 兼容协议根地址）。
     * @param apiKey         API Key（已为 char[] 形式；内部会 clone 一份，不共享调用方数组）。
     * @param model          模型名。
     * @param timeoutSeconds 单次请求超时（秒）。
     * @param maxTokens      单次回答的最大 token 数。
     */
    public AiConfig(String name, String baseUrl, char[] apiKey, String model,
                    int timeoutSeconds, int maxTokens) {
        this.name = name;
        this.baseUrl = baseUrl;
        this.apiKey = apiKey == null ? new char[0] : apiKey.clone();
        this.model = model;
        this.timeoutSeconds = timeoutSeconds;
        this.maxTokens = maxTokens;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    /**
     * 返回 API Key 的内部 {@code char[]} 副本。
     *
     * <p><b>为什么不直接返回内部引用：</b>直接返回会让调用方拿到可写入的内部数组，
     * 任何 {@code Arrays.fill(...)} 都会破坏本类的"安全清理"机制。本方法返回
     * {@code clone()}，调用方可以正常用、用完置零,都不会影响本类持有的主副本。</p>
     *
     * <p><b>性能取舍：</b>配置变更 / 启动时调用,频次可忽略。{@code CancellableAiCall}
     * 每轮都要拿 Key 拼 HTTP 头,但 {@code OpenAiCompatibleClient} 会在更上层把 Key
     * 转 String 一次缓存到 HeaderBuilder,不在这层高频调用。</p>
     */
    public char[] getApiKey() {
        return apiKey.clone();
    }

    /** 直接以 {@code char[]} 写入：内部复制一份;原数组写入后立即清零(契约:见 Javadoc)。 */
    public void setApiKey(char[] apiKey) {
        // 先清零旧的内部副本,再 clone 入参并清零入参——任何"原数组引用"
        // 都不会在堆里继续保留明文 Key。
        if (this.apiKey != null) {
            Arrays.fill(this.apiKey, '\0');
        }
        if (apiKey != null) {
            this.apiKey = apiKey.clone();
            Arrays.fill(apiKey, '\0');
        } else {
            this.apiKey = new char[0];
        }
    }

    /** 便捷写入：自动转 char[]。 */
    public void setApiKey(String apiKey) {
        setApiKey(apiKey == null ? new char[0] : apiKey.toCharArray());
    }

    public String getModel() {
        return model;
    }

    public void setModel(String model) {
        this.model = model;
    }

    public int getTimeoutSeconds() {
        return timeoutSeconds;
    }

    public void setTimeoutSeconds(int timeoutSeconds) {
        this.timeoutSeconds = timeoutSeconds;
    }

    public int getMaxTokens() {
        return maxTokens;
    }

    public void setMaxTokens(int maxTokens) {
        this.maxTokens = maxTokens;
    }

    /**
     * 把另一份配置的字段全部复制到本对象（<b>原地替换</b>，不改变 Java 引用）。
     *
     * <p>注意：{@link Settings} 切换激活项采用"整体替换 volatile 引用"而非本方法
     * （避免原地修改造成下游读到撕裂的中间态）。本方法目前只用于<b>列表条目编辑
     * 与测试场景</b>，新代码不应依赖它做"热切换配置"。</p>
     */
    public void copyFrom(AiConfig other) {
        if (other == null) {
            return;
        }
        this.name = other.name;
        this.baseUrl = other.baseUrl;
        setApiKey(other.apiKey);
        this.model = other.model;
        this.timeoutSeconds = other.timeoutSeconds;
        this.maxTokens = other.maxTokens;
    }
}
