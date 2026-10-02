package com.auditai.burp.ui;

import com.auditai.burp.ai.PromptBuilder.Lang;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.ref.WeakReference;
import java.nio.charset.StandardCharsets;
import java.text.MessageFormat;
import java.util.Locale;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.PropertyResourceBundle;
import java.util.ResourceBundle;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.border.TitledBorder;

/**
 * 国际化运行时：单例，按 key 查文案，广播语言切换事件。
 * 资源文件位于 classpath {@code i18n/messages_xx.properties}。
 *
 * <p>常用法：</p>
 * <pre>{@code
 *   I18n.get().t("ui.tab.settings");                  // 拿文案
 *   I18n.get().t("ui.toast.deleted", name);           // 带参
 *   JLabel lbl = I18n.label("ui.settings.name");      // 自动跟随语言
 *   I18n.tooltip(filterField, "ui.history.filterTip");
 *   I18n.get().onChange(lang -> refreshI18n());       // 短生命周期组件记得 off
 * }</pre>
 */
public final class I18n {

    private static final I18n INSTANCE = new I18n();

    public static I18n get() {
        return INSTANCE;
    }

    /** key 找不到时返回 {@code !key}，便于肉眼发现漏翻译。 */
    private static final String MISSING_PREFIX = "!";

    // bundles 只在构造期写，运行期跨线程读（EDT + 分析线程都走 t()），
    // 用 ConcurrentHashMap 防 NPE / 读不完整节点。
    /** 按语言加载的 ResourceBundle；只读映射，构造期单线程写后即冻结。 */
    private final Map<Lang, ResourceBundle> bundles = new ConcurrentHashMap<>();

    /** 显式注册的语言切换监听器；强引用，组件销毁前必须 off。 */
    private final CopyOnWriteArrayList<Consumer<Lang>> listeners = new CopyOnWriteArrayList<>();

    // 组件订阅表：弱引用组件，GC 后自动失效。ConcurrentHashMap 是因为监听器回调
    // 可能在任意线程触发"读+删"，普通 HashMap 会 ConcurrentModificationException。
    /** 自动翻译组件的订阅表：key=弱引用组件，value=i18n key。 */
    private final Map<WeakReference<?>, String> subscribers = new ConcurrentHashMap<>();

    // tooltip 独立成表，因为同一个组件可能同时订阅文本 + tooltip（语义不同）。
    /** tooltip 自动翻译订阅表；key=弱引用组件，value=i18n key。 */
    private final Map<WeakReference<JComponent>, String> tooltipSubscribers = new ConcurrentHashMap<>();

    /** 当前语言；set() 中读改写。 */
    private volatile Lang current = Lang.ZH;

    private I18n() {
        bundles.put(Lang.ZH, load(Locale.SIMPLIFIED_CHINESE, "i18n/messages_zh"));
        bundles.put(Lang.EN, load(Locale.ENGLISH, "i18n/messages_en"));
    }

    /** 显式按 UTF-8 加载 properties，避免依赖 JDK 默认行为（Java 8 上是 ISO-8859-1）。 */
    private static ResourceBundle load(Locale locale, String baseName) {
        try {
            InputStream stream = I18n.class.getClassLoader().getResourceAsStream(baseName + ".properties");
            if (stream == null) {
                throw new MissingResourceException("Not found: " + baseName, baseName, "");
            }
            try (InputStreamReader reader = new InputStreamReader(stream, StandardCharsets.UTF_8)) {
                return new PropertyResourceBundle(reader);
            }
        } catch (IOException e) {
            throw new MissingResourceException(
                    "Failed to load " + baseName + ": " + e.getMessage(), baseName, "");
        }
    }

    public Lang current() {
        return current;
    }

    /** 切换语言并刷新所有订阅组件 + 通知监听器。 */
    public void set(Lang lang) {
        if (lang == null || lang == this.current) {
            return;
        }
        this.current = lang;
        refreshSubscribers();
        refreshTooltipSubscribers();
        for (Consumer<Lang> l : listeners) {
            try {
                l.accept(lang);
            } catch (RuntimeException ignored) {
                // 单个监听器抛异常不应阻断其他监听器
            }
        }
    }

    /** 注册语言切换监听器。重复注册同一 listener 不会去重（由调用方控制）。 */
    public void onChange(Consumer<Lang> listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    /**
     * 注销监听器。短生命周期组件（如会被关闭的页签）在构造期注册后必须 off，
     * 否则 CopyOnWriteArrayList 会常驻强引用链导致内存泄漏。
     */
    public void off(Consumer<Lang> listener) {
        if (listener != null) {
            listeners.remove(listener);
        }
    }

    /**
     * 清空所有订阅表和监听器：插件卸载时调用。
     * 不主动清的话：listeners 里强引用 Consumer → MainTab → 子组件，
     * 插件重载后切语言会触发旧组件的 setText 抛 NPE / 视觉错位。
     */
    public void clearAll() {
        listeners.clear();
        subscribers.clear();
        tooltipSubscribers.clear();
    }

    /** 查一段文案。key 不存在时返回 {@code !key}。 */
    public String t(String key) {
        return t(key, new Object[0]);
    }

    /** 带参数的文案，占位符用 {@code {0}}、{@code {1}} 形式。 */
    public String t(String key, Object... args) {
        ResourceBundle rb = bundles.get(current);
        if (rb == null) {
            return MISSING_PREFIX + key;
        }
        String value;
        try {
            value = rb.getString(key);
        } catch (MissingResourceException e) {
            return MISSING_PREFIX + key;
        }
        if (args == null || args.length == 0) {
            return value;
        }
        try {
            return MessageFormat.format(value, args);
        } catch (IllegalArgumentException e) {
            return value;
        }
    }

    // ========== 自动刷新组件工厂 ==========

    /** 创建一个切语言时自动 setText 的 JLabel。 */
    public static JLabel label(String key) {
        JLabel l = new JLabel(INSTANCE.t(key));
        INSTANCE.subscribers.put(new WeakReference<>(l), key);
        return l;
    }

    /** 创建一个切语言时自动 setText 的 JButton。 */
    public static JButton button(String key) {
        JButton b = new JButton(INSTANCE.t(key));
        INSTANCE.subscribers.put(new WeakReference<>(b), key);
        return b;
    }

    /** 创建一个切语言时自动 setText 的 JCheckBox。 */
    public static JCheckBox checkBox(String key) {
        JCheckBox c = new JCheckBox(INSTANCE.t(key));
        INSTANCE.subscribers.put(new WeakReference<>(c), key);
        return c;
    }

    /** 创建一个切语言时自动 setTitle 的 TitledBorder（与 BorderFactory 等价）。 */
    public static TitledBorder titledBorder(String key) {
        TitledBorder b = new TitledBorder(INSTANCE.t(key));
        INSTANCE.subscribers.put(new WeakReference<>(b), key);
        return b;
    }

    /** 让任意组件的 tooltip 跟随语言自动刷新。组件被 GC 后条目自动清理。 */
    public static void tooltip(JComponent c, String key) {
        if (c == null || key == null) {
            return;
        }
        c.setToolTipText(INSTANCE.t(key));
        INSTANCE.tooltipSubscribers.put(new WeakReference<>(c), key);
    }

    private void refreshSubscribers() {
        // 先收集要刷新 / 要清理的条目，再迭代过程中不能改 map（fail-fast）
        java.util.List<java.util.Map.Entry<WeakReference<?>, String>> toRefresh = new java.util.ArrayList<>();
        java.util.List<WeakReference<?>> toRemove = new java.util.ArrayList<>();
        for (java.util.Map.Entry<WeakReference<?>, String> e : subscribers.entrySet()) {
            Object obj = e.getKey().get();
            if (obj == null) {
                toRemove.add(e.getKey());
            } else {
                toRefresh.add(e);
            }
        }
        for (WeakReference<?> r : toRemove) {
            subscribers.remove(r);
        }
        for (java.util.Map.Entry<WeakReference<?>, String> e : toRefresh) {
            Object obj = e.getKey().get();
            String key = e.getValue();
            String value = t(key);
            try {
                if (obj instanceof JLabel lbl) {
                    lbl.setText(value);
                } else if (obj instanceof JButton btn) {
                    btn.setText(value);
                } else if (obj instanceof JCheckBox cb) {
                    cb.setText(value);
                } else if (obj instanceof TitledBorder tb) {
                    tb.setTitle(value);
                }
            } catch (RuntimeException ignored) {
                // 单个组件刷新失败不阻断其他组件
            }
        }
    }

    private void refreshTooltipSubscribers() {
        // 逻辑同 refreshSubscribers
        java.util.List<java.util.Map.Entry<WeakReference<JComponent>, String>> toRefresh = new java.util.ArrayList<>();
        java.util.List<WeakReference<JComponent>> toRemove = new java.util.ArrayList<>();
        for (java.util.Map.Entry<WeakReference<JComponent>, String> e : tooltipSubscribers.entrySet()) {
            if (e.getKey().get() == null) {
                toRemove.add(e.getKey());
            } else {
                toRefresh.add(e);
            }
        }
        for (WeakReference<JComponent> r : toRemove) {
            tooltipSubscribers.remove(r);
        }
        for (java.util.Map.Entry<WeakReference<JComponent>, String> e : toRefresh) {
            JComponent c = e.getKey().get();
            if (c == null) {
                continue;
            }
            try {
                c.setToolTipText(t(e.getValue()));
            } catch (RuntimeException ignored) {
                // 单个组件刷新失败不阻断其他组件
            }
        }
    }
}
