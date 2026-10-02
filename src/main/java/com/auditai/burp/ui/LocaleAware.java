package com.auditai.burp.ui;

/**
 * 标记"需要响应语言切换"的 Swing 组件。
 *
 * <p>契约：实现类在构造期把自己注册到 {@link I18n#onChange}，并在销毁时注销
 * （{@code I18n.off}），由 {@link I18n} 广播语言切换事件；容器类（如
 * {@code SkillsPanel}）也可以按类型遍历自己的子组件代为转发。
 * 实现内部应只做 setText / setToolTipText / setTitle / rebuild 等轻量操作,
 * 不要在刷新回调里 add/remove 组件以避免 EDT 重入异常。</p>
 */
public interface LocaleAware {
    void refreshI18n();
}
