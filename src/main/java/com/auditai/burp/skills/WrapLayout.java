package com.auditai.burp.skills;

import javax.swing.JPanel;
import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Insets;
import java.awt.event.HierarchyEvent;
import java.awt.event.HierarchyListener;
import java.io.Serial;

/**
 * 横向流动、超出宽度自动换行的布局。
 *
 * <p>JDK 自带的 {@link FlowLayout} 只支持单行，超出后直接裁切；
 * {@link java.awt.GridLayout} 会强制拉伸每个 cell。本类在 FlowLayout 的基础上
 * 累计当前行剩余宽度，放不下时换到下一行（gap 与容器边距沿用 FlowLayout 设置）。</p>
 *
 * <p>代码改自社区常见的 WrapLayout 实现（https://github.com/timthom/ WrapLayout 思路），
 * 简化到只保留 AuditAI 需要的部分。</p>
 */
public final class WrapLayout extends FlowLayout {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * @param hgap 组件之间以及容器边缘的水平间距。
     * @param vgap 组件之间以及容器边缘的垂直间距。
     */
    public WrapLayout(int hgap, int vgap) {
        // 本项目只用到左对齐换行（技能卡片网格）；固定 LEFT 免去"对齐值可能传错"的隐患。
        super(FlowLayout.LEFT, hgap, vgap);
    }

    @Override
    public Dimension preferredLayoutSize(Container target) {
        return layoutSize(target, true);
    }

    @Override
    public Dimension minimumLayoutSize(Container target) {
        return layoutSize(target, false);
    }

    /** 按容器当前可用宽度分行累积，返回整组组件所需尺寸。 */
    private Dimension layoutSize(Container target, boolean preferred) {
        synchronized (target.getTreeLock()) {
            int targetWidth = target.getSize().width;
            if (targetWidth == 0) {
                // 容器尚未完成布局：先按 int 最大宽度模拟"单行"——避免拿 0 算出来一行只放一个组件
                targetWidth = Integer.MAX_VALUE;
            }
            Insets insets = target.getInsets();
            int horizontalPadding = insets.left + insets.right + getHgap() * 2;
            int maxWidth = targetWidth - horizontalPadding;

            int x = 0;
            int y = insets.top + getVgap();
            int rowHeight = 0;
            int totalWidth = 0;

            for (Component component : target.getComponents()) {
                if (!component.isVisible()) {
                    continue;
                }
                Dimension size = preferred
                        ? component.getPreferredSize()
                        : component.getMinimumSize();

                // 当前行剩余宽度放不下时换行
                if (x > 0 && x + size.width > maxWidth) {
                    totalWidth = Math.max(totalWidth, x);
                    x = 0;
                    y += rowHeight + getVgap();
                    rowHeight = 0;
                }

                x += size.width + getHgap();
                rowHeight = Math.max(rowHeight, size.height);
            }

            totalWidth = Math.max(totalWidth, x);
            int totalHeight = y + rowHeight + getVgap() + insets.bottom;
            return new Dimension(totalWidth + horizontalPadding, totalHeight);
        }
    }

    @Override
    public void layoutContainer(Container target) {
        synchronized (target.getTreeLock()) {
            Insets insets = target.getInsets();
            int maxWidth = target.getWidth() - (insets.left + insets.right + getHgap() * 2);

            int x = insets.left + getHgap();
            int y = insets.top + getVgap();
            int rowHeight = 0;

            for (Component component : target.getComponents()) {
                if (!component.isVisible()) {
                    continue;
                }
                Dimension size = component.getPreferredSize();

                if (x > insets.left + getHgap() && x + size.width > maxWidth + insets.left + getHgap()) {
                    x = insets.left + getHgap();
                    y += rowHeight + getVgap();
                    rowHeight = 0;
                }

                component.setBounds(x, y, size.width, size.height);
                x += size.width + getHgap();
                rowHeight = Math.max(rowHeight, size.height);
            }
        }
    }

    // —— Scrollable 由容器自身（JPanel）实现，本类只做布局 ——

    /**
     * Burp Suite Tab 的尺寸可能在切换页签后才被正确设置，构造期算出的 preferredLayoutSize = 0，
     * 导致 WrapLayout 退化成"一行一个组件"。给容器加一个层级监听，尺寸变化时重算 preferredSize。
     */
    public static void install(JPanel target) {
        target.addHierarchyListener(new HierarchyListener() {
            @Override
            public void hierarchyChanged(HierarchyEvent e) {
                if ((e.getChangeFlags() & HierarchyEvent.SHOWING_CHANGED) != 0 && target.isShowing()) {
                    target.revalidate();
                }
            }
        });
    }
}
