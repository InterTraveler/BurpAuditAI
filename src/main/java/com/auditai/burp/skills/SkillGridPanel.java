package com.auditai.burp.skills;

import javax.swing.JPanel;
import javax.swing.Scrollable;
import java.awt.Dimension;
import java.awt.Rectangle;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.io.Serial;

/**
 * 技能卡片容器：使用 {@link WrapLayout} 自动换行排版技能卡片，
 * 自身实现 {@link Scrollable} 以与 {@link javax.swing.JScrollPane} 良好配合。
 *
 * <p>滚动行为：</p>
 * <ul>
 *   <li>水平方向：<b>跟随视口宽度</b>，让 {@link WrapLayout} 用真实宽度算出每行能放几个卡片；
 *       同时禁用水平滚动条——一行放不下就换行；</li>
 *   <li>垂直方向：<b>由内容自然撑高</b>（不跟随视口），多行总高度超出视口时由
 *       JScrollPane 自动出垂直滚动条；</li>
 *   <li>滚轮步进：单步 = 32 像素，整屏 = 视口高度。</li>
 * </ul>
 *
 * <p>Burp Suite Tab 的实际尺寸要等用户切到该页签后才被正确设置，因此
 * 通过 {@link WrapLayout#install(JPanel)} 挂一个层级监听，
 * 首次显示时强制 revalidate，让换行计算拿到真实的容器宽度。</p>
 */
public final class SkillGridPanel extends JPanel implements Scrollable {

    @Serial
    private static final long serialVersionUID = 1L;

    /** 卡片之间、卡片与容器边的水平/垂直间距（像素）。 */
    private static final int GAP = 12;

    public SkillGridPanel() {
        super(new WrapLayout(GAP, GAP));
        WrapLayout.install(this);
        // 拉窗口 / 切页签时容器宽度会变：触发 revalidate 让 WrapLayout 重算"一行几个"和总高度，
        // 否则窄窗口下卡片会被裁切、宽窗口下会留出大块空白。
        addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                revalidate();
            }
        });
    }

    @Override
    public Dimension getPreferredScrollableViewportSize() {
        return getPreferredSize();
    }

    @Override
    public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
        return orientation == javax.swing.SwingConstants.VERTICAL ? 32 : 64;
    }

    @Override
    public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
        return orientation == javax.swing.SwingConstants.VERTICAL ? visibleRect.height : visibleRect.width;
    }

    @Override
    public boolean getScrollableTracksViewportWidth() {
        // true → 容器宽度跟随视口，WrapLayout 才能拿到真实宽度算"一行几个"。
        return true;
    }

    @Override
    public boolean getScrollableTracksViewportHeight() {
        // false → 容器高度 = 自己的 preferredSize（多行卡片总高），
        // 超过视口时 JScrollPane 才会出垂直滚动条。
        return false;
    }
}
