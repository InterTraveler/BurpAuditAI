package com.auditai.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import com.auditai.burp.http.HttpResponseLookup;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * 上下文菜单提供器：让用户在其他模块（Proxy 历史、Repeater、Intruder 等）
 * 右键选中的报文一键发送到本插件分析页，菜单项名称为 <b>"Send to AuditAI"</b>，
 * 与 Burp 内置的 "Send to Repeater / Send to Intruder" 命名风格一致。
 *
 * <p>实现说明：</p>
 * <ul>
 *   <li><b>菜单位置</b>：Burp 会把扩展提供的菜单项自动附加在内置菜单
 *       （Send to Repeater 等）下方（分隔线之下），因此无需额外 API 控制位置；
 *       本插件只提供一个菜单项，保持与内置项一致的视觉分组；</li>
 *   <li><b>响应回补</b>：Montoya 的 {@link ContextMenuEvent#selectedRequestResponses()}
 *       在 Repeater、Intruder、原始 Request 编辑器等场景下返回的 {@link HttpRequestResponse}
 *       可能只含请求不含响应（响应在另一 Tab / 另一字段）。这种情况下会尝试从
 *       {@code api.proxy().history()} 反查匹配项（URL + Method 匹配），补回响应。
 *       Proxy 历史表本身右键时已含完整 pair，无需反查；</li>
 *   <li>点击后把选中的报文交给 {@link MainTab#acceptMessage(HttpRequestResponse)}，
 *       由分析页负责填入编辑器并切换页签；</li>
 *   <li>接口的其他两个默认方法（WebSocket / 审计问题上下文）保持默认空实现。</li>
 * </ul>
 */
public final class SendToAuditAiMenuProvider implements ContextMenuItemsProvider {

    /** Burp API 门面：用于从 Proxy 历史反查响应。 */
    private final MontoyaApi api;

    /** 插件主界面：接收报文并切换到分析页。 */
    private final MainTab mainTab;

    /**
     * @param api     Burp API 门面（用于在响应缺失时从 Proxy 历史反查）。
     * @param mainTab 插件主界面。
     */
    public SendToAuditAiMenuProvider(MontoyaApi api, MainTab mainTab) {
        this.api = api;
        this.mainTab = mainTab;
    }

    /**
     * 提供右键菜单项：当前选中了报文时返回 "Send to AuditAI"。
     *
     * @param event 上下文菜单事件（含选中的报文列表）。
     * @return 菜单组件列表；无选中报文时返回空列表（不显示菜单项）。
     */
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        // 只做"是否有选中报文"的廉价判断：selectedMessage() 内部会在响应缺失时做
        // Proxy 历史反查（最多遍历 5000 条并逐条取 request/response），而本回调是在
        // Burp 构建右键菜单时于 EDT 上执行的——即使用户根本不点这一项，也会白等一次
        // 全量反查。因此把真正的解析推迟到点击时。
        if (pickFromEvent(event) == null) {
            return Collections.emptyList();
        }

        // 命名与 Burp 内置 "Send to Repeater / Send to Intruder" 保持一致
        JMenuItem sendItem = new JMenuItem(I18n.get().t("ui.menu.sendToAuditAi"));
        // 取第一条选中报文（多选场景后续可扩展为批量入列）
        sendItem.addActionListener(e -> {
            HttpRequestResponse message = selectedMessage(event);
            if (message != null) {
                mainTab.acceptMessage(message);
            }
        });
        return Collections.singletonList(sendItem);
    }

    /**
     * 从当前右键事件中解析要发送的报文，并补全缺失的响应。
     *
     * <p>取值优先级：</p>
     * <ol>
     *   <li>从 {@link ContextMenuEvent#selectedRequestResponses()} 取第一条；</li>
     *   <li>若列表为空（编辑器内部右键等场景），回退到
     *       {@link ContextMenuEvent#messageEditorRequestResponse()}；</li>
     *   <li>若结果中的 {@code response} 为空（Repeater Request tab 等场景），
     *       从 {@code api.proxy().history()} 按 URL + Method 匹配反查，
     *       找到包含完整响应的副本替换；</li>
     *   <li>仍然没有响应：原样返回（不阻断；用户可能只粘贴了请求）。</li>
     * </ol>
     *
     * @param event 上下文菜单事件。
     * @return 要发送的报文（含响应或不含）；当前上下文没有报文时返回 null。
     */
    private HttpRequestResponse selectedMessage(ContextMenuEvent event) {
        HttpRequestResponse message = pickFromEvent(event);
        if (message == null) {
            return null;
        }
        // 响应缺失：从 Burp Proxy 历史按 URL + Method 反查补回。
        // 反查逻辑统一在 HttpResponseLookup 里，HttpHistoryPanel 也用同一份。
        if (isResponseMissing(message)) {
            HttpRequest request = message.request();
            // 拿到的 request 可能为 null（极端 Montoya 实现）：null 跳过
            if (request != null) {
                HttpResponse lookedUp = HttpResponseLookup.lookupResponse(api, request).orElse(null);
                if (lookedUp != null) {
                    // 重新组装 HttpRequestResponse：保留原 request、把缺失的 response 补上
                    return HttpRequestResponse.httpRequestResponse(request, lookedUp);
                }
            }
        }
        return message;
    }

    /** 按"selectedRequestResponses → messageEditorRequestResponse"顺序取第一条。 */
    private HttpRequestResponse pickFromEvent(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        if (selected != null && !selected.isEmpty()) {
            return selected.get(0);
        }
        Optional<MessageEditorHttpRequestResponse> editorMessage = event.messageEditorRequestResponse();
        return editorMessage.map(MessageEditorHttpRequestResponse::requestResponse).orElse(null);
    }

    /**
     * 判断响应是否缺失。
     *
     * <p>Montoya 2026.7 的 {@code response()} 可能为 null（无响应），
     * 也可能是一个"空对象"（toByteArray 长度为 0，如编辑器刚初始化的占位响应）。两种情况都视为缺失。</p>
     */
    private static boolean isResponseMissing(HttpRequestResponse message) {
        try {
            if (message.response() == null) {
                return true;
            }
            return message.response().toByteArray().length() == 0;
        } catch (RuntimeException e) {
            // 极少数 Montoya 实现可能在 response() 抛异常，保守起见当作缺失处理，让反查补上
            return true;
        }
    }
}
