package com.auditai.burp;

import burp.api.montoya.MontoyaApi;
import com.auditai.burp.ai.AiException;
import com.auditai.burp.history.AnalysisHistoryStore;
import com.auditai.burp.history.AnalysisTrigger;
import com.auditai.burp.http.AnalysisResult;
import com.auditai.burp.http.FindingStore;
import com.auditai.burp.util.WorkflowLogger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.UUID;

/**
 * "分析结果落库"复合接收器：把"写问题库 + 写历史库 + 失败日志 + 审计轨迹落盘"四步合并成一个回调，
 * 让 {@link AuditAiExtension} 装配时只需要构造一次、然后在手动分析与被动分析两路
 * 共享——避免两处 lambda 复制粘贴导致日志措辞 / 失败处理漂移。
 *
 * <p>所有写库失败一律吞异常并通过 {@link MontoyaApi#logging()#logToError} 记录，
 * 不向上抛：分析主流程已结束，UI 提示已经展示，再抛异常只会污染关闭流程。</p>
 *
 * <p>线程：被 {@code TrafficAnalyzer} / {@code PassiveAnalyzer} 在分析线程回调，
 * 与 EDT 解耦；sink 自身不触碰 Swing 组件。</p>
 */
final class AnalysisResultSink {

    private final MontoyaApi api;
    private final FindingStore findingStore;
    private final AnalysisHistoryStore historyStore;
    private final AnalysisTrigger trigger;

    /**
     * @param api          Montoya API 门面（日志输出用；不可为 null）。
     * @param findingStore 全局问题库；可为 null（创建失败等场景），为 null 时跳过 finding 写入。
     * @param historyStore "历史"页签背后的已分析历史库；可为 null，行为同上。
     * @param trigger      触发来源（MANUAL / PASSIVE），传给 {@link AnalysisHistoryStore#add}。
     */
    AnalysisResultSink(MontoyaApi api, FindingStore findingStore,
                       AnalysisHistoryStore historyStore, AnalysisTrigger trigger) {
        this.api = Objects.requireNonNull(api, "api");
        this.findingStore = findingStore;
        this.historyStore = historyStore;
        this.trigger = Objects.requireNonNull(trigger, "trigger");
    }

    /**
     * 处理一条分析结果：写问题库 + 写历史库，IO 失败仅记日志。
     *
     * @param result         本次分析的结果（成功 / 失败 / 取消均可能）。
     * @param requestBytes   本次分析使用的原始请求字节；可空（取自被动分析拦截器或编辑器）。
     * @param responseBytes  本次分析使用的原始响应字节；可空。
     */
    void accept(AnalysisResult result, byte[] requestBytes, byte[] responseBytes) {
        if (result == null) {
            return;
        }
        // 取消路径不写问题库 / 历史库：
        // 1. 取消的 finding 集合为空，避免给用户留一条"已取消"的伪记录；
        // 2. "分析已取消"是用户主动中断，不是真正的分析产出，不该污染历史。
        //    同样地，此时 in-memory 的 WorkflowLogger 缓冲也无须落盘——它会随线程下次复用
        //    被 GC，无需显式清理。
        if (AiException.isCancelledMessage(result.getError())) {
            return;
        }
        if (findingStore != null) {
            findingStore.addFindings(result, requestBytes, responseBytes);
        }
        if (historyStore != null) {
            // 先把审计轨迹 XML 落盘到 audit-trails/；失败仅记日志，不阻塞 history 入库。
            Path auditTrailFile = null;
            WorkflowLogger logger = WorkflowLogger.current();
            if (logger != null) {
                auditTrailFile = writeAuditTrail(logger, historyStore.auditTrailsDirectory());
            }
            try {
                // add 返回 -1 表示"库已关闭（插件卸载竞态），未入库"——此时上面写的 audit-trail
                // 就成了无人引用的孤儿文件（容量淘汰 / 删除都只处理被 entry 引用的文件），
                // 必须立刻物理删除，否则每卸载一次就泄漏一个 XML。
                long entryId = historyStore.add(result, trigger, requestBytes, responseBytes, auditTrailFile);
                if (entryId < 0) {
                    deleteOrphan(auditTrailFile);
                }
            } catch (IOException ioe) {
                String label = trigger == AnalysisTrigger.PASSIVE ? "被动分析" : "手动分析";
                api.logging().logToError("AuditAI " + label + "历史落盘失败：" + ioe.getMessage(), ioe);
                // entry 未入库：对应的 audit-trail 已成为孤儿，立即物理删除。
                deleteOrphan(auditTrailFile);
            }
        }
    }

    /**
     * 把当前线程绑定的 logger 缓冲落盘到 {@code <auditTrailsDir>/<uuid>.xml}。
     * 落盘失败仅记日志并返回 null（不抛给调用方）。
     */
    private Path writeAuditTrail(WorkflowLogger logger, Path auditTrailsDir) {
        try {
            Files.createDirectories(auditTrailsDir);
            Path target = auditTrailsDir.resolve(UUID.randomUUID() + ".xml");
            logger.writeTo(target);
            return target;
        } catch (IOException e) {
            api.logging().logToError("AuditAI 审计轨迹 XML 落盘失败：" + e.getMessage(), e);
            return null;
        }
    }

    /** 孤儿文件清理：add 未入库（抛错或返回 -1）时 audit-trail 已写但 entry 不存在，需要物理删。 */
    private void deleteOrphan(Path file) {
        if (file == null) {
            return;
        }
        try {
            Files.deleteIfExists(file);
        } catch (IOException e) {
            // best-effort：失败时留作孤儿。本类约定"所有写库失败都记日志"，这里同样不静默。
            api.logging().logToError("AuditAI 清理孤儿审计轨迹失败：" + file + "：" + e.getMessage(), e);
        }
    }
}
