package com.auditai.burp.http;

import java.util.Locale;

/**
 * 提取二级域名（最后两段），用于按域聚合同源历史。
 * 示例：{@code a.b.example.com → example.com}，{@code api.example.com → example.com}，
 * IPv4 字面量（{@code 127.0.0.1}）原样返回。
 *
 * <p>MVP 限制：没引入公共后缀列表（PSL），{@code foo.com.cn} 会被归到 {@code com.cn}。
 * 绝大多数 .com / .org / .io 场景正确；要严格判定再单独加 PSL。</p>
 */
public final class DomainClassifier {

    private DomainClassifier() {}

    /**
     * @param urlOrHost 完整 URL 或纯 host；为空返回空串。
     * @return 二级域名（最后两段），IP 整体返回；无法解析返回空串。
     */
    public static String extractSecondLevelDomain(String urlOrHost) {
        if (urlOrHost == null) {
            return "";
        }
        String s = urlOrHost.trim();
        if (s.isEmpty()) {
            return "";
        }
        // 去掉协议头：只看第一个 "://" 之后的部分。
        int schemeIdx = s.indexOf("://");
        if (schemeIdx >= 0) {
            s = s.substring(schemeIdx + 3);
        }
        // 去掉路径与查询串：以第一个 "/" 或 "?" 截断。
        int pathIdx = s.indexOf('/');
        if (pathIdx >= 0) {
            s = s.substring(0, pathIdx);
        }
        int queryIdx = s.indexOf('?');
        if (queryIdx >= 0) {
            s = s.substring(0, queryIdx);
        }
        // 去掉端口：最后一个 ":"（host 不含冒号，端口才含）。
        // IPv6 字面量用 "[]" 包住，这里只处理简单场景，IPv6 不强求。
        int portIdx = s.lastIndexOf(':');
        if (portIdx > 0) {
            s = s.substring(0, portIdx);
        }
        s = s.trim();
        if (s.isEmpty()) {
            return "";
        }
        // 按 "." 切分取最后两段；不足两段时取全部。
        String[] parts = s.split("\\.");
        if (parts.length <= 1) {
            return s.toLowerCase(Locale.ROOT);
        }
        // IP 字面量：所有段都是数字（IPv4），直接返回整体。
        if (isIpv4(parts)) {
            return s.toLowerCase(Locale.ROOT);
        }
        return (parts[parts.length - 2] + "." + parts[parts.length - 1])
                .toLowerCase(Locale.ROOT);
    }

    /** 判断拆分后的 host 段是否全部是数字（即 IPv4 字面量）。 */
    private static boolean isIpv4(String[] parts) {
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            if (part.isEmpty()) {
                return false;
            }
            for (int i = 0; i < part.length(); i++) {
                if (!Character.isDigit(part.charAt(i))) {
                    return false;
                }
            }
        }
        return true;
    }
}
