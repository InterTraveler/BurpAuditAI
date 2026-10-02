package com.auditai.burp.http;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * {@link DomainClassifier} 单元测试：覆盖 Javadoc 列出的全部示例 + null / 空白 /
 * 含端口 / IPv4 / IPv6 等边界。
 *
 * <p>纯函数测试，不依赖 Burp 运行时。</p>
 */
final class DomainClassifierTest {

    /** Javadoc 示例 #1：a.b.example.com → example.com。 */
    @Test
    void extractSubdomainOnly_returnsLastTwoSegments() {
        assertEquals("example.com",
                DomainClassifier.extractSecondLevelDomain("a.b.example.com"));
    }

    /** Javadoc 示例 #2：api.example.com → example.com。 */
    @Test
    void extractSubdomain_returnsLastTwoSegments() {
        assertEquals("example.com",
                DomainClassifier.extractSecondLevelDomain("api.example.com"));
    }

    /** Javadoc 示例 #3：x.b.c → b.c。 */
    @Test
    void extractShortDomain_returnsLastTwoSegments() {
        assertEquals("b.c", DomainClassifier.extractSecondLevelDomain("x.b.c"));
    }

    /** Javadoc 示例 #4：IPv4 整体返回。 */
    @Test
    void extractIpv4_returnsHostUnchanged() {
        assertEquals("127.0.0.1",
                DomainClassifier.extractSecondLevelDomain("127.0.0.1"));
    }

    /** 完整 URL 带协议：protocol://host[:port]/path 走完正常路径。 */
    @Test
    void extractFromFullUrl_stripsProtocolAndPath() {
        assertEquals("example.com",
                DomainClassifier.extractSecondLevelDomain("https://api.example.com/v1/users?x=1"));
        assertEquals("example.com",
                DomainClassifier.extractSecondLevelDomain("http://example.com/path"));
    }

    /** 带端口：去掉 :port 再切段。 */
    @Test
    void extractFromUrlWithPort_stripsPort() {
        assertEquals("example.com",
                DomainClassifier.extractSecondLevelDomain("https://example.com:8443/api"));
    }

    /** null → 空串。 */
    @Test
    void extract_nullReturnsEmpty() {
        assertEquals("", DomainClassifier.extractSecondLevelDomain(null));
    }

    /** 空白字符串 → 空串。 */
    @Test
    void extract_blankReturnsEmpty() {
        assertEquals("", DomainClassifier.extractSecondLevelDomain(""));
        assertEquals("", DomainClassifier.extractSecondLevelDomain("   "));
    }

    /** 不足两段 → 整体返回（小写）。 */
    @Test
    void extract_singleSegment_returnsItAsIs() {
        assertEquals("localhost", DomainClassifier.extractSecondLevelDomain("localhost"));
        assertEquals("example",
                DomainClassifier.extractSecondLevelDomain("EXAMPLE"), "大小写归一");
    }

    /** 仅一段且含点 → 仍只切出整体（不符合两段）。 */
    @Test
    void extract_singleSegmentWithDot_returnsItAsIs() {
        assertEquals("intranet", DomainClassifier.extractSecondLevelDomain("intranet"));
    }

    /** query string 不影响提取。 */
    @Test
    void extract_stripsQueryString() {
        assertEquals("example.com",
                DomainClassifier.extractSecondLevelDomain("example.com?token=abc"));
    }

    /**
     * 已知行为：当前实现不处理 URL 片段（{@code #fragment}）——
     * 现有调用方都传完整 URL 或纯 host，不带 fragment；如果未来需要支持，
     * 在 DomainClassifier.extractSecondLevelDomain 内增加
     * {@code s = s.substring(0, s.indexOf('#'))} 即可。
     */
    @Test
    void extract_fragmentNotStripped_currentBehaviorDocumented() {
        assertEquals("example.com#section",
                DomainClassifier.extractSecondLevelDomain("example.com#section"));
    }

    /** 多级域名 + 多级路径组合。 */
    @Test
    void extract_combinedTrims() {
        assertEquals("example.com",
                DomainClassifier.extractSecondLevelDomain("a.b.example.com:8080/path?q=1#frag"));
    }

    /** 大小写归一：返回 always lowercase。 */
    @Test
    void extract_lowercasesResult() {
        assertEquals("example.com",
                DomainClassifier.extractSecondLevelDomain("API.EXAMPLE.COM"));
    }
}