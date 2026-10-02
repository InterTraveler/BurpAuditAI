package com.auditai.burp.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link ApiKeyCipher} 单元测试：覆盖加解密往返、密文识别、tryDecrypt 兼容老明文。
 */
final class ApiKeyCipherTest {

    @BeforeEach
    @AfterEach
    void resetCache() {
        // 测试间隔离：避免上一个测试的 user.home 缓存影响下一个
        ApiKeyCipher.resetCacheForTest();
    }

    @Test
    void encryptThenDecryptRoundTrips() {
        char[] original = "sk-secret-key-12345".toCharArray();
        String stored = ApiKeyCipher.encrypt(original);
        assertNotNull(stored);
        assertTrue(ApiKeyCipher.isEncrypted(stored), "加密后应带 enc:v1: 前缀");
        assertTrue(stored.startsWith(ApiKeyCipher.PREFIX));

        char[] decrypted = ApiKeyCipher.decrypt(stored);
        assertEquals("sk-secret-key-12345", new String(decrypted));
    }

    @Test
    void encryptEmptyReturnsEmpty() {
        // 空配置不应被套上 enc:v1: 壳（避免"无密钥"也被加密显得做作）
        assertEquals("", ApiKeyCipher.encrypt(new char[0]));
        assertEquals("", ApiKeyCipher.encrypt(null));
    }

    @Test
    void isEncryptedRecognizesPrefix() {
        assertTrue(ApiKeyCipher.isEncrypted("enc:v1:abc"));
        assertFalse(ApiKeyCipher.isEncrypted("plaintext-key"));
        assertFalse(ApiKeyCipher.isEncrypted(""));
        assertFalse(ApiKeyCipher.isEncrypted(null));
    }

    @Test
    void decryptRejectsNonEncryptedString() {
        assertThrows(ApiKeyCipher.ApiKeyCipherException.class,
                () -> ApiKeyCipher.decrypt("plaintext"));
        assertThrows(ApiKeyCipher.ApiKeyCipherException.class,
                () -> ApiKeyCipher.decrypt(""));
        assertThrows(ApiKeyCipher.ApiKeyCipherException.class,
                () -> ApiKeyCipher.decrypt(null));
    }

    @Test
    void tryDecryptReturnsPlaintextForLegacyData() {
        // 老版本明文存储："enc:v1:" 前缀缺失 → 视为明文直接返回
        char[] result = ApiKeyCipher.tryDecrypt("sk-legacy-plain");
        assertEquals("sk-legacy-plain", new String(result));
    }

    @Test
    void tryDecryptReturnsEmptyForNullOrEmpty() {
        assertEquals("", new String(ApiKeyCipher.tryDecrypt(null)));
        assertEquals("", new String(ApiKeyCipher.tryDecrypt("")));
    }

    @Test
    void tryDecryptDecryptsWhenPrefixed() {
        String stored = ApiKeyCipher.encrypt("sk-real".toCharArray());
        assertEquals("sk-real", new String(ApiKeyCipher.tryDecrypt(stored)));
    }

    @Test
    void twoEncryptionsOfSamePlaintextProduceDifferentCiphertexts() {
        // IV 随机：同一明文两次加密应得到不同密文
        String a = ApiKeyCipher.encrypt("hello".toCharArray());
        String b = ApiKeyCipher.encrypt("hello".toCharArray());
        assertNotEquals(a, b, "AES-GCM 每次应使用新 IV");
        // 但两次都能解出原文
        assertEquals("hello", new String(ApiKeyCipher.decrypt(a)));
        assertEquals("hello", new String(ApiKeyCipher.decrypt(b)));
    }
}
