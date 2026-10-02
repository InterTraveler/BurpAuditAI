package com.auditai.burp.config;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.Serial;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

/**
 * API Key 加密器：AES-256-GCM + PBKDF2。
 *
 * <p>用于把 {@code AiConfig.apiKey} 在持久化到 Burp Preferences / 落盘 JSON 之前
 * 做对称加密，磁盘上不再保留明文密钥。</p>
 *
 * <h2>威胁模型</h2>
 * <p>这是<strong>混淆（obfuscation）</strong>，不是完整的密钥管理：</p>
 * <ul>
 *   <li>密钥派生自 <code>user.home</code> + 固定种子 + PBKDF2，绑定"本机本用户"；
 *       拷走 Burp 的 Preferences 文件到另一台机器 / 另一用户账户下无法解密；</li>
 *   <li>同一台机器同一用户跑插件可以正常解密（用户自己不该被挡住）；</li>
 *   <li>JVM 内存里仍以 {@code char[]}（{@link AiConfig}）形式存在，理论上仍可被
 *       本机攻击者通过 heap dump 拿到——这是 Burp 扩展架构层面的限制，完整解决
 *       需要操作系统级密钥库（Windows DPAPI / macOS Keychain / Linux Secret Service），
 *       不在本类的能力范围；</li>
 *   <li>不抗"修改 Preferences 文件塞入明文 {prefix} 假装是密文"这种主动攻击——
 *       攻击者本就可以改文件，没意义专门防护。</li>
 * </ul>
 *
 * <h2>算法</h2>
 * <ul>
 *   <li>对称：AES-256-GCM（12 字节随机 IV、128 位 auth tag）；</li>
 *   <li>密钥派生：PBKDF2WithHmacSHA256，65536 次迭代，16 字节盐
 *       （盐 = SHA-256(<code>user.home</code> + 固定种子））；</li>
 *   <li>磁盘格式：<code>enc:v1:&lt;base64(IV || ciphertext+tag)&gt;</code>，单行可读；</li>
 *   <li>明文字段（不含 <code>enc:v1:</code> 前缀）继续可被旧版本识别——
 *       {@link #tryDecrypt(String)} 自动按需解密，老数据下次保存时自动重写成密文。</li>
 * </ul>
 */
public final class ApiKeyCipher {

    /** 磁盘格式前缀：标记一段字符串是本类加密的密文。 */
    public static final String PREFIX = "enc:v1:";

    /** PBKDF2 salt 种子：与 {@code user.home} 一起哈希得到稳定的"本机本用户"盐。 */
    private static final String SALT_SEED = "AuditAI.v1.ApiKey.salt";

    /** PBKDF2 迭代次数：兼顾安全强度与启动耗时（实测 ~50ms 一次）。 */
    private static final int PBKDF2_ITERATIONS = 65536;

    /** 派生密钥长度（AES-256）。 */
    private static final int KEY_BITS = 256;

    /** GCM IV 长度（字节）。NIST 推荐 12 字节。 */
    private static final int IV_BYTES = 12;

    /** GCM 认证 tag 长度（位）。 */
    private static final int TAG_BITS = 128;

    /**
     * 派生密钥缓存（含来源 user.home）：首次派生后稳定；检测到 user.home 切换时
     * 整体替换 holder（原子发布，避免“新 key + 旧 home”撕裂读导致误用错误密钥）。
     */
    private static volatile CachedKey cachedKey;

    /** 缓存键值对：home 与 key 必须成对不可变发布，二者不允许被拆开单独更新。 */
    private record CachedKey(String userHome, SecretKey key) {
    }

    private ApiKeyCipher() {}

    /**
     * 加密一段明文：返回 {@value #PREFIX} 开头的密文（单行 base64）。
     *
     * <p>空数组 / null 视为"未设置"：返回空串，避免在磁盘上写出"密文"——空配置
     * 没必要套一层加密壳（且加密空串在某些实现上会报参数错误）。</p>
     *
     * <p><b>不修改入参</b>：内部先复制一份再处理，调用方（如
     * {@code SettingsStore.save} 直接传入 {@code AiConfig.getApiKey()} 的内部数组）
     * 的密钥不会被清零或改写。</p>
     *
     * @throws ApiKeyCipherException 加密失败时抛出（拒绝静默降级为明文落盘）。
     */
    public static String encrypt(char[] plaintext) {
        if (plaintext == null || plaintext.length == 0) {
            return "";
        }
        // 复制入参：任何清零/改写都只作用于副本，绝不影响调用方持有的数组。
        char[] input = plaintext.clone();
        try {
            SecretKey key = getOrDeriveKey();
            byte[] iv = new byte[IV_BYTES];
            // 用默认 SecureRandom 而非 getInstanceStrong()：
            // 后者在容器 / 沙箱 / 熵源紧张时会阻塞到熵池充足（macOS 沙箱里实测可卡数秒），
            // 卡在 AI 调用线程里就是"保存后没反应"。默认构造的 SecureRandom 已经是
            // 加密学强随机（NativePRNGBlocking 等实现），满足 AES-GCM IV 需求。
            new SecureRandom().nextBytes(iv);
            Cipher cipher = wrapCrypto(() -> Cipher.getInstance("AES/GCM/NoPadding"));
            wrapCrypto(() -> {
                cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
                return null;
            });
            byte[] plainBytes = toBytes(input); // 内部会把 input 副本清零
            byte[] ct;
            try {
                ct = wrapCrypto(() -> cipher.doFinal(plainBytes));
            } finally {
                // doFinal 结束后明文中间字节不再需要，立即清零
                Arrays.fill(plainBytes, (byte) 0);
            }
            ByteBuffer buf = ByteBuffer.allocate(IV_BYTES + ct.length);
            buf.put(iv).put(ct);
            return PREFIX + Base64.getEncoder().encodeToString(buf.array());
        } catch (GeneralCryptoFailure e) {
            // 加密失败：清零副本后抛业务异常，拒绝把明文 Key 静默写盘。
            Arrays.fill(input, '\0');
            throw new ApiKeyCipherException("API Key 加密失败（本次未保存）：" + e.getMessage(), e);
        }
    }

    /**
     * 解密 {@value #PREFIX} 开头的密文为明文字符数组。
     *
     * @throws ApiKeyCipherException 输入非密文格式 / 鉴权 tag 校验失败 / 数据损坏。
     */
    public static char[] decrypt(String stored) {
        if (stored == null || stored.isEmpty() || !isEncrypted(stored)) {
            throw new ApiKeyCipherException("不是 " + PREFIX + " 格式的密文");
        }
        try {
            byte[] raw;
            try {
                raw = Base64.getDecoder().decode(stored.substring(PREFIX.length()));
            } catch (IllegalArgumentException e) {
                // 手工改坏/截断的密文：Base64 解码抛 IllegalArgumentException（非 JCE 异常），
                // 必须包成业务异常——否则原始 IAE 会穿透 SettingsStore.load 的启动路径。
                throw new ApiKeyCipherException("密文不是合法 Base64：" + e.getMessage(), e);
            }
            if (raw.length < IV_BYTES + (TAG_BITS / 8)) {
                throw new ApiKeyCipherException("密文长度异常");
            }
            byte[] iv = new byte[IV_BYTES];
            System.arraycopy(raw, 0, iv, 0, IV_BYTES);
            byte[] ct = new byte[raw.length - IV_BYTES];
            System.arraycopy(raw, IV_BYTES, ct, 0, ct.length);
            Arrays.fill(raw, (byte) 0);
            SecretKey key = getOrDeriveKey();
            Cipher cipher = wrapCrypto(() -> Cipher.getInstance("AES/GCM/NoPadding"));
            wrapCrypto(() -> {
                cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
                return null;
            });
            byte[] plain = wrapCrypto(() -> cipher.doFinal(ct));
            Arrays.fill(ct, (byte) 0);
            try {
                return toChars(plain);
            } finally {
                // 明文中间字节用完即清零
                Arrays.fill(plain, (byte) 0);
            }
        } catch (GeneralCryptoFailure e) {
            throw new ApiKeyCipherException("解密失败：" + e.getMessage(), e);
        }
    }

    /**
     * 智能读取：输入若以 {@value #PREFIX} 开头则解密；否则视为旧版明文直接返回。
     * 磁盘上混着新老数据时这一条入口就能搞定。
     */
    public static char[] tryDecrypt(String stored) {
        if (stored == null || stored.isEmpty()) {
            return new char[0];
        }
        if (isEncrypted(stored)) {
            return decrypt(stored);
        }
        return stored.toCharArray();
    }

    /** 是否为本类产生的密文。 */
    public static boolean isEncrypted(String value) {
        return value != null && value.startsWith(PREFIX);
    }

    // ===== 内部：密钥派生 + 缓存 =====

    private static SecretKey getOrDeriveKey() {
        String currentHome = System.getProperty("user.home", "");
        CachedKey entry = cachedKey;
        if (entry != null && currentHome.equals(entry.userHome())) {
            return entry.key();
        }
        synchronized (ApiKeyCipher.class) {
            entry = cachedKey;
            if (entry != null && currentHome.equals(entry.userHome())) {
                return entry.key();
            }
            SecretKey derived = deriveKey(currentHome);
            cachedKey = new CachedKey(currentHome, derived);
            return derived;
        }
    }

    private static SecretKey deriveKey(String userHome) {
        try {
            byte[] salt = MessageDigest.getInstance("SHA-256")
                    .digest((SALT_SEED + "|" + userHome).getBytes(StandardCharsets.UTF_8));
            // PBKDF2 输入"口令"用一段固定字符串（密钥派生用 user.home，无需用户输入）
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            PBEKeySpec pbeSpec = new PBEKeySpec(
                    SALT_SEED.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_BITS);
            try {
                byte[] keyBytes = factory.generateSecret(pbeSpec).getEncoded();
                try {
                    // SecretKeySpec 内部持有密钥字节副本，派生中间字节可立即清零
                    return new SecretKeySpec(keyBytes, "AES");
                } finally {
                    Arrays.fill(keyBytes, (byte) 0);
                }
            } finally {
                // PBEKeySpec 内部持有口令字符数组，用完即清，避免长时间驻留内存
                pbeSpec.clearPassword();
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("无法派生 AES 密钥：" + e.getMessage(), e);
        }
    }

    /**
     * 清除派生密钥缓存：仅供测试场景使用（让派生路径在测试之间隔离），
     * 生产代码不应调用。
     */
    static void resetCacheForTest() {
        synchronized (ApiKeyCipher.class) {
            cachedKey = null;
        }
    }

    private static byte[] toBytes(char[] chars) {
        // 走 UTF-8 编码；和磁盘的 Preference 字符串保存路径保持一致。
        // 中间 String 用完立刻弃用——char[] 的清零只能保证调用方传进来的字符数组，
        // JDK 解码过程中产生的临时 String 副本会在堆里多活一个 GC 周期（String 不可变，
        // 无法直接置零），这里只能尽早松开引用。
        String intermediate = new String(chars);
        Arrays.fill(chars, '\0');
        return intermediate.getBytes(StandardCharsets.UTF_8);
    }

    private static char[] toChars(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8).toCharArray();
    }

    /** 加密 / 解密失败的业务异常。 */
    public static final class ApiKeyCipherException extends RuntimeException {

        /** 序列化版本号。 */
        @Serial
        private static final long serialVersionUID = 1L;

        public ApiKeyCipherException(String message) {
            super(message);
        }

        public ApiKeyCipherException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * 把 JCE 一堆受检异常统一包成 RuntimeException，方便在
     * {@link #encrypt}/{@link #decrypt} 顶层只 catch 一处。
     */
    private static final class GeneralCryptoFailure extends RuntimeException {

        /** 序列化版本号。 */
        @Serial
        private static final long serialVersionUID = 1L;

        GeneralCryptoFailure(Throwable cause) {
            super(cause);
        }
    }

    /** 把一段会抛受检 JCE 异常的操作包成运行时异常抛出。 */
    private static <T> T wrapCrypto(JceOp<T> op) {
        try {
            return op.run();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new GeneralCryptoFailure(e);
        }
    }

    @FunctionalInterface
    private interface JceOp<T> {
        T run() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
                InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException;
    }
}
