package crypto;

import java.io.*;
import java.nio.file.*;
import java.util.*;

import javax.crypto.spec.SecretKeySpec;

public class CryptoFactory {

    // ======== CONFIG CLASS =========
    public static class Config {
        public final String alg;
        public final int dataKeySizeBits;
        public final int macKeySizeBits;

        public Config(String alg, int dataBits, int macBits) {
            this.alg = alg;
            this.dataKeySizeBits = dataBits;
            this.macKeySizeBits = macBits;
        }

        public static Config load(Path path) throws IOException {
            Properties p = new Properties();
            try (Reader r = Files.newBufferedReader(path)) {
                p.load(r);
            }
            String alg = p.getProperty("ALG", "AES_GCM").trim().toUpperCase();
            int dataBits = Integer.parseInt(p.getProperty("DATA_KEY_SIZE", "256"));
            int macBits = Integer.parseInt(p.getProperty("MAC_KEY_SIZE", "256")); // used only for CBC+HMAC
            return new Config(alg, dataBits, macBits);
        }
    }

    // ======== FACTORY =========
    public static CryptoSuite build(Config cfg, byte[] dataKey) {
        return build(cfg, dataKey, null);
    }

    public static CryptoSuite build(Config cfg, byte[] dataKey, byte[] macKey) {
        switch (cfg.alg.toUpperCase()) {
            case "AES_GCM":
                return new AesGcmSuite(dataKey);
            case "AES_CBC_HMAC":
                if (macKey == null) throw new IllegalArgumentException("MAC key required for AES_CBC_HMAC");
                return new AesCbcHmacSuite(dataKey, macKey);
            case "CHACHA20_POLY1305":
                return new ChaCha20PolySuite(dataKey);
            default:
                throw new IllegalArgumentException("Unsupported ALG: " + cfg.alg);
        }
    }

    private static byte[] random(int n) {
        byte[] b = new byte[n];
        new java.security.SecureRandom().nextBytes(b);
        return b;
    }
}
