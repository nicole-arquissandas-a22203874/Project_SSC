package iam.crypto;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

public class PasswordUtil {

    public static final String ALG = "PBKDF2WithHmacSHA256";
    public static final int DEFAULT_ITER = 150_000; // slow
    public static final int SALT_LEN = 16;
    public static final int KEY_LEN  = 256; // bits

    public static class PasswordRecord {
        public final int iterations;
        public final byte[] salt;
        public final byte[] key;
        public PasswordRecord(int iterations, byte[] salt, byte[] key) {
            this.iterations = iterations;
            this.salt = salt;
            this.key  = key;
        }
    }

    public static PasswordRecord deriveFromPassword(char[] password) throws GeneralSecurityException {
        byte[] salt = new byte[SALT_LEN];
        new SecureRandom().nextBytes(salt);
        int iters = DEFAULT_ITER;
        byte[] key = pbkdf2(password, salt, iters);
        return new PasswordRecord(iters, salt, key);
    }

    private static byte[] pbkdf2(char[] pwd, byte[] salt, int iters) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(pwd, salt, iters, KEY_LEN);
        SecretKeyFactory skf = SecretKeyFactory.getInstance(ALG);
        return skf.generateSecret(spec).getEncoded();
    }

    public static String encodeRecord(PasswordRecord rec) {
        return "PBKDF2$" + rec.iterations + "$" +
                Base64.getEncoder().encodeToString(rec.salt) + "$" +
                Base64.getEncoder().encodeToString(rec.key);
    }

    public static PasswordRecord decodeRecord(String s) {
        String[] parts = s.split("\\$");
        if (parts.length != 4 || !"PBKDF2".equals(parts[0])) {
            throw new IllegalArgumentException("Invalid password record");
        }
        int iters = Integer.parseInt(parts[1]);
        byte[] salt = Base64.getDecoder().decode(parts[2]);
        byte[] key  = Base64.getDecoder().decode(parts[3]);
        return new PasswordRecord(iters, salt, key);
    }

    public static byte[] deriveKeyForAuth(char[] password, PasswordRecord rec) throws GeneralSecurityException {
        return pbkdf2(password, rec.salt, rec.iterations);
    }
}
