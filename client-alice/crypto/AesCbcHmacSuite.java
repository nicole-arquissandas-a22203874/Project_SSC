package crypto;



import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.*;
import java.io.*;

public class AesCbcHmacSuite implements CryptoSuite {

    private static final int IV_LEN = 16; // AES block size (CBC)
    private final byte[] encKey;
    private final byte[] macKey;

    public AesCbcHmacSuite(byte[] encKey, byte[] macKey) {
        this.encKey = Arrays.copyOf(encKey, encKey.length);
        this.macKey = Arrays.copyOf(macKey, macKey.length);
    }

    @Override
    public byte[] encrypt(byte[] plaintext, byte[] aad) {
        try {
            // 1. Generate IV
            byte[] iv = new byte[IV_LEN];
            new SecureRandom().nextBytes(iv);

            // 2. Encrypt using AES/CBC/PKCS5Padding
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec aesKey = new SecretKeySpec(encKey, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
            byte[] ciphertext = cipher.doFinal(plaintext);

            // 3. Compute HMAC over (AAD || IV || ciphertext)
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(macKey, "HmacSHA256"));
            mac.update(aad);
            mac.update(iv);
            mac.update(ciphertext);
            byte[] tag = mac.doFinal();

            // 4. Return iv || ciphertext || tag
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(iv);
            out.write(ciphertext);
            out.write(tag);
            return out.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("AES-CBC-HMAC encrypt failed", e);
        }
    }

    @Override
    public byte[] decrypt(byte[] blob, byte[] aad) {
        try {
            // Split blob: iv || ciphertext || tag
            if (blob.length < IV_LEN + 32) throw new IllegalArgumentException("Ciphertext too short");
            int tagPos = blob.length - 32;
            byte[] iv = Arrays.copyOfRange(blob, 0, IV_LEN);
            byte[] ciphertext = Arrays.copyOfRange(blob, IV_LEN, tagPos);
            byte[] tag = Arrays.copyOfRange(blob, tagPos, blob.length);

            // Verify HMAC
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(macKey, "HmacSHA256"));
            mac.update(aad);
            mac.update(iv);
            mac.update(ciphertext);
            byte[] expected = mac.doFinal();
            if (!MessageDigest.isEqual(tag, expected))
                throw new SecurityException("HMAC verification failed");

            // Decrypt
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec aesKey = new SecretKeySpec(encKey, "AES");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new RuntimeException("AES-CBC-HMAC decrypt failed", e);
        }
    }
}

