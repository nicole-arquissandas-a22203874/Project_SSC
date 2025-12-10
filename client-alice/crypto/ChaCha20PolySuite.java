package crypto;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.*;
import java.io.*;

public class ChaCha20PolySuite implements CryptoSuite {

    private static final int NONCE_LEN = 12; // Standard for ChaCha20-Poly1305
    private final byte[] key;

    public ChaCha20PolySuite(byte[] key) {
        this.key = Arrays.copyOf(key, key.length);
    }

    @Override
    public byte[] encrypt(byte[] plaintext, byte[] aad) {
        try {
            byte[] nonce = new byte[NONCE_LEN];
            new SecureRandom().nextBytes(nonce);

            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            SecretKeySpec keySpec = new SecretKeySpec(key, "ChaCha20");
            ChaCha20ParameterSpec paramSpec = new ChaCha20ParameterSpec(nonce, 1);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, paramSpec);
            cipher.updateAAD(aad);

            byte[] ciphertext = cipher.doFinal(plaintext);

            // Return nonce || ciphertext (ciphertext already includes the 16-byte Poly1305 tag)
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(nonce);
            out.write(ciphertext);
            return out.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("ChaCha20-Poly1305 encrypt failed", e);
        }
    }

    @Override
    public byte[] decrypt(byte[] blob, byte[] aad) {
        try {
            if (blob.length < NONCE_LEN + 16)
                throw new IllegalArgumentException("Ciphertext too short");

            byte[] nonce = Arrays.copyOfRange(blob, 0, NONCE_LEN);
            byte[] ciphertext = Arrays.copyOfRange(blob, NONCE_LEN, blob.length);

            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            SecretKeySpec keySpec = new SecretKeySpec(key, "ChaCha20");
            ChaCha20ParameterSpec paramSpec = new ChaCha20ParameterSpec(nonce, 1);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, paramSpec);
            cipher.updateAAD(aad);

            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new RuntimeException("ChaCha20-Poly1305 decrypt failed", e);
        }
    }
}
