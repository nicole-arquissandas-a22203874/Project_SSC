package crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;

public class AesGcmSuite implements CryptoSuite {
    private final byte[] dataKey;
    private final SecureRandom rnd = new SecureRandom();

    public AesGcmSuite(byte[] dataKey) {
        this.dataKey = dataKey;
    }

    @Override public byte[] encrypt(byte[] plaintext, byte[] aad) throws Exception {
        byte[] iv = new byte[12];
        rnd.nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(dataKey, "AES"), new GCMParameterSpec(128, iv));
        if (aad != null) c.updateAAD(aad);
        byte[] ctTag = c.doFinal(plaintext);              // ciphertext || 16B tag
        byte[] out = new byte[iv.length + ctTag.length];  // iv || ctTag
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(ctTag, 0, out, iv.length, ctTag.length);
        return out;
    }

    @Override public byte[] decrypt(byte[] blob, byte[] aad) throws Exception {
        byte[] iv = Arrays.copyOfRange(blob, 0, 12);
        byte[] ctTag = Arrays.copyOfRange(blob, 12, blob.length);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(dataKey, "AES"), new GCMParameterSpec(128, iv));
        if (aad != null) c.updateAAD(aad);
        return c.doFinal(ctTag);                           // throws on tamper
    }
}

