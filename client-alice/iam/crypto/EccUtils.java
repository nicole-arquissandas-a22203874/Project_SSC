package iam.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class EccUtils {

    private static final String EC_CURVE = "secp256r1";
    private static final String SIGN_ALG = "SHA256withECDSA";
    private static final String KA_ALG   = "ECDH";
    private static final String AES_ALG  = "AES/GCM/NoPadding";

    public static KeyPair generateEcKeyPair() throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec(EC_CURVE), new SecureRandom());
        return kpg.generateKeyPair();
    }

    public static String publicKeyToBase64(PublicKey pk) {
        return Base64.getEncoder().encodeToString(pk.getEncoded());
    }
    public static String privateKeyToBase64(PrivateKey sk) {
        return Base64.getEncoder().encodeToString(sk.getEncoded());
    }
    public static PublicKey publicKeyFromBase64(String s) throws GeneralSecurityException {
        byte[] bytes = Base64.getDecoder().decode(s);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePublic(new X509EncodedKeySpec(bytes));
    }
    public static PrivateKey privateKeyFromBase64(String s) throws GeneralSecurityException {
        byte[] bytes = Base64.getDecoder().decode(s);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePrivate(new PKCS8EncodedKeySpec(bytes));
    }

    public static byte[] sign(PrivateKey sk, byte[] data) throws GeneralSecurityException {
        Signature sig = Signature.getInstance(SIGN_ALG);
        sig.initSign(sk);
        sig.update(data);
        return sig.sign();
    }
    public static boolean verify(PublicKey pk, byte[] data, byte[] signature) throws GeneralSecurityException {
        Signature sig = Signature.getInstance(SIGN_ALG);
        sig.initVerify(pk);
        sig.update(data);
        return sig.verify(signature);
    }

    private static byte[] deriveSharedSecret(PrivateKey mySk, PublicKey otherPk) throws GeneralSecurityException {
        KeyAgreement ka = KeyAgreement.getInstance(KA_ALG);
        ka.init(mySk);
        ka.doPhase(otherPk, true);
        return ka.generateSecret();
    }
    private static byte[] kdf(byte[] sharedSecret) throws GeneralSecurityException {
        return MessageDigest.getInstance("SHA-256").digest(sharedSecret);
    }

    public static String encryptFor(PublicKey recipientPk, byte[] plaintext) throws GeneralSecurityException {
        KeyPair ephem = generateEcKeyPair();
        byte[] shared = deriveSharedSecret(ephem.getPrivate(), recipientPk);
        byte[] aesKey = kdf(shared);

        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(AES_ALG);
        cipher.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(aesKey, "AES"),
                new GCMParameterSpec(128, iv));
        byte[] ct = cipher.doFinal(plaintext);

        byte[] ephemPub = ephem.getPublic().getEncoded();
        byte[] out = new byte[ephemPub.length + iv.length + ct.length];
        System.arraycopy(ephemPub, 0, out, 0, ephemPub.length);
        System.arraycopy(iv, 0, out, ephemPub.length, iv.length);
        System.arraycopy(ct, 0, out, ephemPub.length + iv.length, ct.length);

        return Base64.getEncoder().encodeToString(out);
    }

    public static byte[] decryptFrom(PrivateKey recipientSk, String encDataB64) throws GeneralSecurityException {
        byte[] data = Base64.getDecoder().decode(encDataB64);
        // assume first 91 bytes = ephem key, 12 = iv, rest = ct
        int ephemLen = 91;
        byte[] ephemPub = Arrays.copyOfRange(data, 0, ephemLen);
        byte[] iv       = Arrays.copyOfRange(data, ephemLen, ephemLen + 12);
        byte[] ct       = Arrays.copyOfRange(data, ephemLen + 12, data.length);

        PublicKey ephemPk = KeyFactory.getInstance("EC")
                .generatePublic(new X509EncodedKeySpec(ephemPub));

        byte[] shared = deriveSharedSecret(recipientSk, ephemPk);
        byte[] aesKey = kdf(shared);

        Cipher cipher = Cipher.getInstance(AES_ALG);
        cipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(aesKey, "AES"),
                new GCMParameterSpec(128, iv));
        return cipher.doFinal(ct);
    }
}
