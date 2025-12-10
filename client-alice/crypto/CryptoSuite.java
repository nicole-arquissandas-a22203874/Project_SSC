package crypto;

public interface CryptoSuite {
        byte[] encrypt(byte[] plaintext, byte[] aad) throws Exception; // returns blob to store (nonce/iv||ct||tag/mac)
        byte[] decrypt(byte[] blob, byte[] aad) throws Exception;      // verifies & returns plaintext
    }

