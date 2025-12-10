package iam.crypto;

import java.security.*;
import java.util.Base64;

public class TokenUtils {

    public static String createToken(PrivateKey oasSk, String userPubKeyB64, long lifetimeMillis)
            throws GeneralSecurityException {
        long now = System.currentTimeMillis();
        long exp = now + lifetimeMillis;
        String payload = userPubKeyB64 + "|" + now + "|" + exp;
        byte[] payloadBytes = payload.getBytes();
        byte[] sig = EccUtils.sign(oasSk, payloadBytes);
        return Base64.getEncoder().encodeToString(payloadBytes) + "." +
                Base64.getEncoder().encodeToString(sig);
    }

    public static class TokenData {
        public final String userPubKeyB64;
        public final long issuedAt;
        public final long expiresAt;
        public TokenData(String u,long i,long e){userPubKeyB64=u;issuedAt=i;expiresAt=e;}
    }

    public static TokenData verifyAndParse(PublicKey oasPk, String token) throws GeneralSecurityException {
        String[] parts = token.split("\\.");
        if (parts.length != 2) throw new GeneralSecurityException("Invalid token");
        byte[] payloadBytes = Base64.getDecoder().decode(parts[0]);
        byte[] sigBytes     = Base64.getDecoder().decode(parts[1]);
        if (!EccUtils.verify(oasPk, payloadBytes, sigBytes))
            throw new GeneralSecurityException("Bad token signature");
        String[] fields = new String(payloadBytes).split("\\|");
        if (fields.length != 3) throw new GeneralSecurityException("Bad token payload");
        String user = fields[0];
        long iat = Long.parseLong(fields[1]);
        long exp = Long.parseLong(fields[2]);
        if (System.currentTimeMillis() > exp)
            throw new GeneralSecurityException("Token expired");
        return new TokenData(user, iat, exp);
    }
}
