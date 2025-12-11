import iam.crypto.EccUtils;
import iam.crypto.PasswordUtil;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.Base64;

public class IamClient {


    private final String authHost = "localhost"; // OAS
    private final int authPort    = 6000;
    private final String oamsHost = "localhost"; // OAMS
    private final int oamsPort    = 7000;

    private PublicKey userPk;
    private PrivateKey userSk;
    private String userPubKeyB64;

    private static final Path TOKEN_FILE = Paths.get("auth_token.txt");


    private String authToken; // token from OAS after LOGIN

    public IamClient() throws Exception {
        loadOrCreateUserKeys();
        loadTokenIfExists();
    }
    private void loadTokenIfExists() {
        try {
            if (Files.exists(TOKEN_FILE)) {
                String t = Files.readString(TOKEN_FILE).trim();
                if (!t.isEmpty()) {
                    this.authToken = t;
                }
            }
        } catch (Exception e) {

        }
    }

    //static classes
    public static class SharedForMe {
        public final String fileId;
        public final String permissions;
        public final byte[] kwKey;  // decrypted search key

        public SharedForMe(String fileId, String permissions, byte[] kwKey) {
            this.fileId = fileId;
            this.permissions = permissions;
            this.kwKey = kwKey;
        }
    }
    //

    // ECC keypair management
    private void loadOrCreateUserKeys() throws Exception {
        Path privPath = Paths.get("user_ec_priv.b64");
        Path pubPath  = Paths.get("user_ec_pub.b64");
        if (Files.exists(privPath) && Files.exists(pubPath)) {
            String skB64 = Files.readString(privPath).trim();
            String pkB64 = Files.readString(pubPath).trim();
            userSk = EccUtils.privateKeyFromBase64(skB64);
            userPk = EccUtils.publicKeyFromBase64(pkB64);
            userPubKeyB64 = pkB64;
        } else {
            KeyPair kp = EccUtils.generateEcKeyPair();
            userSk = kp.getPrivate();
            userPk = kp.getPublic();
            userPubKeyB64 = EccUtils.publicKeyToBase64(userPk);
            Files.writeString(privPath, EccUtils.privateKeyToBase64(userSk));
            Files.writeString(pubPath,  userPubKeyB64);
        }
    }

    private String signString(String s) throws GeneralSecurityException {
        byte[] sig = EccUtils.sign(userSk, s.getBytes());
        return Base64.getEncoder().encodeToString(sig);
    }

    public String getUserPubKeyB64() {
        return userPubKeyB64;
    }

    public boolean hasToken() {
        return authToken != null;
    }

    public String getAuthToken() {
        return authToken;
    }
    //                OAS                //
    public boolean registerAtOAS(String password) throws Exception {
        PasswordUtil.PasswordRecord pr = PasswordUtil.deriveFromPassword(password.toCharArray());
        String pwRecord = PasswordUtil.encodeRecord(pr);

        // We don't use extra attributes => keep a dummy hash "0"
        String attributesHash = "0";

        try (Socket s = new Socket(authHost, authPort);
             DataInputStream in = new DataInputStream(s.getInputStream());
             DataOutputStream out = new DataOutputStream(s.getOutputStream())) {

            String cmd = "CREATE_REG";
            String toSign = cmd + "|" + userPubKeyB64 + "|" + pwRecord + "|" + attributesHash;
            String sigB64 = signString(toSign);

            out.writeUTF(cmd);
            out.writeUTF(userPubKeyB64);
            out.writeUTF(pwRecord);
            out.writeUTF(attributesHash);
            out.writeUTF(sigB64);
            out.flush();

            String status = in.readUTF();
            String msg    = in.readUTF();
            System.out.println("REGISTER: " + status + " - " + msg);
            return "OK".equals(status);
        }
    }
    public boolean modifyRegistration(String oldPassword, String newPassword) throws Exception {
        if (authToken == null) {
            System.out.println("You must LOGIN first");
            return false;
        }

        // derivar nova pass record
        PasswordUtil.PasswordRecord prNew = PasswordUtil.deriveFromPassword(newPassword.toCharArray());
        String pwRecordNew   = PasswordUtil.encodeRecord(prNew);
        String attributesHash = "0";

        try (Socket s = new Socket(authHost, authPort);
             DataInputStream in = new DataInputStream(s.getInputStream());
             DataOutputStream out = new DataOutputStream(s.getOutputStream())) {

            String cmd = "MODIFY_REG";

            String toSign = cmd + "|" + userPubKeyB64 + "|" + pwRecordNew + "|" + attributesHash;
            String sigB64 = signString(toSign);

            out.writeUTF(cmd);

            out.writeUTF(userPubKeyB64);
            out.writeUTF(pwRecordNew);
            out.writeUTF(attributesHash);
            out.writeUTF(sigB64);
            out.flush();

            String status = in.readUTF();
            String msg    = in.readUTF();
            System.out.println("REGMOD: " + status + " - " + msg);
            return "OK".equals(status);
        }
    }

    public boolean deleteRegistration(String password) throws Exception {
        if (authToken == null) {
            System.out.println("You must LOGIN first");
            return false;
        }

        try (Socket s = new Socket(authHost, authPort);
             DataInputStream in = new DataInputStream(s.getInputStream());
             DataOutputStream out = new DataOutputStream(s.getOutputStream())) {

            String cmd = "DELETE_REG";
            String toSign = cmd + "|" + userPubKeyB64;
            String sigB64 = signString(toSign);

            out.writeUTF(cmd);

            out.writeUTF(userPubKeyB64);
            out.writeUTF(sigB64);
            out.flush();

            String status = in.readUTF();
            String msg    = in.readUTF();
            System.out.println("REGDEL: " + status + " - " + msg);
            if ("OK".equals(status)) {
                authToken = null;
                try {
                    Files.deleteIfExists(TOKEN_FILE);
                } catch (Exception e) {
                    // ignore
                }
                return true;
            }
            return false;
        }
    }


    //  Authenticate (AUTH_STEP1 + AUTH_STEP2)
    public boolean login(String password) throws Exception {
        String challengeB64;
        String pwRecord;

        // Step 1: request challenge
        try (Socket s = new Socket(authHost, authPort);
             DataInputStream in = new DataInputStream(s.getInputStream());
             DataOutputStream out = new DataOutputStream(s.getOutputStream())) {

            String cmd = "AUTH_STEP1";
            String sigB64 = signString(cmd + "|" + userPubKeyB64);

            out.writeUTF(cmd);
            out.writeUTF(userPubKeyB64);
            out.writeUTF(sigB64);
            out.flush();

            String resp = in.readUTF();
            if (!"AUTH_CHALLENGE".equals(resp)) {
                String msg = in.readUTF();
                System.out.println("AUTH_STEP1 failed: " + resp + " - " + msg);
                return false;
            }
            challengeB64 = in.readUTF();
            pwRecord     = in.readUTF();
            String oasSig = in.readUTF(); // optional: verify
        }

        // Client computes password-based proof
        PasswordUtil.PasswordRecord pr = PasswordUtil.decodeRecord(pwRecord);
        byte[] derivedKey = PasswordUtil.deriveKeyForAuth(password.toCharArray(), pr);
        byte[] challenge  = Base64.getDecoder().decode(challengeB64);
        byte[] hmac       = hmacSha256(derivedKey, challenge);
        String responseB64 = Base64.getEncoder().encodeToString(hmac);

        // send proof
        try (Socket s = new Socket(authHost, authPort);
             DataInputStream in = new DataInputStream(s.getInputStream());
             DataOutputStream out = new DataOutputStream(s.getOutputStream())) {

            String cmd = "AUTH_STEP2";
            String toSign = cmd + "|" + userPubKeyB64 + "|" + challengeB64 + "|" + responseB64;
            String sigB64 = signString(toSign);

            out.writeUTF(cmd);
            out.writeUTF(userPubKeyB64);
            out.writeUTF(challengeB64);
            out.writeUTF(responseB64);
            out.writeUTF(sigB64);
            out.flush();

            String status = in.readUTF();
            if (!"AUTH_OK".equals(status)) {
                String msg = in.readUTF();
                System.out.println("AUTH_STEP2 failed: " + msg);
                return false;
            }
            authToken = in.readUTF();
            String oasSig = in.readUTF(); // optional: verify

            System.out.println("Authenticated:\nToken = " + authToken);
            //para gusarda o token no file
            try {
                Files.writeString(TOKEN_FILE, authToken);
            } catch (Exception e) {
                System.err.println("Warning: could not save auth token: " + e);
            }

            return true;
        }
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }

//                   OAMS                  //


    public boolean shareFile(String fileId, String authorizedPubKeyB64,
                             String permissions, byte[] fileDataKey, byte[] fileKwKey) throws Exception {
        if (authToken == null) {
            System.out.println("You must LOGIN first");
            return false;
        }

        PublicKey authzPk = EccUtils.publicKeyFromBase64(authorizedPubKeyB64);
        String encFileKey = EccUtils.encryptFor(authzPk, fileDataKey);
        String encKwKey   = EccUtils.encryptFor(authzPk, fileKwKey);

        try (Socket s = new Socket(oamsHost, oamsPort);
             DataInputStream in = new DataInputStream(s.getInputStream());
             DataOutputStream out = new DataOutputStream(s.getOutputStream())) {

            String cmd = "SHARE_CREATE";
            String toSign = cmd + "|" + authToken + "|" + fileId + "|" +
                    authorizedPubKeyB64 + "|" + permissions + "|" +
                    encFileKey + "|" + encKwKey;
            String sigB64 = signString(toSign);

            out.writeUTF(cmd);
            out.writeUTF(authToken);
            out.writeUTF(fileId);
            out.writeUTF(authorizedPubKeyB64);
            out.writeUTF(permissions);
            out.writeUTF(encFileKey);
            out.writeUTF(encKwKey);
            out.writeUTF(sigB64);
            out.flush();

            String status = in.readUTF();
            String msg    = in.readUTF();
            System.out.println("SHARE_CREATE: " + status + " - " + msg);
            return "OK".equals(status);
        }
    }
    public boolean deleteShare(String fileId, String authorizedPubKeyB64) throws Exception {
        if (authToken == null) {
            System.out.println("You must LOGIN first");
            return false;
        }

        try (Socket s = new Socket(oamsHost, oamsPort);
             DataInputStream in = new DataInputStream(s.getInputStream());
             DataOutputStream out = new DataOutputStream(s.getOutputStream())) {

            String cmd = "SHARE_DELETE";
            String toSign = cmd + "|" + authToken + "|" + fileId + "|" + authorizedPubKeyB64;
            String sigB64 = signString(toSign);

            out.writeUTF(cmd);
            out.writeUTF(authToken);
            out.writeUTF(fileId);
            out.writeUTF(authorizedPubKeyB64);
            out.writeUTF(sigB64);
            out.flush();

            String status = in.readUTF();
            String msg    = in.readUTF();
            System.out.println("SHARE_DELETE: " + status + " - " + msg);
            return "OK".equals(status);
        }
    }

    // get keys for shared file

    public static class SharedKeys {
        public final String fileId;
        public final String permissions;
        public final byte[] fileKey;
        public final byte[] kwKey;
        public SharedKeys(String f, String p, byte[] fk, byte[] kk) {
            fileId = f; permissions = p; fileKey = fk; kwKey = kk;
        }
    }

    public SharedKeys getSharedKeys(String fileId) throws Exception {
        if (authToken == null) {
            System.out.println("You must LOGIN first");
            return null;
        }

        try (Socket s = new Socket(oamsHost, oamsPort);
             DataInputStream in = new DataInputStream(s.getInputStream());
             DataOutputStream out = new DataOutputStream(s.getOutputStream())) {

            String cmd = "SHARE_GETKEYS";
            String toSign = cmd + "|" + authToken + "|" + fileId;
            String sigB64 = signString(toSign);

            out.writeUTF(cmd);
            out.writeUTF(authToken);
            out.writeUTF(fileId);
            out.writeUTF(sigB64);
            out.flush();

            String status = in.readUTF();
            if (!"OK".equals(status)) {
                String msg = in.readUTF();
                System.out.println("SHARE_GETKEYS failed: " + msg);
                return null;
            }
            String permissions = in.readUTF();
            String encFileKey  = in.readUTF();
            String encKwKey    = in.readUTF();

            byte[] fileKey = EccUtils.decryptFrom(userSk, encFileKey);
            byte[] kwKey   = EccUtils.decryptFrom(userSk, encKwKey);

            return new SharedKeys(fileId, permissions, fileKey, kwKey);
        }
    }
    public java.util.List<SharedForMe> listSharesForMe() throws Exception {
        if (authToken == null) {
            System.out.println("You must LOGIN first");
            return java.util.Collections.emptyList();
        }

        java.util.List<SharedForMe> result = new java.util.ArrayList<>();

        try (Socket s = new Socket(oamsHost, oamsPort);
             DataInputStream in = new DataInputStream(s.getInputStream());
             DataOutputStream out = new DataOutputStream(s.getOutputStream())) {

            String cmd = "SHARE_LIST_MY";
            String toSign = cmd + "|" + authToken;
            String sigB64 = signString(toSign);

            out.writeUTF(cmd);
            out.writeUTF(authToken);
            out.writeUTF(sigB64);
            out.flush();

            String status = in.readUTF();
            if (!"OK".equals(status)) {
                String msg = in.readUTF();
                System.out.println("SHARE_LIST_MY failed: " + msg);
                return result;
            }

            int n = in.readInt();
            for (int i = 0; i < n; i++) {
                String fileId      = in.readUTF();
                String permissions = in.readUTF();
                String encKwKey    = in.readUTF();

                byte[] kwKey = EccUtils.decryptFrom(userSk, encKwKey);
                result.add(new SharedForMe(fileId, permissions, kwKey));
            }
        }

        return result;
    }




}
