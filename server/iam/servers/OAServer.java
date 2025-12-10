package iam.servers;


import iam.crypto.EccUtils;
import iam.crypto.PasswordUtil;
import iam.crypto.TokenUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Base64;

public class OAServer {

    private static final int PORT = 6000;

    private static KeyPair oasKeyPair;

    // ECC public key (B64) → registration
    private static final Map<String, Registration> registrations = new ConcurrentHashMap<>();
    // pending challenge per user for AUTH
    private static final Map<String, byte[]> pendingChallenges = new ConcurrentHashMap<>();

    public static void main(String[] args) throws Exception {
        oasKeyPair = loadOrCreateOasKeyPair();
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("OAServer running on port " + PORT);

        while (true) {
            Socket client = serverSocket.accept();
            new Thread(() -> handleClient(client)).start();
        }
    }

    private static KeyPair loadOrCreateOasKeyPair() throws Exception {
        File priv = new File("oas_ec_priv.b64");
        File pub  = new File("oas_ec_pub.b64");
        if (priv.exists() && pub.exists()) {
            String skB64 = new String(java.nio.file.Files.readAllBytes(priv.toPath())).trim();
            String pkB64 = new String(java.nio.file.Files.readAllBytes(pub.toPath())).trim();
            PrivateKey sk = EccUtils.privateKeyFromBase64(skB64);
            PublicKey pk  = EccUtils.publicKeyFromBase64(pkB64);
            return new KeyPair(pk, sk);
        } else {
            KeyPair kp = EccUtils.generateEcKeyPair();
            try (FileWriter fw = new FileWriter(priv)) {
                fw.write(EccUtils.privateKeyToBase64(kp.getPrivate()));
            }
            try (FileWriter fw = new FileWriter(pub)) {
                fw.write(EccUtils.publicKeyToBase64(kp.getPublic()));
            }
            return kp;
        }
    }

    private static void handleClient(Socket socket) {
        try (DataInputStream in = new DataInputStream(socket.getInputStream());
             DataOutputStream out= new DataOutputStream(socket.getOutputStream())) {

            while (true) {
                String cmd;
                try { cmd = in.readUTF(); }
                catch (EOFException e) { break; }

                switch (cmd) {
                    case "CREATE_REG" -> handleCreateRegistration(in, out);   // OAS-FR-1
                    case "MODIFY_REG" -> handleModifyRegistration(in, out);   // OAS-FR-4,5
                    case "AUTH_STEP1" -> handleAuthenticateStep1(in, out);    // OAS-FR-7 (part 1)
                    case "AUTH_STEP2" -> handleAuthenticateStep2(in, out);    // OAS-FR-7,8,14 (part 2)
                    case "DELETE_REG" -> handleDeleteRegistration(in, out);   // OAS-FR-6,9
                    case "EXIT"       -> { return; }
                    default -> {
                        out.writeUTF("ERROR");
                        out.writeUTF("Unknown command: " + cmd);
                        out.flush();
                    }
                }
            }

        } catch (IOException e) {
            System.err.println("OAS client error: " + e.getMessage());
        }
    }

    // CreateRegistration
    private static void handleCreateRegistration(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            String userPubKeyB64  = in.readUTF();
            String passwordRecord = in.readUTF();   // PBKDF2$iters$salt$hash
            String attrsHash      = in.readUTF();   // hashed attributes
            String sigB64         = in.readUTF();   // signature by user

            PublicKey userPk = EccUtils.publicKeyFromBase64(userPubKeyB64);
            String toSignStr = "CREATE_REG|" + userPubKeyB64 + "|" + passwordRecord + "|" + attrsHash;
            byte[] sigBytes = Base64.getDecoder().decode(sigB64);
            if (!EccUtils.verify(userPk, toSignStr.getBytes(), sigBytes)) {
                out.writeUTF("NOK");
                out.writeUTF("Invalid signature");
                out.flush();
                return;
            }

            if (registrations.containsKey(userPubKeyB64)) {
                out.writeUTF("NOK");
                out.writeUTF("User already exists");
            } else {
                registrations.put(userPubKeyB64,
                        new Registration(userPubKeyB64, passwordRecord, attrsHash));
                out.writeUTF("OK");
                out.writeUTF("Registered");
            }
            out.flush();

        } catch (GeneralSecurityException e) {
            out.writeUTF("NOK");
            out.writeUTF("Crypto error: " + e.getMessage());
            out.flush();
        }
    }

    // ModifyRegistration()
    private static void handleModifyRegistration(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            String userPubKeyB64  = in.readUTF();
            String newPasswordRec = in.readUTF(); // new PBKDF2 record
            String newAttrsHash   = in.readUTF();
            String sigB64         = in.readUTF();

            PublicKey userPk = EccUtils.publicKeyFromBase64(userPubKeyB64);
            String toSignStr = "MODIFY_REG|" + userPubKeyB64 + "|" + newPasswordRec + "|" + newAttrsHash;
            if (!EccUtils.verify(userPk, toSignStr.getBytes(),
                    Base64.getDecoder().decode(sigB64))) {
                out.writeUTF("NOK");
                out.writeUTF("Invalid signature");
                out.flush();
                return;
            }

            Registration reg = registrations.get(userPubKeyB64);
            if (reg == null) {
                out.writeUTF("NOK");
                out.writeUTF("Invalid credentials");
            } else {
                reg.passwordRecord = newPasswordRec;
                reg.attributesHash = newAttrsHash;
                out.writeUTF("OK");
                out.writeUTF("Modified");
            }
            out.flush();

        } catch (GeneralSecurityException e) {
            out.writeUTF("NOK");
            out.writeUTF("Crypto error: " + e.getMessage());
            out.flush();
        }
    }

    // Authenticate Step 1
    //checks signature over eccpublickey of the user to prove the user owns the publickey
    //looks up user by that publickey, if it exists it sends a challenge and the passport record
    private static void handleAuthenticateStep1(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            String userPubKeyB64 = in.readUTF();
            String sigB64        = in.readUTF();

            PublicKey userPk = EccUtils.publicKeyFromBase64(userPubKeyB64);
            String toSignStr = "AUTH_STEP1|" + userPubKeyB64;
            if (!EccUtils.verify(userPk, toSignStr.getBytes(),
                    Base64.getDecoder().decode(sigB64))) {
                out.writeUTF("NOK");
                out.writeUTF("Invalid signature");
                out.flush();
                return;
            }

            Registration reg = registrations.get(userPubKeyB64);
            if (reg == null) {

                out.writeUTF("NOK");
                out.writeUTF("Invalid credentials");
                out.flush();
                return;
            }

            byte[] challenge = new byte[32];
            new SecureRandom().nextBytes(challenge);
            pendingChallenges.put(userPubKeyB64, challenge);

            String challengeB64 = Base64.getEncoder().encodeToString(challenge);
            out.writeUTF("AUTH_CHALLENGE");
            out.writeUTF(challengeB64);
            out.writeUTF(reg.passwordRecord); // PBKDF2 parameters for client

            // sign challenge to let client verify it's from OAS
            String signStr = "AUTH_CHALLENGE|" + userPubKeyB64 + "|" +
                    challengeB64 + "|" + reg.passwordRecord;
            byte[] oasSig = EccUtils.sign(oasKeyPair.getPrivate(), signStr.getBytes());
            out.writeUTF(Base64.getEncoder().encodeToString(oasSig));
            out.flush();

        } catch (GeneralSecurityException e) {
            out.writeUTF("NOK");
            out.writeUTF("Crypto error: " + e.getMessage());
            out.flush();
        }
    }

    // Authenticate Step 2
    //in the client side it ask the user the password
    //reconstructs the PBKDF2 key using passwordRecord
    //computes responde(proof) and sends back to the oas with users signature
    //oas verifies signature ,locates stores password for the userpubkey and recomputes
    // the expected response and compares with the response client sent, if it matches
    //the password is correct and oas sends token signed with oas eccprivkey
    private static void handleAuthenticateStep2(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            String userPubKeyB64 = in.readUTF();
            String challengeB64  = in.readUTF();
            String responseB64   = in.readUTF();
            String sigB64        = in.readUTF();

            PublicKey userPk = EccUtils.publicKeyFromBase64(userPubKeyB64);
            String toSignStr = "AUTH_STEP2|" + userPubKeyB64 + "|" +
                    challengeB64 + "|" + responseB64;
            if (!EccUtils.verify(userPk, toSignStr.getBytes(),
                    Base64.getDecoder().decode(sigB64))) {
                out.writeUTF("NOK");
                out.writeUTF("Invalid signature");
                out.flush();
                return;
            }

            Registration reg = registrations.get(userPubKeyB64);
            byte[] challenge = pendingChallenges.remove(userPubKeyB64);
            if (reg == null || challenge == null) {
                out.writeUTF("NOK");
                out.writeUTF("Invalid credentials");
                out.flush();
                return;
            }

            PasswordUtil.PasswordRecord pr = PasswordUtil.decodeRecord(reg.passwordRecord);
            byte[] storedKey = pr.key;
            byte[] clientResp = Base64.getDecoder().decode(responseB64);
            byte[] expected = hmacSha256(storedKey, Base64.getDecoder().decode(challengeB64));

            if (!MessageDigest.isEqual(expected, clientResp)) {
                out.writeUTF("NOK");
                out.writeUTF("Invalid credentials");
                out.flush();
                return;
            }

            String token = TokenUtils.createToken(
                    oasKeyPair.getPrivate(), userPubKeyB64,
                    15 * 60 * 1000L); // 15 min validity

            out.writeUTF("AUTH_OK");
            out.writeUTF(token);

            String signStr = "AUTH_OK|" + userPubKeyB64 + "|" + token;
            byte[] oasSig = EccUtils.sign(oasKeyPair.getPrivate(), signStr.getBytes());
            out.writeUTF(Base64.getEncoder().encodeToString(oasSig));
            out.flush();

        } catch (GeneralSecurityException e) {
            out.writeUTF("NOK");
            out.writeUTF("Crypto error: " + e.getMessage());
            out.flush();
        }
    }

    // DeleteRegistration
    private static void handleDeleteRegistration(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            String userPubKeyB64 = in.readUTF();
            String sigB64        = in.readUTF();

            PublicKey userPk = EccUtils.publicKeyFromBase64(userPubKeyB64);
            String toSignStr = "DELETE_REG|" + userPubKeyB64;
            if (!EccUtils.verify(userPk, toSignStr.getBytes(),
                    Base64.getDecoder().decode(sigB64))) {
                out.writeUTF("NOK");
                out.writeUTF("Invalid signature");
                out.flush();
                return;
            }

            registrations.remove(userPubKeyB64);
            out.writeUTF("OK");
            out.writeUTF("Deleted");
            out.flush();

        } catch (GeneralSecurityException e) {
            out.writeUTF("NOK");
            out.writeUTF("Crypto error: " + e.getMessage());
            out.flush();
        }
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }

    private static class Registration {
        final String userPubKeyB64;
        String passwordRecord;
        String attributesHash;
        Registration(String pk, String pwRec, String attrs) {
            this.userPubKeyB64 = pk;
            this.passwordRecord = pwRec;
            this.attributesHash = attrs;
        }
    }
}
