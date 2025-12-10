package iam.servers;


import iam.crypto.EccUtils;
import iam.crypto.TokenUtils;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Base64;

public class OAMServer {

    private static final int PORT = 7000;

    private static PublicKey oasPublicKey; // from oas_ec_pub.b64

    // (fileId|owner|authz) -> entry
    private static final Map<String, SharingEntry> sharings = new ConcurrentHashMap<>();

    public static void main(String[] args) throws Exception {
        oasPublicKey = loadOasPublicKey();
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("OAMSServer running on port " + PORT);
        while (true) {
            Socket client = serverSocket.accept();
            new Thread(() -> handleClient(client)).start();
        }
    }

    private static PublicKey loadOasPublicKey() throws Exception {
        String pkB64 = new String(java.nio.file.Files.readAllBytes(
                new File("oas_ec_pub.b64").toPath())).trim();
        return EccUtils.publicKeyFromBase64(pkB64);
    }

    private static void handleClient(Socket socket) {
        try (DataInputStream in = new DataInputStream(socket.getInputStream());
             DataOutputStream out= new DataOutputStream(socket.getOutputStream())) {

            while (true) {
                String cmd;
                try { cmd = in.readUTF(); }
                catch (EOFException e) { break; }

                switch (cmd) {
                    case "SHARE_CREATE"  -> handleShareCreate(in, out);
                    case "SHARE_DELETE"  -> handleShareDelete(in, out);
                    case "SHARE_GETKEYS" -> handleShareGetKeys(in, out);
                    case "SHARE_LIST_MY" -> handleShareListMy(in, out);
                    case "EXIT"          -> { return; }
                    default -> {
                        out.writeUTF("ERROR");
                        out.writeUTF("Unknown command: " + cmd);
                        out.flush();
                    }
                }
            }

        } catch (IOException e) {
            System.err.println("OAMS client error: " + e.getMessage());
        }
    }

// CreateSharingRegistration()
    private static void handleShareCreate(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            String authToken          = in.readUTF();
            String fileId             = in.readUTF();
            String authorizedPubKeyB64= in.readUTF();
            String permissions        = in.readUTF();
            String encFileKey         = in.readUTF();
            String encKwKey           = in.readUTF();
            String sigB64             = in.readUTF();

            TokenUtils.TokenData td = TokenUtils.verifyAndParse(oasPublicKey, authToken);
            String ownerPubKeyB64 = td.userPubKeyB64;
            PublicKey ownerPk     = EccUtils.publicKeyFromBase64(ownerPubKeyB64);

            String toSignStr = "SHARE_CREATE|" + authToken + "|" + fileId + "|" +
                    authorizedPubKeyB64 + "|" + permissions + "|" + encFileKey + "|" + encKwKey;
            if (!EccUtils.verify(ownerPk, toSignStr.getBytes(),
                    Base64.getDecoder().decode(sigB64))) {
                out.writeUTF("NOK");
                out.writeUTF("Invalid signature");
                out.flush();
                return;
            }

            String key = key(fileId, ownerPubKeyB64, authorizedPubKeyB64);
            sharings.put(key, new SharingEntry(fileId, ownerPubKeyB64, authorizedPubKeyB64,
                    permissions, encFileKey, encKwKey));

            out.writeUTF("OK");
            out.writeUTF("Share created");
            out.flush();

        } catch (GeneralSecurityException e) {
            out.writeUTF("NOK");
            out.writeUTF("Crypto error: " + e.getMessage());
            out.flush();
        }
    }

//DeleteSharingRegistration()
    private static void handleShareDelete(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            String authToken          = in.readUTF();
            String fileId             = in.readUTF();
            String authorizedPubKeyB64= in.readUTF();
            String sigB64             = in.readUTF();

            TokenUtils.TokenData td = TokenUtils.verifyAndParse(oasPublicKey, authToken);
            String ownerPubKeyB64 = td.userPubKeyB64;
            PublicKey ownerPk     = EccUtils.publicKeyFromBase64(ownerPubKeyB64);

            String toSignStr = "SHARE_DELETE|" + authToken + "|" + fileId + "|" + authorizedPubKeyB64;
            if (!EccUtils.verify(ownerPk, toSignStr.getBytes(),
                    Base64.getDecoder().decode(sigB64))) {
                out.writeUTF("NOK");
                out.writeUTF("Invalid signature");
                out.flush();
                return;
            }

            String key = key(fileId, ownerPubKeyB64, authorizedPubKeyB64);
            if (sharings.remove(key) != null) {
                out.writeUTF("OK");
                out.writeUTF("Share deleted");
            } else {
                out.writeUTF("NOK");
                out.writeUTF("Share not found");
            }
            out.flush();

        } catch (GeneralSecurityException e) {
            out.writeUTF("NOK");
            out.writeUTF("Crypto error: " + e.getMessage());
            out.flush();
        }
    }

    private static void handleShareGetKeys(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            String authToken = in.readUTF();
            String fileId    = in.readUTF();
            String sigB64    = in.readUTF();

            TokenUtils.TokenData td = TokenUtils.verifyAndParse(oasPublicKey, authToken);
            String reqPubKeyB64 = td.userPubKeyB64;
            PublicKey reqPk     = EccUtils.publicKeyFromBase64(reqPubKeyB64);

            String toSignStr = "SHARE_GETKEYS|" + authToken + "|" + fileId;
            if (!EccUtils.verify(reqPk, toSignStr.getBytes(),
                    Base64.getDecoder().decode(sigB64))) {
                out.writeUTF("NOK");
                out.writeUTF("Invalid signature");
                out.flush();
                return;
            }

            SharingEntry found = null;
            for (SharingEntry se : sharings.values()) {
                if (se.fileId.equals(fileId) && se.authorizedPubKeyB64.equals(reqPubKeyB64)) {
                    found = se; break;
                }
            }

            if (found == null) {
                out.writeUTF("NOK");
                out.writeUTF("No sharing entry");
            } else {
                out.writeUTF("OK");
                out.writeUTF(found.permissions);
                out.writeUTF(found.encFileKey);
                out.writeUTF(found.encKwKey);
            }
            out.flush();

        } catch (GeneralSecurityException e) {
            out.writeUTF("NOK");
            out.writeUTF("Crypto error: " + e.getMessage());
            out.flush();
        }
    }
    //lista todos os shared files do user
    private static void handleShareListMy(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            String authToken = in.readUTF();
            String sigB64    = in.readUTF();

            // 1) verify token
            TokenUtils.TokenData td = TokenUtils.verifyAndParse(oasPublicKey, authToken);
            String userPubKeyB64 = td.userPubKeyB64;
            PublicKey userPk     = EccUtils.publicKeyFromBase64(userPubKeyB64);

            // 2) verify client's signature
            String toSign = "SHARE_LIST_MY|" + authToken;
            if (!EccUtils.verify(userPk, toSign.getBytes(),
                    Base64.getDecoder().decode(sigB64))) {
                out.writeUTF("NOK");
                out.writeUTF("Invalid signature");
                out.flush();
                return;
            }

            // 3) collect all sharing entries where this user is authorized
            java.util.List<SharingEntry> mine = new java.util.ArrayList<>();
            for (SharingEntry se : sharings.values()) {
                if (se.authorizedPubKeyB64.equals(userPubKeyB64)) {
                    mine.add(se);
                }
            }

            out.writeUTF("OK");
            out.writeInt(mine.size());
            for (SharingEntry se : mine) {
                out.writeUTF(se.fileId);
                out.writeUTF(se.permissions);
                out.writeUTF(se.encKwKey);  // encrypted search key
            }
            out.flush();

        } catch (GeneralSecurityException e) {
            out.writeUTF("NOK");
            out.writeUTF("Crypto error: " + e.getMessage());
            out.flush();
        }
    }


    private static String key(String fileId, String owner, String authz) {
        return fileId + "|" + owner + "|" + authz;
    }

    private static class SharingEntry {
        final String fileId;
        final String ownerPubKeyB64;
        final String authorizedPubKeyB64;
        final String permissions;
        final String encFileKey;
        final String encKwKey;
        SharingEntry(String f,String o,String a,String p,String ef,String ek){
            fileId=f;ownerPubKeyB64=o;authorizedPubKeyB64=a;
            permissions=p;encFileKey=ef;encKwKey=ek;
        }
    }
}
