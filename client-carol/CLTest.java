

public class CLTest {

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.out.println("""
Usage:
  Project 1
  CLTest PUT <path/dir/file> <keywords>
  CLTest LIST
  CLTest SEARCH <keywords>
  CLTest GET <file> <path/dir>
  CLTest GET <keywords> <path/dir>
  CLTest GET CHECKINTEGRITY <path/dir/file>

  Project 2
  CLTest REG <password>
  CLTest REGMOD <oldPassword> <newPassword>
  CLTest REGDEL <password>
  CLTest LOGIN <password>
  CLTest SHOWPUB
  CLTest SHARE <filename> <authorizedPubKeyB64> <GET|SEARCH|GET+SEARCH>
  CLTest SHAREDEL <filename> <authorizedPubKeyB64>
  CLTest GETSHARED <fileId> <path/dir/file>
  CLTest SEARCHSHARED <keywords>
  CLTest LISTSHARED
""");
            return;
        }

        ClientCore core = new ClientCore("localhost", 5000);
        IamClient iam   = new IamClient();
        String cmd = args[0].toUpperCase();

        switch (cmd) {
            case "PUT" -> {

                core.put(java.nio.file.Paths.get(args[1]), parseKeywords(args[2]));
            }

            case "LIST" -> core.listLocal();
            case "SEARCH" -> core.search(args[1]);
            case "GET" -> {
                if ("CHECKINTEGRITY".equalsIgnoreCase(args[1])) core.checkIntegrity(args[2]);
                else if (args[2] != null) {
                    // decide: if args[1] looks like filename -> getToDir, else getByKeywords
                    if (args[1].contains(".") && !args[1].contains(" ")) core.getToDir(args[1], args[2]);
                    else core.getByKeywords(args[1], args[2]);
                }
            }
            //OAServer
            case "REG" -> {
                // CLTest REG <password>
                if (args.length < 2) {
                    System.out.println("Usage: REG <password>");
                    break;
                }
                iam.registerAtOAS(args[1]);
            }
            case "REGMOD" -> {
                // CLTest REGMOD <oldPassword> <newPassword>
                if (args.length < 3) {
                    System.out.println("Usage: REGMOD <oldPassword> <newPassword>");
                    break;
                }
                if (!iam.hasToken()) {
                    System.out.println("You must LOGIN first.");
                    break;
                }
                iam.modifyRegistration(args[1], args[2]);
            }

            case "REGDEL" -> {
                // CLTest REGDEL <password>
                if (args.length < 2) {
                    System.out.println("Usage: REGDEL <password>");
                    break;
                }
                if (!iam.hasToken()) {
                    System.out.println("You must LOGIN first.");
                    break;
                }
                iam.deleteRegistration(args[1]);
            }

            case "LOGIN" -> {
                // CLTest LOGIN <password>
                if (args.length < 2) {
                    System.out.println("Usage: LOGIN <password>");
                    break;
                }
                if (iam.login(args[1])) {
                    System.out.println("My public key (user ID) is:");
                    System.out.println(iam.getUserPubKeyB64());
                }
            }
            //adicional para testes
            case "SHOWPUB" -> {
                // CLTest SHOWPUB
                System.out.println("My public key (user ID) is:");
                System.out.println(iam.getUserPubKeyB64());
            }
            //OAMServer
            case "SHARE" -> {

                if (args.length < 4) {
                    System.out.println("Usage: SHARE <filename> <authorizedPubKeyB64> <GET|SEARCH|GET+SEARCH>");
                    break;
                }
                if (!iam.hasToken()) {
                    System.out.println("You must LOGIN first.");
                    break;
                }

                String filename         = args[1];
                String authorizedPubKey = args[2];
                String permissions      = args[3];

                String fileId = core.getFileIdForName(filename);
                if (fileId == null) {
                    System.out.println("Unknown file: " + filename);
                    break;
                }

                ClientCore.FileKeys fk = core.getFileKeysForFileId(fileId);
                //global key
                iam.shareFile(fileId, authorizedPubKey, permissions, fk.dataKey, ClientCore.KEYS.kwKey);
            }
            case "SHAREDEL" -> {

                if (args.length < 3) {
                    System.out.println("Usage: SHAREDEL <filename> <authorizedPubKeyB64>");
                    break;
                }
                if (!iam.hasToken()) {
                    System.out.println("You must LOGIN first.");
                    break;
                }

                String filename         = args[1];
                String authorizedPubKey = args[2];

                String fileId = core.getFileIdForName(filename);
                if (fileId == null) {
                    System.out.println("Unknown file: " + filename);
                    break;
                }

                iam.deleteShare(fileId, authorizedPubKey);
            }
            //adicional para testes
            case "LISTSHARED" -> {

                if (!iam.hasToken()) {
                    System.out.println("You must LOGIN first.");
                    break;
                }

                java.util.List<IamClient.SharedForMe> shares = iam.listSharesForMe();
                if (shares.isEmpty()) {
                    System.out.println("No files shared with you.");
                    break;
                }

                System.out.println("Files shared with me:");
                for (IamClient.SharedForMe sf : shares) {
                    System.out.println(" - fileId=" + sf.fileId +
                            " perms=" + sf.permissions);
                }
            }

            case "GETSHARED" -> {
                // CLTest GETSHARED <fileId> <outputPath>
                if (args.length < 3) {
                    System.out.println("Usage: GETSHARED <fileId> <outputPath>");
                    break;
                }
                if (!iam.hasToken()) {
                    System.out.println("You must LOGIN first.");
                    break;
                }

                String fileId    = args[1];
                String outputPath = args[2];

                IamClient.SharedKeys sk = iam.getSharedKeys(fileId);
                if (sk == null) {
                    System.out.println("No shared keys or no permission.");
                    break;
                }

                // enforce GET permission
                if (!sk.permissions.contains("GET")) {
                    System.out.println("You do NOT have GET permission for this file.");
                    break;
                }

                core.getSharedFile(fileId, outputPath, sk.fileKey);
                System.out.println("Shared file written to " + outputPath);
            }
            case "SEARCHSHARED" -> {
                //
                if (args.length < 2) {
                    System.out.println("Usage: SEARCHSHARED <keyword>");
                    break;
                }
                if (!iam.hasToken()) {
                    System.out.println("You must LOGIN first.");
                    break;
                }

                String keyword = args[1];

                // get all shares where I am the authorized user
                java.util.List<IamClient.SharedForMe> shares = iam.listSharesForMe();
                if (shares.isEmpty()) {
                    System.out.println("No files shared with you.");
                    break;
                }

                java.util.List<String> matches = new java.util.ArrayList<>();

                //  for each shared file with SEARCH permission ask OBSS
                for (IamClient.SharedForMe sf : shares) {
                    if (!sf.permissions.contains("SEARCH")) {
                        continue; // skip files where I don't have SEARCH permission
                    }

                    boolean found = core.searchSharedInFile(keyword, sf.fileId, sf.kwKey);
                    if (found) {
                        matches.add(sf.fileId);
                    }
                }

                //  print result
                if (matches.isEmpty()) {
                    System.out.println("No shared files contain keyword \"" + keyword + "\".");
                } else {
                    System.out.println("Shared files containing \"" + keyword + "\":");
                    for (String fid : matches) {
                        System.out.println(" - " + fid);
                    }
                }
            }

            default -> System.out.println("Unknown command");
        }
    }

    static java.util.List<String> parseKeywords(String s) {
        java.util.List<String> out = new java.util.ArrayList<>();
        for (String p : s.split("[,\\s]+")) if (!p.isBlank()) out.add(p.trim().toLowerCase());
        return out;
    }
}


