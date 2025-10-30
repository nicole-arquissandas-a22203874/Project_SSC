import crypto.CryptoFactory;
import crypto.CryptoSuite;

import java.io.*;
import java.net.Socket;
import java.nio.file.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ClientCore {

         final String host;
         final int port;


    static CryptoSuite SUITE;

    static final String INDEX_FILE = "client_index.ser";      // filename -> blockIds
        static final String KW_INDEX_FILE = "client_keywords.ser";// filename -> keywords
        static final String KEYS_FILE = "client_keys.properties"; // AES/HMAC keys
        static final String FILEID_FILE = "client_fileids.ser";//filename->fileid


        static final int BLOCK_SIZE = 4096;

        static final class Keys {
            byte[] dataKey;
            byte[] kwKey;
            byte[] macKey;

        }
        static Keys KEYS;
        //file->blockids
        static Map<String, List<String>> fileIndex = new HashMap<>();
        //file->keywords
        static Map<String, List<String>> fileKeywords = new HashMap<>();
        //filename->fileid //para nao mandar filename para o servidor e mandar fileid
        static Map<String, String> fileIds = new HashMap<>();

    public ClientCore(String host, int port) {
        this.host = host;
        this.port = port;
        loadIndex();
        loadKeywords();
        loadFileIds();
        try {
            var cfg = CryptoFactory.Config.load(Paths.get("cryptoconfig.txt"));
            KEYS = loadOrCreateKeys();
            if ("AES_CBC_HMAC".equalsIgnoreCase(cfg.alg))
                SUITE = CryptoFactory.build(cfg, KEYS.dataKey, KEYS.macKey);
            else
                SUITE = CryptoFactory.build(cfg, KEYS.dataKey);
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize crypto suite", e);
        }
    }


  //
    public void put(Path filePath, List<String> keywords) throws Exception {
        try (Socket s = new Socket(host, port);
             DataInputStream in = new DataInputStream(s.getInputStream());
             DataOutputStream out = new DataOutputStream(s.getOutputStream())) {
            putFile_impl(filePath.toFile(), keywords, out, in);            // reuse your existing logic
            fileKeywords.put(filePath.getFileName().toString(), keywords);
            saveKeywords();
        }
    }

    public void listLocal() {
        listLocal_impl();                                             // reuse below
    }

    public void search(String keywords) throws Exception {
        try (Socket s = new Socket(host, port);
             DataInputStream in = new DataInputStream(s.getInputStream());
             DataOutputStream out = new DataOutputStream(s.getOutputStream())) {
            searchFiles_impl(keywords, out, in);
        }
    }

    public void getToDir(String filename, String outDir) throws Exception {
        try (Socket s = new Socket(host, port);
             DataInputStream in = new DataInputStream(s.getInputStream());
             DataOutputStream out = new DataOutputStream(s.getOutputStream())) {
            getFileToDir_impl(filename, outDir, out, in);
        }
    }

    public void getByKeywords(String keywords, String outDir) throws Exception {
        try (Socket s = new Socket(host, port);
             DataInputStream in = new DataInputStream(s.getInputStream());
             DataOutputStream out = new DataOutputStream(s.getOutputStream())) {
            getByKeywords_impl(keywords, outDir, out, in);            // see rename below
        }
    }

    public void checkIntegrity(String pathToLocalOriginal) throws Exception {
        try (Socket s = new Socket(host, port);
             DataInputStream in = new DataInputStream(s.getInputStream());
             DataOutputStream out = new DataOutputStream(s.getOutputStream())) {
            checkIntegrity_impl(pathToLocalOriginal, out, in);        // see rename below
        }
    }
//

    private static void putFile_impl(File file, List<String> keywords, DataOutputStream out, DataInputStream in) throws Exception {
            String filename = file.getName();
            List<String> blocks = new ArrayList<>();
            String fileId = UUID.randomUUID().toString().replace("-", "");
            fileIds.put(filename, fileId);
            saveFileIds();
            try (InputStream fis = Files.newInputStream(file.toPath())) {
                byte[] buf = new byte[BLOCK_SIZE];
                int n, idx = 0;
                while ((n = fis.read(buf)) > 0) {
                    byte[] plaintext = Arrays.copyOf(buf, n);

                    byte[] aad = (fileId + ":" + idx).getBytes(); //idx e o block number
                    String blockId = fileId + "_block_" + idx;
                    byte[] blob = SUITE.encrypt(plaintext, aad); // suite returns iv||ct||tag por exemplo para aes gcm(or suite-specific)
                    out.writeUTF("STORE_BLOCK");
                    out.writeUTF(blockId);
                    out.writeInt(blob.length);
                    out.write(blob);
                    // se block for 0 entao envia os tokens
                    if (idx == 0) {
                        List<String> toks = new ArrayList<>();
                        for (String kw : keywords) if (!kw.isBlank()) toks.add(token(KEYS.kwKey, kw));
                        out.writeInt(toks.size());
                        for (String t : toks) out.writeUTF(t);
                    } else {
                        out.writeInt(0);
                    }

                    out.flush();
                    String resp = in.readUTF();
                    if (!"OK".equals(resp)) die("server returned: " + resp);

                    blocks.add(blockId);
                    System.out.print(".");
                    idx++;
                }
            }
            fileIndex.put(filename, blocks);
            saveIndex();


            System.out.println("\nPUT: stored " + filename + " (" + blocks.size() + " blocks)");
        }

       private static void listLocal_impl() {
            if (fileIndex.isEmpty()) { System.out.println("No files in local index."); return; }
            System.out.println("LIST:");
            fileIndex.keySet().forEach(f -> System.out.println(" - " + f));
        }

       private static void searchFiles_impl(String keywords, DataOutputStream out, DataInputStream in) throws Exception {
            String tok = token(KEYS.kwKey, keywords);
            out.writeUTF("SEARCH");
            out.writeUTF(tok);
            out.flush();
            int count = in.readInt();
            System.out.println("SEARCH results:");
            for (int i=0;i<count;i++) {
                String filename=findFileNameById(in.readUTF());

                System.out.println(" - " + filename);
            }

        }
    private static String findFileNameById(String fileId) {
        for (Map.Entry<String,String> e : fileIds.entrySet()) {
            if (e.getValue().equals(fileId)){
                return e.getKey(); // filename
            }
        }
        return null;
    }

       private static void getFileToDir_impl(String filename, String outDir, DataOutputStream out, DataInputStream in) throws Exception {
            String fileid=fileIds.get(filename);
            List<String> blocks = fileIndex.get(filename);
            if (blocks == null) die("not in local index: " + filename);
            Path dir = Paths.get(outDir); Files.createDirectories(dir);
            Path outFile = dir.resolve(filename);

            try (OutputStream fos = Files.newOutputStream(outFile, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                int i = 0;
                for (String blockId : blocks) {
                    out.writeUTF("GET_BLOCK");
                    out.writeUTF(blockId);
                    out.flush();
                    int len = in.readInt();
                    if (len == -1) die("missing block on server: " + blockId);
                    byte[] blob = in.readNBytes(len); //blob e o bloco encriptado
                    byte[] aad = (fileid + ":" + i).getBytes();
                    byte[] plain = SUITE.decrypt(blob, aad);
                    fos.write(plain);
                    System.out.print(".");
                    i++;
                }
            }
            System.out.println("\nGET: reconstructed to " + outFile.toAbsolutePath());
        }

        private static void getByKeywords_impl(String keywords, String outDir, DataOutputStream out, DataInputStream in) throws Exception {
            String tok = token(KEYS.kwKey, keywords);
            out.writeUTF("SEARCH");
            out.writeUTF(tok);
            out.flush();
            int count = in.readInt();
            if (count == 0) { System.out.println("No matches."); return; }
            List<String> names = new ArrayList<>();
            for (int i=0;i<count;i++){
                String filename=findFileNameById(in.readUTF());
                names.add(filename);
            }

            for (String name : names) {
                System.out.println("Downloading " + name);
                getFileToDir_impl(name, outDir, out, in);
            }
        }

       private static void checkIntegrity_impl(String pathToFile, DataOutputStream out, DataInputStream in) throws Exception {

            Path p = Paths.get(pathToFile);
            String filename = p.getFileName().toString();
            List<String> blocks = fileIndex.get(filename);
            String fileid=fileIds.get(filename);
            if (blocks == null) die("not in local index: " + filename);

            // 1) verify every block via GCM tag
            for (int i=0;i<blocks.size();i++) {
                String blockId = blocks.get(i);
                out.writeUTF("GET_BLOCK");
                out.writeUTF(blockId);
                out.flush();
                int len = in.readInt();
                if (len == -1) die("missing block: " + blockId);
                byte[] blob = in.readNBytes(len); //blob e o bloco encriptado
                byte[] aad = (fileid + ":" + i).getBytes();

                try {
                    SUITE.decrypt(blob, aad);
                }
                catch (Exception ex) {
                    die("Integrity FAIL on block " + i);
                }
            }
           System.out.println("Blocks OK (" + SUITE.getClass().getSimpleName().replace("Suite", "") + ").");


           // 2) verify keyword linkage still returns this file
            List<String> kws = fileKeywords.getOrDefault(filename, List.of());
            for (String kw : kws) {
                String tok = token(KEYS.kwKey, kw);
                out.writeUTF("SEARCH");
                out.writeUTF(tok);
                out.flush();
                int n = in.readInt();
                boolean found = false;
                for (int i=0;i<n;i++) {
                    if (fileid.equals(in.readUTF())){
                        found = true;
                    }
                }
                if (!found) die("Keyword link missing: \"" + kw + "\"");
            }
            System.out.println("Keywords OK (" + kws.size() + ").");
            System.out.println("CHECKINTEGRITY: PASS for " + filename);
        }

        // ====== funcoes para ajudar ======

       private static List<String> parseKeywords(String s) {
            List<String> res = new ArrayList<>();
            for (String w : s.split("[,\\s]+")) if (!w.isBlank()) res.add(w.trim().toLowerCase());
            return res;
        }
       private static boolean looksLikeFileName(String s) { return s.contains(".") && !s.contains(" "); }

      private  static void die(String msg) { System.out.println(msg); System.exit(1); }

       private static void loadIndex() {
            File f = new File(INDEX_FILE);

            if (!f.exists()) return;

            try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(f))) {
                //noinspection unchecked
                fileIndex = (Map<String, List<String>>) ois.readObject();
            } catch (Exception e) { System.err.println("loadIndex: " + e.getMessage()); }
        }
      private  static void saveIndex() {
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(INDEX_FILE))) {
                oos.writeObject(fileIndex);
            } catch (IOException e) { System.err.println("saveIndex: " + e.getMessage()); }
        }
      private  static void loadKeywords() {
            File f = new File(KW_INDEX_FILE); if (!f.exists()) return;
            try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(f))) {
                //noinspection unchecked
                fileKeywords = (Map<String, List<String>>) ois.readObject();
            } catch (Exception e) { System.err.println("loadKeywords: " + e.getMessage()); }
        }
       private static void saveKeywords() {
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(KW_INDEX_FILE))) {
                oos.writeObject(fileKeywords);
            } catch (IOException e) { System.err.println("saveKeywords: " + e.getMessage()); }
        }
    private  static void loadFileIds() {
        File f = new File(FILEID_FILE); if (!f.exists()) return;
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(f))) {
            //noinspection unchecked
            fileIds = (Map<String, String>) ois.readObject();
        } catch (Exception e) { System.err.println("loadFilesIds: " + e.getMessage()); }
    }
    private static void saveFileIds() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(FILEID_FILE))) {
            oos.writeObject(fileIds);
        } catch (IOException e) { System.err.println("saveFilesIds: " + e.getMessage()); }
    }


    private static Keys loadOrCreateKeys() {
        try {
            // 1. Read crypto config first
            var cfg = crypto.CryptoFactory.Config.load(Paths.get("cryptoconfig.txt"));
            int dataBytes = cfg.dataKeySizeBits / 8;
            int macBytes = cfg.macKeySizeBits / 8;

            // 2. Load or create keys file
            Properties p = new Properties();
            File f = new File(KEYS_FILE);
            if (f.exists()) try (var r = new FileReader(f)) { p.load(r); }

            Keys k = new Keys();

            // === DATA KEY ===
            if (p.containsKey("DATAKEY")) {
                k.dataKey = Base64.getDecoder().decode(p.getProperty("DATAKEY"));
            } else {
                k.dataKey = random(dataBytes);
                p.setProperty("DATAKEY", Base64.getEncoder().encodeToString(k.dataKey));
            }

            // === KEYWORD KEY ===
            if (p.containsKey("KWKEY")) {
                k.kwKey = Base64.getDecoder().decode(p.getProperty("KWKEY"));
            } else {
                k.kwKey = random(32); // Always 256 bits for HMAC-SHA256
                p.setProperty("KWKEY", Base64.getEncoder().encodeToString(k.kwKey));
            }

            // === MAC KEY (only for AES_CBC_HMAC) ===
            if ("AES_CBC_HMAC".equalsIgnoreCase(cfg.alg)) {
                if (p.containsKey("MACKEY")) {
                    k.macKey = Base64.getDecoder().decode(p.getProperty("MACKEY"));
                } else {
                    k.macKey = random(macBytes);
                    p.setProperty("MACKEY", Base64.getEncoder().encodeToString(k.macKey));
                }
            }

            // Save if any key was newly created
            try (var w = new FileWriter(f)) { p.store(w, "client keys"); }

            return k;
        } catch (Exception e) {
            throw new RuntimeException("Failed to load or create keys", e);
        }
    }


       private static byte[] random(int n){
            byte[] b=new byte[n];
            new java.security.SecureRandom().nextBytes(b);
            return b;
        }


       private static String token(byte[] kwKey, String kw) {
            try {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(kwKey,"HmacSHA256"));
                return Base64.getEncoder().encodeToString(mac.doFinal(kw.trim().toLowerCase().getBytes()));
            } catch (Exception e) { throw new RuntimeException(e); }
        }
    }


