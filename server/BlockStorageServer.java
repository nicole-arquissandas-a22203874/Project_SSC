// Ref. Iniial code for a Java Implentation of a Block-Storage Server
// This is a naive and insecure implementation as initial reference for
// Project assignment

import java.io.*;
import java.net.*;
import java.util.*;

public class BlockStorageServer {
    private static final int PORT = 5000;
    private static final String BLOCK_DIR = "blockstorage";
    private static final String META_FILE = "metadata.ser";

    // Map token-> set of fileIds
    private static Map<String, Set<String>> metadata = new HashMap<>();

    public static void main(String[] args) throws IOException {
        File dir = new File(BLOCK_DIR);
        if (!dir.exists()) dir.mkdir();
        loadMetadata();

        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("BlockStorageServer running on port " + PORT);

        while (true) {
            Socket clientSocket = serverSocket.accept();
            new Thread(() -> handleClient(clientSocket)).start();
        }
    }

    private static void handleClient(Socket socket) {
        try (
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        ) {
            String command;
            while ((command = in.readUTF()) != null) {
                switch (command) {
                    case "STORE_BLOCK":
                        storeBlock(in, out);
                        break;
                    case "GET_BLOCK":
                        getBlock(in, out);
                        break;
                    case "LIST_BLOCKS":
                        listBlocks(out);
                        break;
                    case "SEARCH":
                        searchBlocks(in, out);
                        break;
                    case "EXIT":
                        return;
                    default:
                        out.writeUTF("ERROR: Unknown command");
                        out.flush();
                        break;
                }
            }
        } catch (IOException e) {
            System.err.println("Client disconnected.");
        }
    }

    private static void storeBlock(DataInputStream in, DataOutputStream out) throws IOException {
        String blockId = in.readUTF();
        int length = in.readInt();
        byte[] data = new byte[length];
        in.readFully(data); // data holds iv||ciphertext+tag

        // Save block file verbatim
        File blockFile = new File(BLOCK_DIR, blockId);
        try (FileOutputStream fos = new FileOutputStream(blockFile)) {
            fos.write(data);
        }

        // Read tokens (first block only will send >0)
        int tokenCount = in.readInt();
        if (tokenCount > 0) {
            String fileId = blockId.split("_block_")[0];
            for (int i = 0; i < tokenCount; i++) {
                String tok = in.readUTF();
                metadata.computeIfAbsent(tok, k -> new HashSet<>()).add(fileId);
            }
            saveMetadata();
        }

        out.writeUTF("OK");
        out.flush();
    }



    private static void getBlock(DataInputStream in, DataOutputStream out) throws IOException {
        String blockId = in.readUTF();
        File blockFile = new File(BLOCK_DIR, blockId);
        if (!blockFile.exists()) {
            out.writeInt(-1);
        } else {
            byte[] data = new byte[(int) blockFile.length()];
            try (FileInputStream fis = new FileInputStream(blockFile)) {
                fis.read(data);
            }
            out.writeInt(data.length);
            out.write(data);
        }
        out.flush();
    }

    private static void listBlocks(DataOutputStream out) throws IOException {
        String[] files = new File(BLOCK_DIR).list();
        if (files == null) files = new String[0];
        out.writeInt(files.length);
        for (String f : files) out.writeUTF(f);
        out.flush();
    }

    private static void searchBlocks(DataInputStream in, DataOutputStream out) throws IOException {
        String token = in.readUTF(); //Hmac token sent b7 the client
        List<String> results = new ArrayList<>(metadata.getOrDefault(token, Set.of()));
        out.writeInt(results.size());
        //envia os ids dos files que tem esse token
        for (String name : results){
            out.writeUTF(name);
        }
        out.flush();
    }


    private static void saveMetadata() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(META_FILE))) {
            oos.writeObject(metadata);
        } catch (IOException e) {
            System.err.println("Error saving metadata: " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private static void loadMetadata() {
        File f = new File(META_FILE);
        if (!f.exists()) return;
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(f))) {
            metadata = (Map<String, Set<String>>) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            System.err.println("Error loading metadata: " + e.getMessage());
        }
    }



}
