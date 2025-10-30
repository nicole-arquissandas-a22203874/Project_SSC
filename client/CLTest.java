

public class CLTest {

        public static void main(String[] args) throws Exception {
            if (args.length == 0) {
                System.out.println("""
        Usage:
          CLTest PUT <path/dir/file> <keywords>
          CLTest LIST
          CLTest SEARCH <keywords>
          CLTest GET <file> <path/dir>
          CLTest GET <keywords> <path/dir>
          CLTest GET CHECKINTEGRITY <path/dir/file>
      """);
                return;
            }

            ClientCore core = new ClientCore("localhost", 5000);
            String cmd = args[0].toUpperCase();

            switch (cmd) {
                case "PUT" -> core.put(java.nio.file.Paths.get(args[1]), parseKeywords(args[2]));
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
                default -> System.out.println("Unknown command");
            }
        }

        static java.util.List<String> parseKeywords(String s) {
            java.util.List<String> out = new java.util.ArrayList<>();
            for (String p : s.split("[,\\s]+")) if (!p.isBlank()) out.add(p.trim().toLowerCase());
            return out;
        }
    }


