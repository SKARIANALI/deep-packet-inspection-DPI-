import dpi.DPIEngine;
import dpi.Types;
import java.util.Scanner;
import java.util.Set;
import javax.swing.SwingUtilities;

public class Main {
    public static void main(String[] args) {
        if (args.length == 0 || containsFlag(args, "--ui")) {
            SwingUtilities.invokeLater(PacketAnalyzerUI::new);
            return;
        }

        runCli(args);
    }

    private static boolean containsFlag(String[] args, String flag) {
        for (String arg : args) {
            if (flag.equalsIgnoreCase(arg)) {
                return true;
            }
        }
        return false;
    }

    private static void runCli(String[] args) {
        if (args.length < 2) {
            printUsage();
            return;
        }

        String inputFile = args[0];
        String outputFile = args[1];
        DPIEngine.Config config = new DPIEngine.Config();
        boolean interactive = false;
        String listAppName = null;

        int index = 2;
        if (index < args.length && !args[index].startsWith("--")) {
            try {
                config.numLoadBalancers = Integer.parseInt(args[index]);
            } catch (NumberFormatException ignored) {
            }
            index++;
        }
        if (index < args.length && !args[index].startsWith("--")) {
            try {
                config.fpsPerLb = Integer.parseInt(args[index]);
            } catch (NumberFormatException ignored) {
            }
            index++;
        }

        DPIEngine engine = new DPIEngine(config);
        while (index < args.length) {
            String option = args[index];
            switch (option) {
                case "--rules" -> {
                    index++;
                    if (index < args.length) {
                        config.rulesFile = args[index];
                    } else {
                        System.err.println("Missing value for --rules");
                        return;
                    }
                }
                case "--block-ip" -> {
                    index++;
                    if (index < args.length) {
                        try {
                            engine.blockIp(args[index]);
                        } catch (IllegalArgumentException e) {
                            System.err.println("Invalid IP for --block-ip: " + args[index]);
                        }
                    } else {
                        System.err.println("Missing value for --block-ip");
                        return;
                    }
                }
                case "--block-app" -> {
                    index++;
                    if (index < args.length) {
                        engine.blockApp(args[index].toUpperCase());
                    } else {
                        System.err.println("Missing value for --block-app");
                        return;
                    }
                }
                case "--block-domain" -> {
                    index++;
                    if (index < args.length) {
                        engine.blockDomain(args[index]);
                    } else {
                        System.err.println("Missing value for --block-domain");
                        return;
                    }
                }
                case "--block-port" -> {
                    index++;
                    if (index < args.length) {
                        try {
                            engine.blockPort(Integer.parseInt(args[index]));
                        } catch (NumberFormatException e) {
                            System.err.println("Invalid port for --block-port: " + args[index]);
                            return;
                        }
                    } else {
                        System.err.println("Missing value for --block-port");
                        return;
                    }
                }
                case "--list-app" -> {
                    index++;
                    if (index < args.length) {
                        listAppName = args[index].toUpperCase();
                    } else {
                        System.err.println("Missing value for --list-app");
                        return;
                    }
                }
                case "--show-apps" -> {
                    printAppTypes();
                    return;
                }
                case "--interactive" -> interactive = true;
                case "--help", "-h" -> {
                    printUsage();
                    return;
                }
                default -> {
                    System.err.println("Unknown option: " + option);
                    printUsage();
                    return;
                }
            }
            index++;
        }

        if (!config.rulesFile.isEmpty()) {
            if (!engine.loadRules(config.rulesFile)) {
                System.err.println("Warning: failed to load rules from " + config.rulesFile);
            }
        }

        if (listAppName != null) {
            printAppSources(engine, inputFile, listAppName);
            return;
        }

        if (interactive) {
            previewDomains(engine, inputFile);
            promptForBlocking(engine);
        }

        engine.processFile(inputFile, outputFile);
    }

    private static void printUsage() {
        System.out.println("Usage: java Main <input.pcap> <output.pcap> [numLoadBalancers] [fpsPerLb] [options]");
        System.out.println("Example: java Main test_dpi.pcap output.pcap 2 2 --rules rules.txt --block-app YOUTUBE --block-domain facebook");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --rules <file>         Load blocked rules from a file");
        System.out.println("  --block-ip <ip>        Block a source IP address");
        System.out.println("  --block-app <app>      Block an application type (e.g. YOUTUBE)");
        System.out.println("  --block-domain <name>  Block a domain substring or wildcard pattern");
        System.out.println("  --block-port <port>    Block a destination port");
        System.out.println("  --list-app <app>       List source IPs and ports for the given app");
        System.out.println("  --show-apps            Print supported app names");
        System.out.println("  --interactive          Preview domains and choose runtime blocking");
        System.out.println("  --ui                   Launch the desktop dashboard");
        System.out.println("  --help, -h             Show this help message");
    }

    private static void printAppSources(DPIEngine engine, String inputFile, String appName) {
        System.out.println("Scanning PCAP for app: " + appName);
        Set<String> sources = engine.collectAppSources(inputFile, appName);
        if (sources.isEmpty()) {
            System.out.println("No source IP/port pairs found for app " + appName + ".");
            return;
        }
        System.out.println("Source IP:Port pairs for app " + appName + ":");
        sources.stream().sorted().forEach(source -> System.out.println("  " + source));
    }

    private static void printAppTypes() {
        System.out.println("Supported apps:");
        for (Types.AppType type : Types.AppType.values()) {
            System.out.println("  " + type.name());
        }
    }

    private static boolean isValidIp(String ip) {
        try {
            Types.parseIp(ip);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static boolean isAppTypeName(String token) {
        for (Types.AppType type : Types.AppType.values()) {
            if (type.name().equalsIgnoreCase(token) || Types.appTypeToString(type).equalsIgnoreCase(token)) {
                return true;
            }
        }
        return false;
    }

    private static void previewDomains(DPIEngine engine, String inputFile) {
        System.out.println("Scanning PCAP for domains...");
        Set<String> domains = engine.collectDomains(inputFile);
        if (domains.isEmpty()) {
            System.out.println("No domains were detected in the PCAP file.");
            return;
        }
        domains.removeIf(domain -> engine.isDomainBlocked(domain)
                || engine.isAppBlocked(Types.sniToAppType(domain)));
        if (domains.isEmpty()) {
            System.out.println("All detected domains are already blocked.");
            return;
        }
        System.out.println("Detected domains:");
        domains.stream().sorted().forEach(domain -> System.out.println("  " + domain));
    }

    private static void promptForBlocking(DPIEngine engine) {
        try (Scanner scanner = new Scanner(System.in)) {
            System.out.println();
            processMultiLineInput(scanner,
                    "Enter comma-separated source IPs to block, or press Enter on an empty line to skip:",
                    token -> {
                        String ip = token.trim();
                        if (!ip.isEmpty()) {
                            if (isValidIp(ip)) {
                                engine.blockIp(ip);
                            } else if (isAppTypeName(ip)) {
                                engine.blockApp(ip);
                                System.out.println("Detected app name in IP prompt; blocked app: " + ip);
                            } else {
                                System.err.println("Skipping invalid IP: " + ip);
                            }
                        }
                    });

            processMultiLineInput(scanner,
                    "Enter comma-separated app names to block (e.g. YOUTUBE), or press Enter on an empty line to skip:",
                    token -> {
                        String app = token.trim();
                        if (!app.isEmpty()) {
                            engine.blockApp(app);
                        }
                    });

            processMultiLineInput(scanner,
                    "Enter comma-separated domains to block, or press Enter on an empty line to skip:",
                    token -> {
                        String domain = token.trim();
                        if (!domain.isEmpty()) {
                            engine.blockDomain(domain);
                        }
                    });

            processMultiLineInput(scanner,
                    "Enter comma-separated ports to block, or press Enter on an empty line to skip:",
                    token -> {
                        String portToken = token.trim();
                        if (!portToken.isEmpty()) {
                            try {
                                engine.blockPort(Integer.parseInt(portToken));
                            } catch (NumberFormatException e) {
                                System.err.println("Skipping invalid port: " + portToken);
                            }
                        }
                    });
        }
    }

    private static void processMultiLineInput(Scanner scanner, String prompt, java.util.function.Consumer<String> consumer) {
        System.out.println(prompt);
        while (true) {
            String line = scanner.nextLine();
            if (line == null) {
                break;
            }
            line = line.trim();
            if (line.isEmpty()) {
                break;
            }
            for (String token : line.split(",")) {
                consumer.accept(token);
            }
        }
    }
}
