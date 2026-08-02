import dpi.DPIEngine;
import dpi.Types;
import java.awt.*;
import java.awt.geom.Arc2D;
import java.awt.geom.Point2D;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.swing.*;
import javax.swing.border.EmptyBorder;

public class PacketAnalyzerUI extends JFrame {
    private final JTextField inputFileField = new JTextField();
    private final JTextField outputFileField = new JTextField();
    private final JTextField rulesFileField = new JTextField();
    private final JTextField loadBalancersField = new JTextField("2");
    private final JTextField fpsField = new JTextField("2");
    private final JComboBox<String> ruleTypeCombo = new JComboBox<>(new String[]{"IP", "Application", "Domain", "Port"});
    private final JTextField ruleValueField = new JTextField();
    private final DefaultListModel<String> ruleModel = new DefaultListModel<>();
    private final JList<String> ruleList = new JList<>(ruleModel);
    private final JTextArea logArea = new JTextArea();
    private final JTextArea previewArea = new JTextArea();
    private final JLabel statusLabel = new JLabel("Ready");
    private final JLabel sidebarTitleLabel = new JLabel("Quick Control");
    private final JLabel sidebarStatusLabel = new JLabel("System ready");
    private final JLabel sidebarHintLabel = new JLabel("Start a scan to see live results.");
    private final JButton dashboardButton = new JButton("Dashboard");
    private final JButton rulesButton = new JButton("Rules");
    private final JButton logsButton = new JButton("Logs");
    private final DashboardCard packetsCard = new DashboardCard("Total Packets", "0");
    private final DashboardCard forwardedCard = new DashboardCard("Forwarded", "0");
    private final DashboardCard droppedCard = new DashboardCard("Dropped", "0");
    private final DashboardCard rulesCard = new DashboardCard("Rules", "0");
    private final StatChartPanel chartPanel = new StatChartPanel();
    private boolean darkMode = false;
    private long currentTotalPackets = 0;
    private long currentForwardedPackets = 0;
    private long currentDroppedPackets = 0;
    private final Color lightBg = new Color(248, 250, 252);
    private final Color lightFg = new Color(15, 23, 42);
    private final Color darkBg = new Color(15, 23, 42);
    private final Color darkFg = new Color(226, 232, 240);
    private final Color accentBlue = new Color(37, 99, 235);
    private final Color accentGreen = new Color(16, 185, 129);
    private final Color accentPurple = new Color(139, 92, 246);
    private final Color accentRed = new Color(248, 113, 113);
    private final Color accentAmber = new Color(245, 158, 11);

    public PacketAnalyzerUI() {
        super("Packet Analyzer Dashboard");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1100, 780);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout(10, 10));

        // place sidebar and main center in a split pane so they never overlap
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        split.setLeftComponent(buildSidebar());
        split.setRightComponent(buildMainCenterPanel());
        split.setDividerLocation(240);
        split.setDividerSize(6);
        split.setOneTouchExpandable(false);
        split.setContinuousLayout(true);
        split.setBorder(null);
        add(split, BorderLayout.CENTER);
        add(buildBottomPanel(), BorderLayout.SOUTH);

        populateDefaultPaths();
        applyTheme();
        setVisible(true);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(PacketAnalyzerUI::new);
    }

    private JPanel buildSidebar() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(accentPurple, 2),
                BorderFactory.createEmptyBorder(12, 12, 12, 12)));
        panel.setPreferredSize(new Dimension(220, 0));
        panel.setOpaque(true);
        panel.setBackground(lightBg);

        sidebarTitleLabel.setFont(new Font("Segoe UI", Font.BOLD, 15));
        sidebarTitleLabel.setForeground(accentPurple);
        panel.add(sidebarTitleLabel);
        panel.add(Box.createVerticalStrut(10));

        sidebarStatusLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));
        sidebarStatusLabel.setForeground(accentGreen);
        panel.add(sidebarStatusLabel);
        panel.add(Box.createVerticalStrut(6));

        sidebarHintLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        sidebarHintLabel.setForeground(new Color(100, 116, 139));
        sidebarHintLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(sidebarHintLabel);
        panel.add(Box.createVerticalStrut(16));

        dashboardButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        rulesButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        logsButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        styleButton(dashboardButton, accentBlue, Color.WHITE);
        styleButton(rulesButton, accentPurple, Color.WHITE);
        styleButton(logsButton, accentAmber, Color.WHITE);

        dashboardButton.addActionListener(e -> {
            previewArea.setText("Dashboard view active.\nUse the controls above to run or inspect the capture.");
            statusLabel.setText("Dashboard view active.");
        });
        rulesButton.addActionListener(e -> {
            previewArea.setText("Active rules:\n" + (ruleModel.size() == 0 ? "No rules configured." : String.join("\n", getRulePreview())));
            statusLabel.setText("Rule view active.");
        });
        logsButton.addActionListener(e -> {
            previewArea.setText("Live log and output feed will appear here after each analysis run.");
            statusLabel.setText("Logs view active.");
        });

        panel.add(dashboardButton);
        panel.add(Box.createVerticalStrut(8));
        panel.add(rulesButton);
        panel.add(Box.createVerticalStrut(8));
        panel.add(logsButton);
        panel.add(Box.createVerticalStrut(16));

        JPanel miniCard = new JPanel();
        miniCard.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(accentGreen, 1),
                BorderFactory.createEmptyBorder(8, 8, 8, 8)));
        miniCard.setOpaque(false);
        JLabel info = new JLabel("<html><b>Ready for capture</b><br/>Input and output files are prepared.</html>");
        info.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        miniCard.add(info);
        panel.add(miniCard);

        return panel;
    }

    private JPanel buildTopPanel() {
        GradientPanel panel = new GradientPanel();
        panel.setBorder(new EmptyBorder(10, 10, 5, 10));
        panel.setPreferredSize(new Dimension(0, 420));

        JLabel title = new JLabel("Packet Analyzer Control Center", SwingConstants.CENTER);
        title.setFont(new Font("Segoe UI", Font.BOLD, 24));
        title.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 0));
        title.setForeground(Color.WHITE);
        panel.add(title, BorderLayout.NORTH);

        JPanel body = new JPanel(new GridBagLayout());
        body.setOpaque(false);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 8, 8, 8);
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        gbc.weighty = 0.3;
        gbc.fill = GridBagConstraints.BOTH;
        body.add(buildStatsPanel(), gbc);

        JPanel inputPanel = buildInputPanel();
        inputPanel.setPreferredSize(new Dimension(520, 240));
        inputPanel.setMinimumSize(new Dimension(420, 220));
        JPanel rulePanel = buildRulePanel();
        rulePanel.setPreferredSize(new Dimension(520, 240));
        rulePanel.setMinimumSize(new Dimension(420, 220));

        gbc.gridy = 1;
        gbc.gridwidth = 1;
        gbc.weightx = 0.5;
        gbc.weighty = 0.7;
        body.add(inputPanel, gbc);

        gbc.gridx = 1;
        body.add(rulePanel, gbc);

        panel.add(body, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildStatsPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder(BorderFactory.createLineBorder(accentBlue, 1), "Live Dashboard"),
                BorderFactory.createEmptyBorder(6, 6, 6, 6)));

        JPanel cards = new JPanel(new GridLayout(1, 4, 10, 0));
        cards.add(packetsCard);
        cards.add(forwardedCard);
        cards.add(droppedCard);
        cards.add(rulesCard);
        panel.add(cards, BorderLayout.NORTH);
        panel.add(chartPanel, BorderLayout.CENTER);

        return panel;
    }

    private JPanel buildInputPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder(BorderFactory.createLineBorder(accentGreen, 1), "Input and Output"),
                BorderFactory.createEmptyBorder(6, 6, 6, 6)));
        panel.setPreferredSize(new Dimension(0, 220));
        panel.setMinimumSize(new Dimension(420, 190));

        panel.add(createLabeledField("Input PCAP:", inputFileField, createBrowseButton(inputFileField, "Choose input PCAP", true)));
        panel.add(Box.createVerticalStrut(8));
        panel.add(createLabeledField("Output PCAP:", outputFileField, createBrowseButton(outputFileField, "Choose output PCAP", false)));
        panel.add(Box.createVerticalStrut(8));
        panel.add(createLabeledField("Rules File:", rulesFileField, createBrowseButton(rulesFileField, "Choose rules file", false)));
        panel.add(Box.createVerticalStrut(10));

        JPanel configPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        configPanel.setOpaque(false);
        configPanel.add(new JLabel("Load Balancers:"));
        configPanel.add(loadBalancersField);
        loadBalancersField.setPreferredSize(new Dimension(70, 28));
        configPanel.add(new JLabel("FPS per LB:"));
        configPanel.add(fpsField);
        fpsField.setPreferredSize(new Dimension(70, 28));
        panel.add(configPanel);

        return panel;
    }

    private JPanel buildRulePanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder(BorderFactory.createLineBorder(accentPurple, 1), "Blocking Rules"),
                BorderFactory.createEmptyBorder(6, 6, 6, 6)));
        panel.setPreferredSize(new Dimension(0, 220));
        panel.setMinimumSize(new Dimension(420, 190));

        JPanel top = new JPanel(new GridBagLayout());
        top.setOpaque(false);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.gridy = 0;

        gbc.gridx = 0;
        gbc.anchor = GridBagConstraints.WEST;
        top.add(new JLabel("Rule Type:"), gbc);

        gbc.gridx = 1;
        ruleTypeCombo.setPreferredSize(new Dimension(120, 28));
        top.add(ruleTypeCombo, gbc);

        gbc.gridx = 2;
        top.add(new JLabel("Value:"), gbc);

        gbc.gridx = 3;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        ruleValueField.setPreferredSize(new Dimension(260, 28));
        top.add(ruleValueField, gbc);

        gbc.gridx = 4;
        gbc.weightx = 0;
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.EAST;
        JButton addRuleButton = new JButton("Add Rule");
        addRuleButton.addActionListener(e -> addRule());
        top.add(addRuleButton, gbc);

        panel.add(top);

        JPanel listPanel = new JPanel(new BorderLayout(6, 6));
        listPanel.setPreferredSize(new Dimension(0, 170));
        ruleList.setBorder(BorderFactory.createEtchedBorder());
        listPanel.add(new JScrollPane(ruleList), BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JButton removeButton = new JButton("Remove Selected");
        removeButton.addActionListener(e -> removeSelectedRule());
        JButton clearButton = new JButton("Clear Rules");
        clearButton.addActionListener(e -> ruleModel.clear());
        JButton saveButton = new JButton("Save Rules");
        saveButton.addActionListener(e -> saveRulesToFile());
        JButton loadButton = new JButton("Load Rules");
        loadButton.addActionListener(e -> loadRulesFromFile());
        buttons.add(removeButton);
        buttons.add(clearButton);
        buttons.add(saveButton);
        buttons.add(loadButton);
        listPanel.add(buttons, BorderLayout.SOUTH);

        panel.add(listPanel);
        return panel;
    }

    private JPanel buildCenterPanel() {
        JPanel panel = new JPanel(new GridLayout(1, 2, 10, 0));
        panel.setBorder(new EmptyBorder(5, 10, 5, 10));
        panel.setOpaque(false);

        JPanel logPanel = new JPanel(new BorderLayout());
        logPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder(BorderFactory.createLineBorder(accentBlue, 1), "Live Log"),
                BorderFactory.createEmptyBorder(6, 6, 6, 6)));
        logArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        logArea.setEditable(false);
        logArea.setLineWrap(true);
        logArea.setWrapStyleWord(true);
        logPanel.add(new JScrollPane(logArea), BorderLayout.CENTER);

        JPanel previewPanel = new JPanel(new BorderLayout());
        previewPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder(BorderFactory.createLineBorder(accentGreen, 1), "Preview / Results"),
                BorderFactory.createEmptyBorder(6, 6, 6, 6)));
        previewArea.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        previewArea.setEditable(false);
        previewArea.setLineWrap(true);
        previewArea.setWrapStyleWord(true);
        previewPanel.add(new JScrollPane(previewArea), BorderLayout.CENTER);

        panel.add(logPanel);
        panel.add(previewPanel);
        return panel;
    }

    private JPanel buildMainCenterPanel() {
        JPanel main = new JPanel(new BorderLayout(10, 10));
        main.setOpaque(true);
        main.setBackground(lightBg);
        main.setBorder(new EmptyBorder(10, 10, 10, 10));
        main.add(buildTopPanel(), BorderLayout.NORTH);
        main.add(buildCenterPanel(), BorderLayout.CENTER);
        return main;
    }

    private JPanel buildBottomPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 8));
        panel.setBorder(new EmptyBorder(5, 10, 10, 10));
        panel.setOpaque(false);

        JButton runButton = new JButton("Run Analysis");
        runButton.setFont(new Font("Segoe UI", Font.BOLD, 13));
        styleButton(runButton, accentGreen, Color.WHITE);
        runButton.addActionListener(e -> runAnalysis());
        panel.add(runButton);

        JButton previewButton = new JButton("Preview Domains");
        styleButton(previewButton, accentBlue, Color.WHITE);
        previewButton.addActionListener(e -> previewDomains());
        panel.add(previewButton);

        JButton insightsButton = new JButton("Preview Insights");
        styleButton(insightsButton, accentPurple, Color.WHITE);
        insightsButton.addActionListener(e -> previewInsights());
        panel.add(insightsButton);

        JButton appButton = new JButton("Show Supported Apps");
        styleButton(appButton, accentAmber, Color.WHITE);
        appButton.addActionListener(e -> showSupportedApps());
        panel.add(appButton);

        JButton clearLogButton = new JButton("Clear Log");
        styleButton(clearLogButton, accentRed, Color.WHITE);
        clearLogButton.addActionListener(e -> logArea.setText(""));
        panel.add(clearLogButton);

        JButton sampleInputButton = new JButton("Use Sample Input");
        styleButton(sampleInputButton, accentBlue, Color.WHITE);
        sampleInputButton.addActionListener(e -> useSampleInput());
        panel.add(sampleInputButton);

        JButton sampleOutputButton = new JButton("Use Sample Output");
        styleButton(sampleOutputButton, accentGreen, Color.WHITE);
        sampleOutputButton.addActionListener(e -> useSampleOutput());
        panel.add(sampleOutputButton);

        JButton themeButton = new JButton("Toggle Theme");
        styleButton(themeButton, accentPurple, Color.WHITE);
        themeButton.addActionListener(e -> toggleTheme());
        panel.add(themeButton);

        JButton openFolderButton = new JButton("Open Output Folder");
        styleButton(openFolderButton, accentAmber, Color.WHITE);
        openFolderButton.addActionListener(e -> openOutputFolder());
        panel.add(openFolderButton);

        panel.add(Box.createHorizontalStrut(20));
        JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        statusPanel.setOpaque(false);
        statusLabel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(accentGreen, 1),
                BorderFactory.createEmptyBorder(4, 8, 4, 8)));
        statusLabel.setForeground(accentGreen.darker());
        statusPanel.add(statusLabel);
        panel.add(statusPanel);

        return panel;
    }

    private JButton createBrowseButton(JTextField target, String title, boolean isInputFile) {
        JButton button = new JButton("Browse");
        styleButton(button, accentBlue, Color.WHITE);
        button.setPreferredSize(new Dimension(80, 28));
        button.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle(title);
            if (isInputFile) {
                chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            } else {
                chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            }
            int result = chooser.showOpenDialog(this);
            if (result == JFileChooser.APPROVE_OPTION) {
                target.setText(chooser.getSelectedFile().getAbsolutePath());
            }
        });
        return button;
    }

    private JPanel createLabeledField(String labelText, JTextField field, JButton browseButton) {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setOpaque(false);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);

        JLabel label = new JLabel(labelText);
        label.setPreferredSize(new Dimension(110, 28));
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        panel.add(label, gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        field.setPreferredSize(new Dimension(360, 28));
        field.setMinimumSize(new Dimension(120, 28));
        panel.add(field, gbc);

        if (browseButton != null) {
            gbc.gridx = 2;
            gbc.weightx = 0;
            gbc.fill = GridBagConstraints.NONE;
            panel.add(browseButton, gbc);
        }

        return panel;
    }

    private void addRule() {
        String type = (String) ruleTypeCombo.getSelectedItem();
        String value = ruleValueField.getText().trim();
        if (value.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a value for the rule.");
            return;
        }
        String formatted = type + ":" + value;
        ruleModel.addElement(formatted);
        ruleValueField.setText("");
        statusLabel.setText("Rule added: " + formatted);
        updateDashboardStats(currentTotalPackets, currentForwardedPackets, currentDroppedPackets, ruleModel.size());
    }

    private void removeSelectedRule() {
        int index = ruleList.getSelectedIndex();
        if (index >= 0) {
            ruleModel.remove(index);
            statusLabel.setText("Selected rule removed.");
            updateDashboardStats(currentTotalPackets, currentForwardedPackets, currentDroppedPackets, ruleModel.size());
        }
    }

    private void saveRulesToFile() {
        String path = rulesFileField.getText().trim();
        if (path.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please choose a rules file first.");
            return;
        }
        try (BufferedWriter writer = Files.newBufferedWriter(Path.of(path), StandardCharsets.UTF_8)) {
            for (int i = 0; i < ruleModel.size(); i++) {
                writer.write(ruleModel.getElementAt(i));
                writer.newLine();
            }
            appendLog("Rules saved to " + path + "\n");
            statusLabel.setText("Rules saved successfully.");
            updateDashboardStats(currentTotalPackets, currentForwardedPackets, currentDroppedPackets, ruleModel.size());
        } catch (IOException ex) {
            appendLog("Failed to save rules: " + ex.getMessage() + "\n");
            statusLabel.setText("Failed to save rules.");
        }
    }

    private void loadRulesFromFile() {
        String path = rulesFileField.getText().trim();
        if (path.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please choose a rules file first.");
            return;
        }
        try {
            List<String> lines = Files.readAllLines(Path.of(path), StandardCharsets.UTF_8);
            ruleModel.clear();
            for (String line : lines) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty()) {
                    ruleModel.addElement(trimmed);
                }
            }
            appendLog("Rules loaded from " + path + "\n");
            statusLabel.setText("Rules loaded successfully.");
            updateDashboardStats(currentTotalPackets, currentForwardedPackets, currentDroppedPackets, ruleModel.size());
        } catch (IOException ex) {
            appendLog("Failed to load rules: " + ex.getMessage() + "\n");
            statusLabel.setText("Failed to load rules.");
        }
    }

    private void runAnalysis() {
        String inputFile = inputFileField.getText().trim();
        String outputFile = outputFileField.getText().trim();
        if (inputFile.isEmpty() || outputFile.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please select both an input PCAP and an output PCAP file.");
            return;
        }

        try {
            int loadBalancers = Integer.parseInt(loadBalancersField.getText().trim());
            int fps = Integer.parseInt(fpsField.getText().trim());
            if (loadBalancers <= 0 || fps <= 0) {
                throw new NumberFormatException("Values must be positive");
            }

            DPIEngine.Config config = new DPIEngine.Config();
            config.numLoadBalancers = loadBalancers;
            config.fpsPerLb = fps;
            DPIEngine engine = new DPIEngine(config);

            for (int i = 0; i < ruleModel.size(); i++) {
                String rule = ruleModel.getElementAt(i);
                applyRule(engine, rule);
            }

            String rulesFile = rulesFileField.getText().trim();
            if (!rulesFile.isEmpty()) {
                if (!engine.loadRules(rulesFile)) {
                    appendLog("Warning: could not load rules from " + rulesFile + "\n");
                }
            }

            redirectOutputToUI();
            try {
                boolean success = engine.processFile(inputFile, outputFile);
                String report = engine.generateReport();
                appendLog("Analysis completed successfully: " + success + "\n");
                appendLog(report + "\n");
                previewArea.setText("Output written to: " + outputFile + "\n\n" + engine.generateClassificationReport() + "\n\n" + buildInsightSummary(engine, inputFile));
                updateDashboardStatsFromReport(report, ruleModel.size());
                statusLabel.setText("Analysis finished.");
            } finally {
                restoreOutput();
            }
        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(this, "Please enter valid positive numbers for load balancers and FPS.");
        }
    }

    private void applyRule(DPIEngine engine, String rule) {
        String[] parts = rule.split(":", 2);
        if (parts.length < 2) {
            return;
        }
        String type = parts[0].trim();
        String value = parts[1].trim();
        switch (type.toLowerCase()) {
            case "ip" -> engine.blockIp(value);
            case "application" -> engine.blockApp(value);
            case "domain" -> engine.blockDomain(value);
            case "port" -> {
                try {
                    engine.blockPort(Integer.parseInt(value));
                } catch (NumberFormatException ignored) {
                    appendLog("Ignored invalid port rule: " + value + "\n");
                }
            }
            default -> {
            }
        }
    }

    private void previewDomains() {
        String inputFile = inputFileField.getText().trim();
        if (inputFile.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please choose an input PCAP file first.");
            return;
        }

        try {
            DPIEngine.Config config = new DPIEngine.Config();
            DPIEngine engine = new DPIEngine(config);
            for (int i = 0; i < ruleModel.size(); i++) {
                applyRule(engine, ruleModel.getElementAt(i));
            }

            Set<String> domains = engine.collectDomains(inputFile);
            if (domains.isEmpty()) {
                previewArea.setText("No domains detected in the selected PCAP.");
            } else {
                StringBuilder builder = new StringBuilder("Detected domains:\n");
                domains.stream().sorted().forEach(domain -> builder.append("- ").append(domain).append("\n"));
                previewArea.setText(builder.toString());
            }
        } catch (Exception ex) {
            previewArea.setText("Failed to preview domains: " + ex.getMessage());
        }
    }

    private void previewInsights() {
        String inputFile = inputFileField.getText().trim();
        if (inputFile.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please choose an input PCAP file first.");
            return;
        }

        try {
            DPIEngine.Config config = new DPIEngine.Config();
            DPIEngine engine = new DPIEngine(config);
            previewArea.setText(buildInsightSummary(engine, inputFile));
            statusLabel.setText("Insights generated.");
        } catch (Exception ex) {
            previewArea.setText("Failed to generate insights: " + ex.getMessage());
        }
    }

    private String buildInsightSummary(DPIEngine engine, String inputFile) {
        StringBuilder builder = new StringBuilder();
        builder.append("Quick Insights\n");
        builder.append("================\n");

        Map<String, Integer> appStats = engine.collectAppStats(inputFile);
        Map<String, Integer> domainStats = engine.collectDomainStats(inputFile);

        builder.append("Top Applications:\n");
        if (appStats.isEmpty()) {
            builder.append("- No application activity detected.\n");
        } else {
            appendTopEntries(builder, appStats, 5);
        }

        builder.append("\nTop Domains:\n");
        if (domainStats.isEmpty()) {
            builder.append("- No domains detected.\n");
        } else {
            appendTopEntries(builder, domainStats, 5);
        }

        return builder.toString();
    }

    private void appendTopEntries(StringBuilder builder, Map<String, Integer> stats, int limit) {
        int count = 0;
        for (Map.Entry<String, Integer> entry : stats.entrySet()) {
            if (count >= limit) {
                break;
            }
            builder.append("- ").append(entry.getKey()).append(" (count: ").append(entry.getValue()).append(")\n");
            count++;
        }
    }

    private void showSupportedApps() {
        StringBuilder builder = new StringBuilder("Supported applications:\n");
        for (Types.AppType app : Types.AppType.values()) {
            builder.append("- ").append(app.name()).append(" (")
                    .append(Types.appTypeToString(app)).append(")\n");
        }
        previewArea.setText(builder.toString());
        statusLabel.setText("Supported apps list displayed.");
    }

    private void populateDefaultPaths() {
        Path root = Path.of(System.getProperty("user.dir"));
        for (String candidate : List.of("test_dpi.pcap", "output.pcap", "output_run.pcap", "output_int.pcap")) {
            Path path = root.resolve(candidate);
            if (Files.exists(path)) {
                inputFileField.setText(path.toString());
                break;
            }
        }
        Path outputPath = root.resolve("output_run.pcap");
        if (Files.exists(outputPath)) {
            outputFileField.setText(outputPath.toString());
        } else {
            outputFileField.setText(root.resolve("output_run.pcap").toString());
        }
        Path rulesPath = root.resolve("rules.txt");
        if (Files.exists(rulesPath)) {
            rulesFileField.setText(rulesPath.toString());
        }
        updateDashboardStats(0, 0, 0, ruleModel.size());
    }

    private void useSampleInput() {
        Path root = Path.of(System.getProperty("user.dir"));
        for (String candidate : List.of("test_dpi.pcap", "output.pcap", "output_run.pcap")) {
            Path path = root.resolve(candidate);
            if (Files.exists(path)) {
                inputFileField.setText(path.toString());
                statusLabel.setText("Sample input loaded.");
                return;
            }
        }
        statusLabel.setText("No sample PCAP found in project root.");
    }

    private void useSampleOutput() {
        Path root = Path.of(System.getProperty("user.dir"));
        Path path = root.resolve("output_run.pcap");
        outputFileField.setText(path.toString());
        statusLabel.setText("Sample output path set.");
    }

    private void toggleTheme() {
        darkMode = !darkMode;
        applyTheme();
        statusLabel.setText(darkMode ? "Dark mode enabled." : "Light mode enabled.");
    }

    private void updateDashboardStats(long totalPackets, long forwardedPackets, long droppedPackets, int ruleCount) {
        currentTotalPackets = totalPackets;
        currentForwardedPackets = forwardedPackets;
        currentDroppedPackets = droppedPackets;
        packetsCard.setValue(String.valueOf(totalPackets));
        forwardedCard.setValue(String.valueOf(forwardedPackets));
        droppedCard.setValue(String.valueOf(droppedPackets));
        rulesCard.setValue(String.valueOf(ruleCount));
        chartPanel.setValues(totalPackets, forwardedPackets, droppedPackets, ruleCount);
    }

    private void updateDashboardStatsFromReport(String report, int ruleCount) {
        if (report == null || report.isBlank()) {
            updateDashboardStats(currentTotalPackets, currentForwardedPackets, currentDroppedPackets, ruleCount);
            return;
        }
        long totalPackets = extractMetric(report, "Total Packets:");
        long forwardedPackets = extractMetric(report, "Forwarded:");
        long droppedPackets = extractMetric(report, "Dropped:");
        updateDashboardStats(totalPackets, forwardedPackets, droppedPackets, ruleCount);
    }

    private long extractMetric(String report, String prefix) {
        int start = report.indexOf(prefix);
        if (start < 0) {
            return 0;
        }
        int valueStart = start + prefix.length();
        int valueEnd = report.indexOf('\n', valueStart);
        if (valueEnd < 0) {
            valueEnd = report.length();
        }
        String value = report.substring(valueStart, valueEnd).trim();
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private void styleButton(JButton button, Color bg, Color fg) {
        button.setBackground(bg);
        button.setForeground(fg);
        button.setFocusPainted(false);
        button.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(bg.darker(), 1),
                BorderFactory.createEmptyBorder(6, 10, 6, 10)));
    }

    private void applyTheme() {
        Color bg = darkMode ? darkBg : lightBg;
        Color fg = darkMode ? darkFg : lightFg;
        getContentPane().setBackground(bg);
        getContentPane().setForeground(fg);
        applyThemeToContainer(getContentPane(), bg, fg);
        sidebarStatusLabel.setForeground(darkMode ? accentGreen : accentGreen.darker());
        sidebarTitleLabel.setForeground(darkMode ? accentAmber : accentPurple);
        sidebarHintLabel.setForeground(darkMode ? new Color(148, 163, 184) : new Color(100, 116, 139));
        SwingUtilities.updateComponentTreeUI(this);
    }

    private void applyThemeToContainer(Container container, Color bg, Color fg) {
        for (Component component : container.getComponents()) {
            if (component instanceof JComponent jComponent) {
                if (jComponent instanceof JButton) {
                    return;
                }
                jComponent.setBackground(bg);
                jComponent.setForeground(fg);
                if (jComponent instanceof JTextArea textArea) {
                    textArea.setCaretColor(fg);
                }
                if (jComponent instanceof JScrollPane scrollPane) {
                    scrollPane.getViewport().setBackground(bg);
                    scrollPane.getViewport().setForeground(fg);
                }
                if (component instanceof Container childContainer) {
                    applyThemeToContainer(childContainer, bg, fg);
                }
            }
        }
    }

    private List<String> getRulePreview() {
        List<String> preview = new java.util.ArrayList<>();
        for (int i = 0; i < ruleModel.size(); i++) {
            preview.add(ruleModel.getElementAt(i));
        }
        return preview;
    }

    private void openOutputFolder() {
        String outputPath = outputFileField.getText().trim();
        File file = new File(outputPath);
        File folder = file.isDirectory() ? file : file.getParentFile();
        if (folder == null) {
            folder = new File(System.getProperty("user.dir"));
        }
        if (folder.exists()) {
            try {
                Desktop.getDesktop().open(folder);
                statusLabel.setText("Opened output folder.");
            } catch (IOException ex) {
                statusLabel.setText("Could not open output folder.");
            }
        }
    }

    private PrintStream originalOut;
    private PrintStream originalErr;

    private class DashboardCard extends JPanel {
        private final JLabel titleLabel = new JLabel();
        private final JLabel valueLabel = new JLabel();
        private final JLabel hintLabel = new JLabel();

        DashboardCard(String title, String value) {
            setLayout(new BorderLayout(4, 4));
            Color accent = title.contains("Forward") ? accentGreen : title.contains("Dropped") ? accentRed : title.contains("Rules") ? accentPurple : accentBlue;
            setBackground(darkMode ? new Color(30, 41, 59) : Color.WHITE);
            setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(accent, 2),
                    BorderFactory.createEmptyBorder(10, 10, 10, 10)));
            setOpaque(true);
            titleLabel.setText(title);
            titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));
            titleLabel.setForeground(accent);
            valueLabel.setText(value);
            valueLabel.setFont(new Font("Segoe UI", Font.BOLD, 20));
            valueLabel.setForeground(darkMode ? Color.WHITE : lightFg);
            hintLabel.setText("Live snapshot");
            hintLabel.setFont(new Font("Segoe UI", Font.PLAIN, 10));
            hintLabel.setForeground(new Color(100, 116, 139));
            add(titleLabel, BorderLayout.NORTH);
            add(valueLabel, BorderLayout.CENTER);
            add(hintLabel, BorderLayout.SOUTH);
        }

        void setValue(String value) {
            valueLabel.setText(value);
        }
    }

    private class StatChartPanel extends JPanel {
        private long totalPackets;
        private long forwardedPackets;
        private long droppedPackets;
        private int ruleCount;

        void setValues(long totalPackets, long forwardedPackets, long droppedPackets, int ruleCount) {
            this.totalPackets = totalPackets;
            this.forwardedPackets = forwardedPackets;
            this.droppedPackets = droppedPackets;
            this.ruleCount = ruleCount;
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            Color fg = getForeground();
            Color bg = getBackground();

            int width = getWidth();
            int height = getHeight();
            int barWidth = 46;
            int gap = 20;
            int x = 30;
            int baseY = height - 40;
            long maxValue = Math.max(1, Math.max(totalPackets, Math.max(forwardedPackets, Math.max(droppedPackets, ruleCount))));
            long[] values = {totalPackets, forwardedPackets, droppedPackets, ruleCount};
            Color[] colors = {new Color(59, 130, 246), new Color(34, 197, 94), new Color(248, 113, 113), new Color(168, 85, 247)};
            String[] labels = {"Total", "Forwarded", "Dropped", "Rules"};

            g2.setColor(fg);
            g2.drawLine(20, baseY, width - 20, baseY);
            g2.drawLine(20, 20, 20, baseY);

            for (int i = 0; i < values.length; i++) {
                int barHeight = (int) ((values[i] * 120) / Math.max(1, maxValue));
                int barX = x + i * (barWidth + gap);
                int barY = baseY - barHeight;
                g2.setColor(colors[i]);
                g2.fillRoundRect(barX, barY, barWidth, barHeight, 10, 10);
                g2.setColor(fg);
                g2.drawString(String.valueOf(values[i]), barX, barY - 6);
                g2.drawString(labels[i], barX - 6, baseY + 18);
            }

            int centerX = width - 120;
            int centerY = height / 2 + 10;
            int radius = 54;
            g2.setColor(new Color(226, 232, 240));
            g2.fillOval(centerX - radius, centerY - radius, radius * 2, radius * 2);
            double forwardedAngle = totalPackets > 0 ? (forwardedPackets * 360.0) / Math.max(1, totalPackets) : 0;
            double droppedAngle = totalPackets > 0 ? (droppedPackets * 360.0) / Math.max(1, totalPackets) : 0;
            g2.setColor(new Color(34, 197, 94));
            g2.fill(new Arc2D.Double(centerX - radius, centerY - radius, radius * 2, radius * 2, 90, -forwardedAngle, Arc2D.PIE));
            g2.setColor(new Color(248, 113, 113));
            g2.fill(new Arc2D.Double(centerX - radius, centerY - radius, radius * 2, radius * 2, 90 - forwardedAngle, -droppedAngle, Arc2D.PIE));
            g2.setColor(bg);
            g2.fillOval(centerX - 28, centerY - 28, 56, 56);
            g2.setColor(fg);
            g2.drawString("Flow", centerX - 16, centerY - 4);
            g2.dispose();
        }
    }

    private static class GradientPanel extends JPanel {
        GradientPanel() {
            super(new BorderLayout());
            setOpaque(true);
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            LinearGradientPaint paint = new LinearGradientPaint(
                    new Point2D.Double(0, 0),
                    new Point2D.Double(getWidth(), getHeight()),
                    new float[]{0f, 1f},
                    new Color[]{new Color(37, 99, 235), new Color(139, 92, 246)});
            g2.setPaint(paint);
            g2.fillRoundRect(0, 0, getWidth(), Math.max(120, getHeight()), 24, 24);
            g2.dispose();
        }
    }

    private void redirectOutputToUI() {
        originalOut = System.out;
        originalErr = System.err;
        System.setOut(new PrintStream(new TextAreaOutputStream(logArea), true, StandardCharsets.UTF_8));
        System.setErr(new PrintStream(new TextAreaOutputStream(logArea), true, StandardCharsets.UTF_8));
        appendLog("Starting analysis...\n");
    }

    private void restoreOutput() {
        if (originalOut != null) {
            System.setOut(originalOut);
        }
        if (originalErr != null) {
            System.setErr(originalErr);
        }
    }

    private void appendLog(String text) {
        SwingUtilities.invokeLater(() -> logArea.append(text));
    }

    private static class TextAreaOutputStream extends OutputStream {
        private final JTextArea textArea;
        private final StringBuilder buffer = new StringBuilder();

        private TextAreaOutputStream(JTextArea textArea) {
            this.textArea = textArea;
        }

        @Override
        public void write(int b) {
            buffer.append((char) b);
            if (b == '\n') {
                flushBuffer();
            }
        }

        @Override
        public void write(byte[] b, int off, int len) {
            if (b == null) {
                throw new NullPointerException();
            }
            if (off < 0 || len < 0 || off + len > b.length) {
                throw new IndexOutOfBoundsException();
            }
            buffer.append(new String(b, off, len, StandardCharsets.UTF_8));
            if (buffer.toString().contains("\n")) {
                flushBuffer();
            }
        }

        @Override
        public void flush() {
            flushBuffer();
        }

        private void flushBuffer() {
            if (buffer.length() == 0) {
                return;
            }
            String text = buffer.toString();
            buffer.setLength(0);
            SwingUtilities.invokeLater(() -> textArea.append(text));
        }
    }
}
