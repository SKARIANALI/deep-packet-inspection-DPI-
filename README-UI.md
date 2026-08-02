# Packet Analyzer Dashboard UI

## Overview
This project is a Java-based packet analyzer with an enhanced Swing desktop UI available via `Main --ui`.

## How to run
1. Build the project:
   ```powershell
   cmd /c "d:\Final year project\Packet_analyzer-main\java\build_compile.bat"
   ```
2. Launch the UI:
   ```powershell
   cd /d "d:\Final year project\Packet_analyzer-main"
   java -cp java\out Main --ui
   ```
3. Or double-click `run_ui.bat` from the project root.

## UI Sections
- **Quick Control**: switch between dashboard, rule preview, and log preview.
- **Input and Output**: choose the input PCAP, output PCAP, and rules file.
- **Blocking Rules**: create and add packet filter rules by type and value.
- **Live Log**: displays runtime log output while the analysis runs.
- **Preview / Results**: shows analysis reports, domain previews, and insights.

## Buttons
- `Run Analysis`: processes the selected input PCAP and writes the output PCAP.
- `Preview Domains`: lists detected domains from the input PCAP.
- `Preview Insights`: shows traffic insight summary.
- `Show Supported Apps`: displays supported app types.
- `Clear Log`: clears the live log view.
- `Use Sample Input`: sets a default input PCAP from the project root.
- `Use Sample Output`: sets a default output PCAP path in the project root.
- `Toggle Theme`: switches between light and dark modes.
- `Open Output Folder`: opens the selected output file's folder.

## Notes
- Keep the existing `README.md`; this file is an additional UI-specific guide.
- The UI is implemented in `java/src/main/java/PacketAnalyzerUI.java`.
