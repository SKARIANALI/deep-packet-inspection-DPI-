# DPI Engine - Deep Packet Inspection System

This document explains **everything** about this project — from basic networking concepts to the complete Java code architecture. After reading this, you should understand exactly how packets flow through the system without needing to read the code.

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet](#5-the-journey-of-a-packet)
6. [Multi-threaded Architecture](#6-multi-threaded-architecture)
7. [Deep Dive: Each Component](#7-deep-dive-each-component)
8. [How SNI Extraction Works](#8-how-sni-extraction-works)
9. [How Blocking Works](#9-how-blocking-works)
10. [Building and Running](#10-building-and-running)
11. [Understanding the Output](#11-understanding-the-output)
12. [Extending the Project](#12-extending-the-project)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What Our DPI Engine Does:
```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

---

## 2. Networking Background

### The Network Stack (Layers)

When you visit a website, data travels through multiple "layers":

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS               │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)   │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)       │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network)│
└─────────────────────────────────────────────────────────┘
```

### A Packet's Structure

Every network packet is like a **Russian nesting doll** — headers wrapped inside headers:

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### The Five-Tuple

A **connection** (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it's going |
| Source Port | 54321 | Sender's application identifier |
| Destination Port | 443 | Service being accessed (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP |

**Why is this important?**
- All packets with the same 5-tuple belong to the same connection
- If we block one packet of a connection, we should block all of them
- This is how we "track" conversations between computers

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:

1. Your browser sends a "Client Hello" message
2. This message includes the domain name in **plaintext** (not encrypted yet!)
3. The server uses this to know which certificate to send

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  ← We extract THIS!
```

**This is the key to DPI**: Even though HTTPS is encrypted, the destination domain is visible in the first packet.

---

## 3. Project Overview

### What This Project Does

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Wireshark   │     │ DPI Engine  │     │ Output      │
│ Capture     │ ──► │             │ ──► │ PCAP        │
│ (input.pcap)│     │ - Parse     │     │ (filtered)  │
└─────────────┘     │ - Classify  │     └─────────────┘
                    │ - Block     │
                    │ - Report    │
                    └─────────────┘
```

### Java Version

This repository contains the Java implementation of the DPI engine. The engine is designed to parse PCAP input, classify traffic, apply blocking rules, and write filtered packets to an output PCAP file.

---

## 4. File Structure

```
Packet_analyzer-main/
├── java/                       # Java DPI engine source
│   └── src/main/java/
│       ├── Main.java           # Program entrypoint
│       ├── dpi/                # DPI engine components
│       │   ├── DPIEngine.java
│       │   ├── FastPathProcessor.java
│       │   ├── LoadBalancer.java
│       │   ├── ConnectionTracker.java
│       │   ├── RuleManager.java
│       │   ├── SNIExtractor.java
│       │   ├── ThreadSafeQueue.java
│       │   ├── Types.java
│       │   └── ...
│       └── packetanalyzer/     # PCAP/packet parsing
│           ├── PcapReader.java
│           ├── PacketParser.java
│           └── GenerateTestPcap.java
│
├── generate_test_pcap.py      # Python helper to create sample capture
├── test_dpi.pcap              # Sample capture with various traffic
├── output.pcap                # Example output PCAP file
├── README.md                  # This file!
└── WINDOWS_SETUP.md           # Windows setup notes
```

---

## 5. The Journey of a Packet

The Java DPI engine is a threaded pipeline. A packet travels through the following stages:

### Step 1: Read command-line arguments

`Main.java` reads the input and output file names and optional thread counts:
```java
java -cp java/out Main input.pcap output.pcap [numLoadBalancers] [fpsPerLb]
```

### Step 2: Create the DPI engine

`Main` creates a `DPIEngine` with a configuration object. Default values are:
- `numLoadBalancers = 2`
- `fpsPerLb = 2`
- `queueSize = 10000`

The engine builds:
- `LBManager` to manage load balancers
- `FastPathProcessor` threads for DPI classification
- `ThreadSafeQueue` objects for inter-thread handoff
- `RuleManager` for blocking rules

### Step 3: Read the PCAP file

The reader thread in `DPIEngine` opens the input PCAP using `PcapReader`.
It writes the global PCAP header to the output file and then reads each packet record.

### Step 4: Parse protocol headers

For each packet, `PacketParser.parse()` extracts:
- Ethernet header
- IPv4 header
- TCP or UDP header
- Source/destination IP and ports
- TCP flags

If a packet has no IP layer or is neither TCP nor UDP, it is skipped.

### Step 5: Build the five-tuple and dispatch

The engine creates a `Types.PacketJob` containing:
- source/destination IP
- source/destination port
- protocol
- payload offset and length
- packet bytes

The packet is hashed and dispatched to a specific `LoadBalancer` so all packets for the same connection follow the same path.

### Step 6: FastPath classification

Each `FastPathProcessor` processes packets independently. It:
- extracts SNI and application metadata
- determines the packet action via `RuleManager`
- forwards or drops the packet

### Step 7: Write filtered packets

Packets marked for forwarding are pushed to the output queue.
The output thread serializes packet headers and packet bytes into the output PCAP file.

### Step 8: Report results

When processing completes, the engine prints summary statistics and per-fast-path statistics to standard output.

---

## 6. Multi-threaded Architecture

The Java DPI engine is built around a producer-consumer thread pipeline:

```
                    ┌─────────────────┐
                    │  Reader Thread  │
                    │  (reads PCAP)   │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │      LBManager / LBs         │
              │  (route packets by hash)     │
              └────────┬────────┬───────────┘
                       │        │
                 ┌─────┴───┐┌───┴─────┐
                 │ FP0     ││ FP1     │
                 │(FastPath)││(FastPath)│
                 └─────┬───┘└───┬─────┘
                       │        │
                       └────────┴────────┐
                                    │
                           ┌───────────────────────┐
                           │   Output Queue        │
                           └───────────┬───────────┘
                                       │
                           ┌───────────────────────┐
                           │  Output Thread        │
                           │  (writes PCAP)        │
                           └───────────────────────┘
```

### Why this design works

- `LoadBalancer` threads distribute packets across `FastPathProcessor` threads
- `FastPathProcessor` threads maintain flow-specific state
- A shared output queue keeps disk writes serialized and safe
- The same 5-tuple always goes to the same fast path, so connection state stays consistent

---

## 7. Deep Dive: Each Component

### `Main.java`

The program entrypoint. It parses command-line arguments, builds `DPIEngine.Config`, and starts processing.

### `dpi/DPIEngine.java`

The central orchestrator. It creates the pipeline, starts threads, reads packets, writes output, and prints reports.

### `dpi/LoadBalancer.java`

Routes `Types.PacketJob` objects to the correct `FastPathProcessor` queue based on a consistent hash.

### `dpi/FastPathProcessor.java`

Processes packets, applies DPI classification, and decides whether to forward or drop.

### `dpi/RuleManager.java`

Holds blocking rules for:
- IP addresses
- application types
- domain substrings

It is used by the fast path processors to determine packet actions.

### `dpi/SNIExtractor.java`

Extracts TLS SNI hostnames from HTTPS ClientHello packets and HTTP host headers from request payloads.

### `dpi/ThreadSafeQueue.java`

A thread-safe producer-consumer queue used for passing packets between threads.

### `dpi/Types.java`

Defines shared data structures such as `PacketJob`, `FiveTuple`, `AppType`, and helper parsing utilities.

### `packetanalyzer/PcapReader.java`

Reads PCAP global headers and packet records from the input file.

### `packetanalyzer/PacketParser.java`

Parses Ethernet, IPv4, TCP, and UDP headers to populate packet metadata.

---

## 8. How SNI Extraction Works

### The TLS Handshake

When you visit `https://www.youtube.com`:

```
┌──────────┐                              ┌──────────┐
│  Browser │                              │  Server  │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │ ──── Client Hello ─────────────────────►│
     │      (includes SNI: www.youtube.com)    │
     │                                         │
     │ ◄─── Server Hello ───────────────────── │
     │      (includes certificate)             │
     │                                         │
     │ ──── Key Exchange ─────────────────────►│
     │                                         │
     │ ◄═══ Encrypted Data ══════════════════► │
     │      (from here on, everything is       │
     │       encrypted - we can't see it)      │
```

The engine can only extract the domain name from the first ClientHello packet, before encryption begins.

### TLS ClientHello structure

- Record content type: `0x16` (Handshake)
- Handshake type: `0x01` (ClientHello)
- Session ID, cipher suites, compression methods
- Extensions section
- SNI extension: type `0x0000`

The `SNIExtractor` parses the extension list and returns the hostname string when present.

---

## 9. How Blocking Works

### Rule Types

| Rule Type | Example | What it Blocks |
|-----------|---------|----------------|
| IP | `192.168.1.50` | All traffic from this source |
| App | `YOUTUBE` | All YouTube connections |
| Domain | `facebook` | Any SNI containing `facebook` |

### The Blocking Flow

```
Packet arrives
      │
      ▼
┌─────────────────────────────────┐
│ Is source IP blocked?          │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Is app type blocked?           │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Does SNI/domain match rule?    │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
            FORWARD
```

### Flow-Based Blocking

All packets for a connection are kept together by hash-based routing. This means the engine can:

- allow early packets before SNI is known
- identify the flow when the ClientHello arrives
- mark the flow blocked if needed
- drop subsequent packets on that same connection

---

## 10. Building and Running

### Prerequisites

- **Java JDK 17** or newer installed
- `javac` and `java` available on your `PATH`

### Build Commands

From the project root, compile the Java sources into an output directory:

```powershell
javac -d java/out java/src/main/java/Main.java java/src/main/java/dpi/*.java java/src/main/java/packetanalyzer/*.java
```

If your shell supports glob expansion:

```powershell
javac -d java/out java/src/main/java/**/*.java
```

### Running

Run the engine with input and output PCAP paths:

```powershell
java -cp java/out Main input.pcap output.pcap [numLoadBalancers] [fpsPerLb] [options]
```

Example:

```powershell
java -cp java/out Main test_dpi.pcap output.pcap 2 2
```

This creates 2 load balancers and 2 fast-path processors per load balancer.

### Blocking at runtime

The engine now supports runtime blocking rules passed through the command line.

```powershell
java -cp java/out Main test_dpi.pcap output.pcap 2 2 --block-ip 192.168.1.50 --block-app YOUTUBE --block-domain facebook --block-port 443
```

You can also load a rule file with:

```powershell
java -cp java/out Main test_dpi.pcap output.pcap 2 2 --rules rules.txt
```

### Supported app names

To print the list of all supported application names, use:

```powershell
java -cp java/out Main test_dpi.pcap output.pcap 2 2 --show-apps
```

This works independently of any blocking rules and is useful both before and after using `--block-app` or other block options.

### Step-by-step blocking workflow

Use these commands in order to build, inspect supported apps, block apps, and then verify again.

1. Build the project:

```powershell
cd "d:\Final year project\Packet_analyzer-main"
javac -d java/out java/src/main/java/Main.java java/src/main/java/dpi/*.java java/src/main/java/packetanalyzer/*.java
```

2. Show supported app names:

```powershell
java -cp java/out Main test_dpi.pcap output.pcap 2 2 --show-apps
```

3. Block an app such as YouTube:

```powershell
java -cp java/out Main test_dpi.pcap output.pcap 2 2 --block-app YOUTUBE

```

4. Show the supported app names again (the same list is available anytime):

```powershell
java -cp java/out Main test_dpi.pcap output.pcap 2 2 --show-apps
```

The `--show-apps` command always lists the supported application types. It does not change app blocking state, but it is useful for confirming the exact app name to pass to `--block-app`.

### Interactive domain preview

To scan the PCAP first, print all detected domains, and then choose block rules interactively:

```powershell
java -cp java/out Main test_dpi.pcap output.pcap 2 2 --interactive
```

The program will print detected domains and then prompt you to enter IPs, app names, domains, and ports to block before processing.

Rules file format is the same one used by `RuleManager` and supports sections like `[BLOCKED_IPS]`, `[BLOCKED_APPS]`, `[BLOCKED_DOMAINS]`, and `[BLOCKED_PORTS]`.

### Rule Configuration

The current Java implementation exposes blocking through `RuleManager`.
Rules can be loaded programmatically from a file or added at runtime using the API methods:
- `blockIp("192.168.1.50")`
- `blockApp(Types.AppType.YOUTUBE)`
- `blockDomain("facebook")`
- `blockPort(443)`

The rules file format is simple and supports sections:

```text
[BLOCKED_IPS]
192.168.1.50

[BLOCKED_APPS]
YouTube

[BLOCKED_DOMAINS]
facebook

[BLOCKED_PORTS]
443
```

Currently, `Main.java` accepts only the input/output paths and optional thread counts.
Adding command-line support for a rules file is a natural next improvement.

### Creating Test Data

Generate a sample PCAP using the Java test generator:

```powershell
java -cp java/out packetanalyzer.GenerateTestPcap test_dpi.pcap
```

Or use the Python helper:

```powershell
python generate_test_pcap.py
```

---

## 11. Understanding the Output

The engine prints a summary report after processing, including:
- total packets
- total bytes
- TCP and UDP packet counts
- forwarded vs dropped packets
- per-fast-path processing statistics

### Example Output

```
=== DPI ENGINE STATISTICS ===
Total Packets: 77
Total Bytes: 5738
TCP Packets: 73
UDP Packets: 4
Forwarded: 69
Dropped: 8

=== CLASSIFICATION REPORT ===
FP0: processed=53, forwarded=53, dropped=0
FP1: processed=24, forwarded=16, dropped=8
```

### What Each Section Means

| Section | Meaning |
|---------|---------|
| Total Packets | Packets read from the input file |
| Total Bytes | Total packet payload size processed |
| TCP Packets | Packets parsed as TCP |
| UDP Packets | Packets parsed as UDP |
| Forwarded | Packets written to the output file |
| Dropped | Packets blocked by rules |
| Classification Report | Work distribution across fast-path threads |

---

## 12. Extending the Project

### Ideas for Improvement

1. **Add More App Signatures**
   - Extend `Types.appTypeToString()` / `Types.sniToAppType()` mappings.

2. **Add Bandwidth Throttling**
   - Delay forwarding instead of dropping in `FastPathProcessor`.

3. **Add Live Statistics Dashboard**
   - Add a monitoring thread that prints stats periodically while processing.

4. **Add QUIC / HTTP/3 Support**
   - QUIC uses UDP on port 443 and requires parsing the QUIC Initial packet.

5. **Add Persistent Rules**
   - Save and load rule sets from files via `RuleManager`.

---

## Summary

This Java DPI engine demonstrates:

1. **Network Protocol Parsing** — Understanding packet structure
2. **Deep Packet Inspection** — Looking inside HTTPS handshakes
3. **Flow Tracking** — Keeping connection state across packets
4. **Multi-threaded Architecture** — Scaling with producer-consumer queues
5. **Thread-Safe IPC** — Safe handoff between reader, load balancers, processors, and writer

The key insight is that HTTPS handshakes leak domain names in the TLS ClientHello, allowing application classification and blocking even when the rest of the traffic is encrypted.

---

## Questions?

If you have questions about any part of this project, the code is well-commented and follows the same flow described in this document. Start with `Main.java` and `dpi/DPIEngine.java` to understand the pipeline, then inspect `packetanalyzer/PacketParser.java` and `dpi/SNIExtractor.java` for protocol parsing.

Happy learning! 🚀


cd "d:\Final year project\Packet_analyzer-main"
java -cp java/out Main test_dpi.pcap output.pcap 2 2 --list-app  YOUTUBE

java -cp java/out Main test_dpi.pcap output.pcap 2 2 --show-apps

java -cp java/out Main test_dpi.pcap output.pcap 2 2 --block-app YOUTUBE