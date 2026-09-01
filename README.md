# DPI Engine v2

DPI Engine is a C++17-based Deep Packet Inspection system that processes network traffic (PCAP), parses protocols, identifies applications from traffic metadata like TLS SNI and HTTP Host headers, and applies configurable blocking rules.

The project also includes a multi-threaded processing architecture designed to distribute packet processing across load-balancer and fast-path workers for high performance. Furthermore, it features a Python FastAPI backend and a web dashboard for uploading PCAPs and viewing structured JSON analysis reports.

---

## What it does

- **Reads PCAP files**: Processes captured network traffic.
- **Parses Protocols**: Decodes Ethernet, IPv4, TCP, and UDP headers.
- **Flow Tracking**: Tracks network connections using a standard 5-tuple (Source IP, Destination IP, Source Port, Destination Port, Protocol).
- **TLS SNI Extraction**: Inspects the TLS Client Hello to extract the Server Name Indication (SNI) before encryption begins.
- **HTTP Host Extraction**: Inspects plaintext HTTP traffic to extract the Host header.
- **Application Classification**: Maps identified domains (e.g., youtube.com, facebook.com) to specific applications.
- **Blocking Engine**: Supports dropping packets based on Source IP, Application type, or Domain substring matches.
- **PCAP Output**: Writes the filtered (non-blocked) traffic to a new PCAP file.
- **Structured Reporting**: Generates a detailed JSON report of processing statistics, active flows, and application breakdown.
- **Web Dashboard**: A FastAPI-based backend and HTML dashboard for visual analysis.

---

## How it works

At a high level, the engine processes traffic sequentially:

```text
PCAP Input
  │
  ▼
Packet Reader
  │
  ▼
Packet Parser (Ethernet → IP → TCP/UDP)
  │
  ▼
Flow Tracking (5-tuple lookup)
  │
  ▼
DPI / Classification
  ├── Extract TLS SNI
  ├── Extract HTTP Host
  └── Map to Application
  │
  ▼
Rules Engine
  ├── Block IP?
  ├── Block App?
  └── Block Domain?
  │
  ├──────────────┐
  │ DROP         │ FORWARD
  ▼              ▼
Stats          Output PCAP
```

The system reads packets from the input PCAP file one by one. It parses the protocol layers to identify the connection (5-tuple) and inspects the payload of the first few packets in a flow (specifically looking for TLS Client Hello or HTTP requests) to classify the application. Blocking rules are then evaluated, and allowed packets are forwarded to the output PCAP file.

---

## Multi-threaded Architecture

The repository also includes a multi-threaded architecture implementation (`src/dpi_mt.cpp`) designed for high-throughput processing. 

```text
Reader Thread
  │
  ▼  (Hash % N)
Load Balancers (LBs)
  │
  ▼  (Hash % M)
Fast Path Workers (FPs)
  │
  ▼
Output Queue
  │
  ▼
Output Writer Thread
```

- **Reader Thread**: Sequentially reads packets from the PCAP file and distributes them to Load Balancers based on a hash of the 5-tuple.
- **Load Balancers (LBs)**: Act as an intermediate routing layer, forwarding packets to Fast Path workers.
- **Fast Path Workers (FPs)**: Perform the heavy lifting—flow tracking, payload parsing, SNI extraction, classification, and rule evaluation.
- **Consistent Hashing**: Packets are routed using a hash of their 5-tuple. This guarantees that all packets belonging to the same connection are always processed by the same Fast Path worker, eliminating the need for expensive cross-thread locks on the flow tables.
- **Thread-safe Queues**: Communication between thread stages relies on lock-backed `TSQueue` structures.

---

## DPI / Detection

The Deep Packet Inspection relies on extracting plaintext metadata before encryption takes over. 

- **TLS SNI**: For HTTPS traffic (port 443), the engine parses the TLS record layer to find the `Client Hello` handshake message. It skips past session IDs and cipher suites to locate the SNI (Server Name Indication) extension (type `0x0000`), extracting the requested domain.
- **HTTP Host**: For standard HTTP traffic (port 80), it searches the payload for the `Host:` header.
- **Application Mapping**: The extracted domain is mapped against known application signatures (e.g., `youtube`, `facebook`, `google`).
- **Fallbacks**: If no SNI or Host is found, the engine falls back to port-based classification (e.g., port 53 → DNS). Traffic that cannot be classified is marked as `UNKNOWN`.
- **Limitations**: The current implementation inspects plaintext handshakes. It does not decrypt payloads and may be limited by advanced privacy features like Encrypted Client Hello (ECH).

---

## Blocking

The rules engine applies blocking criteria on a per-packet basis, though the classification state is stored per-flow.

Supported rule types:
- **IP Blocking**: Matches the exact Source IPv4 address (`--block-ip`).
- **Application Blocking**: Matches the classified application enum (`--block-app`).
- **Domain Blocking**: Performs a substring match against the extracted SNI or HTTP Host (`--block-domain`).

Example Command:
```bash
./dpi_engine input.pcap output.pcap --block-app YOUTUBE --block-ip 192.168.1.50 --block-domain evil.com
```

Processing Flow:
`Packet → Identify Flow (5-tuple) → Extract SNI/Host → Classify App → Check Rules → DROP or FORWARD`

---

## Project Structure

```text
backend/
  ├── main.py                # FastAPI backend serving the UI and invoking dpi_engine
frontend/
  ├── code.html              # Web dashboard UI
include/
  ├── dpi_engine.h           # Core structures
  ├── fast_path.h            # MT Fast Path worker
  ├── load_balancer.h        # MT Load balancer
  ├── packet_parser.h        # Protocol parsing
  ├── pcap_reader.h          # PCAP I/O
  ├── rule_manager.h         # Blocking engine
  ├── sni_extractor.h        # TLS/HTTP parsing
  ├── thread_safe_queue.h    # MT queues
  └── types.h                # Common types (FiveTuple, AppType)
src/
  ├── main.cpp               # Simple packet analyzer (Target: packet_analyzer)
  ├── main_working.cpp       # Single-threaded DPI engine (Target: dpi_engine)
  ├── dpi_mt.cpp             # Multi-threaded DPI engine entry point
  ├── fast_path.cpp          # MT Fast path implementation
  ├── load_balancer.cpp      # MT Load balancer implementation
  ├── packet_parser.cpp      # Protocol parsing implementation
  ├── pcap_reader.cpp        # PCAP reading implementation
  ├── rule_manager.cpp       # Blocking rules implementation
  └── sni_extractor.cpp      # SNI and Host extraction implementation
CMakeLists.txt               # CMake build configuration
generate_test_pcap.py        # Script to generate synthetic PCAP test data
```
