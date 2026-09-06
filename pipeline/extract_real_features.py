"""
extract_real_features.py
------------------------
Phase 1 of the DPI-Engine ML pipeline.

Reads real PCAP files using dpkt, groups packets into TCP/UDP flows using
the same 5-tuple concept as the C++ engine (src_ip, dst_ip, src_port,
dst_port, protocol), then computes per-flow statistics entirely from the
actual packet data. Labels are obtained by invoking the already-built
dpi_engine.exe (via subprocess, same method as main.py) and matching each
flow's SNI/domain to the engine's JSON output -- zero randomly generated
values, zero invented labels.

Output CSV columns
------------------
  flow_id          : canonical 5-tuple string identifier
  packet_count     : total packets in this flow (both directions)
  mean_packet_size : arithmetic mean of packet wire lengths (bytes)
  std_packet_size  : population std dev of packet wire lengths (bytes)
  flow_duration    : last_ts - first_ts (seconds, 0.0 for single-packet flows)
  bytes_ratio      : bytes flowing src->dst / bytes flowing dst->src
                     (inf when there is no return traffic; 0 if only return)
  label            : app string from dpi_engine.exe's detected_domains JSON
                     field, or the port-based fallback used by the C++ engine
                     (HTTPS / HTTP / DNS / Unknown)

Usage
-----
    python pipeline/extract_real_features.py [pcap_file] [output_csv]

Defaults:
    pcap_file   = test_dpi.pcap   (project root)
    output_csv  = pipeline/data/real_flow_features.csv
"""

import csv
import json
import math
import os
import socket
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

import dpkt

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT   = Path(__file__).resolve().parent.parent
DPI_ENGINE     = PROJECT_ROOT / "build" / "dpi_engine.exe"
MSYS2_BIN      = Path(r"C:\msys64\ucrt64\bin")
DEFAULT_PCAP   = PROJECT_ROOT / "test_dpi.pcap"
DEFAULT_OUTPUT = PROJECT_ROOT / "pipeline" / "data" / "real_flow_features.csv"


# ---------------------------------------------------------------------------
# 5-Tuple helpers
# ---------------------------------------------------------------------------

def _ip_str(raw_bytes):
    """Convert 4-byte IP address to dotted-decimal string."""
    return socket.inet_ntoa(raw_bytes)


def canonical_tuple(src_ip, dst_ip, src_port, dst_port, proto):
    """
    Return a canonical (sorted) 5-tuple string so that both directions of a
    TCP/UDP conversation map to the same flow key -- matching the C++ engine's
    bidirectional flow tracking.
    The canonical form always places the lexicographically smaller (ip, port) pair first.
    """
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a > b:
        a, b = b, a
    return f"{a[0]}:{a[1]}<->{b[0]}:{b[1]}/{proto}"


def direction_is_forward(src_ip, src_port, key):
    """Return True if this packet travels in the 'forward' direction of key."""
    return key.startswith(f"{src_ip}:{src_port}<->")


# ---------------------------------------------------------------------------
# TLS SNI extractor (pure Python, mirrors sni_extractor.h logic)
# ---------------------------------------------------------------------------

def extract_tls_sni(payload):
    """
    Parse a TLS ClientHello to extract the SNI hostname.
    Returns the hostname string or None if not found.
    """
    if len(payload) < 5:
        return None
    if payload[0] != 0x16:          # Must be Handshake record
        return None
    rec_len = struct.unpack(">H", payload[3:5])[0]
    if len(payload) < 5 + rec_len:
        return None
    hs = payload[5:]
    if len(hs) < 4 or hs[0] != 0x01:
        return None                  # Not a ClientHello

    # Skip: type(1) + length(3) + version(2) + random(32)
    offset = 4 + 2 + 32
    if offset >= len(hs):
        return None

    # Session ID
    sid_len = hs[offset]
    offset += 1 + sid_len
    if offset + 2 > len(hs):
        return None

    # Cipher suites
    cs_len = struct.unpack(">H", hs[offset:offset+2])[0]
    offset += 2 + cs_len
    if offset + 1 > len(hs):
        return None

    # Compression methods
    cm_len = hs[offset]
    offset += 1 + cm_len
    if offset + 2 > len(hs):
        return None

    # Extensions total length
    ext_total = struct.unpack(">H", hs[offset:offset+2])[0]
    offset += 2
    end = offset + ext_total

    while offset + 4 <= end and offset + 4 <= len(hs):
        ext_type = struct.unpack(">H", hs[offset:offset+2])[0]
        ext_len  = struct.unpack(">H", hs[offset+2:offset+4])[0]
        offset  += 4
        if ext_type == 0x0000:       # server_name extension
            if offset + 5 > len(hs):
                break
            name_len  = struct.unpack(">H", hs[offset+3:offset+5])[0]
            name_start = offset + 5
            if name_start + name_len <= len(hs):
                return hs[name_start:name_start+name_len].decode("ascii", errors="replace")
            break
        offset += ext_len

    return None


def extract_http_host(payload):
    """Extract the Host: header value from an HTTP/1.x request."""
    try:
        text = payload.decode("latin-1", errors="replace")
    except Exception:
        return None
    for line in text.split("\r\n"):
        if line.lower().startswith("host:"):
            return line[5:].strip()
    return None


def extract_dns_query(payload):
    """Extract the first query name from a UDP DNS message."""
    try:
        dns = dpkt.dns.DNS(payload)
        if dns.qd:
            return dns.qd[0].name
    except Exception:
        return None
    return None


# ---------------------------------------------------------------------------
# Run dpi_engine.exe and read its JSON output
# ---------------------------------------------------------------------------

def run_dpi_engine(pcap_path):
    """
    Invoke dpi_engine.exe on pcap_path, collect its --json-output, and
    return a dict mapping domain_string -> app_string (ground-truth labels).
    """
    if not DPI_ENGINE.exists():
        raise FileNotFoundError(
            f"dpi_engine.exe not found at {DPI_ENGINE}. "
            "Build the project first (cmake --build build)."
        )

    env = os.environ.copy()
    if MSYS2_BIN.exists():
        env["PATH"] = str(MSYS2_BIN) + os.pathsep + env.get("PATH", "")

    with tempfile.TemporaryDirectory(prefix="dpi_feat_") as tmpdir:
        out_pcap = os.path.join(tmpdir, "out.pcap")
        out_json = os.path.join(tmpdir, "report.json")

        result = subprocess.run(
            [str(DPI_ENGINE), str(pcap_path), out_pcap, "--json-output", out_json],
            capture_output=True,
            timeout=60,
            env=env,
        )
        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"dpi_engine.exe failed (exit {result.returncode}): {stderr}")

        if not os.path.exists(out_json):
            raise RuntimeError("dpi_engine.exe succeeded but produced no JSON report.")

        with open(out_json, "r", encoding="utf-8") as jf:
            report = json.load(jf)

    # Build domain -> app lookup table from the engine's detected_domains list
    domain_to_app = {}
    for entry in report.get("detected_domains", []):
        domain_to_app[entry["domain"].lower()] = entry["app"]

    print(f"[engine]  {len(domain_to_app)} domains labelled by dpi_engine.exe:")
    for d, a in domain_to_app.items():
        print(f"           {d!r:35s} -> {a}")

    return domain_to_app


# ---------------------------------------------------------------------------
# PCAP flow extraction
# ---------------------------------------------------------------------------

class FlowRecord:
    """Accumulates real packet data for a single bidirectional flow."""

    def __init__(self, key, dst_port, proto):
        self.key       = key
        self.packets   = 0
        self.sizes     = []       # raw wire lengths (bytes)
        self.first_ts  = None
        self.last_ts   = None
        self.fwd_bytes = 0        # bytes src->dst (original direction)
        self.rev_bytes = 0        # bytes dst->src
        self.sni       = None     # TLS SNI / HTTP Host / DNS query name
        self.dst_port  = dst_port # destination port of the initiating direction
        self.proto     = proto    # "TCP" | "UDP"

    def add_packet(self, ts, wire_len, is_forward, sni_candidate):
        self.packets += 1
        self.sizes.append(wire_len)
        if self.first_ts is None:
            self.first_ts = ts
        self.last_ts = ts
        if is_forward:
            self.fwd_bytes += wire_len
        else:
            self.rev_bytes += wire_len
        if sni_candidate and self.sni is None:
            self.sni = sni_candidate.lower()


def extract_flows(pcap_path):
    """
    Parse every packet in pcap_path and group them into bidirectional flows.
    Returns a dict {flow_key: FlowRecord}.
    """
    flows = {}

    with open(pcap_path, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue

            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data

            src_ip = _ip_str(ip.src)
            dst_ip = _ip_str(ip.dst)

            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                src_port, dst_port = tcp.sport, tcp.dport
                proto   = "TCP"
                payload = bytes(tcp.data)
            elif isinstance(ip.data, dpkt.udp.UDP):
                udp = ip.data
                src_port, dst_port = udp.sport, udp.dport
                proto   = "UDP"
                payload = bytes(udp.data)
            else:
                continue  # only track TCP/UDP, matching C++ engine filter

            key    = canonical_tuple(src_ip, dst_ip, src_port, dst_port, proto)
            is_fwd = direction_is_forward(src_ip, src_port, key)

            if key not in flows:
                # Use the dst_port of the initiating direction for port-based labelling
                init_dst_port = dst_port if is_fwd else src_port
                flows[key]    = FlowRecord(key, init_dst_port, proto)

            flow = flows[key]
            wire_len = len(buf)

            # SNI / Host / DNS extraction
            sni_candidate = None
            if proto == "TCP" and dst_port == 443 and payload and flow.sni is None:
                sni_candidate = extract_tls_sni(payload)
            elif proto == "TCP" and dst_port == 80 and payload and flow.sni is None:
                sni_candidate = extract_http_host(payload)
            elif proto == "UDP" and (dst_port == 53 or src_port == 53) and payload and flow.sni is None:
                sni_candidate = extract_dns_query(payload)

            flow.add_packet(ts, wire_len, is_fwd, sni_candidate)

    return flows


# ---------------------------------------------------------------------------
# Feature computation
# ---------------------------------------------------------------------------

def compute_features(flow, domain_to_app):
    """
    Compute the six ML features for one flow and assign its ground-truth label.
    All values derive strictly from actual packet data in the PCAP.
    """
    n         = flow.packets
    mean_size = sum(flow.sizes) / n

    # Population standard deviation (ddof=0)
    variance = sum((s - mean_size) ** 2 for s in flow.sizes) / n
    std_size  = math.sqrt(variance)

    duration = (flow.last_ts - flow.first_ts) if flow.first_ts != flow.last_ts else 0.0

    # bytes_ratio: fwd / rev (guard against zero-rev flows)
    if flow.rev_bytes == 0:
        bytes_ratio = float("inf") if flow.fwd_bytes > 0 else 1.0
    else:
        bytes_ratio = flow.fwd_bytes / flow.rev_bytes

    # --- Label assignment (ground-truth from dpi_engine.exe) ---
    label = None
    if flow.sni:
        # Direct lookup
        label = domain_to_app.get(flow.sni)
        if label is None:
            # Suffix/prefix partial match
            for domain, app in domain_to_app.items():
                if flow.sni.endswith(domain) or domain.endswith(flow.sni):
                    label = app
                    break

    if label is None:
        # Port-based fallback -- identical to C++ engine logic
        if flow.dst_port == 443:
            label = "HTTPS"
        elif flow.dst_port == 80:
            label = "HTTP"
        elif flow.dst_port == 53:
            label = "DNS"
        else:
            label = "Unknown"

    br_str = f"{bytes_ratio:.6f}" if math.isfinite(bytes_ratio) else "inf"

    return {
        "flow_id":          flow.key,
        "packet_count":     n,
        "mean_packet_size": round(mean_size, 4),
        "std_packet_size":  round(std_size,  4),
        "flow_duration":    round(duration,  6),
        "bytes_ratio":      br_str,
        "label":            label,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    pcap_path  = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PCAP
    output_csv = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_OUTPUT

    if not pcap_path.exists():
        sys.exit(f"ERROR: PCAP not found: {pcap_path}")

    output_csv.parent.mkdir(parents=True, exist_ok=True)

    print(f"\n[1/3] Running dpi_engine.exe on {pcap_path.name} for ground-truth labels...")
    domain_to_app = run_dpi_engine(pcap_path)

    print(f"\n[2/3] Parsing {pcap_path.name} with dpkt and extracting real flow features...")
    flows = extract_flows(pcap_path)
    print(f"      Found {len(flows)} bidirectional flows.")

    print(f"\n[3/3] Computing per-flow statistics and assigning labels...")
    rows = []
    for flow in flows.values():
        rows.append(compute_features(flow, domain_to_app))

    # Sort by packet_count descending for readability
    rows.sort(key=lambda r: r["packet_count"], reverse=True)

    # Write CSV
    fieldnames = ["flow_id", "packet_count", "mean_packet_size",
                  "std_packet_size", "flow_duration", "bytes_ratio", "label"]
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n      CSV written to: {output_csv}")
    print(f"      Total rows (flows): {len(rows)}")

    # Print first 10 rows in tabular format
    col_w  = [50, 12, 16, 15, 14, 12, 15]
    header = "  ".join(h.ljust(col_w[i]) for i, h in enumerate(fieldnames))
    sep    = "-" * sum(col_w) + "-" * (2 * (len(fieldnames) - 1))
    print(f"\n{'='*len(sep)}")
    print("FIRST 10 ROWS -- all values computed from real packet data in PCAP")
    print(f"{'='*len(sep)}")
    print(header)
    print(sep)
    for row in rows[:10]:
        line = "  ".join(
            str(row[k]).ljust(col_w[i]) for i, k in enumerate(fieldnames)
        )
        print(line)
    print(sep)

    # Label source summary
    sni_labelled  = sum(1 for r in rows if r["label"] not in ("HTTPS", "HTTP", "DNS", "Unknown"))
    port_labelled = sum(1 for r in rows if r["label"] in ("HTTPS", "HTTP", "DNS"))
    unknown       = sum(1 for r in rows if r["label"] == "Unknown")
    print(f"\nLabel source breakdown:")
    print(f"  SNI/domain match (engine ground-truth): {sni_labelled} flows")
    print(f"  Port-based fallback (HTTPS/HTTP/DNS):   {port_labelled} flows")
    print(f"  Unlabelled (Unknown):                   {unknown} flows")
    print(f"\nDone. {len(rows)} real flows extracted from {pcap_path.name}.")


if __name__ == "__main__":
    main()
