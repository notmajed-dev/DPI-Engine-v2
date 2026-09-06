import os
import struct
import random
import sys
import subprocess
from pathlib import Path

class PCAPWriter:
    def __init__(self, filename, base_ts):
        self.file = open(filename, 'wb')
        self.write_global_header()
        self.timestamp = base_ts
        
    def write_global_header(self):
        # Magic, version 2.4, timezone 0, sigfigs 0, snaplen 65535, linktype Ethernet
        header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        self.file.write(header)
        
    def write_packet(self, data, ts_delta_sec=0, ts_delta_usec=0):
        self.timestamp += ts_delta_sec
        ts_sec = int(self.timestamp)
        ts_usec = int((self.timestamp - ts_sec) * 1000000) + ts_delta_usec
        if ts_usec >= 1000000:
            ts_sec += ts_usec // 1000000
            ts_usec = ts_usec % 1000000
            
        pkt_header = struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data))
        self.file.write(pkt_header)
        self.file.write(data)
        
    def close(self):
        self.file.close()

def create_ethernet_header(src_mac, dst_mac, ethertype=0x0800):
    return bytes.fromhex(dst_mac.replace(':', '')) + \
           bytes.fromhex(src_mac.replace(':', '')) + \
           struct.pack('>H', ethertype)

def create_ip_header(src_ip, dst_ip, protocol, payload_len):
    version_ihl = 0x45
    tos = 0
    total_len = 20 + payload_len
    ident = random.randint(1, 65535)
    flags_frag = 0x4000
    ttl = 64
    checksum = 0
    
    header = struct.pack('>BBHHHBBH', version_ihl, tos, total_len, ident, flags_frag, ttl, protocol, checksum)
    header += bytes([int(x) for x in src_ip.split('.')])
    header += bytes([int(x) for x in dst_ip.split('.')])
    return header

def create_tcp_header(src_port, dst_port, seq, ack, flags, payload_len=0):
    data_offset = 5 << 4
    window = 65535
    checksum = 0
    urgent = 0
    return struct.pack('>HHIIBBHHH', src_port, dst_port, seq, ack, data_offset, flags, window, checksum, urgent)

def create_udp_header(src_port, dst_port, payload_len):
    length = 8 + payload_len
    checksum = 0
    return struct.pack('>HHHH', src_port, dst_port, length, checksum)

def create_tls_client_hello(sni):
    sni_bytes = sni.encode('ascii')
    sni_entry = struct.pack('>BH', 0, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack('>H', len(sni_entry)) + sni_entry
    sni_ext = struct.pack('>HH', 0x0000, len(sni_list)) + sni_list
    supported_versions = struct.pack('>HHB', 0x002b, 3, 2) + struct.pack('>H', 0x0304)
    extensions = sni_ext + supported_versions
    extensions_data = struct.pack('>H', len(extensions)) + extensions
    
    client_version = struct.pack('>H', 0x0303)
    random_bytes = bytes([random.randint(0, 255) for _ in range(32)])
    session_id = struct.pack('B', 0)
    cipher_suites = struct.pack('>H', 4) + struct.pack('>HH', 0x1301, 0x1302)
    compression = struct.pack('BB', 1, 0)
    
    client_hello_body = client_version + random_bytes + session_id + cipher_suites + compression + extensions_data
    
    handshake = struct.pack('B', 0x01) + struct.pack('>I', len(client_hello_body))[1:] + client_hello_body
    record = struct.pack('B', 0x16) + struct.pack('>H', 0x0301) + struct.pack('>H', len(handshake)) + handshake
    return record

def create_http_request(host, path='/'):
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: DPI-Test/1.0\r\nAccept: */*\r\n\r\n".encode()

def create_dns_query(domain):
    txid = struct.pack('>H', random.randint(1, 65535))
    flags = struct.pack('>H', 0x0100)
    counts = struct.pack('>HHHH', 1, 0, 0, 0)
    question = b''
    for label in domain.split('.'):
        question += struct.pack('B', len(label)) + label.encode()
    question += struct.pack('B', 0) + struct.pack('>HH', 1, 1)
    return txid + flags + counts + question

def generate_varied_pcap(filename, seed):
    random.seed(seed)
    writer = PCAPWriter(filename, 1700000000 + seed * 1000)
    
    user_mac = '00:11:22:33:44:55'
    user_ip = '192.168.1.100'
    gateway_mac = 'aa:bb:cc:dd:ee:ff'
    
    tls_connections = [
        ('142.250.185.206', 'www.google.com'),
        ('142.250.185.110', 'www.youtube.com'),
        ('157.240.1.35', 'www.facebook.com'),
        ('157.240.1.174', 'www.instagram.com'),
        ('104.244.42.65', 'twitter.com'),
        ('52.94.236.248', 'www.amazon.com'),
        ('23.52.167.61', 'www.netflix.com'),
        ('140.82.114.4', 'github.com'),
        ('104.16.85.20', 'discord.com'),
        ('35.186.224.25', 'zoom.us'),
        ('35.186.227.140', 'web.telegram.org'),
        ('99.86.0.100', 'www.tiktok.com'),
        ('35.186.224.47', 'open.spotify.com'),
        ('192.0.78.24', 'www.cloudflare.com'),
        ('13.107.42.14', 'www.microsoft.com'),
        ('17.253.144.10', 'www.apple.com'),
    ]
    
    http_connections = [
        ('93.184.216.34', 'example.com'),
        ('185.199.108.153', 'httpbin.org'),
    ]
    
    dns_queries = [
        'www.google.com',
        'www.youtube.com',
        'www.facebook.com',
        'api.twitter.com',
    ]
    
    seq_base = 1000
    
    # Generate TLS connections
    for dst_ip, sni in tls_connections:
        num_connections = random.randint(1, 5) # Generate multiple flows per SNI
        for _ in range(num_connections):
            src_port = random.randint(49152, 65535)
            dst_port = 443
            
            # Handshake
            eth_out = create_ethernet_header(user_mac, gateway_mac)
            eth_in = create_ethernet_header(gateway_mac, user_mac)
            
            tcp_syn = create_tcp_header(src_port, dst_port, seq_base, 0, 0x02)
            writer.write_packet(eth_out + create_ip_header(user_ip, dst_ip, 6, len(tcp_syn)) + tcp_syn, 0.0, random.randint(1000, 5000))
            
            tcp_synack = create_tcp_header(dst_port, src_port, seq_base + 1000, seq_base + 1, 0x12)
            writer.write_packet(eth_in + create_ip_header(dst_ip, user_ip, 6, len(tcp_synack)) + tcp_synack, 0.0, random.randint(10000, 50000))
            
            tcp_ack = create_tcp_header(src_port, dst_port, seq_base + 1, seq_base + 1001, 0x10)
            writer.write_packet(eth_out + create_ip_header(user_ip, dst_ip, 6, len(tcp_ack)) + tcp_ack, 0.0, random.randint(1000, 5000))
            
            # TLS Client Hello
            tls_data = create_tls_client_hello(sni)
            tcp_ch = create_tcp_header(src_port, dst_port, seq_base + 1, seq_base + 1001, 0x18)
            writer.write_packet(eth_out + create_ip_header(user_ip, dst_ip, 6, len(tcp_ch) + len(tls_data)) + tcp_ch + tls_data, 0.0, random.randint(1000, 5000))
            
            # Simulate data exchange (App data)
            num_data_pkts = random.randint(2, 20)
            c_seq = seq_base + 1 + len(tls_data)
            s_seq = seq_base + 1001
            for __ in range(num_data_pkts):
                if random.random() > 0.5: # Client -> Server
                    payload = bytes([random.randint(0, 255) for _ in range(random.randint(50, 1000))])
                    tcp = create_tcp_header(src_port, dst_port, c_seq, s_seq, 0x18)
                    writer.write_packet(eth_out + create_ip_header(user_ip, dst_ip, 6, len(tcp) + len(payload)) + tcp + payload, random.uniform(0.01, 0.5), random.randint(100, 10000))
                    c_seq += len(payload)
                else: # Server -> Client
                    payload = bytes([random.randint(0, 255) for _ in range(random.randint(100, 1400))])
                    tcp = create_tcp_header(dst_port, src_port, s_seq, c_seq, 0x18)
                    writer.write_packet(eth_in + create_ip_header(dst_ip, user_ip, 6, len(tcp) + len(payload)) + tcp + payload, random.uniform(0.01, 0.5), random.randint(100, 10000))
                    s_seq += len(payload)
            
            seq_base += 100000

    # Generate HTTP connections
    for dst_ip, host in http_connections:
        num_connections = random.randint(1, 3)
        for _ in range(num_connections):
            src_port = random.randint(49152, 65535)
            dst_port = 80
            
            eth_out = create_ethernet_header(user_mac, gateway_mac)
            tcp_syn = create_tcp_header(src_port, dst_port, seq_base, 0, 0x02)
            writer.write_packet(eth_out + create_ip_header(user_ip, dst_ip, 6, len(tcp_syn)) + tcp_syn, 0.0, random.randint(1000, 5000))
            
            http_data = create_http_request(host)
            tcp = create_tcp_header(src_port, dst_port, seq_base + 1, 1, 0x18)
            writer.write_packet(eth_out + create_ip_header(user_ip, dst_ip, 6, len(tcp) + len(http_data)) + tcp + http_data, 0.0, random.randint(1000, 5000))
            
            seq_base += 100000

    # Generate DNS queries
    dns_server = '8.8.8.8'
    for domain in dns_queries:
        num_queries = random.randint(1, 5)
        for _ in range(num_queries):
            src_port = random.randint(49152, 65535)
            dns_data = create_dns_query(domain)
            eth = create_ethernet_header(user_mac, gateway_mac)
            udp = create_udp_header(src_port, 53, len(dns_data))
            ip = create_ip_header(user_ip, dns_server, 17, len(udp) + len(dns_data))
            writer.write_packet(eth + ip + udp + dns_data, 0.0, random.randint(1000, 5000))

    writer.close()
    return filename

def main():
    num_pcaps = 12
    pcap_dir = Path("pipeline/data/raw_pcaps")
    pcap_dir.mkdir(parents=True, exist_ok=True)
    
    combined_csv = Path("pipeline/data/combined_flow_features.csv")
    if combined_csv.exists():
        combined_csv.unlink()
    
    generated_pcaps = []
    print(f"Generating {num_pcaps} PCAPs...")
    for i in range(num_pcaps):
        pcap_file = pcap_dir / f"synthetic_varied_{i}.pcap"
        generate_varied_pcap(str(pcap_file), seed=42+i)
        generated_pcaps.append(pcap_file)
        
    print(f"Running extraction on {num_pcaps} PCAPs...")
    header_written = False
    
    total_rows = 0
    label_counts = {}
    
    for pcap in generated_pcaps:
        # Run extract_real_features.py on this PCAP
        temp_csv = pcap.with_suffix('.csv')
        cmd = [sys.executable, "pipeline/extract_real_features.py", str(pcap), str(temp_csv)]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            print(f"Error processing {pcap}:\n{res.stderr}")
            continue
            
        # Append to combined CSV
        if temp_csv.exists():
            with open(temp_csv, "r", encoding="utf-8") as f_in:
                lines = f_in.readlines()
                if len(lines) > 1:
                    with open(combined_csv, "a", encoding="utf-8") as f_out:
                        if not header_written:
                            f_out.write(lines[0])
                            header_written = True
                        for line in lines[1:]:
                            f_out.write(line)
                            total_rows += 1
                            lbl = line.strip().split(',')[-1]
                            label_counts[lbl] = label_counts.get(lbl, 0) + 1
            temp_csv.unlink()

    print(f"\nFinal combined CSV: {combined_csv}")
    print(f"Total Rows: {total_rows}")
    print("\nLabel Breakdown:")
    for lbl, count in sorted(label_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {lbl}: {count}")

if __name__ == '__main__':
    main()
