from scapy.all import sniff, IP, TCP, ARP
import time
import socket

# ---------------- HELPER ----------------
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

# ---------------- CONFIG ----------------
LOCAL_IP = get_local_ip()
TIME_WINDOW = 10
PORT_THRESHOLD = 5

# ---------------- MEMORY ----------------
ports = {}              # src_ip -> list of (dst_port, time)
alerted_ips = set()
arp_table = {}

# ---------------- PACKET HANDLER ----------------
def handle_packet(packet):

    # ========== PORT SCAN DETECTION ==========
    if packet.haslayer(IP) and packet.haslayer(TCP):

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport

        # Only detect traffic COMING TO ME
        if dst_ip != LOCAL_IP:
            return

        # Only detect NEW connection attempts
        if packet[TCP].flags != "S":
            return

        current_time = time.time()

        if src_ip not in ports:
            ports[src_ip] = []

        # Store destination port + time
        ports[src_ip].append((dst_port, current_time))

        # ---- TIME WINDOW CLEANUP ----
        ports[src_ip] = [
            (p, t) for (p, t) in ports[src_ip]
            if current_time - t <= TIME_WINDOW
        ]

        unique_ports = {p for (p, _ ) in ports[src_ip]}

        # ---- ALERT ONCE ----
        if len(unique_ports) >= PORT_THRESHOLD and src_ip not in alerted_ips:
            print(f"[ALERT] Possible port scan detected!")
            print(f"Scanner IP : {src_ip}")
            print(f"Target IP  : {LOCAL_IP}")
            print(f"Ports      : {unique_ports}")
            print("-" * 50)
            alerted_ips.add(src_ip)

    # ========== ARP SPOOF DETECTION ==========
    if packet.haslayer(ARP):

        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        # Ignore ARP probes
        if ip == "0.0.0.0":
            return

        if ip not in arp_table:
            arp_table[ip] = mac
            print(f"[ARP] Learned {ip} is at {mac}")

        elif arp_table[ip] != mac:
            print("[ALERT] ARP spoof detected!")
            print(f"{ip} changed from {arp_table[ip]} to {mac}")
            print("-" * 50)

# ---------------- START ----------------
print(f"[*] Monitoring host IP: {LOCAL_IP}")
sniff(prn=handle_packet)

