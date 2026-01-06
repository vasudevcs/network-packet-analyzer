from scapy.all import sniff, IP, TCP, ARP
import time

# ---------------- MEMORY ----------------
ports = {}              # IP -> list of (port, time)
last_ports_seen = {}    # IP -> last printed port set
arp_table = {}

# ---------------- CONFIG ----------------
LOCAL_IP = "192.168.2.52"
TIME_WINDOW = 10
PORT_THRESHOLD = 5

def handle_packet(packet):

    # ---------------- TCP / PORT SCAN ----------------
    if packet.haslayer(IP) and packet.haslayer(TCP):

        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        # Ignore packets not from our machine
        if src_ip != LOCAL_IP:
            return

        current_time = time.time()

        if src_ip not in ports:
            ports[src_ip] = []

        # Store (port, time)
        ports[src_ip].append((dst_port, current_time))

        # -------- TIME WINDOW CLEANUP --------
        ports[src_ip] = [
            (p, t) for (p, t) in ports[src_ip]
            if current_time - t <= TIME_WINDOW
        ]

        # Count unique ports in window
        unique_ports = {p for (p, t) in ports[src_ip]}

        # -------- NOISE REDUCTION --------
        if src_ip not in last_ports_seen or last_ports_seen[src_ip] != unique_ports:
            print(f"{src_ip} -> ports in last {TIME_WINDOW}s: {unique_ports}")
            last_ports_seen[src_ip] = unique_ports.copy()

        # -------- ALERT --------
        if len(unique_ports) >= PORT_THRESHOLD:
            print(f"[ALERT] Possible port scan from {src_ip}")
            print("-" * 40)

    # ---------------- ARP SPOOF DETECTION ----------------
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

# ---------------- START SNIFFING ----------------
sniff(prn=handle_packet)
