import socket
import threading
import argparse
import os
import sys

if os.geteuid() != 0:
    print("[!] Please run this script as root (use sudo)")
    sys.exit(1)
    
from scapy.all import ARP, Ether, srp, IP, ICMP
from datetime import datetime
from termcolor import colored

# --------------------------
# TCP Port Scanner
# --------------------------
def scan_port(ip, port, timeout=0.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        print(colored(f"[+] {ip}:{port} is OPEN", "green"))
        s.close()
    except:
        pass

def port_scanner(ip, ports):
    print(colored(f"\n[~] Starting port scan on {ip}", "cyan"))
    threads = []
    for port in ports:
        t = threading.Thread(target=scan_port, args=(ip, port))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

# --------------------------
# ARP Scanner
# --------------------------
def arp_scan(subnet):
    print(colored(f"\n[~] Performing ARP scan on {subnet}", "cyan"))
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=False)[0]

    live_hosts = []
    for sent, received in result:
        live_hosts.append((received.psrc, received.hwsrc))
        print(colored(f"[+] {received.psrc} - {received.hwsrc}", "yellow"))
    return live_hosts

# --------------------------
# TTL OS Fingerprinting
# --------------------------
def detect_os(ip):
    pkt = IP(dst=ip)/ICMP()
    resp = srp(Ether()/pkt, timeout=1, verbose=False)[0]
    if resp:
        ttl = resp[0][1].ttl
        if ttl <= 64:
            os = "Linux/Unix"
        elif ttl <= 128:
            os = "Windows"
        else:
            os = "Unknown"
        print(colored(f"[OS Detection] {ip} appears to be: {os} (TTL={ttl})", "magenta"))

# --------------------------
# Argument Parser
# --------------------------
def main():
    parser = argparse.ArgumentParser(description="Advanced Network Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP or subnet (e.g. 192.168.1.1/24)")
    parser.add_argument("-p", "--ports", default="20-1024", help="Port range to scan (e.g. 1-1000)")
    args = parser.parse_args()

    # Process port range
    if '-' in args.ports:
        start, end = map(int, args.ports.split('-'))
        ports = range(start, end + 1)
    else:
        ports = [int(p) for p in args.ports.split(',')]

    start_time = datetime.now()

    # Step 1: Discover hosts
    hosts = arp_scan(args.target)

    # Step 2: Port scan each host
    for ip, mac in hosts:
        print(colored(f"\n[>] Scanning {ip} ({mac})", "blue"))
        detect_os(ip)
        port_scanner(ip, ports)

    duration = datetime.now() - start_time
    print(colored(f"\n[✓] Scan completed in {duration}", "green"))

if __name__ == "__main__":
    main()
