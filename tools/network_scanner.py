import socket
import argparse
import json
from datetime import datetime
from scapy.all import ARP, Ether, srp

def arp_scan(target_ip):
    print(f"[~] Performing ARP scan on {target_ip}")
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=False)[0]

    hosts = []
    for sent, received in result:
        hosts.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })
        print(f"[+] {received.psrc} - {received.hwsrc}")
    return hosts

def detect_os(ip):
    try:
        ttl = socket.gethostbyname(ip)  # basic TTL-based detection stub
        return "Linux/Unix (TTL~64)"  # Simplified
    except:
        return "Unknown"

def banner_grab(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))
        banner = s.recv(1024).decode().strip()
        s.close()
        return banner if banner else "No banner"
    except:
        return "No response"

def port_scan(ip, ports):
    print(f"\n[~] Starting port scan on {ip}")
    open_ports = []
    for port in ports:
        s = socket.socket()
        s.settimeout(0.5)
        try:
            s.connect((ip, port))
            banner = banner_grab(ip, port)
            print(f"[+] {ip}:{port} is OPEN - {banner}")
            open_ports.append({
                "port": port,
                "banner": banner
            })
        except:
            pass
        s.close()
    return open_ports

def main():
    parser = argparse.ArgumentParser(description="Advanced Network Scanner")
    parser.add_argument("-t", "--target", help="Target IP/subnet", required=True)
    parser.add_argument("-p", "--ports", help="Ports (e.g. 22,80,443 or 20-100)", required=True)
    args = parser.parse_args()

    # Parse port range
    if "-" in args.ports:
        start, end = map(int, args.ports.split("-"))
        ports = range(start, end + 1)
    else:
        ports = [int(p) for p in args.ports.split(",")]

    # ARP Scan
    hosts = arp_scan(args.target)

    # Full scan results
    scan_data = {
        "timestamp": datetime.now().isoformat(),
        "target": args.target,
        "results": []
    }

    for host in hosts:
        print(f"\n[>] Scanning {host['ip']} ({host['mac']})")
        os_guess = detect_os(host['ip'])
        ports_info = port_scan(host['ip'], ports)
        scan_data["results"].append({
            "ip": host['ip'],
            "mac": host['mac'],
            "os": os_guess,
            "open_ports": ports_info
        })

    # Save to file
    output_file = f"scan_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, "w") as f:
        json.dump(scan_data, f, indent=4)
    print(f"\n[✓] Scan completed. Results saved to {output_file}")

if __name__ == "__main__":
    main()
