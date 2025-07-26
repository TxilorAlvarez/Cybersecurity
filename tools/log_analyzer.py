#!/usr/bin/env python3

"""
log_analyzer.py
----------------
A professional-grade log analysis tool for detecting suspicious activities
from common server logs (Apache, NGINX, syslog).

Author: Your Name
License: MIT
"""

import re
import argparse
import pandas as pd
from datetime import datetime
from rich.console import Console
from rich.table import Table

# Optional: GeoIP lookups
try:
    import geoip2.database
    GEOIP_ENABLED = True
except ImportError:
    GEOIP_ENABLED = False

# Optional: Colorful terminal
console = Console()

# Regex for Apache common log format
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) - - \[(?P<datetime>[^\]]+)\] "(?P<method>\S+)\s(?P<url>\S+).*?" (?P<status>\d+) (?P<size>\S+)'
)

def parse_log_file(file_path):
    logs = []
    with open(file_path, "r") as file:
        for line in file:
            match = LOG_PATTERN.search(line)
            if match:
                log = match.groupdict()
                log['datetime'] = datetime.strptime(log['datetime'], "%d/%b/%Y:%H:%M:%S %z")
                logs.append(log)
    return pd.DataFrame(logs)

def detect_anomalies(df):
    """ Detect simple anomalies: repeated requests, 404s, suspicious patterns """
    suspicious_ips = df[df['status'].isin(['401', '403', '404'])]['ip'].value_counts()
    brute_force = df[df['status'] == '401']['ip'].value_counts()
    top_ips = df['ip'].value_counts().head(10)

    console.rule("[bold red]Anomaly Detection")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Suspicious IP", style="dim")
    table.add_column("404/403/401 Count")

    for ip, count in suspicious_ips.items():
        table.add_row(ip, str(count))

    console.print(table)

    return suspicious_ips

def geoip_lookup(ip):
    if not GEOIP_ENABLED:
        return "GeoIP disabled"
    try:
        reader = geoip2.database.Reader('GeoLite2-City.mmdb')
        response = reader.city(ip)
        return f"{response.city.name}, {response.country.name}"
    except:
        return "Unknown"

def show_summary(df):
    console.rule("[bold green]Log Summary")
    table = Table(title="Top URLs")
    table.add_column("URL")
    table.add_column("Hits", justify="right")
    top_urls = df['url'].value_counts().head(5)
    for url, hits in top_urls.items():
        table.add_row(url, str(hits))
    console.print(table)

def main():
    parser = argparse.ArgumentParser(description="Advanced Log Analyzer for Security Teams")
    parser.add_argument("-f", "--file", required=True, help="Path to log file (Apache, NGINX, etc.)")
    parser.add_argument("--geoip", action="store_true", help="Enable GeoIP lookup (requires geoip2 and DB)")

    args = parser.parse_args()
    df = parse_log_file(args.file)

    show_summary(df)
    detect_anomalies(df)

    if args.geoip and GEOIP_ENABLED:
        unique_ips = df['ip'].unique()[:5]
        console.rule("[bold yellow]GeoIP Lookup")
        for ip in unique_ips:
            location = geoip_lookup(ip)
            console.print(f"{ip} → {location}")
    elif args.geoip:
        console.print("[red]GeoIP module not available. Install with: pip install geoip2")

if __name__ == "__main__":
    main()
