# 🛠️ Cybersecurity Toolkit – Usage Guide

Welcome to the **Cybersecurity Toolkit**. This guide will help you get started with using, customizing, and safely experimenting with the tools provided in this repository.

---

## 📦 What's Inside

This repository contains:

- 🧰 Python scripts for common security tasks (port scanning, log parsing, etc.)
- 🧪 Examples and demos of tool usage
- 🧠 CTF writeups (methodology & educational only)
- 📚 Documentation for secure practices

---

## 🚀 Getting Started

### 1. Set Up a Virtual Environment (Recommended)

bash ### How to create it. 

    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate   deactivate
    pip install -r requirements.txt

###
Each tool is found in the /tools/ directory.

# Example: Network Scanner
bash

If you want to run in Windows, you need to download WinPcap or Npcap

    python tools/network_scanner.py -t 192.168.1.1/24

        -t or --target: Network range or IP

    sudo python3 tools/network_scanner.py -t 192.168.1.0/24 -p 22,80,443


Results will print open ports and detected hosts    

# Example: Log Analyzer

🧠 Features
✅ Parses Apache/Nginx logs with regex
✅ Displays top IPs and requested URLs
✅ Detects potential attacks (404, brute force, unauthorized access)
✅ Optional GeoIP location detection
✅ Modern CLI interface using rich
✅ Ready for expansion with APIs or ML

    python tools/log_analyzer.py -f logs/syslog.txt
    pip install pandas rich geoip2

# To use GeoIP:

Download GeoLite2-City.mmdb from MaxMind

Place it in your working directory or change the path in geoip_lookup()

    python tools/log_analyzer.py -f access.log
    python tools/log_analyzer.py -f access.log --geoip


### 📖 Writeups and CTFs
Navigate to:
/CTF/writeups/

Each writeup includes:

Challenge summary

Step-by-step solution

Tools/techniques used

Lessons learned

⚠️ All writeups are for educational purposes only. No challenge answers are provided for live platforms.

# How to create demo.gif para network_scanner.py?   
Instala una herramienta para grabar la terminal como gif, por ejemplo:

asciinema + svg-to-gif
(grabación limpia basada en texto):

sudo apt install asciinema
asciinema rec demo.cast
# haz tu demo
# Ctrl+D para terminar
# convierte .cast a gif usando svg-term-cli (Node.js)
npx svg-term --in demo.cast --out demo.gif --window --padding 10




# 💼 Professional Use
Follow best practices for responsible disclosure

Do not use scanning/exploitation tools without proper authorization

Use virtual machines or isolated lab environments for experimentation

Comply with local and international cyber laws

# 📚 Additional Resources
OWASP Top 10

MITRE ATT&CK Framework

TryHackMe Labs 

Tenable Nessus

# 🙋 Need Help?
Open an issue or connect with me on LinkedIn.

# ⚠️ Disclaimer
This project is for educational and ethical use only. Do not engage in unauthorized scanning or exploitation. By using this repository, you agree to our LICENSE.



---

### ✅ Where to place it

- File path: `cybersecurity-toolkit/docs/usage_guide.md`
- Link to it from the main `README.md` for visibility.


### . Clone the Repository

```bash
git clone https://github.com/TxilorAlvarez/Cybersecurity-toolkit.git
cd cybersecurity-toolkit



