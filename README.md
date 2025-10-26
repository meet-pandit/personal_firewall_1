Personal Firewall using Python

Overview
This project provides a lightweight personal firewall written in Python. It can sniff packets using scapy, evaluate them against user-defined rules, log suspicious activity, and optionally enforce OS-level firewall rules using Windows netsh or Linux iptables.

Features
- Rule engine to allow/deny by IPs, ports, protocol, and direction
- Live packet sniffing and logging
- CLI to manage rules, run the sniffer, and apply OS-level rules
- Optional Tkinter GUI for live monitoring

Requirements
- Python 3.9+
- Administrator/root privileges to sniff or enforce rules
- Windows: Install Npcap (in WinPcap API-compatible mode) from `https://nmap.org/npcap/`
- Linux: sudo access and iptables installed

Quick Start (VS Code / PowerShell)
1) Create and activate a virtual environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2) Install dependencies
```powershell
pip install -r requirements.txt
```

3) Initialize default rules file
```powershell
python -m src.cli init-rules
```

4) Start the firewall (sniffer + rule evaluation)
```powershell
python -m src.cli start --iface auto --log-level info
```

5) Open the GUI (optional)
```powershell
python -m src.cli gui
```

6) Apply OS-level rules (optional, requires admin/root)
```powershell
# Windows example
python -m src.cli enforce --platform windows

# Linux example
python -m src.cli enforce --platform linux
```

Project Structure
```
personal_firewall_1/
  requirements.txt
  README.md
  data/rules.json
  logs/
  src/
    __init__.py
    config.py
    rules.py
    logger_util.py
    sniffer.py
    enforcer.py
    cli.py
    gui.py
```

Common Commands
- List rules: `python -m src.cli list-rules`
- Add rule: `python -m src.cli add-rule --action deny --direction any --protocol tcp --dst-port 23 --description "Block Telnet"`
- Remove rule by id: `python -m src.cli remove-rule --id <RULE_ID>`
- Clear OS-level rules: `python -m src.cli clear-enforce --platform windows|linux`

Notes
- Live packet blocking purely from user-space is limited. For reliable blocking, use the `enforce` commands which call the OS firewall (netsh/iptables). The sniffer still logs matches for auditing.
- Run terminals as Administrator on Windows or with sudo privileges on Linux for sniffing and enforcement.


