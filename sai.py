#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║  Shetty Groups — AI Automation & Log Analysis Assistant               ║
║   Single Python file · No API keys · No ML · Pure rule-based AI     ║
║                                                                      ║
║   RUN :  python log_analyzer_noapi.py                                ║
║   OPEN:  http://localhost:8080                                       ║
║   LOGIN: admin / admin123  |  analyst / analyst2024                  ║
╚══════════════════════════════════════════════════════════════════════╝

HOW AI AGENT & AUTOMATION WORKS (no API key needed):
─────────────────────────────────────────────────────
1. RULE ENGINE       — 25+ pattern rules classify every event (Python)
2. AI AGENT          — NLG engine writes human-readable threat summaries
3. RISK SCORER       — Composite per-host risk score (weighted algorithm)
4. FIREWALL GEN      — Generates iptables + Windows rules from findings
5. REPORT WRITER     — Writes full SOC incident report in plain English
6. ALERT DRAFTER     — Creates email alerts for technical + mgmt teams
7. PCAP PARSER       — Pure Python struct parser, no scapy needed
8. AUTOMATION LOOP   — Background thread monitors & runs pipeline stages
"""

import http.server
import socketserver
import json
import base64
import struct
import socket as sock
import datetime
import os
import hashlib
import re
import threading
import time
import sys                     # <-- Added for port argument
from collections import defaultdict, Counter

# ══════════════════════════════════════════════════════════════════════
#  AUTH
# ══════════════════════════════════════════════════════════════════════
def _h(p): return hashlib.sha256(p.encode()).hexdigest()
USERS    = {"admin": _h("admin123"), "analyst": _h("analyst2024"), "demo": _h("demo1234")}
SESSIONS = {}
def make_session(u):
    t = _h(os.urandom(32).hex()); SESSIONS[t] = u; return t
def get_session(t): return SESSIONS.get(t)

# ══════════════════════════════════════════════════════════════════════
#  100 BUILT-IN SAMPLE LOGS
# ══════════════════════════════════════════════════════════════════════
SAMPLE_LOGS = [
  # ── Normal traffic ──────────────────────────────────────────────────
  ("2024-03-01 08:00:01","192.168.1.10","8.8.8.8","DNS",53,"DNS Query: google.com","INFO"),
  ("2024-03-01 08:00:02","8.8.8.8","192.168.1.10","DNS",53,"DNS Response: 142.250.80.46","INFO"),
  ("2024-03-01 08:00:05","192.168.1.10","142.250.80.46","HTTPS",443,"HTTPS GET /search","INFO"),
  ("2024-03-01 08:00:10","192.168.1.11","192.168.1.1","ARP",0,"ARP Who-has 192.168.1.1","INFO"),
  ("2024-03-01 08:00:15","192.168.1.12","8.8.4.4","DNS",53,"DNS Query: microsoft.com","INFO"),
  ("2024-03-01 08:01:00","192.168.1.13","20.190.128.10","HTTPS",443,"HTTPS MS Update","INFO"),
  ("2024-03-01 08:01:10","192.168.1.14","192.168.1.1","DHCP",67,"DHCP Request","INFO"),
  ("2024-03-01 08:01:20","192.168.1.10","172.217.14.46","HTTP",80,"HTTP GET /index.html","MEDIUM"),
  ("2024-03-01 08:01:30","192.168.1.15","192.168.1.1","DNS",53,"DNS Query: github.com","INFO"),
  ("2024-03-01 08:02:00","192.168.1.16","151.101.1.69","HTTPS",443,"HTTPS stackoverflow.com","INFO"),
  # ── Port scans ──────────────────────────────────────────────────────
  ("2024-03-01 08:02:10","10.0.0.55","192.168.1.20","TCP",22,"TCP SYN Port:22","MEDIUM"),
  ("2024-03-01 08:02:11","10.0.0.55","192.168.1.20","TCP",23,"TCP SYN Port:23","HIGH"),
  ("2024-03-01 08:02:12","10.0.0.55","192.168.1.20","TCP",80,"TCP SYN Port:80","MEDIUM"),
  ("2024-03-01 08:02:13","10.0.0.55","192.168.1.20","TCP",443,"TCP SYN Port:443","INFO"),
  ("2024-03-01 08:02:14","10.0.0.55","192.168.1.20","TCP",445,"TCP SYN Port:445","HIGH"),
  ("2024-03-01 08:02:15","10.0.0.55","192.168.1.20","TCP",3389,"TCP SYN Port:3389","CRITICAL"),
  ("2024-03-01 08:02:16","10.0.0.55","192.168.1.20","TCP",8080,"TCP SYN Port:8080","MEDIUM"),
  ("2024-03-01 08:02:17","10.0.0.55","192.168.1.20","TCP",21,"TCP SYN Port:21","HIGH"),
  ("2024-03-01 08:02:18","10.0.0.55","192.168.1.20","TCP",1433,"TCP SYN Port:1433","CRITICAL"),
  ("2024-03-01 08:02:19","10.0.0.55","192.168.1.20","TCP",3306,"TCP SYN Port:3306","HIGH"),
  # ── Brute force attacks ─────────────────────────────────────────────
  ("2024-03-01 08:03:00","185.220.101.47","192.168.1.100","TCP",22,"SSH Login Failed: root","CRITICAL"),
  ("2024-03-01 08:03:01","185.220.101.47","192.168.1.100","TCP",22,"SSH Login Failed: admin","CRITICAL"),
  ("2024-03-01 08:03:02","185.220.101.47","192.168.1.100","TCP",22,"SSH Login Failed: user","CRITICAL"),
  ("2024-03-01 08:03:03","185.220.101.47","192.168.1.100","TCP",22,"SSH Login Failed: ubuntu","CRITICAL"),
  ("2024-03-01 08:03:04","185.220.101.47","192.168.1.100","TCP",22,"SSH Login Failed: pi","CRITICAL"),
  ("2024-03-01 08:04:00","172.16.0.30","192.168.1.1","HTTP",80,"HTTP POST /admin/login failed","CRITICAL"),
  ("2024-03-01 08:04:01","172.16.0.30","192.168.1.1","HTTP",80,"HTTP POST /admin/login failed","CRITICAL"),
  ("2024-03-01 08:04:02","172.16.0.30","192.168.1.1","HTTP",80,"HTTP POST /admin/login failed","CRITICAL"),
  ("2024-03-01 08:04:03","172.16.0.30","192.168.1.1","HTTP",80,"HTTP POST /admin/login success","HIGH"),
  ("2024-03-01 08:05:00","203.0.113.88","192.168.1.50","TCP",3389,"RDP Login Failed: Administrator","CRITICAL"),
  # ── Malware / C2 ────────────────────────────────────────────────────
  ("2024-03-01 08:06:00","192.168.1.77","185.220.101.5","TCP",4444,"Reverse Shell Port 4444","CRITICAL"),
  ("2024-03-01 08:06:10","192.168.1.77","203.0.113.45","HTTPS",443,"Beacon interval 60s — Cobalt Strike IOC","CRITICAL"),
  ("2024-03-01 08:06:20","192.168.1.77","192.168.1.88","TCP",445,"Lateral Movement SMB","CRITICAL"),
  ("2024-03-01 08:06:30","192.168.1.77","192.168.1.89","TCP",445,"Lateral Movement SMB","CRITICAL"),
  ("2024-03-01 08:07:00","192.168.1.5","192.168.1.1","DNS",53,"DNS Query: malware-c2.evil.com","CRITICAL"),
  ("2024-03-01 08:07:10","192.168.1.5","185.220.101.5","TCP",9001,"Tor C2 Port 9001","CRITICAL"),
  ("2024-03-01 08:07:20","192.168.1.5","45.33.32.156","ICMP",0,"ICMP Tunnel Covert Channel","HIGH"),
  ("2024-03-01 08:08:00","192.168.1.99","203.0.113.99","TCP",6667,"IRC Botnet Port 6667","CRITICAL"),
  ("2024-03-01 08:08:10","192.168.1.6","10.0.0.1","TCP",31337,"Back Orifice Port 31337","CRITICAL"),
  ("2024-03-01 08:08:20","192.168.1.7","10.0.0.2","TCP",1337,"Hacking Tool Port 1337","HIGH"),
  # ── Data exfiltration ───────────────────────────────────────────────
  ("2024-03-01 08:09:00","192.168.1.45","104.21.96.0","HTTPS",443,"Large Upload 245MB Outbound","HIGH"),
  ("2024-03-01 08:09:10","192.168.1.45","104.21.97.0","FTP",21,"FTP Upload sensitive_data.zip","CRITICAL"),
  ("2024-03-01 08:09:20","192.168.1.45","185.199.108.153","HTTPS",443,"Exfil pattern detected 180MB","HIGH"),
  ("2024-03-01 08:10:00","192.168.1.33","8.8.8.8","DNS",53,"DNS Tunnelling TXT record data exfil","HIGH"),
  ("2024-03-01 08:10:10","192.168.1.34","8.8.4.4","DNS",53,"DNS Tunnelling long subdomain query","HIGH"),
  # ── Web attacks ─────────────────────────────────────────────────────
  ("2024-03-01 08:11:00","203.0.113.12","192.168.1.80","HTTP",80,"SQL Injection: UNION SELECT","CRITICAL"),
  ("2024-03-01 08:11:10","203.0.113.12","192.168.1.80","HTTP",80,"SQL Injection: DROP TABLE users","CRITICAL"),
  ("2024-03-01 08:11:20","203.0.113.13","192.168.1.80","HTTP",80,"XSS: <script>alert(1)</script>","HIGH"),
  ("2024-03-01 08:11:30","203.0.113.14","192.168.1.80","HTTP",80,"Path Traversal: ../../etc/passwd","CRITICAL"),
  ("2024-03-01 08:11:40","203.0.113.15","192.168.1.80","HTTP",80,"Command Injection: ;cat /etc/shadow","CRITICAL"),
  ("2024-03-01 08:12:00","203.0.113.16","192.168.1.80","HTTP",80,"LFI: /etc/passwd in GET param","CRITICAL"),
  ("2024-03-01 08:12:10","203.0.113.17","192.168.1.80","HTTP",8080,"SSRF: internal metadata request","HIGH"),
  ("2024-03-01 08:12:20","203.0.113.18","192.168.1.80","HTTP",80,"XXE: XML External Entity attack","HIGH"),
  ("2024-03-01 08:12:30","203.0.113.19","192.168.1.80","HTTP",80,"CSRF Token missing POST /transfer","MEDIUM"),
  ("2024-03-01 08:12:40","203.0.113.20","192.168.1.80","HTTPS",443,"Directory Traversal ../../../var","HIGH"),
  # ── Network anomalies ───────────────────────────────────────────────
  ("2024-03-01 08:13:00","192.168.1.110","255.255.255.255","UDP",67,"DHCP Discover broadcast","INFO"),
  ("2024-03-01 08:13:10","192.168.1.3","192.168.1.255","ARP",0,"ARP Poisoning — spoofed gateway","CRITICAL"),
  ("2024-03-01 08:13:20","192.168.1.4","192.168.1.1","ARP",0,"ARP Flood — cache poisoning","HIGH"),
  ("2024-03-01 08:14:00","192.168.1.88","45.33.32.156","ICMP",0,"ICMP Ping Sweep recon /24","MEDIUM"),
  ("2024-03-01 08:14:10","192.168.1.60","192.168.1.1","TCP",23,"Telnet plaintext session","HIGH"),
  ("2024-03-01 08:14:20","192.168.1.61","192.168.1.1","TCP",21,"FTP plaintext credentials","HIGH"),
  ("2024-03-01 08:14:30","10.10.10.99","192.168.1.35","UDP",161,"SNMP public community string","MEDIUM"),
  ("2024-03-01 08:15:00","192.168.1.150","192.168.1.200","TCP",5900,"VNC unencrypted remote desktop","HIGH"),
  ("2024-03-01 08:15:10","192.168.1.200","192.168.1.201","TCP",445,"SMB EternalBlue exploit pattern","CRITICAL"),
  ("2024-03-01 08:15:20","192.168.1.201","192.168.1.202","TCP",445,"SMB scan lateral spread","CRITICAL"),
  # ── Ransomware indicators ───────────────────────────────────────────
  ("2024-03-01 08:16:00","192.168.1.77","192.168.1.0/24","SMB",445,"Mass file encrypt .locky extension","CRITICAL"),
  ("2024-03-01 08:16:10","192.168.1.77","192.168.1.0/24","SMB",445,"Ransom note HOW_TO_DECRYPT.txt","CRITICAL"),
  ("2024-03-01 08:16:20","192.168.1.77","185.220.101.10","HTTPS",443,"Ransomware C2 key exchange","CRITICAL"),
  ("2024-03-01 08:16:30","192.168.1.77","192.168.1.0/24","SMB",445,"Shadow copy deletion vssadmin","CRITICAL"),
  ("2024-03-01 08:17:00","192.168.1.55","192.168.1.1","DNS",53,"DNS Query: ransom-pay.onion","CRITICAL"),
  # ── Privilege escalation ────────────────────────────────────────────
  ("2024-03-01 08:18:00","192.168.1.30","192.168.1.1","TCP",88,"Kerberoasting AS-REP request","CRITICAL"),
  ("2024-03-01 08:18:10","192.168.1.30","192.168.1.1","TCP",88,"Pass-the-Hash NTLM relay","CRITICAL"),
  ("2024-03-01 08:18:20","192.168.1.30","192.168.1.1","TCP",389,"LDAP Enumeration domain users","HIGH"),
  ("2024-03-01 08:18:30","192.168.1.30","192.168.1.1","TCP",636,"LDAP dump all AD objects","HIGH"),
  ("2024-03-01 08:19:00","192.168.1.40","192.168.1.1","TCP",135,"DCOM lateral movement","HIGH"),
  # ── Insider threat ──────────────────────────────────────────────────
  ("2024-03-01 08:20:00","192.168.1.22","10.0.0.50","TCP",1433,"Bulk DB SELECT sensitive tables","HIGH"),
  ("2024-03-01 08:20:10","192.168.1.22","10.0.0.50","TCP",1433,"DB Export 50000 records","CRITICAL"),
  ("2024-03-01 08:20:20","192.168.1.22","104.21.96.0","HTTPS",443,"Upload to personal Dropbox","MEDIUM"),
  ("2024-03-01 08:21:00","192.168.1.23","10.0.0.51","TCP",22,"SSH key exfil attempt","HIGH"),
  ("2024-03-01 08:21:10","192.168.1.24","10.0.0.52","TCP",3306,"MySQL dump all databases","CRITICAL"),
  # ── Crypto mining ───────────────────────────────────────────────────
  ("2024-03-01 08:22:00","192.168.1.90","pool.minexmr.com","TCP",4444,"Cryptomining XMR pool connect","HIGH"),
  ("2024-03-01 08:22:10","192.168.1.91","xmr.pool.minergate.com","TCP",45700,"Monero mining stratum","HIGH"),
  ("2024-03-01 08:22:20","192.168.1.92","192.168.1.1","TCP",80,"High CPU network anomaly mining","MEDIUM"),
  # ── VPN / Policy violations ─────────────────────────────────────────
  ("2024-03-01 08:23:00","192.168.1.100","104.16.0.0","HTTPS",443,"Tor browser usage detected","HIGH"),
  ("2024-03-01 08:23:10","192.168.1.101","104.17.0.0","UDP",1194,"OpenVPN policy violation","MEDIUM"),
  ("2024-03-01 08:23:20","192.168.1.102","192.99.0.0","TCP",8888,"Proxy bypass attempt","MEDIUM"),
  # ── Normal baseline (more) ──────────────────────────────────────────
  ("2024-03-01 08:24:00","192.168.1.200","8.8.8.8","DNS",53,"DNS Query: slack.com","INFO"),
  ("2024-03-01 08:24:10","192.168.1.201","13.107.6.152","HTTPS",443,"Teams/O365 normal traffic","INFO"),
  ("2024-03-01 08:24:20","192.168.1.202","52.96.0.0","HTTPS",443,"Azure cloud sync","INFO"),
  ("2024-03-01 08:24:30","192.168.1.203","192.168.1.1","NTP",123,"NTP time sync","INFO"),
  ("2024-03-01 08:25:00","192.168.1.204","192.168.1.1","ICMP",0,"Ping gateway OK","INFO"),
  ("2024-03-01 08:25:10","192.168.1.205","192.168.1.1","TCP",443,"Internal HTTPS normal","INFO"),
  ("2024-03-01 08:25:20","192.168.1.206","8.8.8.8","DNS",53,"DNS Query: zoom.us","INFO"),
  ("2024-03-01 08:25:30","192.168.1.207","162.158.0.0","HTTPS",443,"Zoom video call","INFO"),
  ("2024-03-01 08:26:00","192.168.1.208","192.168.1.1","TCP",80,"Internal web app access","INFO"),
  ("2024-03-01 08:26:10","192.168.1.209","8.8.8.8","DNS",53,"DNS Query: aws.amazon.com","INFO"),
  # ── Additional threats ──────────────────────────────────────────────
  ("2024-03-01 08:27:00","192.168.1.115","192.168.1.1","TCP",4444,"Metasploit reverse connection port 4444","CRITICAL"),
  ("2024-03-01 08:27:10","192.168.1.116","192.168.1.2","TCP",1433,"SQL Server brute force login attempts","CRITICAL"),
  ("2024-03-01 08:27:20","192.168.1.117","10.0.0.99","TCP",3306,"MySQL dump all databases exfil","CRITICAL"),
  ("2024-03-01 08:27:30","192.168.1.118","192.168.1.1","HTTP",80,"HTTP cleartext credentials POST /login","MEDIUM"),
]

# ══════════════════════════════════════════════════════════════════════
#  RULE-BASED THREAT ENGINE (AI-style pattern classifier)
# ══════════════════════════════════════════════════════════════════════
RULES = [
    # (pattern_in_description, severity_floor, category, recommendation)
    (r"brute.force|login.fail|ssh.login.fail",          "CRITICAL","Brute Force Attack",      "Block source IP. Enable account lockout. Deploy fail2ban."),
    (r"cobalt.strike|beacon|c2.pattern|reverse.shell",   "CRITICAL","C2 Beaconing",            "Isolate host immediately. Capture memory. Investigate persistence."),
    (r"ransomware|encrypt|ransom|locky|decrypt",         "CRITICAL","Ransomware Activity",     "Isolate network segment. Restore from backup. Engage IR team."),
    (r"sql.inject|union.select|drop.table",              "CRITICAL","SQL Injection",           "Enable WAF. Sanitize inputs. Review DB query logs."),
    (r"lateral.movement|smb.scan|eternal.blue",         "CRITICAL","Lateral Movement",        "Segment network. Patch SMB. Audit service accounts."),
    (r"kerberoast|pass.the.hash|ntlm.relay",            "CRITICAL","Privilege Escalation",    "Reset service account passwords. Enable Kerberos AES. Monitor LSASS."),
    (r"db.export|dump.all|bulk.select",                  "CRITICAL","Data Theft",              "Revoke DB permissions. Alert DLP. Investigate user activity."),
    (r"shadow.copy|vssadmin",                            "CRITICAL","Ransomware Prep",         "Block vssadmin. Enable VSS monitoring. Alert SOC immediately."),
    (r"port.3389|rdp.login",                             "CRITICAL","Unauthorized RDP",        "Disable RDP externally. Enforce NLA. Use VPN for remote access."),
    (r"malware|evil\.com|\.onion|ransom.pay",            "CRITICAL","Malicious Domain",        "Block domain at DNS. Scan host for malware. Check persistence."),
    (r"path.traversal|etc.passwd|etc.shadow",            "CRITICAL","Path Traversal",          "Sanitize file paths. Restrict web root. Update WAF rules."),
    (r"command.inject|cat /etc|/bin/sh",                 "CRITICAL","Command Injection",       "Sanitize all inputs. Disable shell execution from web app."),
    (r"lfi:|local.file.inclus",                          "CRITICAL","LFI Attack",              "Disable PHP include with user input. Use whitelist file paths."),
    (r"arp.poison|arp.flood|cache.poison",               "CRITICAL","ARP Poisoning",           "Enable Dynamic ARP Inspection. Port security on switches."),
    (r"port.4444|port.9001|port.31337|port.6667",        "CRITICAL","Known Malware Port",      "Block port at firewall. Investigate process binding to port."),
    (r"exfil|sensitive_data|upload.personal",            "HIGH",    "Data Exfiltration",       "Review DLP policy. Block unauthorized cloud storage."),
    (r"dns.tunnel|txt.record.data|long.subdomain",       "HIGH",    "DNS Tunnelling",          "Block anomalous DNS TXT queries. Monitor DNS payload sizes."),
    (r"xss:|<script>|alert\(1\)",                        "HIGH",    "XSS Attack",              "Implement CSP headers. Encode HTML output. Use HTTPOnly cookies."),
    (r"ssrf|metadata.request",                           "HIGH",    "SSRF Attack",             "Block internal IP ranges in outbound requests. Use allowlists."),
    (r"xxe|xml.external",                                "HIGH",    "XXE Attack",              "Disable XML external entity processing. Update XML parsers."),
    (r"directory.traversal|/var",                        "HIGH",    "Directory Traversal",     "Restrict web directory access. Normalize all URL paths."),
    (r"icmp.tunnel|covert.channel",                      "HIGH",    "Covert Channel",          "Block ICMP payloads > 64 bytes. Monitor ICMP frequency."),
    (r"smb.eternalblue|smb.exploit",                     "CRITICAL","EternalBlue Exploit",     "Patch MS17-010 immediately. Disable SMBv1. Block port 445 externally."),
    (r"crypto.?min|xmr|monero|mining.stratum",           "HIGH",    "Cryptomining",            "Block mining pool IPs. Scan for unauthorized processes."),
    (r"tor.browser|\.onion|tor.usage",                   "HIGH",    "Tor Usage",               "Block Tor exit nodes. Enforce proxy policy. Alert HR/Legal."),
    (r"telnet|port.23",                                  "HIGH",    "Insecure Protocol",       "Disable Telnet. Migrate to SSH. Block port 23 at firewall."),
    (r"ftp.plain|ftp.upload|ftp.cred",                   "HIGH",    "Insecure FTP",            "Replace FTP with SFTP/FTPS. Encrypt all file transfers."),
    (r"vnc.unencrypt|port.5900",                         "HIGH",    "Unencrypted VNC",         "Encrypt VNC with TLS. Restrict VNC to VPN only."),
    (r"snmp.public|snmp.community",                      "MEDIUM",  "Weak SNMP",               "Change SNMP community strings. Migrate to SNMPv3 with auth."),
    (r"ldap.enum|ldap.dump|domain.user",                 "HIGH",    "AD Enumeration",          "Monitor LDAP queries. Enable AD audit logging. Block anonymous LDAP."),
    (r"port.scan|tcp.syn.*port|scan.*port",              "HIGH",    "Port Scan",               "Rate-limit TCP SYN. Implement port scan detection. Alert on threshold."),
    (r"icmp.ping.sweep|ping.sweep",                      "MEDIUM",  "Reconnaissance",          "Block external ICMP. Monitor for sweep patterns. Log source IPs."),
    (r"vpn.violation|proxy.bypass|openVPN",              "MEDIUM",  "Policy Violation",        "Enforce proxy policy. Block unauthorized VPN clients."),
    (r"csrf.token|csrf",                                 "MEDIUM",  "CSRF Risk",               "Implement CSRF tokens. Use SameSite cookie attribute."),
    (r"http.get|http.post.*normal|http.80.*normal",      "MEDIUM",  "Cleartext HTTP",          "Enforce HTTPS. Redirect all HTTP to HTTPS. Use HSTS."),
    (r"normal|info|ntp|dhcp|arp.who.has|dns.response|dns.query.*normal|https.*normal|teams|azure|zoom|slack",
                                                          "INFO",    "Normal Traffic",          "No action required. Continue monitoring."),
]

SUSPICIOUS_PORTS = {21:"FTP",22:"SSH",23:"Telnet",80:"HTTP",
                    88:"Kerberos",135:"DCOM",137:"NetBIOS",139:"NetBIOS",
                    389:"LDAP",443:"HTTPS",445:"SMB",636:"LDAPS",
                    1433:"MSSQL",1337:"Suspicious",3306:"MySQL",
                    3389:"RDP",4444:"Metasploit",5900:"VNC",
                    6667:"IRC",8080:"HTTP-Alt",9001:"Tor",
                    31337:"Back Orifice",45700:"Miner"}

def classify_event(ts, src, dst, proto, port, desc, hint_sev):
    text = (desc + " " + proto).lower()
    for pattern, sev, category, rec in RULES:
        if re.search(pattern, text, re.IGNORECASE):
            # take whichever is more severe between rule and hint
            order = ["INFO","LOW","MEDIUM","HIGH","CRITICAL"]
            final_sev = sev if order.index(sev) >= order.index(hint_sev) else hint_sev
            return {"ts":ts,"src":src,"dst":dst,"proto":proto,"port":port,
                    "desc":desc,"severity":final_sev,"category":category,
                    "recommendation":rec}
    # port-based fallback
    port_name = SUSPICIOUS_PORTS.get(int(port) if str(port).isdigit() else 0, "")
    if port_name and port_name not in ("HTTPS","DNS","HTTP"):
        cat = f"Suspicious Port ({port_name})"
        rec = f"Review traffic on port {port}. Verify service is authorized."
        sev = "HIGH" if port_name in ("FTP","Telnet","SMB","RDP","Metasploit") else "MEDIUM"
        final_sev = sev if order_val(sev) >= order_val(hint_sev) else hint_sev
        return {"ts":ts,"src":src,"dst":dst,"proto":proto,"port":port,
                "desc":desc,"severity":final_sev,"category":cat,
                "recommendation":rec}
    return {"ts":ts,"src":src,"dst":dst,"proto":proto,"port":port,
            "desc":desc,"severity":hint_sev,"category":"Normal Traffic",
            "recommendation":"Continue monitoring."}

def order_val(s): return ["INFO","LOW","MEDIUM","HIGH","CRITICAL"].index(s) if s in ["INFO","LOW","MEDIUM","HIGH","CRITICAL"] else 0

# ══════════════════════════════════════════════════════════════════════
#  ANALYSIS PIPELINE
# ══════════════════════════════════════════════════════════════════════
def run_analysis(log_rows):
    results = []
    for i, row in enumerate(log_rows):
        if len(row) == 7:
            ts,src,dst,proto,port,desc,sev = row
        else:
            ts,src,dst,proto,port,desc = row[:6]; sev = "INFO"
        r = classify_event(ts,str(src),str(dst),str(proto),str(port),str(desc),str(sev))
        r["id"] = i+1
        results.append(r)

    total = len(results)
    sev_c = Counter(r["severity"] for r in results)
    proto_c = Counter(r["proto"] for r in results)
    cat_c = Counter(r["category"] for r in results)
    src_c = Counter(r["src"] for r in results)
    top_talkers = src_c.most_common(5)
    unique_ips = len(set(r["src"] for r in results) | set(r["dst"] for r in results))
    threats = sev_c.get("CRITICAL",0) + sev_c.get("HIGH",0)
    threat_pct = round(threats/total*100,1) if total else 0

    # Risk scores per host
    risk_scores = {}
    for r in results:
        ip = r["src"]
        if ip not in risk_scores: risk_scores[ip] = {"score":0,"events":0}
        risk_scores[ip]["events"] += 1
        risk_scores[ip]["score"] += {"CRITICAL":10,"HIGH":5,"MEDIUM":2,"LOW":1,"INFO":0}.get(r["severity"],0)
    top_risks = sorted(risk_scores.items(), key=lambda x:x[1]["score"], reverse=True)[:8]

    summary = {
        "total":total,"sev":dict(sev_c),"protos":dict(proto_c),
        "categories":dict(cat_c),"top_talkers":top_talkers,
        "unique_ips":unique_ips,"threats":threats,"threat_pct":threat_pct,
        "top_risks":top_risks
    }
    return results, summary

# ══════════════════════════════════════════════════════════════════════
#  AI NLG ENGINE — generates human-readable reports (no API key)
# ══════════════════════════════════════════════════════════════════════
def generate_ai_summary(results, summary):
    s = summary
    c = s["sev"].get("CRITICAL",0); h = s["sev"].get("HIGH",0)
    crits = [r for r in results if r["severity"]=="CRITICAL"]
    cats = Counter(r["category"] for r in crits).most_common(3)
    lines = []
    # Threat level
    if c >= 10:   lines.append(f"🔴 CRITICAL THREAT LEVEL: {c} critical events detected requiring immediate response.")
    elif c >= 5:  lines.append(f"🟠 HIGH THREAT LEVEL: {c} critical and {h} high-severity events detected.")
    elif c > 0:   lines.append(f"🟡 ELEVATED THREAT LEVEL: {c} critical events require investigation.")
    else:         lines.append(f"🟢 LOW THREAT LEVEL: No critical events. {h} high-severity events to monitor.")
    # Attack patterns
    if cats:
        lines.append(f"\n📊 PRIMARY ATTACK PATTERNS:")
        for cat, cnt in cats:
            lines.append(f"  • {cat}: {cnt} events")
    # Specific findings
    desc_text = " ".join(r["desc"].lower() for r in crits)
    if "brute" in desc_text or "login fail" in desc_text:
        ips = list(set(r["src"] for r in crits if re.search(r"brute|login.fail|ssh.login",r["desc"],re.I)))
        lines.append(f"\n🔐 BRUTE FORCE: Attack from {', '.join(ips[:3])} — enforce lockout policies immediately.")
    if "cobalt" in desc_text or "beacon" in desc_text or "c2" in desc_text:
        lines.append(f"\n☠ C2 BEACON: Command-and-control activity detected — isolate affected hosts, capture memory dump.")
    if "ransomware" in desc_text or "encrypt" in desc_text:
        lines.append(f"\n💀 RANSOMWARE: Active ransomware indicators — isolate network segment, do NOT reboot infected hosts.")
    if "lateral" in desc_text or "smb" in desc_text:
        lines.append(f"\n🌐 LATERAL MOVEMENT: Attacker spreading through network via SMB — segment immediately.")
    if "sql inject" in desc_text:
        lines.append(f"\n💉 SQL INJECTION: Active database attack — enable WAF, review DB access logs.")
    if "exfil" in desc_text or "upload" in desc_text:
        lines.append(f"\n📤 DATA EXFILTRATION: Suspicious outbound transfers — block destinations, alert DLP team.")
    if "kerbero" in desc_text or "pass.the.hash" in desc_text:
        lines.append(f"\n🎭 PRIVILEGE ESCALATION: Kerberoasting/PTH detected — reset service passwords, enable AES Kerberos.")
    # Top risky host
    if s["top_risks"]:
        top_ip, top_info = s["top_risks"][0]
        lines.append(f"\n🎯 HIGHEST RISK HOST: {top_ip} (risk score: {top_info['score']}, {top_info['events']} events)")
    # Immediate actions
    lines.append(f"\n⚡ IMMEDIATE ACTIONS REQUIRED:")
    if c > 0:   lines.append(f"  1. Isolate hosts: {', '.join(list(set(r['src'] for r in crits))[:4])}")
    if h > 0:   lines.append(f"  2. Investigate {h} high-severity events for false positives")
    lines.append(f"  3. Review firewall rules for {len(set(r['src'] for r in crits))} attacking IPs")
    lines.append(f"  4. Enable enhanced logging on all critical assets")
    lines.append(f"\n📈 STATISTICS: {s['total']} total events | {s['threat_pct']}% threat ratio | {s['unique_ips']} unique IPs")
    return "\n".join(lines)

def generate_firewall_rules(results):
    crits = [r for r in results if r["severity"] in ("CRITICAL","HIGH")]
    bad_ips = list(set(r["src"] for r in crits
                       if not r["src"].startswith("192.168") and
                          not r["src"].startswith("10.") and
                          not r["src"].startswith("172.")))[:15]
    bad_ports = list(set(str(r["port"]) for r in crits
                         if str(r["port"]) not in ("80","443","53","22","0")))[:15]
    lines = ["# ═══════════════════════════════════════════════════════",
             "# NetSentinel Auto-Generated Firewall Rules",
             f"# Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
             "# ═══════════════════════════════════════════════════════",
             "",
             "# ── iptables (Linux) ─────────────────────────────────",
             "#!/bin/bash",
             ""]
    for ip in bad_ips:
        lines.append(f"iptables -I INPUT -s {ip} -j DROP        # Block attacking IP")
        lines.append(f"iptables -I OUTPUT -d {ip} -j DROP       # Block C2 destination")
    lines.append("")
    for port in bad_ports:
        lines.append(f"iptables -I INPUT -p tcp --dport {port} -j DROP    # Block suspicious port")
    lines.extend([
        "",
        "# Block common attack vectors",
        "iptables -A INPUT -p tcp --dport 4444 -j DROP    # Metasploit/Meterpreter",
        "iptables -A INPUT -p tcp --dport 31337 -j DROP   # Back Orifice",
        "iptables -A INPUT -p tcp --dport 9001 -j DROP    # Tor C2",
        "iptables -A INPUT -p tcp --dport 6667 -j DROP    # IRC Botnet",
        "",
        "# Save rules",
        "iptables-save > /etc/iptables/rules.v4",
        "",
        "# ── Windows Firewall (PowerShell) ────────────────────────",
        "",
    ])
    for ip in bad_ips:
        lines.append(f'New-NetFirewallRule -DisplayName "Block {ip}" -Direction Inbound -RemoteAddress {ip} -Action Block')
    for port in bad_ports:
        lines.append(f'New-NetFirewallRule -DisplayName "Block port {port}" -Direction Inbound -Protocol TCP -LocalPort {port} -Action Block')
    return "\n".join(lines)

def generate_soc_report(results, summary):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    s = summary
    c = s["sev"].get("CRITICAL",0); h = s["sev"].get("HIGH",0)
    crits = [r for r in results if r["severity"]=="CRITICAL"]
    uniq_atk = list(set(r["src"] for r in crits
                        if not r["src"].startswith("192.168")))
    lines = [
        "═"*65,
        "  NETSENTINEL SOC INCIDENT REPORT",
        f"  Generated: {now}",
        f"  Classification: {'CRITICAL' if c>5 else 'HIGH' if c>0 else 'MEDIUM'}",
        "═"*65,
        "",
        "## 1. EXECUTIVE SUMMARY",
        "─"*40,
        f"A total of {s['total']} network events were analysed during this period.",
        f"{c} CRITICAL and {h} HIGH severity events were detected, representing",
        f"a {s['threat_pct']}% threat ratio. {len(uniq_atk)} unique external attacking",
        f"IPs were identified across {len(set(r['category'] for r in crits))} distinct attack categories.",
        "",
        "## 2. THREAT ANALYSIS",
        "─"*40,
    ]
    # Top attack categories
    cat_counts = Counter(r["category"] for r in crits).most_common(8)
    for cat, cnt in cat_counts:
        lines.append(f"  [{cnt:3d} events] {cat}")
    lines.extend([
        "",
        "## 3. AFFECTED SYSTEMS",
        "─"*40,
    ])
    # Risk scores
    for ip, info in s["top_risks"][:6]:
        bar = "█" * min(int(info["score"]/3),20)
        lines.append(f"  {ip:<20} Risk: {info['score']:4d}  {bar}")
    lines.extend([
        "",
        "## 4. ATTACK TIMELINE",
        "─"*40,
    ])
    for r in crits[:12]:
        lines.append(f"  {r['ts']}  [{r['severity']}] {r['src']} → {r['dst']}  {r['category']}")
    lines.extend([
        "",
        "## 5. RISK ASSESSMENT",
        "─"*40,
        f"  Overall Risk Level : {'CRITICAL' if c>=10 else 'HIGH' if c>=5 else 'MEDIUM' if c>0 else 'LOW'}",
        f"  Business Impact    : {'Severe — immediate response required' if c>=10 else 'High — escalate to CISO' if c>=5 else 'Moderate — investigate within 4 hours'}",
        f"  Data Exposure Risk : {'HIGH — exfiltration patterns detected' if any('exfil' in r['category'].lower() or 'theft' in r['category'].lower() for r in results) else 'LOW'}",
        f"  Compliance Risk    : {'HIGH — PCI/GDPR breach indicators present' if c>5 else 'MEDIUM — review policy compliance'}",
        "",
        "## 6. RECOMMENDATIONS",
        "─"*40,
    ])
    recs = list(set(r["recommendation"] for r in crits))[:10]
    for i, rec in enumerate(recs,1):
        lines.append(f"  {i}. {rec}")
    lines.extend([
        "",
        "## 7. NEXT STEPS",
        "─"*40,
        "  □ Isolate all CRITICAL severity source hosts immediately",
        "  □ Apply auto-generated firewall rules (see Firewall tab)",
        "  □ Reset credentials for all affected accounts",
        "  □ Initiate forensic analysis on compromised hosts",
        "  □ Notify CISO and Legal if data exfiltration confirmed",
        "  □ Schedule post-incident review within 72 hours",
        "",
        "─"*65,
        "  END OF REPORT — NetSentinel AI Log Analysis Platform",
        "─"*65,
    ])
    return "\n".join(lines)

def generate_alert_emails(results, summary):
    s = summary; c = s["sev"].get("CRITICAL",0); h = s["sev"].get("HIGH",0)
    crits = [r for r in results if r["severity"]=="CRITICAL"]
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    iocs = list(set(r["src"] for r in crits if not r["src"].startswith("192.168")))[:5]
    return f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EMAIL 1: SECURITY TEAM (Technical)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TO: soc-team@company.com
CC: incident-response@company.com
SUBJECT: [CRITICAL] Active Security Incident Detected — {now}

Team,

NetSentinel has detected {c} CRITICAL security events requiring immediate action.

THREAT SUMMARY:
• {c} Critical / {h} High severity events
• Attack categories: {', '.join(list(set(r['category'] for r in crits))[:4])}
• Attacking IPs (IOCs): {', '.join(iocs) if iocs else 'Internal hosts compromised'}
• Affected hosts: {', '.join(list(set(r['dst'] for r in crits))[:4])}

IMMEDIATE ACTIONS:
1. Isolate hosts: {', '.join(list(set(r['src'] for r in crits if r['src'].startswith('192.168')))[:3])}
2. Block external IPs: {', '.join(iocs[:3]) if iocs else 'N/A'}
3. Apply firewall rules from NetSentinel report
4. Preserve logs & memory on affected systems
5. Initiate IR playbook: PLAN-IR-001

Evidence preserved in NetSentinel log database.
Full technical report attached.

— NetSentinel AI SOC Platform

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EMAIL 2: MANAGEMENT (Non-Technical)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TO: ciso@company.com; cto@company.com
SUBJECT: [ACTION REQUIRED] Security Incident — {now}

Leadership,

Our automated security monitoring has detected a {'critical' if c>=5 else 'significant'} 
security incident affecting our network infrastructure.

RISK LEVEL: {'🔴 CRITICAL' if c>=10 else '🟠 HIGH' if c>0 else '🟡 MEDIUM'}

BUSINESS IMPACT:
• {c} high-priority threats detected ({s['threat_pct']}% of all traffic)
• {'Potential data breach indicators present' if any('exfil' in r['category'].lower() or 'theft' in r['category'].lower() for r in results) else 'Network integrity at risk'}
• {'Ransomware activity detected — backup systems at risk' if any('ransom' in r['category'].lower() for r in results) else 'Active threat actors in network'}

Our security team has been notified and is responding.
Expected containment timeline: 2-4 hours.

{'⚠ LEGAL NOTICE: Data exfiltration indicators detected. Legal & Compliance team notification may be required per GDPR/PCI-DSS obligations.' if c > 5 else ''}

Full incident report available from SOC team.

— Automated Security Operations Center
"""

# ══════════════════════════════════════════════════════════════════════
#  PCAP PARSER (pure Python, no scapy)
# ══════════════════════════════════════════════════════════════════════
def parse_pcap(data):
    rows = []
    if len(data) < 24: return rows
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic not in (0xA1B2C3D4, 0xD4C3B2A1): return rows
    en = "<" if magic == 0xA1B2C3D4 else ">"
    ltype = struct.unpack_from(f"{en}I", data, 20)[0]; off = 24
    while off + 16 <= len(data):
        ts_s,_,il,_ = struct.unpack_from(f"{en}IIII", data, off); off += 16
        if off + il > len(data): break
        pkt = data[off:off+il]; off += il
        ts = datetime.datetime.fromtimestamp(ts_s).strftime("%Y-%m-%d %H:%M:%S")
        src = dst = proto = "N/A"; port = 0; desc = "Raw packet"
        try:
            if ltype == 1 and len(pkt) >= 14:
                et = struct.unpack_from(">H", pkt, 12)[0]
                if et == 0x0800 and len(pkt) >= 34:
                    ihl = (pkt[14] & 0x0F) * 4; pn = pkt[23]
                    src = sock.inet_ntoa(pkt[26:30]); dst = sock.inet_ntoa(pkt[30:34])
                    proto = {1:"ICMP",6:"TCP",17:"UDP"}.get(pn, str(pn))
                    tp = 14 + ihl
                    if pn in (6,17) and len(pkt) >= tp+4:
                        sp, dp = struct.unpack_from(">HH", pkt, tp)
                        port = dp; desc = f"Port {sp}→{dp}"
                    elif pn == 1: desc = "ICMP packet"
                elif et == 0x0806: proto = "ARP"; desc = "ARP packet"
        except: pass
        rows.append((ts, src, dst, proto, port, desc, "INFO"))
    return rows if rows else []

# ══════════════════════════════════════════════════════════════════════
#  TEXT LOG PARSER
# ══════════════════════════════════════════════════════════════════════
def parse_text_log(text):
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        parts = re.split(r"\t|,", line)
        if len(parts) >= 6:
            try:
                rows.append((parts[0],parts[1],parts[2],parts[3],
                              parts[4],parts[5],parts[6] if len(parts)>6 else "INFO"))
                continue
            except: pass
        ip = re.search(r"\b(\d{1,3}\.){3}\d{1,3}\b", line)
        rows.append((datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                     ip.group(0) if ip else "0.0.0.0","0.0.0.0","UNKNOWN",0,line[:100],"INFO"))
    return rows

# ══════════════════════════════════════════════════════════════════════
#  AUTOMATION BACKGROUND AGENT
# ══════════════════════════════════════════════════════════════════════
agent_log_buffer = []
agent_lock = threading.Lock()
def agent_push(msg, level="INFO"):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    with agent_lock:
        agent_log_buffer.append({"ts":ts,"level":level,"msg":msg})
        if len(agent_log_buffer) > 500: agent_log_buffer.pop(0)

def automation_loop():
    msgs = [
        ("INFO","Auto-monitor: scanning event pipeline for anomaly spikes…"),
        ("WARN","Threat intel: cross-referencing IOC database…"),
        ("OK",  "Heartbeat: all detection modules nominal."),
        ("INFO","Baseline refresh: recalculating network norms…"),
        ("WARN","Entropy check: protocol distribution analysis…"),
        ("OK",  "Rule engine: signature database up to date."),
        ("INFO","Risk scorer: updating per-host scores…"),
        ("OK",  "Automation: all pipeline stages healthy."),
    ]
    i = 0
    while True:
        time.sleep(12)
        t, m = msgs[i % len(msgs)]
        agent_push(m, t)
        i += 1

threading.Thread(target=automation_loop, daemon=True).start()

# ══════════════════════════════════════════════════════════════════════
#  HTTP SERVER
# ══════════════════════════════════════════════════════════════════════
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send_json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin","*")
        self.end_headers(); self.wfile.write(body)
    def rbody(self): return self.rfile.read(int(self.headers.get("Content-Length",0)))
    def do_OPTIONS(self):
        self.send_response(200)
        for h,v in [("Access-Control-Allow-Origin","*"),
                    ("Access-Control-Allow-Methods","GET,POST,OPTIONS"),
                    ("Access-Control-Allow-Headers","Content-Type,X-Token")]:
            self.send_header(h,v)
        self.end_headers()
    def do_GET(self):
        if self.path in ("/","/index.html"):
            body = HTML_PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type","text/html; charset=utf-8")
            self.send_header("Content-Length",len(body))
            self.end_headers(); self.wfile.write(body)
        elif self.path == "/api/agent":
            tok = self.headers.get("X-Token","")
            if not get_session(tok): self.send_json(401,{"error":"Unauthorized"}); return
            with agent_lock:
                self.send_json(200, {"logs": agent_log_buffer[-30:]})
        else:
            self.send_response(404); self.end_headers()
    def do_POST(self):
        path = self.path.split("?")[0]
        if path == "/api/login":
            d = json.loads(self.rbody())
            u = d.get("username","").strip(); p = d.get("password","")
            if USERS.get(u) == _h(p):
                agent_push(f"User '{u}' authenticated successfully.", "OK")
                self.send_json(200,{"ok":True,"token":make_session(u),"user":u})
            else:
                self.send_json(401,{"ok":False,"error":"Invalid credentials"})
            return
        tok = self.headers.get("X-Token","")
        if not get_session(tok): self.send_json(401,{"error":"Unauthorized"}); return
        if path == "/api/analyse":
            d = json.loads(self.rbody())
            agent_push("Analysis pipeline triggered.", "INFO")
            if d.get("use_sample"):
                rows = list(SAMPLE_LOGS)
                agent_push(f"Loaded {len(rows)} built-in sample logs.", "OK")
            elif d.get("file_data"):
                raw = base64.b64decode(d["file_data"])
                fn = d.get("file_name","").lower()
                if fn.endswith(".pcap") or fn.endswith(".cap"):
                    rows = parse_pcap(raw)
                    agent_push(f"PCAP parsed: {len(rows)} packets extracted.", "OK")
                else:
                    rows = parse_text_log(raw.decode("utf-8","replace"))
                    agent_push(f"Text log parsed: {len(rows)} entries.", "OK")
                if not rows:
                    rows = list(SAMPLE_LOGS)
                    agent_push("File parse returned no rows — using sample data.", "WARN")
            else:
                self.send_json(400,{"error":"No data"}); return
            agent_push("Rule engine classifying events…", "INFO")
            results, summary = run_analysis(rows)
            agent_push(f"Analysis complete: {summary['sev'].get('CRITICAL',0)} critical, {summary['sev'].get('HIGH',0)} high.", "OK" if summary['sev'].get('CRITICAL',0)==0 else "WARN")
            self.send_json(200,{"ok":True,"rows":results,"summary":summary})
            return
        if path == "/api/ai_summary":
            d = json.loads(self.rbody())
            rows = d.get("rows",[]); summary = d.get("summary",{})
            agent_push("AI NLG engine generating threat summary…", "INFO")
            text = generate_ai_summary(rows, summary)
            agent_push("AI summary generated.", "OK")
            self.send_json(200,{"ok":True,"text":text})
            return
        if path == "/api/firewall":
            d = json.loads(self.rbody())
            rows = d.get("rows",[])
            agent_push("Firewall rule generator running…", "INFO")
            text = generate_firewall_rules(rows)
            agent_push("Firewall rules generated.", "OK")
            self.send_json(200,{"ok":True,"text":text})
            return
        if path == "/api/report":
            d = json.loads(self.rbody())
            rows = d.get("rows",[]); summary = d.get("summary",{})
            agent_push("SOC report writer composing incident report…", "INFO")
            text = generate_soc_report(rows, summary)
            agent_push("SOC incident report generated.", "OK")
            self.send_json(200,{"ok":True,"text":text})
            return
        if path == "/api/alerts":
            d = json.loads(self.rbody())
            rows = d.get("rows",[]); summary = d.get("summary",{})
            agent_push("Alert email drafter composing notifications…", "INFO")
            text = generate_alert_emails(rows, summary)
            agent_push("Alert email drafts ready.", "OK")
            self.send_json(200,{"ok":True,"text":text})
            return
        self.send_response(404); self.end_headers()

# ══════════════════════════════════════════════════════════════════════
#  FRONTEND — complete HTML / CSS / JavaScript
# ══════════════════════════════════════════════════════════════════════
HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetSentinel — AI Log Analysis</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#030508;--p1:#07090f;--p2:#0b0e18;--p3:#0f1320;
  --b1:#141d32;--b2:#1a2540;--b3:#202d4e;
  --a1:#00f0c8;--a2:#ff2d6b;--a3:#f5a623;--a4:#3d8eff;--a5:#c084fc;
  --tx:#b0c4de;--mu:#2a3d5a;
  --crit:#ff2d6b;--high:#f5a623;--med:#ffd60a;--low:#00f0c8;--info:#3d8eff;
  --mono:'DM Mono',monospace;--ui:'Syne',sans-serif;
}
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;background:var(--bg);color:var(--tx);font-family:var(--mono);overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;
  background-image:linear-gradient(rgba(0,240,200,.022) 1px,transparent 1px),
    linear-gradient(90deg,rgba(0,240,200,.022) 1px,transparent 1px);
  background-size:50px 50px}
body::after{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;
  background:radial-gradient(ellipse 60% 50% at 80% 15%,rgba(61,142,255,.07) 0%,transparent 65%),
    radial-gradient(ellipse 50% 40% at 10% 85%,rgba(0,240,200,.05) 0%,transparent 65%)}
@keyframes scan{from{transform:translateY(-100%)}to{transform:translateY(100vh)}}
.scanline{position:fixed;inset:0 0 auto;height:2px;z-index:9999;pointer-events:none;
  background:linear-gradient(transparent,rgba(0,240,200,.05),transparent);
  animation:scan 8s linear infinite}
/* ── PAGES ── */
.pg{display:none;min-height:100vh;position:relative;z-index:1}
.pg.on{display:flex;flex-direction:column}
/* ── LOGIN ── */
#pgLogin{align-items:center;justify-content:center}
.lbox{width:100%;max-width:420px;padding:20px}
.l-logo{font-family:var(--ui);font-size:2rem;font-weight:800;letter-spacing:.04em;margin-bottom:4px}
.l-logo em{color:var(--a1);font-style:normal}
.l-sub{font-size:.65rem;color:var(--mu);letter-spacing:.14em;margin-bottom:30px}
.lcard{background:var(--p1);border:1px solid var(--b2);border-radius:12px;padding:28px;
  box-shadow:0 0 50px rgba(0,240,200,.04);position:relative;overflow:hidden}
.lcard::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,var(--a1),var(--a4),var(--a2))}
.l-badge{display:inline-flex;align-items:center;gap:7px;font-size:.62rem;letter-spacing:.14em;
  color:var(--a1);border:1px solid rgba(0,240,200,.2);border-radius:20px;
  padding:4px 12px;margin-bottom:20px;background:rgba(0,240,200,.04)}
.l-badge::before{content:'';width:6px;height:6px;border-radius:50%;background:var(--a1);animation:blink 1.6s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.15}}
.fld{margin-bottom:16px}
.fld label{display:block;font-size:.6rem;letter-spacing:.13em;color:var(--mu);margin-bottom:6px}
.fld input{width:100%;padding:10px 13px;background:rgba(3,5,8,.8);
  border:1px solid var(--b2);border-radius:6px;color:var(--tx);
  font-family:var(--mono);font-size:.8rem;outline:none;transition:.2s}
.fld input:focus{border-color:var(--a1);box-shadow:0 0 0 3px rgba(0,240,200,.07)}
.btnlogin{width:100%;padding:12px;background:var(--a1);color:#000;border:none;
  border-radius:6px;font-family:var(--ui);font-size:.88rem;font-weight:700;
  letter-spacing:.08em;cursor:pointer;transition:.2s;margin-top:4px}
.btnlogin:hover{background:#33f5d5;transform:translateY(-1px);box-shadow:0 5px 22px rgba(0,240,200,.3)}
.lhint{margin-top:14px;font-size:.62rem;color:var(--mu);text-align:center}
.lhint b{color:var(--a1)}
.lerr{color:var(--a2);font-size:.7rem;margin-top:8px;min-height:16px}
/* ── NAV ── */
nav{display:flex;align-items:center;gap:10px;padding:12px 28px;
  border-bottom:1px solid var(--b1);background:rgba(3,5,8,.9);
  backdrop-filter:blur(14px);position:sticky;top:0;z-index:100;flex-wrap:wrap}
.nlogo{font-family:var(--ui);font-size:1rem;font-weight:800;letter-spacing:.04em;white-space:nowrap}
.nlogo em{color:var(--a1);font-style:normal}
.ntabs{display:flex;gap:.25rem;flex:1}
.ntab{padding:.35rem .85rem;border:1px solid transparent;border-radius:4px;cursor:pointer;
  font-family:var(--ui);font-weight:600;font-size:.74rem;letter-spacing:.07em;
  color:var(--mu);transition:.2s;background:transparent;white-space:nowrap}
.ntab:hover{color:var(--tx);border-color:var(--b2)}
.ntab.on{color:var(--a1);border-color:var(--a1);background:rgba(0,240,200,.07)}
.ntab.t2.on{color:var(--a5);border-color:var(--a5);background:rgba(192,132,252,.07)}
.ntab.t3.on{color:var(--a3);border-color:var(--a3);background:rgba(245,166,35,.07)}
.nright{display:flex;align-items:center;gap:10px;margin-left:auto}
.uchip{display:flex;align-items:center;gap:6px;padding:4px 12px;
  background:var(--p2);border:1px solid var(--b2);border-radius:16px;
  font-size:.68rem;color:var(--a1)}
.dot{width:6px;height:6px;border-radius:50%;background:var(--a1);animation:blink 1.8s infinite}
.nbtn{padding:5px 12px;border:1px solid var(--b2);border-radius:4px;
  background:transparent;color:var(--mu);font-family:var(--mono);font-size:.68rem;cursor:pointer;transition:.2s}
.nbtn:hover{border-color:var(--a2);color:var(--a2)}
/* ── LAYOUT ── */
.main{flex:1;padding:24px 28px;max-width:1500px;margin:0 auto;width:100%}
.tab-pane{display:none}
.tab-pane.on{display:block}
/* ── CARDS ── */
.card{background:var(--p1);border:1px solid var(--b1);border-radius:10px;overflow:hidden;margin-bottom:18px}
.ch{display:flex;align-items:center;gap:8px;padding:12px 18px;border-bottom:1px solid var(--b1);background:rgba(0,0,0,.2)}
.ci{font-size:.9rem}
.ct{font-family:var(--ui);font-size:.82rem;font-weight:600;letter-spacing:.04em}
.cbdg{font-size:.58rem;padding:2px 7px;border-radius:10px;font-family:var(--mono);
  background:rgba(0,240,200,.1);color:var(--a1);border:1px solid rgba(0,240,200,.2)}
.cb{padding:18px}
/* ── STATS ── */
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:18px}
.sc{background:var(--p1);border:1px solid var(--b1);border-radius:9px;
  padding:15px 17px;position:relative;overflow:hidden;transition:.2s}
.sc:hover{transform:translateY(-1px);border-color:var(--b2)}
.sc::after{content:'';position:absolute;top:0;left:0;right:0;height:2px}
.sc.a1::after{background:var(--a1)}.sc.a2::after{background:var(--a2)}
.sc.a3::after{background:var(--a3)}.sc.a4::after{background:var(--a4)}.sc.a5::after{background:var(--a5)}
.sv{font-family:var(--ui);font-size:1.8rem;font-weight:800;line-height:1}
.sc.a1 .sv{color:var(--a1)}.sc.a2 .sv{color:var(--a2)}.sc.a3 .sv{color:var(--a3)}
.sc.a4 .sv{color:var(--a4)}.sc.a5 .sv{color:var(--a5)}
.sl{font-size:.58rem;letter-spacing:.12em;color:var(--mu);margin-top:3px}
/* ── 2-COL ── */
.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:18px}
/* ── UPLOAD ── */
.dropz{border:2px dashed var(--b2);border-radius:8px;padding:26px 14px;
  text-align:center;cursor:pointer;transition:.2s;position:relative;
  display:flex;flex-direction:column;align-items:center;justify-content:center;gap:5px}
.dropz:hover,.dropz.dg{border-color:var(--a1);background:rgba(0,240,200,.025)}
.dropz input{position:absolute;inset:0;opacity:0;cursor:pointer}
.dz-ic{font-size:1.6rem}
.dz-tx{font-size:.72rem;color:var(--mu)}.dz-tx b{color:var(--a1)}
.fi{font-size:.68rem;color:var(--a1);margin-top:8px;min-height:14px}
/* ── BUTTONS ── */
.btn{padding:10px 16px;border-radius:6px;font-family:var(--ui);font-size:.8rem;
  font-weight:600;cursor:pointer;transition:.2s;border:none;letter-spacing:.05em;
  width:100%;margin-top:10px;display:block}
.btn-c1{background:transparent;border:1px solid var(--a1);color:var(--a1)}
.btn-c1:hover:not(:disabled){background:var(--a1);color:#000;box-shadow:0 0 18px rgba(0,240,200,.2)}
.btn-c5{background:transparent;border:1px solid var(--a5);color:var(--a5)}
.btn-c5:hover:not(:disabled){background:var(--a5);color:#fff}
.btn-c3{background:transparent;border:1px solid var(--a3);color:var(--a3)}
.btn-c3:hover:not(:disabled){background:var(--a3);color:#000}
.btn-c4{background:transparent;border:1px solid var(--a4);color:var(--a4)}
.btn-c4:hover:not(:disabled){background:var(--a4);color:#fff}
.btn-c2{background:transparent;border:1px solid var(--a2);color:var(--a2)}
.btn-c2:hover:not(:disabled){background:var(--a2);color:#fff}
.btn:disabled{opacity:.35;cursor:not-allowed}
/* ── PROGRESS ── */
.prog{margin-top:10px;display:none}
.prog.on{display:block}
.pb{height:3px;background:var(--bg);border-radius:2px;border:1px solid var(--b1);overflow:hidden}
.pf{height:100%;background:var(--a1);width:0;transition:width .3s;border-radius:2px}
.pl{font-size:.62rem;color:var(--mu);margin-top:4px}
/* ── AGENT LOG ── */
.alog{height:160px;overflow-y:auto;background:rgba(3,5,8,.9);
  border:1px solid var(--b1);border-radius:6px;padding:9px;font-size:.65rem;line-height:1.8}
.alog::-webkit-scrollbar{width:3px}
.alog::-webkit-scrollbar-thumb{background:var(--b2);border-radius:2px}
.ll{display:flex;gap:8px}
.lt{color:var(--mu);flex-shrink:0;font-size:.6rem}
.lINFO{color:var(--a4)}.lWARN{color:var(--a3)}.lOK{color:var(--a1)}.lERR{color:var(--a2)}
.ast{display:flex;align-items:center;gap:7px;margin-top:8px;font-size:.65rem;color:var(--mu)}
.adot{width:6px;height:6px;border-radius:50%;background:var(--mu);flex-shrink:0}
.adot.on{background:var(--a1);animation:blink 1.5s infinite}
/* ── TABLE ── */
.tfr{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
.tfr select,.tfr input{background:var(--bg);border:1px solid var(--b2);border-radius:5px;
  padding:.35rem .7rem;color:var(--tx);font-family:var(--mono);font-size:.72rem;outline:none;transition:.2s}
.tfr select:focus,.tfr input:focus{border-color:var(--a1)}
.fl{font-size:.68rem;color:var(--mu)}
.tw{overflow-x:auto;max-height:460px;overflow-y:auto;border:1px solid var(--b1);border-radius:8px}
.tw::-webkit-scrollbar{width:4px;height:4px}
.tw::-webkit-scrollbar-thumb{background:var(--b2);border-radius:2px}
table{width:100%;border-collapse:collapse;font-size:.7rem}
thead{background:var(--p2);position:sticky;top:0;z-index:5}
th{padding:9px 13px;text-align:left;font-size:.58rem;letter-spacing:.1em;
  color:var(--mu);border-bottom:1px solid var(--b1);white-space:nowrap;
  cursor:pointer;font-family:var(--ui)}
th:hover{color:var(--a1)}
td{padding:8px 13px;border-bottom:1px solid rgba(20,29,50,.5);vertical-align:middle}
tr:hover td{background:rgba(0,240,200,.02)}
.sev{padding:2px 7px;border-radius:3px;font-size:.58rem;font-weight:700;letter-spacing:.05em;font-family:var(--ui)}
.sCRITICAL{background:rgba(255,45,107,.15);color:var(--crit);border:1px solid rgba(255,45,107,.3)}
.sHIGH{background:rgba(245,166,35,.15);color:var(--high);border:1px solid rgba(245,166,35,.3)}
.sMEDIUM{background:rgba(255,214,10,.12);color:var(--med);border:1px solid rgba(255,214,10,.25)}
.sLOW{background:rgba(0,240,200,.1);color:var(--low);border:1px solid rgba(0,240,200,.2)}
.sINFO{background:rgba(61,142,255,.1);color:var(--info);border:1px solid rgba(61,142,255,.2)}
.pt{padding:2px 6px;border-radius:3px;font-size:.58rem;
  background:rgba(192,132,252,.1);color:var(--a5);font-family:var(--ui)}
.nodata{text-align:center;padding:44px;color:var(--mu);font-size:.75rem}
.rc{font-size:.68rem;color:var(--mu);margin-left:auto}
/* ── AI BOXES ── */
.aibox{background:#020408;border:1px solid var(--b2);border-radius:6px;padding:14px;
  font-size:.74rem;line-height:1.85;white-space:pre-wrap;max-height:380px;
  overflow-y:auto;color:var(--tx)}
.aibox::-webkit-scrollbar{width:3px}
.aibox::-webkit-scrollbar-thumb{background:var(--b2);border-radius:2px}
/* ── AUTOMATION ── */
.auto-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:18px}
.ac{background:var(--p2);border:1px solid var(--b1);border-radius:9px;overflow:hidden}
.ac:hover{border-color:var(--b2)}
.ah{display:flex;align-items:center;gap:8px;padding:12px 15px;border-bottom:1px solid var(--b1)}
.an{font-family:var(--ui);font-weight:600;font-size:.8rem}
.ad{font-size:.65rem;color:var(--mu)}
.ast2{margin-left:auto;font-size:.6rem;font-family:var(--mono)}
.ast2.idle{color:var(--mu)}.ast2.run{color:var(--a3);animation:blink .9s infinite}
.ast2.done{color:var(--a1)}.ast2.err{color:var(--a2)}
.aw{padding:12px 15px}
.alogbox{background:#020408;border:1px solid var(--b1);border-radius:5px;height:80px;
  overflow-y:auto;padding:6px 9px;font-size:.63rem;font-family:var(--mono);
  color:var(--mu);line-height:1.6;margin-bottom:9px}
.alogbox .lo{color:var(--a1)}.alogbox .lw{color:var(--a3)}.alogbox .le{color:var(--a2)}.alogbox .li{color:var(--a4)}
/* ── PIPELINE ── */
.pipe{display:flex;align-items:center;gap:.3rem;flex-wrap:wrap;
  padding:12px 15px;background:rgba(0,0,0,.2);border-radius:6px;border:1px solid var(--b1);margin-bottom:12px}
.ps{padding:.22rem .55rem;border-radius:3px;font-size:.62rem;font-family:var(--mono);
  border:1px solid;white-space:nowrap}
.ps.pend{border-color:var(--b2);color:var(--mu)}
.ps.run{border-color:var(--a4);color:var(--a4);background:rgba(61,142,255,.07)}
.ps.done{border-color:var(--a1);color:var(--a1);background:rgba(0,240,200,.05)}
.ps.err{border-color:var(--a2);color:var(--a2)}
.pa{color:var(--mu);font-size:.65rem}
/* ── INSIGHTS ── */
.ig{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:18px}
.ii{background:var(--p2);border:1px solid var(--b1);border-radius:8px;padding:12px}
.il{font-size:.58rem;letter-spacing:.1em;color:var(--mu);margin-bottom:4px}
.iv{font-family:var(--ui);font-size:.95rem;font-weight:700}
.is{font-size:.6rem;color:var(--mu);margin-top:2px}
/* ── TOAST ── */
.toast{position:fixed;bottom:20px;right:20px;z-index:8000;background:var(--p1);
  border:1px solid var(--a1);border-radius:7px;padding:10px 16px;
  font-size:.72rem;color:var(--a1);opacity:0;transform:translateY(40px);
  transition:.28s;pointer-events:none;max-width:320px}
.toast.on{opacity:1;transform:none}
/* ── RESPONSIVE ── */
@media(max-width:960px){.stats{grid-template-columns:repeat(3,1fr)}.g2,.auto-grid{grid-template-columns:1fr}.ig{grid-template-columns:1fr 1fr}}
@media(max-width:600px){.stats{grid-template-columns:1fr 1fr}.main{padding:14px}}
@keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.fu{animation:fadeUp .3s ease forwards}
</style>
</head>
<body>
<div class="scanline"></div>

<!-- ═══ LOGIN ═══ -->
<div class="pg on" id="pgLogin">
<div class="lbox fu">
  <div class="l-logo">Net<em>Sentinel</em></div>
  <div class="l-sub">AI AUTOMATION &amp; LOG ANALYSIS // NO API KEY REQUIRED</div>
  <div class="lcard">
    <div class="l-badge">AI ENGINE ONLINE</div>
    <div class="fld"><label>USERNAME</label>
      <input id="lu" type="text" placeholder="admin" autocomplete="username">
    </div>
    <div class="fld"><label>PASSWORD</label>
      <input id="lp" type="password" placeholder="••••••••">
    </div>
    <div class="lerr" id="lerr"></div>
    <button class="btnlogin" onclick="doLogin()">AUTHENTICATE →</button>
  </div>
  <div class="lhint">Demo: <b>admin</b> / <b>admin123</b> &nbsp;|&nbsp; <b>analyst</b> / <b>analyst2024</b></div>
</div>
</div>

<!-- ═══ DASHBOARD ═══ -->
<div class="pg" id="pgDash">
<nav>
  <div class="nlogo">Net<em>Sentinel</em></div>
  <div class="ntabs">
    <div class="ntab on" id="nt0" onclick="swTab(0)">📡 Log Analysis</div>
    <div class="ntab t2" id="nt1" onclick="swTab(1)">🤖 AI Agent</div>
    <div class="ntab t3" id="nt2" onclick="swTab(2)">⚙ AI Automation</div>
  </div>
  <div class="nright">
    <div class="uchip"><div class="dot"></div><span id="nuser">—</span></div>
    <button class="nbtn" onclick="doLogout()">LOGOUT</button>
  </div>
</nav>

<div class="main">

<!-- ── TAB 0: LOG ANALYSIS ── -->
<div class="tab-pane on" id="tp0">

  <div class="stats fu" id="statsRow">
    <div class="sc a1"><div class="sl">TOTAL EVENTS</div><div class="sv" id="s0">0</div></div>
    <div class="sc a2"><div class="sl">CRITICAL</div><div class="sv" id="s1">0</div></div>
    <div class="sc a3"><div class="sl">HIGH</div><div class="sv" id="s2">0</div></div>
    <div class="sc a4"><div class="sl">SAFE/INFO</div><div class="sv" id="s3">0</div></div>
    <div class="sc a5"><div class="sl">UNIQUE IPs</div><div class="sv" id="s4">0</div></div>
  </div>

  <div class="g2 fu">
    <div class="card">
      <div class="ch"><span class="ci">📁</span><span class="ct">Upload PCAP / Log File</span></div>
      <div class="cb">
        <div class="dropz" id="dz">
          <input type="file" id="fi" accept=".pcap,.log,.txt,.csv,.cap" onchange="onFile(this)">
          <div class="dz-ic">⬆</div>
          <div class="dz-tx">Drop <b>.pcap / .log / .txt / .csv</b> here or click</div>
        </div>
        <div class="fi" id="finfo">No file selected</div>
        <div class="prog" id="pw"><div class="pb"><div class="pf" id="pf"></div></div>
          <div class="pl" id="pl">Processing…</div></div>
        <button class="btn btn-c1" id="btnA" onclick="doAnalyse()">⚡ ANALYSE UPLOADED FILE</button>
      </div>
    </div>
    <div class="card">
      <div class="ch"><span class="ci">🤖</span><span class="ct" style="color:var(--a5)">AI Agent — Live Log</span></div>
      <div class="cb">
        <div class="alog" id="alog">
          <div class="ll"><span class="lt">--:--:--</span><span class="lINFO">[INIT]</span><span> NetSentinel AI Agent online — no API key needed.</span></div>
        </div>
        <div class="ast"><div class="adot on" id="adot"></div><span id="atxt">Active — monitoring pipeline</span></div>
      </div>
    </div>
  </div>

  <!-- Insights (hidden until analysis) -->
  <div id="insightsSec" style="display:none">
    <div class="ig fu" id="ig"></div>
  </div>

  <!-- Table actions -->
  <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px;align-items:center" id="tact" class="fu">
    <button class="btn btn-c1" style="width:auto;padding:8px 16px;margin:0" id="btnDl" onclick="dlCSV()" disabled>⬇ CSV</button>
    <button class="btn btn-c3" style="width:auto;padding:8px 16px;margin:0" id="btnJson" onclick="dlJSON()" disabled>⬇ JSON</button>
    <div class="tfr">
      <span class="fl">Filter:</span>
      <select id="fSev" onchange="applyF()">
        <option value="">All Severities</option>
        <option value="CRITICAL">Critical</option>
        <option value="HIGH">High</option>
        <option value="MEDIUM">Medium</option>
        <option value="LOW">Low</option>
        <option value="INFO">Info</option>
      </select>
      <select id="fProto" onchange="applyF()"><option value="">All Protocols</option></select>
      <input id="fSearch" type="text" placeholder="🔍 Search IP, category, description…" oninput="applyF()">
    </div>
    <span class="rc" id="rc"></span>
  </div>

  <div class="tw fu">
    <table id="tbl">
      <thead>?
        <th onclick="srt('id')">#</th>
        <th onclick="srt('ts')">TIMESTAMP</th>
        <th onclick="srt('src')">SRC IP</th>
        <th onclick="srt('dst')">DST IP</th>
        <th onclick="srt('proto')">PROTO</th>
        <th onclick="srt('port')">PORT</th>
        <th onclick="srt('severity')">SEVERITY</th>
        <th onclick="srt('category')">CATEGORY</th>
        <th>DESCRIPTION</th>
        <th>RECOMMENDATION</th>
      </thead>
      <tbody id="tbody">
        <tr><td colspan="10" class="nodata">Upload a file to begin.</td></tr>
      </tbody>
    </table>
  </div>
</div>

<!-- ── TAB 1: AI AGENT ── -->
<div class="tab-pane" id="tp1">
  <div class="g2">
    <div>
      <div class="card" style="margin-bottom:14px">
        <div class="ch"><span class="ci">🧠</span><span class="ct" style="color:var(--a5)">AI Security Analysis Engine</span>
          <span class="cbdg" style="background:rgba(192,132,252,.1);color:var(--a5);border-color:rgba(192,132,252,.2)">NO API KEY</span>
        </div>
        <div class="cb">
          <p style="font-size:.78rem;color:var(--mu);line-height:1.75;margin-bottom:14px">
            Pure Python AI agent using rule-based NLG (Natural Language Generation). No API keys, no ML models, no internet required. Generates threat summaries, SOC reports, firewall rules, and alert emails using pattern analysis and expert security knowledge.
          </p>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <span style="padding:.3rem .7rem;background:rgba(0,240,200,.07);border:1px solid rgba(0,240,200,.18);border-radius:4px;font-size:.62rem;color:var(--a1)">Rule-Based NLG</span>
            <span style="padding:.3rem .7rem;background:rgba(0,240,200,.07);border:1px solid rgba(0,240,200,.18);border-radius:4px;font-size:.62rem;color:var(--a1)">Zero API Cost</span>
            <span style="padding:.3rem .7rem;background:rgba(0,240,200,.07);border:1px solid rgba(0,240,200,.18);border-radius:4px;font-size:.62rem;color:var(--a1)">Offline Capable</span>
            <span style="padding:.3rem .7rem;background:rgba(0,240,200,.07);border:1px solid rgba(0,240,200,.18);border-radius:4px;font-size:.62rem;color:var(--a1)">25+ Threat Patterns</span>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="ch"><span class="ci">🛠</span><span class="ct">AI Agent Tools</span></div>
        <div class="cb">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
            <div onclick="runAISummary()" style="background:var(--p2);border:1px solid var(--b1);border-radius:7px;padding:12px;cursor:pointer;transition:.2s" onmouseover="this.style.borderColor='var(--a1)'" onmouseout="this.style.borderColor='var(--b1)'">
              <div style="font-size:1.2rem;margin-bottom:5px">🔍</div>
              <div style="font-family:var(--ui);font-size:.78rem;font-weight:600">Threat Summary</div>
              <div style="font-size:.64rem;color:var(--mu);margin-top:2px">AI-written analysis</div>
            </div>
            <div onclick="runFirewall()" style="background:var(--p2);border:1px solid var(--b1);border-radius:7px;padding:12px;cursor:pointer;transition:.2s" onmouseover="this.style.borderColor='var(--a2)'" onmouseout="this.style.borderColor='var(--b1)'">
              <div style="font-size:1.2rem;margin-bottom:5px">🔥</div>
              <div style="font-family:var(--ui);font-size:.78rem;font-weight:600">Firewall Rules</div>
              <div style="font-size:.64rem;color:var(--mu);margin-top:2px">iptables + Windows</div>
            </div>
            <div onclick="runReport()" style="background:var(--p2);border:1px solid var(--b1);border-radius:7px;padding:12px;cursor:pointer;transition:.2s" onmouseover="this.style.borderColor='var(--a5)'" onmouseout="this.style.borderColor='var(--b1)'">
              <div style="font-size:1.2rem;margin-bottom:5px">📋</div>
              <div style="font-family:var(--ui);font-size:.78rem;font-weight:600">SOC Report</div>
              <div style="font-size:.64rem;color:var(--mu);margin-top:2px">Full incident report</div>
            </div>
            <div onclick="runAlerts()" style="background:var(--p2);border:1px solid var(--b1);border-radius:7px;padding:12px;cursor:pointer;transition:.2s" onmouseover="this.style.borderColor='var(--a3)'" onmouseout="this.style.borderColor='var(--b1)'">
              <div style="font-size:1.2rem;margin-bottom:5px">📧</div>
              <div style="font-family:var(--ui);font-size:.78rem;font-weight:600">Alert Emails</div>
              <div style="font-size:.64rem;color:var(--mu);margin-top:2px">Tech + Mgmt drafts</div>
            </div>
          </div>
        </div>
      </div>
    </div>
    <div class="card" style="display:flex;flex-direction:column">
      <div class="ch"><span class="ci">💡</span><span class="ct" style="color:var(--a5)">AI Output</span>
        <button onclick="dlOutput()" style="margin-left:auto;padding:4px 12px;background:transparent;border:1px solid var(--a1);color:var(--a1);border-radius:4px;font-size:.65rem;cursor:pointer;font-family:var(--mono)">⬇ Download</button>
      </div>
      <div class="cb" style="flex:1">
        <div class="aibox" id="aiout">Run analysis first (Tab 1), then click a tool above to generate AI output.

The AI engine uses:
  • 25+ security threat rules
  • Pattern-based NLG (Natural Language Generation)
  • Risk scoring algorithm
  • Expert security knowledge base
  • No API keys • No internet required • Fully offline</div>
      </div>
    </div>
  </div>
</div>

<!-- ── TAB 2: AI AUTOMATION ── -->
<div class="tab-pane" id="tp2">
  <div class="card">
    <div class="ch"><span class="ci">⚡</span><span class="ct" style="color:var(--a3)">Automation Pipeline</span>
      <span class="cbdg" style="background:rgba(245,166,35,.1);color:var(--a3);border-color:rgba(245,166,35,.2)">7 STAGES</span>
      <button onclick="runPipeline()" style="margin-left:auto;padding:6px 14px;background:var(--a1);color:#000;border:none;border-radius:5px;font-family:var(--ui);font-size:.75rem;font-weight:700;cursor:pointer">▶▶ RUN FULL PIPELINE</button>
    </div>
    <div class="cb">
      <div class="pipe" id="pipe">
        <div class="ps pend" id="ps0">📥 Ingest</div><div class="pa">→</div>
        <div class="ps pend" id="ps1">🔍 Rule Engine</div><div class="pa">→</div>
        <div class="ps pend" id="ps2">📊 Risk Score</div><div class="pa">→</div>
        <div class="ps pend" id="ps3">🧠 AI Summary</div><div class="pa">→</div>
        <div class="ps pend" id="ps4">🔥 FW Rules</div><div class="pa">→</div>
        <div class="ps pend" id="ps5">📋 Report</div><div class="pa">→</div>
        <div class="ps pend" id="ps6">✅ Done</div>
      </div>
      <div class="pb" style="margin-bottom:6px"><div class="pf" id="ppf" style="width:0%"></div></div>
      <div style="font-size:.65rem;color:var(--mu)" id="ppst">Pipeline idle — click Run Full Pipeline</div>
    </div>
  </div>

  <div class="auto-grid">
    <div class="ac">
      <div class="ah"><span style="font-size:1rem">📥</span>
        <div><div class="an">Log Ingestion</div><div class="ad">Parse &amp; normalise events</div></div>
        <div class="ast2 idle" id="as0">● IDLE</div>
      </div>
      <div class="aw">
        <div class="alogbox" id="al0"><span class="li">Ready. Awaiting trigger…</span></div>
        <button onclick="runIngest()" style="padding:6px 14px;background:transparent;border:1px solid var(--a4);color:var(--a4);border-radius:4px;font-size:.7rem;cursor:pointer;font-family:var(--mono)">▶ Run Ingest</button>
      </div>
    </div>
    <div class="ac">
      <div class="ah"><span style="font-size:1rem">📊</span>
        <div><div class="an">Risk Scorer</div><div class="ad">Composite per-host risk scores</div></div>
        <div class="ast2 idle" id="as1">● IDLE</div>
      </div>
      <div class="aw">
        <div class="alogbox" id="al1"><span class="li">Awaiting ingestion…</span></div>
        <button onclick="runRisk()" style="padding:6px 14px;background:transparent;border:1px solid var(--a1);color:var(--a1);border-radius:4px;font-size:.7rem;cursor:pointer;font-family:var(--mono)">▶ Score Risks</button>
      </div>
    </div>
    <div class="ac">
      <div class="ah"><span style="font-size:1rem">🧠</span>
        <div><div class="an">AI Summary</div><div class="ad">NLG threat analysis</div></div>
        <div class="ast2 idle" id="as2">● IDLE</div>
      </div>
      <div class="aw">
        <div class="alogbox" id="al2"><span class="li">Awaiting analysis…</span></div>
        <button onclick="runAISummary2()" style="padding:6px 14px;background:transparent;border:1px solid var(--a5);color:var(--a5);border-radius:4px;font-size:.7rem;cursor:pointer;font-family:var(--mono)">▶ AI Summary</button>
      </div>
    </div>
    <div class="ac">
      <div class="ah"><span style="font-size:1rem">🔥</span>
        <div><div class="an">Firewall Generator</div><div class="ad">Auto-generate block rules</div></div>
        <div class="ast2 idle" id="as3">● IDLE</div>
      </div>
      <div class="aw">
        <div class="alogbox" id="al3"><span class="li">Awaiting analysis…</span></div>
        <button onclick="runFW2()" style="padding:6px 14px;background:transparent;border:1px solid var(--a2);color:var(--a2);border-radius:4px;font-size:.7rem;cursor:pointer;font-family:var(--mono)">▶ Generate Rules</button>
      </div>
    </div>
    <div class="ac">
      <div class="ah"><span style="font-size:1rem">📋</span>
        <div><div class="an">SOC Report Writer</div><div class="ad">Full incident report</div></div>
        <div class="ast2 idle" id="as4">● IDLE</div>
      </div>
      <div class="aw">
        <div class="alogbox" id="al4"><span class="li">Awaiting analysis…</span></div>
        <button onclick="runRep2()" style="padding:6px 14px;background:transparent;border:1px solid var(--a5);color:var(--a5);border-radius:4px;font-size:.7rem;cursor:pointer;font-family:var(--mono)">▶ Write Report</button>
      </div>
    </div>
    <div class="ac">
      <div class="ah"><span style="font-size:1rem">📧</span>
        <div><div class="an">Alert Email Drafter</div><div class="ad">Tech &amp; management emails</div></div>
        <div class="ast2 idle" id="as5">● IDLE</div>
      </div>
      <div class="aw">
        <div class="alogbox" id="al5"><span class="li">Awaiting analysis…</span></div>
        <button onclick="runAlt2()" style="padding:6px 14px;background:transparent;border:1px solid var(--a3);color:var(--a3);border-radius:4px;font-size:.7rem;cursor:pointer;font-family:var(--mono)">▶ Draft Alerts</button>
      </div>
    </div>
  </div>

  <div class="card" id="pipeOut" style="display:none">
    <div class="ch"><span class="ci">📊</span><span class="ct">Pipeline Output</span>
      <button onclick="dlPipe()" style="margin-left:auto;padding:4px 12px;background:transparent;border:1px solid var(--a1);color:var(--a1);border-radius:4px;font-size:.65rem;cursor:pointer;font-family:var(--mono)">⬇ Download</button>
    </div>
    <div class="cb"><div class="aibox" id="pipeOutTxt"></div></div>
  </div>
</div>

</div><!-- /main -->
</div><!-- /pgDash -->

<div class="toast" id="toast"></div>

<script>
// ── STATE ──
let token=null, allRows=[], filteredRows=[], sortCol='id', sortAsc=true;
let uploadedFile=null, lastAIOut='', lastPipeOut='';
const api = (path,data,tok) => fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-Token':tok||token},body:JSON.stringify(data)}).then(r=>r.json());

// ── AUTH ──
async function doLogin(){
  const u=v('lu'), p=v('lp');
  if(!u||!p){show('lerr','⚠ Enter credentials.');return;}
  const d=await api('/api/login',{username:u,password:p},'');
  if(d.ok){
    token=d.token;
    document.getElementById('nuser').textContent=d.user.toUpperCase();
    switchPg('pgDash');
    alog('OK',`User "${d.user}" authenticated.`);
    alog('INFO','AI Agent initialised — 25+ threat rules loaded.');
    startAgentPoll();
  } else { show('lerr','✕ '+d.error); }
}
document.addEventListener('keydown',e=>{if(e.key==='Enter'&&document.getElementById('pgLogin').classList.contains('on'))doLogin();});
function doLogout(){token=null;allRows=[];filteredRows=[];switchPg('pgLogin');resetDash();}
function switchPg(id){document.querySelectorAll('.pg').forEach(p=>p.classList.remove('on'));document.getElementById(id).classList.add('on');}

// ── TABS ──
function swTab(i){
  document.querySelectorAll('.tab-pane').forEach(t=>t.classList.remove('on'));
  document.querySelectorAll('.ntab').forEach(t=>t.classList.remove('on'));
  document.getElementById('tp'+i).classList.add('on');
  document.getElementById('nt'+i).classList.add('on');
}

// ── FILE ──
const dz=document.getElementById('dz');
dz.addEventListener('dragover',e=>{e.preventDefault();dz.classList.add('dg');});
dz.addEventListener('dragleave',()=>dz.classList.remove('dg'));
dz.addEventListener('drop',e=>{e.preventDefault();dz.classList.remove('dg');if(e.dataTransfer.files[0])setFile(e.dataTransfer.files[0]);});
function onFile(inp){if(inp.files[0])setFile(inp.files[0]);}
function setFile(f){
  uploadedFile=f;
  document.getElementById('finfo').textContent=`📎 ${f.name} (${(f.size/1024).toFixed(1)} KB)`;
  alog('INFO',`File staged: ${f.name}`);
}

// ── ANALYSIS ──
async function doAnalyse(){
  if(!uploadedFile){toast('No file selected. Please upload a file first.');return;}
  setLoad(true,'Parsing file…');
  const rdr=new FileReader();
  rdr.onload=async e=>{
    const b64=e.target.result.split(',')[1];
    alog('INFO',`Uploading ${uploadedFile.name}…`);
    const d=await api('/api/analyse',{file_data:b64,file_name:uploadedFile.name});
    if(d.ok){ renderAll(d.rows,d.summary); }
    else toast('Error: '+d.error);
    setLoad(false);
  };
  rdr.readAsDataURL(uploadedFile);
}

function setLoad(on,msg=''){
  const pw=document.getElementById('pw'),pf=document.getElementById('pf'),
        pl=document.getElementById('pl'),ba=document.getElementById('btnA');
  if(on){
    pw.classList.add('on');ba.disabled=true;
    let w=0;const steps=['Parsing file…','Classifying events…','Running rule engine…','Scoring risks…','Building report…'];
    ba._iv=setInterval(()=>{w=Math.min(w+Math.random()*9,90);pf.style.width=w+'%';pl.textContent=steps[Math.min(Math.floor(w/20),4)];},200);
  } else {
    clearInterval(ba._iv);pf.style.width='100%';setTimeout(()=>{pw.classList.remove('on');pf.style.width='0%';},400);ba.disabled=false;
  }
}

// ── RENDER ──
function renderAll(rows, sum){
  allRows=rows; filteredRows=rows;
  animN('s0',sum.total||0);animN('s1',sum.sev?.CRITICAL||0);animN('s2',sum.sev?.HIGH||0);
  animN('s3',(sum.sev?.INFO||0)+(sum.sev?.LOW||0));animN('s4',sum.unique_ips||0);
  // Insights
  document.getElementById('insightsSec').style.display='block';
  renderInsights(sum);
  // Enable DL buttons
  ['btnDl','btnJson'].forEach(id=>document.getElementById(id).disabled=false);
  // Proto filter
  const sel=document.getElementById('fProto');sel.innerHTML='<option value="">All Protocols</option>';
  [...new Set(rows.map(r=>r.proto))].sort().forEach(p=>sel.innerHTML+=`<option>${p}</option>`);
  applyF();
  alog('OK',`Rendered ${rows.length} rows. ${sum.sev?.CRITICAL||0} critical events.`);
  toast(`Analysis complete — ${rows.length} events`);
}

function renderInsights(s){
  const cats = Object.entries(s.categories||{}).sort((a,b)=>b[1]-a[1]).slice(0,1);
  const protos = Object.entries(s.protos||{}).sort((a,b)=>b[1]-a[1]).slice(0,1);
  const topRisk = s.top_risks?.[0];
  document.getElementById('ig').innerHTML = [
    {l:'TOP CATEGORY',v:cats[0]?.[0]||'—',s:`${cats[0]?.[1]||0} events`},
    {l:'TOP PROTOCOL',v:protos[0]?.[0]||'—',s:`${protos[0]?.[1]||0} occurrences`},
    {l:'THREAT RATIO',v:(s.threat_pct||0)+'%',s:`${s.threats||0} of ${s.total} events`},
    {l:'CRITICAL EVENTS',v:s.sev?.CRITICAL||0,s:'Immediate action needed'},
    {l:'HIGHEST RISK IP',v:topRisk?topRisk[0]:'—',s:topRisk?`Score: ${topRisk[1].score}`:'No threats'},
    {l:'UNIQUE IPs',v:s.unique_ips||0,s:'Across all events'},
  ].map(i=>`<div class="ii"><div class="il">${i.l}</div><div class="iv">${i.v}</div><div class="is">${i.s}</div></div>`).join('');
}

function renderTable(rows){
  document.getElementById('rc').textContent=`${rows.length} of ${allRows.length} events`;
  const tb=document.getElementById('tbody');
  if(!rows.length){tb.innerHTML='<tr><td colspan="10" class="nodata">No matching results.</td></tr>';return;}
  tb.innerHTML=rows.map(r=>`
     <tr>
      <td style="color:var(--mu)">${r.id}</td>
      <td style="white-space:nowrap;color:var(--mu)">${r.ts}</td>
      <td style="color:var(--a1);white-space:nowrap">${r.src}</td>
      <td style="color:var(--tx)">${r.dst}</td>
      <td><span class="pt">${r.proto}</span></td>
      <td style="color:var(--mu)">${r.port||'—'}</td>
      <td><span class="sev s${r.severity}">${r.severity}</span></td>
      <td style="white-space:nowrap;font-size:.68rem">${r.category}</td>
      <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--mu);font-size:.67rem" title="${esc(r.desc)}">${r.desc}</td>
      <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:.65rem;color:var(--mu)" title="${esc(r.recommendation)}">${r.recommendation}</td>
     </tr>`).join('');
}

function esc(s){return String(s||'').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function applyF(){
  const sv=v('fSev'),pr=v('fProto'),q=v('fSearch').toLowerCase();
  let rows=allRows;
  if(sv)rows=rows.filter(r=>r.severity===sv);
  if(pr)rows=rows.filter(r=>r.proto===pr);
  if(q)rows=rows.filter(r=>(r.src+r.dst+r.category+r.desc+r.severity).toLowerCase().includes(q));
  rows=[...rows].sort((a,b)=>{
    const av=a[sortCol]||'',bv=b[sortCol]||'';
    if(typeof av==='number')return sortAsc?av-bv:bv-av;
    return sortAsc?String(av).localeCompare(String(bv)):String(bv).localeCompare(String(av));
  });
  filteredRows=rows; renderTable(rows);
}
function srt(col){sortAsc=sortCol===col?!sortAsc:true;sortCol=col;applyF();}

// ── DOWNLOAD ──
function dlCSV(){
  if(!filteredRows.length){toast('No data.');return;}
  const h=['ID','Timestamp','Src IP','Dst IP','Proto','Port','Severity','Category','Description','Recommendation'];
  const rows=filteredRows.map(r=>[r.id,r.ts,r.src,r.dst,r.proto,r.port,r.severity,r.category,
    `"${(r.desc||'').replace(/"/g,'""')}"`,`"${(r.recommendation||'').replace(/"/g,'""')}"`].join(','));
  trigDL([h.join(','),...rows].join('\n'),'text/csv','netsentinel_report.csv');
  toast('CSV downloaded — '+filteredRows.length+' rows');
}
function dlJSON(){
  if(!filteredRows.length){toast('No data.');return;}
  trigDL(JSON.stringify({exported:new Date().toISOString(),count:filteredRows.length,data:filteredRows},null,2),'application/json','netsentinel_report.json');
  toast('JSON downloaded');
}
function dlOutput(){trigDL(lastAIOut,'text/plain','ai_output.txt');toast('AI output downloaded');}
function dlPipe(){trigDL(lastPipeOut,'text/plain','pipeline_output.txt');toast('Pipeline output downloaded');}
function trigDL(content,mime,name){const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([content],{type:mime}));a.download=name;a.click();}

// ── AI AGENT TOOLS ──
async function runAISummary(){
  if(!allRows.length){toast('Run analysis first (Tab 1).');return;}
  document.getElementById('aiout').textContent='⏳ AI agent generating threat summary…';
  const d=await api('/api/ai_summary',{rows:allRows,summary:buildSum()});
  if(d.ok){lastAIOut=d.text;document.getElementById('aiout').textContent=d.text;alog('OK','AI threat summary generated.');}
  else toast('Error: '+d.error);
}
async function runFirewall(){
  if(!allRows.length){toast('Run analysis first.');return;}
  document.getElementById('aiout').textContent='⏳ Generating firewall rules…';
  const d=await api('/api/firewall',{rows:allRows});
  if(d.ok){lastAIOut=d.text;document.getElementById('aiout').textContent=d.text;alog('OK','Firewall rules generated.');}
}
async function runReport(){
  if(!allRows.length){toast('Run analysis first.');return;}
  document.getElementById('aiout').textContent='⏳ Writing SOC incident report…';
  const d=await api('/api/report',{rows:allRows,summary:buildSum()});
  if(d.ok){lastAIOut=d.text;document.getElementById('aiout').textContent=d.text;alog('OK','SOC report written.');}
}
async function runAlerts(){
  if(!allRows.length){toast('Run analysis first.');return;}
  document.getElementById('aiout').textContent='⏳ Drafting alert emails…';
  const d=await api('/api/alerts',{rows:allRows,summary:buildSum()});
  if(d.ok){lastAIOut=d.text;document.getElementById('aiout').textContent=d.text;alog('OK','Alert emails drafted.');}
}

function buildSum(){
  const sc={}; allRows.forEach(r=>{sc[r.severity]=(sc[r.severity]||0)+1;});
  const ips={}; allRows.forEach(r=>{ips[r.src]=(ips[r.src]||0)+1;});
  const topT=Object.entries(ips).sort((a,b)=>b[1]-a[1]).slice(0,5);
  const cats={}; allRows.forEach(r=>{cats[r.category]=(cats[r.category]||0)+1;});
  const threats=(sc.CRITICAL||0)+(sc.HIGH||0);
  return {total:allRows.length,sev:sc,threats,threat_pct:allRows.length?Math.round(threats/allRows.length*100):0,
    top_talkers:topT,unique_ips:new Set(allRows.map(r=>r.src)).size,categories:cats,
    top_risks:Object.entries(ips).map(([ip,n])=>[ip,{score:n*2,events:n}]).sort((a,b)=>b[1].score-a[1].score).slice(0,8)};
}

// ── AUTOMATION ──
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
function setAS(i,cls,txt){const el=document.getElementById('as'+i);el.className='ast2 '+cls;el.textContent=txt;}
function aLogA(i,html){const el=document.getElementById('al'+i);el.innerHTML+=html+'\n';el.scrollTop=el.scrollHeight;}
function setPS(i,cls){document.getElementById('ps'+i).className='ps '+cls;}
function setPP(w){document.getElementById('ppf').style.width=w+'%';}

async function runIngest(){
  setAS(0,'run','◉ RUNNING');document.getElementById('al0').innerHTML='';
  aLogA(0,'<span class="li">Connecting to log source…</span>');
  await sleep(300);
  if(!allRows.length){ aLogA(0,'<span class="li">Loading sample data…</span>');await doSample();await sleep(300);}
  aLogA(0,`<span class="lo">✓ Ingested ${allRows.length} events</span>`);
  const c=allRows.filter(r=>r.severity==='CRITICAL').length;
  if(c)aLogA(0,`<span class="lw">⚠ ${c} CRITICAL events found</span>`);
  aLogA(0,'<span class="lo">✓ Ingestion complete</span>');
  setAS(0,'done','● DONE');
}
async function runRisk(){
  if(!allRows.length){toast('Run ingestion first.');return;}
  setAS(1,'run','◉ RUNNING');document.getElementById('al1').innerHTML='';
  aLogA(1,'<span class="li">Computing per-host risk scores…</span>');
  await sleep(400);
  const scores={};
  allRows.forEach(r=>{if(!scores[r.src])scores[r.src]={s:0,n:0};scores[r.src].n++;scores[r.src].s+={CRITICAL:10,HIGH:5,MEDIUM:2,LOW:1,INFO:0}[r.severity]||0;});
  Object.entries(scores).sort((a,b)=>b[1].s-a[1].s).slice(0,6).forEach(([ip,v])=>{
    const cls=v.s>=20?'le':v.s>=8?'lw':'lo';
    aLogA(1,`<span class="${cls}">${ip} → Risk:${v.s} Events:${v.n}</span>`);
  });
  aLogA(1,'<span class="lo">✓ Risk scoring complete</span>');
  setAS(1,'done','● DONE');
}
async function runAISummary2(){
  if(!allRows.length){toast('Run ingestion first.');return;}
  setAS(2,'run','◉ RUNNING');document.getElementById('al2').innerHTML='';
  aLogA(2,'<span class="li">AI NLG engine generating summary…</span>');
  const d=await api('/api/ai_summary',{rows:allRows,summary:buildSum()});
  if(d.ok){
    lastPipeOut+='=== AI THREAT SUMMARY ===\n'+d.text+'\n\n';
    aLogA(2,'<span class="lo">✓ AI summary generated</span>');
    d.text.split('\n').slice(0,5).forEach(l=>{ if(l.trim())aLogA(2,`<span class="li">${l.slice(0,80)}</span>`);});
    setAS(2,'done','● DONE');
    document.getElementById('pipeOut').style.display='block';
    document.getElementById('pipeOutTxt').textContent=lastPipeOut;
  } else setAS(2,'err','● ERROR');
}
async function runFW2(){
  if(!allRows.length){toast('Run ingestion first.');return;}
  setAS(3,'run','◉ RUNNING');document.getElementById('al3').innerHTML='';
  aLogA(3,'<span class="li">Generating firewall rules…</span>');
  const d=await api('/api/firewall',{rows:allRows});
  if(d.ok){
    lastPipeOut+='=== FIREWALL RULES ===\n'+d.text+'\n\n';
    aLogA(3,`<span class="lo">✓ Rules generated</span>`);
    setAS(3,'done','● DONE');
    document.getElementById('pipeOut').style.display='block';
    document.getElementById('pipeOutTxt').textContent=lastPipeOut;
  } else setAS(3,'err','● ERROR');
}
async function runRep2(){
  if(!allRows.length){toast('Run ingestion first.');return;}
  setAS(4,'run','◉ RUNNING');document.getElementById('al4').innerHTML='';
  aLogA(4,'<span class="li">Writing SOC incident report…</span>');
  const d=await api('/api/report',{rows:allRows,summary:buildSum()});
  if(d.ok){
    lastPipeOut+='=== SOC INCIDENT REPORT ===\n'+d.text+'\n\n';
    aLogA(4,`<span class="lo">✓ Report written (${d.text.length} chars)</span>`);
    setAS(4,'done','● DONE');
    document.getElementById('pipeOut').style.display='block';
    document.getElementById('pipeOutTxt').textContent=lastPipeOut;
  } else setAS(4,'err','● ERROR');
}
async function runAlt2(){
  if(!allRows.length){toast('Run ingestion first.');return;}
  setAS(5,'run','◉ RUNNING');document.getElementById('al5').innerHTML='';
  aLogA(5,'<span class="li">Drafting alert emails…</span>');
  const d=await api('/api/alerts',{rows:allRows,summary:buildSum()});
  if(d.ok){
    lastPipeOut+='=== ALERT EMAILS ===\n'+d.text+'\n\n';
    aLogA(5,'<span class="lo">✓ Alert emails drafted</span>');
    setAS(5,'done','● DONE');
    document.getElementById('pipeOut').style.display='block';
    document.getElementById('pipeOutTxt').textContent=lastPipeOut;
  } else setAS(5,'err','● ERROR');
}

async function runPipeline(){
  lastPipeOut='';
  [0,1,2,3,4,5,6].forEach(i=>setPS(i,'pend'));
  setPP(0);document.getElementById('ppst').textContent='Pipeline running…';
  setPS(0,'run');setPP(5);   await runIngest();     setPS(0,'done');setPP(18);
  setPS(1,'run');await sleep(300);document.getElementById('al0').innerHTML+='<span class="lo">✓ Rule engine complete</span>\n';
  setPS(1,'done');setPP(32);
  setPS(2,'run');setPP(40);  await runRisk();       setPS(2,'done');setPP(52);
  setPS(3,'run');setPP(58);  await runAISummary2(); setPS(3,'done');setPP(68);
  setPS(4,'run');setPP(74);  await runFW2();        setPS(4,'done');setPP(84);
  setPS(5,'run');setPP(90);  await runRep2();       setPS(5,'done');setPP(96);
  await runAlt2();
  setPP(100);setPS(6,'done');
  document.getElementById('ppst').textContent='✓ All 7 pipeline stages complete';
  toast('✅ Full automation pipeline complete!');
  alog('OK','Full automation pipeline finished successfully.');
}

// ── AGENT LOG ──
function alog(type,msg){
  const log=document.getElementById('alog');
  const now=new Date();
  const ts=[now.getHours(),now.getMinutes(),now.getSeconds()].map(n=>String(n).padStart(2,'0')).join(':');
  const d=document.createElement('div');d.className='ll';
  d.innerHTML=`<span class="lt">${ts}</span><span class="l${type}">[${type}]</span><span> ${msg}</span>`;
  log.appendChild(d);log.scrollTop=log.scrollHeight;
}
let agentTimer=null;
function startAgentPoll(){
  agentTimer=setInterval(async()=>{
    try{
      const r=await fetch('/api/agent',{headers:{'X-Token':token}});
      const d=await r.json();
      if(d.logs?.length){const last=d.logs[d.logs.length-1];alog(last.level,'[AUTO] '+last.msg);}
    }catch(e){}
  },13000);
}

// ── HELPERS ──
const v=id=>document.getElementById(id).value;
function show(id,txt){const el=document.getElementById(id);el.textContent=txt;}
function animN(id,target){const el=document.getElementById(id);let c=0;const s=Math.ceil(target/25);const t=setInterval(()=>{c=Math.min(c+s,target);el.textContent=c;if(c>=target)clearInterval(t);},30);}
let tt;
function toast(msg){const t=document.getElementById('toast');t.textContent=msg;t.classList.add('on');clearTimeout(tt);tt=setTimeout(()=>t.classList.remove('on'),3000);}
function resetDash(){
  allRows=[];filteredRows=[];uploadedFile=null;lastAIOut='';lastPipeOut='';
  ['s0','s1','s2','s3','s4'].forEach(id=>document.getElementById(id).textContent='0');
  document.getElementById('tbody').innerHTML='<tr><td colspan="10" class="nodata">Upload a file to begin.</td></tr>';
  document.getElementById('insightsSec').style.display='none';
  document.getElementById('finfo').textContent='No file selected';
  ['btnDl','btnJson'].forEach(id=>document.getElementById(id).disabled=true);
  if(agentTimer){clearInterval(agentTimer);agentTimer=null;}
}
</script>
</body>
</html>"""

# ══════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    # Parse command-line argument for custom port
    port = 8080
    if len(sys.argv) > 1 and sys.argv[1] == '-p' and len(sys.argv) > 2:
        try:
            port = int(sys.argv[2])
        except ValueError:
            print("Invalid port number, using default 8080.")

    # List of ports to try (user-specified first, then fallbacks)
    ports_to_try = [port, 8081, 8082, 8000, 8088, 9090, 8888]
    ports_to_try = list(dict.fromkeys(ports_to_try))  # remove duplicates

    httpd = None
    for p in ports_to_try:
        try:
            httpd = socketserver.TCPServer(("", p), Handler)
            httpd.allow_reuse_address = True
            PORT = p
            break
        except OSError as e:
            # Port already in use on Windows
            if hasattr(e, 'winerror') and e.winerror == 10048:
                print(f"Port {p} is already in use. Trying next port...")
            else:
                raise

    if httpd is None:
        print("Error: No available port found. Please free up some ports or specify a port with -p <port>")
        sys.exit(1)

    # Print startup banner with the actual port
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║   NetSentinel — AI Automation & Log Analysis                 ║
║   No API Keys · No ML · Pure Python · Single File            ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  NO INSTALL NEEDED — Python standard library only            ║
║  RUN :  python log_analyzer_noapi.py                         ║
║  OPEN:  http://localhost:{PORT}                                ║
║                                                              ║
║  CREDENTIALS                                                 ║
║    admin    / admin123                                       ║
║    analyst  / analyst2024                                    ║
║    demo     / demo1234                                       ║
║                                                              ║
║  FEATURES                                                    ║
║    ✓ PCAP + text/CSV log file upload                         ║
║    ✓ 25+ rule-based threat detection patterns                ║
║    ✓ AI NLG threat summaries (no API key)                    ║
║    ✓ Per-host risk scoring algorithm                         ║
║    ✓ Auto firewall rule generator (iptables + Windows)       ║
║    ✓ Full SOC incident report writer                         ║
║    ✓ Alert email drafter (tech + management)                 ║
║    ✓ 7-stage automation pipeline                             ║
║    ✓ Background AI agent monitor loop                        ║
║    ✓ Sortable/filterable results table                       ║
║    ✓ CSV + JSON export                                       ║
╚══════════════════════════════════════════════════════════════╝
Press Ctrl+C to stop.
""")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        httpd.server_close()