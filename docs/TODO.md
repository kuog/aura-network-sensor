# TODO: MITRE ATT&CK Techniques — Not Yet Implemented (Network-Observable)

> Only techniques whose indicators can be reliably extracted from pcap / pcapng
> or real-time network traffic capture.

## Already implemented in the codebase

| Код MITRE | Название | Файл |
| --- | --- | --- |
| T1001 | Data Obfuscation | obfuscation.rs |
| T1011 | Exfiltration Over Other Network Medium (beaconing) | main.rs |
| T1039 | Data from Network Shared Drive (SMB) | smb.rs |
| T1041 | Exfiltration Over C2 Channel | l4_reassembly.rs |
| T1046 | Network Service Discovery (port scan) | scan.rs |
| T1059 | Command and Scripting Interpreter (shell) | shell.rs |
| T1071.001 | Application Layer Protocol: Web Protocols | http.rs |
| T1071.004 | Application Layer Protocol: DNS | dns.rs |
| T1105 | Ingress Tool Transfer (UA patterns) | http.rs |
| T1557 | Adversary-in-the-Middle (ARP spoofing) | arp.rs |
| T1562.001 | Impair Defenses: SSL Stripping | stripping.rs |
| T1571 | Non-Standard Port | port_anomaly.rs |
| T1573 | Encrypted Channel (JA3) | tls.rs, main.rs |
| T1595 | Active Scanning (UA patterns) | http.rs |

---

## TODO — techniques to implement

### Reconnaissance

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 1 | T1595.001 | Active Scanning: Scanning IP Blocks |
| 2 | T1595.002 | Active Scanning: Vulnerability Scanning |
| 3 | T1595.003 | Active Scanning: Wordlist Scanning |
| 4 | T1590 | Gather Victim Network Information (DNS zone transfer — AXFR) |
| 5 | T1590.004 | Gather Victim Network Information: Network Topology (traceroute / ICMP TTL patterns) |
| 6 | T1590.005 | Gather Victim Network Information: IP Addresses (mass DNS resolution) |

### Initial Access

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 7 | T1133 | External Remote Services (VPN/RDP/SSH from external IPs) |
| 8 | T1190 | Exploit Public-Facing Application (exploit payload signatures in HTTP) |
| 9 | T1659 | Content Injection (HTTP response injection / iframe inject) |
| 10 | T1566.002 | Phishing: Spearphishing Link (malicious URL patterns in HTTP/SMTP) |
| 11 | T1200 | Hardware Additions (rogue device — new MAC address on network) |

### Execution

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 12 | T1059.001 | Command and Scripting Interpreter: PowerShell (network payload detection) |
| 13 | T1047 | Windows Management Instrumentation (WMI over DCOM port 135) |

### Persistence

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 14 | T1197 | BITS Jobs (HTTP range request patterns for stealthy downloads) |

### Discovery

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 15 | T1016 | System Network Configuration Discovery (DHCP/DNS recon queries) |
| 16 | T1018 | Remote System Discovery (NetBIOS/LLMNR/mDNS enumeration) |
| 17 | T1040 | Network Sniffing (promiscuous mode detection via ARP anomalies) |
| 18 | T1049 | System Network Connections Discovery (SMB session enum) |
| 19 | T1135 | Network Share Discovery (SMB share enumeration) |
| 20 | T1580 | Cloud Infrastructure Discovery (cloud metadata API calls — 169.254.169.254) |

### Lateral Movement

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 21 | T1021.001 | Remote Services: Remote Desktop Protocol (RDP on 3389) |
| 22 | T1021.002 | Remote Services: SMB/Windows Admin Shares (PsExec lateral) |
| 23 | T1021.003 | Remote Services: Distributed Component Object Model (DCOM on 135) |
| 24 | T1021.004 | Remote Services: SSH |
| 25 | T1021.005 | Remote Services: VNC |
| 26 | T1021.006 | Remote Services: Windows Remote Management (WinRM on 5985/5986) |
| 27 | T1210 | Exploitation of Remote Services (exploit payload signatures) |
| 28 | T1570 | Lateral Tool Transfer (internal file copy via SMB/WinRM) |
| 29 | T1563 | Remote Service Session Hijacking |
| 30 | T1563.001 | Remote Service Session Hijacking: SSH Hijacking |
| 31 | T1563.002 | Remote Service Session Hijacking: RDP Hijacking |

### Credential Access

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 32 | T1110 | Brute Force (repeated failed auth attempts on same service) |
| 33 | T1110.001 | Brute Force: Password Guessing |
| 34 | T1110.002 | Brute Force: Password Cracking (Kerberos AS-REP roasting traffic) |
| 35 | T1110.003 | Brute Force: Password Spraying |
| 36 | T1110.004 | Brute Force: Credential Stuffing |
| 37 | T1187 | Forced Authentication (SMB relay / NTLM capture) |
| 38 | T1557.001 | Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning |
| 39 | T1557.002 | Adversary-in-the-Middle: ARP Cache Poisoning (rate-based detection) |
| 40 | T1557.003 | Adversary-in-the-Middle: DHCP Spoofing |
| 41 | T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting (TGS-REQ anomalies on port 88) |

### Collection

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 42 | T1114.002 | Email Collection: Remote Email Collection (IMAP/POP3 bulk download) |
| 43 | T1119 | Automated Collection (bulk SMB/FTP access patterns) |
| 44 | T1560 | Archive Collected Data (compressed stream detection in transfers) |

### Command and Control

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 45 | T1071.002 | Application Layer Protocol: File Transfer Protocols (FTP/FTPS) |
| 46 | T1071.003 | Application Layer Protocol: Mail Protocols (SMTP/IMAP/POP3) |
| 47 | T1090 | Proxy (SOCKS/HTTP CONNECT proxy detection) |
| 48 | T1090.001 | Proxy: Internal Proxy |
| 49 | T1090.002 | Proxy: External Proxy |
| 50 | T1090.003 | Proxy: Multi-hop Proxy |
| 51 | T1090.004 | Proxy: Domain Fronting (TLS SNI vs HTTP Host mismatch) |
| 52 | T1095 | Non-Application Layer Protocol (raw TCP/UDP/ICMP C2) |
| 53 | T1102 | Web Service (C2 via known cloud/web services) |
| 54 | T1102.001 | Web Service: Dead Drop Resolver |
| 55 | T1102.002 | Web Service: Bidirectional Communication |
| 56 | T1102.003 | Web Service: One-Way Communication |
| 57 | T1104 | Multi-Stage Channels (staged payload download detection) |
| 58 | T1132 | Data Encoding (Base64/custom encoding in payloads) |
| 59 | T1132.001 | Data Encoding: Standard Encoding |
| 60 | T1132.002 | Data Encoding: Non-Standard Encoding |
| 61 | T1001.001 | Data Obfuscation: Junk Data |
| 62 | T1001.002 | Data Obfuscation: Steganography (deep image analysis) |
| 63 | T1001.003 | Data Obfuscation: Protocol Impersonation |
| 64 | T1008 | Fallback Channels (multiple C2 endpoints per session) |
| 65 | T1568 | Dynamic Resolution |
| 66 | T1568.001 | Dynamic Resolution: Fast Flux DNS |
| 67 | T1568.002 | Dynamic Resolution: Domain Generation Algorithms (DGA) |
| 68 | T1568.003 | Dynamic Resolution: DNS Calculation |
| 69 | T1572 | Protocol Tunneling (SSH tunnels, DNS-over-HTTPS, ICMP tunnels) |
| 70 | T1573.001 | Encrypted Channel: Symmetric Cryptography |
| 71 | T1573.002 | Encrypted Channel: Asymmetric Cryptography (JA3S, certificate anomalies) |
| 72 | T1205 | Traffic Signaling (port knocking sequences) |
| 73 | T1205.001 | Traffic Signaling: Port Knocking |
| 74 | T1205.002 | Traffic Signaling: Socket Filters |
| 75 | T1219 | Remote Access Software (TeamViewer, AnyDesk, ngrok, etc.) |

### Exfiltration

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 76 | T1048 | Exfiltration Over Alternative Protocol |
| 77 | T1048.001 | Exfiltration Over Symmetric Encrypted Non-C2 Protocol |
| 78 | T1048.002 | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol |
| 79 | T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol |
| 80 | T1567 | Exfiltration Over Web Service |
| 81 | T1567.001 | Exfiltration Over Web Service: Exfiltration to Code Repository |
| 82 | T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage |
| 83 | T1567.004 | Exfiltration Over Web Service: Exfiltration Over Webhook |
| 84 | T1020 | Automated Exfiltration (periodic large transfers) |
| 85 | T1029 | Scheduled Transfer (time-based exfil patterns) |
| 86 | T1030 | Data Transfer Size Limits (chunked exfil detection) |

### Impact

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 87 | T1498 | Network Denial of Service (volumetric flood detection) |
| 88 | T1498.001 | Network Denial of Service: Direct Network Flood |
| 89 | T1498.002 | Network Denial of Service: Reflection Amplification |
| 90 | T1499 | Endpoint Denial of Service |
| 91 | T1499.001 | Endpoint Denial of Service: OS Exhaustion Flood (SYN flood) |
| 92 | T1499.002 | Endpoint Denial of Service: Service Exhaustion Flood |
| 93 | T1499.003 | Endpoint Denial of Service: Application Exhaustion Flood |
| 94 | T1565.002 | Data Manipulation: Transmitted Data Manipulation (MITM payload modification) |

### Defense Evasion (network-level)

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 95 | T1599 | Network Boundary Bridging |
| 96 | T1599.001 | Network Boundary Bridging: Network Address Translation Traversal |
| 97 | T1600 | Weaken Encryption (TLS downgrade attacks, weak cipher negotiation) |
| 98 | T1600.001 | Weaken Encryption: Reduce Key Space |
| 99 | T1553.004 | Subvert Trust Controls: Install Root Certificate (unknown CA in TLS handshake) |
| 100 | T1036.005 | Masquerading: Match Legitimate Name or Location (HTTP Host header spoofing) |
| 101 | T1027.009 | Obfuscated Files or Information: Embedded Payloads (in HTTP downloads) |

### Resource Development (network-observable)

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 102 | T1583.006 | Acquire Infrastructure: Web Services (known C2 infra IPs/domains) |
| 103 | T1588.004 | Obtain Capabilities: Digital Certificates (self-signed/anomalous certs in TLS) |

### Other network-observable

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 104 | T1542.003 | Pre-OS Boot: Bootkit (TFTP/PXE boot anomalies) |
| 105 | T1602 | Data from Configuration Repository (SNMP community string brute force) |
| 106 | T1602.001 | Data from Configuration Repository: SNMP (MIB Dump) |
| 107 | T1602.002 | Data from Configuration Repository: Network Device CLI (Telnet/SSH to network devices) |
