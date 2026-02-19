# TODO: MITRE ATT&CK Techniques — Not Yet Implemented (Network-Observable)

> Only techniques whose indicators can be extracted from pcap/pcapng or real-time network traffic.

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

## TODO — techniques to implement

### Reconnaissance

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 1 | T1595.001 | Active Scanning: Scanning IP Blocks |
| 2 | T1595.002 | Active Scanning: Vulnerability Scanning |
| 3 | T1595.003 | Active Scanning: Wordlist Scanning |

### Initial Access

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 4 | T1133 | External Remote Services (VPN/RDP/SSH from external IPs) |
| 5 | T1190 | Exploit Public-Facing Application (exploit payload signatures in HTTP) |
| 6 | T1659 | Content Injection (HTTP response injection / iframe inject) |

### Execution

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 7 | T1059.001 | Command and Scripting Interpreter: PowerShell (network payload) |
| 8 | T1047 | Windows Management Instrumentation (WMI over DCOM/135) |

### Discovery

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 9 | T1016 | System Network Configuration Discovery (DHCP/DNS recon queries) |
| 10 | T1018 | Remote System Discovery (NetBIOS/LLMNR/mDNS enumeration) |
| 11 | T1049 | System Network Connections Discovery (SMB session enum) |
| 12 | T1135 | Network Share Discovery (SMB share enumeration) |
| 13 | T1040 | Network Sniffing (promiscuous mode detection via ARP anomalies) |

### Lateral Movement

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 14 | T1021.001 | Remote Services: Remote Desktop Protocol (RDP on 3389) |
| 15 | T1021.002 | Remote Services: SMB/Windows Admin Shares (PsExec lateral) |
| 16 | T1021.004 | Remote Services: SSH |
| 17 | T1021.005 | Remote Services: VNC |
| 18 | T1021.006 | Remote Services: Windows Remote Management (WinRM on 5985/5986) |
| 19 | T1210 | Exploitation of Remote Services (exploit payload signatures) |
| 20 | T1570 | Lateral Tool Transfer (internal file copy via SMB/WinRM) |
| 21 | T1563 | Remote Service Session Hijacking |
| 22 | T1563.001 | Remote Service Session Hijacking: SSH Hijacking |
| 23 | T1563.002 | Remote Service Session Hijacking: RDP Hijacking |

### Credential Access

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 24 | T1110 | Brute Force (repeated failed auth attempts) |
| 25 | T1110.001 | Brute Force: Password Guessing |
| 26 | T1110.002 | Brute Force: Password Cracking (Kerberos AS-REP roasting traffic) |
| 27 | T1110.003 | Brute Force: Password Spraying |
| 28 | T1110.004 | Brute Force: Credential Stuffing |
| 29 | T1187 | Forced Authentication (SMB relay / NTLM capture) |
| 30 | T1557.001 | Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning |
| 31 | T1557.002 | Adversary-in-the-Middle: ARP Cache Poisoning (rate-based detection) |
| 32 | T1557.003 | Adversary-in-the-Middle: DHCP Spoofing |
| 33 | T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting (TGS-REQ anomalies) |
| 34 | T1040 | Network Sniffing (credential capture detection) |

### Collection

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 35 | T1114.002 | Email Collection: Remote Email Collection (IMAP/POP3 bulk download) |
| 36 | T1560 | Archive Collected Data (compressed stream detection) |

### Command and Control

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 37 | T1071.002 | Application Layer Protocol: File Transfer Protocols (FTP/FTPS) |
| 38 | T1071.003 | Application Layer Protocol: Mail Protocols (SMTP/IMAP/POP3) |
| 39 | T1090 | Proxy (SOCKS/HTTP CONNECT proxy detection) |
| 40 | T1090.001 | Proxy: Internal Proxy |
| 41 | T1090.002 | Proxy: External Proxy |
| 42 | T1090.003 | Proxy: Multi-hop Proxy |
| 43 | T1095 | Non-Application Layer Protocol (raw TCP/UDP/ICMP C2) |
| 44 | T1102 | Web Service (C2 via known cloud/web services) |
| 45 | T1102.001 | Web Service: Dead Drop Resolver |
| 46 | T1102.002 | Web Service: Bidirectional Communication |
| 47 | T1104 | Multi-Stage Channels |
| 48 | T1132 | Data Encoding (Base64/custom encoding in payloads) |
| 49 | T1132.001 | Data Encoding: Standard Encoding |
| 50 | T1132.002 | Data Encoding: Non-Standard Encoding |
| 51 | T1001.001 | Data Obfuscation: Junk Data |
| 52 | T1001.002 | Data Obfuscation: Steganography (deep image analysis) |
| 53 | T1001.003 | Data Obfuscation: Protocol Impersonation |
| 54 | T1008 | Fallback Channels (multiple C2 endpoints per session) |
| 55 | T1568 | Dynamic Resolution |
| 56 | T1568.001 | Dynamic Resolution: Fast Flux DNS |
| 57 | T1568.002 | Dynamic Resolution: Domain Generation Algorithms (DGA) |
| 58 | T1568.003 | Dynamic Resolution: DNS Calculation |
| 59 | T1572 | Protocol Tunneling (SSH tunnels, DNS-over-HTTPS, ICMP tunnels) |
| 60 | T1573.001 | Encrypted Channel: Symmetric Cryptography |
| 61 | T1573.002 | Encrypted Channel: Asymmetric Cryptography (JA3S, cert anomalies) |
| 62 | T1205 | Traffic Signaling (port knocking sequences) |
| 63 | T1205.001 | Traffic Signaling: Port Knocking |
| 64 | T1219 | Remote Access Software (TeamViewer, AnyDesk, ngrok, etc.) |
| 65 | T1104 | Multi-Stage Channels (staged payload download detection) |

### Exfiltration

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 66 | T1048 | Exfiltration Over Alternative Protocol |
| 67 | T1048.001 | Exfiltration Over Symmetric Encrypted Non-C2 Protocol |
| 68 | T1048.002 | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol |
| 69 | T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol |
| 70 | T1567 | Exfiltration Over Web Service |
| 71 | T1567.001 | Exfiltration Over Web Service: Exfiltration to Code Repository |
| 72 | T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage |
| 73 | T1567.004 | Exfiltration Over Web Service: Exfiltration Over Webhook |
| 74 | T1020 | Automated Exfiltration (periodic large transfers) |
| 75 | T1030 | Data Transfer Size Limits (chunked exfil detection) |
| 76 | T1537 | Transfer Data to Cloud Account |
| 77 | T1029 | Scheduled Transfer (time-based exfil patterns) |

### Impact

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 78 | T1498 | Network Denial of Service (volumetric flood detection) |
| 79 | T1498.001 | Network Denial of Service: Direct Network Flood |
| 80 | T1498.002 | Network Denial of Service: Reflection Amplification |
| 81 | T1499 | Endpoint Denial of Service |
| 82 | T1499.001 | Endpoint Denial of Service: OS Exhaustion Flood (SYN flood) |
| 83 | T1499.002 | Endpoint Denial of Service: Service Exhaustion Flood |

### Defense Evasion / Network-level

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 84 | T1599 | Network Boundary Bridging |
| 85 | T1599.001 | Network Boundary Bridging: Network Address Translation Traversal |
| 86 | T1205.002 | Traffic Signaling: Socket Filters |

### Resource Development (network-observable)

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 87 | T1583.006 | Acquire Infrastructure: Web Services (known C2 infra IPs/domains) |
| 88 | T1584.004 | Compromise Infrastructure: Server (known compromised IP feeds) |

### Other network-observable

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 89 | T1542.003 | Pre-OS Boot: Bootkit (TFTP/PXE boot anomalies) |
| 90 | T1021.003 | Remote Services: Distributed Component Object Model (DCOM on 135) |
