# TODO: MITRE ATT&CK Techniques — Not Yet Implemented (Network-Observable)

> Only techniques whose indicators can be reliably extracted from pcap / pcapng
> or real-time network traffic capture — without requiring endpoint telemetry
> or external threat intelligence feeds.

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
| 6 | T1590.005 | Gather Victim Network Information: IP Addresses (mass DNS resolution bursts) |

### Initial Access

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 7 | T1133 | External Remote Services (VPN/RDP/SSH from external IPs) |
| 8 | T1190 | Exploit Public-Facing Application (exploit payload signatures in HTTP) |
| 9 | T1200 | Hardware Additions (rogue device — new MAC address on network) |
| 10 | T1659 | Content Injection (HTTP response injection / iframe inject) |

### Execution

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 11 | T1059.001 | Command and Scripting Interpreter: PowerShell (encoded payload in HTTP download) |
| 12 | T1047 | Windows Management Instrumentation (WMI over DCOM — port 135 RPC traffic) |

### Discovery

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 13 | T1018 | Remote System Discovery (NetBIOS/LLMNR/mDNS enumeration bursts) |
| 14 | T1049 | System Network Connections Discovery (SMB session enumeration) |
| 15 | T1135 | Network Share Discovery (SMB share enumeration — Tree Connect bursts) |
| 16 | T1580 | Cloud Infrastructure Discovery (HTTP to cloud metadata endpoint 169.254.169.254) |

### Lateral Movement

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 17 | T1021.001 | Remote Services: Remote Desktop Protocol (RDP — port 3389) |
| 18 | T1021.002 | Remote Services: SMB/Windows Admin Shares (PsExec — named pipe + service creation) |
| 19 | T1021.003 | Remote Services: Distributed Component Object Model (DCOM — port 135) |
| 20 | T1021.004 | Remote Services: SSH (port 22 lateral connections between internal hosts) |
| 21 | T1021.005 | Remote Services: VNC (port 5900+) |
| 22 | T1021.006 | Remote Services: Windows Remote Management (WinRM — port 5985/5986) |
| 23 | T1210 | Exploitation of Remote Services (exploit payload signatures in internal traffic) |
| 24 | T1570 | Lateral Tool Transfer (internal file copy via SMB/WinRM between hosts) |

### Credential Access

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 25 | T1110 | Brute Force (repeated connection attempts to auth services) |
| 26 | T1110.001 | Brute Force: Password Guessing (many attempts from one IP to one service) |
| 27 | T1110.002 | Brute Force: Password Cracking (Kerberos AS-REQ without pre-auth — AS-REP roasting) |
| 28 | T1110.003 | Brute Force: Password Spraying (one-to-many auth pattern) |
| 29 | T1110.004 | Brute Force: Credential Stuffing (many credentials against one service) |
| 30 | T1187 | Forced Authentication (outbound SMB/NTLM to external IP — relay/capture) |
| 31 | T1557.001 | Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning (responses on UDP 5355/137) |
| 32 | T1557.003 | Adversary-in-the-Middle: DHCP Spoofing (multiple DHCP offers from different MACs) |
| 33 | T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting (TGS-REQ burst for SPNs — port 88) |

### Collection

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 34 | T1114.002 | Email Collection: Remote Email Collection (IMAP/POP3 bulk download) |
| 35 | T1119 | Automated Collection (rapid sequential file access via SMB/FTP) |

### Command and Control

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 36 | T1071.002 | Application Layer Protocol: File Transfer Protocols (FTP/FTPS C2) |
| 37 | T1071.003 | Application Layer Protocol: Mail Protocols (SMTP/IMAP/POP3 C2) |
| 38 | T1090 | Proxy (SOCKS handshake / HTTP CONNECT method detection) |
| 39 | T1090.001 | Proxy: Internal Proxy (internal host relaying traffic) |
| 40 | T1090.002 | Proxy: External Proxy (connections through known proxy services) |
| 41 | T1090.003 | Proxy: Multi-hop Proxy (chained proxy detection) |
| 42 | T1090.004 | Proxy: Domain Fronting (TLS SNI vs HTTP Host header mismatch) |
| 43 | T1095 | Non-Application Layer Protocol (raw TCP/UDP/ICMP C2 — no app-layer headers) |
| 44 | T1102 | Web Service (C2 callbacks to pastebin/discord/telegram/slack APIs) |
| 45 | T1102.001 | Web Service: Dead Drop Resolver |
| 46 | T1102.002 | Web Service: Bidirectional Communication |
| 47 | T1102.003 | Web Service: One-Way Communication |
| 48 | T1104 | Multi-Stage Channels (sequential connections to different C2 servers) |
| 49 | T1132 | Data Encoding (Base64/hex patterns in HTTP/DNS payloads) |
| 50 | T1132.001 | Data Encoding: Standard Encoding (Base64 in HTTP body/URL) |
| 51 | T1132.002 | Data Encoding: Non-Standard Encoding (custom XOR/rotation in payload) |
| 52 | T1001.001 | Data Obfuscation: Junk Data (padding bytes in payload) |
| 53 | T1001.002 | Data Obfuscation: Steganography (deep image payload analysis) |
| 54 | T1001.003 | Data Obfuscation: Protocol Impersonation (fake HTTP/DNS headers over non-standard port) |
| 55 | T1008 | Fallback Channels (session switches between multiple C2 endpoints) |
| 56 | T1568 | Dynamic Resolution |
| 57 | T1568.001 | Dynamic Resolution: Fast Flux DNS (rapid A-record IP rotation) |
| 58 | T1568.002 | Dynamic Resolution: Domain Generation Algorithms (high-entropy NXDomain bursts) |
| 59 | T1568.003 | Dynamic Resolution: DNS Calculation (computed domain from seed) |
| 60 | T1572 | Protocol Tunneling (SSH tunnels, DNS-over-HTTPS, ICMP tunnels) |
| 61 | T1573.001 | Encrypted Channel: Symmetric Cryptography (custom symmetric encryption on non-TLS port) |
| 62 | T1573.002 | Encrypted Channel: Asymmetric Cryptography (JA3S fingerprint, certificate anomalies) |
| 63 | T1205 | Traffic Signaling (specific port-sequence patterns before C2 activation) |
| 64 | T1205.001 | Traffic Signaling: Port Knocking (ordered SYN to closed ports) |
| 65 | T1219 | Remote Access Software (connections to TeamViewer/AnyDesk/ngrok relay servers) |

### Exfiltration

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 66 | T1048 | Exfiltration Over Alternative Protocol (data on unexpected protocol/port) |
| 67 | T1048.001 | Exfiltration Over Symmetric Encrypted Non-C2 Protocol |
| 68 | T1048.002 | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol |
| 69 | T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol |
| 70 | T1567 | Exfiltration Over Web Service (large uploads to cloud/web services) |
| 71 | T1567.001 | Exfiltration Over Web Service: Exfiltration to Code Repository |
| 72 | T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage |
| 73 | T1567.004 | Exfiltration Over Web Service: Exfiltration Over Webhook |
| 74 | T1020 | Automated Exfiltration (periodic large outbound transfers) |
| 75 | T1029 | Scheduled Transfer (time-of-day exfil patterns in pcap timestamps) |
| 76 | T1030 | Data Transfer Size Limits (many small chunked transfers instead of one large) |

### Impact

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 77 | T1498 | Network Denial of Service (volumetric flood detection) |
| 78 | T1498.001 | Network Denial of Service: Direct Network Flood |
| 79 | T1498.002 | Network Denial of Service: Reflection Amplification (DNS/NTP/memcached amplification) |
| 80 | T1499 | Endpoint Denial of Service |
| 81 | T1499.001 | Endpoint Denial of Service: OS Exhaustion Flood (SYN flood) |
| 82 | T1499.002 | Endpoint Denial of Service: Service Exhaustion Flood |
| 83 | T1499.003 | Endpoint Denial of Service: Application Exhaustion Flood (HTTP flood) |

### Defense Evasion (network-level)

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 84 | T1600 | Weaken Encryption (TLS downgrade — weak cipher suites in handshake) |
| 85 | T1600.001 | Weaken Encryption: Reduce Key Space (short key lengths in TLS negotiation) |
| 86 | T1553.004 | Subvert Trust Controls: Install Root Certificate (unknown/self-signed CA in TLS chain) |
| 87 | T1036.005 | Masquerading: Match Legitimate Name or Location (HTTP Host header spoofing) |
| 88 | T1027.009 | Obfuscated Files or Information: Embedded Payloads (PE/ELF magic bytes in HTTP downloads) |

### Resource Development (network-observable)

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 89 | T1588.004 | Obtain Capabilities: Digital Certificates (self-signed/anomalous certs in TLS handshake) |

### Other network-observable

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 90 | T1542.003 | Pre-OS Boot: Bootkit (TFTP/PXE boot anomalies on UDP 69) |
| 91 | T1602 | Data from Configuration Repository (SNMP community string brute force) |
| 92 | T1602.001 | Data from Configuration Repository: SNMP (MIB Dump — bulk GET-NEXT on UDP 161) |
| 93 | T1602.002 | Data from Configuration Repository: Network Device CLI (Telnet cleartext on port 23) |
