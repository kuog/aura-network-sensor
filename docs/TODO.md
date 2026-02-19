# TODO: MITRE ATT&CK Techniques — Not Yet Implemented (Network-Observable)

> Only techniques whose indicators can be reliably detected by **passively**
> observing network packets (pcap / pcapng / real-time capture) — without
> requiring endpoint telemetry, external threat intelligence, or active probing.

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
| 4 | T1590 | Gather Victim Network Information (DNS zone transfer — AXFR query on TCP 53) |
| 5 | T1590.004 | Gather Victim Network Information: Network Topology (traceroute ICMP TTL-exceeded) |
| 6 | T1590.005 | Gather Victim Network Information: IP Addresses (mass DNS A-record query bursts) |

### Initial Access

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 7 | T1133 | External Remote Services (RDP/SSH/VPN connections from external IPs) |
| 8 | T1190 | Exploit Public-Facing Application (exploit payload signatures in HTTP requests) |
| 9 | T1659 | Content Injection (injected iframe/script in HTTP response body) |

### Execution

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 10 | T1059.001 | Command and Scripting Interpreter: PowerShell (encoded PS payload in HTTP download) |
| 11 | T1047 | Windows Management Instrumentation (WMI UUID in DCOM/RPC on port 135) |

### Discovery

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 12 | T1018 | Remote System Discovery (NetBIOS name query bursts on UDP 137, LLMNR on UDP 5355) |
| 13 | T1049 | System Network Connections Discovery (SMB session enumeration requests) |
| 14 | T1135 | Network Share Discovery (SMB Tree Connect request bursts) |

### Lateral Movement

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 15 | T1021.001 | Remote Services: Remote Desktop Protocol (RDP — port 3389 internal-to-internal) |
| 16 | T1021.002 | Remote Services: SMB/Windows Admin Shares (PsExec — IPC$ + ADMIN$ named pipes) |
| 17 | T1021.003 | Remote Services: Distributed Component Object Model (DCOM — port 135 + high ports) |
| 18 | T1021.004 | Remote Services: SSH (port 22 internal-to-internal connections) |
| 19 | T1021.005 | Remote Services: VNC (port 5900+ internal-to-internal) |
| 20 | T1021.006 | Remote Services: Windows Remote Management (WinRM — port 5985/5986) |
| 21 | T1210 | Exploitation of Remote Services (exploit payload signatures in internal traffic) |
| 22 | T1570 | Lateral Tool Transfer (SMB Write requests for PE/script files between internal hosts) |

### Credential Access

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 23 | T1110 | Brute Force (repeated rapid connection attempts to auth services) |
| 24 | T1110.001 | Brute Force: Password Guessing (many attempts from one IP to one service) |
| 25 | T1110.002 | Brute Force: Password Cracking (Kerberos AS-REQ without pre-auth on port 88) |
| 26 | T1110.003 | Brute Force: Password Spraying (one-to-many auth connection pattern) |
| 27 | T1110.004 | Brute Force: Credential Stuffing (many credentials against one service) |
| 28 | T1187 | Forced Authentication (outbound SMB/NTLM auth to external IP — relay/capture) |
| 29 | T1557.001 | Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning (spoofed responses on UDP 5355/137) |
| 30 | T1557.003 | Adversary-in-the-Middle: DHCP Spoofing (multiple DHCP Offer from different MACs) |
| 31 | T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting (TGS-REQ burst for SPNs on port 88) |

### Collection

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 32 | T1114.002 | Email Collection: Remote Email Collection (IMAP/POP3 bulk download — many FETCH) |
| 33 | T1119 | Automated Collection (rapid sequential SMB/FTP file reads) |

### Command and Control

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 34 | T1071.002 | Application Layer Protocol: File Transfer Protocols (FTP commands in cleartext) |
| 35 | T1071.003 | Application Layer Protocol: Mail Protocols (SMTP/IMAP C2 commands) |
| 36 | T1090 | Proxy (SOCKS5 handshake / HTTP CONNECT method detection) |
| 37 | T1090.002 | Proxy: External Proxy (connections through known proxy service IPs) |
| 38 | T1090.004 | Proxy: Domain Fronting (TLS SNI vs HTTP Host header mismatch) |
| 39 | T1095 | Non-Application Layer Protocol (raw ICMP/TCP/UDP payload without app-layer headers) |
| 40 | T1102 | Web Service (C2 callbacks to pastebin/discord/telegram/slack API endpoints) |
| 41 | T1102.001 | Web Service: Dead Drop Resolver |
| 42 | T1102.002 | Web Service: Bidirectional Communication |
| 43 | T1102.003 | Web Service: One-Way Communication |
| 44 | T1104 | Multi-Stage Channels (sequential connections to different C2 servers) |
| 45 | T1132 | Data Encoding (Base64/hex-encoded payloads in HTTP body or DNS labels) |
| 46 | T1132.001 | Data Encoding: Standard Encoding (Base64 in HTTP body/URL/DNS) |
| 47 | T1132.002 | Data Encoding: Non-Standard Encoding (custom XOR/rotation in payload bytes) |
| 48 | T1001.001 | Data Obfuscation: Junk Data (padding/filler bytes in payload) |
| 49 | T1001.002 | Data Obfuscation: Steganography (deep image payload analysis beyond magic bytes) |
| 50 | T1001.003 | Data Obfuscation: Protocol Impersonation (fake HTTP/DNS structure on wrong port) |
| 51 | T1008 | Fallback Channels (session switches between multiple C2 endpoints) |
| 52 | T1568 | Dynamic Resolution |
| 53 | T1568.001 | Dynamic Resolution: Fast Flux DNS (rapid A-record IP rotation in DNS responses) |
| 54 | T1568.002 | Dynamic Resolution: Domain Generation Algorithms (high-entropy NXDomain query bursts) |
| 55 | T1568.003 | Dynamic Resolution: DNS Calculation (computed domain from seed in DNS queries) |
| 56 | T1572 | Protocol Tunneling (SSH tunnels, DNS-over-HTTPS, ICMP data tunnels) |
| 57 | T1573.001 | Encrypted Channel: Symmetric Cryptography (high-entropy payload on non-TLS port) |
| 58 | T1573.002 | Encrypted Channel: Asymmetric Cryptography (JA3S fingerprint + certificate anomalies) |
| 59 | T1205 | Traffic Signaling (specific port-sequence patterns before C2 activation) |
| 60 | T1205.001 | Traffic Signaling: Port Knocking (ordered SYN packets to closed ports) |
| 61 | T1219 | Remote Access Software (connections to TeamViewer/AnyDesk/ngrok relay servers by SNI) |

### Exfiltration

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 62 | T1048 | Exfiltration Over Alternative Protocol (data on unexpected protocol/port) |
| 63 | T1048.001 | Exfiltration Over Symmetric Encrypted Non-C2 Protocol |
| 64 | T1048.002 | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol |
| 65 | T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol |
| 66 | T1567 | Exfiltration Over Web Service (large uploads to cloud/web services) |
| 67 | T1567.001 | Exfiltration Over Web Service: Exfiltration to Code Repository |
| 68 | T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage |
| 69 | T1567.004 | Exfiltration Over Web Service: Exfiltration Over Webhook |
| 70 | T1020 | Automated Exfiltration (periodic large outbound transfers) |
| 71 | T1029 | Scheduled Transfer (time-of-day exfil patterns in pcap timestamps) |
| 72 | T1030 | Data Transfer Size Limits (many small chunked transfers to same destination) |

### Impact

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 73 | T1498 | Network Denial of Service (volumetric flood detection) |
| 74 | T1498.001 | Network Denial of Service: Direct Network Flood |
| 75 | T1498.002 | Network Denial of Service: Reflection Amplification (DNS/NTP/memcached amplification) |
| 76 | T1499 | Endpoint Denial of Service |
| 77 | T1499.001 | Endpoint Denial of Service: OS Exhaustion Flood (SYN flood) |
| 78 | T1499.002 | Endpoint Denial of Service: Service Exhaustion Flood |
| 79 | T1499.003 | Endpoint Denial of Service: Application Exhaustion Flood (HTTP flood) |

### Defense Evasion (network-level)

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 80 | T1600 | Weaken Encryption (TLS downgrade — weak cipher suites in ServerHello) |
| 81 | T1600.001 | Weaken Encryption: Reduce Key Space (short key lengths in TLS negotiation) |
| 82 | T1553.004 | Subvert Trust Controls: Install Root Certificate (unknown/self-signed CA in TLS chain) |
| 83 | T1027.009 | Obfuscated Files or Information: Embedded Payloads (PE/ELF magic bytes in HTTP response) |

### Other network-observable

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 84 | T1542.003 | Pre-OS Boot: Bootkit (anomalous TFTP traffic on UDP 69) |
| 85 | T1602 | Data from Configuration Repository (SNMP community string brute force on UDP 161) |
| 86 | T1602.001 | Data from Configuration Repository: SNMP (bulk GET-NEXT/WALK on UDP 161) |
| 87 | T1602.002 | Data from Configuration Repository: Network Device CLI (Telnet cleartext on port 23) |
