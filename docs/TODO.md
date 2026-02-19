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

| № | Код MITRE | Название техники |
| --- | --- | --- |
| 1 | T1071.002 | Application Layer Protocol: File Transfer Protocols (FTP/FTPS) |
| 2 | T1071.003 | Application Layer Protocol: Mail Protocols (SMTP/IMAP/POP3) |
| 3 | T1090 | Proxy (SOCKS/HTTP CONNECT proxy detection) |
| 4 | T1090.001 | Proxy: Internal Proxy |
| 5 | T1090.002 | Proxy: External Proxy |
| 6 | T1090.003 | Proxy: Multi-hop Proxy |
| 7 | T1095 | Non-Application Layer Protocol (raw TCP/UDP/ICMP C2) |
| 8 | T1102 | Web Service (C2 via known cloud/web services) |
| 9 | T1104 | Multi-Stage Channels |
| 10 | T1110.001 | Brute Force: Password Guessing (repeated auth on same port) |
| 11 | T1110.003 | Brute Force: Password Spraying (single password, many targets) |
| 12 | T1110.004 | Brute Force: Credential Stuffing |
| 13 | T1133 | External Remote Services (VPN/RDP/SSH from external) |
| 14 | T1205 | Traffic Signaling (port knocking) |
| 15 | T1205.001 | Traffic Signaling: Port Knocking |
| 16 | T1048 | Exfiltration Over Alternative Protocol |
| 17 | T1048.001 | Exfiltration Over Symmetric Encrypted Non-C2 Protocol |
| 18 | T1048.002 | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol |
| 19 | T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol |
| 20 | T1572 | Protocol Tunneling (SSH tunnels, DNS-over-HTTPS, ICMP tunnels) |
| 21 | T1568 | Dynamic Resolution |
| 22 | T1568.001 | Dynamic Resolution: Fast Flux DNS |
| 23 | T1568.002 | Dynamic Resolution: Domain Generation Algorithms (DGA) |
| 24 | T1568.003 | Dynamic Resolution: DNS Calculation |
| 25 | T1498 | Network Denial of Service (volumetric flood detection) |
| 26 | T1498.001 | Network Denial of Service: Direct Network Flood |
| 27 | T1499 | Endpoint Denial of Service |
| 28 | T1499.001 | Endpoint Denial of Service: OS Exhaustion Flood (SYN flood) |
| 29 | T1499.002 | Endpoint Denial of Service: Service Exhaustion Flood |
| 30 | T1021.001 | Remote Services: Remote Desktop Protocol (RDP) |
| 31 | T1021.002 | Remote Services: SMB/Windows Admin Shares (lateral PsExec) |
| 32 | T1021.004 | Remote Services: SSH |
| 33 | T1021.005 | Remote Services: VNC |
| 34 | T1021.006 | Remote Services: Windows Remote Management (WinRM) |
| 35 | T1219 | Remote Access Software (TeamViewer, AnyDesk, etc.) |
| 36 | T1001.001 | Data Obfuscation: Junk Data |
| 37 | T1001.002 | Data Obfuscation: Steganography (deep image analysis) |
| 38 | T1001.003 | Data Obfuscation: Protocol Impersonation |
| 39 | T1132 | Data Encoding (Base64/custom encoding in payloads) |
| 40 | T1132.001 | Data Encoding: Standard Encoding |
| 41 | T1132.002 | Data Encoding: Non-Standard Encoding |
| 42 | T1008 | Fallback Channels (multiple C2 endpoints) |
| 43 | T1573.001 | Encrypted Channel: Symmetric Cryptography |
| 44 | T1573.002 | Encrypted Channel: Asymmetric Cryptography (JA3S, cert anomalies) |
| 45 | T1571 | Non-Standard Port (expand: dynamic port profiling beyond 4 ports) |
| 46 | T1557.001 | Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning |
| 47 | T1557.002 | Adversary-in-the-Middle: ARP Cache Poisoning (rate-based) |
| 48 | T1557.003 | Adversary-in-the-Middle: DHCP Spoofing |
| 49 | T1040 | Network Sniffing (promiscuous mode detection via ARP) |
| 50 | T1018 | Remote System Discovery (NetBIOS/LLMNR enumeration) |
| 51 | T1016 | System Network Configuration Discovery (DHCP/DNS recon) |
| 52 | T1049 | System Network Connections Discovery (net session enum via SMB) |
| 53 | T1567 | Exfiltration Over Web Service |
| 54 | T1567.001 | Exfiltration Over Web Service: Exfiltration to Code Repository |
| 55 | T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage (deep) |
| 56 | T1020 | Automated Exfiltration (periodic large transfers) |
| 57 | T1030 | Data Transfer Size Limits (chunked exfil detection) |
| 58 | T1599 | Network Boundary Bridging |
| 59 | T1599.001 | Network Boundary Bridging: Network Address Translation Traversal |
| 60 | T1187 | Forced Authentication (SMB relay / NTLM capture) |
| 61 | T1210 | Exploitation of Remote Services (exploit payload signatures) |
| 62 | T1570 | Lateral Tool Transfer (internal file copy via SMB/WinRM) |
| 63 | T1563 | Remote Service Session Hijacking |
| 64 | T1563.001 | Remote Service Session Hijacking: SSH Hijacking |
| 65 | T1563.002 | Remote Service Session Hijacking: RDP Hijacking |
| 66 | T1542.003 | Pre-OS Boot: Bootkit (TFTP/PXE anomalies) |
| 67 | T1583.006 | Acquire Infrastructure: Web Services (known C2 infra IPs) |
| 68 | T1102.001 | Web Service: Dead Drop Resolver |
| 69 | T1102.002 | Web Service: Bidirectional Communication |
| 70 | T1659 | Content Injection (HTTP response injection / iframe inject) |
