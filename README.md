# Using-Firewall-IDS-IPS-For-Protection

# Advanced Enterprise Network Security Architecture: IPS, WAF & Stateful Firewall

##  Project Overview
This project demonstrates the design and implementation of a secure 3-tier virtualized network topology (Gateway, Internal Trust Zone, and DMZ). The architecture enforces a strict "Defense in Depth" strategy, utilizing kernel-level mitigations, a Stateful Firewall (`iptables`), a Web Application Firewall (`ModSecurity`), and an Intrusion Prevention System (`Snort` in inline mode) to actively detect and block network attacks.

**Technologies Used:** Kali Linux, Debian, `iptables` (Stateful Inspection, NAT, Port Forwarding), Snort IPS (NFQUEUE), ModSecurity (WAF), `hping3`, `nmap`, `hydra`, `tcpdump`.

---

##  Network Topology & Architecture
The network consists of three isolated virtual machines, routing all internal and external traffic through a centralized Linux Gateway for packet inspection and Network Address Translation (NAT).

| Hostname | Interface | IP Address | Subnet Role | Description |
| :--- | :--- | :--- | :--- | :--- |
| **VM1 (Gateway)** | `eth0` | DHCP/NAT | External | Internet Facing Interface |
| | `eth1` | `10.0.0.1` | Internal Zone (ITZ) | Gateway for Corporate LAN |
| | `eth2` | `10.1.0.1` | DMZ | Gateway for Public Services |
| **VM2 (ITZ)** | `eth0` | `10.0.0.10` | Internal Zone (ITZ) | Secure Corporate Client |
| **VM3 (DMZ)** | `eth0` | `10.1.0.10` | DMZ | Public Web & FTP Server |

---

## Phase 1: Gateway Configuration & Routing (Layer 3)
To enable the Gateway to route traffic between isolated networks while providing internet access, IP forwarding and NAT (Masquerade) were enabled.

```bash
# Enable IP Forwarding on the Gateway
sudo sysctl -w net.ipv4.ip_forward=1

# Enable NAT for internal networks to access the internet
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```
Phase 2: Stateful Firewall & Port Forwarding (Layer 4)
A strict "Default Deny" policy was implemented using iptables. All forwarding is blocked by default, and only explicitly defined traffic is allowed.

1. Stateful Inspection & DNAT
The firewall permits outbound traffic from the internal network and tracks established connections to safely route return traffic. Destination NAT (Port Forwarding) exposes the DMZ Web Server to the internet
```bash
# Drop invalid packets and allow established/related connections
sudo iptables -A FORWARD -m conntrack --ctstate INVALID -j DROP
sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Port Forwarding (DNAT) to Web Server (Port 80) in DMZ
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j DNAT --to-destination 10.1.0.10:80
sudo iptables -A FORWARD -i eth0 -o eth2 -p tcp --dport 80 -d 10.1.0.10 -m conntrack --ctstate NEW -j ACCEPT
```
2. Log & Drop Policy (BLACKHOLE Chain)
Unauthorized traffic is routed to a custom BLACKHOLE chain, where it is rate-limited, logged to the kernel, and then dropped silently to prevent log flooding.
```bash
# Custom Logging and Dropping Chain
sudo iptables -A FORWARD -j BLACKHOLE 
sudo iptables -A BLACKHOLE -m limit --limit 2/sec -j LOG --log-prefix "ALERT: " --log-level 4 
sudo iptables -A BLACKHOLE -j DROP
```
Phase 3: Application Layer Protection (WAF)
To protect the Apache Web Server in the DMZ from Layer 7 attacks (e.g., Cross-Site Scripting, SQL Injection), ModSecurity was installed and configured in active blocking mode (SecRuleEngine On).

Validation: An XSS attack simulation curl "http://[Gateway-IP]/?test=<script>" successfully triggered a 403 Forbidden response, proving the WAF intercepted the payload.

Phase 4: Threat Simulation & Kernel Mitigation (Red vs. Blue)
Various volumetric and reconnaissance attacks were launched via Kali Linux to test the resilience of the architecture.

1. SYN Flood Attack (DoS) & Mitigation
Attack: sudo hping3 -S -p 80 --flood [Gateway-IP]

Defense: Enabled TCP SYN Cookies at the kernel level to prevent memory exhaustion from half-open connections.
```bash
echo "net.ipv4.tcp_syncookies=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```
2. Stealth Port Scanning & Dynamic Blacklisting
Attack: nmap -F -T4 -sS -Pn [Gateway-IP]

Defense: Utilized the iptables recent module to create a dynamic "Hacker Trap", permanently dropping IPs that initiate more than 15 new connections within 60 seconds.
```bash
sudo iptables -I FORWARD 1 -m state --state NEW -m recent --update --seconds 60 --hitcount 15 --name SCANNER -j DROP 
sudo iptables -I FORWARD 2 -m state --state NEW -m recent --set --name SCANNER
```
Phase 5: Deep Packet Inspection via Snort IPS (Inline Mode)
To provide true Deep Packet Inspection (DPI) without dismantling the existing iptables firewall, Snort was deployed as an Intrusion Prevention System (IPS) in inline mode using NFQUEUE.

Traffic is handed to Snort first; if the payload is safe, it is passed back to iptables for standard routing.
```bash
# Route incoming HTTP and FTP traffic to Snort via NFQUEUE
sudo iptables -I FORWARD 1 -j NFQUEUE --queue-num 0 

# Start Snort in inline IPS mode
sudo snort -Q --daq nfq -c /etc/snort/snort.lua -R /etc/snort/rules/local.rules -A cmg --daq-var queue=0
```
Custom Snort Rules Developed (local.rules)
Custom signatures were authored to detect and actively drop malicious payloads based on content, flags, and behavioral thresholds:
```bash
# Block FTP Brute Force (Hydra) based on connection rate and payload
drop tcp any any -> 10.1.0.10 21 (msg:"[IPS] FTP Hydra BruteForce Blocked!"; content:"USER"; detection_filter:track by_src, count 3, seconds 10; sid:1000002; rev:4;) 

# Block Volumetric DoS / SYN Floods (Stateless for memory efficiency)
drop tcp any any -> 10.1.0.10 80 (msg:"[IPS] Siege/Hping3 SYN Flood KILLED!"; flags:S; flow:stateless; detection_filter:track by_src, count 20, seconds 2; classtype:denial-of-service; sid:1000004; rev:3;) 

# Block Application-Layer Stress Testing (Siege)
drop tcp any any -> 10.1.0.10 80 (msg:"[IPS] Siege Stress Testing Tool KILLED!"; content:"Siege/"; classtype:denial-of-service; sid:1000008; rev:3;) 

# Block Nmap Stealth Scans (XMAS, NULL, FIN)
drop tcp any any -> any any (msg:"[IPS] ET-Rule: Nmap XMAS Scan Blocked!"; flags:FPU; flow:stateless; classtype:attempted-recon; sid:1000010; rev:2;)
```
Conclusion: The integration of stateless firewall rules, stateful inspection, application-layer WAF, and Deep Packet Inspection (Snort IPS) successfully secured the DMZ and internal networks against Layer 3, 4, and 7 attacks, creating a highly robust enterprise defense architecture.





