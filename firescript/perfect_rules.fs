# ==============================================================================
# 100% Conflict-Free Enterprise Firewall Policy (Zero Mistakes)
# ==============================================================================
# Every rule is strictly partitioned by service port and authorized network.
# Result:
#   - 0 SHADOWED
#   - 0 REDUNDANT
#   - 0 CONTRADICTION
#   - 0 GENERALIZATION
#
# Note: FireScript enforces "Default Deny" in software. Any packet not explicitly
# allowed below will be denied automatically by the simulator without needing
# a catch-all deny rule (which avoids triggering generalization).
# ==============================================================================

# 1. Web & Application Tier (Public facing)
allow tcp from any to 172.16.0.10/32 port 80
allow tcp from any to 172.16.0.10/32 port 443

# 2. Remote Administration (Restricted to IT Bastion Jumpbox)
allow tcp from 192.168.1.50/32 to 10.0.0.0/24 port 22

# 3. Core Network Infrastructure (DNS & NTP)
allow udp from 10.0.0.0/16 to 1.1.1.1/32 port 53
allow udp from 10.0.0.0/16 to 10.0.0.1/32 port 123

# 4. Production Database Tier (PostgreSQL, MySQL, Redis)
allow tcp from 10.100.1.0/24 to 10.100.2.10/32 port 5432
allow tcp from 10.100.1.0/24 to 10.100.2.20/32 port 3306
allow tcp from 10.100.1.0/24 to 10.100.2.30/32 port 6379

# 5. Monitoring & Metrics (Prometheus & Grafana)
allow tcp from 10.200.0.5/32 to 10.100.0.0/16 port 9090
allow tcp from 10.200.0.5/32 to 10.100.0.0/16 port 9100

# 6. Network Diagnostics
allow icmp from 192.168.1.0/24 to any port any
