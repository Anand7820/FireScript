# ==============================================================================
# FireScript Enterprise Security Policy Demo (Multi-Tier Cloud Datacenter)
# ==============================================================================
# Use this demo file to showcase FireScript's static rule conflict analysis:
#   - SHADOWED rules (hidden dead code from misplaced broad policies)
#   - REDUNDANT rules (duplicate / useless entries)
#   - CONTRADICTION (overlapping IP/Port policies with opposing verdicts)
#   - GENERALIZATION (specific exceptions followed by defense-in-depth blocks)
# ==============================================================================

# 1. Threat Intelligence Blacklist (Known Malicious Subnets)
deny any from 198.51.100.0/24 to any port any
deny any from 203.0.113.0/24 to any port any

# 2. Public Web / DMZ Tier (HTTP & HTTPS)
allow tcp from any to any port 80
allow tcp from any to any port 443
allow tcp from any to any port 80                      # [REDUNDANT: duplicate of line 12]

# 3. Remote Management & SSH Bastion Access
# Emergency lockdown applied globally:
deny tcp from any to any port 22
# Specific admin workstations added later (SHADOWED: blocked by line 17!):
allow tcp from 192.168.1.50/32 to any port 22         # [SHADOWED: admin locked out]
allow tcp from 10.200.0.0/24 to any port 22           # [SHADOWED: jumpbox blocked]

# 4. Internal Microservices & API Gateway
allow tcp from 10.10.0.0/16 to any port 8080          # Specific service
deny  tcp from 10.10.0.0/16 to any port 8000-8080     # [GENERALIZATION: broad range block]

# 5. Production Database Tier (PostgreSQL & Redis)
allow tcp from 10.0.0.0/8 to any port 5432            # Broad internal VPC allow
deny  tcp from 10.50.0.0/16 to any port 5432          # [SHADOWED: analytics subnet blocked]
allow tcp from 10.0.10.0/24 to any port 6379
allow tcp from 10.0.10.0/24 to any port 6379          # [REDUNDANT: duplicate rule]

# 6. Core Infrastructure Services (DNS & NTP)
allow udp from 1.1.1.1/32 to any port 53
allow udp from 8.8.8.8/32 to any port 53
allow udp from any to any port 123

# 7. Partner API Exception vs Blacklist
allow tcp from 198.51.100.25/32 to any port 443       # [SHADOWED: blocked by line 8 blacklist]

# 8. Zero-Trust Default Boundary
deny any from any to any port any
