# Sample FireScript rules
allow tcp from 10.0.0.0/24 to any port 80
allow tcp from 10.0.0.0/24 to any port 443
allow udp from any to 8.8.8.8 port 53
deny  tcp from any to any port 22
allow tcp from 10.0.0.5 to any port 22
deny  any from any to any port any
