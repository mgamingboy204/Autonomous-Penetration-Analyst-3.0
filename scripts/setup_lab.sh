#!/usr/bin/env bash
set -euo pipefail
cat <<'TEXT'
[Lab Setup - VirtualBox Host-Only]
1. Create Host-Only Adapter (vboxnet0) with 192.168.56.1/24.
2. Kali NIC1: Host-Only Adapter -> vboxnet0, IP 192.168.56.10/24.
3. Metasploitable2 NIC1: Host-Only Adapter -> vboxnet0, IP 192.168.56.101/24.
4. Optional targets: DVWA 192.168.56.102, Juice Shop 192.168.56.103.
5. Keep demo traffic on host-only network.
6. Restrict config/whitelist.txt to authorized assets.
TEXT
