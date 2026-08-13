#!/usr/bin/env bash
# Idempotent bring-up of the Threat-X scan targets: OWASP Juice Shop (app-layer findings
# for Nuclei/ZAP) and Metasploitable2 (network-layer findings for Nmap --script vuln).
#
# Juice Shop alone only exposes port 3000, so it gives Nmap almost nothing to scan.
# Metasploitable2 is added purely to give Nmap real CVEs to find (e.g. vsftpd 2.3.4
# backdoor CVE-2011-2523, distccd CVE-2004-2687). It is deliberately vulnerable and
# unpatched by design — keep it on the isolated `threatx-net` bridge network only,
# never publish its ports to the host or the internet.
#
# Requires Docker running locally. Run this on your own machine, not inside a sandboxed
# CI/agent environment without a docker daemon.
set -euo pipefail

NETWORK="threatx-net"
JUICE_SHOP_IMAGE="bkimminich/juice-shop"
METASPLOITABLE_IMAGE="${METASPLOITABLE_IMAGE:-tleemcjr/metasploitable2}"

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker daemon is not reachable. Start Docker and re-run this script." >&2
  exit 1
fi

if ! docker network inspect "$NETWORK" >/dev/null 2>&1; then
  echo "Creating docker network $NETWORK..."
  docker network create "$NETWORK"
else
  echo "Network $NETWORK already exists, skipping."
fi

if ! docker inspect juice-shop >/dev/null 2>&1; then
  echo "Starting juice-shop container..."
  docker run -d --name juice-shop --network "$NETWORK" -p 3000:3000 "$JUICE_SHOP_IMAGE"
else
  echo "Container juice-shop already exists, ensuring it's running..."
  docker start juice-shop >/dev/null
fi

if ! docker inspect metasploitable >/dev/null 2>&1; then
  echo "Starting metasploitable container..."
  docker run -d --name metasploitable --network "$NETWORK" "$METASPLOITABLE_IMAGE"
else
  echo "Container metasploitable already exists, ensuring it's running..."
  docker start metasploitable >/dev/null
fi

echo "Waiting for containers to warm up..."
sleep 5

JUICE_IP=$(docker inspect -f "{{.NetworkSettings.Networks.${NETWORK}.IPAddress}}" juice-shop)
META_IP=$(docker inspect -f "{{.NetworkSettings.Networks.${NETWORK}.IPAddress}}" metasploitable)

echo ""
echo "Targets ready:"
echo "  juice-shop      http://localhost:3000  (internal IP: $JUICE_IP)"
echo "  metasploitable  internal IP: $META_IP"
echo ""
echo "export JUICE_IP=$JUICE_IP"
echo "export META_IP=$META_IP"

# Persist for other scripts in this session (e.g. run_scanners.py) to source.
cat > "$(dirname "$0")/../data/.target_env" <<EOF
JUICE_IP=$JUICE_IP
META_IP=$META_IP
EOF
