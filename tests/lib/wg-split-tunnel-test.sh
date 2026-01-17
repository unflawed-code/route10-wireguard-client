#!/bin/sh

# test.sh - Verification script for WG Split Tunnel
# Usage: ./test.sh <interface> <domain>

INTERFACE="$1"
DOMAIN="$2"

if [ -z "$INTERFACE" ] || [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <interface> <domain>"
    exit 1
fi

echo "=== Testing Split Tunnel for $INTERFACE ($DOMAIN) ==="

# 1. Interface Check
if ip link show "$INTERFACE" >/dev/null 2>&1; then
    echo "[PASS] Interface $INTERFACE is UP"
else
    echo "[FAIL] Interface $INTERFACE is DOWN or missing"
    exit 1
fi

# 2. WireGuard Handshake Check
# Dump format: public_key preshared_key endpoint allowed_ips latest_handshake transfer_rx transfer_tx persistent_keepalive
# Use tail -n 1 to get the peer line (first line is interface)
LATEST_HANDSHAKE_EPOCH=$(wg show "$INTERFACE" dump | tail -n 1 | awk '{print $5}')
CURRENT_EPOCH=$(date +%s)
AGE=$((CURRENT_EPOCH - LATEST_HANDSHAKE_EPOCH))

if [ "$AGE" -lt 180 ] 2>/dev/null; then
    echo "[PASS] Handshake active ($AGE seconds ago)"
else
    echo "[WARN] Handshake might be stale (last: $AGE seconds ago)"
fi

# 3. Routing Rules (Priority 50)
if ip rule show | grep -q "lookup 200"; then
    echo "[PASS] PBR Routing rules (table 200) exist"
else
    echo "[FAIL] PBR Routing rules missing!"
fi

if ip rule show | grep -q "^49:"; then
    echo "[PASS] DNS Force-Routing rules (priority 49) exist"
else
    echo "[WARN] DNS Force-Routing rules missing (might be optional)"
fi

# 4. Firewall Forwarding
if iptables -S FORWARD | grep -q -- "-o $INTERFACE -j ACCEPT"; then
    echo "[PASS] Firewall FORWARD allow rule exists"
else
    echo "[FAIL] Firewall FORWARD allow rule missing!"
fi

# 5. IPSet / DNS Check
echo "Resolving $DOMAIN to trigger IPSet population..."
IP=$(nslookup "$DOMAIN" 127.0.0.1 | tail -n +3 | grep "Address" | awk '{print $3}' | head -n 1)

if [ -n "$IP" ]; then
    echo "Resolved $DOMAIN to $IP"
    sleep 1
    # Check IPSet
    IPSET_NAME="dst_vpn_${INTERFACE}"
    if ipset list "$IPSET_NAME" 2>/dev/null | grep -q "$IP"; then
        echo "[PASS] IP $IP found in ipset $IPSET_NAME"
    else
        echo "[FAIL] IP $IP NOT found in ipset $IPSET_NAME"
        echo "Current ipset contents:"
        ipset list "$IPSET_NAME" | head -5
    fi
else
    echo "[FAIL] Could not resolve $DOMAIN using local DNS"
fi

echo "=== Test Complete ==="

# 6. IPv6 Leak Protection & Bypass Verification
echo "Checking IPv6 rules in chain split_${INTERFACE}..."

# Check for VPN skip rules (should always exist for vpn6_*)
if ip6tables -t mangle -S "split_${INTERFACE}" 2>/dev/null | grep -q "vpn6_.*RETURN"; then
    echo "[PASS] IPv6 VPN skip rules (RETURN) found"
else
    # It might be valid if no other VPNs exist yet, but we expect the mechanism to be there.
    # Actually the script loop over `ipset list`, so if no vpn6 ipsets exist, no rules are added.
    # We should at least check if the chain exists.
    if ip6tables -t mangle -L "split_${INTERFACE}" -n >/dev/null 2>&1; then
        echo "[PASS] Split-tunnel IPv6 chain exists"
    else
        echo "[FAIL] Split-tunnel IPv6 chain missing"
    fi
fi

# Check for DROP or MARK rule
if ip6tables -t mangle -S "split_${INTERFACE}" 2>/dev/null | grep -q -- "-j DROP"; then
    echo "[INFO] IPv6 DROP rule found (IPv6 blocking active - correct for IPv4-only tunnel)"
elif ip6tables -t mangle -S "split_${INTERFACE}" 2>/dev/null | grep -q -- "-j MARK"; then
    echo "[INFO] IPv6 MARK rule found (IPv6 routing active - correct for IPv6-enabled tunnel)"
else
    echo "[FAIL] Neither DROP nor MARK rule found for IPv6 (Potential LEAK!)"
fi
