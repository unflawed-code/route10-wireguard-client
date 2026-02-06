#!/bin/sh

# test.sh - Verification script for WG Split Tunnel
# Usage: ./test.sh <interface> <domain> [direct_ipv4] [direct_ipv6]

INTERFACE="$1"
DOMAIN="$2"

if [ -z "$INTERFACE" ] || [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <interface> <domain> [direct_ipv4] [direct_ipv6]"
    echo ""
    echo "Arguments:"
    echo "  interface    - WireGuard interface name"
    echo "  domain       - Domain to test DNS-based ipset population"
    echo "  direct_ipv4  - (Optional) IPv4 address passed to -d to verify direct ipset add"
    echo "  direct_ipv6  - (Optional) IPv6 address passed to -d to verify direct ipset add"
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

# 4. Routing Rules
# Get routing table ID from database
ROUTING_TABLE=$(sqlite3 "/tmp/wg-custom/wg_pbr.db" "SELECT routing_table FROM interfaces WHERE name='$INTERFACE';" 2>/dev/null)

if [ -n "$ROUTING_TABLE" ]; then
    # Get the expected mark for this interface
    MARK=$((0x10000 + ROUTING_TABLE))
    MASKED_MARK_HEX=$(printf "0x%x/0x%x" "$MARK" "$MARK")
    
    # Check if a rule exists for this masked mark pointing to the correct table
    if ip rule show | grep -q "fwmark $MASKED_MARK_HEX lookup $ROUTING_TABLE"; then
        echo "[PASS] Masked PBR Routing rules (mark $MASKED_MARK_HEX -> table $ROUTING_TABLE) exist"
    else
        echo "[FAIL] Masked PBR Routing rules for table $ROUTING_TABLE missing or incorrect format!"
        echo "       Expected: fwmark $MASKED_MARK_HEX lookup $ROUTING_TABLE"
        echo "       Current rules:"
        ip rule show | grep "lookup $ROUTING_TABLE"
    fi
else
    echo "[FAIL] Could not find routing table for $INTERFACE in database"
fi

# Check for OUTPUT chain DNS marking (split-tunnel uses INSERT at position 1 for priority)
# This verifies the split-tunnel interface has OUTPUT marking for its DNS servers
if iptables -t mangle -S OUTPUT 2>/dev/null | grep -q -- "--dport 53.*MARK.*0x100"; then
    echo "[PASS] OUTPUT chain DNS marking rules exist for split-tunnel"
else
    echo "[WARN] OUTPUT chain DNS marking rules missing for split-tunnel"
fi

# 4. Firewall Forwarding
if iptables -S FORWARD | grep -q -- "-o $INTERFACE -j ACCEPT"; then
    echo "[PASS] Firewall FORWARD allow rule exists"
else
    echo "[FAIL] Firewall FORWARD allow rule missing!"
fi

# 5. IPSet / DNS Check
echo "Resolving $DOMAIN to trigger IPSet population..."
# Try resolving without forcing 127.0.0.1 first, as dnsmasq might bind elsewhere (e.g. ::1)
IP=$(nslookup "$DOMAIN" | tail -n +3 | grep "Address" | awk '{print $3}' | head -n 1)

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
    # Check dedicated dnsmasq process is running
    DED_PID_FILE="/tmp/wg-custom/${INTERFACE}-split-dnsmasq.pid"
    if [ -f "$DED_PID_FILE" ] && kill -0 $(cat "$DED_PID_FILE") 2>/dev/null; then
        echo "[PASS] Dedicated dnsmasq process running for $INTERFACE"
    else
        echo "[WARN] Dedicated dnsmasq process not found"
    fi
    
    # Check stub file exists in /tmp/dnsmasq.d/
    STUB_CONF="/tmp/dnsmasq.d/${INTERFACE}-split-stub.conf"
    if [ -f "$STUB_CONF" ]; then
        STUB_PORT=$(grep "server=/" "$STUB_CONF" | head -1 | sed 's/.*#\([0-9]*\)/\1/')
        echo "[PASS] Stub config exists, forwarding to port $STUB_PORT"
    else
        echo "[FAIL] Stub config $STUB_CONF missing - Main Dnsmasq won't forward to dedicated instance"
    fi
else
    echo "[FAIL] Could not resolve $DOMAIN using local DNS"
fi

# 6. Direct IP Address Check (TLS certificate discovery feature)
DIRECT_IP="$3"
DIRECT_IP6="$4"

if [ -n "$DIRECT_IP" ]; then
    echo ""
    echo "=== Testing TLS Certificate Discovery Feature ==="
    IPSET_NAME="dst_vpn_${INTERFACE}"
    DNSMASQ_CONF="/tmp/dnsmasq.d/${INTERFACE}-split.conf"
    
    # Check if IP is in ipset (means TLS succeeded)
    if ipset list "$IPSET_NAME" 2>/dev/null | grep -q "$DIRECT_IP"; then
        echo "[PASS] IPv4 $DIRECT_IP found in ipset (TLS discovery succeeded)"
        
        # Check if a domain was discovered and added to dnsmasq
        if [ -f "$DNSMASQ_CONF" ]; then
            # Look for any server= line that's not the explicitly provided domains
            DISCOVERED=$(grep "server=/" "$DNSMASQ_CONF" | grep -v "$DOMAIN" | head -1 | sed 's/server=\/\([^/]*\).*/\1/')
            if [ -n "$DISCOVERED" ]; then
                echo "[PASS] Auto-discovered domain from TLS: $DISCOVERED"
            else
                echo "[INFO] No additional domain discovered (might be same as test domain)"
            fi
        fi
    else
        echo "[INFO] IPv4 $DIRECT_IP NOT in ipset (TLS discovery failed or IP rejected)"
        echo "       This is expected if the IP has no valid TLS certificate"
    fi
fi

if [ -n "$DIRECT_IP6" ]; then
    IPSET6_NAME="dst6_vpn_${INTERFACE}"
    
    if ipset list "$IPSET6_NAME" 2>/dev/null | grep -q "$DIRECT_IP6"; then
        echo "[PASS] IPv6 $DIRECT_IP6 found in ipset (TLS discovery succeeded)"
    else
        echo "[INFO] IPv6 $DIRECT_IP6 NOT in ipset (TLS discovery failed or IP rejected)"
    fi
fi

echo "=== Test Complete ==="

# 7. IPv6 Leak Protection & Bypass Verification
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

# 8. Check for conflicting OUTPUT DNS marking from target-IP interfaces
# This was a bug where target-IP interfaces added OUTPUT marking for DNS servers
# which conflicted with split-tunnel when using same DNS server IPs (e.g., SurfShark anycast)
echo ""
echo "=== Testing for DNS Routing Conflicts ==="

# Get the DNS servers configured for this split-tunnel interface
DED_CONF="/tmp/wg-custom/${INTERFACE}-split-dnsmasq.conf"
if [ -f "$DED_CONF" ]; then
    DNS_SERVERS=$(grep "^server=" "$DED_CONF" | sed 's/server=\([^@]*\).*/\1/')
    
    # Get the expected mark for this interface
    EXPECTED_MARK=$(printf "0x100%02x" "$ROUTING_TABLE" 2>/dev/null)
    
    for dns in $DNS_SERVERS; do
        # Skip IPv6 for this test
        echo "$dns" | grep -q ":" && continue
        
        # Check if any OTHER interface has OUTPUT marking for this DNS server
        OTHER_MARKS=$(iptables-save -t mangle | grep "OUTPUT.*-d $dns" | grep "dport 53.*MARK" | grep -v "$EXPECTED_MARK" | wc -l)
        
        if [ "$OTHER_MARKS" -gt 0 ]; then
            echo "[FAIL] Conflicting OUTPUT DNS marking for $dns from other interfaces!"
            echo "       Other marks: $(iptables-save -t mangle | grep "OUTPUT.*-d $dns" | grep "dport 53.*MARK" | grep -v "$EXPECTED_MARK")"
        else
            echo "[PASS] No conflicting OUTPUT DNS marking for $dns"
        fi
    done
else
    echo "[INFO] No dedicated dnsmasq config found - skipping conflict check"
fi

echo "=== Test Complete ==="
