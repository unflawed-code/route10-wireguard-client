#!/bin/sh
# Test script for assign-ips and remove-ips commands
# Run this from the router: cd /cfg/wg-custom && sh tests/plugins/05-manage-commands-test.sh

# Source test configuration
. "${0%/*}/../test.conf"
cd "$SCRIPT_ROOT"

# Discover running WireGuard interfaces from SQLite database
discover_interfaces() {
    sqlite3 "$WG_DB" "SELECT name FROM interfaces WHERE committed = 1 AND name != 'wgssla' ORDER BY name;" 2>/dev/null
}

# Discover IP-routing capable interfaces
discover_ip_routing_interfaces() {
    sqlite3 "$WG_DB" "SELECT name FROM interfaces WHERE committed = 1 AND (domains IS NULL OR domains = '' OR domains = 'none') AND name != 'wgssla' ORDER BY name;" 2>/dev/null
}

RUNNING_IFACES=$(discover_interfaces)
IFACE_COUNT=$(echo "$RUNNING_IFACES" | grep -c .)
IP_ROUTING_IFACES=$(discover_ip_routing_interfaces)
IP_ROUTING_COUNT=$(echo "$IP_ROUTING_IFACES" | grep -c . 2>/dev/null || echo "0")

echo "=========================================="
echo " WireGuard Interface Detection"
echo "=========================================="
echo ""

if [ "$IFACE_COUNT" -eq 0 ]; then
    echo "${RED}ERROR${NC}: No running WireGuard interfaces found."
    exit 1
fi

IFACE_A=$(echo "$IP_ROUTING_IFACES" | sed -n '1p')
IFACE_B=$(echo "$IP_ROUTING_IFACES" | sed -n '2p')
IFACE_IPV6=$(sqlite3 "$WG_DB" "SELECT name FROM interfaces WHERE ipv6_support = 1 AND (domains IS NULL OR domains = '' OR domains = 'none') LIMIT 1;" 2>/dev/null)
IFACE_IPV4_ONLY=$(sqlite3 "$WG_DB" "SELECT name FROM interfaces WHERE (ipv6_support = 0 OR ipv6_support IS NULL) AND (domains IS NULL OR domains = '' OR domains = 'none') LIMIT 1;" 2>/dev/null)

log_info "Found $IFACE_COUNT running interface(s)"
log_info "Found $IP_ROUTING_COUNT IP-routing capable interface(s)"
log_info "Primary interface (IP routing): $IFACE_A"
[ -n "$IFACE_B" ] && log_info "Secondary interface (IP routing): $IFACE_B"
[ -n "$IFACE_IPV6" ] && log_info "IPv6-enabled interface: $IFACE_IPV6"
[ -n "$IFACE_IPV4_ONLY" ] && log_info "IPv4-only interface: $IFACE_IPV4_ONLY"
echo ""

TEST_IFACE="wgtest_ips"
TEST_SPLIT_IFACE="wgtsplit"
TEST_IP1="10.99.0.1"
TEST_IP2="10.99.0.2"
TEST_SUBNET="10.99.1.0/24"

get_staged_targets() {
    sqlite3 "$WG_DB" "SELECT target_ips FROM interfaces WHERE name = '$1';" 2>/dev/null
}

interface_exists() {
    local count=$(sqlite3 "$WG_DB" "SELECT COUNT(*) FROM interfaces WHERE name = '$1';" 2>/dev/null)
    [ "$count" -gt 0 ]
}

get_staged_domains() {
    sqlite3 "$WG_DB" "SELECT domains FROM interfaces WHERE name = '$1';" 2>/dev/null
}

cleanup_all() {
    log_info "Running cleanup..."
    sqlite3 "$WG_DB" "DELETE FROM interfaces WHERE name IN ('${TEST_IFACE}', '${TEST_SPLIT_IFACE}');" 2>/dev/null
    rm -f "$TEST_CONF" 2>/dev/null
}

trap cleanup_all EXIT INT TERM
cleanup_all

cat > "$TEST_CONF" << 'EOF'
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.99.99.1/32
[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = 127.0.0.1:51820
AllowedIPs = 0.0.0.0/0
EOF

echo "=========================================="
echo " Testing assign-ips and remove-ips"
echo "=========================================="
echo ""

log_info "Staging test interface ${TEST_IFACE}..."
./wg-pbr.sh "$TEST_IFACE" --conf "$TEST_CONF" -r 250 -t none > /dev/null 2>&1
if interface_exists "$TEST_IFACE"; then
    log_pass "Test interface staged successfully"
else
    log_fail "Failed to stage test interface"
fi

log_info "Testing assign-ips with single IP ${TEST_IP1}..."
./wg-pbr.sh assign-ips "$TEST_IFACE" "$TEST_IP1" > /dev/null 2>&1
if get_staged_targets "$TEST_IFACE" | grep -q "$TEST_IP1"; then
    log_pass "assign-ips with single IP works"
else
    log_fail "assign-ips did not add $TEST_IP1"
fi

log_info "Testing assign-ips accumulation with ${TEST_IP2}..."
./wg-pbr.sh assign-ips "$TEST_IFACE" "$TEST_IP2" > /dev/null 2>&1
staged=$(get_staged_targets "$TEST_IFACE")
if echo "$staged" | grep -q "$TEST_IP1" && echo "$staged" | grep -q "$TEST_IP2"; then
    log_pass "assign-ips accumulates IPs correctly"
else
    log_fail "assign-ips did not accumulate IPs"
fi

log_info "Testing assign-ips with subnet ${TEST_SUBNET}..."
./wg-pbr.sh assign-ips "$TEST_IFACE" "$TEST_SUBNET" > /dev/null 2>&1
if get_staged_targets "$TEST_IFACE" | grep -q "10.99.1.0/24"; then
    log_pass "assign-ips with subnet works"
else
    log_fail "assign-ips did not add subnet $TEST_SUBNET"
fi

log_info "Testing remove-ips with single IP ${TEST_IP1}..."
./wg-pbr.sh remove-ips "$TEST_IFACE" "$TEST_IP1" > /dev/null 2>&1
if ! get_staged_targets "$TEST_IFACE" | grep -q "$TEST_IP1"; then
    log_pass "remove-ips removed single IP"
else
    log_fail "remove-ips did not remove $TEST_IP1"
fi

log_info "Testing remove-ips for last IP ${TEST_IP2}..."
./wg-pbr.sh remove-ips "$TEST_IFACE" "$TEST_IP2" > /dev/null 2>&1
./wg-pbr.sh remove-ips "$TEST_IFACE" "$TEST_SUBNET" > /dev/null 2>&1
staged=$(get_staged_targets "$TEST_IFACE")
if [ -z "$staged" ] || [ "$staged" = "none" ]; then
    log_pass "remove-ips handles removing all IPs (sets to none)"
else
    log_fail "remove-ips did not clear all IPs"
fi

echo ""
echo "=========================================="
echo " Testing MAC Address Support"
echo "=========================================="
echo ""

./wg-pbr.sh "$TEST_IFACE" --conf "$TEST_CONF" -r 250 -t none > /dev/null 2>&1
TEST_MAC="cc:dd:ee:ff:00:11"
TEST_MAC_IP="10.97.0.100"
ip neigh replace $TEST_MAC_IP lladdr $TEST_MAC dev br-lan nud reachable 2>/dev/null || true

log_info "Testing assign-ips with MAC address..."
./wg-pbr.sh assign-ips "$TEST_IFACE" "$TEST_MAC" > /dev/null 2>&1
if get_staged_targets "$TEST_IFACE" | grep -q "cc:dd:ee:ff:00:11=$TEST_MAC_IP"; then
    log_pass "assign-ips stored MAC in MAC=ip format"
else
    log_fail "assign-ips did not store MAC correctly"
fi

log_info "Testing status format for MAC targets..."
status_output=$(./wg-pbr.sh status "$TEST_IFACE")
if echo "$status_output" | grep -q "${TEST_MAC} -> ${TEST_MAC_IP}"; then
    log_pass "Status displays MAC targets correctly"
else
    log_fail "Status format for MAC target is incorrect"
fi

log_info "Testing remove-ips by IP for MAC target (should warn)..."
if ./wg-pbr.sh remove-ips "$TEST_IFACE" "$TEST_MAC_IP" 2>&1 | grep -q "WARN.*not found"; then
    log_pass "remove-ips by IP correctly warns for MAC target"
else
    log_fail "remove-ips by IP did not warn"
fi

log_info "Testing remove-ips by MAC..."
./wg-pbr.sh remove-ips "$TEST_IFACE" "$TEST_MAC" > /dev/null 2>&1
if ! get_staged_targets "$TEST_IFACE" | grep -q "cc:dd:ee:ff:00:11"; then
    log_pass "remove-ips by MAC successfully removed target"
else
    log_fail "remove-ips by MAC failed"
fi

ip neigh del $TEST_MAC_IP dev br-lan 2>/dev/null || true

echo ""
echo "=========================================="
echo " Testing IP Routing Verification"
echo "=========================================="
echo ""

ROUTING_TEST_IFACE="$IFACE_A"
ROUTING_TEST_IP="10.77.0.100"
ROUTING_TEST_SUBNET="10.77.1.0/24"

log_info "Testing ip rule creation..."
./wg-pbr.sh assign-ips "$ROUTING_TEST_IFACE" "$ROUTING_TEST_IP" > /dev/null 2>&1
./wg-pbr.sh commit > /dev/null 2>&1
if ip rule | grep -q "from $ROUTING_TEST_IP"; then
    log_pass "ip rule created for single IP"
else
    log_fail "ip rule NOT created"
fi

log_info "Testing DNS DNAT creation..."
if iptables -t nat -L "vpn_dns_nat_${ROUTING_TEST_IFACE}" -n 2>/dev/null | grep -q "$ROUTING_TEST_IP"; then
    log_pass "DNS DNAT rule created"
else
    log_fail "DNS DNAT rule NOT created"
fi

log_info "Cleaning up routing test rules..."
./wg-pbr.sh remove-ips "$ROUTING_TEST_IFACE" "$ROUTING_TEST_IP" > /dev/null 2>&1
./wg-pbr.sh commit > /dev/null 2>&1

echo ""
echo "=========================================="
echo " Testing IP Movement and Cleanup Fixes"
echo "=========================================="
echo ""

if [ -n "$IFACE_B" ]; then
    MOVE_TEST_IP="10.66.0.100"
    log_info "Moving $MOVE_TEST_IP between $IFACE_A and $IFACE_B..."
    ./wg-pbr.sh assign-ips "$IFACE_A" "$MOVE_TEST_IP" > /dev/null 2>&1
    ./wg-pbr.sh commit > /dev/null 2>&1
    ./wg-pbr.sh assign-ips "$IFACE_B" "$MOVE_TEST_IP" > /dev/null 2>&1
    ./wg-pbr.sh commit > /dev/null 2>&1
    
    if ip rule | grep -q "from $MOVE_TEST_IP.*${IFACE_B}_rt" && ! ip rule | grep -q "from $MOVE_TEST_IP.*${IFACE_A}_rt"; then
        log_pass "IP movement and cleanup works"
    else
        log_fail "IP movement failed or stale rule exists"
    fi
    ./wg-pbr.sh remove-ips "$IFACE_B" "$MOVE_TEST_IP" > /dev/null 2>&1
    ./wg-pbr.sh commit > /dev/null 2>&1
else
    log_skip "Movement tests require 2 IP-routing interfaces"
fi

echo ""
echo "=========================================="
echo " Testing IPv6/IPv4-Only Logic"
echo "=========================================="
echo ""

if [ -n "$IFACE_IPV4_ONLY" ]; then
    log_info "Verifying NO IPv6 chain for IPv4-only $IFACE_IPV4_ONLY..."
    if ! ip6tables -t mangle -L "mark_ipv6_${IFACE_IPV4_ONLY}" -n >/dev/null 2>&1; then
        log_pass "IPv4-only interface isolation works"
    else
        log_fail "IPv6 chain exists for IPv4-only interface"
    fi
fi

if [ -n "$IFACE_IPV6" ]; then
    log_info "Verifying IPv6 routing rule for $IFACE_IPV6..."
    if ip -6 rule | grep -q "fwmark.*lookup ${IFACE_IPV6}_rt"; then
        log_pass "IPv6 routing rule exists"
    else
        log_fail "IPv6 routing rule missing"
    fi
fi

echo ""
echo "=========================================="
echo " Testing assign-domains and remove-domains"
echo "=========================================="
echo ""

log_info "Staging split-tunnel interface $TEST_SPLIT_IFACE..."
./wg-pbr.sh "$TEST_SPLIT_IFACE" --conf "$TEST_CONF" -d "none" > /dev/null 2>&1
if interface_exists "$TEST_SPLIT_IFACE"; then
    log_pass "Split-tunnel interface staged"
    
    log_info "Testing assign-domains with single domain..."
    ./wg-pbr.sh assign-domains "$TEST_SPLIT_IFACE" "google.com" > /dev/null 2>&1
    if get_staged_domains "$TEST_SPLIT_IFACE" | grep -qF "google.com"; then
        log_pass "assign-domains works"
    else
        log_fail "assign-domains failed"
    fi

    log_info "Testing regression: assign-domains character integrity (ipleak.net)..."
    ./wg-pbr.sh assign-domains "$TEST_SPLIT_IFACE" "ipleak.net" > /dev/null 2>&1
    staged=$(get_staged_domains "$TEST_SPLIT_IFACE")
    if echo "$staged" | grep -qF "ipleak.net"; then
         if echo "$staged" | grep -qF "iwleak.net"; then
             log_fail "Regression: ipleak.net corrupted to iwleak.net"
         else
             log_pass "Regression: ipleak.net passed character integrity check"
         fi
    else
        log_fail "Regression: ipleak.net not added"
    fi
    
    log_info "Testing assign-domains accumulation and deduplication..."
    ./wg-pbr.sh assign-domains "$TEST_SPLIT_IFACE" "facebook.com,GOOGLE.COM" > /dev/null 2>&1
    staged=$(get_staged_domains "$TEST_SPLIT_IFACE")
    count=$(echo "$staged" | tr ',' '\n' | grep -ci "google.com" | xargs)
    if echo "$staged" | grep -qF "facebook.com" && [ "$count" -eq 1 ]; then
        log_pass "Accumulation and deduplication works"
    else
        log_fail "Accumulation/Deduplication failed"
    fi
    
    log_info "Testing assign-domains comma-separated list..."
    ./wg-pbr.sh assign-domains "$TEST_SPLIT_IFACE" "apple.com,msn.com" > /dev/null 2>&1
    staged=$(get_staged_domains "$TEST_SPLIT_IFACE")
    if echo "$staged" | grep -qF "apple.com" && echo "$staged" | grep -qF "msn.com"; then
        log_pass "Comma-separated list works"
    else
        log_fail "CS list failed"
    fi
    
    log_info "Testing remove-domains..."
    ./wg-pbr.sh remove-domains "$TEST_SPLIT_IFACE" "facebook.com" > /dev/null 2>&1
    if ! get_staged_domains "$TEST_SPLIT_IFACE" | grep -qF "facebook.com"; then
        log_pass "remove-domains works"
    else
        log_fail "remove-domains failed"
    fi
    
    log_info "Testing remove-domains (clear all)..."
    ./wg-pbr.sh remove-domains "$TEST_SPLIT_IFACE" "google.com,apple.com,msn.com,ipleak.net" > /dev/null 2>&1
    staged=$(get_staged_domains "$TEST_SPLIT_IFACE")
    if [ -z "$staged" ] || [ "$staged" = "none" ]; then
        log_pass "remove-domains cleared all"
    else
        log_fail "remove-domains did not clear (got: $staged)"
    fi
    
    log_info "Testing validation against IP-routing interfaces..."
    if ./wg-pbr.sh assign-domains "$IFACE_A" "example.com" 2>&1 | grep -q "Error"; then
        log_pass "Validation correctly blocks assign-domains on IP interface"
    else
        log_fail "Validation failed to block assign-domains"
    fi
else
    log_fail "Failed to stage split-tunnel interface"
fi

echo ""
echo "=== Summary ==="
log_info "Passed: $PASS_COUNT"
[ "$FAIL_COUNT" -gt 0 ] && log_fail "Failed: $FAIL_COUNT" || log_pass "All tests passed!"