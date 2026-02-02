#!/bin/sh
# Test script for assign-ips and remove-ips commands
# Run this from the router: cd /cfg/wg-custom && sh tests/plugins/05-manage-commands-test.sh

# Source test configuration
. "${0%/*}/../test.conf"
cd "$SCRIPT_ROOT"

# Discover running WireGuard interfaces from SQLite database
discover_interfaces() {
    # Get interfaces from SQLite (committed and running interfaces)
    # Exclude wgssla as it's active and managed by systemic processes
    sqlite3 "$WG_DB" "SELECT name FROM interfaces WHERE committed = 1 AND name != 'wgssla' ORDER BY name;" 2>/dev/null
}

# Discover IP-routing capable interfaces (those without domains configured)
discover_ip_routing_interfaces() {
    # Only interfaces with NULL or empty domains support IP routing (assign-ips)
    # Exclude wgssla as it's active and managed by systemic processes
    sqlite3 "$WG_DB" "SELECT name FROM interfaces WHERE committed = 1 AND (domains IS NULL OR domains = '') AND name != 'wgssla' ORDER BY name;" 2>/dev/null
}

# Get interface count
RUNNING_IFACES=$(discover_interfaces)
IFACE_COUNT=$(echo "$RUNNING_IFACES" | grep -c .)

# Get IP-routing capable interfaces for movement tests
IP_ROUTING_IFACES=$(discover_ip_routing_interfaces)
IP_ROUTING_COUNT=$(echo "$IP_ROUTING_IFACES" | grep -c . 2>/dev/null || echo "0")

echo "=========================================="
echo " WireGuard Interface Detection"
echo "=========================================="
echo ""

if [ "$IFACE_COUNT" -eq 0 ]; then
    echo "${RED}ERROR${NC}: No running WireGuard interfaces found."
    echo "Please start at least one WireGuard interface before running tests."
    exit 1
fi

# For movement tests, use IP-routing capable interfaces only
IFACE_A=$(echo "$IP_ROUTING_IFACES" | sed -n '1p')
IFACE_B=$(echo "$IP_ROUTING_IFACES" | sed -n '2p')

# Find an interface with IPv6 support from SQLite (must also be IP-routing capable)
IFACE_IPV6=""
IFACE_IPV4_ONLY=""
IFACE_IPV6=$(sqlite3 "$WG_DB" "SELECT name FROM interfaces WHERE ipv6_support = 1 AND (domains IS NULL OR domains = '') LIMIT 1;" 2>/dev/null)
IFACE_IPV4_ONLY=$(sqlite3 "$WG_DB" "SELECT name FROM interfaces WHERE (ipv6_support = 0 OR ipv6_support IS NULL) AND (domains IS NULL OR domains = '') LIMIT 1;" 2>/dev/null)

log_info "Found $IFACE_COUNT running interface(s)"
log_info "Found $IP_ROUTING_COUNT IP-routing capable interface(s)"
log_info "Primary interface (IP routing): $IFACE_A"
[ -n "$IFACE_B" ] && log_info "Secondary interface (IP routing): $IFACE_B"
[ -n "$IFACE_IPV6" ] && log_info "IPv6-enabled interface: $IFACE_IPV6"
[ -n "$IFACE_IPV4_ONLY" ] && log_info "IPv4-only interface: $IFACE_IPV4_ONLY"
echo ""

# Test configuration
TEST_IFACE="wgtest_ips"
TEST_IP1="10.99.0.1"
TEST_IP2="10.99.0.2"
TEST_SUBNET="10.99.1.0/24"

# Helper to get staged targets for an interface from SQLite
get_staged_targets() {
    local iface="$1"
    sqlite3 "$WG_DB" "SELECT target_ips FROM interfaces WHERE name = '$iface';" 2>/dev/null
}

# Helper to check if interface exists in SQLite
interface_exists() {
    local iface="$1"
    local count=$(sqlite3 "$WG_DB" "SELECT COUNT(*) FROM interfaces WHERE name = '$iface';" 2>/dev/null)
    [ "$count" -gt 0 ]
}

cleanup_all() {
    log_info "Running cleanup..."
    # Remove all test interfaces from SQLite database
    sqlite3 "$WG_DB" "DELETE FROM interfaces WHERE name IN ('${TEST_IFACE}', '${TEST_SPLIT_IFACE:-wgtsplit}');" 2>/dev/null
    
    # Remove test config file
    rm -f "$TEST_CONF" 2>/dev/null
    
    # Remove temporary cleanup script if it exists
    rm -f /tmp/cleanup_test.sql 2>/dev/null
}

# Register cleanup trap
trap cleanup_all EXIT INT TERM

# Run cleanup at start to ensure clean state
cleanup_all

# Create dummy WireGuard config for testing
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

# --- Test 1: Stage a test interface ---
log_info "Staging test interface ${TEST_IFACE}..."
./wg-pbr.sh "$TEST_IFACE" --conf "$TEST_CONF" -r 250 -t none > /dev/null 2>&1

if interface_exists "$TEST_IFACE"; then
    log_pass "Test interface staged successfully"
else
    log_fail "Failed to stage test interface"
fi

# --- Test 2: assign-ips with single IP ---
log_info "Testing assign-ips with single IP ${TEST_IP1}..."
./wg-pbr.sh assign-ips "$TEST_IFACE" "$TEST_IP1" > /dev/null 2>&1

staged_targets=$(get_staged_targets "$TEST_IFACE")
if echo "$staged_targets" | grep -q "$TEST_IP1"; then
    log_pass "assign-ips with single IP works"
else
    log_fail "assign-ips did not add $TEST_IP1"
fi

# --- Test 3: assign-ips with additional IP (accumulates) ---
log_info "Testing assign-ips accumulation with ${TEST_IP2}..."
./wg-pbr.sh assign-ips "$TEST_IFACE" "$TEST_IP2" > /dev/null 2>&1

staged_targets=$(get_staged_targets "$TEST_IFACE")
if echo "$staged_targets" | grep -q "$TEST_IP1" && echo "$staged_targets" | grep -q "$TEST_IP2"; then
    log_pass "assign-ips accumulates IPs correctly"
else
    log_fail "assign-ips did not accumulate IPs (expected both $TEST_IP1 and $TEST_IP2)"
fi

# --- Test 4: assign-ips with subnet ---
log_info "Testing assign-ips with subnet ${TEST_SUBNET}..."
./wg-pbr.sh assign-ips "$TEST_IFACE" "$TEST_SUBNET" > /dev/null 2>&1

staged_targets=$(get_staged_targets "$TEST_IFACE")
if echo "$staged_targets" | grep -q "10.99.1.0/24"; then
    log_pass "assign-ips with subnet works"
else
    log_fail "assign-ips did not add subnet $TEST_SUBNET"
fi

# --- Test 5: remove-ips with single IP ---
log_info "Testing remove-ips with single IP ${TEST_IP1}..."
./wg-pbr.sh remove-ips "$TEST_IFACE" "$TEST_IP1" > /dev/null 2>&1

staged_targets=$(get_staged_targets "$TEST_IFACE")
if ! echo "$staged_targets" | grep -q "$TEST_IP1"; then
    log_pass "remove-ips removed single IP"
else
    log_fail "remove-ips did not remove $TEST_IP1"
fi

# --- Test 6: Verify remaining IPs ---
log_info "Verifying remaining IPs..."
staged_targets=$(get_staged_targets "$TEST_IFACE")
if echo "$staged_targets" | grep -q "$TEST_IP2" && echo "$staged_targets" | grep -q "10.99.1.0/24"; then
    log_pass "Remaining IPs ($TEST_IP2, $TEST_SUBNET) still present"
else
    log_fail "Some IPs were incorrectly removed"
fi

# --- Test 7: remove-ips with subnet ---
log_info "Testing remove-ips with subnet ${TEST_SUBNET}..."
./wg-pbr.sh remove-ips "$TEST_IFACE" "$TEST_SUBNET" > /dev/null 2>&1

staged_targets=$(get_staged_targets "$TEST_IFACE")
if ! echo "$staged_targets" | grep -q "10.99.1.0/24"; then
    log_pass "remove-ips removed subnet"
else
    log_fail "remove-ips did not remove subnet $TEST_SUBNET"
fi

# --- Test 8: remove-ips for last IP ---
log_info "Testing remove-ips for last IP ${TEST_IP2}..."
./wg-pbr.sh remove-ips "$TEST_IFACE" "$TEST_IP2" > /dev/null 2>&1

staged_targets=$(get_staged_targets "$TEST_IFACE")
# After removing all IPs, target_ips should be "none" or empty
if [ -z "$staged_targets" ] || [ "$staged_targets" = "none" ]; then
    log_pass "remove-ips handles removing last IP (sets to none)"
else
    if ! echo "$staged_targets" | grep -q "$TEST_IP2"; then
        log_pass "remove-ips removed last IP"
    else
        log_fail "remove-ips did not remove last IP $TEST_IP2"
    fi
fi

# --- Test 9: assign-ips with comma-separated list ---
log_info "Testing assign-ips with comma-separated list..."
./wg-pbr.sh assign-ips "$TEST_IFACE" "10.88.0.1,10.88.0.2,10.88.0.0/24" > /dev/null 2>&1

staged_targets=$(get_staged_targets "$TEST_IFACE")
if echo "$staged_targets" | grep -q "10.88.0.1" && echo "$staged_targets" | grep -q "10.88.0.2" && echo "$staged_targets" | grep -q "10.88.0.0/24"; then
    log_pass "assign-ips with comma-separated list works"
else
    log_fail "assign-ips did not add all comma-separated items"
fi

# --- Cleanup ---
cleanup

echo ""
echo "=========================================="
echo " Testing MAC Address Support"
echo "=========================================="
echo ""

# Stage test interface for MAC tests
log_info "Staging test interface for MAC tests..."
./wg-pbr.sh "$TEST_IFACE" --conf "$TEST_CONF" -r 250 -t none > /dev/null 2>&1

# Create dummy ARP entry for MAC resolution
TEST_MAC="cc:dd:ee:ff:00:11"
TEST_MAC_IP="10.97.0.100"
ip neigh replace $TEST_MAC_IP lladdr $TEST_MAC dev br-lan nud reachable 2>/dev/null || true

# --- Test: assign-ips with MAC address (colon format) ---
log_info "Testing assign-ips with MAC address (colon format)..."
./wg-pbr.sh assign-ips "$TEST_IFACE" "$TEST_MAC" > /dev/null 2>&1

staged_targets=$(get_staged_targets "$TEST_IFACE")
if echo "$staged_targets" | grep -q "cc:dd:ee:ff:00:11=$TEST_MAC_IP"; then
    log_pass "assign-ips stored MAC in MAC=ip format"
else
    log_fail "assign-ips did not store MAC in expected format (got: $staged_targets)"
fi

# --- Test: assign-ips with MAC address (no separator format) ---
TEST_MAC2="aabbccddeeff"
TEST_MAC2_IP="10.97.0.101"
ip neigh replace $TEST_MAC2_IP lladdr aa:bb:cc:dd:ee:ff dev br-lan nud reachable 2>/dev/null || true

log_info "Testing assign-ips with MAC address (no separator format)..."
./wg-pbr.sh assign-ips "$TEST_IFACE" "$TEST_MAC2" > /dev/null 2>&1

staged_targets=$(get_staged_targets "$TEST_IFACE")
if echo "$staged_targets" | grep -q "aa:bb:cc:dd:ee:ff=$TEST_MAC2_IP"; then
    log_pass "assign-ips with no-separator MAC format works"
else
    log_fail "assign-ips did not handle no-separator MAC format"
fi

# --- Test: Verify status output format for MAC targets ---
log_info "Testing status format for MAC targets..."
./wg-pbr.sh assign-ips "$TEST_IFACE" "$TEST_MAC" > /dev/null 2>&1
# Capture status output
status_output=$(./wg-pbr.sh status "$TEST_IFACE")
# Check for "MAC -> IP" single line format
if echo "$status_output" | grep -q "${TEST_MAC} -> ${TEST_MAC_IP}"; then
    log_pass "Status displays MAC targets in single-line 'MAC -> IP' format"
else
    log_fail "Status did NOT use single-line format for MAC target (or alignment broke)"
    echo "Output was:"
    echo "$status_output"
fi

# --- Test: remove-ips by IP should warn (strict format) ---
log_info "Testing remove-ips by IP for MAC target (should warn)..."
output=$(./wg-pbr.sh remove-ips "$TEST_IFACE" "$TEST_MAC_IP" 2>&1)
if echo "$output" | grep -q "WARN.*not found"; then
    log_pass "remove-ips by IP correctly warns for MAC target"
else
    log_fail "remove-ips by IP did not warn for MAC target"
fi

# --- Test: remove-ips by MAC works (strict format) ---
log_info "Testing remove-ips by MAC (should work)..."
./wg-pbr.sh remove-ips "$TEST_IFACE" "$TEST_MAC" > /dev/null 2>&1

staged_targets=$(get_staged_targets "$TEST_IFACE")
if ! echo "$staged_targets" | grep -q "cc:dd:ee:ff:00:11"; then
    log_pass "remove-ips by MAC successfully removed target"
else
    log_fail "remove-ips by MAC did not remove target"
fi

# --- Test: MAC + IP deduplication ---
TEST_DEDUPE_IP="10.97.0.200"
TEST_DEDUPE_MAC="dd:ee:ff:00:11:22"
ip neigh replace $TEST_DEDUPE_IP lladdr $TEST_DEDUPE_MAC dev br-lan nud reachable 2>/dev/null || true

log_info "Testing MAC + IP deduplication..."
./wg-pbr.sh assign-ips "$TEST_IFACE" "$TEST_DEDUPE_IP" > /dev/null 2>&1
output=$(./wg-pbr.sh assign-ips "$TEST_IFACE" "$TEST_DEDUPE_MAC" 2>&1)
if echo "$output" | grep -q "already in target list"; then
    log_pass "MAC + IP deduplication works"
else
    log_fail "MAC + IP deduplication did not trigger"
fi

# Cleanup MAC test ARP entries
ip neigh del $TEST_MAC_IP dev br-lan 2>/dev/null || true
ip neigh del $TEST_MAC2_IP dev br-lan 2>/dev/null || true
ip neigh del $TEST_DEDUPE_IP dev br-lan 2>/dev/null || true

# Cleanup MAC test interface
cleanup

echo ""
echo "=========================================="
echo " Testing IP Routing Verification"
echo "=========================================="
echo ""

# For routing tests, use the primary detected interface
ROUTING_TEST_IFACE="$IFACE_A"
ROUTING_TEST_IP="10.77.0.100"
ROUTING_TEST_SUBNET="10.77.1.0/24"

# --- Test 10: Verify ip rule created after assign-ips + commit ---
log_info "Testing ip rule creation for single IP..."
./wg-pbr.sh assign-ips "$ROUTING_TEST_IFACE" "$ROUTING_TEST_IP" > /dev/null 2>&1
./wg-pbr.sh commit > /dev/null 2>&1

if ip rule | grep -q "from $ROUTING_TEST_IP"; then
    log_pass "ip rule created for single IP $ROUTING_TEST_IP"
else
    log_fail "ip rule NOT created for single IP $ROUTING_TEST_IP"
fi

# --- Test 11: Verify DNS DNAT created for single IP ---
log_info "Testing DNS DNAT creation for single IP..."
if iptables -t nat -L "vpn_dns_nat_${ROUTING_TEST_IFACE}" -n 2>/dev/null | grep -q "$ROUTING_TEST_IP"; then
    log_pass "DNS DNAT rule created for single IP $ROUTING_TEST_IP"
else
    log_fail "DNS DNAT rule NOT created for single IP $ROUTING_TEST_IP"
fi

# --- Test 12: Verify ip rule created for subnet ---
log_info "Testing ip rule creation for subnet..."
./wg-pbr.sh assign-ips "$ROUTING_TEST_IFACE" "$ROUTING_TEST_SUBNET" > /dev/null 2>&1
./wg-pbr.sh commit > /dev/null 2>&1

if ip rule | grep -q "from 10.77.1.0/24"; then
    log_pass "ip rule created for subnet $ROUTING_TEST_SUBNET"
else
    log_fail "ip rule NOT created for subnet $ROUTING_TEST_SUBNET"
fi

# --- Test 13: Verify DNS DNAT created for subnet ---
log_info "Testing DNS DNAT creation for subnet..."
if iptables -t nat -L "vpn_dns_nat_${ROUTING_TEST_IFACE}" -n 2>/dev/null | grep -q "10.77.1.0/24"; then
    log_pass "DNS DNAT rule created for subnet $ROUTING_TEST_SUBNET"
else
    log_fail "DNS DNAT rule NOT created for subnet $ROUTING_TEST_SUBNET"
fi

# --- Cleanup routing test IPs ---
log_info "Cleaning up routing test IPs..."
./wg-pbr.sh remove-ips "$ROUTING_TEST_IFACE" "$ROUTING_TEST_IP" > /dev/null 2>&1
./wg-pbr.sh remove-ips "$ROUTING_TEST_IFACE" "$ROUTING_TEST_SUBNET" > /dev/null 2>&1
./wg-pbr.sh commit > /dev/null 2>&1

# --- Test 14: Verify ip rule removed after remove-ips + commit ---
log_info "Testing ip rule removal after remove-ips..."
if ! ip rule | grep -q "from $ROUTING_TEST_IP"; then
    log_pass "ip rule removed for single IP $ROUTING_TEST_IP"
else
    log_fail "ip rule NOT removed for single IP $ROUTING_TEST_IP"
fi

# --- Test 15: Verify DNS DNAT removed after remove-ips ---
log_info "Testing DNS DNAT removal after remove-ips..."
if ! iptables -t nat -L "vpn_dns_nat_${ROUTING_TEST_IFACE}" -n 2>/dev/null | grep -q "$ROUTING_TEST_IP"; then
    log_pass "DNS DNAT rule removed for single IP $ROUTING_TEST_IP"
else
    log_fail "DNS DNAT rule NOT removed for single IP $ROUTING_TEST_IP"
fi

echo ""
echo "=========================================="
echo " Testing IP Movement Between Interfaces"
echo "=========================================="
echo ""

# For movement tests, we need two IP-routing capable interfaces 
if [ -z "$IFACE_B" ]; then
    log_skip "Movement tests require 2 IP-routing capable interfaces (found $IP_ROUTING_COUNT)"
    log_skip "Skipping tests 16-24 (split-tunnel interfaces don't support assign-ips)"
else
    MOVE_IFACE_A="$IFACE_A"
    MOVE_IFACE_B="$IFACE_B"
    MOVE_TEST_IP="10.66.0.100"

    # --- Test 16: Assign IP to interface A ---
    log_info "Assigning $MOVE_TEST_IP to $MOVE_IFACE_A..."
    ./wg-pbr.sh assign-ips "$MOVE_IFACE_A" "$MOVE_TEST_IP" > /dev/null 2>&1
    ./wg-pbr.sh commit > /dev/null 2>&1

    if ip rule | grep -q "from $MOVE_TEST_IP.*${MOVE_IFACE_A}_rt"; then
        log_pass "IP $MOVE_TEST_IP assigned to $MOVE_IFACE_A"
    else
        log_fail "IP $MOVE_TEST_IP NOT assigned to $MOVE_IFACE_A"
    fi

    # --- Test 17: Move IP to interface B ---
    log_info "Moving $MOVE_TEST_IP from $MOVE_IFACE_A to $MOVE_IFACE_B..."
    ./wg-pbr.sh assign-ips "$MOVE_IFACE_B" "$MOVE_TEST_IP" > /dev/null 2>&1
    ./wg-pbr.sh commit > /dev/null 2>&1

    # Verify IP is now on interface B
    if ip rule | grep -q "from $MOVE_TEST_IP.*${MOVE_IFACE_B}_rt"; then
        log_pass "IP $MOVE_TEST_IP moved to $MOVE_IFACE_B"
    else
        log_fail "IP $MOVE_TEST_IP NOT on $MOVE_IFACE_B after move"
    fi

    # --- Test 18: Verify IP removed from interface A ---
    log_info "Verifying $MOVE_TEST_IP removed from $MOVE_IFACE_A..."
    if ! ip rule | grep -q "from $MOVE_TEST_IP.*${MOVE_IFACE_A}_rt"; then
        log_pass "IP $MOVE_TEST_IP correctly removed from $MOVE_IFACE_A"
    else
        log_fail "IP $MOVE_TEST_IP still on $MOVE_IFACE_A (not cleaned up)"
    fi

    # --- Test 19: Verify DNS DNAT moved to interface B ---
    log_info "Verifying DNS DNAT moved to $MOVE_IFACE_B..."
    if iptables -t nat -L "vpn_dns_nat_${MOVE_IFACE_B}" -n 2>/dev/null | grep -q "$MOVE_TEST_IP"; then
        log_pass "DNS DNAT rule moved to $MOVE_IFACE_B"
    else
        log_fail "DNS DNAT rule NOT on $MOVE_IFACE_B"
    fi

    # --- Test 20: Move IP back to interface A ---
    log_info "Moving $MOVE_TEST_IP back to $MOVE_IFACE_A..."
    ./wg-pbr.sh assign-ips "$MOVE_IFACE_A" "$MOVE_TEST_IP" > /dev/null 2>&1
    ./wg-pbr.sh commit > /dev/null 2>&1

    if ip rule | grep -q "from $MOVE_TEST_IP.*${MOVE_IFACE_A}_rt"; then
        log_pass "IP $MOVE_TEST_IP moved back to $MOVE_IFACE_A"
    else
        log_fail "IP $MOVE_TEST_IP NOT back on $MOVE_IFACE_A"
    fi

    # --- Test 21: Verify database updated after move ---
    log_info "Verifying database updated for $MOVE_IFACE_A..."
    db_targets=$(sqlite3 "$WG_DB" "SELECT target_ips FROM interfaces WHERE name = '$MOVE_IFACE_A';" 2>/dev/null)
    if echo "$db_targets" | grep -q "$MOVE_TEST_IP"; then
        log_pass "Database shows $MOVE_TEST_IP on $MOVE_IFACE_A"
    else
        log_fail "Database NOT updated - $MOVE_TEST_IP missing from $MOVE_IFACE_A"
    fi

    # --- Test 22: Verify database cleared for old interface ---
    log_info "Verifying database cleared for $MOVE_IFACE_B..."
    db_targets=$(sqlite3 "$WG_DB" "SELECT target_ips FROM interfaces WHERE name = '$MOVE_IFACE_B';" 2>/dev/null)
    if ! echo "$db_targets" | grep -q "$MOVE_TEST_IP"; then
        log_pass "Database correctly cleared $MOVE_TEST_IP from $MOVE_IFACE_B"
    else
        log_fail "Database still shows $MOVE_TEST_IP on $MOVE_IFACE_B (stale)"
    fi

    # --- Cleanup movement test ---
    log_info "Cleaning up movement test IP..."
    ./wg-pbr.sh remove-ips "$MOVE_IFACE_A" "$MOVE_TEST_IP" > /dev/null 2>&1
    ./wg-pbr.sh commit > /dev/null 2>&1
    
    # --- Test 23: Hot-Reload Cleanup Bug Fix Verification ---
    # This tests the fix for: cleanup_mac_for_ip() causing script abort
    # when ip6tables -D commands fail on non-existent rules (set -e issue)
    echo ""
    log_info "=== Testing Hot-Reload Cleanup Bug Fix ==="
    
    HOTFIX_TEST_IP="10.67.0.200"
    
    # Step 1: Assign IP to first interface and commit
    log_info "Step 1: Assigning $HOTFIX_TEST_IP to $MOVE_IFACE_A..."
    ./wg-pbr.sh assign-ips "$MOVE_IFACE_A" "$HOTFIX_TEST_IP" > /dev/null 2>&1
    ./wg-pbr.sh commit > /dev/null 2>&1
    
    # Verify initial assignment
    if ! ip rule | grep -q "from $HOTFIX_TEST_IP.*${MOVE_IFACE_A}_rt"; then
        log_fail "Hot-reload bug fix test: Initial assignment failed"
    else
        # Step 2: Move IP to second interface (triggers cleanup_mac_for_ip)
        log_info "Step 2: Moving $HOTFIX_TEST_IP to $MOVE_IFACE_B (triggers cleanup)..."
        ./wg-pbr.sh assign-ips "$MOVE_IFACE_B" "$HOTFIX_TEST_IP" > /dev/null 2>&1
        
        # Capture commit output to verify it completes
        commit_output=$(./wg-pbr.sh commit 2>&1)
        
        # Step 3: Verify hot-reload ran for both interfaces (not aborted mid-way)
        # If the set -e bug was present, only one interface would be processed
        if echo "$commit_output" | grep -q "Hot-reloading targets for $MOVE_IFACE_A" && \
           echo "$commit_output" | grep -q "Hot-reloading targets for $MOVE_IFACE_B"; then
            log_pass "Hot-reload processed both interfaces (no abort)"
        else
            log_fail "Hot-reload did not process both interfaces (possible set -e bug)"
        fi
        
        # Step 4: Verify BOTH interfaces were processed
        # Old interface should have IP removed
        if ip rule | grep -q "from $HOTFIX_TEST_IP.*${MOVE_IFACE_A}_rt"; then
            log_fail "Hot-reload cleanup failed - IP still on old interface"
        else
            log_pass "Hot-reload cleanup: IP removed from $MOVE_IFACE_A"
        fi
        
        # New interface should have IP added
        if ip rule | grep -q "from $HOTFIX_TEST_IP.*${MOVE_IFACE_B}_rt"; then
            log_pass "Hot-reload setup: IP added to $MOVE_IFACE_B"
        else
            log_fail "Hot-reload setup failed - IP not on new interface (abort bug)"
        fi
        
        # Cleanup
        ./wg-pbr.sh remove-ips "$MOVE_IFACE_B" "$HOTFIX_TEST_IP" > /dev/null 2>&1
        ./wg-pbr.sh commit > /dev/null 2>&1
    fi
    
    # --- Test 24: IPv4 DNS Block Rule Cleanup ---
    # This tests the fix for: stale vpn_dns_block and vpn_dns_filter rules
    # causing clients to lose internet when removed from VPN routing
    echo ""
    log_info "=== Testing IPv4 DNS/DoT Rule Cleanup ==="
    
    DNS_CLEANUP_TEST_IP="10.68.0.200"
    DNS_CLEANUP_TEST_MAC="bb:cc:dd:ee:ff:00"
    
    # Simulate client in ARP cache
    ip neigh replace $DNS_CLEANUP_TEST_IP lladdr $DNS_CLEANUP_TEST_MAC dev br-lan nud reachable 2>/dev/null || true
    
    # Step 1: Assign IP and commit (creates DNS block rules)
    log_info "Step 1: Assigning $DNS_CLEANUP_TEST_IP to $MOVE_IFACE_A..."
    ./wg-pbr.sh assign-ips "$MOVE_IFACE_A" "$DNS_CLEANUP_TEST_IP" > /dev/null 2>&1
    ./wg-pbr.sh commit > /dev/null 2>&1
    
    # Wait for DHCP processing to create rules
    sleep 1
    
    # Step 2: Verify DNS block rule exists (port 53)
    log_info "Step 2: Verifying DNS block rule created..."
    if iptables -L "vpn_dns_block_${MOVE_IFACE_A}" -n 2>/dev/null | grep -q "$DNS_CLEANUP_TEST_IP"; then
        log_pass "DNS block rule created for $DNS_CLEANUP_TEST_IP"
        
        # Step 3: Remove IP and commit (should clean up DNS block rules)
        log_info "Step 3: Removing $DNS_CLEANUP_TEST_IP (triggers cleanup)..."
        ./wg-pbr.sh remove-ips "$MOVE_IFACE_A" "$DNS_CLEANUP_TEST_IP" > /dev/null 2>&1
        ./wg-pbr.sh commit > /dev/null 2>&1
        
        # Step 4: Verify DNS block rule cleaned up
        log_info "Step 4: Verifying DNS block rule removed..."
        if ! iptables-save | grep -q "$DNS_CLEANUP_TEST_IP.*dport 53"; then
            log_pass "DNS block rules removed for $DNS_CLEANUP_TEST_IP"
        else
            log_fail "DNS block rules NOT removed for $DNS_CLEANUP_TEST_IP (stale rules!)"
        fi
        
        # Step 5: Verify DoT block rule cleaned up (port 853)
        log_info "Step 5: Verifying DoT block rule removed..."
        if ! iptables-save | grep -q "$DNS_CLEANUP_TEST_IP.*dport 853"; then
            log_pass "DoT block rules removed for $DNS_CLEANUP_TEST_IP"
        else
            log_fail "DoT block rules NOT removed for $DNS_CLEANUP_TEST_IP (stale rules!)"
        fi
    else
        log_skip "DNS block chain not found (may not be configured for this interface)"
    fi
    
    # Cleanup ARP entry
    ip neigh del $DNS_CLEANUP_TEST_IP dev br-lan 2>/dev/null || true
fi

echo ""
echo "=========================================="
echo " Testing IPv4-Only Interface"
echo "=========================================="
echo ""

# For IPv4-only tests, we need an interface without IPv6
if [ -z "$IFACE_IPV4_ONLY" ]; then
    log_skip "IPv4-only tests require an interface without IPv6 support (none found)"
    log_skip "Skipping IPv4-only tests"
else
    IPV4_ONLY_TEST_IP="10.44.0.100"
    
    # --- Test: Assign IP to IPv4-only interface ---
    log_info "Assigning $IPV4_ONLY_TEST_IP to IPv4-only interface $IFACE_IPV4_ONLY..."
    ./wg-pbr.sh assign-ips "$IFACE_IPV4_ONLY" "$IPV4_ONLY_TEST_IP" > /dev/null 2>&1
    ./wg-pbr.sh commit > /dev/null 2>&1
    
    # Verify IPv4 rule created
    if ip rule | grep -q "from $IPV4_ONLY_TEST_IP"; then
        log_pass "IPv4 rule created for $IPV4_ONLY_TEST_IP on IPv4-only interface"
    else
        log_fail "IPv4 rule NOT created for $IPV4_ONLY_TEST_IP on IPv4-only interface"
    fi
    
    # --- Test: Verify NO IPv6 fwmark chain for IPv4-only interface ---
    log_info "Verifying NO IPv6 fwmark chain for IPv4-only $IFACE_IPV4_ONLY..."
    if ! ip6tables -t mangle -L "mark_ipv6_${IFACE_IPV4_ONLY}" -n >/dev/null 2>&1; then
        log_pass "No IPv6 fwmark chain for IPv4-only interface (correct)"
    else
        log_fail "IPv6 fwmark chain EXISTS for IPv4-only interface (leak risk!)"
    fi
    
    # --- Cleanup IPv4-only test ---
    log_info "Cleaning up IPv4-only test IP..."
    ./wg-pbr.sh remove-ips "$IFACE_IPV4_ONLY" "$IPV4_ONLY_TEST_IP" > /dev/null 2>&1
    ./wg-pbr.sh commit > /dev/null 2>&1
fi

echo ""
echo "=========================================="
echo " Testing IPv6 Support"
echo "=========================================="
echo ""

# For IPv6 tests, we need an interface with IPv6 enabled
if [ -z "$IFACE_IPV6" ]; then
    log_skip "IPv6 tests require an interface with IPv6 support (none found)"
    log_skip "Skipping IPv6 tests"
else
    IPV6_TEST_IP="10.55.0.100"
    
    # Get routing table for IPv6 interface from SQLite
    IPV6_RT=$(sqlite3 "$WG_DB" "SELECT routing_table FROM interfaces WHERE name = '$IFACE_IPV6';" 2>/dev/null)
    
    # --- Test 21: Assign IP to IPv6-enabled interface ---
    log_info "Assigning $IPV6_TEST_IP to IPv6-enabled interface $IFACE_IPV6..."
    ./wg-pbr.sh assign-ips "$IFACE_IPV6" "$IPV6_TEST_IP" > /dev/null 2>&1
    ./wg-pbr.sh commit > /dev/null 2>&1
    
    # Verify IPv4 rule created
    if ip rule | grep -q "from $IPV6_TEST_IP"; then
        log_pass "IPv4 rule created for $IPV6_TEST_IP on IPv6 interface"
    else
        log_fail "IPv4 rule NOT created for $IPV6_TEST_IP on IPv6 interface"
    fi
    
    # --- Test 22: Verify IPv6 fwmark chain exists ---
    log_info "Verifying IPv6 fwmark chain for $IFACE_IPV6..."
    if ip6tables -t mangle -L "mark_ipv6_${IFACE_IPV6}" -n >/dev/null 2>&1; then
        log_pass "IPv6 fwmark chain exists for $IFACE_IPV6"
    else
        log_fail "IPv6 fwmark chain NOT found for $IFACE_IPV6"
    fi
    
    # --- Test 23: Verify IPv6 routing rule exists ---
    log_info "Verifying IPv6 routing rule for fwmark..."
    if ip -6 rule | grep -q "fwmark.*lookup ${IFACE_IPV6}_rt"; then
        log_pass "IPv6 fwmark routing rule exists"
    else
        log_fail "IPv6 fwmark routing rule NOT found"
    fi
    
    # --- Test 24: Verify DHCP deferred processing populates MAC state ---
    # This tests the fix for the subshell bug where DEFERRED_DHCP_IPS was lost
    log_info "Testing DHCP deferred processing via temp file..."
    
    DHCP_TEST_IP="10.56.0.100"
    # Simulate client in ARP cache (required for DHCP lookup)
    DHCP_TEST_MAC="aa:bb:cc:dd:ee:ff"
    ip neigh replace $DHCP_TEST_IP lladdr $DHCP_TEST_MAC dev br-lan nud reachable 2>/dev/null || true
    
    # Assign IP and commit (should trigger deferred DHCP processing)
    ./wg-pbr.sh assign-ips "$IFACE_IPV6" "$DHCP_TEST_IP" > /dev/null 2>&1
    ./wg-pbr.sh commit > /dev/null 2>&1
    
    # Check MAC state in SQLite
    if sqlite3 "$WG_DB" "SELECT * FROM mac_state WHERE ip = '$DHCP_TEST_IP';" 2>/dev/null | grep -q "$DHCP_TEST_MAC"; then
        log_pass "DHCP deferred processing populated MAC state in SQLite"
    else
        log_fail "DHCP deferred processing did NOT populate MAC state"
    fi
    
    # --- Test 25: Verify IPv6 fwmark rule created for deferred DHCP client ---
    log_info "Verifying IPv6 fwmark rule for deferred DHCP client..."
    if ip6tables -t mangle -L "mark_ipv6_${IFACE_IPV6}" -n 2>/dev/null | grep -qi "$DHCP_TEST_MAC"; then
        log_pass "IPv6 fwmark rule created for deferred DHCP client"
    else
        log_fail "IPv6 fwmark rule NOT created for deferred DHCP client"
    fi
    
    # --- Test 26: Cleanup removes MAC state from SQLite ---
    log_info "Testing cleanup removes MAC state from SQLite..."
    ./wg-pbr.sh remove-ips "$IFACE_IPV6" "$DHCP_TEST_IP" > /dev/null 2>&1
    ./wg-pbr.sh commit > /dev/null 2>&1
    
    if ! sqlite3 "$WG_DB" "SELECT * FROM mac_state WHERE ip = '$DHCP_TEST_IP';" 2>/dev/null | grep -q "$DHCP_TEST_MAC"; then
        log_pass "Cleanup removed MAC state from SQLite"
    else
        log_fail "Cleanup did NOT remove MAC state from SQLite"
    fi
    
    # Clean up ARP entry
    ip neigh del $DHCP_TEST_IP dev br-lan 2>/dev/null || true
    
    # --- Cleanup IPv6 test ---
    log_info "Cleaning up IPv6 test IP..."
    ./wg-pbr.sh remove-ips "$IFACE_IPV6" "$IPV6_TEST_IP" > /dev/null 2>&1
    ./wg-pbr.sh commit > /dev/null 2>&1
fi

# --- Test: Verify assign-ips fails for split-tunnel interface ---
echo ""
echo "=========================================="
echo " Testing Split-Tunnel Exclusions"
echo "=========================================="
echo ""

TEST_SPLIT_IFACE="wgtsplit"
# Use same test conf
log_info "Staging split-tunnel interface $TEST_SPLIT_IFACE..."
./wg-pbr.sh "$TEST_SPLIT_IFACE" --conf "$TEST_CONF" -d "example.com" > /dev/null 2>&1

if interface_exists "$TEST_SPLIT_IFACE"; then
    log_pass "Split-tunnel interface staged"
    
    # Try to assign IP - SHOULD FAIL
    log_info "Attempting to assign IP to split-tunnel interface (should fail)..."
    if ./wg-pbr.sh assign-ips "$TEST_SPLIT_IFACE" "10.200.200.1" > /dev/null 2>&1; then
        log_fail "assign-ips succeeded on split-tunnel interface (should be blocked)"
    else
        log_pass "assign-ips blocked on split-tunnel interface (correct)"
    fi
    
    # Try to remove IP - SHOULD FAIL (though technically harmless, semantic block)
    # The script blocks both target management commands for split-tunnel mode
    log_info "Attempting to remove IP from split-tunnel interface (should fail)..."
    if ./wg-pbr.sh remove-ips "$TEST_SPLIT_IFACE" "10.200.200.1" > /dev/null 2>&1; then
        log_fail "remove-ips succeeded on split-tunnel interface (should be blocked)"
    else
        log_pass "remove-ips blocked on split-tunnel interface (correct)"
    fi
    
    # Cleanup split interface
    log_info "Cleaning up split-tunnel test interface..."
    sqlite3 "$WG_DB" "DELETE FROM interfaces WHERE name = '${TEST_SPLIT_IFACE}';" 2>/dev/null
else
    log_fail "Failed to stage split-tunnel interface for testing"
fi

# --- Final Cleanup ---
log_info "Final cleanup..."
rm -f "$TEST_CONF" 2>/dev/null

# --- Summary ---
test_summary
exit $?
