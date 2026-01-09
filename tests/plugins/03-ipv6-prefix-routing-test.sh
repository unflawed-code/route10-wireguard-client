#!/bin/sh
# Test script for 03-ipv6-prefix-routing.sh plugin
# Run this from the router: cd /cfg/wg-custom && sh tests/plugins/03-ipv6-prefix-routing-test.sh

# Source test configuration
. "${0%/*}/../test.conf"
cd "$SCRIPT_ROOT"

# Source the plugin
. "${PLUGIN_DIR}/03-ipv6-prefix-routing.sh"

echo "=========================================="
echo " Testing 03-ipv6-prefix-routing.sh Plugin"
echo "=========================================="
echo ""

# Reset global variables before each test
reset_vars() {
    VPN_IP6_SUBNETS=""
    VPN_IP6_NEEDS_NAT66=""
}

# --- Test 1: /64 prefix handling ---
log_info "Testing /64 prefix handling..."
reset_vars
process_ipv6_prefix "2001:db8:1234:5678::1/64" "64" "2001:db8:1234:5678::1" > /dev/null

if echo "$VPN_IP6_SUBNETS" | grep -q "2001:db8:1234:5678::/64"; then
    log_pass "/64 subnet correctly extracted"
else
    log_fail "/64 subnet NOT extracted (got: $VPN_IP6_SUBNETS)"
fi

if [ "$VPN_IP6_NEEDS_NAT66" = "1" ]; then
    log_pass "NAT66 enabled for /64"
else
    log_fail "NAT66 NOT enabled for /64"
fi

# --- Test 2: /48 prefix handling ---
log_info "Testing /48 prefix handling..."
reset_vars
process_ipv6_prefix "2001:db8:abcd::1/48" "48" "2001:db8:abcd::1" > /dev/null

# Accept both 2001:db8:abcd::/48 and 2001:db8:abcd:0::/48 (both valid)
if echo "$VPN_IP6_SUBNETS" | grep -Eq "2001:db8:abcd:(0)?::/48"; then
    log_pass "/48 subnet correctly extracted"
else
    log_fail "/48 subnet NOT extracted (got: $VPN_IP6_SUBNETS)"
fi

# --- Test 3: /65 prefix handling ---
log_info "Testing /65 prefix handling..."
reset_vars
process_ipv6_prefix "2001:db8::1/65" "65" "2001:db8::1" > /dev/null

if echo "$VPN_IP6_SUBNETS" | grep -q "2001:db8::1/65"; then
    log_pass "/65 subnet correctly stored (full address)"
else
    log_fail "/65 subnet NOT stored correctly (got: $VPN_IP6_SUBNETS)"
fi

# --- Test 4: /96 prefix handling ---
log_info "Testing /96 prefix handling..."
reset_vars
process_ipv6_prefix "2001:db8:1234:5678:90ab:cdef::/96" "96" "2001:db8:1234:5678:90ab:cdef::" > /dev/null

if echo "$VPN_IP6_SUBNETS" | grep -q "2001:db8:1234:5678:90ab:cdef::/96"; then
    log_pass "/96 subnet correctly stored"
else
    log_fail "/96 subnet NOT stored correctly (got: $VPN_IP6_SUBNETS)"
fi

# --- Test 5: /127 prefix handling ---
log_info "Testing /127 prefix handling..."
reset_vars
process_ipv6_prefix "2001:db8::a/127" "127" "2001:db8::a" > /dev/null

if echo "$VPN_IP6_SUBNETS" | grep -q "2001:db8::a/127"; then
    log_pass "/127 subnet correctly stored"
else
    log_fail "/127 subnet NOT stored correctly (got: $VPN_IP6_SUBNETS)"
fi

# --- Test 6: /128 prefix handling (should be ignored by plugin) ---
log_info "Testing /128 prefix handling (should return 1)..."
reset_vars
process_ipv6_prefix "2001:db8::1/128" "128" "2001:db8::1" > /dev/null
result=$?

if [ "$result" = "1" ]; then
    log_pass "/128 correctly NOT handled by plugin (return 1)"
else
    log_fail "/128 should return 1 but returned $result"
fi

if [ -z "$VPN_IP6_SUBNETS" ]; then
    log_pass "No subnet added for /128"
else
    log_fail "Subnet incorrectly added for /128 (got: $VPN_IP6_SUBNETS)"
fi

# --- Test 7: Duplicate prevention ---
log_info "Testing duplicate prevention..."
reset_vars
process_ipv6_prefix "2001:db8:1234:5678::1/64" "64" "2001:db8:1234:5678::1" > /dev/null
process_ipv6_prefix "2001:db8:1234:5678::2/64" "64" "2001:db8:1234:5678::2" > /dev/null

# Count occurrences of the subnet
count=$(echo "$VPN_IP6_SUBNETS" | grep -o "2001:db8:1234:5678::/64" | wc -l)
if [ "$count" = "1" ]; then
    log_pass "Duplicate /64 correctly prevented"
else
    log_fail "Duplicate /64 NOT prevented (count: $count)"
fi

# --- Test 8: Multiple different subnets ---
log_info "Testing multiple different subnets..."
reset_vars
process_ipv6_prefix "2001:db8:aaaa::1/64" "64" "2001:db8:aaaa::1" > /dev/null
process_ipv6_prefix "2001:db8:bbbb::1/64" "64" "2001:db8:bbbb::1" > /dev/null
process_ipv6_prefix "2001:db8:cccc::1/65" "65" "2001:db8:cccc::1" > /dev/null

# Accept both compressed and expanded formats
if echo "$VPN_IP6_SUBNETS" | grep -Eq "2001:db8:aaaa:(0)?::/64" && \
   echo "$VPN_IP6_SUBNETS" | grep -Eq "2001:db8:bbbb:(0)?::/64" && \
   echo "$VPN_IP6_SUBNETS" | grep -q "2001:db8:cccc::1/65"; then
    log_pass "Multiple different subnets correctly added"
else
    log_fail "Multiple subnets NOT correctly added (got: $VPN_IP6_SUBNETS)"
fi

# --- Summary ---
test_summary
exit $?
