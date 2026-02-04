#!/bin/sh
# Test script for delete command
# Run this from the router: cd /cfg/wg-custom && sh tests/plugins/06-wg-delete-test.sh

# Source test configuration
. "${0%/*}/../test.conf"
cd "$SCRIPT_ROOT"

# Test configuration
TEST_IFACE="wgtestdel"
TEST_RT=251
TEST_IP="10.95.0.100"

cleanup_all() {
    log_info "Running cleanup..."
    # Ensure test interface is deleted from UCI and DB
    uci delete network.${TEST_IFACE} 2>/dev/null || true
    uci commit network 2>/dev/null || true
    
    # Try to delete from SQLite if DB exists
    [ -f "$WG_DB" ] && sqlite3 "$WG_DB" "DELETE FROM interfaces WHERE name = '${TEST_IFACE}';" 2>/dev/null
    [ -f "$WG_DB" ] && sqlite3 "$WG_DB" "DELETE FROM mac_state WHERE interface = '${TEST_IFACE}';" 2>/dev/null
    
    rm -f "$TEST_CONF" 2>/dev/null
    rm -f "/etc/hotplug.d/iface/99-${TEST_IFACE}-routing" 2>/dev/null
    rm -f "/etc/hotplug.d/iface/99-${TEST_IFACE}-cleanup" 2>/dev/null
}

# Register cleanup trap
trap cleanup_all EXIT INT TERM

# Run cleanup at start
cleanup_all

# Create dummy WireGuard config
cat > "$TEST_CONF" << 'EOF'
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.95.95.1/32

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = 127.0.0.1:51820
AllowedIPs = 0.0.0.0/0
EOF

log_info "Staging test interface ${TEST_IFACE}..."
# Stage using -r and -t
./wg-pbr.sh "$TEST_IFACE" --conf "$TEST_CONF" -r "$TEST_RT" -t "$TEST_IP" > /dev/null 2>&1

# --- Test 1: Verify existence after setup ---
log_info "Verifying state after setup..."
if [ -f "$WG_DB" ] && sqlite3 "$WG_DB" "SELECT name FROM interfaces WHERE name = '${TEST_IFACE}';" 2>/dev/null | grep -q "$TEST_IFACE"; then
    log_pass "Database record staged successfully"
else
    log_fail "Database record missing after staging"
fi

# Simulate a commit to create UCI and files if we were on a real router
# But here we just want to test if 'delete' removes what is there.
# Let's manually create some things that 'delete' should remove.
# This makes the test more robust even if we don't run a full 'commit'.
uci set network.${TEST_IFACE}=interface 2>/dev/null || true
touch "/etc/hotplug.d/iface/99-${TEST_IFACE}-routing"
touch "/etc/hotplug.d/iface/99-${TEST_IFACE}-cleanup"
mkdir -p "/tmp/dnsmasq.d"
touch "/tmp/dnsmasq.d/99-${TEST_IFACE}-dns.conf"

# --- Test 2: Run delete command ---
log_info "Running delete command for ${TEST_IFACE}..."
./wg-pbr.sh delete "$TEST_IFACE"

# --- Test 3: Run delete command for unmanaged interface (should fail) ---
log_info "Testing validation for unmanaged interface..."
UNMANAGED_IFACE="wgunmanaged"
output=$(./wg-pbr.sh delete "$UNMANAGED_IFACE" 2>&1)
if echo "$output" | grep -q "Error: Interface.*not managed"; then
    log_pass "Correctly refused to delete unmanaged interface"
else
    log_fail "Failed to block deletion of unmanaged interface"
fi

# --- Test 4: Verify removal of managed interface ---
log_info "Verifying removal after delete..."

if ! uci get network.${TEST_IFACE} >/dev/null 2>&1; then
    log_pass "UCI interface removed"
else
    log_fail "UCI interface still exists"
fi

if [ ! -f "/etc/hotplug.d/iface/99-${TEST_IFACE}-routing" ]; then
    log_pass "Hotplug routing script removed"
else
    log_fail "Hotplug routing script still exists"
fi

if [ ! -f "/etc/hotplug.d/iface/99-${TEST_IFACE}-cleanup" ]; then
    log_pass "Hotplug cleanup script removed"
else
    log_fail "Hotplug cleanup script still exists"
fi

if [ ! -f "/tmp/dnsmasq.d/99-${TEST_IFACE}-dns.conf" ]; then
    log_pass "dnsmasq config removed"
else
    log_fail "dnsmasq config still exists"
fi

if [ -f "$WG_DB" ] && ! sqlite3 "$WG_DB" "SELECT name FROM interfaces WHERE name = '${TEST_IFACE}';" 2>/dev/null | grep -q "$TEST_IFACE"; then
    log_pass "Database record purged"
else
    log_fail "Database record still exists in SQLite"
fi

# Final summary
test_summary
exit $?
