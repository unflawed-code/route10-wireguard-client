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
    rm -f "/etc/hotplug.d/iface/99-${TEST_IFACE}-split" 2>/dev/null
    rm -f "/tmp/dnsmasq.d/${TEST_IFACE}-split-stub.conf" 2>/dev/null
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
touch "/etc/hotplug.d/iface/99-${TEST_IFACE}-split"
mkdir -p "/tmp/dnsmasq.d"
touch "/tmp/dnsmasq.d/99-${TEST_IFACE}-dns.conf"
touch "/tmp/dnsmasq.d/${TEST_IFACE}-split-stub.conf"
touch "/tmp/wg-custom/${TEST_IFACE}-split-dnsmasq.pid"
touch "/tmp/wg-custom/${TEST_IFACE}-split-dnsmasq.conf"
# Mock ipsets
ipset create "dst_vpn_${TEST_IFACE}" hash:ip 2>/dev/null || true
ipset create "dst6_vpn_${TEST_IFACE}" hash:ip family inet6 2>/dev/null || true

# --- Test 2: Run delete command ---
log_info "Running delete command for ${TEST_IFACE}..."
output=$(./wg-pbr.sh delete "$TEST_IFACE")
echo "$output"

if echo "$output" | grep -q "Database entry confirmed deleted"; then
    log_pass "Delete command reported success"
else
    log_fail "Delete command did not report success"
fi

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

if [ ! -f "/etc/hotplug.d/iface/99-${TEST_IFACE}-split" ]; then
    log_pass "Split hotplug script removed"
else
    log_fail "Split hotplug script still exists"
fi

if [ ! -f "/tmp/dnsmasq.d/${TEST_IFACE}-split-stub.conf" ]; then
    log_pass "Split dnsmasq stub removed"
else
    log_fail "Split dnsmasq stub still exists"
fi

if [ ! -f "/tmp/wg-custom/${TEST_IFACE}-split-dnsmasq.pid" ]; then
    log_pass "Dedicated dnsmasq PID file removed"
else
    log_fail "Dedicated dnsmasq PID file still exists"
fi

if ! ipset list "dst_vpn_${TEST_IFACE}" >/dev/null 2>&1; then
    log_pass "Split IPset (v4) removed"
else
    log_fail "Split IPset (v4) still exists"
fi

# --- Test 5: Verify forced kernel interface removal ---
log_info "Testing forced kernel interface removal..."

# 1. Manually create a dummy interface to simulate a stuck WireGuard interface
ip link add "$TEST_IFACE" type dummy 2>/dev/null || true
ip link set "$TEST_IFACE" up 2>/dev/null || true

if ! ip link show "$TEST_IFACE" >/dev/null 2>&1; then
    log_info "Could not create dummy interface. Skipping forced deletion test."
else
    # 2. Register it in DB so delete command accepts it
    if [ -f "$WG_DB" ]; then
        sqlite3 "$WG_DB" "INSERT OR REPLACE INTO interfaces (name, routing_table) VALUES ('$TEST_IFACE', '$TEST_RT');" 2>/dev/null
    fi
    
    # 3. Run delete
    ./wg-pbr.sh delete "$TEST_IFACE"
    
    # 4. Verify it's gone
    if ! ip link show "$TEST_IFACE" >/dev/null 2>&1; then
        log_pass "Kernel interface force-deleted"
    else
        log_fail "Kernel interface still exists after delete"
        # Cleanup
        ip link delete "$TEST_IFACE" 2>/dev/null || true
    fi
fi

# --- Test 6: Verify deletion of stale DB entry (User Scenario) ---
log_info "Testing deletion of stale DB entry..."
STALE_IFACE="wgstale"
# Insert stale entry
sqlite3 "$WG_DB" "INSERT INTO interfaces (name, routing_table, committed) VALUES ('$STALE_IFACE', 252, 1);" 2>/dev/null
sqlite3 "$WG_DB" "INSERT INTO mac_state (mac, interface, ip, routing_table) VALUES ('00:11:22:33:44:55', '$STALE_IFACE', '10.99.99.99', 252);" 2>/dev/null

# Run delete
output=$(./wg-pbr.sh delete "$STALE_IFACE")
if echo "$output" | grep -q "Database entry confirmed deleted"; then
    log_pass "Stale DB entry deleted successfully"
else
    log_fail "Failed to delete stale DB entry"
fi

# Verify DB is clean
if sqlite3 "$WG_DB" "SELECT name FROM interfaces WHERE name = '$STALE_IFACE';" 2>/dev/null | grep -q "$STALE_IFACE"; then
    log_fail "Stale interface record still in DB"
else
    log_pass "Stale interface record purged from DB"
fi

if sqlite3 "$WG_DB" "SELECT mac FROM mac_state WHERE interface = '$STALE_IFACE';" 2>/dev/null | grep -q "00:11:22:33:44:55"; then
    log_fail "Stale MAC record still in DB"
else
    log_pass "Stale MAC record purged from DB"
fi

# Final summary
test_summary
exit $?
