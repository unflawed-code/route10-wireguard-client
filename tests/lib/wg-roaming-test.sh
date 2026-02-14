#!/bin/sh
# wg-roaming-test.sh - Verify IP cleanup when clients roam between interfaces
# Usage: ./wg-roaming-test.sh

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
LIB_DIR="$(dirname "$SCRIPT_DIR")/../lib"
. "$LIB_DIR/wg-common.sh"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Mock DB for testing
WG_TMP_DIR="/tmp/wg-custom"
mkdir -p "$WG_TMP_DIR"
WG_DB_PATH="${WG_TMP_DIR}/wg_pbr.db"

# Mock get_ip_from_target if needed, but wg-common has it.

setup() {
    echo "Setting up test environment..."
    # Create dummy ipsets
    ipset destroy vpn_test1 2>/dev/null || true
    ipset destroy vpn_test2 2>/dev/null || true
    ipset create vpn_test1 hash:ip
    ipset create vpn_test2 hash:ip
    
    # Configure dummy routing tables
    # Append to rt_tables if not present
    if ! grep -q "201 test1_rt" /etc/iproute2/rt_tables; then
        echo "201 test1_rt" >> /etc/iproute2/rt_tables
    fi
    if ! grep -q "202 test2_rt" /etc/iproute2/rt_tables; then
        echo "202 test2_rt" >> /etc/iproute2/rt_tables
    fi
}

cleanup() {
    echo "Cleaning up..."
    ipset destroy vpn_test1 2>/dev/null
    ipset destroy vpn_test2 2>/dev/null
    ip rule del from 192.0.2.100 lookup test1_rt 2>/dev/null
    ip rule del from 192.0.2.100 lookup test2_rt 2>/dev/null
    
    # Remove temporary tables
    sed -i '/test1_rt/d' /etc/iproute2/rt_tables
    sed -i '/test2_rt/d' /etc/iproute2/rt_tables
}
trap cleanup EXIT

echo "=== Testing Roaming Logic ==="
setup

TEST_IP="192.0.2.100"

# 1. Add IP to Interface 1
echo "Step 1: Adding $TEST_IP to test1..."
update_ipset_targets "test1" "$TEST_IP" ""

# Verify
if ipset list vpn_test1 | grep -q "$TEST_IP"; then
    echo "${GREEN}[PASS] IP added to vpn_test1${NC}"
else
    echo "${RED}[FAIL] IP not in vpn_test1${NC}"
    exit 1
fi

if ip rule show | grep -q "from $TEST_IP lookup test1_rt"; then
    echo "${GREEN}[PASS] Rule added for test1_rt${NC}"
else
    echo "${RED}[FAIL] Rule missing for test1_rt${NC}"
    exit 1
fi

# 2. Roam IP to Interface 2
# Note: In real operation, the controller calls update for BOTH interfaces.
# 1. Update test2 with NEW IP
# 2. Update test1 with IP REMOVED
echo "Step 2: Roaming $TEST_IP to test2..."

# Add to test2
update_ipset_targets "test2" "$TEST_IP" ""

# Verify Intermediate State (Should be in both? Or just added to 2?)
# update_ipset_targets doesn't auto-remove from others unless we tell it the old list for THAT interface doesn't have it.
# Ideally, we call update for test1 with empty list or list without the IP.

# Remove from test1 (Simulate controller update)
# We need to pass the OLD list (which had the IP) and the NEW list (empty)
update_ipset_targets "test1" "none" "$TEST_IP"

# 3. Verify Cleanup
echo "Step 3: Verifying cleanup..."

# Check vpn_test1 is empty
if ! ipset list vpn_test1 | grep -q "$TEST_IP"; then
    echo "${GREEN}[PASS] IP removed from vpn_test1${NC}"
else
    echo "${RED}[FAIL] IP still in vpn_test1${NC}"
    exit 1
fi

# Check test1_rt rule is gone
if ! ip rule show | grep -q "from $TEST_IP lookup test1_rt"; then
    echo "${GREEN}[PASS] Rule removed for test1_rt${NC}"
else
    echo "${RED}[FAIL] Rule still exists for test1_rt${NC}"
    exit 1
fi

# Check vpn_test2 has IP
if ipset list vpn_test2 | grep -q "$TEST_IP"; then
    echo "${GREEN}[PASS] IP present in vpn_test2${NC}"
else
    echo "${RED}[FAIL] IP missing from vpn_test2${NC}"
    exit 1
fi

# Check test2_rt rule exists
if ip rule show | grep -q "from $TEST_IP lookup test2_rt"; then
    echo "${GREEN}[PASS] Rule added for test2_rt${NC}"
else
    echo "${RED}[FAIL] Rule missing for test2_rt${NC}"
    exit 1
fi

echo "=== Roaming Test Complete ==="
