#!/bin/sh
# wg-mac-test.sh - Test suite for MAC address target support

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
WG_COMMON="${PROJECT_ROOT}/lib/wg-common.sh"
TEMP_DIR="/tmp/wg-mac-test-$$"

mkdir -p "$TEMP_DIR"
trap 'rm -rf "$TEMP_DIR"' EXIT

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS_COUNT=$((PASS_COUNT + 1)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }

# Load functions from wg-common.sh
. "$WG_COMMON"

# --- is_mac tests ---

test_is_mac_colon_format() {
    if is_mac "2a:30:12:ef:5a:aa"; then
        log_pass "is_mac: colon-separated format"
    else
        log_fail "is_mac: colon-separated format"
    fi
}

test_is_mac_dash_format() {
    if is_mac "2a-30-12-ef-5a-aa"; then
        log_pass "is_mac: dash-separated format"
    else
        log_fail "is_mac: dash-separated format"
    fi
}

test_is_mac_no_separator() {
    if is_mac "2a3012ef5aaa"; then
        log_pass "is_mac: no separator format"
    else
        log_fail "is_mac: no separator format"
    fi
}

test_is_mac_uppercase() {
    if is_mac "2A:30:12:EF:5A:AA"; then
        log_pass "is_mac: uppercase format"
    else
        log_fail "is_mac: uppercase format"
    fi
}

test_is_mac_not_ip() {
    if is_mac "192.168.1.1"; then
        log_fail "is_mac: should NOT match IP address"
    else
        log_pass "is_mac: correctly rejects IP address"
    fi
}

test_is_mac_not_subnet() {
    if is_mac "10.90.5.0/24"; then
        log_fail "is_mac: should NOT match CIDR subnet"
    else
        log_pass "is_mac: correctly rejects CIDR subnet"
    fi
}

test_is_mac_invalid_chars() {
    if is_mac "2g:30:12:ef:5a:aa"; then
        log_fail "is_mac: should NOT match with invalid hex char 'g'"
    else
        log_pass "is_mac: correctly rejects invalid hex"
    fi
}

# --- normalize_mac tests ---

test_normalize_colon() {
    local result=$(normalize_mac "2A:30:12:EF:5A:AA")
    if [ "$result" = "2a:30:12:ef:5a:aa" ]; then
        log_pass "normalize_mac: colon format"
    else
        log_fail "normalize_mac: colon format (got: $result)"
    fi
}

test_normalize_dash() {
    local result=$(normalize_mac "2A-30-12-EF-5A-AA")
    if [ "$result" = "2a:30:12:ef:5a:aa" ]; then
        log_pass "normalize_mac: dash format"
    else
        log_fail "normalize_mac: dash format (got: $result)"
    fi
}

test_normalize_no_sep() {
    local result=$(normalize_mac "2A3012EF5AAA")
    if [ "$result" = "2a:30:12:ef:5a:aa" ]; then
        log_pass "normalize_mac: no separator format"
    else
        log_fail "normalize_mac: no separator format (got: $result)"
    fi
}

test_normalize_invalid() {
    if normalize_mac "invalid"; then
        log_fail "normalize_mac: should fail on invalid input"
    else
        log_pass "normalize_mac: correctly rejects invalid input"
    fi
}

# --- Deduplication tests ---

# Simulates the dedup logic from wg-pbr.sh
simulate_dedupe() {
    local targets="$1"
    local RESOLVED_VPN_IPS=""
    
    for target in $targets; do
        # Resolve MAC to IP if needed
        if is_mac "$target"; then
            local mac=$(normalize_mac "$target")
            # Simulate resolution - for test, hardcode that this MAC = 10.90.1.10
            if [ "$mac" = "2a:30:12:ef:5a:aa" ]; then
                target="10.90.1.10"
            else
                continue
            fi
        fi
        
        # Skip IPv6 and subnets
        case "$target" in
            *:*|*/*) 
                RESOLVED_VPN_IPS="$RESOLVED_VPN_IPS $target"
                continue
                ;;
        esac
        
        # Deduplicate
        if echo "$RESOLVED_VPN_IPS" | grep -qw "$target"; then
            continue  # Skip duplicates
        fi
        
        RESOLVED_VPN_IPS="$RESOLVED_VPN_IPS $target"
    done
    
    echo "$RESOLVED_VPN_IPS" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

test_dedupe_ip_and_mac() {
    # Both IP and MAC point to same device - should dedupe
    local result=$(simulate_dedupe "10.90.1.10 2a3012ef5aaa")
    if [ "$result" = "10.90.1.10" ]; then
        log_pass "dedupe: IP + MAC for same device"
    else
        log_fail "dedupe: IP + MAC for same device (got: '$result', expected: '10.90.1.10')"
    fi
}

test_dedupe_mac_first() {
    # MAC first, then same IP - should still dedupe
    local result=$(simulate_dedupe "2a3012ef5aaa 10.90.1.10")
    if [ "$result" = "10.90.1.10" ]; then
        log_pass "dedupe: MAC then IP for same device"
    else
        log_fail "dedupe: MAC then IP for same device (got: '$result', expected: '10.90.1.10')"
    fi
}

test_dedupe_different_targets() {
    # Different IPs - should NOT dedupe
    local result=$(simulate_dedupe "10.90.1.10 10.90.1.20")
    if [ "$result" = "10.90.1.10 10.90.1.20" ]; then
        log_pass "dedupe: different IPs kept"
    else
        log_fail "dedupe: different IPs kept (got: '$result')"
    fi
}

# --- MAIN ---

echo "Running MAC Address Tests..."
echo "Source: $WG_COMMON"
echo ""

if [ ! -f "$WG_COMMON" ]; then
    echo "Error: wg-common.sh not found at $WG_COMMON"
    exit 1
fi

echo "=== is_mac() Tests ==="
test_is_mac_colon_format
test_is_mac_dash_format
test_is_mac_no_separator
test_is_mac_uppercase
test_is_mac_not_ip
test_is_mac_not_subnet
test_is_mac_invalid_chars

echo ""
echo "=== normalize_mac() Tests ==="
test_normalize_colon
test_normalize_dash
test_normalize_no_sep
test_normalize_invalid

echo ""
echo "=== Deduplication Tests ==="
test_dedupe_ip_and_mac
test_dedupe_mac_first
test_dedupe_different_targets

echo ""
echo "=== Summary ==="
echo "Passed: $PASS_COUNT"
echo "Failed: $FAIL_COUNT"

[ $FAIL_COUNT -eq 0 ] && exit 0 || exit 1

