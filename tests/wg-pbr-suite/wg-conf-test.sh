#!/bin/sh
# wg-conf-test.sh - Test suite for WireGuard configuration parsing

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
WG_PBR="${PROJECT_ROOT}/wg-pbr.sh"
TEMP_DIR="/tmp/wg-conf-test-$$"

mkdir -p "$TEMP_DIR"
trap 'rm -rf "$TEMP_DIR"' EXIT

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; }

# Helper to load the parser from the main script
load_parser() {
    # Extract the parse_config function from wg-pbr.sh using sed
    # It finds the function definition and prints until it closes
    sed -n '/^parse_config() {/,/^}/p' "$WG_PBR" > "$TEMP_DIR/parser.sh"
    . "$TEMP_DIR/parser.sh"
}

# --- TESTS ---

test_valid_config() {
    local test_file="$TEMP_DIR/valid.conf"
    cat > "$test_file" <<EOF
[Interface]
PrivateKey = AAAA
Address = 10.0.0.1/32

[Peer]
PublicKey = BBBB
Endpoint = 1.1.1.1:51820
AllowedIPs = 0.0.0.0/0
EOF

    # Variables must be cleared before parsing
    unset PRIVATE_KEY CLIENT_IP PEER_PUBLIC_KEY ENDPOINT ALLOWED_IPS
    
    CONFIG_FILE="$test_file"
    parse_config
    
    local errors=0
    [ "$PRIVATE_KEY" = "AAAA" ] || { echo "  PrivateKey mismatch: '$PRIVATE_KEY'"; errors=1; }
    [ "$PEER_PUBLIC_KEY" = "BBBB" ] || { echo "  PublicKey mismatch: '$PEER_PUBLIC_KEY'"; errors=1; }
    [ "$ENDPOINT" = "1.1.1.1:51820" ] || { echo "  Endpoint mismatch: '$ENDPOINT'"; errors=1; }
    
    if [ $errors -eq 0 ]; then
        log_pass "Valid Config Parsing"
    else
        log_fail "Valid Config Parsing"
    fi
}

test_comments() {
    local test_file="$TEMP_DIR/comments.conf"
    cat > "$test_file" <<EOF
[Interface]
# This is a comment
PrivateKey = AAAA # Inline comment

[Peer]
PublicKey = BBBB
EOF

    unset PRIVATE_KEY PEER_PUBLIC_KEY
    
    CONFIG_FILE="$test_file"
    parse_config
    
    local errors=0
    [ "$PRIVATE_KEY" = "AAAA" ] || { echo "  PrivateKey mismatch: '$PRIVATE_KEY'"; errors=1; }
    [ "$PEER_PUBLIC_KEY" = "BBBB" ] || { echo "  PublicKey mismatch: '$PEER_PUBLIC_KEY'"; errors=1; }
    
    if [ $errors -eq 0 ]; then
        log_pass "Comments Handling"
    else
        log_fail "Comments Handling"
    fi
}

test_ipv6_endpoint() {
    local test_file="$TEMP_DIR/ipv6_endpoint.conf"
    cat > "$test_file" <<EOF
[Interface]
PrivateKey = AAAA
Address = 10.0.0.1/32

[Peer]
PublicKey = BBBB
Endpoint = [2001:db8::1]:51820
AllowedIPs = 0.0.0.0/0
EOF

    unset PRIVATE_KEY PEER_PUBLIC_KEY ENDPOINT
    
    CONFIG_FILE="$test_file"
    parse_config
    
    local errors=0
    [ "$PRIVATE_KEY" = "AAAA" ] || { echo "  PrivateKey mismatch: '$PRIVATE_KEY'"; errors=1; }
    [ "$ENDPOINT" = "[2001:db8::1]:51820" ] || { echo "  IPv6 Endpoint mismatch: '$ENDPOINT'"; errors=1; }
    
    if [ $errors -eq 0 ]; then
        log_pass "IPv6 Endpoint Parsing"
    else
        log_fail "IPv6 Endpoint Parsing"
    fi
}

test_dual_stack_addresses() {
    local test_file="$TEMP_DIR/dual_stack.conf"
    cat > "$test_file" <<EOF
[Interface]
PrivateKey = AAAA
Address = 10.0.0.1/32, 2001:db8::1/128
DNS = 1.1.1.1, 2606:4700:4700::1111

[Peer]
PublicKey = BBBB
Endpoint = 1.1.1.1:51820
AllowedIPs = 0.0.0.0/0, ::/0
EOF

    unset PRIVATE_KEY CLIENT_IP CLIENT_IP6 DNS_SERVERS
    
    CONFIG_FILE="$test_file"
    parse_config
    
    local errors=0
    [ "$PRIVATE_KEY" = "AAAA" ] || { echo "  PrivateKey mismatch: '$PRIVATE_KEY'"; errors=1; }
    echo "$CLIENT_IP" | grep -q "10.0.0.1/32" || { echo "  CLIENT_IP missing IPv4: '$CLIENT_IP'"; errors=1; }
    echo "$CLIENT_IP6" | grep -q "2001:db8::1/128" || { echo "  CLIENT_IP6 missing IPv6: '$CLIENT_IP6'"; errors=1; }
    echo "$DNS_SERVERS" | grep -q "1.1.1.1" || { echo "  DNS missing IPv4: '$DNS_SERVERS'"; errors=1; }
    echo "$DNS_SERVERS" | grep -q "2606:4700:4700::1111" || { echo "  DNS missing IPv6: '$DNS_SERVERS'"; errors=1; }
    
    if [ $errors -eq 0 ]; then
        log_pass "Dual-Stack Address Parsing"
    else
        log_fail "Dual-Stack Address Parsing"
    fi
}

test_preshared_key() {
    local test_file="$TEMP_DIR/psk.conf"
    cat > "$test_file" <<EOF
[Interface]
PrivateKey = AAAA
Address = 10.0.0.1/32

[Peer]
PublicKey = BBBB
PresharedKey = CCCC
Endpoint = 1.1.1.1:51820
EOF

    unset PRIVATE_KEY PEER_PUBLIC_KEY PRESHARED_KEY
    
    CONFIG_FILE="$test_file"
    parse_config
    
    local errors=0
    [ "$PRESHARED_KEY" = "CCCC" ] || { echo "  PresharedKey mismatch: '$PRESHARED_KEY'"; errors=1; }
    
    if [ $errors -eq 0 ]; then
        log_pass "PresharedKey Parsing"
    else
        log_fail "PresharedKey Parsing"
    fi
}

test_mtu_parsing() {
    local test_file="$TEMP_DIR/mtu.conf"
    cat > "$test_file" <<EOF
[Interface]
PrivateKey = AAAA
Address = 10.0.0.1/32
MTU = 1420

[Peer]
PublicKey = BBBB
Endpoint = 1.1.1.1:51820
EOF

    unset PRIVATE_KEY MTU
    
    CONFIG_FILE="$test_file"
    parse_config
    
    local errors=0
    [ "$MTU" = "1420" ] || { echo "  MTU mismatch: '$MTU'"; errors=1; }
    
    if [ $errors -eq 0 ]; then
        log_pass "MTU Parsing"
    else
        log_fail "MTU Parsing"
    fi
}

# --- MAIN ---

echo "Running WireGuard Config Tests..."
echo "Target Script: $WG_PBR"

if [ ! -f "$WG_PBR" ]; then
    echo "Error: wg-pbr.sh not found at $WG_PBR"
    exit 1
fi

load_parser

test_valid_config
test_comments
test_ipv6_endpoint
test_dual_stack_addresses
test_preshared_key
test_mtu_parsing

echo "Done."
