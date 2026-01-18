#!/bin/ash

# wg-split-tunnel.sh - WireGuard Split-Tunnel Module
# Called by wg-pbr.sh during commit

set -e

# Source shared library
SCRIPT_DIR="$(dirname "$0")"
. "$SCRIPT_DIR/wg-common.sh"

log() {
    logger -t wg-split-tunnel "[$INTERFACE] $1"
    echo "$1"
}

cleanup() {
    rm -f "$WG_CONFIG_TEMP"
}

trap cleanup EXIT

# === ARGUMENT PARSING ===

INTERFACE=""
CONFIG_FILE=""
DOMAINS=""
ROUTING_TABLE=""

while [ $# -gt 0 ]; do
    case "$1" in
        -c|--conf)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -d|--domains)
            DOMAINS="$2"
            shift 2
            ;;
        -r|--routing-table)
            ROUTING_TABLE="$2"
            shift 2
            ;;
        -*)
            echo "Error: Unknown option: $1"
            exit 1
            ;;
        *)
            if [ -z "$INTERFACE" ]; then
                INTERFACE="$1"
            else
                echo "Error: Unknown argument: $1"
                exit 1
            fi
            shift
            ;;
    esac
done

if [ -z "$INTERFACE" ] || [ -z "$CONFIG_FILE" ] || [ -z "$DOMAINS" ]; then
    echo "Error: Missing required arguments (interface, config, domains)."
    exit 1
fi

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Config file not found: $CONFIG_FILE"
    exit 1
fi

WG_CONFIG_TEMP="/tmp/wg-split-${INTERFACE}-$$.conf"

# Validate routing table (required - allocated by wg-pbr.sh)
if [ -z "$ROUTING_TABLE" ]; then
    echo "Error: --routing-table (-r) is required. Use wg-pbr.sh -d to stage split-tunnel configs."
    exit 1
fi
MARK=$((0x10000 + ROUTING_TABLE))
log "Using Routing Table: $ROUTING_TABLE (Mark: $(printf '0x%x' $MARK))"

# === CONFIG PARSING ===

PRIVATE_KEY=""
PEER_PUBLIC_KEY=""
PRESHARED_KEY=""
ENDPOINT=""
ALLOWED_IPS=""
CLIENT_IP=""
CLIENT_IP6=""
DNS_SERVERS=""
KEEPALIVE="25"

parse_config() {
    local section=""
    local line key value value_spaced
    
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%%#*}"
        line="$(trim "$line")"
        [ -z "$line" ] && continue
        
        case "$line" in
            \[*\]) section="${line#["["]}"; section="${section%]}"; continue;;
        esac
        
        case "$line" in
            *=*)
                key="${line%%=*}"; value="${line#*=}"
                key="$(trim "$key")"
                value="$(trim "$value")"
                
                case "$section" in
                    Interface)
                        case "$key" in
                            PrivateKey) PRIVATE_KEY="$value" ;;
                            Address)
                                value_spaced=$(echo "$value" | sed 's/,/ /g')
                                for addr in $value_spaced; do
                                    case "$addr" in
                                        *:*) CLIENT_IP6="$CLIENT_IP6 $addr" ;;
                                        *)   CLIENT_IP="$CLIENT_IP $addr" ;;
                                    esac
                                done
                                ;;
                            DNS)
                                value_spaced=$(echo "$value" | sed 's/,/ /g')
                                for dns in $value_spaced; do
                                    DNS_SERVERS="$DNS_SERVERS $dns"
                                done
                                ;;
                        esac;;
                    Peer)
                        case "$key" in
                            PublicKey) PEER_PUBLIC_KEY="$value" ;;
                            PresharedKey) PRESHARED_KEY="$value" ;;
                            Endpoint) ENDPOINT="$value" ;;
                            AllowedIPs) ALLOWED_IPS="$value" ;;
                            PersistentKeepalive) KEEPALIVE="$value" ;;
                        esac;;
                esac;;
        esac
    done < "$CONFIG_FILE"
}

log "Parsing configuration..."
parse_config

# Trim parsed values
DNS_SERVERS=$(trim "$DNS_SERVERS")
CLIENT_IP6=$(trim "$CLIENT_IP6")

# === DNS CONFLICT DETECTION ===
# Check if any DNS server is shared with other WG interfaces
# If conflict, use Cloudflare DNS to avoid routing issues
CONF_DIR="$(dirname "$CONFIG_FILE")"
NEW_DNS=""
for dns in $DNS_SERVERS; do
    dns_conflict=0
    for conf in "$CONF_DIR"/*.conf; do
        [ "$conf" = "$CONFIG_FILE" ] && continue  # Skip self
        [ ! -f "$conf" ] && continue
        if grep -q "DNS.*$dns" "$conf" 2>/dev/null; then
            dns_conflict=1
            conflicting_iface=$(basename "$conf" .conf)
            break
        fi
    done
    
    if [ "$dns_conflict" = "1" ]; then
        case "$dns" in
            *:*)
                # IPv6 DNS conflict - use Cloudflare IPv6
                log "Warning: DNS $dns shared with $conflicting_iface, using 2606:4700:4700::1111 instead"
                NEW_DNS="$NEW_DNS 2606:4700:4700::1111"
                ;;
            *)
                # IPv4 DNS conflict - use Cloudflare IPv4
                log "Warning: DNS $dns shared with $conflicting_iface, using 1.1.1.1 instead"
                NEW_DNS="$NEW_DNS 1.1.1.1"
                ;;
        esac
    else
        NEW_DNS="$NEW_DNS $dns"
    fi
done
DNS_SERVERS=$(trim "$NEW_DNS")
log "Using DNS servers: $DNS_SERVERS"

# Detect IPv6 support based on config
if [ -n "$CLIENT_IP6" ]; then
    IPV6_SUPPORTED=1
    log "IPv6 support: Enabled (address: $CLIENT_IP6)"
else
    IPV6_SUPPORTED=0
    log "IPv6 support: Disabled (no IPv6 address in config)"
    log "IPv6 traffic for split-tunnel domains will be blocked to prevent leak"
fi

if [ -z "$PRIVATE_KEY" ] || [ -z "$PEER_PUBLIC_KEY" ] || [ -z "$ENDPOINT" ]; then
    echo "Error: Invalid config. Missing PrivateKey, Peer PublicKey, or Endpoint."
    exit 1
fi

# === INTERFACE SETUP ===

setup_interface() {
    log "Setting up WireGuard interface..."
    
    if ip link show "$INTERFACE" >/dev/null 2>&1; then
        log "Interface exists, re-configuring..."
    else
        ip link add dev "$INTERFACE" type wireguard
    fi
    
    cat <<EOF > "$WG_CONFIG_TEMP"
[Interface]
PrivateKey = $PRIVATE_KEY

[Peer]
PublicKey = $PEER_PUBLIC_KEY
Endpoint = $ENDPOINT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = $KEEPALIVE
EOF
    if [ -n "$PRESHARED_KEY" ]; then
        sed -i "/PublicKey =/a PresharedKey = $PRESHARED_KEY" "$WG_CONFIG_TEMP"
    fi

    wg setconf "$INTERFACE" "$WG_CONFIG_TEMP"
    
    for ip in $CLIENT_IP; do
        if ! ip addr show dev "$INTERFACE" | grep -q "$ip"; then
            ip addr add "$ip" dev "$INTERFACE"
        fi
    done
    
    for ip6 in $CLIENT_IP6; do
        if ! ip -6 addr show dev "$INTERFACE" | grep -q "$ip6"; then
            ip -6 addr add "$ip6" dev "$INTERFACE"
        fi
    done
    
    ip link set up dev "$INTERFACE"
    log "Interface $INTERFACE is UP."
}

setup_interface

# === DNS SETUP ===

setup_dns() {
    log "Configuring DNS for split tunneling..."
    
    local vpn_dns_primary=$(echo "$DNS_SERVERS" | awk '{print $1}')
    
    if [ -z "$vpn_dns_primary" ]; then
        log "Warning: No DNS servers found in config. Skipping DNS setup."
        return
    fi
    
    local ipset_v4="dst_vpn_${INTERFACE}"
    local ipset_v6="dst6_vpn_${INTERFACE}"
    
    # Create IP sets (and flush old entries if they exist)
    ipset create "$ipset_v4" hash:ip family inet 2>/dev/null || ipset flush "$ipset_v4"
    ipset create "$ipset_v6" hash:ip family inet6 2>/dev/null || ipset flush "$ipset_v6"
    
    # Generate dnsmasq config
    local dnsmasq_conf="/tmp/dnsmasq.d/${INTERFACE}-split.conf"
    mkdir -p /tmp/dnsmasq.d
    
    echo "# Auto-generated by wg-split-tunnel.sh for $INTERFACE" > "$dnsmasq_conf"
    
    local old_ifs="$IFS"
    IFS=","
    for entry in $DOMAINS; do
        entry="$(trim "$entry")"
        [ -z "$entry" ] && continue
        
        # Wrap each entry in error handling to ensure one failure doesn't stop others
        (
            set +e  # Disable exit on error for this entry
            
            # Check if entry is an IP address (IPv4 or IPv6)
            case "$entry" in
                # IPv4: digits and dots only, with 3 dots
                [0-9]*.[0-9]*.[0-9]*.[0-9]*)
                    # Attempt domain discovery via TLS certificate (required for IP entries)
                    discovered_domain=""
                    
                    if command -v openssl >/dev/null 2>&1; then
                        discovered_domain=$(echo | timeout 3 openssl s_client -connect "$entry:443" 2>/dev/null | \
                            openssl x509 -noout -subject 2>/dev/null | \
                            sed 's/.*CN = //' | sed 's/,.*//' | grep -v "^$") || true
                    fi
                    
                    if [ -n "$discovered_domain" ]; then
                        log "Adding IPv4 $entry (discovered domain: $discovered_domain)"
                        ipset add "$ipset_v4" "$entry" 2>/dev/null || true
                        echo "server=/$discovered_domain/$vpn_dns_primary" >> "$dnsmasq_conf"
                        echo "ipset=/$discovered_domain/$ipset_v4,$ipset_v6" >> "$dnsmasq_conf"
                    else
                        log "ERROR: Rejecting $entry - no TLS certificate found (use domain name instead)"
                    fi
                    ;;
                # IPv6: contains colons
                *:*)
                    # Attempt domain discovery via TLS certificate (required for IP entries)
                    discovered_domain6=""
                    
                    if command -v openssl >/dev/null 2>&1; then
                        discovered_domain6=$(echo | timeout 3 openssl s_client -connect "[$entry]:443" 2>/dev/null | \
                            openssl x509 -noout -subject 2>/dev/null | \
                            sed 's/.*CN = //' | sed 's/,.*//' | grep -v "^$") || true
                    fi
                    
                    if [ -n "$discovered_domain6" ]; then
                        log "Adding IPv6 $entry (discovered domain: $discovered_domain6)"
                        ipset add "$ipset_v6" "$entry" 2>/dev/null || true
                        echo "server=/$discovered_domain6/$vpn_dns_primary" >> "$dnsmasq_conf"
                        echo "ipset=/$discovered_domain6/$ipset_v4,$ipset_v6" >> "$dnsmasq_conf"
                    else
                        log "ERROR: Rejecting $entry - no TLS certificate found (use domain name instead)"
                    fi
                    ;;
                # Domain name: use dnsmasq
                *)
                    log "Adding domain to dnsmasq config: $entry"
                    echo "server=/$entry/$vpn_dns_primary" >> "$dnsmasq_conf"
                    echo "ipset=/$entry/$ipset_v4,$ipset_v6" >> "$dnsmasq_conf"
                    ;;
            esac
        ) || log "ERROR: Failed to process entry: $entry (continuing with remaining entries)"
    done
    IFS="$old_ifs"
    
    # Note: dnsmasq restart is handled by wg-pbr.sh commit (once after all interfaces)
}

setup_dns

# === FIREWALL SETUP ===

setup_firewall() {
    log "Configuring Firewall..."
    
    # Cleanup existing rules to prevent duplicates
    for proto in iptables ip6tables; do
        # NAT (v4/v6)
        while $proto -t nat -D POSTROUTING -o "$INTERFACE" -j MASQUERADE 2>/dev/null; do :; done
        
        # Forwarding
        while $proto -D FORWARD -o "$INTERFACE" -j ACCEPT 2>/dev/null; do :; done
        while $proto -D FORWARD -i "$INTERFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; do :; done
        
        # Output/Input
        while $proto -D OUTPUT -o "$INTERFACE" -j ACCEPT 2>/dev/null; do :; done
        while $proto -D INPUT -i "$INTERFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; do :; done
        
        # MSS Clamping
        while $proto -t mangle -D FORWARD -p tcp -o "$INTERFACE" --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; do :; done
    done
    
    # 1. Masquerade (NAT) - Required for routing to work
    iptables -t nat -A POSTROUTING -o "$INTERFACE" -j MASQUERADE
    ip6tables -t nat -A POSTROUTING -o "$INTERFACE" -j MASQUERADE
    
    # 2. Forwarding Rules - Insert at TOP to ensure they are hit
    # Allow LAN -> VPN
    iptables -I FORWARD 1 -o "$INTERFACE" -j ACCEPT
    ip6tables -I FORWARD 1 -o "$INTERFACE" -j ACCEPT
    
    # Allow VPN -> LAN (Related/Established)
    iptables -I FORWARD 1 -i "$INTERFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    ip6tables -I FORWARD 1 -i "$INTERFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    
    # 3. Output/Input Rules (Router <-> VPN) - Insert at TOP to ensure they are hit (fix for EPERM/Ping)
    iptables -I OUTPUT 1 -o "$INTERFACE" -j ACCEPT
    ip6tables -I OUTPUT 1 -o "$INTERFACE" -j ACCEPT
    
    iptables -I INPUT 1 -i "$INTERFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    ip6tables -I INPUT 1 -i "$INTERFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    
    # 4. MSS Clamping (Fixes huge packet / HTTP timeout issues)
    iptables -t mangle -A FORWARD -p tcp -o "$INTERFACE" --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    ip6tables -t mangle -A FORWARD -p tcp -o "$INTERFACE" --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
}

setup_firewall

# === PBR SETUP ===

setup_pbr() {
    log "Configuring Policy Based Routing (Global Mode)..."
    
    local ipset_v4="dst_vpn_${INTERFACE}"
    local ipset_v6="dst6_vpn_${INTERFACE}"
    local split_chain="split_${INTERFACE}"
    
    # 1. Routing Table - default route via WireGuard interface
    ip route flush table "$ROUTING_TABLE" 2>/dev/null || true
    # Add source hint to route (fixes some source validation issues)
    # We use the interface address (first one) as source
    # Add source hint to route (fixes some source validation issues)
    local first_addr="${ADDRESS%%/*}"
    if [ -n "$first_addr" ]; then
        ip route add default dev "$INTERFACE" table "$ROUTING_TABLE" src "$first_addr"
    else
        log "Warning: No address found for interface. Adding route without source hint."
        ip route add default dev "$INTERFACE" table "$ROUTING_TABLE"
    fi
    
    # IPv6 default route (only if IPv6 supported)
    if [ "$IPV6_SUPPORTED" = "1" ]; then
        ip -6 route flush table "$ROUTING_TABLE" 2>/dev/null || true
        ip -6 route add default dev "$INTERFACE" table "$ROUTING_TABLE"
    fi
    
    # 2. IP Rules - lookup table based on fwmark (priority 50 = high priority)
    ip rule del fwmark "$MARK" table "$ROUTING_TABLE" 2>/dev/null || true
    ip rule add fwmark "$MARK" table "$ROUTING_TABLE" priority 50
    if [ "$IPV6_SUPPORTED" = "1" ]; then
        ip -6 rule del fwmark "$MARK" table "$ROUTING_TABLE" 2>/dev/null || true
        ip -6 rule add fwmark "$MARK" table "$ROUTING_TABLE" priority 50
    fi
    
    # 2b. DNS Routing - REMOVED destination-based rules (caused conflict when multiple interfaces share same DNS)
    # DNS routing is now handled via fwmark in the split_chain below, which marks packets to the VPN's
    # DNS servers with this interface's mark, then uses the existing fwmark routing rules.
    
    # 3. Mangle Chain Setup (always create IPv6 chain for DROP rules even if no IPv6 support)
    iptables -t mangle -N "$split_chain" 2>/dev/null || iptables -t mangle -F "$split_chain"
    ip6tables -t mangle -N "$split_chain" 2>/dev/null || ip6tables -t mangle -F "$split_chain"
    
    # Remove any existing hooks
    iptables -t mangle -D PREROUTING -j "$split_chain" 2>/dev/null || true
    ip6tables -t mangle -D PREROUTING -j "$split_chain" 2>/dev/null || true
    
    # INSERT at position 1 for HIGHEST PRIORITY
    iptables -t mangle -I PREROUTING 1 -j "$split_chain"
    ip6tables -t mangle -I PREROUTING 1 -j "$split_chain"
    
    # 4. Chain Rules:
    # Step 0: Skip packets arriving FROM this VPN interface (return traffic)
    # Return traffic should NOT be marked - it needs to go back to clients via LAN
    iptables -t mangle -A "$split_chain" -i "$INTERFACE" -j RETURN
    if [ "$IPV6_SUPPORTED" = "1" ]; then
        ip6tables -t mangle -A "$split_chain" -i "$INTERFACE" -j RETURN
    fi
    
    # Step 0a: Restore OUR mark from conntrack (for established connections)
    # Only restore if connmark matches our specific mark (prevents restoring unrelated marks)
    iptables -t mangle -A "$split_chain" -m connmark --mark "$MARK" -j CONNMARK --restore-mark
    if [ "$IPV6_SUPPORTED" = "1" ]; then
        ip6tables -t mangle -A "$split_chain" -m connmark --mark "$MARK" -j CONNMARK --restore-mark
    fi
    
    # Step 0b: If packet already has our mark, ACCEPT it (skip further processing)
    iptables -t mangle -A "$split_chain" -m mark --mark "$MARK" -j ACCEPT
    if [ "$IPV6_SUPPORTED" = "1" ]; then
        ip6tables -t mangle -A "$split_chain" -m mark --mark "$MARK" -j ACCEPT
    fi
    
    # Step 0c: Skip packets from VPN-routed clients (source IP in vpn_* ipsets)
    # This ensures split-tunnel only affects direct connection clients
    # Note: We check source ipset rather than mark because mark chains run after this
    for vpn_set in $(ipset list -n | grep '^vpn_' | grep -v '^vpn6_'); do
        # Skip our own destination ipset (dst_vpn_*)
        case "$vpn_set" in dst_vpn_*) continue ;; esac
        iptables -t mangle -A "$split_chain" -m set --match-set "$vpn_set" src -j RETURN
        log "Skipping VPN ipset: $vpn_set (IPv4)"
    done
    # IPv6: Always add VPN skip rules (even if tunnel has no IPv6 support)
    # This prevents VPN clients from being affected by the DROP rule
    for vpn_set in $(ipset list -n | grep '^vpn6_'); do
        ip6tables -t mangle -A "$split_chain" -m set --match-set "$vpn_set" src -j RETURN
        log "Skipping VPN ipset: $vpn_set (IPv6)"
    done
    # IPv6: Also skip by MAC address - wg-pbr.sh uses mark_ipv6_* chains with MAC matching
    # Extract MACs from existing mark_ipv6_* chains and add RETURN rules
    for mac in $(ip6tables -t mangle -S 2>/dev/null | grep 'mark_ipv6_' | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | sort -u); do
        ip6tables -t mangle -A "$split_chain" -m mac --mac-source "$mac" -j RETURN
        log "Skipping VPN MAC: $mac (IPv6)"
    done
    
    # Step 0d: Mark DNS packets destined for THIS interface's DNS servers
    # This uses fwmark instead of destination-based ip rules to avoid conflicts
    # when multiple interfaces share the same DNS server IP
    # We mark both PREROUTING (client traffic) and OUTPUT (router-originated DNS like dnsmasq)
    if [ -n "$DNS_SERVERS" ]; then
        log "Adding fwmark-based DNS routing for: $DNS_SERVERS"
        for dns in $DNS_SERVERS; do
            case "$dns" in
                *:*)
                    # IPv6 DNS
                    if [ "$IPV6_SUPPORTED" = "1" ]; then
                        # PREROUTING (client traffic)
                        ip6tables -t mangle -A "$split_chain" -p udp -d "$dns" --dport 53 -j MARK --set-mark "$MARK"
                        ip6tables -t mangle -A "$split_chain" -p tcp -d "$dns" --dport 53 -j MARK --set-mark "$MARK"
                        # OUTPUT (router-originated DNS, e.g. dnsmasq queries)
                        ip6tables -t mangle -A OUTPUT -p udp -d "$dns" --dport 53 -j MARK --set-mark "$MARK"
                        ip6tables -t mangle -A OUTPUT -p tcp -d "$dns" --dport 53 -j MARK --set-mark "$MARK"
                    fi
                    ;;
                *)
                    # IPv4 DNS - PREROUTING (client traffic)
                    iptables -t mangle -A "$split_chain" -p udp -d "$dns" --dport 53 -j MARK --set-mark "$MARK"
                    iptables -t mangle -A "$split_chain" -p tcp -d "$dns" --dport 53 -j MARK --set-mark "$MARK"
                    # IPv4 DNS - OUTPUT (router-originated DNS, e.g. dnsmasq queries)
                    iptables -t mangle -A OUTPUT -p udp -d "$dns" --dport 53 -j MARK --set-mark "$MARK"
                    iptables -t mangle -A OUTPUT -p tcp -d "$dns" --dport 53 -j MARK --set-mark "$MARK"
                    ;;
            esac
        done
    fi
    
    # Step 1: Mark packets matching destination ipset FIRST
    log "Adding global PBR rules for domains (all sources)"
    iptables -t mangle -A "$split_chain" -m set --match-set "$ipset_v4" dst -j MARK --set-mark "$MARK"
    if [ "$IPV6_SUPPORTED" = "1" ]; then
        ip6tables -t mangle -A "$split_chain" -m set --match-set "$ipset_v6" dst -j MARK --set-mark "$MARK"
    else
        # Block IPv6 traffic to these domains since tunnel has no IPv6 (prevent leak)
        ip6tables -t mangle -A "$split_chain" -m set --match-set "$ipset_v6" dst -j DROP
        log "IPv6 traffic to split-tunnel domains will be blocked (no IPv6 support)"
    fi
    
    # Step 2: Save mark to conntrack
    iptables -t mangle -A "$split_chain" -m mark --mark "$MARK" -j CONNMARK --save-mark
    if [ "$IPV6_SUPPORTED" = "1" ]; then
        ip6tables -t mangle -A "$split_chain" -m mark --mark "$MARK" -j CONNMARK --save-mark
    fi
    
    # Step 3: ACCEPT marked packets
    iptables -t mangle -A "$split_chain" -m mark --mark "$MARK" -j ACCEPT
    if [ "$IPV6_SUPPORTED" = "1" ]; then
        ip6tables -t mangle -A "$split_chain" -m mark --mark "$MARK" -j ACCEPT
    fi
    
    log "PBR configured: priority 50, DNS priority 49, INSERT position 1, ACCEPT on match"
}

setup_pbr

log "Setup complete. Domain split-tunneling configured for: $DOMAINS"
