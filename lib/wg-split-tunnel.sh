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

# === DNS VALIDATION ===
# Since we use dedicated Dnsmasq instances for split-tunnel, 
# shared DNS servers are allowed and safely isolated.
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

# === DNS VALIDATION ===

setup_dns_stub() {
    # Ensure main dnsmasq includes /tmp/dnsmasq.d for stubs
    local confdir=$(uci -q get dhcp.@dnsmasq[0].confdir)
    # Check if we need to add the include directory
    if ! echo "$confdir" | grep -q "/tmp/dnsmasq.d"; then
         log "Configuring dnsmasq to include /tmp/dnsmasq.d..."
         uci add_list dhcp.@dnsmasq[0].confdir='/tmp/dnsmasq.d'
         uci commit dhcp
         /etc/init.d/dnsmasq restart
    fi

    # Create the directory
    mkdir -p "/tmp/dnsmasq.d"

    # === MAIN DNSMASQ STUB GENERATION ===
    # Tell Main Dnsmasq to forward these domains to our dedicated instance (127.0.0.1#PORT)
    # Also include the ipset directives in the MAIN instance so it populates the sets
    MAIN_STUB_CONF="/tmp/dnsmasq.d/${INTERFACE}-split-stub.conf"
    
    
    # Cleanup legacy config (prevent pollution)
    rm -f "/tmp/dnsmasq.d/${INTERFACE}-split.conf"
    rm -f "$MAIN_STUB_CONF"
    
    echo "# Auto-generated stub for Main Dnsmasq -> Dedicated Instance ($INTERFACE)" > "$MAIN_STUB_CONF"
    
    # Process domains for stub file
    local old_ifs="$IFS"
    IFS=","
    for entry in $DOMAINS; do
        entry="$(trim "$entry")"
        [ -z "$entry" ] && continue
        
        # Add server forwarding rule (Domain -> Local Dedicated Port)
        echo "server=/$entry/127.0.0.1#$DNS_PORT" >> "$MAIN_STUB_CONF"
        
        # Add ipset rule (Main Dnsmasq handles ipset population)
        echo "ipset=/$entry/$ipset_v4,$ipset_v6" >> "$MAIN_STUB_CONF"
    done
    IFS="$old_ifs"
    
    # Note: dnsmasq restart is handled by wg-pbr.sh commit (once all stubs are ready)
}

setup_dns() {
    log "Configuring Dedicated DNS for split tunneling..."
    
    # DEBUG: Log DNS servers
    log "Debug: DNS_SERVERS='$DNS_SERVERS'"
    
    local vpn_dns_primary=$(echo "$DNS_SERVERS" | awk '{print $1}')
    
    if [ -z "$vpn_dns_primary" ]; then
        log "Warning: No DNS servers found. Skipping DNS setup."
        return
    fi
    log "Debug: Primary DNS='$vpn_dns_primary'"
    
    local ipset_v4="dst_vpn_${INTERFACE}"
    local ipset_v6="dst6_vpn_${INTERFACE}"
    
    # Create IP sets
    ipset create "$ipset_v4" hash:ip family inet 2>/dev/null || ipset flush "$ipset_v4"
    ipset create "$ipset_v6" hash:ip family inet6 2>/dev/null || ipset flush "$ipset_v6"
    
    # Calculate unique port based on routing table (allocated by wg-pbr.sh)
    # Formula: 5300 + (Table ID - 100)
    # Table 100 -> 5300, Table 101 -> 5301
    DNS_PORT=$((5300 + ROUTING_TABLE - 100))
    
    # === DEDICATED DNSMASQ ===
    local ded_conf="/tmp/wg-custom/${INTERFACE}-split-dnsmasq.conf"
    local ded_pid="/tmp/wg-custom/${INTERFACE}-split-dnsmasq.pid"
    
    mkdir -p /tmp/wg-custom
    
    echo "# Dedicated Resolver for $INTERFACE (Split-Tunnel)" > "$ded_conf"
    echo "port=$DNS_PORT" >> "$ded_conf"
    echo "bind-interfaces" >> "$ded_conf"
    # Bind to loopback/router-ip so Main Dnsmasq can reach it
    echo "listen-address=127.0.0.1" >> "$ded_conf"
    echo "no-resolv" >> "$ded_conf"
    echo "no-hosts" >> "$ded_conf"
    
    # Upstream servers (bound to VPN interface)
    # This forces the dedicated instance to use the VPN tunnel
    for dns in $DNS_SERVERS; do
        echo "server=$dns@$INTERFACE" >> "$ded_conf"
    done
    
    # Start Dedicated Instance with robust error handling
    log "Starting dedicated dnsmasq on port $DNS_PORT..."
    
    # 1. Kill any existing process using this port
    local port_pid=$(netstat -nlp 2>/dev/null | grep ":$DNS_PORT " | awk '{print $NF}' | cut -d'/' -f1)
    if [ -n "$port_pid" ]; then
        log "Warning: Port $DNS_PORT in use by PID $port_pid, killing..."
        kill "$port_pid" 2>/dev/null || true
        sleep 1
    fi
    
    # 2. Kill process from PID file if it exists
    if [ -f "$ded_pid" ]; then
        local old_pid=$(cat "$ded_pid")
        if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
            log "Killing stale dnsmasq process: $old_pid"
            kill "$old_pid" 2>/dev/null || true
            sleep 1
        fi
        rm -f "$ded_pid"
    fi
    
    # 3. Start the dedicated instance
    if ! dnsmasq -C "$ded_conf" -x "$ded_pid" 2>&1; then
        log "ERROR: Failed to start dedicated dnsmasq on port $DNS_PORT"
        log "Check if port is still in use or config is invalid"
        return 1
    fi
    
    # 4. Health check: Verify process started and port is listening
    sleep 1
    if [ ! -f "$ded_pid" ]; then
        log "ERROR: dnsmasq PID file not created: $ded_pid"
        return 1
    fi
    
    local new_pid=$(cat "$ded_pid")
    if ! kill -0 "$new_pid" 2>/dev/null; then
        log "ERROR: dnsmasq process $new_pid not running"
        return 1
    fi
    
    if ! netstat -nlp 2>/dev/null | grep -q ":$DNS_PORT "; then
        log "ERROR: Port $DNS_PORT not listening after dnsmasq startup"
        kill "$new_pid" 2>/dev/null || true
        return 1
    fi
    
    log "Success: Dedicated dnsmasq running on port $DNS_PORT (PID: $new_pid)"
    
    # Create Main Dnsmasq Stub
    setup_dns_stub
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
    ip rule del fwmark "$MARK/$MARK" table "$ROUTING_TABLE" 2>/dev/null || true
    ip rule add fwmark "$MARK/$MARK" table "$ROUTING_TABLE" priority 50
    if [ "$IPV6_SUPPORTED" = "1" ]; then
        ip -6 rule del fwmark "$MARK/$MARK" table "$ROUTING_TABLE" 2>/dev/null || true
        ip -6 rule add fwmark "$MARK/$MARK" table "$ROUTING_TABLE" priority 50
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
    
    # Step 0a: Skip packets from VPN-routed clients (source IP in vpn_* ipsets)
    # This MUST come BEFORE connmark restore to prevent VPN clients from having
    # a cached split-tunnel mark restored and routed incorrectly
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
    for mac in $(ip6tables -t mangle -S 2>/dev/null | grep 'mark_ipv6_' | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | sort -u); do
        ip6tables -t mangle -A "$split_chain" -m mac --mac-source "$mac" -j RETURN
        log "Skipping VPN MAC: $mac (IPv6)"
    done
    
    # Step 0b: Restore OUR mark from conntrack (for established connections)
    # Only restore if connmark matches our specific mark (prevents restoring unrelated marks)
    # This comes AFTER VPN skip to prevent restoring marks for VPN clients
    iptables -t mangle -A "$split_chain" -m connmark --mark "$MARK" -j CONNMARK --restore-mark
    if [ "$IPV6_SUPPORTED" = "1" ]; then
        ip6tables -t mangle -A "$split_chain" -m connmark --mark "$MARK" -j CONNMARK --restore-mark
    fi
    
    # Step 0c: If packet already has our mark, ACCEPT it (skip further processing)
    iptables -t mangle -A "$split_chain" -m mark --mark "$MARK" -j ACCEPT
    if [ "$IPV6_SUPPORTED" = "1" ]; then
        ip6tables -t mangle -A "$split_chain" -m mark --mark "$MARK" -j ACCEPT
    fi
    
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
                        # Use INSERT at position 1 to take priority over target-IP interface rules
                        ip6tables -t mangle -I OUTPUT 1 -p udp -d "$dns" --dport 53 -j MARK --set-mark "$MARK"
                        ip6tables -t mangle -I OUTPUT 1 -p tcp -d "$dns" --dport 53 -j MARK --set-mark "$MARK"
                    fi
                    ;;
                *)
                    # IPv4 DNS - PREROUTING (client traffic)
                    iptables -t mangle -A "$split_chain" -p udp -d "$dns" --dport 53 -j MARK --set-mark "$MARK"
                    iptables -t mangle -A "$split_chain" -p tcp -d "$dns" --dport 53 -j MARK --set-mark "$MARK"
                    # IPv4 DNS - OUTPUT (router-originated DNS, e.g. dnsmasq queries)
                    # Use INSERT at position 1 to take priority over target-IP interface rules
                    iptables -t mangle -I OUTPUT 1 -p udp -d "$dns" --dport 53 -j MARK --set-mark "$MARK"
                    iptables -t mangle -I OUTPUT 1 -p tcp -d "$dns" --dport 53 -j MARK --set-mark "$MARK"
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

# === HOTPLUG SCRIPT GENERATION ===
log "Generating hotplug script for interface lifecycle management..."

HOTPLUG_SCRIPT="/etc/hotplug.d/iface/99-${INTERFACE}-split"
SCRIPT_DIR="$(cd "$(dirname "${CONFIG_FILE}")" && pwd)"
HOTPLUG_TEMPLATE="${SCRIPT_DIR}/../lib/wg-split-tunnel-hotplug.template"

# Check if template exists
if [ ! -f "$HOTPLUG_TEMPLATE" ]; then
    log "Warning: Hotplug template not found: $HOTPLUG_TEMPLATE"
    log "Skipping hotplug script generation"
else
    # Read template and substitute placeholders
    cat "$HOTPLUG_TEMPLATE" | \
        sed "s/INTERFACE_PLACEHOLDER/$INTERFACE/g" | \
        sed "s|CONFIG_FILE_PLACEHOLDER|$CONFIG_FILE|g" | \
        sed "s/ROUTING_TABLE_PLACEHOLDER/$ROUTING_TABLE/g" | \
        sed "s/DOMAINS_PLACEHOLDER/$DOMAINS/g" | \
        sed "s/MARK_PLACEHOLDER/$MARK/g" \
        > "$HOTPLUG_SCRIPT"
    
    chmod +x "$HOTPLUG_SCRIPT"
    log "Hotplug script installed: $HOTPLUG_SCRIPT"
fi

log "Setup complete. Domain split-tunneling configured for: $DOMAINS"
