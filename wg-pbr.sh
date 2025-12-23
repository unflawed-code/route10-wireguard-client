#!/bin/ash

set -e
trap 'rm -f /tmp/neigh_*_$$' EXIT

usage() {
    echo "Usage: $0 <interface_name> -c <config_file> -r <positive_number> -t <IPs_comma_separated>"
    echo "  Arguments for configuration:"
    echo "    <interface_name>:   WireGuard interface name (max 11 chars)"
    echo "    -c, --conf <file>:      Relative or absolute path to the wg conf file"
    echo "    -r, --routing-table <N>: Positive number for the routing table"
    echo "    -t, --target-ips <IPs>:  Comma-separated list of IPv4 addresses or subnets"
    echo ""
    echo "Commands:"
    echo "  $0 commit               Apply all staged WireGuard interface configurations."
    echo "  $0 reapply              Re-apply firewall rules for all registered interfaces."
    exit 1
}

trim() {
    echo "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

STAGING_DB="/tmp/wg_pbr_staging_db"
WG_REGISTRY="/tmp/wg_interface_registry"
WG_MAC_STATE="/tmp/wg_mac_state"
MASTER_DHCP_HOTPLUG="/etc/hotplug.d/dhcp/99-wg-master-pbr"

# Plugin system
PLUGIN_DIR="$(dirname "$0")/plugins"

# Shared library for generated hotplug scripts
LIB_DIR="$(dirname "$0")/lib"
COMMON_LIB="$LIB_DIR/wg-common.sh"

# Source the common library for functions needed by main script
if [ -f "$COMMON_LIB" ]; then
    . "$COMMON_LIB"
fi

# Inject library content into a generated script by replacing COMMON_LIB_PLACEHOLDER
# Usage: inject_common_lib <target_script>
inject_common_lib() {
    local target="$1"
    local lib_content_file="/tmp/wg_lib_content_$$"
    
    if [ -f "$COMMON_LIB" ]; then
        # Extract library content (skip shebang and header comments)
        sed -n '/^# === IP ADDRESS UTILITIES ===/,$p' "$COMMON_LIB" > "$lib_content_file"
        
        # Use sed to replace placeholder line with file content
        sed -i -e '/COMMON_LIB_PLACEHOLDER/{r '"$lib_content_file"'' -e 'd}' "$target"
        rm -f "$lib_content_file"
    else
        echo "WARNING: wg-common.sh not found at $COMMON_LIB"
        sed -i 's/COMMON_LIB_PLACEHOLDER/# WARNING: wg-common.sh not found/' "$target"
    fi
}

# Run hook: sources all plugins and calls the hook function if defined
# Usage: run_hook <hook_name> [args...]
# Available hooks (in execution order):
#   1. allocate_routing_table  - Auto-allocate routing table (args: INTERFACE_NAME) Sets: ROUTING_TABLE_OVERRIDE
#   2. pre_commit              - Before committing staged configs (args: none)
#   3. pre_setup               - Before interface setup (args: INTERFACE_NAME WG_REGISTRY)
#   4. process_ipv6_prefix     - For non-/128 IPv6 prefixes (args: ip6, prefix_len, addr_part)
#   5. post_setup              - After interface setup complete (args: INTERFACE_NAME)
#   6. post_commit             - After all interfaces are up (args: none)
run_hook() {
    local hook_name="$1"
    shift
    
    [ -d "$PLUGIN_DIR" ] || return 0
    
    for plugin in "$PLUGIN_DIR"/*.sh; do
        [ -f "$plugin" ] || continue
        
        # Source the plugin to load its functions
        . "$plugin"
        
        # Call the hook function if it exists
        if type "${hook_name}" >/dev/null 2>&1; then
            "${hook_name}" "$@" || echo "Warning: Hook ${hook_name} in $(basename "$plugin") returned error"
        fi
        
        # Unset the function to avoid calling it again from next plugin
        unset -f "${hook_name}" 2>/dev/null || true
    done
}

# Update the WireGuard interface registry
update_wg_registry() {
    local iface="$1" rt="$2" vpn_ips="$3" ipv6="$4" ip6_subs="$5" nat66="$6"
    # Convert space-separated to comma-separated for storage
    local vpn_ips_csv=$(echo "$vpn_ips" | tr ' ' ',')
    # Remove old entry for this interface
    sed -i "/^${iface}|/d" "$WG_REGISTRY" 2>/dev/null || true
    touch "$WG_REGISTRY"
    # Add new entry
    echo "${iface}|${rt}|${vpn_ips_csv}|${ipv6}|${ip6_subs}|${nat66}" >> "$WG_REGISTRY"
}

# Remove interface from registry
unregister_wg_interface() {
    local iface="$1"
    sed -i "/^${iface}|/d" "$WG_REGISTRY" 2>/dev/null || true
    # Also clean up any MAC state entries pointing to this interface
    sed -i "/|${iface}|/d" "$WG_MAC_STATE" 2>/dev/null || true
}

if [ "$1" = "commit" ]; then
    if [ -f "$STAGING_DB" ]; then
        echo "Committing staged configurations..."
        run_hook pre_commit
        # Use a temporary file for the updated DB
        touch "${STAGING_DB}.tmp"
        
        while IFS='|' read -r iface cmd committed; do
            # Always try to apply configuration if it hasn't been successfully committed yet
            if [ "$committed" != "true" ]; then
                echo "Applying configuration for $iface..."
                if eval "$cmd --internal-exec"; then
                    committed="true"
                else
                    echo "Error applying configuration for $iface"
                    committed="false"
                fi
            fi
            
            # Use the status from the setup attempt
            if [ "$committed" = "true" ]; then
                echo "Bringing up $iface..."
                # Commit UCI changes for this interface
                uci commit network
                uci commit firewall
                
                # Bring up the interface (redirects stdout/stderr to suppress errors if already up?) 
                # Better to be verbose so user sees what's happening
                ifup "$iface"
                
                # Write back with true status
                echo "$iface|$cmd|true" >> "${STAGING_DB}.tmp"
            else
                echo "$iface|$cmd|false" >> "${STAGING_DB}.tmp"
            fi
        done < "$STAGING_DB"
        mv "${STAGING_DB}.tmp" "$STAGING_DB"
        run_hook post_commit
        echo "Commit complete. Interfaces brought up and firewall rules applied."
    else
        echo "No staged configurations found."
    fi
    exit 0
fi

if [ "$1" = "reapply" ]; then
    echo "Re-applying firewall rules for all registered WireGuard interfaces..."
    if [ -f "$WG_REGISTRY" ]; then
        while IFS='|' read -r iface rt vpn_ips ipv6_sup vpn_ip6_subs vpn_ip6_nat66; do
            if [ -n "$iface" ]; then
                ROUTING_SCRIPT="/etc/hotplug.d/iface/99-${iface}-routing"
                if [ -f "$ROUTING_SCRIPT" ] && [ -x "$ROUTING_SCRIPT" ]; then
                    echo "Re-applying rules for $iface..."
                    ACTION="fw-reload" INTERFACE="$iface" "$ROUTING_SCRIPT" 2>/dev/null || \
                        echo "Warning: Failed to re-apply rules for $iface"
                else
                    echo "Warning: Routing script not found for $iface"
                fi
            fi
        done < "$WG_REGISTRY"
        echo "Reapply complete."
    else
        echo "No registered interfaces found."
    fi
    exit 0
fi

INTERFACE_NAME=""
CONFIG_FILE=""
ROUTING_TABLE_OVERRIDE=""
VPN_IPS_OVERRIDE=""
INTERNAL_EXEC=0

while [ $# -gt 0 ]; do
    case "$1" in
        -c|--conf)
            [ -z "$2" ] && echo "Error: --conf requires a value" && usage
            CONFIG_FILE=$(trim "$2")
            shift 2
            ;;
        -r|--routing-table)
            [ -z "$2" ] && echo "Error: --routing-table requires a value" && usage
            ROUTING_TABLE_OVERRIDE=$(trim "$2")
            shift 2
            ;;
        -t|--target-ips)
            [ -z "$2" ] && echo "Error: --target-ips requires a value" && usage
            VPN_IPS_OVERRIDE=$(trim "$2")
            shift 2
            ;;
        --internal-exec)
            INTERNAL_EXEC=1
            shift
            ;;
        -*)
            echo "Error: Unknown option: $1"
            usage
            ;;
        *)
            # The first non-option argument is the interface name
            if [ -z "$INTERFACE_NAME" ]; then
                INTERFACE_NAME=$(trim "$1")
            else
                echo "Error: Unknown positional argument: $1"
                usage
            fi
            shift
            ;;
    esac
done

# Validate arguments
if [ -z "$INTERFACE_NAME" ]; then
    echo "Error: WireGuard interface name required"
    usage
fi

if [ ${#INTERFACE_NAME} -gt 11 ]; then
    echo "Error: Interface name must be 11 characters or less."
    usage
fi

if [ -z "$CONFIG_FILE" ]; then
    echo "Error: --conf <config_file> is required"
    usage
fi

if [ -z "$ROUTING_TABLE_OVERRIDE" ]; then
    # Try to auto-allocate via plugin hook
    run_hook allocate_routing_table "$INTERFACE_NAME"
    if [ -z "$ROUTING_TABLE_OVERRIDE" ]; then
        echo "Error: --routing-table <positive_number> is required (no auto-allocator plugin found)"
        usage
    fi
fi

if [ -z "$VPN_IPS_OVERRIDE" ]; then
    echo "Error: --target-ips <IPs_comma_separated> is required"
    usage
fi

# Validate routing table is a positive number
if ! echo "$ROUTING_TABLE_OVERRIDE" | grep -Eq '^[1-9][0-9]*$'; then
    echo "Error: --routing-table must be a positive number (e.g., 100)"
    usage
fi

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Configuration file not found: $CONFIG_FILE"
    exit 1
fi

# --- STAGING LOGIC ---
if [ "$INTERNAL_EXEC" -eq 0 ]; then
    # Reconstruct the command for staging
    FULL_CMD="$0 $INTERFACE_NAME --conf $CONFIG_FILE --routing-table $ROUTING_TABLE_OVERRIDE --target-ips $VPN_IPS_OVERRIDE"
    
    # Ensure DB file exists
    touch "$STAGING_DB"
    
    # Remove existing entry for this interface to update it
    sed -i "/^$INTERFACE_NAME|/d" "$STAGING_DB"
    
    # Append new entry
    echo "$INTERFACE_NAME|$FULL_CMD|false" >> "$STAGING_DB"
    
    echo "Configuration staged for $INTERFACE_NAME."
    echo "Run '$0 commit' to apply changes."

    exit 0
fi
# --- END STAGING LOGIC ---

echo "Setting up WireGuard interface: $INTERFACE_NAME"
echo "Reading configuration from: $CONFIG_FILE"

# Parse configuration file
parse_config() {
    local section=""
    local line key value value_spaced
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%%#*}"; line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [ -z "$line" ] && continue
        case "$line" in
            \[*\]) section="${line#["["]}"; section="${section%]}"; continue;;
        esac
        case "$line" in
            *=*)
                key="${line%%=*}"; value="${line#*=}"
                key="$(echo "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
                value="$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
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

parse_config

# Trim whitespace from parsed variables
CLIENT_IP=$(echo "$CLIENT_IP" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
CLIENT_IP6=$(echo "$CLIENT_IP6" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
# Deduplicate IPv6 addresses (in case config has duplicates)
CLIENT_IP6=$(echo "$CLIENT_IP6" | tr ' ' '\n' | sort -u | tr '\n' ' ' | sed 's/[[:space:]]*$//')
DNS_SERVERS=$(echo "$DNS_SERVERS" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

if [ -z "$PRIVATE_KEY" ] || [ -z "$PEER_PUBLIC_KEY" ] || [ -z "$ENDPOINT" ]; then
    echo "Error: PrivateKey, Peer PublicKey, or Endpoint not found in config"
    exit 1
fi

ALLOWED_IPS="${ALLOWED_IPS:-0.0.0.0/0, ::/0}"
KEEPALIVE="${KEEPALIVE:-25}"

# --- START VARIABLE OVERRIDE ---

# Set routing table from the required CLI parameter
ROUTING_TABLE="$ROUTING_TABLE_OVERRIDE"
echo "Using Routing Table: $ROUTING_TABLE (from --routing-table)"

ROUTING_TABLE_NAME="${INTERFACE_NAME}_rt"

# Set VPN_IPS from the required CLI parameter
# Convert comma-separated string to space-separated list
VPN_IPS=$(echo "$VPN_IPS_OVERRIDE" | sed 's/,/ /g' | tr -s ' ')
echo "Using Target IPs: $VPN_IPS (from --target-ips)"

# --- END VARIABLE OVERRIDE ---

VPN_DNS_SERVERS="$DNS_SERVERS"
VPN_IP6S=""
DHCP_HOTPLUG_SCRIPT="/etc/hotplug.d/dhcp/99-${INTERFACE_NAME}-pbr"

# Define ipset and dnsmasq config paths
IPSET_NAME="vpn_${INTERFACE_NAME}"
IPSET_NAME_V6="vpn6_${INTERFACE_NAME}"
DNSMASQ_DIR="/tmp/dnsmasq.d"
DNSMASQ_CONF="${DNSMASQ_DIR}/99-${INTERFACE_NAME}-dns.conf"
mkdir -p $DNSMASQ_DIR

if [ -n "$VPN_DNS_SERVERS" ]; then
    echo "Configuring dnsmasq for selective DNS routing via ipset..."
    # Create or flush the ipset
    ipset create $IPSET_NAME hash:net 2>/dev/null || ipset flush $IPSET_NAME
    ipset create $IPSET_NAME_V6 hash:net family inet6 2>/dev/null || ipset flush $IPSET_NAME_V6

    # Add all VPN-bound subnets/IPs to the set
    for item in $VPN_IPS; do
        if echo "$item" | grep -q ":"; then
             ipset add $IPSET_NAME_V6 $item 2>/dev/null
        else
             ipset add $IPSET_NAME $item 2>/dev/null
        fi
    done
    
    # Also add routable IPv6 subnets to the IPv6 set
    if [ -n "$VPN_IP6_SUBNETS" ]; then
        for subnet in $VPN_IP6_SUBNETS; do
            ipset add $IPSET_NAME_V6 $subnet 2>/dev/null
        done
    fi

    # Create the dnsmasq config file
    # Note: We do NOT add server=IP@ipset lines because dnsmasq does not support ipsets for server selection.
    # Instead, we rely on DNAT and blocking access to the local dnsmasq to ensure no leaks.
    echo "# Auto-generated by $(basename "$0") for $INTERFACE_NAME" > $DNSMASQ_CONF
    echo "# This file is a placeholder to ensure clean reload." >> $DNSMASQ_CONF
else
    # If no DNS is set, make sure to remove any old config
    echo "No VPN_DNS servers specified; removing any old dnsmasq config."
    rm -f $DNSMASQ_CONF
fi

INTERFACE_EXISTS=0
if uci get network.$INTERFACE_NAME >/dev/null 2>&1; then INTERFACE_EXISTS=1; fi

# Clean up old rules for this interface (essential for roaming/reconfiguration)
cleanup_interface_rules "$INTERFACE_NAME" "$WG_REGISTRY"

# Run pre_setup hook for additional plugin processing
run_hook pre_setup "$INTERFACE_NAME" "$WG_REGISTRY"

echo "Removing existing setup..."
while uci -q delete network.@wireguard_$INTERFACE_NAME[0]; do :; done
uci delete network.$INTERFACE_NAME 2>/dev/null || true
for section in $(uci show firewall | grep "\.name='${INTERFACE_NAME}'" | cut -d. -f2 | cut -d= -f1); do uci delete firewall.$section 2>/dev/null || true; done
ZONE_NAME=$(echo "$INTERFACE_NAME" | cut -c1-11)
for section in $(uci show firewall | grep "\.name='${ZONE_NAME}'" | cut -d. -f2 | cut -d= -f1); do uci delete firewall.$section 2>/dev/null || true; done
rm -f "$DHCP_HOTPLUG_SCRIPT" 2>/dev/null

rm -f /etc/hotplug.d/iface/99-${INTERFACE_NAME}-routing 2>/dev/null
rm -f /etc/hotplug.d/iface/99-${INTERFACE_NAME}-cleanup 2>/dev/null

    uci set network.$INTERFACE_NAME=interface
    uci set network.$INTERFACE_NAME.proto='wireguard'
    uci set network.$INTERFACE_NAME.private_key="$PRIVATE_KEY"
    uci set network.$INTERFACE_NAME.ipv6='0'
    uci set network.$INTERFACE_NAME.delegate='0'
    uci set network.$INTERFACE_NAME.ra='0'
    uci set network.$INTERFACE_NAME.route_allowed_ips='0'
    if [ -n "$CLIENT_IP" ]; then for ip in $CLIENT_IP; do uci add_list network.$INTERFACE_NAME.addresses="$ip"; done; fi

    # Determine IPv6 support from wg conf
    IPV6_SUPPORTED=0
    VPN_IP6_SUBNETS=""
    VPN_IP6_NEEDS_NAT66=0
    IPV6_REJECTED=0
    if [ -n "$CLIENT_IP6" ]; then
        IPV6_SUPPORTED=1
        for ip6 in $CLIENT_IP6; do 
            uci add_list network.$INTERFACE_NAME.addresses="$ip6"
            # Extract subnet for routing (e.g., 2001:db8::/64 from 2001:db8::1/64)
            if echo "$ip6" | grep -q '/'; then
                # Has a prefix length, extract it
                prefix_len="${ip6##*/}"
                addr_part="${ip6%/*}"
                
                if [ "$prefix_len" -eq 128 ]; then
                    # /128 is a single host - needs NAT66 for client routing
                    # Do NOT add to VPN_IP6_SUBNETS (the interface already has this address)
                    # Only set the NAT66 flag
                    VPN_IP6_NEEDS_NAT66=1
                    echo "INFO: Detected /128 IPv6 address: $ip6 (will enable NAT66)"
                else
                    # Non-/128 prefixes: try plugin hook
                    # Plugin sets VPN_IP6_SUBNETS and VPN_IP6_NEEDS_NAT66
                    SUBNETS_BEFORE="$VPN_IP6_SUBNETS"
                    run_hook process_ipv6_prefix "$ip6" "$prefix_len" "$addr_part"
                    
                    # Check if plugin handled this prefix
                    if [ "$VPN_IP6_SUBNETS" = "$SUBNETS_BEFORE" ] && [ "$VPN_IP6_NEEDS_NAT66" = "0" ]; then
                        # Plugin did not handle this prefix - reject IPv6
                        echo "WARNING: /${prefix_len} IPv6 prefix detected but no plugin to handle it."
                        echo "WARNING: IPv6 support disabled. Install ipv6-prefix-routing.sh plugin for /${prefix_len} support."
                        IPV6_REJECTED=1
                    fi
                fi
            fi
        done
        VPN_IP6_SUBNETS=$(echo "$VPN_IP6_SUBNETS" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        
        # If any non-/128 prefix was rejected, disable IPv6 entirely
        if [ "$IPV6_REJECTED" = "1" ]; then
            IPV6_SUPPORTED=0
            VPN_IP6_SUBNETS=""
            VPN_IP6_NEEDS_NAT66=0
            # Remove IPv6 addresses from interface config
            uci delete network.$INTERFACE_NAME.addresses 2>/dev/null || true
            # Re-add only IPv4 addresses
            if [ -n "$CLIENT_IP" ]; then for ip in $CLIENT_IP; do uci add_list network.$INTERFACE_NAME.addresses="$ip"; done; fi
            echo "INFO: Continuing with IPv4-only configuration."
        fi
    elif echo "$ALLOWED_IPS" | grep -q "::"; then
        IPV6_SUPPORTED=1
        echo "INFO: IPv6 routing is enabled via AllowedIPs, but no local IPv6 tunnel address is configured."
    fi

    uci add network wireguard_$INTERFACE_NAME
    uci set network.@wireguard_$INTERFACE_NAME[-1]=wireguard_$INTERFACE_NAME
    uci set network.@wireguard_$INTERFACE_NAME[-1].public_key="$PEER_PUBLIC_KEY"

    # Parse endpoint (supports both IPv4 and IPv6)
    case "$ENDPOINT" in
        \[*\]:*)
            # IPv6 format: [2401:dc20::50]:51820
            ENDPOINT_HOST="${ENDPOINT%]:*}"
            ENDPOINT_HOST="${ENDPOINT_HOST#["["]}"
            ENDPOINT_PORT="${ENDPOINT##*]:}"
            ;;
        *:*)
            # IPv4 format: 1.2.3.4:51820
            ENDPOINT_HOST="${ENDPOINT%:*}"
            ENDPOINT_PORT="${ENDPOINT##*:}"
            ;;
        *)
            echo "Error: Invalid endpoint format: $ENDPOINT"
            exit 1
            ;;
    esac

    uci set network.@wireguard_$INTERFACE_NAME[-1].endpoint_host="$ENDPOINT_HOST"
    uci set network.@wireguard_$INTERFACE_NAME[-1].endpoint_port="$ENDPOINT_PORT"

    uci set network.@wireguard_$INTERFACE_NAME[-1].persistent_keepalive="$KEEPALIVE"
    echo "$ALLOWED_IPS" | tr ',' '\n' | while read -r ip; do ip="$(echo "$ip" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"; [ -n "$ip" ] && uci add_list network.@wireguard_$INTERFACE_NAME[-1].allowed_ips="$ip"; done
    if [ -n "$PRESHARED_KEY" ]; then uci set network.@wireguard_$INTERFACE_NAME[-1].preshared_key="$PRESHARED_KEY"; fi
    ZONE_NAME=$(echo "$INTERFACE_NAME" | cut -c1-11)
    uci set firewall.${INTERFACE_NAME}_zone=zone
    uci set firewall.${INTERFACE_NAME}_zone.name="$ZONE_NAME"
    uci set firewall.${INTERFACE_NAME}_zone.input='REJECT'
    uci set firewall.${INTERFACE_NAME}_zone.output='ACCEPT'
    uci set firewall.${INTERFACE_NAME}_zone.forward='ACCEPT'
    uci set firewall.${INTERFACE_NAME}_zone.masq='1'
    uci add_list firewall.${INTERFACE_NAME}_zone.network="$INTERFACE_NAME"
    uci set firewall.${INTERFACE_NAME}_fwd=forwarding
    uci set firewall.${INTERFACE_NAME}_fwd.src='lan'
    uci set firewall.${INTERFACE_NAME}_fwd.dest="$ZONE_NAME"

echo "Configuring policy-based routing..."
if ! grep -q "^$ROUTING_TABLE[[:space:]]*$ROUTING_TABLE_NAME" /etc/iproute2/rt_tables 2>/dev/null; then
    echo "$ROUTING_TABLE $ROUTING_TABLE_NAME" >> /etc/iproute2/rt_tables
fi

# Create ifup script
cat > /etc/hotplug.d/iface/99-${INTERFACE_NAME}-routing << 'EOF_IFACE_ROUTING'
#!/bin/sh
# Handle both ifup and fw-reload (for re-applying rules via 'reapply' command or manual trigger)
[ "$ACTION" = "ifup" ] || [ "$ACTION" = "fw-reload" ] || exit 0
[ "$INTERFACE" = "INTERFACE_NAME_PLACEHOLDER" ] || exit 0

trap 'rm -f /tmp/neigh_${WG_INTERFACE}_$$' EXIT

ROUTING_TABLE="ROUTING_TABLE_PLACEHOLDER"
IPV6_SUPPORTED="IPV6_SUPPORTED_PLACEHOLDER"
WG_INTERFACE="INTERFACE_NAME_PLACEHOLDER"
VPN_IPS="VPN_IPS_PLACEHOLDER"
VPN_DNS="VPN_DNS_PLACEHOLDER"
IPSET_NAME="IPSET_NAME_PLACEHOLDER"
IPSET_NAME_V6="vpn6_${WG_INTERFACE}"
MARK_CHAIN="mark_${WG_INTERFACE}"
MARK_VALUE="$((0x10000 + ROUTING_TABLE))"
KS_CHAIN="${WG_INTERFACE}_killswitch"
BLOCK_CHAIN="${WG_INTERFACE}_ipv6_block"
BLOCK_IPV4_ONLY_CHAIN="${WG_INTERFACE}_ipv4_only_block"
BLOCK_IPV6_DNS_INPUT_CHAIN="${WG_INTERFACE}_v6_dns_in"

# === INJECTED COMMON LIBRARY ===
COMMON_LIB_PLACEHOLDER

handle_client_ipv6() {
    local mac_addr="$1"
    local client_ip="$2"
    local log_prefix="${3:-client}"
    
    if [ "$IPV6_SUPPORTED" = "1" ]; then
        # Universal blocking rule (Leak Prevention) - Applied for both NAT66 and Native
        # Use fwmark matching instead of output interface - allows marked traffic through
        local lan_ifaces=$(ip link show type bridge | awk -F': ' '/br-lan/{print $2}')
        [ -z "$lan_ifaces" ] && lan_ifaces="br-lan"
        for lan_if in $lan_ifaces; do
            # Block unmarked IPv6 traffic (allows fwmark-routed traffic through)
            ip6tables -I $BLOCK_CHAIN 1 -i $lan_if -m mac --mac-source $mac_addr -m mark ! --mark $MARK_VALUE -j DROP
        done

        if [ "$VPN_IP6_NEEDS_NAT66" = "1" ]; then
            logger -t wireguard "[$WG_INTERFACE] NAT66 active - IPv6 routed via fwmark for $log_prefix ($mac_addr)"
        else
            logger -t wireguard "[$WG_INTERFACE] IPv6 internet blocked for $log_prefix ($mac_addr) until routing configured"
            apply_ipv6_rules "$mac_addr"
        fi
    else
        # IPv4-only tunnel: Block IPv6 for this client
        logger -t wireguard "[$WG_INTERFACE] Blocking IPv6 for $log_prefix ($mac_addr) on IPv4-only tunnel."
        ip6tables -A $BLOCK_IPV4_ONLY_CHAIN -m mac --mac-source $mac_addr -j DROP
        # ALSO Block IPv6 acquisition (RS and DHCPv6) to prevent persistence
        ip6tables -A INPUT -m mac --mac-source $mac_addr -p icmpv6 --icmpv6-type 133 -j DROP
        ip6tables -A INPUT -m mac --mac-source $mac_addr -p udp --dport 547 -j DROP
    fi
    
    # Block IPv6 DNS to router for this client (both modes)
    ip6tables -A $BLOCK_IPV6_DNS_INPUT_CHAIN -m mac --mac-source $mac_addr -p udp --dport 53 -j REJECT
    ip6tables -A $BLOCK_IPV6_DNS_INPUT_CHAIN -m mac --mac-source $mac_addr -p tcp --dport 53 -j REJECT
}

setup_secure_dns() {
    local vpn_dns_list="$1"
    local vpn_ips="$2"
    local wg_interface="$3"
    local vpn_ip6_subnets="${4:-}"

    [ -z "$vpn_dns_list" ] && return 0

    local nat_chain="vpn_dns_nat_${wg_interface}"
    local nat_chain_v6="vpn_dns_nat6_${wg_interface}"
    local filter_chain="vpn_dns_filter_${wg_interface}"
    local filter_chain_v6="vpn_dns_filter6_${wg_interface}"
    local input_block_chain="vpn_dns_block_${wg_interface}"
    local input_block_chain_v6="vpn_dns_block6_${wg_interface}"

    logger -t wireguard "[$wg_interface] Setting up complete DNS hijacking (IPv4+IPv6)"

    # Initialize INPUT block chains (Prevent direct access to Router DNS)
    iptables -N $input_block_chain 2>/dev/null || iptables -F $input_block_chain
    iptables -C INPUT -j $input_block_chain 2>/dev/null || iptables -I INPUT 1 -j $input_block_chain
    
    if [ "$IPV6_SUPPORTED" = "1" ]; then
        ip6tables -N $input_block_chain_v6 2>/dev/null || ip6tables -F $input_block_chain_v6
        ip6tables -C INPUT -j $input_block_chain_v6 2>/dev/null || ip6tables -I INPUT 1 -j $input_block_chain_v6
    fi

    # Cleanup old rules (IPv4)
    iptables -t nat -D PREROUTING -j $nat_chain 2>/dev/null
    iptables -t nat -F $nat_chain 2>/dev/null
    iptables -t nat -X $nat_chain 2>/dev/null
    iptables -D FORWARD -j $filter_chain 2>/dev/null
    iptables -F $filter_chain 2>/dev/null
    iptables -X $filter_chain 2>/dev/null

    # Cleanup old rules (IPv6)
    ip6tables -t nat -D PREROUTING -j $nat_chain_v6 2>/dev/null
    ip6tables -t nat -F $nat_chain_v6 2>/dev/null
    ip6tables -t nat -X $nat_chain_v6 2>/dev/null
    ip6tables -D FORWARD -j $filter_chain_v6 2>/dev/null
    ip6tables -F $filter_chain_v6 2>/dev/null
    ip6tables -X $filter_chain_v6 2>/dev/null

    # Create new chains with error handling
    if ! iptables -t nat -N $nat_chain 2>/dev/null; then
        logger -t wireguard "[$wg_interface] Warning: Could not create IPv4 NAT chain (may exist)"
    fi
    if ! iptables -N $filter_chain 2>/dev/null; then
        logger -t wireguard "[$wg_interface] Warning: Could not create IPv4 filter chain (may exist)"
    fi

    if [ "$IPV6_SUPPORTED" = "1" ]; then
        if ! ip6tables -t nat -N $nat_chain_v6 2>/dev/null; then
            logger -t wireguard "[$wg_interface] Warning: Could not create IPv6 NAT chain (may exist)"
        fi
        if ! ip6tables -N $filter_chain_v6 2>/dev/null; then
            logger -t wireguard "[$wg_interface] Warning: Could not create IPv6 filter chain (may exist)"
        fi
    fi

    # Separate IPv4 and IPv6 DNS servers
    local vpn_dns_v4="" vpn_dns_v6=""
    for dns in $vpn_dns_list; do
        case "$dns" in
            *:*) vpn_dns_v6="$vpn_dns_v6 $dns" ;;
            *.*) vpn_dns_v4="$vpn_dns_v4 $dns" ;;
        esac
    done
    vpn_dns_v4=$(echo "$vpn_dns_v4" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    vpn_dns_v6=$(echo "$vpn_dns_v6" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

    # IPv4 DNS DNAT + Filtering
    if [ -n "$vpn_dns_v4" ]; then
        # Filter VPN_IPS for IPv4 only
        local vpn_ips_v4=""
        for item in $vpn_ips; do
            if ! echo "$item" | grep -q ":"; then
                vpn_ips_v4="$vpn_ips_v4 $item"
            fi
        done

        for item in $vpn_ips_v4; do
            # DNAT DNS queries to VPN DNS (IPv4)
            if [ "$(echo $vpn_dns_v4 | wc -w)" -eq 1 ]; then
                iptables -t nat -A $nat_chain -s $item -p udp --dport 53 -j DNAT --to-destination $vpn_dns_v4
                iptables -t nat -A $nat_chain -s $item -p tcp --dport 53 -j DNAT --to-destination $vpn_dns_v4
            else
                local i=0 dns_count=$(echo $vpn_dns_v4 | wc -w)
                for dns in $vpn_dns_v4; do
                    iptables -t nat -A $nat_chain -s $item -p udp --dport 53 -m statistic --mode nth --every $((dns_count - i)) --packet 0 -j DNAT --to-destination $dns
                    iptables -t nat -A $nat_chain -s $item -p tcp --dport 53 -m statistic --mode nth --every $((dns_count - i)) --packet 0 -j DNAT --to-destination $dns
                    i=$((i + 1))
                done
            fi

            # Block DoT/DoH (IPv4)
            iptables -A $filter_chain -s $item -p tcp --dport 853 -j REJECT --reject-with tcp-reset
            iptables -A $filter_chain -s $item -p udp --dport 853 -j REJECT --reject-with icmp-port-unreachable

            # Dynamically block DoH providers by reading the https-dns-proxy config
            if [ -f /etc/config/https-dns-proxy ]; then
                DOH_DOMAINS=$(grep 'resolver_url' /etc/config/https-dns-proxy | awk -F'/' '{print $3}')
            fi

            # Add any other domains to block
            DOH_DOMAINS="$DOH_DOMAINS dns.quad9.net"

            for domain in $DOH_DOMAINS; do
                iptables -A $filter_chain -s $item -p tcp --dport 443 -m string --algo bm --string "$domain" -j REJECT --reject-with tcp-reset
            done

            # Block access to local dnsmasq (INPUT)
            iptables -A $input_block_chain -s $item -p udp --dport 53 -j REJECT --reject-with icmp-port-unreachable
            iptables -A $input_block_chain -s $item -p tcp --dport 53 -j REJECT --reject-with tcp-reset
        done
        iptables -t nat -I PREROUTING 1 -j $nat_chain 2>/dev/null || \
            logger -t wireguard "[$wg_interface] Warning: Could not insert IPv4 NAT chain"
        iptables -I FORWARD 1 -j $filter_chain 2>/dev/null || \
            logger -t wireguard "[$wg_interface] Warning: Could not insert IPv4 filter chain"
    fi

    # IPv6 DNS DNAT + Filtering
    if [ -n "$vpn_dns_v6" ] && [ "$IPV6_SUPPORTED" = "1" ]; then
        # Filter VPN_IPS for IPv6 only and add routable subnets
        local vpn_ips_v6=""
        for item in $vpn_ips; do
            if echo "$item" | grep -q ":"; then
                vpn_ips_v6="$vpn_ips_v6 $item"
            fi
        done
        # Append routable subnets
        if [ -n "$vpn_ip6_subnets" ]; then
            vpn_ips_v6="$vpn_ips_v6 $vpn_ip6_subnets"
        fi

        for item in $vpn_ips_v6; do
            # DNAT DNS queries to VPN DNS (IPv6)
            if [ "$(echo $vpn_dns_v6 | wc -w)" -eq 1 ]; then
                ip6tables -t nat -A $nat_chain_v6 -s $item -p udp --dport 53 -j DNAT --to-destination $vpn_dns_v6
                ip6tables -t nat -A $nat_chain_v6 -s $item -p tcp --dport 53 -j DNAT --to-destination $vpn_dns_v6
            else
                local i=0 dns_count=$(echo $vpn_dns_v6 | wc -w)
                for dns in $vpn_dns_v6; do
                    ip6tables -t nat -A $nat_chain_v6 -s $item -p udp --dport 53 -m statistic --mode nth --every $((dns_count - i)) --packet 0 -j DNAT --to-destination "[$dns]"
                    ip6tables -t nat -A $nat_chain_v6 -s $item -p tcp --dport 53 -m statistic --mode nth --every $((dns_count - i)) --packet 0 -j DNAT --to-destination "[$dns]"
                    i=$((i + 1))
                done
            fi

            # Block access to local dnsmasq (INPUT)
            ip6tables -A $input_block_chain_v6 -s $item -p udp --dport 53 -j REJECT --reject-with icmp6-port-unreachable
            ip6tables -A $input_block_chain_v6 -s $item -p tcp --dport 53 -j REJECT --reject-with tcp-reset
        done

        # Block DoT/DoH (IPv6) - apply broadly
        ip6tables -A $filter_chain_v6 -p tcp --dport 853 -j REJECT --reject-with tcp-reset
        ip6tables -A $filter_chain_v6 -p udp --dport 853 -j REJECT --reject-with icmp6-port-unreachable
        ip6tables -A $filter_chain_v6 -p tcp --dport 443 -m string --algo bm --string "dns.google" -j REJECT --reject-with tcp-reset
        ip6tables -A $filter_chain_v6 -p tcp --dport 443 -m string --algo bm --string "cloudflare-dns.com" -j REJECT --reject-with tcp-reset
        ip6tables -A $filter_chain_v6 -p tcp --dport 443 -m string --algo bm --string "dns.quad9.net" -j REJECT --reject-with tcp-reset

        ip6tables -t nat -I PREROUTING 1 -j $nat_chain_v6
        ip6tables -I FORWARD 1 -j $filter_chain_v6
    fi

    logger -t wireguard "[$wg_interface] Complete DNS hijacking configured (IPv4+IPv6)"
}

apply_ipv6_rules() {
    # This function only runs if IPV6_SUPPORTED=1
    local mac_addr="$1"
    local subnet_item="${2:-}"
    logger -t wireguard "[$WG_INTERFACE] Starting IPv6 discovery for MAC: $mac_addr"
    (
        start_time=$(date +%s 2>/dev/null || echo 0)
        start_time_ns=$(date +%s%N 2>/dev/null || echo ${start_time}000000000)
        MAX_RETRIES=10
        RETRY_COUNT=0
        PING_CLIENT=1

        # If proactive mode, try to trigger IPv6 discovery
        if [ $PING_CLIENT -eq 1 ]; then
            client_ip=$(ip neigh show | grep -i "$mac_addr" | awk '{print $1}' | head -1)
            if [ -n "$client_ip" ]; then
                logger -t wireguard "[$WG_INTERFACE] Proactively pinging $client_ip to discover IPv6..."
                ping -c 3 -W 1 "$client_ip" >/dev/null 2>&1 &
            fi
        fi

        while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
            sleep 2
            ipv6_addrs=$(ip -6 neigh show | grep -i "$mac_addr" | grep -v "fe80:" | awk '{print $1}')

            if [ -n "$ipv6_addrs" ]; then
                ipv6_addr=$(echo "$ipv6_addrs" | head -n1)
                STATE_FILE="/tmp/wg_prefix_${WG_INTERFACE}_${mac_addr//:/}"
                
                # Check if this IPv6 address is within a routable VPN subnet
                # VPN_IP6_SUBNETS is provided by the main script
                IN_VPN_SUBNET=0
                if [ -n "$VPN_IP6_SUBNETS" ]; then
                    for vpn_subnet in $VPN_IP6_SUBNETS; do
                        # Extract prefix length from VPN subnet (e.g., /64 from 2001:db8::/64)
                        vpn_prefix_len="${vpn_subnet##*/}"
                        vpn_network="${vpn_subnet%/*}"
                        
                        # Simple prefix match check (first 4 blocks for /64)
                        if [ "$vpn_prefix_len" -le 64 ]; then
                            vpn_prefix_part=$(echo "$vpn_network" | cut -d: -f1-4)
                            client_prefix_part=$(echo "$ipv6_addr" | cut -d: -f1-4)
                            if [ "$vpn_prefix_part" = "$client_prefix_part" ]; then
                                IN_VPN_SUBNET=1
                                logger -t wireguard "[$WG_INTERFACE] Client $ipv6_addr is within VPN subnet $vpn_subnet"
                                break
                            fi
                        fi
                    done
                fi
                
                if [ "$IN_VPN_SUBNET" = "1" ]; then
                    # Client is within routable VPN subnet - route the full /128 address
                    new_rule="${ipv6_addr}/128"
                    old_rule=""
                    [ -f "$STATE_FILE" ] && old_rule=$(cat "$STATE_FILE")
                    
                    if [ "$old_rule" != "$new_rule" ]; then
                        logger -t wireguard "[$WG_INTERFACE] Routing client IPv6 $new_rule (within VPN subnet)"
                        
                        # Remove old rule if different
                        if [ -n "$old_rule" ]; then
                            ip -6 rule del from $old_rule table $ROUTING_TABLE 2>/dev/null
                        fi
                        
                        # Add new rule
                        ip -6 rule del from $new_rule table $ROUTING_TABLE 2>/dev/null
                        ip -6 rule add from $new_rule table $ROUTING_TABLE priority $ROUTING_TABLE
                        echo "$new_rule" > "$STATE_FILE"
                    fi
                else
                    # Legacy behavior: client has own prefix delegation, extract /64
                    prefix=$(echo "$ipv6_addr" | cut -d: -f1-4)
                    if [ -n "$prefix" ]; then
                        # Clean up old rule before adding new one
                        if [ -f "$STATE_FILE" ]; then
                            OLD_PREFIX=$(cat "$STATE_FILE")
                            # Check if old rule was a /64 or /128
                            if echo "$OLD_PREFIX" | grep -q '/128'; then
                                # Old was /128, delete it
                                ip -6 rule del from $OLD_PREFIX table $ROUTING_TABLE 2>/dev/null
                            elif [ "$OLD_PREFIX" != "$prefix" ]; then
                                logger -t wireguard "[$WG_INTERFACE] IPv6 prefix changed for $mac_addr. Old: $OLD_PREFIX, New: $prefix. Updating rule."
                                ip -6 rule del from ${OLD_PREFIX}::/64 table $ROUTING_TABLE 2>/dev/null
                            fi
                        fi

                        # Add routing FIRST (with idempotency)
                        ip -6 rule del from ${prefix}::/64 table $ROUTING_TABLE 2>/dev/null
                        ip -6 rule add from ${prefix}::/64 table $ROUTING_TABLE priority $ROUTING_TABLE
                        echo "$prefix" > "$STATE_FILE"
                        logger -t wireguard "[$WG_INTERFACE] Routing client IPv6 prefix ${prefix}::/64 (prefix delegation)"
                    fi
                fi
                
                # Verify default route is correct, but DO NOT remove the block rule.
                # Keeping the block rule ensures that if the client tries to use a non-VPN IPv6 address (like ISP global),
                # it will be blocked instead of leaking.
                if ip -6 route show table "$ROUTING_TABLE" | grep -q "default dev $WG_INTERFACE"; then
                    # lan_ifaces=$(ip link show | grep -o 'br-lan[^:]*' | tr '\n' ' ')
                    # [ -z "$lan_ifaces" ] && lan_ifaces="br-lan"
                    # for lan_if in $lan_ifaces; do
                    #    ip6tables -D $BLOCK_CHAIN -i $lan_if ! -o $WG_INTERFACE -m mac --mac-source $mac_addr -j DROP 2>/dev/null
                    # done
                    end_time_ns=$(date +%s%N 2>/dev/null || echo ${start_time}000000000)
                    elapsed_ms=$(( (end_time_ns - start_time_ns) / 1000000 ))
                    elapsed_s=$(printf "%d.%03d" $((elapsed_ms / 1000)) $((elapsed_ms % 1000)) 2>/dev/null || echo "$((RETRY_COUNT * 2))")
                    logger -t wireguard "[$WG_INTERFACE] IPv6 unblocked and routed for $mac_addr in ${elapsed_s}s"
                    return 0
                else
                     logger -t wireguard "[$WG_INTERFACE] ERROR: Default IPv6 route in table $ROUTING_TABLE is missing or incorrect. IPv6 remains blocked for $mac_addr."
                fi
                return 1 # Exit on first valid prefix found, even if routing fails
            fi

            RETRY_COUNT=$((RETRY_COUNT+1))
            if [ $RETRY_COUNT -eq 1 ]; then
                logger -t wireguard "[$WG_INTERFACE] IPv6 not found for MAC $mac_addr, retrying every 2 seconds..."
            fi
        done


        logger -t wireguard "[$WG_INTERFACE] WARNING: IPv6 not found for MAC $mac_addr after $((MAX_RETRIES * 2))s. IPv6 remains blocked."
    ) &
}

# Disable Kill Switch
logger -t wireguard "[$WG_INTERFACE] Interface is up. Disabling kill switch."
iptables -F $KS_CHAIN 2>/dev/null; ip6tables -F $KS_CHAIN 2>/dev/null
iptables -D FORWARD -j $KS_CHAIN 2>/dev/null; ip6tables -D FORWARD -j $KS_CHAIN 2>/dev/null
iptables -X $KS_CHAIN 2>/dev/null; ip6tables -X $KS_CHAIN 2>/dev/null

# Create IPv6 DNS blocking chain for ALL interfaces (needed for DNS leak prevention and proper roaming cleanup)
ip6tables -F $BLOCK_IPV6_DNS_INPUT_CHAIN 2>/dev/null
ip6tables -X $BLOCK_IPV6_DNS_INPUT_CHAIN 2>/dev/null
ip6tables -N $BLOCK_IPV6_DNS_INPUT_CHAIN 2>/dev/null
ip6tables -C INPUT -j $BLOCK_IPV6_DNS_INPUT_CHAIN 2>/dev/null || ip6tables -I INPUT 1 -j $BLOCK_IPV6_DNS_INPUT_CHAIN

# Create appropriate IPv6 blocking chain (leak prevention OR IPv4-only block)
if [ "$IPV6_SUPPORTED" = "1" ]; then
    ip6tables -F $BLOCK_CHAIN 2>/dev/null
    ip6tables -X $BLOCK_CHAIN 2>/dev/null
    ip6tables -N $BLOCK_CHAIN 2>/dev/null
    ip6tables -C FORWARD -j $BLOCK_CHAIN 2>/dev/null || ip6tables -I FORWARD 1 -j $BLOCK_CHAIN
else
    logger -t wireguard "[$WG_INTERFACE] IPv4-only tunnel detected. IPv6 will be blocked for specified clients."
    
    ip6tables -F $BLOCK_IPV4_ONLY_CHAIN 2>/dev/null
    ip6tables -X $BLOCK_IPV4_ONLY_CHAIN 2>/dev/null
    ip6tables -N $BLOCK_IPV4_ONLY_CHAIN 2>/dev/null

    ip6tables -C FORWARD -j $BLOCK_IPV4_ONLY_CHAIN 2>/dev/null || ip6tables -I FORWARD 1 -j $BLOCK_IPV4_ONLY_CHAIN
fi

# Setup routing table
logger -t wireguard "[$WG_INTERFACE] Setting up default routes in table $ROUTING_TABLE."
ip route flush table $ROUTING_TABLE 2>/dev/null; ip -6 route flush table $ROUTING_TABLE 2>/dev/null
ip route add default dev $WG_INTERFACE table $ROUTING_TABLE
if [ "$IPV6_SUPPORTED" = "1" ]; then
    ip -6 route add default dev $WG_INTERFACE table $ROUTING_TABLE 2>/dev/null
    # Add routable IPv6 subnets to the routing table
    VPN_IP6_SUBNETS="VPN_IP6_SUBNETS_PLACEHOLDER"
    VPN_IP6_NEEDS_NAT66="VPN_IP6_NEEDS_NAT66_PLACEHOLDER"
    if [ -n "$VPN_IP6_SUBNETS" ]; then
        for subnet in $VPN_IP6_SUBNETS; do
            logger -t wireguard "[$WG_INTERFACE] Adding routable IPv6 subnet $subnet to table $ROUTING_TABLE"
            ip -6 route add $subnet dev $WG_INTERFACE table $ROUTING_TABLE 2>/dev/null
        done
    fi
    
    # Enable NAT66 masquerading if needed (for /128 addresses)
    if [ "$VPN_IP6_NEEDS_NAT66" = "1" ]; then
        NAT66_CHAIN="nat66_${WG_INTERFACE}"
        logger -t wireguard "[$WG_INTERFACE] Enabling IPv6 masquerading (NAT66) for /128 address"
        
        # Create NAT66 chain
        ip6tables -t nat -N $NAT66_CHAIN 2>/dev/null || ip6tables -t nat -F $NAT66_CHAIN
        ip6tables -t nat -A $NAT66_CHAIN -o $WG_INTERFACE -m mark --mark $MARK_VALUE -j MASQUERADE
        
        # Insert into POSTROUTING
        ip6tables -t nat -D POSTROUTING -j $NAT66_CHAIN 2>/dev/null
        ip6tables -t nat -I POSTROUTING 1 -j $NAT66_CHAIN
        
        logger -t wireguard "[$WG_INTERFACE] NAT66 masquerading enabled on $WG_INTERFACE"
    fi

    # Universal IPv6 Routing: Use fwmark-based routing for ALL IPv6 clients.
    # This replaces legacy "ip rule from <prefix>" logic which was fragile and broke roaming.
    # With fwmark, we rout based on MAC address, so roaming is seamless.
    
    IPV6_MARK_CHAIN="mark_ipv6_${WG_INTERFACE}"
    logger -t wireguard "[$WG_INTERFACE] Setting up universal MAC-based fwmark IPv6 routing"
    
    # Create IPv6 marking chain
    ip6tables -t mangle -N $IPV6_MARK_CHAIN 2>/dev/null || ip6tables -t mangle -F $IPV6_MARK_CHAIN
    
    PROCESSED_MACS_V6=""
    
    # Get DHCP lease file location
    DHCP_LEASE_FILE=$(get_dhcp_lease_file)

    for item in $VPN_IPS; do
        case "$item" in
            */*) # Subnet
                # Skip IPv6 subnets - is_in_subnet is IPv4-only. We only mark MACs from user config which are usually IPv4 subnets/IPs.
                echo "$item" | grep -q ":" && continue
                # Scan DHCP leases for clients in this subnet
                if [ -n "$DHCP_LEASE_FILE" ]; then
                    while read -r exp mac ip host; do
                        if is_in_subnet "$ip" "$item" && ! echo "$PROCESSED_MACS_V6" | grep -q "$mac"; then
                            PROCESSED_MACS_V6="$PROCESSED_MACS_V6 $mac"
                            logger -t wireguard "[$WG_INTERFACE] Marking IPv6 traffic from $ip ($mac) for VPN routing"
                            # Mark ALL IPv6 packets from this MAC with the routing mark
                            ip6tables -t mangle -A $IPV6_MARK_CHAIN -m mac --mac-source $mac -j MARK --set-mark $MARK_VALUE
                        fi
                    done < "$DHCP_LEASE_FILE"
                fi
                
                # Also check ARP table
                ip neigh show > /tmp/neigh_v6marked_${WG_INTERFACE}_$$
                while read -r line; do
                    ip=$(echo $line | awk '{print $1}')
                    mac=$(echo $line | grep -o -E '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}')
                    if [ -n "$mac" ] && is_in_subnet "$ip" "$item" && ! echo "$PROCESSED_MACS_V6" | grep -q "$mac"; then
                        PROCESSED_MACS_V6="$PROCESSED_MACS_V6 $mac"
                        logger -t wireguard "[$WG_INTERFACE] Marking IPv6 traffic from $ip ($mac) via ARP"
                        ip6tables -t mangle -A $IPV6_MARK_CHAIN -m mac --mac-source $mac -j MARK --set-mark $MARK_VALUE
                    fi
                done < /tmp/neigh_v6marked_${WG_INTERFACE}_$$
                rm -f /tmp/neigh_v6marked_${WG_INTERFACE}_$$
                ;;
            *) # Single IP
                # Skip pure IPv6 IPs from this discovery as we can't 'ping' them easily blindly, but usually target-ips are IPv4.
                # If target IS an IPv6 address, we might need manual handling, but standard usage is IPv4 target -> dual stack routing.
                
                mac=$(discover_mac_for_ip "$item")
                
                if [ -n "$mac" ]; then
                    logger -t wireguard "[$WG_INTERFACE] Marking IPv6 traffic from $item ($mac)"
                    ip6tables -t mangle -A $IPV6_MARK_CHAIN -m mac --mac-source $mac -j MARK --set-mark $MARK_VALUE
                else
                    logger -t wireguard "[$WG_INTERFACE] WARNING: Could not discover MAC for $item after retries, IPv6 may not route correctly"
                fi
                ;;
        esac
    done
    
    # Apply marking rules to PREROUTING
    lan_ifaces=$(get_lan_ifaces)
    for lan_if in $lan_ifaces; do
        ip6tables -t mangle -C PREROUTING -i $lan_if -j $IPV6_MARK_CHAIN 2>/dev/null || \
            ip6tables -t mangle -A PREROUTING -i $lan_if -j $IPV6_MARK_CHAIN
    done
    
    logger -t wireguard "[$WG_INTERFACE] IPv6 fwmark routing configured - clients can roam between VLANs"

    # Setup IPv6 DNS DNAT (using fwmark matching) - also universal now
    # Extract IPv6 DNS from VPN_DNS
    VPN_DNS_V6=""
    for dns in $VPN_DNS; do
        echo "$dns" | grep -q ":" && VPN_DNS_V6="$VPN_DNS_V6 $dns"
    done
    
    if [ -n "$VPN_DNS_V6" ]; then
        MARK_DNS_CHAIN="mark_dns_v6_${WG_INTERFACE}"
        ip6tables -t nat -N $MARK_DNS_CHAIN 2>/dev/null || ip6tables -t nat -F $MARK_DNS_CHAIN
        
        # DNAT all DNS from marked traffic to VPN IPv6 DNS
        first_dns=$(echo $VPN_DNS_V6 | awk '{print $1}')
        ip6tables -t nat -A $MARK_DNS_CHAIN -m mark --mark $MARK_VALUE -p udp --dport 53 -j DNAT --to-destination $first_dns
        ip6tables -t nat -A $MARK_DNS_CHAIN -m mark --mark $MARK_VALUE -p tcp --dport 53 -j DNAT --to-destination $first_dns
        
        # Insert into PREROUTING
        ip6tables -t nat -D PREROUTING -j $MARK_DNS_CHAIN 2>/dev/null
        ip6tables -t nat -I PREROUTING 1 -j $MARK_DNS_CHAIN
        
        logger -t wireguard "[$WG_INTERFACE] IPv6 DNS redirect configured to $first_dns"
    fi
fi

# Create/Flush ipset on every ifup to prevent race condition
logger -t wireguard "[$WG_INTERFACE] Creating/flushing ipset $IPSET_NAME."
ipset create $IPSET_NAME hash:net 2>/dev/null || ipset flush $IPSET_NAME
for item in $VPN_IPS; do
    if echo "$item" | grep -q ":"; then
         ipset add $IPSET_NAME_V6 $item 2>/dev/null
    else
         ipset add $IPSET_NAME $item 2>/dev/null
    fi
done

# CRITICAL: Block WAN DNS responses to VPN clients (IPv4) - applied EARLY
logger -t wireguard "[$WG_INTERFACE] Blocking WAN DNS responses to VPN clients (IPv4)"
iptables -t mangle -D OUTPUT -p udp --sport 53 -m set --match-set $IPSET_NAME dst -m mark ! --mark $MARK_VALUE -j DROP 2>/dev/null
iptables -t mangle -D OUTPUT -p tcp --sport 53 -m set --match-set $IPSET_NAME dst -m mark ! --mark $MARK_VALUE -j DROP 2>/dev/null
iptables -t mangle -I OUTPUT 1 -p udp --sport 53 -m set --match-set $IPSET_NAME dst -m mark ! --mark $MARK_VALUE -j DROP
iptables -t mangle -I OUTPUT 1 -p tcp --sport 53 -m set --match-set $IPSET_NAME dst -m mark ! --mark $MARK_VALUE -j DROP

# CRITICAL: Block WAN DNS responses to VPN clients (IPv6) - applied EARLY
if [ "$IPV6_SUPPORTED" = "1" ]; then
    logger -t wireguard "[$WG_INTERFACE] Blocking WAN DNS responses to VPN clients (IPv6)"
    ip6tables -t mangle -D OUTPUT -p udp --sport 53 -m set --match-set $IPSET_NAME_V6 dst -m mark ! --mark $MARK_VALUE -j DROP 2>/dev/null
    ip6tables -t mangle -D OUTPUT -p tcp --sport 53 -m set --match-set $IPSET_NAME_V6 dst -m mark ! --mark $MARK_VALUE -j DROP 2>/dev/null
    ip6tables -t mangle -I OUTPUT 1 -p udp --sport 53 -m set --match-set $IPSET_NAME_V6 dst -m mark ! --mark $MARK_VALUE -j DROP
    ip6tables -t mangle -I OUTPUT 1 -p tcp --sport 53 -m set --match-set $IPSET_NAME_V6 dst -m mark ! --mark $MARK_VALUE -j DROP
fi

# Setup fwmark for DNS routing (IPv4)
logger -t wireguard "[$WG_INTERFACE] Setting up DNS fwmark $MARK_VALUE (IPv4)."
iptables -t mangle -N $MARK_CHAIN 2>/dev/null
iptables -t mangle -F $MARK_CHAIN
iptables -t mangle -A $MARK_CHAIN -p udp --dport 53 -m set --match-set $IPSET_NAME src -j MARK --set-mark $MARK_VALUE
iptables -t mangle -A $MARK_CHAIN -p tcp --dport 53 -m set --match-set $IPSET_NAME src -j MARK --set-mark $MARK_VALUE

# Mark outgoing DNS requests from Router to VPN DNS servers (IPv4)
for dns in $VPN_DNS; do
    if ! echo "$dns" | grep -q ":"; then
        iptables -t mangle -A OUTPUT -d $dns -p udp --dport 53 -j MARK --set-mark $MARK_VALUE
        iptables -t mangle -A OUTPUT -d $dns -p tcp --dport 53 -j MARK --set-mark $MARK_VALUE
    fi
done

lan_ifaces=$(get_lan_ifaces)
for lan_if in $lan_ifaces; do
    iptables -t mangle -C PREROUTING -i $lan_if -j $MARK_CHAIN 2>/dev/null || iptables -t mangle -A PREROUTING -i $lan_if -j $MARK_CHAIN
done

# Setup fwmark for DNS routing (IPv6)
if [ "$IPV6_SUPPORTED" = "1" ]; then
    logger -t wireguard "[$WG_INTERFACE] Setting up DNS fwmark $MARK_VALUE (IPv6)."
    ip6tables -t mangle -N $MARK_CHAIN 2>/dev/null
    ip6tables -t mangle -F $MARK_CHAIN
    ip6tables -t mangle -A $MARK_CHAIN -p udp --dport 53 -m set --match-set $IPSET_NAME_V6 src -j MARK --set-mark $MARK_VALUE
    ip6tables -t mangle -A $MARK_CHAIN -p tcp --dport 53 -m set --match-set $IPSET_NAME_V6 src -j MARK --set-mark $MARK_VALUE

    # Mark outgoing DNS requests from Router to VPN DNS servers (IPv6)
    for dns in $VPN_DNS; do
        if echo "$dns" | grep -q ":"; then
            ip6tables -t mangle -A OUTPUT -d $dns -p udp --dport 53 -j MARK --set-mark $MARK_VALUE
            ip6tables -t mangle -A OUTPUT -d $dns -p tcp --dport 53 -j MARK --set-mark $MARK_VALUE
        fi
    done

    for lan_if in $lan_ifaces; do
        ip6tables -t mangle -C PREROUTING -i $lan_if -j $MARK_CHAIN 2>/dev/null || ip6tables -t mangle -A PREROUTING -i $lan_if -j $MARK_CHAIN
    done

fi

ip rule del fwmark $MARK_VALUE table $ROUTING_TABLE 2>/dev/null
ip rule add fwmark $MARK_VALUE table $ROUTING_TABLE priority $((ROUTING_TABLE - 5))
if [ "$IPV6_SUPPORTED" = "1" ]; then
    ip -6 rule del fwmark $MARK_VALUE table $ROUTING_TABLE 2>/dev/null
    ip -6 rule add fwmark $MARK_VALUE table $ROUTING_TABLE priority $((ROUTING_TABLE - 5))
fi

# Discover and configure existing clients
logger -t wireguard "[$WG_INTERFACE] Scanning for existing clients and applying rules..."
PROCESSED_MACS=""

# Get DHCP lease file location (reuse helper)
DHCP_LEASE_FILE=$(get_dhcp_lease_file)

for item in $VPN_IPS; do
    case "$item" in
        */*) # This is a subnet
            ip rule add from $item table $ROUTING_TABLE priority $ROUTING_TABLE 2>/dev/null

            # 1. DHCP Leases (Primary)
            if [ -n "$DHCP_LEASE_FILE" ]; then
                while read -r exp mac ip host; do
                    if is_in_subnet "$ip" "$item" && ! echo "$PROCESSED_MACS" | grep -q "$mac"; then
                        PROCESSED_MACS="$PROCESSED_MACS $mac"
                        logger -t wireguard "[$WG_INTERFACE] Found existing client $ip ($mac) in $item via DHCP lease."
                        ip rule add from $ip table $ROUTING_TABLE priority $ROUTING_TABLE 2>/dev/null
                        handle_client_ipv6 "$mac" "$ip" "$ip"
                    fi
                done < "$DHCP_LEASE_FILE"
            fi

            # 2. ARP/NDP Table (Fallback)
            ip neigh show > /tmp/neigh_${WG_INTERFACE}_$$
            while read -r line; do
                ip=$(echo $line | awk '{print $1}')
                mac=$(echo $line | grep -o -E '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}')
                if [ -n "$mac" ] && is_in_subnet "$ip" "$item" && ! echo "$PROCESSED_MACS" | grep -q "$mac"; then
                    PROCESSED_MACS="$PROCESSED_MACS $mac"
                    logger -t wireguard "[$WG_INTERFACE] Found existing client $ip ($mac) in $item via ARP/NDP table."
                    ip rule add from $ip table $ROUTING_TABLE priority $ROUTING_TABLE 2>/dev/null
                    handle_client_ipv6 "$mac" "$ip" "$ip"
                fi
            done < /tmp/neigh_${WG_INTERFACE}_$$
            rm -f /tmp/neigh_${WG_INTERFACE}_$$
            ;;
        *) # This is an individual IP
            # Always add rule for explicit single IPs
            ip rule add from $item table $ROUTING_TABLE priority $ROUTING_TABLE 2>/dev/null

            # Discover MAC address for this IP
            mac=$(discover_mac_for_ip "$item")
            
            if [ -n "$mac" ] && ! echo "$PROCESSED_MACS" | grep -q "$mac"; then
                logger -t wireguard "[$WG_INTERFACE] Found existing client $item ($mac)."
                handle_client_ipv6 "$mac" "$item" "$item"
            fi
            ;;
    esac
done

# Restore rules for clients registered in MAC state file (for fw-reload via 'reapply' command)
# This ensures DHCP hotplug added clients don't lose their rules after rule re-application
WG_MAC_STATE="/tmp/wg_mac_state"
if [ -f "$WG_MAC_STATE" ] && [ "$IPV6_SUPPORTED" = "1" ]; then
    logger -t wireguard "[$WG_INTERFACE] Restoring block rules from MAC state file..."
    while IFS='|' read -r mac iface ip rt ipv6_sup; do
        # Debug: log what we're comparing
        logger -t wireguard "[$WG_INTERFACE] DEBUG: MAC=$mac IFACE=$iface (expect $WG_INTERFACE)"
        # Only restore for THIS interface
        if [ "$iface" = "$WG_INTERFACE" ] && [ -n "$mac" ]; then
            # Check if we already processed this MAC (avoid duplicates)
            if ! echo "$PROCESSED_MACS" | grep -q "$mac"; then
                PROCESSED_MACS="$PROCESSED_MACS $mac"
                logger -t wireguard "[$WG_INTERFACE] Restoring rules for MAC $mac (IP: $ip) from state file"
                
                # Re-add fwmark marking rule if not present
                if ! ip6tables -t mangle -C $IPV6_MARK_CHAIN -m mac --mac-source $mac -j MARK --set-mark $MARK_VALUE 2>/dev/null; then
                    ip6tables -t mangle -A $IPV6_MARK_CHAIN -m mac --mac-source $mac -j MARK --set-mark $MARK_VALUE
                fi
                
                # Re-add block rules for leak prevention
                lan_ifaces=$(get_lan_ifaces)
                for lan_if in $lan_ifaces; do
                    ip6tables -D $BLOCK_CHAIN -i $lan_if -m mac --mac-source $mac -m mark ! --mark $MARK_VALUE -j DROP 2>/dev/null
                    ip6tables -I $BLOCK_CHAIN 1 -i $lan_if -m mac --mac-source $mac -m mark ! --mark $MARK_VALUE -j DROP
                done
                
                # Re-add IPv6 DNS blocking
                ip6tables -D $BLOCK_IPV6_DNS_INPUT_CHAIN -m mac --mac-source $mac -p udp --dport 53 -j REJECT 2>/dev/null
                ip6tables -D $BLOCK_IPV6_DNS_INPUT_CHAIN -m mac --mac-source $mac -p tcp --dport 53 -j REJECT 2>/dev/null
                ip6tables -A $BLOCK_IPV6_DNS_INPUT_CHAIN -m mac --mac-source $mac -p udp --dport 53 -j REJECT
                ip6tables -A $BLOCK_IPV6_DNS_INPUT_CHAIN -m mac --mac-source $mac -p tcp --dport 53 -j REJECT
            fi
        fi
    done < "$WG_MAC_STATE"
fi

# Setup VPN DNS redirect if DNS servers are configured
if [ -n "$VPN_DNS" ]; then
    setup_secure_dns "$VPN_DNS" "$VPN_IPS" "$WG_INTERFACE" "$VPN_IP6_SUBNETS"
fi

ip route flush cache; ip -6 route flush cache 2>/dev/null

# Update Registry on ifup to ensure persistence across restarts
WG_REGISTRY="/tmp/wg_interface_registry"
# Convert space-separated to comma-separated for storage
VPN_IPS_CSV=$(echo "$VPN_IPS" | tr ' ' ',')
# Remove old entry for this interface
sed -i "/^${WG_INTERFACE}|/d" "$WG_REGISTRY" 2>/dev/null || true
touch "$WG_REGISTRY"
# Add new entry
echo "${WG_INTERFACE}|${ROUTING_TABLE}|${VPN_IPS_CSV}|${IPV6_SUPPORTED}|${VPN_IP6_SUBNETS}|${VPN_IP6_NEEDS_NAT66}" >> "$WG_REGISTRY"
logger -t wireguard "[$WG_INTERFACE] Registered interface in registry."

# Add a final dnsmasq reload to ensure it binds to the ipset
logger -t wireguard "[$WG_INTERFACE] Performing guaranteed dnsmasq reload."
( /etc/init.d/dnsmasq reload >/dev/null 2>&1 ) &

EOF_IFACE_ROUTING

# Inject the common library content
inject_common_lib "/etc/hotplug.d/iface/99-${INTERFACE_NAME}-routing"

sed -i "s|INTERFACE_NAME_PLACEHOLDER|$INTERFACE_NAME|g" /etc/hotplug.d/iface/99-${INTERFACE_NAME}-routing
sed -i "s|ROUTING_TABLE_PLACEHOLDER|$ROUTING_TABLE|g" /etc/hotplug.d/iface/99-${INTERFACE_NAME}-routing
sed -i "s|VPN_IPS_PLACEHOLDER|$VPN_IPS|g" /etc/hotplug.d/iface/99-${INTERFACE_NAME}-routing
sed -i "s|IPV6_SUPPORTED_PLACEHOLDER|$IPV6_SUPPORTED|g" /etc/hotplug.d/iface/99-${INTERFACE_NAME}-routing
sed -i "s|VPN_DNS_PLACEHOLDER|$VPN_DNS_SERVERS|g" /etc/hotplug.d/iface/99-${INTERFACE_NAME}-routing
sed -i "s|IPSET_NAME_PLACEHOLDER|$IPSET_NAME|g" /etc/hotplug.d/iface/99-${INTERFACE_NAME}-routing
sed -i "s|VPN_IP6_SUBNETS_PLACEHOLDER|$VPN_IP6_SUBNETS|g" /etc/hotplug.d/iface/99-${INTERFACE_NAME}-routing
sed -i "s|VPN_IP6_NEEDS_NAT66_PLACEHOLDER|$VPN_IP6_NEEDS_NAT66|g" /etc/hotplug.d/iface/99-${INTERFACE_NAME}-routing
chmod +x /etc/hotplug.d/iface/99-${INTERFACE_NAME}-routing

# Update interface registry and create/update master DHCP hotplug script
echo "Updating WireGuard interface registry..."
update_wg_registry "$INTERFACE_NAME" "$ROUTING_TABLE" "$VPN_IPS" "$IPV6_SUPPORTED" "$VPN_IP6_SUBNETS" "$VPN_IP6_NEEDS_NAT66"

# Remove old per-interface DHCP hotplug script if it exists
rm -f "$DHCP_HOTPLUG_SCRIPT" 2>/dev/null

# Create/update master DHCP hotplug script (always overwrite to ensure latest version)
echo "Creating/updating master DHCP hotplug script: $MASTER_DHCP_HOTPLUG"
cat > "$MASTER_DHCP_HOTPLUG" << 'EOF_MASTER_DHCP'
#!/bin/sh
# Master DHCP hotplug for all WireGuard interfaces
# This script replaces per-interface DHCP hotplug scripts for efficiency

WG_REGISTRY="/tmp/wg_interface_registry"
WG_MAC_STATE="/tmp/wg_mac_state"
LOCK_FILE="/tmp/wg_dhcp_hotplug.lock"

[ "$ACTION" = "add" ] || [ "$ACTION" = "new" ] || exit 0
[ -f "$WG_REGISTRY" ] || exit 0

# Acquire lock to prevent race conditions (BusyBox flock doesn't support -w)
exec 200>"$LOCK_FILE"
flock -x 200 || exit 1

# === INJECTED COMMON LIBRARY ===
COMMON_LIB_PLACEHOLDER

# === CLEANUP FUNCTION FOR A SPECIFIC INTERFACE ===
cleanup_client_from_interface() {
    local iface="$1" mac="$2" rt="$3" ipv6_sup="$4"
    local MARK_VALUE="$((0x10000 + rt))"
    local IPV6_MARK_CHAIN="mark_ipv6_${iface}"
    local BLOCK_CHAIN="${iface}_ipv6_block"
    local BLOCK_IPV4_ONLY_CHAIN="${iface}_ipv4_only_block"
    local BLOCK_IPV6_DNS_INPUT_CHAIN="${iface}_v6_dns_in"
    
    # Remove IPv4 routing rule using state file
    local OLD_IP_FILE="/tmp/wg_ip_${iface}_${mac//:/}"
    if [ -f "$OLD_IP_FILE" ]; then
        local OLD_IP=$(cat "$OLD_IP_FILE")
        ip rule del from "$OLD_IP" table $rt 2>/dev/null
        rm -f "$OLD_IP_FILE"
        logger -t wg-dhcp-master "[$iface] Removed IPv4 rule for $OLD_IP"
    fi
    
    # Remove IPv6 fwmark (NAT66 mode) - loop to remove all duplicates
    while ip6tables -t mangle -D $IPV6_MARK_CHAIN -m mac --mac-source $mac -j MARK --set-mark $MARK_VALUE 2>/dev/null; do :; done
    
    # Remove IPv6 block rules (both old and new format) - loop to remove all duplicates
    local lan_ifaces=$(get_lan_ifaces)
    for lan_if in $lan_ifaces; do
        while ip6tables -D $BLOCK_CHAIN -i $lan_if ! -o $iface -m mac --mac-source $mac -j DROP 2>/dev/null; do :; done
        while ip6tables -D $BLOCK_CHAIN -i $lan_if -m mac --mac-source $mac -m mark ! --mark $MARK_VALUE -j DROP 2>/dev/null; do :; done
    done
    ip6tables -D $BLOCK_IPV4_ONLY_CHAIN -m mac --mac-source $mac -j DROP 2>/dev/null
    ip6tables -D INPUT -m mac --mac-source $mac -p icmpv6 --icmpv6-type 133 -j DROP 2>/dev/null
    ip6tables -D INPUT -m mac --mac-source $mac -p udp --dport 547 -j DROP 2>/dev/null
    while ip6tables -D $BLOCK_IPV6_DNS_INPUT_CHAIN -m mac --mac-source $mac -p udp --dport 53 -j REJECT 2>/dev/null; do :; done
    while ip6tables -D $BLOCK_IPV6_DNS_INPUT_CHAIN -m mac --mac-source $mac -p tcp --dport 53 -j REJECT 2>/dev/null; do :; done
    
    # Remove IPv6 routing rule using state file
    local STATE_FILE="/tmp/wg_prefix_${iface}_${mac//:/}"
    if [ -f "$STATE_FILE" ]; then
        local OLD_RULE=$(cat "$STATE_FILE")
        if [ -n "$OLD_RULE" ]; then
            if echo "$OLD_RULE" | grep -q '/'; then
                ip -6 rule del from "$OLD_RULE" table $rt 2>/dev/null
            else
                ip -6 rule del from "${OLD_RULE}::/64" table $rt 2>/dev/null
            fi
        fi
        rm -f "$STATE_FILE"
    fi
    
    # Flush route cache to apply changes immediately
    ip -6 route flush cache 2>/dev/null
    
    logger -t wg-dhcp-master "[$iface] Cleaned up roaming client $mac"
}

# === FIND MATCHING INTERFACE ===
MATCHED_IFACE=""
while IFS='|' read -r iface rt vpn_ips ipv6_sup vpn_ip6_subs vpn_ip6_nat66; do
    # Convert comma-separated VPN_IPS to space-separated for is_in_list
    vpn_ips_spaced=$(echo "$vpn_ips" | tr ',' ' ')
    if is_in_list "$IPADDR" "$vpn_ips_spaced"; then
        MATCHED_IFACE="$iface"
        MATCHED_RT="$rt"
        MATCHED_VPN_IPS="$vpn_ips_spaced"
        MATCHED_IPV6_SUP="$ipv6_sup"
        MATCHED_VPN_IP6_SUBS="$vpn_ip6_subs"
        MATCHED_VPN_IP6_NAT66="$vpn_ip6_nat66"
        break
    fi
done < "$WG_REGISTRY"

# === HANDLE ROAMING ===
OLD_ENTRY=$(grep "^$MACADDR|" "$WG_MAC_STATE" 2>/dev/null)
OLD_IFACE=$(echo "$OLD_ENTRY" | cut -d'|' -f2)
OLD_RT=$(echo "$OLD_ENTRY" | cut -d'|' -f4)
OLD_IPV6_SUP=$(echo "$OLD_ENTRY" | cut -d'|' -f5)

if [ -n "$OLD_IFACE" ] && [ "$OLD_IFACE" != "$MATCHED_IFACE" ]; then
    logger -t wg-dhcp-master "Client $MACADDR roaming: $OLD_IFACE -> ${MATCHED_IFACE:-direct}"
    cleanup_client_from_interface "$OLD_IFACE" "$MACADDR" "$OLD_RT" "$OLD_IPV6_SUP"
fi

# === APPLY RULES FOR MATCHED INTERFACE ===
if [ -n "$MATCHED_IFACE" ]; then
    WG_INTERFACE="$MATCHED_IFACE"
    ROUTING_TABLE="$MATCHED_RT"
    VPN_IPS="$MATCHED_VPN_IPS"
    IPV6_SUPPORTED="$MATCHED_IPV6_SUP"
    VPN_IP6_SUBNETS="$MATCHED_VPN_IP6_SUBS"
    VPN_IP6_NEEDS_NAT66="$MATCHED_VPN_IP6_NAT66"
    KS_CHAIN="${WG_INTERFACE}_killswitch"
    BLOCK_CHAIN="${WG_INTERFACE}_ipv6_block"
    BLOCK_IPV6_DNS_INPUT_CHAIN="${WG_INTERFACE}_v6_dns_in"
    BLOCK_IPV4_ONLY_CHAIN="${WG_INTERFACE}_ipv4_only_block"
    
    # Check if tunnel interface exists
    if ifconfig | grep -q "$WG_INTERFACE"; then
        logger -t wg-dhcp-master "[$WG_INTERFACE] New client $IPADDR ($MACADDR) detected. Applying VPN routing rules."
        
        # Ensure DNS blocking chain exists (defensive - in case ifup didn't create it)
        ip6tables -N $BLOCK_IPV6_DNS_INPUT_CHAIN 2>/dev/null
        ip6tables -C INPUT -j $BLOCK_IPV6_DNS_INPUT_CHAIN 2>/dev/null || ip6tables -I INPUT 1 -j $BLOCK_IPV6_DNS_INPUT_CHAIN
        
        iptables -D $KS_CHAIN -s $IPADDR -j REJECT 2>/dev/null
        ip6tables -D $KS_CHAIN -m mac --mac-source $MACADDR -j REJECT 2>/dev/null
        ip rule del from $IPADDR table $ROUTING_TABLE 2>/dev/null
        ip rule add from $IPADDR table $ROUTING_TABLE priority $ROUTING_TABLE
        echo "$IPADDR" > "/tmp/wg_ip_${WG_INTERFACE}_${MACADDR//:/}"

        if [ "$IPV6_SUPPORTED" = "1" ]; then
            # Universal MAC-based IPv6 marking (Roaming Support)
            IPV6_MARK_CHAIN="mark_ipv6_${WG_INTERFACE}"
            MARK_VALUE="$((0x10000 + ROUTING_TABLE))"
            
            # Ensure IPv6 marking chain exists (defensive - in case ifup didn't create it)
            ip6tables -t mangle -N $IPV6_MARK_CHAIN 2>/dev/null
            lan_ifaces=$(get_lan_ifaces)
            for lan_if in $lan_ifaces; do
                ip6tables -t mangle -C PREROUTING -i $lan_if -j $IPV6_MARK_CHAIN 2>/dev/null || \
                    ip6tables -t mangle -A PREROUTING -i $lan_if -j $IPV6_MARK_CHAIN
            done
            
            # Check if this MAC is already marked (idempotent)
            if ! ip6tables -t mangle -C $IPV6_MARK_CHAIN -m mac --mac-source $MACADDR -j MARK --set-mark $MARK_VALUE 2>/dev/null; then
                ip6tables -t mangle -A $IPV6_MARK_CHAIN -m mac --mac-source $MACADDR -j MARK --set-mark $MARK_VALUE
                logger -t wg-dhcp-master "[$WG_INTERFACE] Added IPv6 fwmark for MAC $MACADDR (Universal roaming)"
            fi
            
            # Ensure BLOCK_CHAIN exists and is linked to FORWARD (defensive)
            ip6tables -N $BLOCK_CHAIN 2>/dev/null
            ip6tables -C FORWARD -j $BLOCK_CHAIN 2>/dev/null || ip6tables -I FORWARD 1 -j $BLOCK_CHAIN
            
            # Ensure Leak Prevention (Block non-VPN traffic) is ACTIVE
            lan_ifaces=$(get_lan_ifaces)
            for lan_if in $lan_ifaces; do 
                # Remove old rules (both formats for backward compatibility)
                ip6tables -D $BLOCK_CHAIN -i $lan_if ! -o $WG_INTERFACE -m mac --mac-source $MACADDR -j DROP 2>/dev/null
                ip6tables -D $BLOCK_CHAIN -i $lan_if -m mac --mac-source $MACADDR -m mark ! --mark $MARK_VALUE -j DROP 2>/dev/null
                # Add new rule: block unmarked traffic (allows fwmark-routed traffic through)
                ip6tables -I $BLOCK_CHAIN 1 -i $lan_if -m mac --mac-source $MACADDR -m mark ! --mark $MARK_VALUE -j DROP
            done
            
            # Proactive ping to populate neighbor table
            (
                ping -c 2 -W 1 "$IPADDR" >/dev/null 2>&1 &
            ) &
            
            logger -t wg-dhcp-master "[$WG_INTERFACE] IPv6 routing active via fwmark for $MACADDR"
        else
            # IPv4-only tunnel: Block IPv6 for this client
            logger -t wg-dhcp-master "[$WG_INTERFACE] Blocking IPv6 for $IPADDR ($MACADDR) on IPv4-only tunnel."
            
            # Ensure blocking chain exists (defensive)
            ip6tables -N $BLOCK_IPV4_ONLY_CHAIN 2>/dev/null
            ip6tables -C FORWARD -j $BLOCK_IPV4_ONLY_CHAIN 2>/dev/null || ip6tables -I FORWARD 1 -j $BLOCK_IPV4_ONLY_CHAIN
            
            ip6tables -C $BLOCK_IPV4_ONLY_CHAIN -m mac --mac-source $MACADDR -j DROP 2>/dev/null || \
                ip6tables -A $BLOCK_IPV4_ONLY_CHAIN -m mac --mac-source $MACADDR -j DROP
            
            # Block IPv6 acquisition (RS and DHCPv6)
            ip6tables -C INPUT -m mac --mac-source $MACADDR -p icmpv6 --icmpv6-type 133 -j DROP 2>/dev/null || \
                ip6tables -A INPUT -m mac --mac-source $MACADDR -p icmpv6 --icmpv6-type 133 -j DROP
            ip6tables -C INPUT -m mac --mac-source $MACADDR -p udp --dport 547 -j DROP 2>/dev/null || \
                ip6tables -A INPUT -m mac --mac-source $MACADDR -p udp --dport 547 -j DROP
        fi
        
        # Block IPv6 DNS to router for this client
        ip6tables -C $BLOCK_IPV6_DNS_INPUT_CHAIN -m mac --mac-source $MACADDR -p udp --dport 53 -j REJECT 2>/dev/null || \
            ip6tables -A $BLOCK_IPV6_DNS_INPUT_CHAIN -m mac --mac-source $MACADDR -p udp --dport 53 -j REJECT
        ip6tables -C $BLOCK_IPV6_DNS_INPUT_CHAIN -m mac --mac-source $MACADDR -p tcp --dport 53 -j REJECT 2>/dev/null || \
            ip6tables -A $BLOCK_IPV6_DNS_INPUT_CHAIN -m mac --mac-source $MACADDR -p tcp --dport 53 -j REJECT
    else
        # Tunnel is down - apply kill switch
        logger -t wg-dhcp-master "[$WG_INTERFACE] New client $IPADDR ($MACADDR) detected, but tunnel is down. Applying kill switch."
        iptables -N $KS_CHAIN 2>/dev/null; ip6tables -N $KS_CHAIN 2>/dev/null
        iptables -C FORWARD -j $KS_CHAIN 2>/dev/null || iptables -I FORWARD 1 -j $KS_CHAIN
        ip6tables -C FORWARD -j $KS_CHAIN 2>/dev/null || ip6tables -I FORWARD 1 -j $KS_CHAIN
        iptables -A $KS_CHAIN -s $IPADDR -j REJECT --reject-with icmp-host-prohibited
        ip6tables -A $KS_CHAIN -m mac --mac-source $MACADDR -j REJECT --reject-with icmp6-adm-prohibited
    fi
    
    # Update MAC state
    sed -i "/^$MACADDR|/d" "$WG_MAC_STATE" 2>/dev/null
    echo "$MACADDR|$WG_INTERFACE|$IPADDR|$ROUTING_TABLE|$IPV6_SUPPORTED" >> "$WG_MAC_STATE"
else
    # Client is NOT in any VPN list - cleanup was already done above if roaming
    # Also do fallback cleanup just in case
    if [ -z "$OLD_IFACE" ]; then
        # No previous state - check all interfaces for stale rules
        while IFS='|' read -r iface rt vpn_ips ipv6_sup vpn_ip6_subs vpn_ip6_nat66; do
            # Quick cleanup attempt for each interface
            ip rule del from "$IPADDR" table $rt 2>/dev/null
        done < "$WG_REGISTRY"
    fi
    sed -i "/^$MACADDR|/d" "$WG_MAC_STATE" 2>/dev/null
fi

ip route flush cache
flock -u 200
EOF_MASTER_DHCP

# Inject the common library content into master DHCP hotplug
inject_common_lib "$MASTER_DHCP_HOTPLUG"

chmod +x "$MASTER_DHCP_HOTPLUG"

# Create cleanup script
cat > /etc/hotplug.d/iface/99-${INTERFACE_NAME}-cleanup << 'EOFCLEANUP'
#!/bin/sh
[ "$ACTION" = "ifdown" ] || exit 0
[ "$INTERFACE" = "INTERFACE_NAME_PLACEHOLDER" ] || exit 0
VPN_IPS="VPN_IPS_PLACEHOLDER"
VPN_DNS="VPN_DNS_PLACEHOLDER"
ROUTING_TABLE="ROUTING_TABLE_PLACEHOLDER"
IPSET_NAME="IPSET_NAME_PLACEHOLDER"
IPSET_NAME_V6="vpn6_${WG_INTERFACE}"
MARK_CHAIN="mark_${WG_INTERFACE}"
MARK_VALUE="$((0x10000 + ROUTING_TABLE))"
WG_INTERFACE="INTERFACE_NAME_PLACEHOLDER"
KS_CHAIN="${WG_INTERFACE}_killswitch"
BLOCK_CHAIN="${WG_INTERFACE}_ipv6_block"
BLOCK_IPV4_ONLY_CHAIN="${WG_INTERFACE}_ipv4_only_block"

BLOCK_IPV6_DNS_INPUT_CHAIN="${WG_INTERFACE}_v6_dns_in"

# === INJECTED COMMON LIBRARY ===
COMMON_LIB_PLACEHOLDER

# Cleanup function for DNS rules
cleanup_vpn_dns() {
    local wg_interface="$1"
    local nat_chain="vpn_dns_nat_${wg_interface}"
    local nat_chain_v6="vpn_dns_nat6_${wg_interface}"
    local filter_chain="vpn_dns_filter_${wg_interface}"
    local filter_chain_v6="vpn_dns_filter6_${wg_interface}"
    local input_block_chain="vpn_dns_block_${wg_interface}"
    local input_block_chain_v6="vpn_dns_block6_${wg_interface}"

    # Clean up IPv4
    iptables -t nat -D PREROUTING -j $nat_chain 2>/dev/null
    iptables -t nat -F $nat_chain 2>/dev/null
    iptables -t nat -X $nat_chain 2>/dev/null
    iptables -D FORWARD -j $filter_chain 2>/dev/null
    iptables -F $filter_chain 2>/dev/null
    iptables -X $filter_chain 2>/dev/null
    iptables -D INPUT -j $input_block_chain 2>/dev/null
    iptables -F $input_block_chain 2>/dev/null
    iptables -X $input_block_chain 2>/dev/null

    # Clean up IPv6
    ip6tables -t nat -D PREROUTING -j $nat_chain_v6 2>/dev/null
    ip6tables -t nat -F $nat_chain_v6 2>/dev/null
    ip6tables -t nat -X $nat_chain_v6 2>/dev/null
    ip6tables -D FORWARD -j $filter_chain_v6 2>/dev/null
    ip6tables -F $filter_chain_v6 2>/dev/null
    ip6tables -X $filter_chain_v6 2>/dev/null
    ip6tables -D INPUT -j $input_block_chain_v6 2>/dev/null
    ip6tables -F $input_block_chain_v6 2>/dev/null
    ip6tables -X $input_block_chain_v6 2>/dev/null

    logger -t wireguard "[$wg_interface] Complete DNS rules cleaned up (IPv4+IPv6)"
}

# Clean up NAT66 masquerading if it was enabled
NAT66_CHAIN="nat66_${WG_INTERFACE}"
IPV6_MARK_CHAIN="mark_ipv6_${WG_INTERFACE}"

# Clean up NAT66 MASQUERADE chain
ip6tables -t nat -D POSTROUTING -j $NAT66_CHAIN 2>/dev/null
ip6tables -t nat -F $NAT66_CHAIN 2>/dev/null
ip6tables -t nat -X $NAT66_CHAIN 2>/dev/null

# Clean up IPv6 fwmark marking chain
lan_ifaces=$(get_lan_ifaces)
for lan_if in $lan_ifaces; do
    ip6tables -t mangle -D PREROUTING -i $lan_if -j $IPV6_MARK_CHAIN 2>/dev/null
done
ip6tables -t mangle -F $IPV6_MARK_CHAIN 2>/dev/null
ip6tables -t mangle -X $IPV6_MARK_CHAIN 2>/dev/null

logger -t wireguard "[$WG_INTERFACE] NAT66 and IPv6 fwmark chains cleaned up"

# Clean up ALL potential IPv6 blocking chains
ip6tables -F $BLOCK_CHAIN 2>/dev/null
ip6tables -D FORWARD -j $BLOCK_CHAIN 2>/dev/null
ip6tables -X $BLOCK_CHAIN 2>/dev/null
ip6tables -F $BLOCK_IPV4_ONLY_CHAIN 2>/dev/null
ip6tables -D FORWARD -j $BLOCK_IPV4_ONLY_CHAIN 2>/dev/null
ip6tables -X $BLOCK_IPV4_ONLY_CHAIN 2>/dev/null

# Clean up policy routing rules
ip6tables -F $BLOCK_IPV6_DNS_INPUT_CHAIN 2>/dev/null
ip6tables -D INPUT -j $BLOCK_IPV6_DNS_INPUT_CHAIN 2>/dev/null
ip6tables -X $BLOCK_IPV6_DNS_INPUT_CHAIN 2>/dev/null
while ip rule | grep -q "lookup $ROUTING_TABLE"; do
    ip rule del $(ip rule | grep "lookup $ROUTING_TABLE" | head -n1)
done
while ip -6 rule | grep -q "lookup $ROUTING_TABLE"; do
    ip -6 rule del $(ip -6 rule | grep "lookup $ROUTING_TABLE" | head -n1)
done

# Clean up firewall mark rules
logger -t wireguard "[$WG_INTERFACE] Cleaning up DNS leak-prevention firewall mark $MARK_VALUE."
ip rule del fwmark $MARK_VALUE table $ROUTING_TABLE 2>/dev/null
ip -6 rule del fwmark $MARK_VALUE table $ROUTING_TABLE 2>/dev/null

lan_ifaces=$(get_lan_ifaces)
for lan_if in $lan_ifaces; do
    iptables -t mangle -D PREROUTING -i $lan_if -j $MARK_CHAIN 2>/dev/null
    ip6tables -t mangle -D PREROUTING -i $lan_if -j $MARK_CHAIN 2>/dev/null
done
iptables -t mangle -F $MARK_CHAIN 2>/dev/null
iptables -t mangle -X $MARK_CHAIN 2>/dev/null
ip6tables -t mangle -F $MARK_CHAIN 2>/dev/null
ip6tables -t mangle -X $MARK_CHAIN 2>/dev/null

# Clean up specific CONNMARK restore rules

# Clean up outgoing DNS marking rules
for dns in $VPN_DNS; do
    if ! echo "$dns" | grep -q ":"; then
        iptables -t mangle -D OUTPUT -d $dns -p udp --dport 53 -j MARK --set-mark $MARK_VALUE 2>/dev/null
        iptables -t mangle -D OUTPUT -d $dns -p tcp --dport 53 -j MARK --set-mark $MARK_VALUE 2>/dev/null
    else
        ip6tables -t mangle -D OUTPUT -d $dns -p udp --dport 53 -j MARK --set-mark $MARK_VALUE 2>/dev/null
        ip6tables -t mangle -D OUTPUT -d $dns -p tcp --dport 53 -j MARK --set-mark $MARK_VALUE 2>/dev/null
    fi
done

# Clean up WAN DNS blocking rules (IPv4+IPv6)
iptables -t mangle -D OUTPUT -p udp --sport 53 -m set --match-set $IPSET_NAME dst -m mark ! --mark $MARK_VALUE -j DROP 2>/dev/null
iptables -t mangle -D OUTPUT -p tcp --sport 53 -m set --match-set $IPSET_NAME dst -m mark ! --mark $MARK_VALUE -j DROP 2>/dev/null
ip6tables -t mangle -D OUTPUT -p udp --sport 53 -m set --match-set $IPSET_NAME_V6 dst -m mark ! --mark $MARK_VALUE -j DROP 2>/dev/null
ip6tables -t mangle -D OUTPUT -p tcp --sport 53 -m set --match-set $IPSET_NAME_V6 dst -m mark ! --mark $MARK_VALUE -j DROP 2>/dev/null

# Activate Kill Switch
logger -t wireguard "[$WG_INTERFACE] Interface is down. Activating kill switch."
iptables -N $KS_CHAIN 2>/dev/null; ip6tables -N $KS_CHAIN 2>/dev/null
iptables -C FORWARD -j $KS_CHAIN 2>/dev/null || iptables -I FORWARD 1 -j $KS_CHAIN
ip6tables -C FORWARD -j $KS_CHAIN 2>/dev/null || ip6tables -I FORWARD 1 -j $KS_CHAIN

for item in $VPN_IPS; do
    logger -t wireguard "[$WG_INTERFACE] Blocking all traffic from $item."
    iptables -A $KS_CHAIN -s $item -j REJECT --reject-with icmp-host-prohibited
    case "$item" in
        */*) # For subnets, find all known MACs and block them for IPv6
            if [ -f /cfg/dhcp.leases ]; then
                while read -r exp mac ip host; do
                    if is_in_subnet "$ip" "$item"; then
                        ip6tables -A $KS_CHAIN -m mac --mac-source $mac -j REJECT --reject-with icmp6-adm-prohibited
                    fi
                done < /cfg/dhcp.leases
            fi
            ;;
        *) # For individual IPs, get MAC directly
            mac=$(ip neigh show "$item" | grep -o '[0-9a-f:]\{17\}' | head -1)
            if [ -n "$mac" ] && [ "$mac" != "<incomplete>" ]; then
                ip6tables -A $KS_CHAIN -m mac --mac-source $mac -j REJECT --reject-with icmp6-adm-prohibited
            fi
            ;;
    esac
done

ip route flush table $ROUTING_TABLE 2>/dev/null
ip -6 route flush table $ROUTING_TABLE 2>/dev/null
ip route flush cache; ip -6 route flush cache 2>/dev/null
logger -t wireguard "[$WG_INTERFACE] Interface down and routing cleaned up"

cleanup_vpn_dns "$WG_INTERFACE"

# Clean up dnsmasq config and ipset
IPSET_NAME="vpn_${WG_INTERFACE}"
DNSMASQ_CONF="/tmp/dnsmasq.d/99-${INTERFACE_NAME}-dns.conf"

logger -t wireguard "[$WG_INTERFACE] Cleaning up ipset and dnsmasq config."
rm -f $DNSMASQ_CONF
ipset destroy $IPSET_NAME 2>/dev/null
ipset destroy $IPSET_NAME_V6 2>/dev/null

# Reload dnsmasq to apply changes (remove config)
( /etc/init.d/dnsmasq reload >/dev/null 2>&1 ) &

# Clean up IPv6 prefix state files
logger -t wireguard "[$WG_INTERFACE] Cleaning up IPv6 prefix state files."
rm -f /tmp/wg_prefix_${WG_INTERFACE}_*
logger -t wireguard "[$WG_INTERFACE] Cleaning up IPv4 state files."
rm -f /tmp/wg_ip_${WG_INTERFACE}_*

# Unregister from WireGuard interface registry
WG_REGISTRY="/tmp/wg_interface_registry"
WG_MAC_STATE="/tmp/wg_mac_state"
logger -t wireguard "[$WG_INTERFACE] Removing from interface registry."
sed -i "/^${WG_INTERFACE}|/d" "$WG_REGISTRY" 2>/dev/null || true
# Clean up MAC state entries pointing to this interface
sed -i "/|${WG_INTERFACE}|/d" "$WG_MAC_STATE" 2>/dev/null || true

# Note: We do NOT remove the master DHCP hotplug script here even if registry is empty.
# This prevents race conditions at boot where cleanup runs before new interfaces come up.
# The script is harmless when empty and will be overwritten on next commit.
EOFCLEANUP

# Inject the common library content into cleanup script
inject_common_lib "/etc/hotplug.d/iface/99-${INTERFACE_NAME}-cleanup"

sed -i "s|INTERFACE_NAME_PLACEHOLDER|$INTERFACE_NAME|g" /etc/hotplug.d/iface/99-${INTERFACE_NAME}-cleanup
sed -i "s|VPN_IPS_PLACEHOLDER|$VPN_IPS|g" /etc/hotplug.d/iface/99-${INTERFACE_NAME}-cleanup
sed -i "s|ROUTING_TABLE_PLACEHOLDER|$ROUTING_TABLE|g" /etc/hotplug.d/iface/99-${INTERFACE_NAME}-cleanup
sed -i "s|IPSET_NAME_PLACEHOLDER|$IPSET_NAME|g" /etc/hotplug.d/iface/99-${INTERFACE_NAME}-cleanup
sed -i "s|VPN_DNS_PLACEHOLDER|$VPN_DNS_SERVERS|g" /etc/hotplug.d/iface/99-${INTERFACE_NAME}-cleanup
chmod +x /etc/hotplug.d/iface/99-${INTERFACE_NAME}-cleanup

uci commit network
uci commit firewall

# Run post_setup hook
run_hook post_setup "$INTERFACE_NAME"

echo "Configuration applied successfully!"
echo ""
echo "✅ WireGuard client setup complete!"
echo "Interface: $INTERFACE_NAME"
echo "Policy routing: Dynamically managing clients in '$VPN_IPS'"