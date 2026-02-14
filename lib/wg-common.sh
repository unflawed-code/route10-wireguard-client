#!/bin/sh
# wg-common.sh - Shared helper functions for WireGuard hotplug scripts
# This file is injected into generated hotplug scripts at generation time.
# DO NOT source this file at runtime - it is embedded directly.

# === STRING UTILITIES ===

# Trim leading and trailing whitespace
# Usage: result=$(trim "  hello  ")
trim() {
    echo "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

# Wait for system to be ready if uptime is less than 60 seconds
# Usage: wait_for_system_ready
wait_for_system_ready() {
    local uptime_secs wait_secs
    uptime_secs=$(awk '{print int($1)}' /proc/uptime 2>/dev/null)
    if [ -n "$uptime_secs" ] && [ "$uptime_secs" -lt 60 ]; then
        wait_secs=$((60 - uptime_secs))
        echo "System uptime is ${uptime_secs}s. Waiting ${wait_secs}s for system to be ready..."
        sleep "$wait_secs"
    fi
}

# === MAC ADDRESS UTILITIES ===

# Check if a string looks like a MAC address
# Supports: 2a3012ef5aaa, 2a:30:12:ef:5a:aa, 2a-30-12-ef-5a-aa
# Usage: is_mac "2a:30:12:ef:5a:aa" && echo "It's a MAC"
is_mac() {
    local input="$1"
    # Remove separators and check for 12 hex characters
    local clean=$(echo "$input" | tr -d ':-' | tr 'A-F' 'a-f')
    [ ${#clean} -eq 12 ] && echo "$clean" | grep -qE '^[0-9a-f]{12}$'
}

# Normalize MAC address to lowercase colon-separated format
# Input: 2a3012ef5aaa, 2a:30:12:ef:5a:aa, 2a-30-12-ef-5a-aa
# Output: 2a:30:12:ef:5a:aa
# Returns 1 if invalid
# Usage: mac=$(normalize_mac "2a3012ef5aaa")
normalize_mac() {
    local input="$1"
    # Remove separators and lowercase
    local clean=$(echo "$input" | tr -d ':-' | tr 'A-F' 'a-f')
    # Validate 12 hex chars
    if [ ${#clean} -ne 12 ] || ! echo "$clean" | grep -qE '^[0-9a-f]{12}$'; then
        return 1
    fi
    # Insert colons: aabbccddeeff -> aa:bb:cc:dd:ee:ff
    echo "$clean" | sed 's/\(..\)/\1:/g; s/:$//'
}

# Resolve MAC address to IP via ARP/neighbor table
# Usage: ip=$(resolve_mac_to_ip "2a:30:12:ef:5a:aa")
resolve_mac_to_ip() {
    local mac="$1"
    # Normalize to ensure consistent format
    mac=$(normalize_mac "$mac") || return 1
    # Check neighbor table (both IPv4 and IPv6)
    ip neigh show | awk -v mac="$mac" 'tolower($5)==mac && $NF!="FAILED" {print $1; exit}'
}

# === IP ADDRESS UTILITIES ===

# Extract IP part from target (handles plain IP, CIDR, or MAC=IP format)
# Usage: ip=$(get_ip_from_target "aa:bb:cc:dd:ee:ff=10.90.1.10") -> 10.90.1.10
get_ip_from_target() {
    local target="$1"
    case "$target" in
        *=*) echo "${target#*=}" ;;
        *)   echo "$target" ;;
    esac
}

# Convert IPv4 address to integer for subnet calculations
# Usage: ip_to_int "192.168.1.1"
ip_to_int() {
    [ -z "$1" ] && echo "0" && return
    local a b c d
    IFS=. read -r a b c d <<EOF
$1
EOF
    # Validate we got 4 octets
    [ -z "$a" ] || [ -z "$b" ] || [ -z "$c" ] || [ -z "$d" ] && echo "0" && return
    echo "$(( (a << 24) | (b << 16) | (c << 8) | d ))"
}

# Check if an IPv4 address is within a CIDR subnet
# Usage: is_in_subnet "192.168.1.5" "192.168.1.0/24"
is_in_subnet() {
    local ip_to_check="$1" subnet_cidr="$2"
    local ip_int subnet prefix network_int mask i
    ip_int=$(ip_to_int "$ip_to_check")
    subnet="${subnet_cidr%/*}"
    prefix="${subnet_cidr#*/}"
    network_int=$(ip_to_int "$subnet")
    i=0; mask=0
    while [ $i -lt $prefix ]; do
        mask=$(( (mask >> 1) | 0x80000000 ))
        i=$((i+1))
    done
    [ $(( ip_int & mask )) -eq $(( network_int & mask )) ] && return 0 || return 1
}

# Check if an IP matches any item in a list (supports both single IPs and CIDR subnets)
# Usage: is_in_list "192.168.1.5" "192.168.1.0/24 10.0.0.1"
is_in_list() {
    local ip_to_check="$1" list="$2" ip_int item
    ip_int=$(ip_to_int "$ip_to_check")
    for item in $list; do
        local actual_ip=$(get_ip_from_target "$item")
        case "$actual_ip" in
            */*)
                is_in_subnet "$ip_to_check" "$actual_ip" && return 0
                ;;
            *)
                [ "$actual_ip" = "$ip_to_check" ] && return 0
                ;;
        esac
    done
    return 1
}

# === NETWORK INTERFACE UTILITIES ===

# Get LAN bridge interfaces (typically br-lan)
# Usage: lan_ifaces=$(get_lan_ifaces)
get_lan_ifaces() {
    local lan_ifs
    lan_ifs=$(ip link show type bridge 2>/dev/null | awk -F': ' '/br-lan/{print $2}')
    [ -z "$lan_ifs" ] && lan_ifs=$(uci get network.lan.device 2>/dev/null || echo "br-lan")
    echo "$lan_ifs"
}

# Find the DHCP lease file location
# Usage: lease_file=$(get_dhcp_lease_file)
get_dhcp_lease_file() {
    if [ -f "/tmp/dhcp.leases" ]; then echo "/tmp/dhcp.leases"
    elif [ -f "/var/dhcp.leases" ]; then echo "/var/dhcp.leases"
    elif [ -f "/cfg/dhcp.leases" ]; then echo "/cfg/dhcp.leases"
    else echo ""; fi
}

# === FIREWALL UTILITIES ===

# Clean up an iptables chain (unlink, flush, delete)
# Usage: cleanup_iptables_chain "filter" "FORWARD" "my_chain"
# Args: $1=table, $2=parent_chain, $3=chain_name
cleanup_iptables_chain() {
    local table="$1" parent="$2" chain="$3"
    if [ "$table" = "filter" ]; then
        iptables -w -D "$parent" -j "$chain" 2>/dev/null
        iptables -w -F "$chain" 2>/dev/null
        iptables -w -X "$chain" 2>/dev/null
    else
        iptables -w -t "$table" -D "$parent" -j "$chain" 2>/dev/null
        iptables -w -t "$table" -F "$chain" 2>/dev/null
        iptables -w -t "$table" -X "$chain" 2>/dev/null
    fi
}

# Clean up an ip6tables chain (unlink, flush, delete)
# Usage: cleanup_ip6tables_chain "filter" "FORWARD" "my_chain"
# Args: $1=table, $2=parent_chain, $3=chain_name
cleanup_ip6tables_chain() {
    local table="$1" parent="$2" chain="$3"
    if [ "$table" = "filter" ]; then
        ip6tables -w -D "$parent" -j "$chain" 2>/dev/null
        ip6tables -w -F "$chain" 2>/dev/null
        ip6tables -w -X "$chain" 2>/dev/null
    else
        ip6tables -w -t "$table" -D "$parent" -j "$chain" 2>/dev/null
        ip6tables -w -t "$table" -F "$chain" 2>/dev/null
        ip6tables -w -t "$table" -X "$chain" 2>/dev/null
    fi
}

discover_mac_for_ip() {
    local target_ip="$1" max_retries="${2:-3}" mac="" retry=0
    
    # Proactive ping to ensure ARP entry exists
    ping -c 1 -W 1 "$target_ip" >/dev/null 2>&1
    sleep 1
    
    while [ $retry -lt $max_retries ] && [ -z "$mac" ]; do
        mac=$(ip neigh show "$target_ip" | grep -o '[0-9a-f:]\{17\}' | head -1)
        if [ -n "$mac" ] && [ "$mac" != "<incomplete>" ]; then
            echo "$mac"
            return 0
        fi
        mac=""
        sleep 1
        retry=$((retry + 1))
    done
    echo ""
    return 1
}

# === INTERFACE CLEANUP UTILITIES ===

# Clean up old routing rules when reconfiguring an existing WireGuard interface
# This is essential for proper roaming and reconfiguration
# Usage: cleanup_interface_rules "wg0"
cleanup_interface_rules() {
    local INTERFACE_NAME="$1"
    local WG_TMP_DIR="/tmp/wg-custom"
    local WG_DB_PATH="${WG_TMP_DIR}/wg_pbr.db"
    local WG_MAC_STATE="${WG_TMP_DIR}/mac_state"
    
    [ -z "$INTERFACE_NAME" ] && return 0
    
    # Get interface data from SQLite
    local OLD_ENTRY=""
    if [ -f "$WG_DB_PATH" ]; then
        OLD_ENTRY=$(sqlite3 -separator '|' "$WG_DB_PATH" "SELECT name, routing_table, target_ips FROM interfaces WHERE name = '$INTERFACE_NAME';" 2>/dev/null)
    fi
    [ -z "$OLD_ENTRY" ] && return 0
    
    echo "Found existing registry entry for $INTERFACE_NAME, cleaning up old rules..."
    local OLD_RT=$(echo "$OLD_ENTRY" | cut -d'|' -f2)
    local OLD_VPN_IPS=$(echo "$OLD_ENTRY" | cut -d'|' -f3 | tr ',' ' ')
    local OLD_RT_NAME="${INTERFACE_NAME}_rt"
    local OLD_MARK="$((0x10000 + OLD_RT))"
    
    # Remove old ip rules for each old target IP
    for old_ip in $OLD_VPN_IPS; do
        echo "  Removing old ip rule: from $old_ip lookup $OLD_RT_NAME"
        ip rule del from "$old_ip" lookup "$OLD_RT_NAME" 2>/dev/null || true
    done
    
    # Remove old fwmark rule
    echo "  Removing old fwmark rule: $OLD_MARK lookup $OLD_RT_NAME"
    ip rule del fwmark "$OLD_MARK" lookup "$OLD_RT_NAME" 2>/dev/null || true
    
    # Flush old ipsets (will be recreated)
    echo "  Flushing old ipsets: vpn_${INTERFACE_NAME}, vpn6_${INTERFACE_NAME}"
    ipset flush "vpn_${INTERFACE_NAME}" 2>/dev/null || true
    ipset flush "vpn6_${INTERFACE_NAME}" 2>/dev/null || true
    
    # Also handle IPv6 rules
    for old_ip in $OLD_VPN_IPS; do
        ip -6 rule del from "$old_ip" lookup "$OLD_RT_NAME" 2>/dev/null || true
    done
    ip -6 rule del fwmark "$OLD_MARK" lookup "$OLD_RT_NAME" 2>/dev/null || true
    
    # Clean up per-client MAC marks from mangle table
    local IPV6_MARK_CHAIN="mark_ipv6_${INTERFACE_NAME}"
    echo "  Flushing ip6tables mangle chain: $IPV6_MARK_CHAIN"
    ip6tables -w -t mangle -F "$IPV6_MARK_CHAIN" 2>/dev/null || true
    
    # Clean up MAC state entries for this interface (from SQLite)
    echo "  Removing MAC state entries for $INTERFACE_NAME"
    local MACS=$(sqlite3 "$WG_DB_PATH" "SELECT mac FROM mac_state WHERE interface = '$INTERFACE_NAME';" 2>/dev/null)
    
    for mac in $MACS; do
        local mac_clean="${mac//:/}"
        rm -f "${WG_TMP_DIR}/prefix_${INTERFACE_NAME}_${mac_clean}" 2>/dev/null
        rm -f "${WG_TMP_DIR}/ip_${INTERFACE_NAME}_${mac_clean}" 2>/dev/null
    done
    
    sqlite3 "$WG_DB_PATH" "DELETE FROM mac_state WHERE interface = '$INTERFACE_NAME';" 2>/dev/null || true
    
    echo "  Old rules cleaned up."
}

# === IP REMOVAL CLEANUP ===

# Clean up MAC state and firewall rules for a specific IP being removed from an interface
# This is called during hot-reload when an IP is moved to another interface
# Usage: cleanup_mac_for_ip <interface> <removed_ip>
cleanup_mac_for_ip() {
    local iface="$1"
    local removed_ip="$2"
    local WG_TMP_DIR="/tmp/wg-custom"
    local WG_DB_PATH="${WG_TMP_DIR}/wg_pbr.db"
    
    local mac=""
    local rt=""
    
    # 1. Try to find MAC address for this IP from SQLite state
    if [ -f "$WG_DB_PATH" ]; then
        local mac_entry=$(sqlite3 -separator '|' "$WG_DB_PATH" "SELECT mac, routing_table FROM mac_state WHERE interface = '$iface' AND ip = '$removed_ip' LIMIT 1;" 2>/dev/null)
        if [ -n "$mac_entry" ]; then
            mac=$(echo "$mac_entry" | cut -d'|' -f1)
            rt=$(echo "$mac_entry" | cut -d'|' -f2)
        fi
    fi
    
    # 2. Fallback: If not in DB, try to discover MAC via neighbor table
    # This addresses the "stale rule" issue where DB is out of sync but firewall rules persist
    if [ -z "$mac" ]; then
        mac=$(discover_mac_for_ip "$removed_ip" || true)
        # If we discovered a MAC but lack a routing table, try to get it from the interface registry
        if [ -n "$mac" ] && [ -z "$rt" ] && [ -f "$WG_DB_PATH" ]; then
            rt=$(sqlite3 "$WG_DB_PATH" "SELECT routing_table FROM interfaces WHERE name = '$iface' LIMIT 1;" 2>/dev/null)
        fi
    fi
    
    # If we still have no MAC, we can't clean up MAC-based rules
    [ -z "$mac" ] && return 0
    
    # Validate rt is a number
    if [ -z "$rt" ] || ! echo "$rt" | grep -qE '^[0-9]+$'; then
        # Last ditch effort: if we have a MAC but no table, we try to scrub it from the known marks chain 
        # using a grep-and-delete approach to be robust
        local mark_chain="mark_ipv6_${iface}"
        if ip6tables -w -t mangle -L "$mark_chain" -n >/dev/null 2>&1; then
            echo "  WARNING: MAC discovered for $removed_ip but routing table unknown. Attempting bulk scrub."
            # Find and delete any rule matching this MAC in this chain
            while ip6tables -w -t mangle -S "$mark_chain" | grep -q "$mac"; do
                local rule_spec=$(ip6tables -w -t mangle -S "$mark_chain" | grep "$mac" | head -1 | sed 's/-A/-D/')
                ip6tables -w -t mangle $rule_spec 2>/dev/null || break
            done
        fi
        return 0
    fi
    
    # Clean up firewall rules for this client
    local MARK_VALUE="$((0x10000 + rt))"
    local IPV6_MARK_CHAIN="mark_ipv6_${iface}"
    local BLOCK_CHAIN="${iface}_ipv6_block"
    local BLOCK_IPV4_ONLY_CHAIN="${iface}_ipv4_only_block"
    local BLOCK_IPV6_DNS_INPUT_CHAIN="${iface}_v6_dns_in"
    
    # Remove IPv6 fwmark rule - Try both MARK and XMARK versions for resilience
    ip6tables -w -t mangle -D $IPV6_MARK_CHAIN -m mac --mac-source $mac -j MARK --set-mark $MARK_VALUE 2>/dev/null || true
    ip6tables -w -t mangle -D $IPV6_MARK_CHAIN -m mac --mac-source $mac -j MARK --set-xmark $(printf "0x%x" $MARK_VALUE)/0xffffffff 2>/dev/null || true
    
    # Remove IPv6 block rules
    local lan_ifaces=$(get_lan_ifaces)
    for lan_if in $lan_ifaces; do
        ip6tables -w -D $BLOCK_CHAIN -i $lan_if -m mac --mac-source $mac -m mark ! --mark $MARK_VALUE -j DROP 2>/dev/null || true
    done
    
    # Remove IPv4-only block rules
    ip6tables -w -D $BLOCK_IPV4_ONLY_CHAIN -m mac --mac-source $mac -j DROP 2>/dev/null || true
    ip6tables -w -D INPUT -m mac --mac-source $mac -p icmpv6 --icmpv6-type 133 -j DROP 2>/dev/null || true
    ip6tables -w -D INPUT -m mac --mac-source $mac -p udp --dport 547 -j DROP 2>/dev/null || true
    
    # Remove IPv6 DNS block rules
    ip6tables -w -D $BLOCK_IPV6_DNS_INPUT_CHAIN -m mac --mac-source $mac -p udp --dport 53 -j REJECT 2>/dev/null || true
    ip6tables -w -D $BLOCK_IPV6_DNS_INPUT_CHAIN -m mac --mac-source $mac -p tcp --dport 53 -j REJECT 2>/dev/null || true
    
    # Remove IPv4 DNS block rules (filter chains for DoT/DoH blocking)
    local dns_block_chain="vpn_dns_block_${iface}"
    local dns_filter_chain="vpn_dns_filter_${iface}"
    
    # Clean up DNS block rules by IP (port 53 blocking)
    iptables -w -D $dns_block_chain -s $removed_ip -p udp --dport 53 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || true
    iptables -w -D $dns_block_chain -s $removed_ip -p tcp --dport 53 -j REJECT --reject-with tcp-reset 2>/dev/null || true
    
    # Clean up DoT block rules by IP (port 853)
    iptables -w -D $dns_filter_chain -s $removed_ip -p udp --dport 853 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || true
    iptables -w -D $dns_filter_chain -s $removed_ip -p tcp --dport 853 -j REJECT --reject-with tcp-reset 2>/dev/null || true
    
    # Clean up DoH block rules by IP (port 443 with string matching)
    if [ -f /etc/config/https-dns-proxy ]; then
        local domains=$(grep 'resolver_url' /etc/config/https-dns-proxy 2>/dev/null | awk -F'/' '{print $3}')
        for domain in $domains; do
            iptables -w -D $dns_filter_chain -s $removed_ip -p tcp --dport 443 -m string --algo bm --string "$domain" -j REJECT --reject-with tcp-reset 2>/dev/null || true
            iptables -w -D $dns_filter_chain -s $removed_ip -p udp --dport 443 -m string --algo bm --string "$domain" -j REJECT --reject-with tcp-reset 2>/dev/null || true
        done
    fi
    
    # Remove MAC state entry from SQLite
    if [ -f "$WG_DB_PATH" ]; then
        sqlite3 "$WG_DB_PATH" "DELETE FROM mac_state WHERE interface = '$iface' AND mac = '$mac';" 2>/dev/null || true
    fi
    
    # Clean up state files
    local mac_clean="${mac//:/}"
    rm -f "${WG_TMP_DIR}/ip_${iface}_${mac_clean}" 2>/dev/null
    rm -f "${WG_TMP_DIR}/prefix_${iface}_${mac_clean}" 2>/dev/null
    
    echo "  Cleaned up MAC state for $mac (IP: $removed_ip)"
}

# === HOT-RELOAD UTILITIES ===

# Hot-reload: Update ipset with new target IPs without restarting interface
# Also updates ip rules to ensure routing changes immediately
# Triggers DHCP re-processing for moved IPs to update DNS/IPv6 rules
# Usage: update_ipset_targets <interface> <new-ips> [old-ips]
# Note: Appends to DEFERRED_DHCP_IPS global variable for deferred processing
update_ipset_targets() {
    local iface="$1"
    local new_ips="$2"
    local old_ips="${3:-}"  # Optional - if not provided, read from ipset
    local WG_TMP_DIR="/tmp/wg-custom"
    local MASTER_DHCP_HOTPLUG="/etc/hotplug.d/dhcp/99-wg-master-pbr"
    
    local ipset_name="vpn_${iface}"
    local ipset_v6="vpn6_${iface}"
    local rt_name="${iface}_rt"
    
    # If old_ips not provided, read current config from ipset (source of truth)
    if [ -z "$old_ips" ]; then
        old_ips=$(ipset list "$ipset_name" 2>/dev/null | grep -E '^[0-9]' | tr '\n' ' ')
    else
        # Convert old_ips to space-separated if comma-separated
        old_ips=$(echo "$old_ips" | tr ',' ' ')
    fi
    
    # Track IPs that need DHCP re-processing
    local ips_to_reprocess=""
    
    # Remove old ip rules for IPs that are no longer in this interface
    for old_ip in $old_ips; do
        # Check if this IP is still in new list
        local still_exists=0
        for new_ip in $(echo "$new_ips" | tr ',' ' '); do
            local actual_ip=$(get_ip_from_target "$new_ip")
            [ "$old_ip" = "$actual_ip" ] && still_exists=1 && break
        done
        if [ "$still_exists" = "0" ]; then
            # Remove ip rule for this IP
            ip rule del from "$old_ip" lookup "$rt_name" 2>/dev/null && \
                echo "  Removed ip rule: from $old_ip lookup $rt_name" || true
            
            # Remove DNS DNAT rules for this IP (prevents DNAT conflicts when IP moves to another interface)
            local dns_nat_chain="vpn_dns_nat_${iface}"
            while iptables -w -t nat -L "$dns_nat_chain" --line-numbers -n 2>/dev/null | grep -q "^[0-9].*${old_ip}"; do
                local line_num=$(iptables -w -t nat -L "$dns_nat_chain" --line-numbers -n 2>/dev/null | grep "^[0-9].*${old_ip}" | head -1 | awk '{print $1}')
                [ -n "$line_num" ] && iptables -w -t nat -D "$dns_nat_chain" "$line_num" 2>/dev/null && echo "  Removed DNS DNAT rule $line_num for $old_ip" || true
            done
            
            # Clean up MAC state and IPv6 firewall rules for this IP
            cleanup_mac_for_ip "$iface" "$old_ip"
        fi
    done
    
    # Add new ip rules for IPs that need them
    if [ "$new_ips" != "none" ]; then
        for new_ip in $(echo "$new_ips" | tr ',' ' '); do
            local actual_ip=$(get_ip_from_target "$new_ip")
            # Skip IPv6 (actual_ip won't have the MAC part anymore)
            case "$actual_ip" in
                *:*) continue ;;
            esac
            
            # Check if ip rule already exists (more reliable than old_ips comparison)
            if ! ip rule show | grep -q "from $actual_ip lookup $rt_name"; then
                ip rule add from "$actual_ip" lookup "$rt_name" 2>/dev/null && \
                    echo "  Added ip rule: from $actual_ip lookup $rt_name"
                # Mark for DHCP re-processing (DNS/IPv6 rules)
                ips_to_reprocess="$ips_to_reprocess $actual_ip"
            fi
        done
    fi
    
    # Flush and repopulate ipsets
    ipset flush "$ipset_name" 2>/dev/null || true
    ipset flush "$ipset_v6" 2>/dev/null || true
    
    if [ "$new_ips" != "none" ]; then
        for target in $(echo "$new_ips" | tr ',' ' '); do
            local actual_ip=$(get_ip_from_target "$target")
            case "$actual_ip" in
                *:*) ipset add "$ipset_v6" "$actual_ip" 2>/dev/null ;;
                *)   ipset add "$ipset_name" "$actual_ip" 2>/dev/null ;;
            esac
        done
    fi
    
    # Update DNS DNAT rules for moved IPs
    local dns_nat_chain="vpn_dns_nat_${iface}"
    
    # Ensure DNS NAT chain is hooked into PREROUTING
    if iptables -w -t nat -L "$dns_nat_chain" -n >/dev/null 2>&1; then
        iptables -w -t nat -C PREROUTING -j "$dns_nat_chain" 2>/dev/null || \
            iptables -w -t nat -I PREROUTING 1 -j "$dns_nat_chain"
    fi
    
    # Get DNS server from existing rules in this chain
    local dns_server=$(iptables -w -t nat -L "$dns_nat_chain" -n 2>/dev/null | \
        grep -oE 'to:[0-9.]+' | head -1 | cut -d: -f2)
    
    if [ -n "$dns_server" ]; then
        if [ "$new_ips" != "none" ]; then
            for target in $(echo "$new_ips" | tr ',' ' '); do
                local actual_ip=$(get_ip_from_target "$target")
                # Add for single IPs and subnets (skip IPv6)
                case "$actual_ip" in
                    *:*) ;; # Skip IPv6
                    *)
                        # Check if rule already exists
                        if ! iptables -w -t nat -C "$dns_nat_chain" -s "$actual_ip" -p udp --dport 53 -j DNAT --to-destination "$dns_server" 2>/dev/null; then
                            iptables -w -t nat -A "$dns_nat_chain" -s "$actual_ip" -p udp --dport 53 -j DNAT --to-destination "$dns_server" || true
                            iptables -w -t nat -A "$dns_nat_chain" -s "$actual_ip" -p tcp --dport 53 -j DNAT --to-destination "$dns_server" || true
                            echo "  Added DNS DNAT: $actual_ip -> $dns_server"
                        fi
                        ;;
                esac
            done
        fi
    fi
    
    # Trigger DHCP re-processing for ALL single IPs to ensure IPv6 rules are set up
    if [ "$new_ips" != "none" ]; then
        for target in $(echo "$new_ips" | tr ',' ' '); do
            local actual_ip=$(get_ip_from_target "$target")
            case "$actual_ip" in
                */*) ;; # Skip subnets
                *:*) ;; # Skip IPv6
                *)
                    # Write to temp file (survives subshell in commit loop)
                    # Use full target string to preserve MAC=IP if present
                    echo "$target" >> "${WG_TMP_DIR}/deferred_dhcp.tmp"
                    ;;
            esac
        done
    fi
    
    echo "Updated ipset for $iface: $new_ips"
}

# Hot-reload: Update registry with new target IPs (SQLite only)
# Usage: update_registry_targets <interface> <comma-separated-ips>
update_registry_targets() {
    local iface="$1"
    local new_ips="$2"
    local WG_TMP_DIR="/tmp/wg-custom"
    local WG_DB_PATH="${WG_TMP_DIR}/wg_pbr.db"
    
    [ ! -f "$WG_DB_PATH" ] && return 1
    
    # Update target_ips in SQLite
    sqlite3 "$WG_DB_PATH" "UPDATE interfaces SET target_ips = '$new_ips' WHERE name = '$iface';"
    
    echo "Updated registry for $iface"
}
