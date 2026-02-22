#!/bin/sh
# Master DHCP hotplug for all WireGuard interfaces
# This script replaces per-interface DHCP hotplug scripts for efficiency

WG_TMP_DIR="/tmp/wg-custom"
mkdir -p "$WG_TMP_DIR" 2>/dev/null || true
WG_DB_PATH="${WG_TMP_DIR}/wg_pbr.db"
WG_MAC_STATE="${WG_TMP_DIR}/mac_state"
LOCK_FILE="${WG_TMP_DIR}/dhcp_hotplug.lock"
WG_DB_BUSY_TIMEOUT_MS="${WG_DB_BUSY_TIMEOUT_MS:-5000}"

# Use busy timeout to avoid failing on short DB write contention with commits.
sqlite3() {
    command sqlite3 -cmd ".timeout ${WG_DB_BUSY_TIMEOUT_MS}" "$@"
}

[ "$ACTION" = "add" ] || [ "$ACTION" = "new" ] || [ "$ACTION" = "old" ] || [ "$ACTION" = "update" ] || exit 0
[ -f "$WG_DB_PATH" ] || exit 0

# Acquire lock to prevent race conditions (BusyBox flock doesn't support -w)
exec 200>"$LOCK_FILE"
flock -x 200 || exit 1

# Storm guard:
# - drops duplicate events in a very short interval
# - opens a cooldown window when event rate exceeds burst threshold
GUARD_STATE="${WG_TMP_DIR}/dhcp_hotplug.guard"
GUARD_LAST="${WG_TMP_DIR}/dhcp_hotplug.last"
NOW=$(date +%s 2>/dev/null)
[ -n "$NOW" ] || NOW=0
WINDOW=15
BURST=120
COOLDOWN=30
DEDUP=2
EVENT_KEY="${ACTION}|${MACADDR}|${IPADDR}"

WIN_START=0
COUNT=0
SUPPRESS_UNTIL=0
if [ -f "$GUARD_STATE" ]; then
    IFS='|' read -r WIN_START COUNT SUPPRESS_UNTIL < "$GUARD_STATE"
fi
case "$WIN_START" in ''|*[!0-9]*) WIN_START=0 ;; esac
case "$COUNT" in ''|*[!0-9]*) COUNT=0 ;; esac
case "$SUPPRESS_UNTIL" in ''|*[!0-9]*) SUPPRESS_UNTIL=0 ;; esac

if [ "$SUPPRESS_UNTIL" -gt "$NOW" ]; then
    logger -t wg-dhcp-master "Storm guard active; dropping DHCP event $EVENT_KEY"
    flock -u 200
    exit 0
fi

if [ -f "$GUARD_LAST" ]; then
    IFS='|' read -r LAST_TS LAST_KEY < "$GUARD_LAST"
    case "$LAST_TS" in ''|*[!0-9]*) LAST_TS=0 ;; esac
    if [ "$LAST_KEY" = "$EVENT_KEY" ] && [ $((NOW - LAST_TS)) -lt "$DEDUP" ]; then
        flock -u 200
        exit 0
    fi
fi
printf "%s|%s\n" "$NOW" "$EVENT_KEY" > "$GUARD_LAST"

if [ "$WIN_START" -eq 0 ] || [ $((NOW - WIN_START)) -ge "$WINDOW" ]; then
    WIN_START="$NOW"
    COUNT=1
else
    COUNT=$((COUNT + 1))
fi

if [ "$COUNT" -gt "$BURST" ]; then
    SUPPRESS_UNTIL=$((NOW + COOLDOWN))
    printf "%s|%s|%s\n" "$WIN_START" "$COUNT" "$SUPPRESS_UNTIL" > "$GUARD_STATE"
    logger -t wg-dhcp-master "Storm guard tripped (count=$COUNT window=${WINDOW}s); cooling down ${COOLDOWN}s"
    flock -u 200
    exit 0
fi

printf "%s|%s|0\n" "$WIN_START" "$COUNT" > "$GUARD_STATE"

# === INJECTED COMMON LIBRARY ===
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
    ip6tables -t mangle -F "$IPV6_MARK_CHAIN" 2>/dev/null || true
    
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

# === CLEANUP FUNCTION FOR A SPECIFIC INTERFACE ===
cleanup_client_from_interface() {
    local iface="$1" mac="$2" rt="$3" ipv6_sup="$4"
    local MARK_VALUE="$((0x10000 + rt))"
    local IPV6_MARK_CHAIN="mark_ipv6_${iface}"
    local BLOCK_CHAIN="${iface}_ipv6_block"
    local BLOCK_IPV4_ONLY_CHAIN="${iface}_ipv4_only_block"
    local BLOCK_IPV6_DNS_INPUT_CHAIN="${iface}_v6_dns_in"
    
    # Remove IPv4 routing rule using state file
    local OLD_IP_FILE="${WG_TMP_DIR}/ip_${iface}_${mac//:/}"
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
    # Loop to remove all IPv4-only block rules (may have duplicates from multiple sources)
    while ip6tables -D $BLOCK_IPV4_ONLY_CHAIN -m mac --mac-source $mac -j DROP 2>/dev/null; do :; done
    while ip6tables -D INPUT -m mac --mac-source $mac -p icmpv6 --icmpv6-type 133 -j DROP 2>/dev/null; do :; done
    while ip6tables -D INPUT -m mac --mac-source $mac -p udp --dport 547 -j DROP 2>/dev/null; do :; done
    while ip6tables -D $BLOCK_IPV6_DNS_INPUT_CHAIN -m mac --mac-source $mac -p udp --dport 53 -j REJECT 2>/dev/null; do :; done
    while ip6tables -D $BLOCK_IPV6_DNS_INPUT_CHAIN -m mac --mac-source $mac -p tcp --dport 53 -j REJECT 2>/dev/null; do :; done
    
    # Remove IPv6 routing rule using state file
    local STATE_FILE="${WG_TMP_DIR}/prefix_${iface}_${mac//:/}"
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
# Query all committed interfaces from SQLite
sqlite3 -separator '|' "$WG_DB_PATH" "SELECT name, routing_table, target_ips, COALESCE(ipv6_support,0), COALESCE(ipv6_subnets,''), COALESCE(nat66,0) FROM interfaces WHERE committed = 1;" 2>/dev/null | \
while IFS='|' read -r iface rt vpn_ips ipv6_sup vpn_ip6_subs vpn_ip6_nat66; do
    # Convert comma-separated VPN_IPS to space-separated for is_in_list
    vpn_ips_spaced=$(echo "$vpn_ips" | tr ',' ' ')
    if is_in_list "$IPADDR" "$vpn_ips_spaced"; then
        # Write match to temp file (subshell can't export)
        echo "$iface|$rt|$vpn_ips_spaced|$ipv6_sup|$vpn_ip6_subs|$vpn_ip6_nat66" > "${WG_TMP_DIR}/dhcp_match_$$"
        break
    fi
done

# Read match from temp file
if [ -f "${WG_TMP_DIR}/dhcp_match_$$" ]; then
    IFS='|' read -r MATCHED_IFACE MATCHED_RT MATCHED_VPN_IPS MATCHED_IPV6_SUP MATCHED_VPN_IP6_SUBS MATCHED_VPN_IP6_NAT66 < "${WG_TMP_DIR}/dhcp_match_$$"
    rm -f "${WG_TMP_DIR}/dhcp_match_$$"
fi

# === HANDLE ROAMING ===
OLD_ENTRY=$(sqlite3 -separator '|' "$WG_DB_PATH" "SELECT * FROM mac_state WHERE mac = '$MACADDR';" 2>/dev/null)
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
        ip6tables -w -N $BLOCK_IPV6_DNS_INPUT_CHAIN 2>/dev/null
        ip6tables -w -C INPUT -j $BLOCK_IPV6_DNS_INPUT_CHAIN 2>/dev/null || ip6tables -w -I INPUT 1 -j $BLOCK_IPV6_DNS_INPUT_CHAIN
        
        iptables -w -D $KS_CHAIN -s $IPADDR -j REJECT 2>/dev/null
        ip6tables -w -D $KS_CHAIN -m mac --mac-source $MACADDR -j REJECT 2>/dev/null
        ip rule del from $IPADDR table $ROUTING_TABLE 2>/dev/null
        ip rule add from $IPADDR table $ROUTING_TABLE priority $ROUTING_TABLE
        echo "$IPADDR" > "${WG_TMP_DIR}/ip_${WG_INTERFACE}_${MACADDR//:/}"

        if [ "$IPV6_SUPPORTED" = "1" ]; then
            # Universal MAC-based IPv6 marking (Roaming Support)
            IPV6_MARK_CHAIN="mark_ipv6_${WG_INTERFACE}"
            MARK_VALUE="$((0x10000 + ROUTING_TABLE))"
            
            # Ensure IPv6 marking chain exists (defensive - in case ifup didn't create it)
            ip6tables -w -t mangle -N $IPV6_MARK_CHAIN 2>/dev/null
            lan_ifaces=$(get_lan_ifaces)
            for lan_if in $lan_ifaces; do
                ip6tables -w -t mangle -C PREROUTING -i $lan_if -j $IPV6_MARK_CHAIN 2>/dev/null || \
                    ip6tables -w -t mangle -A PREROUTING -i $lan_if -j $IPV6_MARK_CHAIN
            done
            
            # IMPORTANT: Add block rule FIRST to prevent IPv6 leak during setup
            # Ensure BLOCK_CHAIN exists and is linked to FORWARD (defensive)
            ip6tables -w -N $BLOCK_CHAIN 2>/dev/null
            ip6tables -w -C FORWARD -j $BLOCK_CHAIN 2>/dev/null || ip6tables -w -I FORWARD 1 -j $BLOCK_CHAIN
            
            # Ensure Leak Prevention (Block non-VPN traffic) is ACTIVE
            for lan_if in $lan_ifaces; do 
                # Remove old rules (both formats for backward compatibility)
                ip6tables -w -D $BLOCK_CHAIN -i $lan_if ! -o $WG_INTERFACE -m mac --mac-source $MACADDR -j DROP 2>/dev/null
                ip6tables -w -D $BLOCK_CHAIN -i $lan_if -m mac --mac-source $MACADDR -m mark ! --mark $MARK_VALUE -j DROP 2>/dev/null
                # Add new rule: block unmarked traffic (allows fwmark-routed traffic through)
                ip6tables -w -I $BLOCK_CHAIN 1 -i $lan_if -m mac --mac-source $MACADDR -m mark ! --mark $MARK_VALUE -j DROP
            done
            
            # NOW add marking rule (after block is in place, any traffic before this is blocked safely)
            if ! ip6tables -w -t mangle -C $IPV6_MARK_CHAIN -m mac --mac-source $MACADDR -j MARK --set-mark $MARK_VALUE 2>/dev/null; then
                ip6tables -w -t mangle -A $IPV6_MARK_CHAIN -m mac --mac-source $MACADDR -j MARK --set-mark $MARK_VALUE
                logger -t wg-dhcp-master "[$WG_INTERFACE] Added IPv6 fwmark for MAC $MACADDR (Universal roaming)"
            fi
            
            # Proactive ping to populate neighbor table
            (
                ping -c 2 -W 1 "$IPADDR" >/dev/null 2>&1 &
            ) &
            
            logger -t wg-dhcp-master "[$WG_INTERFACE] IPv6 routing active via fwmark for $MACADDR"
        else
            # IPv4-only tunnel: Block IPv6 for this client
            logger -t wg-dhcp-master "[$WG_INTERFACE] Blocking IPv6 for $IPADDR ($MACADDR) on IPv4-only tunnel."
            
            # Ensure blocking chain exists (defensive)
            ip6tables -w -N $BLOCK_IPV4_ONLY_CHAIN 2>/dev/null
            ip6tables -w -C FORWARD -j $BLOCK_IPV4_ONLY_CHAIN 2>/dev/null || ip6tables -w -I FORWARD 1 -j $BLOCK_IPV4_ONLY_CHAIN
            
            ip6tables -w -C $BLOCK_IPV4_ONLY_CHAIN -m mac --mac-source $MACADDR -j DROP 2>/dev/null || \
                ip6tables -w -A $BLOCK_IPV4_ONLY_CHAIN -m mac --mac-source $MACADDR -j DROP
            
            # Block IPv6 acquisition (RS and DHCPv6)
            ip6tables -w -C INPUT -m mac --mac-source $MACADDR -p icmpv6 --icmpv6-type 133 -j DROP 2>/dev/null || \
                ip6tables -w -A INPUT -m mac --mac-source $MACADDR -p icmpv6 --icmpv6-type 133 -j DROP
            ip6tables -w -C INPUT -m mac --mac-source $MACADDR -p udp --dport 547 -j DROP 2>/dev/null || \
                ip6tables -w -A INPUT -m mac --mac-source $MACADDR -p udp --dport 547 -j DROP
        fi
        
        # Block IPv6 DNS to router for this client
        ip6tables -w -C $BLOCK_IPV6_DNS_INPUT_CHAIN -m mac --mac-source $MACADDR -p udp --dport 53 -j REJECT 2>/dev/null || \
            ip6tables -w -A $BLOCK_IPV6_DNS_INPUT_CHAIN -m mac --mac-source $MACADDR -p udp --dport 53 -j REJECT
        ip6tables -w -C $BLOCK_IPV6_DNS_INPUT_CHAIN -m mac --mac-source $MACADDR -p tcp --dport 53 -j REJECT 2>/dev/null || \
            ip6tables -w -A $BLOCK_IPV6_DNS_INPUT_CHAIN -m mac --mac-source $MACADDR -p tcp --dport 53 -j REJECT
    else
        # Tunnel is down - apply kill switch
        logger -t wg-dhcp-master "[$WG_INTERFACE] New client $IPADDR ($MACADDR) detected, but tunnel is down. Applying kill switch."
        iptables -w -N $KS_CHAIN 2>/dev/null; ip6tables -w -N $KS_CHAIN 2>/dev/null
        iptables -w -C FORWARD -j $KS_CHAIN 2>/dev/null || iptables -w -I FORWARD 1 -j $KS_CHAIN
        ip6tables -w -C FORWARD -j $KS_CHAIN 2>/dev/null || ip6tables -w -I FORWARD 1 -j $KS_CHAIN
        iptables -w -A $KS_CHAIN -s $IPADDR -j REJECT --reject-with icmp-host-prohibited
        ip6tables -w -A $KS_CHAIN -m mac --mac-source $MACADDR -j REJECT --reject-with icmp6-adm-prohibited
    fi
    
    # Update MAC state in SQLite
    sqlite3 "$WG_DB_PATH" "DELETE FROM mac_state WHERE mac = '$MACADDR';" 2>/dev/null
    sqlite3 "$WG_DB_PATH" "INSERT INTO mac_state (mac, interface, ip, routing_table, ipv6_support) VALUES ('$MACADDR', '$WG_INTERFACE', '$IPADDR', $ROUTING_TABLE, $IPV6_SUPPORTED);"
else
    # Client is NOT in any VPN list - cleanup was already done above if roaming
    # Also do fallback cleanup just in case
    if [ -z "$OLD_IFACE" ]; then
        # No previous state - check all interfaces for stale rules
        for rt in $(sqlite3 "$WG_DB_PATH" "SELECT routing_table FROM interfaces WHERE committed = 1;" 2>/dev/null); do
            # Quick cleanup attempt for each interface
            ip rule del from "$IPADDR" table $rt 2>/dev/null
        done
    fi
    sqlite3 "$WG_DB_PATH" "DELETE FROM mac_state WHERE mac = '$MACADDR';" 2>/dev/null
fi

ip route flush cache
flock -u 200
