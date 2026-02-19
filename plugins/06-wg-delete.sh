#!/bin/sh
# 06-wg-delete.sh - Delete and cleanup a WireGuard interface
# Usage: ./wg-pbr.sh delete <interface_name>

# Hook: Display available commands in usage/help
show_plugin_help() {
    echo "  $0 delete <interface>            Stop and permanently remove an interface and all rules"
}

# Hook: Handle custom commands
# Returns 0 if command was handled, 1 otherwise
handle_command() {
    local CMD="$1"
    local INTERFACE_NAME="$2"
    
    if [ "$CMD" = "delete" ]; then
        if [ -z "$INTERFACE_NAME" ]; then
            echo "Error: Interface name required for delete command"
            echo "Usage: $0 delete <interface_name>"
            return 0 # Handled with error
        fi
        
        delete_wg_interface "$INTERFACE_NAME"
        return 0 # Handled
    fi
    return 1 # Not handled
}

# Delete a WireGuard interface and all associated rules
delete_wg_interface() {
    local iface="$1"
    
    # Initialize DB paths
    local wg_tmp_dir="/tmp/wg-custom"
    local db_path="${wg_tmp_dir}/wg_pbr.db"
    
    echo "Deleting WireGuard interface: $iface"
    
    # 1. Get info from database before deleting (Validation)
    local rt=""
    if [ -f "$db_path" ]; then
        rt=$(sqlite3 "$db_path" "SELECT routing_table FROM interfaces WHERE name = '$iface';" 2>/dev/null)
    fi
    
    if [ -z "$rt" ]; then
        echo "Error: Interface '$iface' is not managed by wg-pbr.sh."
        echo "Only interfaces registered in the database can be deleted."
        return 1
    fi
    
    # 2. Bring down the interface (this triggers the hotplug cleanup script)
    if ip link show "$iface" >/dev/null 2>&1; then
        echo "  Bringing down interface $iface..."
        ifdown "$iface" >/dev/null 2>&1 || true
        # Give it a second to run hotplug
        sleep 1
        
        # Force delete if still exists (UCI deletion alone doesn't kill kernel device if ifdown fails)
        if ip link show "$iface" >/dev/null 2>&1; then
             echo "  Forcefully removing interface $iface..."
             ip link delete "$iface" 2>/dev/null || true
        fi
    fi
    
    # 3. Clean up UCI configuration
    echo "  Removing UCI configuration..."
    # Remove interface
    uci delete "network.${iface}" 2>/dev/null || true
    
    # Remove firewall zone and forwarding
    # We look for the zone named after the first 11 chars of interface (as done in setup)
    local zone_name=$(echo "$iface" | cut -c1-11)
    
    # Delete zone
    for section in $(uci show firewall 2>/dev/null | grep "\.name='${zone_name}'" | cut -d. -f2 | cut -d= -f1); do
        uci delete "firewall.${section}" 2>/dev/null || true
    done
    
    # Delete forwarding
    uci delete "firewall.${iface}_fwd" 2>/dev/null || true
    uci delete "firewall.${iface}_zone" 2>/dev/null || true
    
    uci commit network 2>/dev/null || true
    uci commit firewall 2>/dev/null || true
    
    # 4. Clean up firewall chains (ensuring nothing is missed)
    echo "  Cleaning up firewall rules..."
    local mark_chain="mark_${iface}"
    local mark_ipv6_chain="mark_ipv6_${iface}"
    local ks_chain="${iface}_killswitch"
    local block_chain="${iface}_ipv6_block"
    local ipv4_only_block_chain="${iface}_ipv4_only_block"
    local v6_dns_in_chain="${iface}_v6_dns_in"
    local nat66_chain="nat66_${iface}"
    local dns_nat_chain="vpn_dns_nat_${iface}"
    local dns_nat6_chain="vpn_dns_nat6_${iface}"
    local dns_filter_chain="vpn_dns_filter_${iface}"
    local dns_filter6_chain="vpn_dns_filter6_${iface}"
    local dns_block_chain="vpn_dns_block_${iface}"
    local dns_block6_chain="vpn_dns_block6_${iface}"
    local split_chain="split_${iface}"
    
    # Unlink and flush IPv4 chains
    for table in mangle nat filter; do
        for chain in $mark_chain $ks_chain $dns_nat_chain $dns_filter_chain $dns_block_chain $split_chain; do
            iptables -w -t $table -F "$chain" 2>/dev/null || true
            iptables -w -t $table -D PREROUTING -j "$chain" 2>/dev/null || true
            iptables -w -t $table -D FORWARD -j "$chain" 2>/dev/null || true
            iptables -w -t $table -D INPUT -j "$chain" 2>/dev/null || true
            iptables -w -t $table -D OUTPUT -j "$chain" 2>/dev/null || true
            iptables -w -t $table -X "$chain" 2>/dev/null || true
        done
        # Special case for split-tunnel: cleanup any lingering OUTPUT rules by target IP if found
        # (Though usually iptables -X handles unlinked chains, we explicitly marked OUTPUT 1)
        iptables -w -t mangle -D OUTPUT -j "$split_chain" 2>/dev/null || true
    done
    
    # Unlink and flush IPv6 chains
    for table in mangle nat filter; do
        for chain in $mark_ipv6_chain $ks_chain $block_chain $ipv4_only_block_chain $v6_dns_in_chain $nat66_chain $dns_nat6_chain $dns_filter6_chain $dns_block6_chain $split_chain; do
            ip6tables -w -t $table -F "$chain" 2>/dev/null || true
            ip6tables -w -t $table -D PREROUTING -j "$chain" 2>/dev/null || true
            ip6tables -w -t $table -D FORWARD -j "$chain" 2>/dev/null || true
            ip6tables -w -t $table -D INPUT -j "$chain" 2>/dev/null || true
            ip6tables -w -t $table -D OUTPUT -j "$chain" 2>/dev/null || true
            ip6tables -w -t $table -X "$chain" 2>/dev/null || true
        done
        ip6tables -w -t mangle -D OUTPUT -j "$split_chain" 2>/dev/null || true
    done
    
    # 5. Clean up routing rules
    if [ -n "$rt" ]; then
        echo "  Cleaning up routing rules (Table: $rt)..."
        while ip rule show | grep -q "lookup $rt"; do
            ip rule del $(ip rule show | grep "lookup $rt" | head -n1 | cut -d: -f2) 2>/dev/null || break
        done
        while ip -6 rule show | grep -q "lookup $rt"; do
            ip -6 rule del $(ip -6 rule show | grep "lookup $rt" | head -n1 | cut -d: -f2) 2>/dev/null || break
        done
        ip route flush table "$rt" 2>/dev/null || true
        ip -6 route flush table "$rt" 2>/dev/null || true
    fi
    
    # 6. Clean up ipsets
    echo "  Removing ipsets..."
    ipset destroy "vpn_${iface}" 2>/dev/null || true
    ipset destroy "vpn6_${iface}" 2>/dev/null || true
    ipset destroy "dst_vpn_${iface}" 2>/dev/null || true
    ipset destroy "dst6_vpn_${iface}" 2>/dev/null || true
    
    # 7. Clean up Dedicated DNS (Split Tunnel)
    echo "  Stopping dedicated DNS instance (if any)..."
    local ded_pid="${wg_tmp_dir}/${iface}-split-dnsmasq.pid"
    if [ -f "$ded_pid" ]; then
        local pid=$(cat "$ded_pid")
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
        fi
        rm -f "$ded_pid" 2>/dev/null || true
    fi
    rm -f "${wg_tmp_dir}/${iface}-split-dnsmasq.conf" 2>/dev/null || true
    rm -f "/tmp/dnsmasq.d/${iface}-split-stub.conf" 2>/dev/null || true
    
    # 8. Remove hotplug scripts
    echo "  Removing hotplug scripts..."
    rm -f "/etc/hotplug.d/iface/99-${iface}-routing" 2>/dev/null || true
    rm -f "/etc/hotplug.d/iface/99-${iface}-cleanup" 2>/dev/null || true
    rm -f "/etc/hotplug.d/iface/99-${iface}-split" 2>/dev/null || true
    
    # 9. Clean up temporary files
    echo "  Removing temporary state files..."
    rm -f "${wg_tmp_dir}/prefix_${iface}_"* 2>/dev/null || true
    rm -f "${wg_tmp_dir}/ip_${iface}_"* 2>/dev/null || true
    rm -f "/tmp/dnsmasq.d/99-${iface}-dns.conf" 2>/dev/null || true
    
    # 10. Purge from database
    if [ -f "$db_path" ]; then
        echo "  Purging database entries..."
        # Remove 2>/dev/null to see errors
        if ! sqlite3 "$db_path" "DELETE FROM mac_state WHERE interface = '$iface';"; then
            echo "Error: Failed to delete from mac_state"
        fi
        if ! sqlite3 "$db_path" "DELETE FROM interfaces WHERE name = '$iface';"; then
             echo "Error: Failed to delete from interfaces"
        fi
        
        # Verify deletion
        if sqlite3 "$db_path" "SELECT name FROM interfaces WHERE name = '$iface';" | grep -q "$iface"; then
             echo "Error: Interface entry still exists in database!"
        else
             echo "  Database entry confirmed deleted."
        fi
    fi
    
    echo "Done - $iface deleted and cleaned up"
    # Reload dnsmasq to pick up removed config
    [ -x /etc/init.d/dnsmasq ] && /etc/init.d/dnsmasq reload >/dev/null 2>&1 || true
}
