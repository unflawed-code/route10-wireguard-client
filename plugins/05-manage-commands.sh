#!/bin/sh
# 05-manage-commands.sh - Management commands plugin for wg-pbr.sh
# Provides: status, remove-ip, assign-ip commands

WG_TMP_DIR="/tmp/wg-custom"
STAGING_DB="${WG_TMP_DIR}/staging_db"
WG_REGISTRY="${WG_TMP_DIR}/registry"

# Source SQLite database functions
# Try multiple paths since plugin may be sourced from different contexts
if [ -f "${LIB_DIR:-./lib}/wg-db.sh" ]; then
    . "${LIB_DIR:-./lib}/wg-db.sh"
elif [ -f "/cfg/wg-custom/lib/wg-db.sh" ]; then
    . "/cfg/wg-custom/lib/wg-db.sh"
fi

# Hook: Display available commands in usage/help
show_plugin_help() {
    echo ""
    echo "Management Commands (via plugin):"
    echo "  $0 status [interface]            Show status of managed interface(s)"
    echo "  $0 assign-ips <interface> <ips>  Add target IPs (comma-separated, accumulates until commit)"
    echo "  $0 remove-ips <interface> <ips>  Remove target IPs (comma-separated, accumulates until commit)"
}

# Hook: Handle custom commands
# Returns 0 if command was handled, 1 otherwise
handle_command() {
    case "$1" in
        status)
            if [ -z "$2" ]; then
                cmd_status_all
            else
                cmd_status "$2"
            fi
            return 0
            ;;
        remove-ips)
            [ -z "$2" ] || [ -z "$3" ] && echo "Error: remove-ips requires interface and IP(s)" && return 1
            cmd_remove_ip "$2" "$3"
            return $?
            ;;
        assign-ips)
            [ -z "$2" ] || [ -z "$3" ] && echo "Error: assign-ips requires interface and IP(s)" && return 1
            cmd_assign_ip "$2" "$3"
            return $?
            ;;
    esac
    return 1
}

# Find which interface routes a given IP (uses SQLite database)
find_interface_for_ip() {
    local ip="$1"
    db_find_interface_by_ip "$ip" 2>/dev/null | head -1
}

# Get staged command for an interface (reconstructs from SQLite)
get_staged_command() {
    local iface="$1"
    db_reconstruct_command "$iface" 2>/dev/null
}

# Check if an interface is already committed (uses SQLite)
is_interface_committed() {
    local iface="$1"
    db_is_committed "$iface" 2>/dev/null
}

# Extract config file from staged command
get_config_from_command() {
    echo "$1" | awk '{for(i=1;i<=NF;i++) if($i=="--conf") print $(i+1)}'
}

# Extract routing table from staged command
get_rt_from_command() {
    echo "$1" | awk '{for(i=1;i<=NF;i++) if($i=="--routing-table") print $(i+1)}'
}

# Extract targets from staged command
# Extract targets from staged command
get_targets_from_command() {
    echo "$1" | awk '{for(i=1;i<=NF;i++) if($i=="--target-ips") print $(i+1)}'
}

# Get base targets from SQLite
get_base_targets() {
    local iface="$1"
    local targets=$(db_get_field "$iface" "target_ips" 2>/dev/null | tr ',' ' ')
    
    if [ -z "$targets" ] || [ "$targets" = "none" ]; then
        targets=""
    fi
    
    echo "$targets"
}

# STATUS ALL command - show all managed interfaces
cmd_status_all() {
    # Initialize database if needed
    db_init 2>/dev/null
    
    # Get all interfaces from SQLite database
    local all_ifaces=$(db_list_interfaces 2>/dev/null)
    
    if [ -z "$all_ifaces" ]; then
        echo "No managed WireGuard interfaces found."
        return
    fi
    
    # Fetch all public IPs in parallel (background)
    for iface in $all_ifaces; do
        if ip link show "$iface" >/dev/null 2>&1; then
            (curl -4 -s --max-time 2 --interface "$iface" ifconfig.me > "${WG_TMP_DIR}/wg_pub_ip_${iface}" 2>/dev/null) &
        fi
    done
    
    # Wait for all curl processes to complete (with timeout)
    wait
    
    # Now display all statuses
    local first=1
    for iface in $all_ifaces; do
        [ "$first" = "0" ] && echo ""
        first=0
        cmd_status "$iface"
    done
}

# STATUS command
cmd_status() {
    local iface="$1"
    
    echo "=== Status for $iface ==="
    echo ""
    
    # Try SQLite database first
    local db_entry=$(db_get_interface "$iface" 2>/dev/null)
    
    if [ -n "$db_entry" ]; then
        # Parse SQLite entry: name|conf|routing_table|target_ips|domains|committed|target_only|ipv6_support|ipv6_subnets|nat66|start_time|running
        local rt=$(echo "$db_entry" | cut -d'|' -f3)
        local vpn_ips=$(echo "$db_entry" | cut -d'|' -f4)
        # Field 5 is domains (not used in status display)
        local committed=$(echo "$db_entry" | cut -d'|' -f6)
        # Field 7 is target_only (not used in status display)
        local ipv6=$(echo "$db_entry" | cut -d'|' -f8)
        local ip6_subs=$(echo "$db_entry" | cut -d'|' -f9)
        local nat66=$(echo "$db_entry" | cut -d'|' -f10)
        local start_time=$(echo "$db_entry" | cut -d'|' -f11)
        local running=$(echo "$db_entry" | cut -d'|' -f12)
        local conf=$(echo "$db_entry" | cut -d'|' -f2)
        
        echo "Routing Table: $rt (${iface}_rt)"
        
        # Check if this is a split-tunnel interface
        local domains=$(echo "$db_entry" | cut -d'|' -f5)
        if [ -n "$domains" ] && [ "$domains" != "" ]; then
            echo "Mode:          Split-Tunnel"
            echo "Domains:       $domains"
        else
            if [ -n "$vpn_ips" ] && [ "$vpn_ips" != "" ] && [ "$vpn_ips" != "none" ]; then
                echo "Target IPs:    $(echo $vpn_ips | tr ',' ' ')"
            else
                echo "Target IPs:    (No targets)"
            fi
        fi
        echo "IPv6 Support:  $([ "$ipv6" = "1" ] && echo "Yes" || echo "No")"
        [ -n "$ip6_subs" ] && [ "$ip6_subs" != "" ] && echo "IPv6 Subnets:  $ip6_subs"
        [ "$nat66" = "1" ] && echo "NAT66:         Enabled"
        
        # Show uptime
        if [ -n "$start_time" ] && [ "$start_time" -gt 0 ] 2>/dev/null; then
            local now=$(date +%s)
            local uptime_secs=$((now - start_time))
            local days=$((uptime_secs / 86400))
            local hours=$(((uptime_secs % 86400) / 3600))
            local mins=$(((uptime_secs % 3600) / 60))
            local secs=$((uptime_secs % 60))
            local uptime_str=""
            [ $days -gt 0 ] && uptime_str="${days}d "
            [ $hours -gt 0 ] || [ $days -gt 0 ] && uptime_str="${uptime_str}${hours}h "
            [ $mins -gt 0 ] || [ $hours -gt 0 ] || [ $days -gt 0 ] && uptime_str="${uptime_str}${mins}m "
            uptime_str="${uptime_str}${secs}s"
            echo "Uptime:        $uptime_str"
        fi
        
        echo ""
        [ -n "$conf" ] && echo "Config File:   $conf"
        echo "Staged:        $([ "$committed" = "1" ] && echo "Committed" || echo "Pending commit")"
        
    else
        echo "Interface not found in database"
    fi
    
    # Show if interface is active and its public IPs
    if ip link show "$iface" >/dev/null 2>&1; then
        local vpn_ip6=$(ip -6 addr show "$iface" 2>/dev/null | awk '/inet6 / && !/fe80/ {split($2,a,"/"); print a[1]}' | head -1)
        echo "Interface:     Active"
        [ -n "$vpn_ip6" ] && echo "Public IPv6:   $vpn_ip6"
        
        # Check for pre-fetched public IP (from cmd_status_all) or fetch if not present
        local tmp_ip="${WG_TMP_DIR}/wg_pub_ip_${iface}"
        if [ -s "$tmp_ip" ]; then
            echo "Public IPv4:   $(cat $tmp_ip)"
            rm -f "$tmp_ip" 2>/dev/null
        else
            # Direct status call - fetch synchronously but with short timeout
            local pub_ip=$(curl -4 -s --max-time 2 --interface "$iface" ifconfig.me 2>/dev/null)
            [ -n "$pub_ip" ] && echo "Public IPv4:   $pub_ip"
        fi
    else
        echo "Interface:     Not active"
    fi
}

# REMOVE-IP command - Accumulates removals from STAGED targets until commit
# Supports comma-separated IPs. Multiple calls accumulate unique removals.
cmd_remove_ip() {
    local iface="$1"
    local ip_list="$2"
    
    # Get current staged entry from SQLite
    local staged_entry=$(db_get_staged "$iface" 2>/dev/null)
    if [ -z "$staged_entry" ]; then
        echo "Error: Interface $iface not found in database"
        return 1
    fi
    
    # Check if this is a split-tunnel interface (has domains)
    local db_entry=$(db_get_interface "$iface" 2>/dev/null)
    local domains=$(echo "$db_entry" | cut -d'|' -f5)
    if [ -n "$domains" ] && [ "$domains" != "" ]; then
        echo "Error: Cannot remove IPs from split-tunnel interface $iface"
        echo "Split-tunnel routes by domain, not client IP."
        return 1
    fi
    
    # Parse: name|conf|routing_table|target_ips|committed|target_only
    local current_targets=$(echo "$staged_entry" | cut -d'|' -f4 | tr ',' ' ')
    
    # Build new targets by removing specified IPs from current
    local new_targets=""
    local removal_list=$(echo "$ip_list" | tr ',' ' ')
    
    for target in $current_targets; do
        local should_remove=0
        for ip_to_remove in $removal_list; do
            if [ "$target" = "$ip_to_remove" ]; then
                should_remove=1
                echo "Removing $ip_to_remove from $iface"
                break
            fi
        done
        if [ "$should_remove" = "0" ]; then
            [ -n "$new_targets" ] && new_targets="${new_targets},"
            new_targets="${new_targets}${target}"
        fi
    done
    
    if [ -z "$new_targets" ]; then
        echo "Note: No targets remaining for $iface"
        new_targets="none"
    fi
    
    # Update database with new targets
    # Set target_only=1 if interface was already committed (hot-reload path)
    local target_only=0
    is_interface_committed "$iface" && target_only=1
    
    db_update_staged_targets "$iface" "$new_targets" "$target_only"
    
    echo "Staged updated configuration for $iface"
    echo "Run './wg-pbr.sh commit' to apply changes"
}

# ASSIGN-IP command - Accumulates IPs to STAGED targets until commit
# Supports comma-separated IPs. Multiple calls accumulate unique IPs.
# Automatically moves IPs from other interfaces.
cmd_assign_ip() {
    local iface="$1"
    local ip_list="$2"
    
    # Get current staged entry from SQLite
    local staged_entry=$(db_get_staged "$iface" 2>/dev/null)
    if [ -z "$staged_entry" ]; then
        echo "Error: Interface $iface not found in database"
        return 1
    fi
    
    # Check if this is a split-tunnel interface (has domains)
    local db_entry=$(db_get_interface "$iface" 2>/dev/null)
    local domains=$(echo "$db_entry" | cut -d'|' -f5)
    if [ -n "$domains" ] && [ "$domains" != "" ]; then
        echo "Error: Cannot assign IPs to split-tunnel interface $iface"
        echo "Split-tunnel routes by domain, not client IP."
        return 1
    fi
    
    # Check each IP for conflicts and move if needed
    for ip_to_add in $(echo "$ip_list" | tr ',' ' '); do
        local current_owner=$(find_interface_for_ip "$ip_to_add")
        if [ -n "$current_owner" ] && [ "$current_owner" != "$iface" ]; then
            echo "Moving $ip_to_add from $current_owner to $iface"
            cmd_remove_ip "$current_owner" "$ip_to_add"
        fi
    done
    
    # Re-read staged entry after potential modifications from cmd_remove_ip
    staged_entry=$(db_get_staged "$iface" 2>/dev/null)
    
    # Parse: name|conf|routing_table|target_ips|committed|target_only
    local current_targets=$(echo "$staged_entry" | cut -d'|' -f4 | tr ',' ' ')
    
    local new_targets_list=""
    
    # Start with current staged targets
    if [ -n "$current_targets" ] && [ "$current_targets" != "none" ]; then
        new_targets_list="$current_targets"
    fi
    
    # Add new IPs (avoiding duplicates)
    for ip_to_add in $(echo "$ip_list" | tr ',' ' '); do
        local exists=0
        for existing in $new_targets_list; do
            if [ "$existing" = "$ip_to_add" ]; then
                exists=1
                break
            fi
        done
        
        if [ "$exists" = "0" ]; then
            [ -n "$new_targets_list" ] && new_targets_list="${new_targets_list},"
            new_targets_list="${new_targets_list}${ip_to_add}"
        fi
    done
    
    # Use normalized comma-separated list
    new_targets_list=$(echo "$new_targets_list" | tr ' ' ',')
    
    # Assigning targets to interface
    echo "Assigning targets to $iface: $new_targets_list"
    
    # Update database with new targets
    # Set target_only=1 if interface was already committed (hot-reload path)
    local target_only=0
    is_interface_committed "$iface" && target_only=1
    
    db_update_staged_targets "$iface" "$new_targets_list" "$target_only"
    
    echo "Staged updated configuration for $iface"
    echo "Run './wg-pbr.sh commit' to apply changes"
}
