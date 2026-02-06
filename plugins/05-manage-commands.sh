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

# Source common utilities for MAC address functions
if [ -f "${LIB_DIR:-./lib}/wg-common.sh" ]; then
    . "${LIB_DIR:-./lib}/wg-common.sh"
elif [ -f "/cfg/wg-custom/lib/wg-common.sh" ]; then
    . "/cfg/wg-custom/lib/wg-common.sh"
fi

# Hook: Display available commands in usage/help
show_plugin_help() {
    echo ""
    echo "Management Commands (via plugin):"
    echo "  $0 status [interface]            Show status of managed interface(s)"
    echo "  $0 assign-ips <interface> <ips>      Add target IPs (comma-separated, accumulates until commit)"
    echo "  $0 remove-ips <interface> <ips>      Remove target IPs (comma-separated, accumulates until commit)"
    echo "  $0 assign-domains <iface> <domains>  Add split-tunnel domains (comma-separated, accumulates until commit)"
    echo "  $0 remove-domains <iface> <domains>  Remove split-tunnel domains (comma-separated, accumulates until commit)"
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
        assign-domains)
            [ -z "$2" ] || [ -z "$3" ] && echo "Error: assign-domains requires interface and domain(s)" && return 1
            cmd_assign_domains "$2" "$3"
            return $?
            ;;
        remove-domains)
            [ -z "$2" ] || [ -z "$3" ] && echo "Error: remove-domains requires interface and domain(s)" && return 1
            cmd_remove_domains "$2" "$3"
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

# STATUS command - Pretty table-like output
cmd_status() {
    local iface="$1"
    
    # Try SQLite database first
    local db_entry=$(db_get_interface "$iface" 2>/dev/null)
    
    if [ -z "$db_entry" ]; then
        echo "Interface $iface not found in database"
        return 1
    fi
    
    # Parse SQLite entry
    local conf=$(echo "$db_entry" | cut -d'|' -f2)
    local rt=$(echo "$db_entry" | cut -d'|' -f3)
    local vpn_ips=$(echo "$db_entry" | cut -d'|' -f4)
    local domains=$(echo "$db_entry" | cut -d'|' -f5)
    local committed=$(echo "$db_entry" | cut -d'|' -f6)
    local ipv6=$(echo "$db_entry" | cut -d'|' -f8)
    local ip6_subs=$(echo "$db_entry" | cut -d'|' -f9)
    local nat66=$(echo "$db_entry" | cut -d'|' -f10)
    local start_time=$(echo "$db_entry" | cut -d'|' -f11)
    
    # Determine interface status
    local iface_status_display="Inactive ❌"
    local pub_ipv4=""
    local pub_ipv6=""
    
    if ip link show "$iface" >/dev/null 2>&1; then
        iface_status_display="Active ✅"
        pub_ipv6=$(ip -6 addr show "$iface" 2>/dev/null | awk '/inet6 / && !/fe80/ {split($2,a,"/"); print a[1]}' | head -1)
        
        # Check for pre-fetched public IP or fetch
        local tmp_ip="${WG_TMP_DIR}/wg_pub_ip_${iface}"
        if [ -s "$tmp_ip" ]; then
            pub_ipv4=$(cat "$tmp_ip")
            rm -f "$tmp_ip" 2>/dev/null
        else
            pub_ipv4=$(curl -4 -s --max-time 2 --interface "$iface" ifconfig.me 2>/dev/null)
        fi
    fi
    
    # Calculate uptime
    local uptime_str="-"
    if [ -n "$start_time" ] && [ "$start_time" -gt 0 ] 2>/dev/null; then
        local now=$(date +%s)
        local uptime_secs=$((now - start_time))
        local days=$((uptime_secs / 86400))
        local hours=$(((uptime_secs % 86400) / 3600))
        local mins=$(((uptime_secs % 3600) / 60))
        local secs=$((uptime_secs % 60))
        uptime_str=""
        [ $days -gt 0 ] && uptime_str="${days}d "
        [ $hours -gt 0 ] || [ $days -gt 0 ] && uptime_str="${uptime_str}${hours}h "
        [ $mins -gt 0 ] || [ $hours -gt 0 ] || [ $days -gt 0 ] && uptime_str="${uptime_str}${mins}m "
        uptime_str="${uptime_str}${secs}s"
        [ -n "$uptime_str" ] && uptime_str="$uptime_str ⏱️"
    fi
    
    # Determine mode
    local mode_display="Client Routing 🌐"
    local is_split=0
    if [ -n "$domains" ] && [ "$domains" != "" ]; then
        mode_display="Split-Tunnel 🛡️"
        is_split=1
    fi
    
    # Print header (+2 for 4-byte 🔗)
    echo "+-----------------------------------------------------------------------+"
    printf "| %-71s |\n" "$iface 🔗"
    echo "+------------------+----------------------------------------------------+"
    
    # Interface section
    # Label col: 16 visual | Value col: 50 visual
    # Compensation for multi-byte emojis in 2nd column
    # Emojis like 🔗, ✅, 🛡️ take more space than 1 char visually but sometimes count as multiple bytes
    # Status: 'Active ✅' -> 6 chars text + 1 char space + emoji. 
    # To align with 50-char width: %-50s works if the emoji is treated correctly.
    # However, 'printf' usually counts bytes. 
    
    printf "| %-16s | %-51s |\n" "Status" "$iface_status_display"
    
    local mode_padding=52
    if echo "$mode_display" | grep -q "Split-Tunnel"; then
         mode_padding=55
    fi
    printf "| %-16s | %-${mode_padding}s |\n" "Mode" "$mode_display"
    
    # Calculate padding for Uptime based on emoji presence (⏱️ is ~6 bytes but 2 columns)
    local uptime_padding=50
    if echo "$uptime_str" | grep -q "⏱️"; then
        uptime_padding=54
    fi
    printf "| %-16s | %-${uptime_padding}s |\n" "Uptime" "$uptime_str"
    
    # Staged row - emojis used
    local staged_display="$([ "$committed" = "1" ] && echo "Committed ✅" || echo "Pending ⏳")"
    printf "| %-16s | %-51s |\n" "Staged" "$staged_display"
    
    # Network section
    echo "+------------------+----------------------------------------------------+"
    printf "| %-16s | %-50s |\n" "Routing Table" "$rt (${iface}_rt)"
    
    local ipv6_display="$([ "$ipv6" = "1" ] && echo "Yes ✅" || echo "No ❌")"
    printf "| %-16s | %-51s |\n" "IPv6 Support" "$ipv6_display"
    [ "$nat66" = "1" ] && printf "| %-16s | %-51s |\n" "NAT66" "Enabled ✅"
    [ -n "$pub_ipv4" ] && printf "| %-16s | %-50s |\n" "Public IPv4" "$pub_ipv4"
    [ -n "$pub_ipv6" ] && printf "| %-16s | %-50s |\n" "Public IPv6" "$pub_ipv6"
    
    # Targets section
    echo "+------------------+----------------------------------------------------+"
    if [ "$is_split" = "1" ]; then
        local first=1
        for domain in $(echo "$domains" | tr ',' ' '); do
            if [ "$first" = "1" ]; then
                printf "| %-16s | %-50s |\n" "Domains" "$domain"
                first=0
            else
                printf "| %-16s | %-50s |\n" "" "$domain"
            fi
        done
        [ "$first" = "1" ] && printf "| %-16s | %-50s |\n" "Domains" "(None)"
    else
        if [ -n "$vpn_ips" ] && [ "$vpn_ips" != "" ] && [ "$vpn_ips" != "none" ]; then
            local first=1
            for target in $(echo "$vpn_ips" | tr ',' ' '); do
                case "$target" in
                    *=*)
                        # MAC=ip format - Consolidate into single line for better alignment
                        local mac="${target%%=*}"
                        local resolved="${target#*=}"
                        if [ "$first" = "1" ]; then
                            printf "| %-16s | %-50s |\n" "Targets" "$mac -> $resolved"
                            first=0
                        else
                            printf "| %-16s | %-50s |\n" "" "$mac -> $resolved"
                        fi
                        ;;
                    *)
                        # Plain IP/subnet
                        if [ "$first" = "1" ]; then
                            printf "| %-16s | %-50s |\n" "Targets" "$target"
                            first=0
                        else
                            printf "| %-16s | %-50s |\n" "" "$target"
                        fi
                        ;;
                esac
            done
        else
            printf "| %-16s | %-50s |\n" "Targets" "(No targets)"
        fi
    fi
    
    # Config section - Multi-line wrapping for long paths
    echo "+------------------+----------------------------------------------------+"
    if [ -n "$conf" ]; then
        local val_w=50
        if [ ${#conf} -le $val_w ]; then
            printf "| %-16s | %-50s |\n" "Config" "$conf"
        else
            # Wrap long path
            local start=1
            while [ $start -le ${#conf} ]; do
                local chunk=$(echo "$conf" | cut -c $start-$((start + val_w - 1)))
                if [ $start -eq 1 ]; then
                    printf "| %-16s | %-50s |\n" "Config" "$chunk"
                else
                    printf "| %-16s | %-50s |\n" "" "$chunk"
                fi
                start=$((start + val_w))
            done
        fi
    fi
    [ -n "$ip6_subs" ] && [ "$ip6_subs" != "" ] && printf "| %-16s | %-50s |\n" "IPv6 Subnets" "$ip6_subs"
    
    echo "+-----------------------------------------------------------------------+"
}

# REMOVE-IP command - Accumulates removals from STAGED targets until commit
# Supports comma-separated IPs/MACs. Strict format matching:
# - MACs must be removed with MAC format (even if resolved IP matches)
# - IPs must be removed with IP format
cmd_remove_ip() {
    local iface="$1"
    local input_list="$2"
    
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
    
    # Build new targets by removing specified items from current
    local new_targets=""
    local removal_list=$(echo "$input_list" | tr ',' ' ')
    local removed_any=0
    
    for target in $current_targets; do
        local should_remove=0
        
        for to_remove in $removal_list; do
            # Normalize to_remove if it's a MAC
            local match_key="$to_remove"
            if is_mac "$to_remove" 2>/dev/null; then
                match_key=$(normalize_mac "$to_remove")
            fi
            
            # Check target format
            case "$target" in
                *=*)
                    # Target is MAC=ip format
                    local target_mac="${target%%=*}"
                    if [ "$target_mac" = "$match_key" ]; then
                        should_remove=1
                        echo "Removing MAC $target_mac from $iface"
                        removed_any=1
                        break
                    fi
                    ;;
                *)
                    # Target is plain IP/subnet
                    if [ "$target" = "$to_remove" ]; then
                        should_remove=1
                        echo "Removing $to_remove from $iface"
                        removed_any=1
                        break
                    fi
                    ;;
            esac
        done
        
        if [ "$should_remove" = "0" ]; then
            [ -n "$new_targets" ] && new_targets="${new_targets},"
            new_targets="${new_targets}${target}"
        fi
    done
    
    # Warn about items that weren't found
    for to_remove in $removal_list; do
        local found=0
        local match_key="$to_remove"
        if is_mac "$to_remove" 2>/dev/null; then
            match_key=$(normalize_mac "$to_remove")
        fi
        
        for target in $current_targets; do
            case "$target" in
                *=*)
                    local target_mac="${target%%=*}"
                    [ "$target_mac" = "$match_key" ] && found=1 && break
                    ;;
                *)
                    [ "$target" = "$to_remove" ] && found=1 && break
                    ;;
            esac
        done
        
        if [ "$found" = "0" ]; then
            if is_mac "$to_remove" 2>/dev/null; then
                echo "WARN: MAC $match_key not found in targets (was it added as IP instead?)"
            else
                echo "WARN: $to_remove not found in targets"
            fi
        fi
    done
    
    if [ -z "$new_targets" ]; then
        echo "Note: No targets remaining for $iface"
        new_targets="none"
    fi
    
    # Update database with new targets
    local target_only=0
    is_interface_committed "$iface" && target_only=1
    
    db_update_staged_targets "$iface" "$new_targets" "$target_only"
    
    echo "Staged updated configuration for $iface"
    echo "Run './wg-pbr.sh commit' to apply changes"
}

# ASSIGN-IP command - Accumulates IPs/MACs to STAGED targets until commit
# Supports comma-separated IPs/MACs. Multiple calls accumulate unique targets.
# MAC addresses are stored as MAC=resolved_ip for strict format tracking.
# Automatically moves IPs from other interfaces.
cmd_assign_ip() {
    local iface="$1"
    local input_list="$2"
    
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
    
    # Parse: name|conf|routing_table|target_ips|committed|target_only
    local current_targets=$(echo "$staged_entry" | cut -d'|' -f4 | tr ',' ' ')
    
    # Build list of currently resolved IPs (for dedup checking)
    local current_resolved_ips=""
    if [ -n "$current_targets" ] && [ "$current_targets" != "none" ]; then
        for target in $current_targets; do
            case "$target" in
                *=*)
                    # MAC=ip format - extract resolved IP
                    current_resolved_ips="$current_resolved_ips ${target#*=}"
                    ;;
                *)
                    # Plain IP/subnet
                    current_resolved_ips="$current_resolved_ips $target"
                    ;;
            esac
        done
    fi
    
    local new_targets_list=""
    if [ -n "$current_targets" ] && [ "$current_targets" != "none" ]; then
        new_targets_list="$current_targets"
    fi
    
    # Process each input target
    for input_target in $(echo "$input_list" | tr ',' ' '); do
        local store_format=""
        local resolved_ip=""
        
        # Check if this is a MAC address
        if is_mac "$input_target" 2>/dev/null; then
            local mac=$(normalize_mac "$input_target")
            if [ -z "$mac" ]; then
                echo "WARN: Invalid MAC address: $input_target, skipping"
                continue
            fi
            
            resolved_ip=$(resolve_mac_to_ip "$mac")
            if [ -z "$resolved_ip" ]; then
                echo "WARN: MAC $mac not found in ARP table, skipping"
                continue
            fi
            
            echo "Resolved MAC $mac -> $resolved_ip"
            store_format="${mac}=${resolved_ip}"
        else
            # Plain IP or subnet
            resolved_ip="$input_target"
            store_format="$input_target"
        fi
        
        # Check for conflicts with other interfaces (by resolved IP)
        local current_owner=$(find_interface_for_ip "$resolved_ip" 2>/dev/null)
        if [ -n "$current_owner" ] && [ "$current_owner" != "$iface" ]; then
            echo "Moving $resolved_ip from $current_owner to $iface"
            # Find the exact target format in the other interface
            local other_targets=$(db_get_field "$current_owner" "target_ips" 2>/dev/null | tr ',' ' ')
            for other_target in $other_targets; do
                local other_resolved=""
                case "$other_target" in
                    *=*) other_resolved="${other_target#*=}" ;;
                    *) other_resolved="$other_target" ;;
                esac
                if [ "$other_resolved" = "$resolved_ip" ]; then
                    cmd_remove_ip "$current_owner" "$other_target"
                    break
                fi
            done
        fi
        
        # Check for duplicates (by resolved IP)
        local is_dupe=0
        for existing_resolved in $current_resolved_ips; do
            if [ "$existing_resolved" = "$resolved_ip" ]; then
                echo "INFO: $resolved_ip already in target list (duplicate), skipping"
                is_dupe=1
                break
            fi
        done
        
        if [ "$is_dupe" = "0" ]; then
            [ -n "$new_targets_list" ] && new_targets_list="${new_targets_list},"
            new_targets_list="${new_targets_list}${store_format}"
            current_resolved_ips="$current_resolved_ips $resolved_ip"
        fi
    done
    
    # Normalize to comma-separated
    new_targets_list=$(echo "$new_targets_list" | tr ' ' ',')
    
    echo "Assigning targets to $iface: $new_targets_list"
    
    # Update database with new targets
    local target_only=0
    is_interface_committed "$iface" && target_only=1
    
    db_update_staged_targets "$iface" "$new_targets_list" "$target_only"
    
    echo "Staged updated configuration for $iface"
    echo "Run './wg-pbr.sh commit' to apply changes"
}

# ASSIGN-DOMAINS command - Accumulates domains for split-tunnel interfaces
cmd_assign_domains() {
    local iface="$1"
    local input_list="$2"
    
    # Get current staged entry from SQLite
    local db_entry=$(db_get_interface "$iface" 2>/dev/null)
    if [ -z "$db_entry" ]; then
        echo "Error: Interface $iface not found in database"
        return 1
    fi
    
    # Validation: Verify interface is in split-tunnel mode
    local targets=$(echo "$db_entry" | cut -d'|' -f4)
    local current_domains=$(echo "$db_entry" | cut -d'|' -f5)
    
    if [ "$targets" != "none" ] && [ -n "$targets" ]; then
        echo "Error: Cannot assign domains to IP-routing interface $iface"
        echo "This interface is configured to route by IP/MAC: $targets"
        return 1
    fi
    
    echo "Updating domains for $iface (Split-Tunnel mode)"
    
    [ "$current_domains" = "none" ] && current_domains=""
    
    # Build unique list of domains
    local new_list="$current_domains"
    # Replace commas with spaces safely
    local input_domains=$(echo "$input_list" | tr ',' ' ')
    
    for domain in $input_domains; do
        # Convert to lowercase
        local domain_clean=$(echo "$domain" | tr A-Z a-z)
        
        # Trim whitespace using shell parameter expansion (safer than external function/pipes)
        # Remove leading whitespace
        domain_clean="${domain_clean#"${domain_clean%%[![:space:]]*}"}"
        # Remove trailing whitespace  
        domain_clean="${domain_clean%"${domain_clean##*[![:space:]]}"}"
        
        [ -z "$domain_clean" ] && continue
        
        # Check if already exists (safe matching with commas)
        case ",$new_list," in
            *",${domain_clean},"*)
                echo "Info: $domain_clean already in list."
                ;;
            *)
                if [ -n "$new_list" ]; then
                    new_list="${new_list},${domain_clean}"
                else
                    new_list="${domain_clean}"
                fi
                echo "Staging addition: $domain_clean"
                ;;
        esac
    done
    
    # Update database
    local target_only=0
    is_interface_committed "$iface" && target_only=1
    db_update_staged_domains "$iface" "$new_list" "$target_only"
    
    echo "Staged updated domain configuration for $iface"
    echo "Run './wg-pbr.sh commit' to apply changes"
}

# REMOVE-DOMAINS command - Removes domains from split-tunnel interfaces
cmd_remove_domains() {
    local iface="$1"
    local input_list="$2"
    
    # Get current staged entry from SQLite
    local db_entry=$(db_get_interface "$iface" 2>/dev/null)
    if [ -z "$db_entry" ]; then
        echo "Error: Interface $iface not found in database"
        return 1
    fi
    
    local current_domains=$(echo "$db_entry" | cut -d'|' -f5)
    if [ -z "$current_domains" ]; then
        echo "Error: No domains configured for $iface"
        return 1
    fi
    
    local new_list=""
    local removed_count=0
    # Process removals safely
    local to_remove_list=$(echo "$input_list" | tr ',' ' ')
    local keep_list=""
    
    # Iterate through current domains
    for current in $(echo "$current_domains" | tr ',' ' '); do
        local keep=1
        for remove_item in $to_remove_list; do
            # normalize remove item
            local clean_remove=$(echo "$remove_item" | tr A-Z a-z)
            # trim
            clean_remove="${clean_remove#"${clean_remove%%[![:space:]]*}"}"
            clean_remove="${clean_remove%"${clean_remove##*[![:space:]]}"}"
            
            if [ "$current" = "$clean_remove" ]; then
                keep=0
                removed_count=$((removed_count + 1))
                echo "Staging removal: $current"
                break
            fi
        done
        
        if [ "$keep" -eq 1 ]; then
            if [ -n "$keep_list" ]; then
                keep_list="${keep_list},${current}"
            else
                keep_list="${current}"
            fi
        fi
    done
    new_list="$keep_list"
    
    if [ $removed_count -eq 0 ]; then
        echo "Warning: None of the specified domains were found in $iface"
        return 0
    fi
    
    # Update database
    local target_only=0
    is_interface_committed "$iface" && target_only=1
    db_update_staged_domains "$iface" "$new_list" "$target_only"
    
    echo "Staged updated domain configuration for $iface ($removed_count removed)"
    echo "Run './wg-pbr.sh commit' to apply changes"
}
