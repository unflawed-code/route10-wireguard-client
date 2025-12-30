#!/bin/sh
# Plugin: ipv6-prefix-routing.sh
# Handles IPv6 routing for /64 and /65-/127 prefixes
# Most commercial VPNs only provide /128, so this is optional
# Hook: process_ipv6_prefix (called for each IPv6 address)

# Hook function: process_ipv6_prefix
# Arguments:
#   $1 - ip6 address (e.g., 2001:db8::1/64)
#   $2 - prefix_len (e.g., 64)
#   $3 - addr_part (e.g., 2001:db8::1)
# Sets global variables:
#   VPN_IP6_SUBNETS - space-separated list of subnets
#   VPN_IP6_NEEDS_NAT66 - 1 if NAT66 is needed
process_ipv6_prefix() {
    local ip6="$1"
    local prefix_len="$2"
    local addr_part="$3"
    
    # Handle /64 and larger subnets
    if [ "$prefix_len" -le 64 ]; then
        # Extract first 4 blocks for /64 and larger
        network_prefix=$(echo "$addr_part" | cut -d: -f1-4)
        subnet="${network_prefix}::/${prefix_len}"
        
        # Check if this subnet was already added (prevent duplicates)
        case " $VPN_IP6_SUBNETS " in
            *" $subnet "*) return 0 ;;  # Already processed, skip silently
        esac
        
        VPN_IP6_SUBNETS="$VPN_IP6_SUBNETS $subnet"
        # Enable NAT66 for /64 to support roaming and routing of ISP client IPs
        VPN_IP6_NEEDS_NAT66=1
        echo "INFO: [plugin] Detected routable IPv6 /${prefix_len} subnet: $subnet (enabling NAT66 for roaming support)"
        return 0
    fi
    
    # Handle /65-/127 subnets
    if [ "$prefix_len" -lt 128 ]; then
        # For /65-/127, use the full address with prefix
        subnet="$ip6"
        VPN_IP6_SUBNETS="$VPN_IP6_SUBNETS $subnet"
        echo "INFO: [plugin] Detected routable IPv6 /${prefix_len} subnet: $subnet"
        return 0
    fi
    
    # /128 is handled by core script, not this plugin
    return 1
}
