#!/bin/ash

CONF_DIR="/path/to/conf"
WG_SCRIPT="/path/to/wg-pbr.sh"

# --- WireGuard Interface Configuration ---
# Usage: $WG_SCRIPT <interface_name> -c <config_file> [-r <routing_table>] -t '<target_ips>'
# Note: -r is optional; if omitted, a routing table will be auto-allocated

# $WG_SCRIPT wgexample -c "$CONF_DIR/wgexample.conf" -t '10.0.0.0/24'
# $WG_SCRIPT wgexample2 -c "$CONF_DIR/wgexample2.conf" -r 100 -t '10.0.1.0/24,10.0.1.5'

# --- End of WireGuard Configuration ---

$WG_SCRIPT commit

exit 0
