#!/bin/ash

CONF_DIR="/path/to/conf"
WG_IPS_SCRIPT="/path/to/wg-pbr.sh"

# (
    # --- Helper Function ---
    # Defines a function to configure an interface
    # Usage: setup_interface <iface_name> <routing_table> <target_ips_list>
    setup_interface() {
        local iface="$1"
        local routing_table="$2"
        local target_ips="$3"
        
        echo "Setting up $iface..."
        $WG_IPS_SCRIPT "$iface" \
            -c "$CONF_DIR/$iface.conf" \
            -r "$routing_table" \
            -t "$target_ips"
    }

    # --- Interface Configuration ---
    # Add or remove lines here to manage interfaces
    # Arguments: interface_name, routing_table, "target_ips"
    
    # setup_interface "interface_name" "routing_table" "target_ips"

    # --- End of Interface Configuration ---

    # echo "Committing configuration..."
    $WG_IPS_SCRIPT commit

    # echo "Reapplying firewall rules..."
    $WG_IPS_SCRIPT reapply
# ) > /tmp/post-cfg.log 2>&1

exit 0
