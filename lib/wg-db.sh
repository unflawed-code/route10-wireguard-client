#!/bin/sh
# wg-db.sh - SQLite database helper functions for WireGuard PBR
# This provides atomic operations for staging and registry data

WG_DB_PATH="${WG_TMP_DIR:-/tmp/wg-custom}/wg_pbr.db"

# Initialize database and create tables
db_init() {
    local db="$WG_DB_PATH"
    mkdir -p "$(dirname "$db")"
    
    sqlite3 "$db" <<EOF
CREATE TABLE IF NOT EXISTS interfaces (
    name TEXT PRIMARY KEY,
    conf TEXT,
    routing_table INTEGER,
    target_ips TEXT,
    domains TEXT,
    committed INTEGER DEFAULT 0,
    target_only INTEGER DEFAULT 0,
    ipv6_support INTEGER DEFAULT 0,
    ipv6_subnets TEXT,
    nat66 INTEGER DEFAULT 0,
    start_time INTEGER,
    running INTEGER DEFAULT 0
);

-- Add missing columns if needed (migration for existing DBs)
ALTER TABLE interfaces ADD COLUMN domains TEXT;
ALTER TABLE interfaces ADD COLUMN target_only INTEGER DEFAULT 0;

CREATE TABLE IF NOT EXISTS mac_state (
    mac TEXT,
    interface TEXT,
    ip TEXT,
    routing_table INTEGER,
    ipv6_support INTEGER,
    PRIMARY KEY (mac, interface, ip)
);
EOF
    # Suppress ALTER TABLE error if column already exists
    true
}


# Stage an interface configuration
# Usage: db_stage_interface <name> <conf> <routing_table> <target_ips>
db_stage_interface() {
    local name="$1"
    local conf="$2"
    local rt="$3"
    local targets="$4"
    
    sqlite3 "$WG_DB_PATH" <<EOF
INSERT OR REPLACE INTO interfaces (name, conf, routing_table, target_ips, committed)
VALUES ('$name', '$conf', $rt, '$targets', 0);
EOF
}

# Commit a staged interface (mark as committed)
# Usage: db_commit_interface <name>
db_commit_interface() {
    local name="$1"
    sqlite3 "$WG_DB_PATH" "UPDATE interfaces SET committed = 1 WHERE name = '$name';"
}

# Mark interface as running with start time
# Usage: db_set_running <name> <running> [start_time]
db_set_running() {
    local name="$1"
    local running="$2"
    local start_time="${3:-$(date +%s)}"
    
    if [ "$running" = "1" ]; then
        sqlite3 "$WG_DB_PATH" "UPDATE interfaces SET running = 1, start_time = $start_time WHERE name = '$name';"
    else
        sqlite3 "$WG_DB_PATH" "UPDATE interfaces SET running = 0 WHERE name = '$name';"
    fi
}

# Update IPv6 settings for an interface
# Usage: db_set_ipv6 <name> <ipv6_support> <ipv6_subnets> <nat66>
db_set_ipv6() {
    local name="$1"
    local ipv6="$2"
    local subnets="$3"
    local nat66="$4"
    
    sqlite3 "$WG_DB_PATH" "UPDATE interfaces SET ipv6_support = $ipv6, ipv6_subnets = '$subnets', nat66 = $nat66 WHERE name = '$name';"
}

# Update target IPs for an interface
# Usage: db_update_targets <name> <target_ips>
db_update_targets() {
    local name="$1"
    local targets="$2"
    
    sqlite3 "$WG_DB_PATH" "UPDATE interfaces SET target_ips = '$targets' WHERE name = '$name';"
}

# Get interface data as pipe-delimited string
# Usage: db_get_interface <name>
# Returns: name|conf|routing_table|target_ips|domains|committed|target_only|ipv6_support|ipv6_subnets|nat66|start_time|running
db_get_interface() {
    local name="$1"
    sqlite3 -separator '|' "$WG_DB_PATH" "SELECT * FROM interfaces WHERE name = '$name';"
}

# Check if interface exists in database
# Usage: db_interface_exists <name>
db_interface_exists() {
    local name="$1"
    local count=$(sqlite3 "$WG_DB_PATH" "SELECT COUNT(*) FROM interfaces WHERE name = '$name';")
    [ "$count" -gt 0 ]
}

# Check if interface is committed
# Usage: db_is_committed <name>
db_is_committed() {
    local name="$1"
    local committed=$(sqlite3 "$WG_DB_PATH" "SELECT committed FROM interfaces WHERE name = '$name';")
    [ "$committed" = "1" ]
}

# Check if interface is running
# Usage: db_is_running <name>
db_is_running() {
    local name="$1"
    local running=$(sqlite3 "$WG_DB_PATH" "SELECT running FROM interfaces WHERE name = '$name';")
    [ "$running" = "1" ]
}

# Get a specific field from interface
# Usage: db_get_field <name> <field>
db_get_field() {
    local name="$1"
    local field="$2"
    sqlite3 "$WG_DB_PATH" "SELECT $field FROM interfaces WHERE name = '$name';"
}

# List all interfaces (running first, then staged)
# Usage: db_list_interfaces
db_list_interfaces() {
    sqlite3 "$WG_DB_PATH" "SELECT name FROM interfaces ORDER BY running DESC, name ASC;"
}

# List running interfaces only
# Usage: db_list_running
db_list_running() {
    sqlite3 "$WG_DB_PATH" "SELECT name FROM interfaces WHERE running = 1;"
}

# Delete an interface from database
# Usage: db_delete_interface <name>
db_delete_interface() {
    local name="$1"
    sqlite3 "$WG_DB_PATH" "DELETE FROM interfaces WHERE name = '$name';"
}

# Find interface that has a specific IP in target_ips
# Usage: db_find_interface_by_ip <ip>
db_find_interface_by_ip() {
    local ip="$1"
    # Search for exact match or as part of comma-separated list
    sqlite3 "$WG_DB_PATH" "SELECT name FROM interfaces WHERE target_ips = '$ip' OR target_ips LIKE '$ip,%' OR target_ips LIKE '%,$ip' OR target_ips LIKE '%,$ip,%';"
}

# Get interface data in registry format (for backward compatibility)
# Returns: iface|routing_table|target_ips|ipv6_support|ipv6_subnets|nat66|start_time
# Usage: db_get_registry_entry <name>
db_get_registry_entry() {
    local name="$1"
    sqlite3 -separator '|' "$WG_DB_PATH" "SELECT name, routing_table, target_ips, COALESCE(ipv6_support,0), COALESCE(ipv6_subnets,''), COALESCE(nat66,0), COALESCE(start_time,0) FROM interfaces WHERE name = '$name';"
}

# List all interfaces in registry format
# Returns one line per interface: iface|routing_table|target_ips|ipv6_support|ipv6_subnets|nat66|start_time
# Usage: db_list_registry_entries
db_list_registry_entries() {
    sqlite3 -separator '|' "$WG_DB_PATH" "SELECT name, routing_table, target_ips, COALESCE(ipv6_support,0), COALESCE(ipv6_subnets,''), COALESCE(nat66,0), COALESCE(start_time,0) FROM interfaces WHERE committed = 1;"
}

# Update interface with full registry data (replaces flat file write)
# Usage: db_update_registry <name> <rt> <targets> <ipv6> <ipv6_subnets> <nat66> <start_time>
db_update_registry() {
    local name="$1"
    local rt="$2"
    local targets="$3"
    local ipv6="${4:-0}"
    local ipv6_subnets="${5:-}"
    local nat66="${6:-0}"
    local start_time="${7:-$(date +%s)}"
    
    sqlite3 "$WG_DB_PATH" <<EOF
UPDATE interfaces SET 
    routing_table = $rt,
    target_ips = '$targets',
    ipv6_support = $ipv6,
    ipv6_subnets = '$ipv6_subnets',
    nat66 = $nat66,
    start_time = $start_time,
    committed = 1,
    running = 1
WHERE name = '$name';
EOF
}

# === MAC State Functions ===

# Set MAC state entry
# Usage: db_set_mac_state <mac> <interface> <ip> <routing_table> <ipv6_support>
db_set_mac_state() {
    local mac="$1"
    local iface="$2"
    local ip="$3"
    local rt="$4"
    local ipv6="$5"
    
    sqlite3 "$WG_DB_PATH" <<EOF
INSERT OR REPLACE INTO mac_state (mac, interface, ip, routing_table, ipv6_support)
VALUES ('$mac', '$iface', '$ip', $rt, $ipv6);
EOF
}

# Get MAC state entry
# Usage: db_get_mac_state <interface> <ip>
db_get_mac_state() {
    local iface="$1"
    local ip="$2"
    sqlite3 -separator '|' "$WG_DB_PATH" "SELECT * FROM mac_state WHERE interface = '$iface' AND ip = '$ip';"
}

# Delete MAC state entry
# Usage: db_delete_mac_state <interface> <ip>
db_delete_mac_state() {
    local iface="$1"
    local ip="$2"
    sqlite3 "$WG_DB_PATH" "DELETE FROM mac_state WHERE interface = '$iface' AND ip = '$ip';"
}

# Delete all MAC state entries for an interface
# Usage: db_delete_mac_state_for_interface <interface>
db_delete_mac_state_for_interface() {
    local iface="$1"
    sqlite3 "$WG_DB_PATH" "DELETE FROM mac_state WHERE interface = '$iface';"
}

# List all MAC state entries for an interface
# Usage: db_list_mac_state <interface>
db_list_mac_state() {
    local iface="$1"
    sqlite3 -separator '|' "$WG_DB_PATH" "SELECT * FROM mac_state WHERE interface = '$iface';"
}

# Get MAC state entry by MAC address (for roaming detection)
# Usage: db_get_mac_by_mac <mac>
# Returns: mac|interface|ip|routing_table|ipv6_support
db_get_mac_by_mac() {
    local mac="$1"
    sqlite3 -separator '|' "$WG_DB_PATH" "SELECT * FROM mac_state WHERE mac = '$mac';"
}

# Get all MACs for an interface (for cleanup)
# Usage: db_get_macs_for_interface <interface>
db_get_macs_for_interface() {
    local iface="$1"
    sqlite3 "$WG_DB_PATH" "SELECT mac FROM mac_state WHERE interface = '$iface';"
}

# Delete MAC state entry by MAC address
# Usage: db_delete_mac_by_mac <mac>
db_delete_mac_by_mac() {
    local mac="$1"
    sqlite3 "$WG_DB_PATH" "DELETE FROM mac_state WHERE mac = '$mac';"
}

# Get MAC state by interface and IP (for cleanup_mac_for_ip)
# Usage: db_get_mac_for_ip <interface> <ip>
db_get_mac_for_ip() {
    local iface="$1"
    local ip="$2"
    sqlite3 -separator '|' "$WG_DB_PATH" "SELECT * FROM mac_state WHERE interface = '$iface' AND ip = '$ip';"
}

# Delete MAC state by interface and MAC
# Usage: db_delete_mac_by_iface_mac <interface> <mac>
db_delete_mac_by_iface_mac() {
    local iface="$1"
    local mac="$2"
    sqlite3 "$WG_DB_PATH" "DELETE FROM mac_state WHERE interface = '$iface' AND mac = '$mac';"
}

# === STAGING FUNCTIONS ===

# Stage an interface with full details (upsert)
# Usage: db_set_staged <name> <conf> <rt> <targets> <committed> <target_only>
db_set_staged() {
    local name="$1"
    local conf="$2"
    local rt="$3"
    local targets="$4"
    local committed="${5:-0}"
    local target_only="${6:-0}"
    
    sqlite3 "$WG_DB_PATH" <<EOF
INSERT OR REPLACE INTO interfaces (name, conf, routing_table, target_ips, committed, target_only)
VALUES ('$name', '$conf', $rt, '$targets', $committed, $target_only);
EOF
}

# Get staged interface info
# Usage: db_get_staged <name>
# Returns: name|conf|routing_table|target_ips|committed|target_only
db_get_staged() {
    local name="$1"
    sqlite3 -separator '|' "$WG_DB_PATH" "SELECT name, conf, routing_table, target_ips, committed, target_only FROM interfaces WHERE name = '$name';"
}

# List all staged/committed interfaces
# Usage: db_list_staged
# Returns one line per interface: name|conf|routing_table|target_ips|committed|target_only
db_list_staged() {
    sqlite3 -separator '|' "$WG_DB_PATH" "SELECT name, conf, routing_table, target_ips, committed, target_only FROM interfaces ORDER BY name;"
}

# Set target_only flag for hot-reload
# Usage: db_set_target_only <name> <target_only>
db_set_target_only() {
    local name="$1"
    local target_only="$2"
    sqlite3 "$WG_DB_PATH" "UPDATE interfaces SET target_only = $target_only WHERE name = '$name';"
}

# Update targets and set target_only flag (for assign-ips/remove-ips)
# Usage: db_update_staged_targets <name> <targets> <target_only>
db_update_staged_targets() {
    local name="$1"
    local targets="$2"
    local target_only="${3:-0}"
    sqlite3 "$WG_DB_PATH" "UPDATE interfaces SET target_ips = '$targets', target_only = $target_only WHERE name = '$name';"
}

# Get all used routing tables (for allocation)
# Usage: db_get_all_routing_tables
db_get_all_routing_tables() {
    sqlite3 "$WG_DB_PATH" "SELECT routing_table FROM interfaces WHERE routing_table IS NOT NULL;"
}

# Reconstruct command string from staged entry
# Usage: db_reconstruct_command <name> <script_path>
db_reconstruct_command() {
    local name="$1"
    local script_path="${2:-./wg-pbr.sh}"
    local entry=$(db_get_staged "$name")
    [ -z "$entry" ] && return 1
    
    local conf=$(echo "$entry" | cut -d'|' -f2)
    local rt=$(echo "$entry" | cut -d'|' -f3)
    local targets=$(echo "$entry" | cut -d'|' -f4)
    
    echo "$script_path $name --conf $conf --routing-table $rt --target-ips $targets"
}
