#!/bin/sh
# Verify hotplug storm guard wiring in legacy WireGuard scripts.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/../test.conf"

HOTPLUG_SCRIPT="$SCRIPT_ROOT/wg-pbr.sh"
MASTER_DHCP="$SCRIPT_ROOT/lib/wg-master-dhcp.sh"
SPLIT_TEMPLATE="$SCRIPT_ROOT/lib/wg-split-tunnel-hotplug.template"

assert_contains() {
    local file="$1"
    local pattern="$2"
    local desc="$3"
    if grep -Fq "$pattern" "$file" 2>/dev/null; then
        log_pass "$desc"
    else
        log_fail "$desc"
        echo "  missing pattern: $pattern"
        echo "  file: $file"
    fi
}

echo "=== Hotplug Storm Guard Tests ==="

assert_contains "$HOTPLUG_SCRIPT" 'GUARD_STATE="${WG_TMP_DIR}/iface_${WG_INTERFACE}.guard"' "routing hotplug guard state is present"
assert_contains "$HOTPLUG_SCRIPT" 'Hotplug storm guard active; skipping $ACTION' "routing hotplug active-suppress log is present"
assert_contains "$HOTPLUG_SCRIPT" 'Hotplug storm detected (count=$COUNT window=${WINDOW}s); cooling down ${COOLDOWN}s' "routing hotplug cooldown log is present"

assert_contains "$MASTER_DHCP" 'GUARD_STATE="${WG_TMP_DIR}/dhcp_hotplug.guard"' "master DHCP guard state is present"
assert_contains "$MASTER_DHCP" 'Storm guard active; dropping DHCP event $EVENT_KEY' "master DHCP active-suppress log is present"
assert_contains "$MASTER_DHCP" 'Storm guard tripped (count=$COUNT window=${WINDOW}s); cooling down ${COOLDOWN}s' "master DHCP cooldown log is present"

assert_contains "$SPLIT_TEMPLATE" 'GUARD_STATE="${WG_TMP_DIR}/split_${WG_IFACE}.guard"' "split hotplug guard state is present"
assert_contains "$SPLIT_TEMPLATE" 'Hotplug storm guard active; skipping $ACTION' "split hotplug active-suppress log is present"
assert_contains "$SPLIT_TEMPLATE" 'Hotplug storm detected (count=$COUNT window=${WINDOW}s); cooling down ${COOLDOWN}s' "split hotplug cooldown log is present"

echo ""
test_summary
exit $?
