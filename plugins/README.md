# WireGuard IPS Plugin System

## Overview

Plugins extend `wg-pbr.sh` by hooking into specific execution points. Each plugin is a shell script that defines functions matching hook names.

## Available Hooks

Hooks are called in the following order:

| # | Hook | When Called | Arguments |
| --- | ------ | ------------- | ----------- |
| 1 | `pre_commit` | Before committing staged configs | (none) |
| 2 | `pre_setup` | Before interface setup | `$1`: INTERFACE_NAME, `$2`: WG_REGISTRY |
| 3 | `process_ipv6_prefix` | For non-/128 IPv6 prefixes | `$1`: ip6, `$2`: prefix_len, `$3`: addr_part |
| 4 | `post_setup` | After interface setup | `$1`: INTERFACE_NAME |
| 5 | `post_commit` | After all interfaces are up | (none) |

## Creating a Plugin

1. Create a `.sh` file in this `plugins/` directory
2. Define one or more hook functions
3. Functions are called automatically when the hook point is reached

### Example Plugin

```shell
#!/bin/sh
# plugins/my_plugin.sh

pre_setup() {
    local INTERFACE_NAME="$1"
    local WG_REGISTRY="$2"
    echo "[my_plugin] Pre-setup for $INTERFACE_NAME"
    # Your logic here
}

post_setup() {
    local INTERFACE_NAME="$1"
    echo "[my_plugin] Post-setup for $INTERFACE_NAME"
    # Your logic here
}
```

## Plugin Guidelines

- **Naming**: Use descriptive names. Prefix with numbers for execution order: `00-first.sh`, `10-second.sh`
- **Return values**: Return 0 on success, non-zero on failure (warning is logged)
- **Logging**: Use `echo` for user-facing output, `logger -t wireguard` for system logs
- **Idempotent**: Plugins may be called multiple times; design accordingly
- **No side effects**: Don't modify global variables or call `exit`
