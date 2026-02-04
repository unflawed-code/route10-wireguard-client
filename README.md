# Route10 WireGuard Client with Policy-Based Routing

This project provides a robust, script-based solution for managing WireGuard interfaces on Route10 (OpenWrt based) routers, with a focus on Policy-Based Routing (PBR). It allows you to selectively route specific clients or subnets through different WireGuard tunnels while maintaining direct internet access for others.

Tested on Route10 firmware version `1.4r`.

## Key Features

| Feature | Description |
| --------- | ------------- |
| IPv4/IPv6/MAC Policy-Based Routing (PBR) | Route specific LAN clients (by IP/MAC) with automatic roaming support through specific WireGuard interfaces. |
| Internet Kill Switch (IPv4/IPv6) :shield: | Ensures that traffic designated for the VPN is blocked if the tunnel is down. |
| IPv6 Leak Prevention :droplet: | Prevents IPv6 traffic from bypassing the VPN tunnel via the default WAN gateway. |
| IPv4/IPv6 DNS Leak Protection :droplet: | Redirects DNS queries through the VPN to prevent leaks to ISP or public DNS servers. |
| Split Tunneling (Domain-based) | Route specific domains through VPN, clients already routed to another VPN are unaffected. |
| Plugin Architecture | Extensible via hook scripts in `plugins/`. |

## Core Scripts

- **`wg-pbr.sh`**: The main engine. It handles:
  - Parsing WireGuard config files.
  - Setting up OpenWrt UCI network and firewall configurations.
  - Generating hotplug scripts for routing and DNS hijacking.
  - Helper commands like `commit` and `reapply`.
- **`post-cfg-template.sh`**: Template for the user-defined configuration script.
- **`post-cfg.sh`**: The local configuration script (renamed from template, not committed). This script is executed after boot to define which interfaces to bring up and which clients route through them.
- **`plugins/`**: Directory for extension scripts.

## Installation & Setup

1. **Clone/Copy & Configure**:
    - Create a folder for the scripts (e.g., `/cfg/wg-pbr/`) and copy all files there.
    - Copy `post-cfg-template.sh` to `/cfg/post-cfg.sh` to ensure it runs on boot.
    - Edit `/cfg/post-cfg.sh` to correct the paths:

        ```sh
        CONF_DIR="/cfg/wg-pbr/conf"
        WG_SCRIPT="/cfg/wg-pbr/wg-pbr.sh"
        ```

    - Define your interfaces in `/cfg/post-cfg.sh` by uncommenting and adapting the example lines:

        ```sh
        $WG_SCRIPT wg0 -c "$CONF_DIR/wg0.conf" -t '192.168.1.55'
        $WG_SCRIPT wg1 -c "$CONF_DIR/wg1.conf" -r 100 -t '10.10.10.0/24'
        ```

2. **Make Executable**:

    ```sh
    cd /cfg/wg-pbr/
    chmod 700 wg-pbr.sh /cfg/post-cfg.sh lib/* plugins/*
    ```

3. **Run the Script**:

    ```sh
    Usage: ./wg-pbr.sh <interface_name> -c <config_file> [ -t <IPs> [-r <routing_table>] | -d <domains> ]
    Usage: ./wg-pbr.sh delete <interface_name>
      Arguments for configuration:
        <interface_name>:   WireGuard interface name (max 11 chars)
        -c, --conf <file>:      Relative or absolute path to the wg conf file
        -t, --target-ips <IPs>:  (Optional) Comma-separated list of IPv4 addresses/subnets/MACs
        -d, --domains <domains>: (Optional) Comma-separated list of domains for split-tunnel (incompatible with -t/-r)
        -r, --routing-table <N>: (Optional) Routing table number, auto-allocated 100-199 if not provided

    Commands:
      ./wg-pbr.sh commit               Apply all staged WireGuard interface configurations.
      ./wg-pbr.sh reapply              Re-apply firewall rules for all registered interfaces.
      ./wg-pbr.sh delete <iface>       Stop and permanently remove a managed interface and all associated rules. Wireguard interfaces not created by wg-pbr.sh will not be deleted.

    Target Management (requires 05-manage-commands.sh plugin):
      ./wg-pbr.sh status [iface]             Show detailed status of all or specific interface.
      ./wg-pbr.sh assign-ips <iface> <IPs>   Add IPs/subnets/MACs to an interface (accumulates until commit).
      ./wg-pbr.sh remove-ips <iface> <IPs>   Remove IPs/subnets/MACs from an interface (accumulates until commit).
    ```

    ```sh
    # Stage one or more configurations (routing table auto-allocated if -r not specified)
    ./wg-pbr.sh wg0 -c /cfg/wg-pbr/conf/wg0.conf -t 192.168.1.55
    ./wg-pbr.sh wg1 -c /cfg/wg-pbr/conf/wgx.conf -t 10.10.10.0/24
    ./wg-pbr.sh wg2 -c /cfg/wg-pbr/conf/wgy.conf -r 120 -t 10.20.20.0/24,10.50.50.50

    # Apply all staged configurations
    ./wg-pbr.sh commit

    # Hot-reload: Move a client between interfaces without restarting tunnels
    ./wg-pbr.sh assign-ips wg1 192.168.1.55   # Automatically removes from wg0
    ./wg-pbr.sh commit                        # Updates routing instantly, no tunnel restart
    ```

## Domain-Based Split Tunneling

Instead of routing specific clients *through* the VPN, you can route specific *domains* through the VPN for all clients, while keeping the rest of the traffic on the default gateway. Clients already routed to another VPN are not affected.

### Usage

```sh
./wg-pbr.sh wg0 -c /cfg/wg-pbr/conf/wgx.conf -d "whatismyipaddress.com,ipleak.net"
```

### How It Works

1. **dnsmasq & ipset**: The script configures `dnsmasq` to intercept DNS queries for the specified domains.
2. **Dynamic Routing**: When a domain is resolved, the resulting IP addresses are added to an `ipset`.
3. **Policy Routing**: Traffic to these IPs is marked and routed through the WireGuard tunnel.
4. **Auto-Restart**: `dnsmasq` is automatically restarted during `commit` to ensure ipsets are populated correctly.

### Important Notes

- **Exclusive Mode**: Split-tunneling (`-d`) cannot be combined with IP-based routing (`-t`) or custom table assignment (`-r`). The interface is dedicated to routing these domains.
- **IPv6 Behavior**:
  - **If VPN supports IPv6**: Both IPv4 and IPv6 traffic to the domains are routed through the tunnel.
  - **If VPN is IPv4-only**: IPv4 traffic is routed, but IPv6 traffic to the domains is **blocked** (DROP) to prevent leaks.

## IPv6 Handling

This project natively supports `/128` IPv6 prefixes (single address) using **NAT66** (Network Address Translation for IPv6). NAT66 allows multiple LAN clients to share the VPN's single IPv6 address, similar to how NAT44 works for IPv4.

> [!NOTE]
> Larger prefix sizes (e.g., `/64`) are supported via the included `03-ipv6-prefix-routing.sh` plugin. See `plugins/README.md` for details.

### Why /128?

Most commercial VPN providers assign a single IPv6 address (`/128`) per connection. Even when providers include larger prefixes like `/64` in the WireGuard config's `AllowedIPs`, they typically do **not** route those prefixes to your tunnel — the larger prefix simply tells WireGuard to send matching traffic through the tunnel, but the VPN server won't forward it.

### Truly Routable IPv6 (Without NAT66)

If you want each LAN client to have its own globally routable IPv6 address, simply setting up a WireGuard client is **not sufficient**. You would need:

1. **A delegated prefix** — The VPN provider must explicitly route a `/64` (or larger) prefix to your tunnel, not just list it in `AllowedIPs`.
2. **Router Advertisement (RA) / DHCPv6** — Your router must advertise the delegated prefix to LAN clients so they can auto-configure addresses.
3. **No NAT66** — Since the addresses are globally routable, NAT is unnecessary and should be disabled.

Most commercial VPNs do not offer delegated prefixes. This is typically available only with self-hosted VPN servers or specialized providers.

## Plugin System

The `plugins/` directory allows extending functionality. See `plugins/README.md` for details on creating plugins.
