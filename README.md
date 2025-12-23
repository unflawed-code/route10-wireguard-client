# Route10 WireGuard Client with Policy-Based Routing

This project provides a robust, script-based solution for managing WireGuard interfaces on Route10 (OpenWrt based) routers, with a focus on Policy-Based Routing (PBR). It allows you to selectively route specific clients or subnets through different WireGuard tunnels while maintaining direct internet access for others.

Tested on Route10 firmware version `1.4o`.

## Key Features

| Feature | Description |
| --------- | ------------- |
| IPv4/IPv6 Policy-Based Routing (PBR) | Route specific LAN clients (by IP) or subnets through specific WireGuard interfaces. |
| Internet Kill Switch (IPv4/IPv6) :shield: | Ensures that traffic designated for the VPN is blocked if the tunnel is down. |
| IPv6 Leak Prevention :droplet: | Prevents IPv6 traffic from bypassing the VPN tunnel via the default WAN gateway. |
| IPv4/IPv6 DNS Leak Protection :droplet: | Redirects DNS queries through the VPN to prevent leaks to ISP or public DNS servers. |
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

1. **Clone/Copy Files**: Place the scripts in a persistent directory on your Route10 (`/cfg/` or any directories in it).
2. **Make Executable**:

    ```sh
    chmod 700 wg-pbr.sh post-cfg.sh
    ```

3. **Run the Script**:

    ```sh
    Usage: ./wg-pbr.sh <interface_name> -c <config_file> -r <positive_number> -t <IPs_comma_separated>
      Arguments for configuration:
        <interface_name>:   WireGuard interface name (max 11 chars)
        -c, --conf <file>:      Relative or absolute path to the wg conf file
        -r, --routing-table <N>: Positive number for the routing table
        -t, --target-ips <IPs>:  Comma-separated list of IPv4 addresses or subnets

    Commands:
      ./wg-pbr.sh commit               Apply all staged WireGuard interface configurations.
      ./wg-pbr.sh reapply              (Optional) Re-apply firewall rules for all registered interfaces.
    ```

    ```sh
    # Stage one or more configurations
    ./wg-pbr.sh wg0 -c /etc/wireguard/wg0.conf -r 100 -t 192.168.1.55
    ./wg-pbr.sh wg1 -c /etc/wireguard/wgx.conf -r 110 -t 10.10.10.0/24
    ./wg-pbr.sh wg2 -c /etc/wireguard/wgy.conf -r 120 -t 10.20.20.0/24, 10.50.50.50

    # Apply all staged configurations
    ./wg-pbr.sh commit
    ```

4. **Configure After Boot (Optional)**:
    - Copy `post-cfg-template.sh` to `post-cfg.sh` (if not already done).
    - Edit `post-cfg.sh` to correct the paths:

        ```ash
        CONF_DIR="/path/to/your/wg/conf/files"
        WG_IPS_SCRIPT="/path/to/wg-pbr.sh"
        ```

    - Define your interfaces in `post-cfg.sh` using the `setup_interface` function.

## IPv6 Handling

This project natively supports `/128` IPv6 prefixes (single address) using **NAT66** (Network Address Translation for IPv6). NAT66 allows multiple LAN clients to share the VPN's single IPv6 address, similar to how NAT44 works for IPv4.

> [!NOTE]
> Support for other prefix sizes (e.g., `/64`) requires creating a plugin. The script will still use NAT66 once the Wireguard interface receives an IPv6 address. See `plugins/README.md` for details.

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
