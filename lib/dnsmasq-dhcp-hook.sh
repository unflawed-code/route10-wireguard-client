#!/bin/sh
# Custom DHCP hook to trigger /etc/hotplug.d/dhcp/ scripts
# Required because OpenWrt procd ubus hotplug doesn't run the directory scripts
ACTION="$1"
MACADDR="$2"
IPADDR="$3"
HOSTNAME="$4"
export ACTION MACADDR IPADDR HOSTNAME
/sbin/hotplug-call dhcp
