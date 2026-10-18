//go:build windows

package main

import (
	"fmt"
	"net"

	"github.com/songgao/water"
)

// openTUN creates a TUN interface using the TAP-Windows driver. The driver must
// be installed (e.g. the OpenVPN TAP-windows6 adapter, component id tap0901).
// Windows requires the interface's network at creation time, so we pass the
// server-assigned CIDR here.
func openTUN(dev, cidr string) (tunDevice, error) {
	params := water.PlatformSpecificParams{
		ComponentID: "tap0901",
		Network:     cidr,
	}
	if dev != "" {
		params.InterfaceName = dev
	}
	return water.New(water.Config{
		DeviceType:             water.TUN,
		PlatformSpecificParams: params,
	})
}

func (r *routeManager) configureAddress(cidr string) error {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	mask := net.IP(ipnet.Mask).String()
	return run("netsh", "interface", "ipv4", "set", "address",
		fmt.Sprintf("name=%s", r.dev), "source=static",
		fmt.Sprintf("address=%s", ip.String()),
		fmt.Sprintf("mask=%s", mask))
}

func (r *routeManager) addRoute(cidr string) error {
	return run("netsh", "interface", "ipv4", "add", "route", cidr, r.dev)
}

func (r *routeManager) delRoute(cidr string) error {
	return run("netsh", "interface", "ipv4", "delete", "route", cidr, r.dev)
}
