//go:build darwin

package main

import (
	"net"

	"github.com/songgao/water"
)

func openTUN(_, _ string) (tunDevice, error) {
	// macOS assigns a utun<N> name automatically; a custom name is not allowed.
	return water.New(water.Config{DeviceType: water.TUN})
}

func (r *routeManager) configureAddress(cidr string) error {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	// utun is point-to-point; use the overlay address on both ends.
	return run("ifconfig", r.dev, "inet", ip.String(), ip.String(), "up")
}

func (r *routeManager) addRoute(cidr string) error {
	return run("route", "-n", "add", "-net", cidr, "-interface", r.dev)
}

func (r *routeManager) delRoute(cidr string) error {
	return run("route", "-n", "delete", "-net", cidr, "-interface", r.dev)
}
