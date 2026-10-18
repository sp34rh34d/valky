//go:build !linux && !darwin && !windows

// Fallback for other platforms (FreeBSD, OpenBSD, NetBSD, ...). The code
// compiles everywhere; whether a TUN device can actually be opened depends on
// the underlying library's support for the platform. Interface and route setup
// use the BSD-style ifconfig/route tools.
package main

import (
	"net"

	"github.com/songgao/water"
)

func openTUN(_, _ string) (tunDevice, error) {
	return water.New(water.Config{DeviceType: water.TUN})
}

func (r *routeManager) configureAddress(cidr string) error {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	return run("ifconfig", r.dev, "inet", ip.String(), ip.String(), "up")
}

func (r *routeManager) addRoute(cidr string) error {
	return run("route", "-n", "add", "-net", cidr, "-interface", r.dev)
}

func (r *routeManager) delRoute(cidr string) error {
	return run("route", "-n", "delete", "-net", cidr, "-interface", r.dev)
}
