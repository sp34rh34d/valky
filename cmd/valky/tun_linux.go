//go:build linux

package main

import "github.com/songgao/water"

func openTUN(dev, _ string) (tunDevice, error) {
	cfg := water.Config{DeviceType: water.TUN}
	if dev != "" {
		cfg.PlatformSpecificParams = water.PlatformSpecificParams{Name: dev}
	}
	return water.New(cfg)
}

func (r *routeManager) configureAddress(cidr string) error {
	if err := run("ip", "addr", "add", cidr, "dev", r.dev); err != nil {
		return err
	}
	return run("ip", "link", "set", "dev", r.dev, "up")
}

func (r *routeManager) addRoute(cidr string) error {
	return run("ip", "route", "replace", cidr, "dev", r.dev)
}

func (r *routeManager) delRoute(cidr string) error {
	return run("ip", "route", "del", cidr, "dev", r.dev)
}
