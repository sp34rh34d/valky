//go:build !linux

package main

import "log"

// natEnable is a no-op outside Linux: egress NAT for forwarded overlay traffic is
// only wired through iptables. On macOS/Windows configure NAT out of band (pf /
// Routing and Remote Access) if this agent must serve a LAN.
func natEnable(overlay, dst string) error {
	log.Printf("nat: masquerade is only supported on Linux agents; ignoring %s -> %s", overlay, dst)
	return nil
}

// natDisable is the matching no-op.
func natDisable(overlay, dst string) {}
