//go:build linux

package main

import "log"

// natEnable masquerades overlay-sourced traffic destined to dst (a network this
// agent delivers into its local LAN). Without it, a LAN host receives packets
// whose source is the originator's overlay address (e.g. 10.9.0.7) and has no
// route back, so its SYN-ACK is lost and the handshake never completes. With
// SNAT the host replies to this agent's own LAN address; conntrack reverses the
// NAT and the reply returns through the tunnel.
//
// It also enables IP forwarding and punches the matching FORWARD-chain accepts.
// Idempotent: the rule is deleted before being (re)added, so reconciles and
// reconnects never stack duplicates.
func natEnable(overlay, dst string) error {
	if err := run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		log.Printf("nat: enable ip_forward: %v", err)
	}
	natDisable(overlay, dst) // clear any stale copy first
	if err := run("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-s", overlay, "-d", dst, "-j", "MASQUERADE"); err != nil {
		return err
	}
	_ = run("iptables", "-A", "FORWARD", "-s", overlay, "-d", dst, "-j", "ACCEPT")
	_ = run("iptables", "-A", "FORWARD", "-s", dst, "-d", overlay, "-j", "ACCEPT")
	log.Printf("nat: masquerading %s -> %s", overlay, dst)
	return nil
}

// natDisable removes the rules installed by natEnable. Best-effort.
func natDisable(overlay, dst string) {
	_ = run("iptables", "-t", "nat", "-D", "POSTROUTING",
		"-s", overlay, "-d", dst, "-j", "MASQUERADE")
	_ = run("iptables", "-D", "FORWARD", "-s", overlay, "-d", dst, "-j", "ACCEPT")
	_ = run("iptables", "-D", "FORWARD", "-s", dst, "-d", overlay, "-j", "ACCEPT")
}
