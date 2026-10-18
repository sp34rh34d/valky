// Package netutil contains small helpers for inspecting raw IP packets and for
// discovering the local network segments a client should advertise.
package netutil

import (
	"errors"
	"net"
)

var errShort = errors.New("netutil: packet too short")

// IPVersion returns the IP version (4 or 6) of a raw packet, or 0 if unknown.
func IPVersion(pkt []byte) int {
	if len(pkt) < 1 {
		return 0
	}
	return int(pkt[0] >> 4)
}

// SrcDstV4 extracts the source and destination addresses from a raw IPv4
// packet. It returns an error for non-IPv4 or truncated input.
func SrcDstV4(pkt []byte) (src, dst net.IP, err error) {
	if len(pkt) < 20 {
		return nil, nil, errShort
	}
	if pkt[0]>>4 != 4 {
		return nil, nil, errors.New("netutil: not an IPv4 packet")
	}
	src = net.IP(append([]byte(nil), pkt[12:16]...))
	dst = net.IP(append([]byte(nil), pkt[16:20]...))
	return src, dst, nil
}

// AffinityHash returns a stable hash of the (source, destination) IPv4 address
// pair, independent of protocol and ports. It pins all traffic from a given
// client to a given destination onto a single delivering agent (session
// affinity), so a browser's many connections — and the NAT source address they
// are given — stay consistent and stateful sessions (e.g. web logins) are not
// reset by load-balancing. Returns a stable value for nil/short IPs too.
func AffinityHash(src, dst net.IP) uint32 {
	var h uint32 = 2166136261 // FNV-1a
	mix := func(b byte) { h ^= uint32(b); h *= 16777619 }
	if s4 := src.To4(); s4 != nil {
		for _, b := range s4 {
			mix(b)
		}
	}
	if d4 := dst.To4(); d4 != nil {
		for _, b := range d4 {
			mix(b)
		}
	}
	return h
}

// LocalSegments returns the IPv4 network segments the host is attached to,
// excluding loopback and link-local ranges. These are advertised to the server
// so the operator can route traffic to them.
func LocalSegments() ([]*net.IPNet, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []*net.IPNet
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipn.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
				continue
			}
			// Normalize to the network address of the segment.
			seg := &net.IPNet{IP: ip4.Mask(ipn.Mask), Mask: ipn.Mask}
			key := seg.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, seg)
		}
	}
	return out, nil
}
