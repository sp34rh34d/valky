package main

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"valky/internal/protocol"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// netstackEgress is the proxy-mode L3 egress: a userspace TCP/IP stack (gVisor)
// that lets an agent without a TUN device still deliver raw IP packets.
//
// Packets routed to this agent as protocol.TypeData (e.g. from a tunnel-mode
// agent's TUN) are injected into the stack via inject(). TCP/UDP forwarders turn
// each new flow into a real OS socket dialed to the original destination, so the
// pivot's kernel performs the SNAT to the LAN naturally — no TUN and no root
// required, which is the whole point of proxy mode. Reply segments the stack
// synthesises carry the overlay source as destination; the pump() loop ships
// them back as TypeData, and the server routes them to the originating agent,
// which writes them to its TUN. The operator's tool therefore talks straight to
// the LAN service with no proxychains in the path.
//
// ICMP is intentionally not forwarded: emitting echo requests on the LAN would
// need a raw socket (root), which proxy mode deliberately avoids.
type netstackEgress struct {
	stack *stack.Stack
	ep    *channel.Endpoint
	cw    *connWriter
	ctx   context.Context
	stop  context.CancelFunc

	wg sync.WaitGroup
}

// nicID is the single NIC the stack owns; the ID is arbitrary but must be stable.
const netstackNICID tcpip.NICID = 1

// netstackMTU clamps the MTU of the virtual NIC. It bounds the TCP MSS the stack
// negotiates and the size of the segments it emits, so replies stay within the
// MTU of the TUN they are ultimately written to on the consuming agent. 1400
// leaves headroom under the usual 1500 without needing path-MTU discovery.
const netstackMTU = 1400

// newNetstackEgress builds the userspace stack and starts the outbound pump.
// Outbound packets are written through cw (the same connection writer the TUN
// pump uses), so they are dropped while the link is down and resume on reconnect.
func newNetstackEgress(cw *connWriter) (*netstackEgress, error) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
	})

	ep := channel.New(512, netstackMTU, "")
	if err := s.CreateNIC(netstackNICID, ep); err != nil {
		return nil, errFromTCPIP("create nic", err)
	}
	// Promiscuous + spoofing: accept packets for any destination (we are routing
	// for a whole published subnet, not a single assigned address) and let the
	// stack originate replies from those addresses.
	if err := s.SetPromiscuousMode(netstackNICID, true); err != nil {
		return nil, errFromTCPIP("promiscuous", err)
	}
	if err := s.SetSpoofing(netstackNICID, true); err != nil {
		return nil, errFromTCPIP("spoofing", err)
	}
	// A default route for both families sends everything to our NIC.
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: netstackNICID},
		{Destination: header.IPv6EmptySubnet, NIC: netstackNICID},
	})

	ctx, cancel := context.WithCancel(context.Background())
	n := &netstackEgress{stack: s, ep: ep, cw: cw, ctx: ctx, stop: cancel}

	// TCP: dial the real target for every connection and splice it.
	tcpFwd := tcp.NewForwarder(s, 0, 2048, n.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	// UDP: userspace dial per flow (no root needed).
	udpFwd := udp.NewForwarder(s, n.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	n.wg.Add(1)
	go n.pump()
	return n, nil
}

// inject feeds one raw IP packet (as received in a TypeData frame) into the
// stack. Non-IP or truncated packets are ignored.
func (n *netstackEgress) inject(pkt []byte) {
	if len(pkt) == 0 {
		return
	}
	var proto tcpip.NetworkProtocolNumber
	switch pkt[0] >> 4 {
	case 4:
		proto = ipv4.ProtocolNumber
	case 6:
		proto = ipv6.ProtocolNumber
	default:
		return
	}
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(pkt),
	})
	n.ep.InjectInbound(proto, pb)
	pb.DecRef()
}

// pump drains packets the stack emits and forwards them to the server, which
// routes them back to the overlay source. It exits when the stack is closed.
func (n *netstackEgress) pump() {
	defer n.wg.Done()
	for {
		pkt := n.ep.ReadContext(n.ctx)
		if pkt == nil {
			return // context cancelled: shutting down
		}
		buf := pkt.ToBuffer()
		data := buf.Flatten()
		pkt.DecRef()
		_ = n.cw.write(protocol.TypeData, data)
	}
}

// handleTCP accepts a forwarded TCP connection, dials the real destination, and
// splices the two. On any failure before the splice it resets the overlay side.
func (n *netstackEgress) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))

	outbound, err := net.DialTimeout("tcp", dst, 10*time.Second)
	if err != nil {
		r.Complete(true) // send RST to the client
		return
	}

	var wq waiter.Queue
	wep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		outbound.Close()
		r.Complete(true)
		return
	}
	r.Complete(false)

	inbound := gonet.NewTCPConn(&wq, wep)
	go splice(inbound, outbound)
}

// handleUDP accepts a forwarded UDP flow, dials the real destination, and relays
// datagrams in both directions until the flow is idle or closed.
func (n *netstackEgress) handleUDP(r *udp.ForwarderRequest) bool {
	id := r.ID()
	dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))

	outbound, err := net.Dial("udp", dst)
	if err != nil {
		return true
	}

	var wq waiter.Queue
	wep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		outbound.Close()
		return true
	}

	inbound := gonet.NewUDPConn(&wq, wep)
	go spliceUDP(inbound, outbound)
	return true
}

// close tears down the stack and waits for the pump to exit.
func (n *netstackEgress) close() {
	n.stop()
	n.stack.Close()
	n.ep.Close()
	n.wg.Wait()
}

// splice copies bytes in both directions between the overlay (gonet) side and
// the real OS socket, closing both when either direction ends.
func splice(a, b net.Conn) {
	var once sync.Once
	done := func() {
		a.Close()
		b.Close()
	}
	go func() {
		io.Copy(a, b)
		once.Do(done)
	}()
	io.Copy(b, a)
	once.Do(done)
}

// spliceUDP relays datagrams both ways and tears the pair down after an idle
// period with no traffic, so forgotten flows do not leak endpoints.
func spliceUDP(inbound, outbound net.Conn) {
	const idle = 60 * time.Second
	var once sync.Once
	done := func() {
		inbound.Close()
		outbound.Close()
	}
	copyIdle := func(dst, src net.Conn) {
		buf := make([]byte, 64*1024)
		for {
			_ = src.SetReadDeadline(time.Now().Add(idle))
			nr, err := src.Read(buf)
			if nr > 0 {
				if _, werr := dst.Write(buf[:nr]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		once.Do(done)
	}
	go copyIdle(outbound, inbound)
	copyIdle(inbound, outbound)
}

// errFromTCPIP wraps a tcpip.Error (which is not a Go error) with context.
func errFromTCPIP(what string, e tcpip.Error) error {
	return &netstackErr{what: what, msg: e.String()}
}

type netstackErr struct {
	what string
	msg  string
}

func (e *netstackErr) Error() string { return e.what + ": " + e.msg }
