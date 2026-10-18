package main

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"valky/internal/protocol"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// TestNetstackEgressTCP exercises the full proxy-mode L3 egress path end to end,
// the way a tunnel-mode agent would drive it: a client gVisor stack (standing in
// for the originating agent's TUN) is bridged to the proxy agent's netstackEgress
// over the same framed connWriter the real link uses. A TCP connection dialed
// through the client stack must reach a real OS listener via the egress and echo
// back, proving SYN handling, the real dial, the splice, and the synthesised
// reply packets routed home.
func TestNetstackEgressTCP(t *testing.T) {
	// Real OS listener playing the LAN service; the egress dials it for real.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }() // echo
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	targetIP := tcpip.AddrFrom4([4]byte{127, 0, 0, 1})

	client, egress, cancel := bridgedStacks(t)
	defer cancel()

	port := mustPort(t, portStr)
	ctx, cc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cc()
	conn, err := gonet.DialContextTCP(ctx, client, tcpip.FullAddress{
		NIC:  clientNICID,
		Addr: targetIP,
		Port: port,
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("dial through egress: %v", err)
	}
	defer conn.Close()

	msg := []byte("valky-l3-egress")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo mismatch: got %q want %q", got, msg)
	}
	_ = egress // kept alive by the bridge until cancel()
}

const clientNICID tcpip.NICID = 1

// bridgedStacks wires a client stack's outbound packets into a netstackEgress and
// the egress's outbound frames back into the client stack, so traffic dialed on
// the client flows through the real egress forwarders. It returns the client
// stack, the egress, and a cancel that tears both down.
func bridgedStacks(t *testing.T) (*stack.Stack, *netstackEgress, func()) {
	t.Helper()

	// The egress writes outbound packets as TypeData frames through cw; we read
	// them off the pipe and inject them into the client stack.
	egressSide, testSide := net.Pipe()
	cw := &connWriter{}
	cw.setConn(egressSide)
	egress, err := newNetstackEgress(cw)
	if err != nil {
		t.Fatalf("newNetstackEgress: %v", err)
	}
	// The test target is 127.0.0.1 (a real OS listener); permit the stack to
	// route to a loopback destination, which it rejects as martian by default.
	// Real LAN targets (e.g. 172.16.5.35) need no such allowance.
	allowLoopback(egress.stack)

	client := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	cep := channel.New(512, netstackMTU, "")
	if err := client.CreateNIC(clientNICID, cep); err != nil {
		t.Fatalf("client nic: %v", err)
	}
	// Overlay source address, like an agent's assigned VIP.
	overlay := tcpip.AddrFrom4([4]byte{10, 9, 0, 2})
	client.AddProtocolAddress(clientNICID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: overlay.WithPrefix(),
	}, stack.AddressProperties{})
	client.SetSpoofing(clientNICID, true)
	client.SetPromiscuousMode(clientNICID, true)
	client.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: clientNICID}})
	allowLoopback(client) // replies carry a 127.0.0.1 source in this test

	ctx, cancel := context.WithCancel(context.Background())

	// egress outbound frames -> client inbound
	go func() {
		for {
			typ, payload, err := protocol.ReadFrame(testSide)
			if err != nil {
				return
			}
			if typ != protocol.TypeData || len(payload) == 0 {
				continue
			}
			pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(payload),
			})
			cep.InjectInbound(ipv4.ProtocolNumber, pb)
			pb.DecRef()
		}
	}()

	// client outbound -> egress inbound
	go func() {
		for {
			pkt := cep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			b := pkt.ToBuffer()
			egress.inject(b.Flatten())
			pkt.DecRef()
		}
	}()

	cleanup := func() {
		cancel()
		egress.close()
		client.Close()
		cep.Close()
		egressSide.Close()
		testSide.Close()
	}
	return client, egress, cleanup
}

func allowLoopback(s *stack.Stack) {
	opt := tcpip.AllowExternalLoopbackTrafficOption(true)
	s.SetNetworkProtocolOption(ipv4.ProtocolNumber, &opt)
}

func mustPort(t *testing.T, s string) uint16 {
	t.Helper()
	p, err := net.LookupPort("tcp", s)
	if err != nil {
		t.Fatalf("bad port %q: %v", s, err)
	}
	return uint16(p)
}
