package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
)

// socksManager runs the client-side SOCKS5 proxy listeners. Each accepted
// connection's CONNECT request is carried over the stream multiplexer to the
// agent that owns the destination network (the server enforces the route-rule
// ACL). It needs no TUN device, so it works without admin privileges.
type socksManager struct {
	mux    *streamMux
	mu     sync.Mutex
	active map[string]net.Listener // listen addr -> listener
}

func newSocksManager(mux *streamMux) *socksManager {
	return &socksManager{mux: mux, active: map[string]net.Listener{}}
}

// reconcile starts/stops SOCKS5 listeners to match the desired listen addresses.
func (m *socksManager) reconcile(desired []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	want := map[string]bool{}
	for _, a := range desired {
		a = strings.TrimSpace(a)
		if a != "" {
			want[a] = true
		}
	}
	for addr, ln := range m.active {
		if !want[addr] {
			ln.Close()
			delete(m.active, addr)
			log.Printf("socks5 proxy stopped: %s", addr)
		}
	}
	for addr := range want {
		if _, ok := m.active[addr]; ok {
			continue
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Printf("socks5 proxy %s: cannot listen: %v", addr, err)
			continue
		}
		m.active[addr] = ln
		go m.serve(ln)
		log.Printf("socks5 proxy active: %s", addr)
	}
}

// list returns the active SOCKS5 listen addresses.
func (m *socksManager) list() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for a := range m.active {
		out = append(out, a)
	}
	return out
}

func (m *socksManager) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go m.handle(c)
	}
}

// socksReply builds a SOCKS5 reply with the given status code and a null bind
// address (0.0.0.0:0).
func socksReply(code byte) []byte {
	return []byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
}

// handle performs the SOCKS5 handshake (no authentication) and, on a CONNECT,
// hands the connection to the stream mux targeting the requested host:port.
func (m *socksManager) handle(c net.Conn) {
	br := bufio.NewReader(c)

	// Greeting: VER, NMETHODS, METHODS...
	ver, err := br.ReadByte()
	if err != nil || ver != 0x05 {
		c.Close()
		return
	}
	n, err := br.ReadByte()
	if err != nil {
		c.Close()
		return
	}
	if _, err := br.Discard(int(n)); err != nil {
		c.Close()
		return
	}
	// Reply: no authentication required.
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		c.Close()
		return
	}

	// Request: VER, CMD, RSV, ATYP, ADDR, PORT
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(br, hdr); err != nil || hdr[0] != 0x05 {
		c.Close()
		return
	}
	if hdr[1] != 0x01 { // only CONNECT
		c.Write(socksReply(0x07)) // command not supported
		c.Close()
		return
	}
	var host string
	switch hdr[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			c.Close()
			return
		}
		host = net.IP(b).String()
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			c.Close()
			return
		}
		host = net.IP(b).String()
	case 0x03: // domain name
		l, err := br.ReadByte()
		if err != nil {
			c.Close()
			return
		}
		b := make([]byte, int(l))
		if _, err := io.ReadFull(br, b); err != nil {
			c.Close()
			return
		}
		host = string(b)
	default:
		c.Write(socksReply(0x08)) // address type not supported
		c.Close()
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		c.Close()
		return
	}
	target := net.JoinHostPort(host, fmt.Sprintf("%d", binary.BigEndian.Uint16(pb)))

	// Optimistic success reply (the stream will simply close if the server
	// denies the destination or the target is unreachable).
	if _, err := c.Write(socksReply(0x00)); err != nil {
		c.Close()
		return
	}

	// Preserve any bytes bufio read ahead (normally none: the client waits for
	// our reply before sending application data).
	conn := net.Conn(c)
	if nbuf := br.Buffered(); nbuf > 0 {
		pre, _ := br.Peek(nbuf)
		buf := make([]byte, len(pre))
		copy(buf, pre)
		conn = &prefixConn{Conn: c, pre: buf}
	}
	m.mux.openStream(conn, target)
}

// prefixConn yields pre-buffered bytes before reading from the underlying conn.
type prefixConn struct {
	net.Conn
	pre []byte
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.pre) > 0 {
		n := copy(b, p.pre)
		p.pre = p.pre[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}
