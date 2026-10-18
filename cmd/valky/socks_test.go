package main

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// TestSocks5Proxy drives a full SOCKS5 CONNECT through the proxy and stream mux
// to a backend, proving it works in userspace without a TUN.
func TestSocks5Proxy(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadString('\n')
				c.Write([]byte("echo:" + line))
			}(c)
		}
	}()
	bhost, bport, _ := net.SplitHostPort(backend.Addr().String())
	bportN, _ := strconv.Atoi(bport)

	// Mux wired to a fake server relay (reuses fakeRelay from forward_test.go).
	muxConn, srv := net.Pipe()
	mux := newStreamMux(&connWriter{conn: muxConn})
	go fakeRelay(srv, mux)

	lp, _ := net.Listen("tcp", "127.0.0.1:0")
	socksAddr := lp.Addr().String()
	lp.Close()

	sm := newSocksManager(mux)
	sm.reconcile([]string{socksAddr})
	defer sm.reconcile(nil)
	time.Sleep(100 * time.Millisecond)

	c, err := net.DialTimeout("tcp", socksAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))

	// Greeting (no-auth) and method reply.
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	methodReply := make([]byte, 2)
	if _, err := io.ReadFull(c, methodReply); err != nil {
		t.Fatalf("method reply: %v", err)
	}
	if methodReply[0] != 0x05 || methodReply[1] != 0x00 {
		t.Fatalf("unexpected method reply: %v", methodReply)
	}

	// CONNECT to the backend (IPv4).
	ip := net.ParseIP(bhost).To4()
	req := []byte{0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], 0, 0}
	binary.BigEndian.PutUint16(req[8:], uint16(bportN))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		t.Fatalf("connect reply: %v", err)
	}
	if rep[1] != 0x00 {
		t.Fatalf("socks connect failed, code=%d", rep[1])
	}

	// Tunneled application data.
	c.Write([]byte("hola\n"))
	resp, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if resp != "echo:hola\n" {
		t.Fatalf("unexpected echo: %q", resp)
	}
}
