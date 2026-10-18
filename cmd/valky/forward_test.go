package main

import (
	"bufio"
	"net"
	"testing"
	"time"

	"valky/internal/protocol"
)

// fakeRelay emulates the server: it reads the frames the mux writes and feeds
// them back into the same mux with translated stream ids, so a single mux plays
// both the forward "listen" side and the "target" side.
func fakeRelay(srv net.Conn, mux *streamMux) {
	peer := map[uint32]uint32{}
	for {
		t, p, err := protocol.ReadFrame(srv)
		if err != nil {
			return
		}
		id, rest := decodeID(p)
		switch t {
		case protocol.TypeStreamOpen:
			bID := id | 0x80000000 // distinct inbound id, reversible
			peer[id] = bID
			peer[bID] = id
			mux.handleOpen(bID, string(rest))
		case protocol.TypeStreamData:
			mux.handleData(peer[id], rest)
		case protocol.TypeStreamClose:
			mux.handleClose(peer[id])
		}
	}
}

// TestStreamMuxForward proves a port-forward works entirely in userspace (no
// TUN): a connection to the listen address is carried over the stream mux and
// delivered to the target, which is dialed with an ordinary socket.
func TestStreamMuxForward(t *testing.T) {
	// Backend echo server (stands in for 192.168.3.12:80).
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

	// Mux wired to a fake server via an in-memory pipe.
	muxConn, srv := net.Pipe()
	mux := newStreamMux(&connWriter{conn: muxConn})
	go fakeRelay(srv, mux)

	// Forward listener (stands in for 192.168.1.10:1234).
	lp, _ := net.Listen("tcp", "127.0.0.1:0")
	listenAddr := lp.Addr().String()
	lp.Close()

	fm := newForwardManager(mux)
	fm.reconcile([]string{listenAddr + "|" + backend.Addr().String()})
	defer fm.reconcile(nil)
	time.Sleep(100 * time.Millisecond)

	c, err := net.DialTimeout("tcp", listenAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("conectar al forward: %v", err)
	}
	defer c.Close()
	c.Write([]byte("hola\n"))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("leer respuesta: %v", err)
	}
	if resp != "echo:hola\n" {
		t.Fatalf("respuesta inesperada: %q", resp)
	}

	// Reconcile to empty: the listener should stop.
	fm.reconcile(nil)
	time.Sleep(100 * time.Millisecond)
	if _, err := net.DialTimeout("tcp", listenAddr, 300*time.Millisecond); err == nil {
		t.Fatal("el forward debería haberse detenido")
	}
}
