package main

import (
	"net"
	"testing"
	"time"

	"valky/internal/protocol"
	"valky/internal/uuid"
)

func mkSession(h *hub, id string, vip string, segs ...string) (*session, net.Conn) {
	srvSide, clientSide := net.Pipe()
	s := &session{uuid: id, virtIP: net.ParseIP(vip), conn: srvSide, streams: map[uint32]*streamEnd{}}
	for _, c := range segs {
		_, n, _ := net.ParseCIDR(c)
		s.segs = append(s.segs, n)
	}
	h.byUUID[id] = s
	h.byVIP[s.virtIP.String()] = s
	return s, clientSide
}

func readFrame(t *testing.T, c net.Conn) (protocol.MessageType, uint32, []byte) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	mt, p, err := protocol.ReadFrame(c)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	id, rest := decodeID(p)
	return mt, id, rest
}

// TestServerStreamRelay drives the server's port-forward stream relay: an open
// from A to a host in B's segment must reach B (with a translated id), data must
// flow both ways, and close must propagate.
func TestServerStreamRelay(t *testing.T) {
	h := testHub(t)
	a := uuid.New()
	b := uuid.New()
	_, aClient := mkSession(h, a, "10.9.0.1")
	_, bClient := mkSession(h, b, "10.9.0.2", "192.168.50.0/24")

	// Allow A to reach B's segment.
	_, seg, _ := net.ParseCIDR("192.168.50.0/24")
	h.rules[uuid.New()] = &rule{id: "r", agentID: a, network: seg}

	// A opens a stream to 192.168.50.10:80.
	go h.onStreamOpen(h.byUUID[a], 1, "192.168.50.10:80")
	mt, bID, rest := readFrame(t, bClient)
	if mt != protocol.TypeStreamOpen || string(rest) != "192.168.50.10:80" {
		t.Fatalf("B esperaba StreamOpen al destino, obtuvo tipo=%d payload=%q", mt, rest)
	}
	if bID&0x80000000 == 0 {
		t.Fatalf("el id hacia B debería estar en la mitad alta: %x", bID)
	}

	// A -> B data.
	go h.onStreamData(h.byUUID[a], 1, []byte("ping"))
	mt, gotID, data := readFrame(t, bClient)
	if mt != protocol.TypeStreamData || gotID != bID || string(data) != "ping" {
		t.Fatalf("B esperaba StreamData(ping), obtuvo tipo=%d id=%x data=%q", mt, gotID, data)
	}

	// B -> A data (uses the B-side id).
	go h.onStreamData(h.byUUID[b], bID, []byte("pong"))
	mt, gotID, data = readFrame(t, aClient)
	if mt != protocol.TypeStreamData || gotID != 1 || string(data) != "pong" {
		t.Fatalf("A esperaba StreamData(pong) id=1, obtuvo tipo=%d id=%x data=%q", mt, gotID, data)
	}

	// Close from A propagates to B.
	go h.onStreamClose(h.byUUID[a], 1)
	mt, gotID, _ = readFrame(t, bClient)
	if mt != protocol.TypeStreamClose || gotID != bID {
		t.Fatalf("B esperaba StreamClose id=%x, obtuvo tipo=%d id=%x", bID, mt, gotID)
	}
}

// TestServerStreamDenied verifies the ACL: without a rule, A's open is rejected
// with a StreamClose and nothing reaches B.
func TestServerStreamDenied(t *testing.T) {
	h := testHub(t)
	a := uuid.New()
	b := uuid.New()
	_, aClient := mkSession(h, a, "10.9.0.1")
	mkSession(h, b, "10.9.0.2", "192.168.50.0/24")

	go h.onStreamOpen(h.byUUID[a], 7, "192.168.50.10:80")
	mt, id, _ := readFrame(t, aClient)
	if mt != protocol.TypeStreamClose || id != 7 {
		t.Fatalf("A esperaba StreamClose id=7 (denegado), obtuvo tipo=%d id=%x", mt, id)
	}
}
