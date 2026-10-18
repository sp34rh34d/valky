package main

import (
	"encoding/binary"
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"valky/internal/protocol"
)

// connWriter serializes writes to the single client<->server TCP connection,
// which is shared by the TUN loop, keepalives and all port-forward streams.
type connWriter struct {
	mu   sync.Mutex
	conn net.Conn
}

func (w *connWriter) write(t protocol.MessageType, p []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.conn == nil {
		return errNotConnected
	}
	return protocol.WriteFrame(w.conn, t, p)
}

// setConn swaps the underlying connection, used by the client's reconnect loop so
// the shared TUN/keepalive writers keep working across reconnects.
func (w *connWriter) setConn(c net.Conn) {
	w.mu.Lock()
	w.conn = c
	w.mu.Unlock()
}

// closeCurrent closes the active connection (if any). The keepalive loop calls it
// when a write fails, so the read loop unblocks and the client reconnects even on
// a half-open link the read side has not yet noticed.
func (w *connWriter) closeCurrent() {
	w.mu.Lock()
	c := w.conn
	w.mu.Unlock()
	if c != nil {
		c.Close()
	}
}

var errNotConnected = errors.New("valky: not connected")

// streamConn is one active userspace TCP stream (one port-forward connection).
type streamConn struct {
	id  uint32
	c   net.Conn
	out chan []byte
	one sync.Once
}

// streamMux multiplexes port-forward TCP connections over the server link. It
// handles both streams this client initiates (the forward "listen" side) and
// streams the server asks it to open (the forward "target" side). It needs no
// TUN device, so port-forwards work without administrative privileges.
type streamMux struct {
	cw    *connWriter
	mu    sync.Mutex
	conns map[uint32]*streamConn
	next  uint32 // outbound id counter, kept in the low half of the id space
}

func newStreamMux(cw *connWriter) *streamMux {
	return &streamMux{cw: cw, conns: map[uint32]*streamConn{}}
}

// nextOutboundID allocates an id in [1, 0x7fffffff] for a stream this client
// initiates. The server allocates incoming ids from the high half, so the two
// never collide on one connection.
func (m *streamMux) nextOutboundID() uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	for {
		m.next++
		id := m.next & 0x7fffffff
		if id == 0 {
			continue
		}
		if _, exists := m.conns[id]; !exists {
			return id
		}
	}
}

func encodeID(id uint32, data []byte) []byte {
	b := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(b[:4], id)
	copy(b[4:], data)
	return b
}

func decodeID(p []byte) (uint32, []byte) {
	if len(p) < 4 {
		return 0, nil
	}
	return binary.BigEndian.Uint32(p[:4]), p[4:]
}

// openStream is called on the forward "listen" side for each accepted local
// connection. It registers the stream and asks the server to open it to target.
func (m *streamMux) openStream(local net.Conn, target string) {
	id := m.nextOutboundID()
	sc := m.register(id, local)
	if err := m.cw.write(protocol.TypeStreamOpen, encodeID(id, []byte(target))); err != nil {
		m.closeStream(id)
		return
	}
	go m.pump(sc)
}

// handleOpen is called on the forward "target" side when the server relays an
// open request. It dials the target locally (ordinary socket, no admin needed).
// The stream is registered *before* dialing so that data chunks arriving while
// the dial is in flight are buffered on sc.out instead of being dropped.
func (m *streamMux) handleOpen(id uint32, target string) {
	sc := &streamConn{id: id, out: make(chan []byte, 128)}
	m.mu.Lock()
	m.conns[id] = sc
	m.mu.Unlock()

	go func() {
		c, err := net.DialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			log.Printf("stream %d: no se pudo conectar a %s: %v", id, target, err)
			m.cw.write(protocol.TypeStreamClose, encodeID(id, nil))
			m.closeStream(id)
			return
		}
		// Make sure the stream wasn't torn down while we were dialing.
		m.mu.Lock()
		cur, ok := m.conns[id]
		if ok && cur == sc {
			sc.c = c
		}
		m.mu.Unlock()
		if !ok || cur != sc {
			c.Close()
			return
		}
		go sc.writer()
		m.pump(sc)
	}()
}

func (m *streamMux) handleData(id uint32, data []byte) {
	m.mu.Lock()
	sc := m.conns[id]
	m.mu.Unlock()
	if sc == nil {
		return
	}
	buf := make([]byte, len(data))
	copy(buf, data)
	select {
	case sc.out <- buf:
	case <-time.After(30 * time.Second):
		m.closeStream(id) // stuck consumer; drop the stream
	}
}

func (m *streamMux) handleClose(id uint32) {
	m.closeStream(id)
}

func (m *streamMux) register(id uint32, c net.Conn) *streamConn {
	sc := &streamConn{id: id, c: c, out: make(chan []byte, 128)}
	m.mu.Lock()
	m.conns[id] = sc
	m.mu.Unlock()
	go sc.writer()
	return sc
}

func (m *streamMux) closeStream(id uint32) {
	m.mu.Lock()
	sc := m.conns[id]
	delete(m.conns, id)
	m.mu.Unlock()
	if sc != nil {
		sc.shutdown()
	}
}

// reset tears down all active streams. The client calls it on reconnect, because
// streams opened over the previous connection cannot survive on the new one.
func (m *streamMux) reset() {
	m.mu.Lock()
	conns := m.conns
	m.conns = map[uint32]*streamConn{}
	m.mu.Unlock()
	for _, sc := range conns {
		sc.shutdown()
	}
}

// pump copies bytes from the local/target socket to the server as StreamData,
// and sends StreamClose when the socket ends.
func (m *streamMux) pump(sc *streamConn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := sc.c.Read(buf)
		if n > 0 {
			if werr := m.cw.write(protocol.TypeStreamData, encodeID(sc.id, buf[:n])); werr != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	m.cw.write(protocol.TypeStreamClose, encodeID(sc.id, nil))
	m.closeStream(sc.id)
}

// writer delivers inbound chunks to the socket in order.
func (sc *streamConn) writer() {
	for b := range sc.out {
		if _, err := sc.c.Write(b); err != nil {
			return
		}
	}
}

func (sc *streamConn) shutdown() {
	sc.one.Do(func() {
		close(sc.out)
		if sc.c != nil {
			sc.c.Close()
		}
	})
}
