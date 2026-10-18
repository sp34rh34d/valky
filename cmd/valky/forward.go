package main

import (
	"log"
	"net"
	"strings"
	"sync"
)

// forwardManager runs the client-side TCP port-forward listeners. Each forward
// listens on a local address; every accepted connection is handed to the stream
// multiplexer, which carries it over the server link to the agent that owns the
// target network. This path uses no TUN device, so port-forwards work without
// administrative privileges.
type forwardManager struct {
	mux    *streamMux
	mu     sync.Mutex
	active map[string]*forwardListener // key "listen|target"
}

type forwardListener struct {
	listen string
	target string
	ln     net.Listener
}

func newForwardManager(mux *streamMux) *forwardManager {
	return &forwardManager{mux: mux, active: map[string]*forwardListener{}}
}

// reconcile starts listeners for new forwards and stops ones no longer desired.
// Each desired entry is "listenIP:port|targetIP:port".
func (m *forwardManager) reconcile(desired []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	want := map[string]struct{ listen, target string }{}
	for _, e := range desired {
		listen, target, ok := strings.Cut(e, "|")
		if !ok {
			continue
		}
		want[e] = struct{ listen, target string }{strings.TrimSpace(listen), strings.TrimSpace(target)}
	}

	for key, fl := range m.active {
		if _, ok := want[key]; !ok {
			fl.ln.Close()
			delete(m.active, key)
			log.Printf("port-forward detenido: %s -> %s", fl.listen, fl.target)
		}
	}
	for key, w := range want {
		if _, ok := m.active[key]; ok {
			continue
		}
		ln, err := net.Listen("tcp", w.listen)
		if err != nil {
			log.Printf("port-forward %s -> %s: no se pudo escuchar: %v", w.listen, w.target, err)
			continue
		}
		fl := &forwardListener{listen: w.listen, target: w.target, ln: ln}
		m.active[key] = fl
		go fl.serve(m.mux)
		log.Printf("port-forward activo: %s -> %s", w.listen, w.target)
	}
}

// list returns the active forwards as "listen -> target" strings.
func (m *forwardManager) list() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, fl := range m.active {
		out = append(out, fl.listen+" -> "+fl.target)
	}
	return out
}

func (fl *forwardListener) serve(mux *streamMux) {
	for {
		c, err := fl.ln.Accept()
		if err != nil {
			return // listener closed
		}
		mux.openStream(c, fl.target)
	}
}
