package main

import (
	"path/filepath"
	"testing"

	"valky/internal/uuid"
)

// Persistencia: guardar la política y recargarla en un hub nuevo preserva reglas,
// forwards (con su /32 reconstruido), socks y rutas publicadas, con sus UUIDs.
func TestStatePersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	a := uuid.New()

	h := testHub(t)
	h.statePath = filepath.Join(dir, "valky.state")
	h.rules["r1"] = &rule{id: "r1", agentID: a, network: mustCIDR(t, "192.168.2.0/24"), nat: true}
	h.forwards["f1"] = &forward{id: "f1", agentID: a, listen: "127.0.0.1:1080",
		target: "10.0.0.5:22", targetNet: hostNet("10.0.0.5:22")}
	h.socks["s1"] = &socksProxy{id: "s1", agentID: a, listen: "127.0.0.1:9050"}
	h.published["p1"] = &publishedNet{id: "p1", agentID: a, network: mustCIDR(t, "10.20.0.0/16")}
	h.saveState()

	h2 := testHub(t)
	h2.statePath = h.statePath
	h2.loadState()

	if len(h2.rules) != 1 || len(h2.forwards) != 1 || len(h2.socks) != 1 || len(h2.published) != 1 {
		t.Fatalf("restored counts rules=%d forwards=%d socks=%d published=%d",
			len(h2.rules), len(h2.forwards), len(h2.socks), len(h2.published))
	}
	if r := h2.rules["r1"]; r == nil || !r.nat || r.network.String() != "192.168.2.0/24" || r.agentID != a {
		t.Fatalf("rule not restored correctly: %+v", r)
	}
	if f := h2.forwards["f1"]; f == nil || f.targetNet == nil || f.targetNet.String() != "10.0.0.5/32" {
		t.Fatalf("forward targetNet not reconstructed: %+v", f)
	}
	if p := h2.published["p1"]; p == nil || p.network.String() != "10.20.0.0/16" {
		t.Fatalf("published route not restored: %+v", p)
	}
}

// Sin archivo de estado previo, loadState no falla (primer arranque).
func TestStateLoadMissingFile(t *testing.T) {
	h := testHub(t)
	h.statePath = filepath.Join(t.TempDir(), "does-not-exist.state")
	h.loadState()
	if len(h.rules) != 0 {
		t.Fatal("expected no rules from a missing state file")
	}
}
