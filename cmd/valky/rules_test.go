package main

import (
	"fmt"
	"net"
	"testing"

	"valky/internal/config"
	"valky/internal/uuid"
)

func testHub(t *testing.T) *hub {
	t.Helper()
	_, overlay, _ := net.ParseCIDR("10.9.0.0/24")
	return newHub(&config.ServerConfig{
		Listen:  "0.0.0.0:0",
		Key:     "k",
		Overlay: overlay,
	})
}

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// Simula "route --add" + "route --del <prefijo>" en una sola instancia.
func TestRuleAddDeleteByPrefix(t *testing.T) {
	h := testHub(t)
	agent := uuid.New()

	// add
	r := &rule{id: uuid.New(), agentID: agent, network: mustCIDR(t, "192.168.2.0/24")}
	h.rules[r.id] = r

	// del por prefijo de 8 chars
	got, err := h.findRuleLocked(r.id[:8])
	if err != nil {
		t.Fatalf("findRuleLocked por prefijo: %v", err)
	}
	if got.id != r.id {
		t.Fatalf("prefijo resolvió a %s, esperaba %s", got.id, r.id)
	}
	delete(h.rules, got.id)
	if len(h.rules) != 0 {
		t.Fatalf("la regla no se eliminó, quedan %d", len(h.rules))
	}
}

func TestPrefixAmbiguous(t *testing.T) {
	h := testHub(t)
	a := &rule{id: "aaaaaaaa-0000-4000-8000-000000000001", agentID: uuid.New(), network: mustCIDR(t, "10.1.0.0/24")}
	b := &rule{id: "aaaaaaaa-0000-4000-8000-000000000002", agentID: uuid.New(), network: mustCIDR(t, "10.2.0.0/24")}
	h.rules[a.id] = a
	h.rules[b.id] = b
	if _, err := h.findRuleLocked("aaaaaaaa"); err == nil {
		t.Fatal("esperaba error por prefijo ambiguo")
	}
}

// ACL: un agente solo alcanza lo que una regla con su uuid permite (más overlay).
func TestACLByAgentUUID(t *testing.T) {
	h := testHub(t)
	a1 := uuid.New()
	a2 := uuid.New()
	s1 := &session{uuid: a1, virtIP: net.ParseIP("10.9.0.1")}
	s2 := &session{uuid: a2, virtIP: net.ParseIP("10.9.0.2")}

	r := &rule{id: uuid.New(), agentID: a1, network: mustCIDR(t, "192.168.2.0/24")}
	h.rules[r.id] = r

	if !h.allowedLocked(s1, net.ParseIP("192.168.2.5")) {
		t.Fatal("a1 debería poder alcanzar 192.168.2.5")
	}
	if h.allowedLocked(s2, net.ParseIP("192.168.2.5")) {
		t.Fatal("a2 NO debería poder alcanzar 192.168.2.5 (no tiene regla)")
	}
	// overlay siempre permitido (respuestas)
	if !h.allowedLocked(s2, net.ParseIP("10.9.0.1")) {
		t.Fatal("el tráfico al overlay debería permitirse siempre")
	}
}

// A published subnet route makes an agent the delivery target for a network it
// did not auto-advertise.
func TestPublishedSubnetRoute(t *testing.T) {
	h := testHub(t)
	a := uuid.New()
	b := uuid.New()
	sa := &session{uuid: a, virtIP: net.ParseIP("10.9.0.1"), streams: map[uint32]*streamEnd{}}
	sb := &session{uuid: b, virtIP: net.ParseIP("10.9.0.2"), streams: map[uint32]*streamEnd{}}
	h.byUUID[a] = sa
	h.byUUID[b] = sb

	dst := net.ParseIP("10.20.30.5")
	// No agent advertises 10.20.30.0/24 -> no delivery target yet.
	if h.routeForLocked(dst) != nil {
		t.Fatal("expected no route before publishing")
	}
	// Publish it via agent B.
	h.published[uuid.New()] = &publishedNet{id: "p", agentID: b, network: mustCIDR(t, "10.20.30.0/24")}
	if got := h.routeForLocked(dst); got != sb {
		t.Fatalf("expected delivery via B after publishing, got %v", got)
	}
	// If B goes offline, delivery stops.
	delete(h.byUUID, b)
	if h.routeForLocked(dst) != nil {
		t.Fatal("expected no route when the publishing agent is offline")
	}
}

// Overlapping/duplicate networks: longest-prefix-match wins, exact ties resolve
// to the lowest uuid, deterministically across many calls.
func TestRouteOverlapLongestPrefix(t *testing.T) {
	h := testHub(t)
	// Fixed uuids so tie-breaking is predictable (a < b).
	a := "11111111-1111-4111-8111-111111111111" // specific /24 + /23
	b := "22222222-2222-4222-8222-222222222222" // broad /16 + same /23
	sa := &session{uuid: a, virtIP: net.ParseIP("10.9.0.1"), streams: map[uint32]*streamEnd{}}
	sb := &session{uuid: b, virtIP: net.ParseIP("10.9.0.2"), streams: map[uint32]*streamEnd{}}
	sa.segs = []*net.IPNet{mustCIDR(t, "172.16.71.0/24"), mustCIDR(t, "172.16.4.0/23")}
	sb.segs = []*net.IPNet{mustCIDR(t, "172.16.0.0/16"), mustCIDR(t, "172.16.4.0/23")}
	h.byUUID[a] = sa
	h.byUUID[b] = sb

	// Most specific wins: 172.16.71.5 -> /24 on A, not /16 on B.
	for i := 0; i < 50; i++ {
		if got := h.routeForLocked(net.ParseIP("172.16.71.5")); got != sa {
			t.Fatalf("172.16.71.5 should route to A (/24), got %v", got)
		}
	}
	// Only B covers this (/16), not A.
	for i := 0; i < 50; i++ {
		if got := h.routeForLocked(net.ParseIP("172.16.200.9")); got != sb {
			t.Fatalf("172.16.200.9 should route to B (/16), got %v", got)
		}
	}
	// Exact duplicate /23: deterministic tie-break to lowest uuid (A).
	for i := 0; i < 50; i++ {
		if got := h.routeForLocked(net.ParseIP("172.16.4.100")); got != sa {
			t.Fatalf("172.16.4.100 (dup /23) should deterministically route to A, got %v", got)
		}
	}
}

// --random spreads flows across agents that deliver the same network, while
// pinning each flow to one agent (same flowHash -> same agent).
func TestRandomLoadBalance(t *testing.T) {
	h := testHub(t)
	a := "11111111-1111-4111-8111-111111111111"
	b := "22222222-2222-4222-8222-222222222222"
	src := "33333333-3333-4333-8333-333333333333"
	sa := &session{uuid: a, virtIP: net.ParseIP("10.9.0.1"), streams: map[uint32]*streamEnd{}}
	sb := &session{uuid: b, virtIP: net.ParseIP("10.9.0.2"), streams: map[uint32]*streamEnd{}}
	ssrc := &session{uuid: src, virtIP: net.ParseIP("10.9.0.3"), streams: map[uint32]*streamEnd{}}
	// A and B both deliver the same /23.
	sa.segs = []*net.IPNet{mustCIDR(t, "172.16.4.0/23")}
	sb.segs = []*net.IPNet{mustCIDR(t, "172.16.4.0/23")}
	h.byUUID[a], h.byUUID[b], h.byUUID[src] = sa, sb, ssrc

	dst := net.ParseIP("172.16.4.100")

	// Without a --random rule: deterministic (lowest uuid = A).
	h.rules["r1"] = &rule{id: "r1", agentID: src, network: mustCIDR(t, "172.16.4.0/23")}
	if h.deliverTargetLocked(ssrc, dst) != sa {
		t.Fatal("non-random should always pick A (lowest uuid)")
	}

	// With --random: a single client sticks to one agent for the same dst, so a
	// browser's many connections keep the same NAT source and sessions survive.
	h.rules["r1"] = &rule{id: "r1", agentID: src, network: mustCIDR(t, "172.16.4.0/23"), random: true}
	first := h.deliverTargetLocked(ssrc, dst)
	for i := 0; i < 50; i++ {
		if h.deliverTargetLocked(ssrc, dst) != first {
			t.Fatal("same client must stick to the same agent (session affinity)")
		}
	}

	// ...but different clients spread across both A and B.
	seen := map[*session]bool{}
	for i := 0; i < 64; i++ {
		c := &session{
			uuid:    uuid.New(),
			virtIP:  net.ParseIP(fmt.Sprintf("10.9.1.%d", i)),
			streams: map[uint32]*streamEnd{},
		}
		h.byUUID[c.uuid] = c
		h.rules["rc"] = &rule{id: "rc", agentID: c.uuid, network: mustCIDR(t, "172.16.4.0/23"), random: true}
		seen[h.deliverTargetLocked(c, dst)] = true
	}
	if !seen[sa] || !seen[sb] {
		t.Fatal("--random should spread different clients across both A and B")
	}
}

// NAT: el masquerade lo debe aplicar el agente que ENTREGA la red (el dueño del
// segmento), no el agente consumidor que la regla autoriza. deliversLocked
// identifica a ese agente de salida.
func TestNATTargetsDeliveringAgent(t *testing.T) {
	h := testHub(t)
	consumer := uuid.New() // inicia la conexión (overlay 10.9.0.7)
	owner := uuid.New()    // posee 192.168.2.0/24 y entrega en su LAN

	sConsumer := &session{uuid: consumer, virtIP: net.ParseIP("10.9.0.7")}
	sOwner := &session{uuid: owner, virtIP: net.ParseIP("10.9.0.8"),
		segs: []*net.IPNet{mustCIDR(t, "192.168.2.0/24")}}
	h.byUUID[consumer] = sConsumer
	h.byUUID[owner] = sOwner

	// Regla con --nat: el consumidor puede alcanzar la red del owner.
	net2 := mustCIDR(t, "192.168.2.0/24")
	h.rules["rnat"] = &rule{id: "rnat", agentID: consumer, network: net2, nat: true}

	if !h.deliversLocked(sOwner, net2) {
		t.Fatal("el owner del segmento debe ser quien entrega (y hace NAT)")
	}
	if h.deliversLocked(sConsumer, net2) {
		t.Fatal("el consumidor NO entrega la red; no debe recibir el NAT")
	}

	// Una regla sin --nat no debe marcar ninguna red para masquerade.
	h.rules["rplain"] = &rule{id: "rplain", agentID: consumer,
		network: mustCIDR(t, "192.168.3.0/24"), nat: true}
	// El owner no anuncia 192.168.3.0/24, así que no la entrega.
	if h.deliversLocked(sOwner, mustCIDR(t, "192.168.3.0/24")) {
		t.Fatal("el owner no anuncia 192.168.3.0/24; no debe entregarla")
	}
}
