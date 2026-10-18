package main

// Server-side persistence of the policy (rules, port-forwards, SOCKS proxies and
// published subnet routes). Without this, a server restart loses all the operator
// configured; agents reconnect but with no rules. The live connection state
// (sessions, overlay-IP allocations) is intentionally NOT persisted: it is rebuilt
// as agents reconnect and their policy is pushed to them again.

import (
	"encoding/json"
	"log"
	"net"
	"os"
)

type persistedRule struct {
	ID      string `json:"id"`
	AgentID string `json:"agent_id"`
	Network string `json:"network"`
	Random  bool   `json:"random,omitempty"`
	NAT     bool   `json:"nat,omitempty"`
}

type persistedForward struct {
	ID      string `json:"id"`
	AgentID string `json:"agent_id"`
	Listen  string `json:"listen"`
	Target  string `json:"target"`
}

type persistedSocks struct {
	ID      string `json:"id"`
	AgentID string `json:"agent_id"`
	Listen  string `json:"listen"`
}

type persistedPublished struct {
	ID      string `json:"id"`
	AgentID string `json:"agent_id"`
	Network string `json:"network"`
}

type persistedState struct {
	Rules     []persistedRule      `json:"rules"`
	Forwards  []persistedForward   `json:"forwards"`
	Socks     []persistedSocks     `json:"socks"`
	Published []persistedPublished `json:"published"`
}

// saveState writes the current policy to disk atomically. It snapshots under the
// read lock and writes outside it, so a slow disk never blocks routing. A no-op
// when no state path is configured.
func (h *hub) saveState() {
	if h.statePath == "" {
		return
	}
	h.mu.RLock()
	var st persistedState
	for _, r := range h.rules {
		st.Rules = append(st.Rules, persistedRule{r.id, r.agentID, r.network.String(), r.random, r.nat})
	}
	for _, f := range h.forwards {
		st.Forwards = append(st.Forwards, persistedForward{f.id, f.agentID, f.listen, f.target})
	}
	for _, sp := range h.socks {
		st.Socks = append(st.Socks, persistedSocks{sp.id, sp.agentID, sp.listen})
	}
	for _, p := range h.published {
		st.Published = append(st.Published, persistedPublished{p.id, p.agentID, p.network.String()})
	}
	h.mu.RUnlock()

	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		log.Printf("state: marshal: %v", err)
		return
	}
	tmp := h.statePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		log.Printf("state: write: %v", err)
		return
	}
	if err := os.Rename(tmp, h.statePath); err != nil {
		log.Printf("state: rename: %v", err)
	}
}

// loadState restores the policy saved by a previous run. Missing file is fine
// (first run). Rules keep their original UUIDs so agents' rules reattach exactly.
func (h *hub) loadState() {
	if h.statePath == "" {
		return
	}
	data, err := os.ReadFile(h.statePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("state: read: %v", err)
		}
		return
	}
	var st persistedState
	if err := json.Unmarshal(data, &st); err != nil {
		log.Printf("state: parse %s: %v", h.statePath, err)
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range st.Rules {
		_, nd, err := net.ParseCIDR(r.Network)
		if err != nil {
			continue
		}
		h.rules[r.ID] = &rule{id: r.ID, agentID: r.AgentID, network: nd, random: r.Random, nat: r.NAT}
	}
	for _, f := range st.Forwards {
		h.forwards[f.ID] = &forward{id: f.ID, agentID: f.AgentID, listen: f.Listen,
			target: f.Target, targetNet: hostNet(f.Target)}
	}
	for _, sp := range st.Socks {
		h.socks[sp.ID] = &socksProxy{id: sp.ID, agentID: sp.AgentID, listen: sp.Listen}
	}
	for _, p := range st.Published {
		_, nd, err := net.ParseCIDR(p.Network)
		if err != nil {
			continue
		}
		h.published[p.ID] = &publishedNet{id: p.ID, agentID: p.AgentID, network: nd}
	}
	log.Printf("state: restored %d rules, %d forwards, %d socks, %d published routes",
		len(st.Rules), len(st.Forwards), len(st.Socks), len(st.Published))
}

// hostNet returns the host part of an "ip:port" target as a /32 (or /128) net,
// matching how cmdForwardAdd derives a forward's auto-route. Returns nil for a
// non-IP target (a hostname), as the live path does.
func hostNet(target string) *net.IPNet {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}
