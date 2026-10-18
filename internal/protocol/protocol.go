// Package protocol defines the wire format used between the valky client and
// server. Frames are length-prefixed and sent over a single TCP connection.
//
//	+-----------------+---------+==============+
//	| len (uint16 BE) | type(1) |   payload    |
//	+-----------------+---------+==============+
//
// len covers the type byte plus the payload.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// MessageType identifies the kind of frame being exchanged.
type MessageType byte

const (
	// TypeAuth is sent by the client right after connecting. Payload is three
	// newline-separated lines: "<password>\n<agent-uuid>\n<cidr1,cidr2,...>"
	// where the CIDRs are the local LAN segments the client advertises (may be
	// empty). The agent UUID is a stable identity the client persists, so the
	// operator's rules survive reconnects.
	TypeAuth MessageType = 1
	// TypeAuthOK is the server's reply on success. Payload is the assigned
	// virtual IP in CIDR form, e.g. "10.9.0.2/24".
	TypeAuthOK MessageType = 2
	// TypeAuthFail is the server's reply on failure. Payload is a reason.
	TypeAuthFail MessageType = 3
	// TypeData carries a single raw IP packet (the payload) in either
	// direction once the connection is authenticated.
	TypeData MessageType = 4
	// TypeKeepAlive is an empty frame used to keep the connection alive and
	// to detect dead peers.
	TypeKeepAlive MessageType = 5
	// TypeRoutes is pushed by the server whenever the operator changes the
	// rules. Payload is the full desired set of CIDRs the client should
	// route into the tunnel, comma-separated. The client reconciles its
	// kernel routes to match.
	TypeRoutes MessageType = 6
	// TypeForwards is pushed by the server with the full desired set of local
	// TCP port-forwards for this client. Payload is a comma-separated list of
	// "listenIP:port|targetIP:port" entries. The client reconciles its
	// listeners to match: each accepted connection is proxied, over the
	// tunnel, to the target.
	TypeForwards MessageType = 7

	// The Stream* messages carry userspace TCP streams for port-forwards,
	// independent of any TUN device (so they work without admin privileges).
	// Every payload begins with a 4-byte big-endian stream id.
	//
	// TypeStreamOpen: initiator -> server -> target agent. Payload is
	// id(4) + "targetIP:port". The server relays it to the agent that owns
	// the target network, which dials the target locally.
	TypeStreamOpen MessageType = 8
	// TypeStreamData carries a chunk of stream payload: id(4) + data.
	TypeStreamData MessageType = 9
	// TypeStreamClose closes a stream in either direction: id(4).
	TypeStreamClose MessageType = 10

	// TypeSocks is pushed by the server with the full desired set of local
	// SOCKS5 proxy listeners for this client, as a comma-separated list of
	// "ip:port" addresses. Each CONNECT is carried over the stream mux to the
	// agent owning the destination; the server enforces the agent's route
	// rules as the proxy's ACL. Works without a TUN (no admin needed).
	TypeSocks MessageType = 11

	// TypeMode is sent by the client once it knows its operating mode. Payload
	// is "tunnel" (a TUN device was created, full L3) or "proxy" (userspace
	// forwards/socks only). The server shows it in the console.
	TypeMode MessageType = 12

	// TypeSegments is sent by the client whenever its local LAN segments change
	// (it re-scans periodically). Payload is the full comma-separated CIDR set.
	// The server replaces the agent's advertised segments, so routing follows
	// the host's current networks without reconnecting.
	TypeSegments MessageType = 13

	// TypeDestroy is sent by the server to order an agent to self-destruct:
	// wipe its persisted identity and runtime files, delete its own binary and
	// exit. The server only sends it after the operator confirms with the
	// config.ini key. Payload is empty.
	TypeDestroy MessageType = 14

	// TypeNAT is pushed by the server with the full desired set of networks the
	// agent should masquerade (SNAT) overlay traffic toward, comma-separated
	// (may be empty). These are the networks this agent delivers into its LAN
	// whose rule has egress NAT enabled (on by default; `route --add ... --no-nat`
	// opts out), so destination hosts reply to the agent instead of to the
	// originator's overlay address. The client reconciles its egress NAT rules to
	// match. Tunnel mode only.
	TypeNAT MessageType = 15
)

// MaxPayload is the largest payload we accept in a single frame.
const MaxPayload = 65535 - 1

var errFrameTooBig = errors.New("protocol: frame exceeds maximum size")

// WriteFrame writes a single framed message to w.
func WriteFrame(w io.Writer, t MessageType, payload []byte) error {
	if len(payload) > MaxPayload {
		return errFrameTooBig
	}
	var hdr [3]byte
	binary.BigEndian.PutUint16(hdr[0:2], uint16(len(payload)+1))
	hdr[2] = byte(t)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// ReadFrame reads a single framed message from r.
func ReadFrame(r io.Reader) (MessageType, []byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	if n == 0 {
		return 0, nil, fmt.Errorf("protocol: zero-length frame")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return MessageType(body[0]), body[1:], nil
}
