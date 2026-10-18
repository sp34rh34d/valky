package main

import (
	"io"
	"net"
	"testing"
)

// Cifrado: con la misma clave, cliente y server derivan las mismas claves y los
// datos viajan AEAD en ambos sentidos.
func TestSecureHandshakeRoundTrip(t *testing.T) {
	psk := []byte("shared-key")
	cc, sc := net.Pipe()
	type res struct {
		conn net.Conn
		enc  bool
		err  error
	}
	sch := make(chan res, 1)
	go func() {
		conn, enc, err := secureServerHandshake(sc, psk, true)
		sch <- res{conn, enc, err}
	}()
	ccon, cenc, cerr := secureClientHandshake(cc, psk, true)
	if cerr != nil {
		t.Fatalf("client handshake: %v", cerr)
	}
	s := <-sch
	if s.err != nil {
		t.Fatalf("server handshake: %v", s.err)
	}
	if !cenc || !s.enc {
		t.Fatal("expected encryption active on both ends")
	}

	// server echoes one 5-byte message
	go func() {
		buf := make([]byte, 5)
		if _, err := io.ReadFull(s.conn, buf); err == nil {
			s.conn.Write(buf)
		}
	}()
	if _, err := ccon.Write([]byte("hello")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(ccon, got); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("round-trip got %q, want %q", got, "hello")
	}
}

// Una clave distinta en cada extremo: el handshake completa, pero el primer
// registro cifrado no se puede descifrar (autenticación vía PSK).
func TestSecureHandshakeWrongKey(t *testing.T) {
	cc, sc := net.Pipe()
	type res struct {
		conn net.Conn
		err  error
	}
	sch := make(chan res, 1)
	go func() {
		conn, _, err := secureServerHandshake(sc, []byte("server-key"), true)
		sch <- res{conn, err}
	}()
	ccon, _, cerr := secureClientHandshake(cc, []byte("client-key"), true)
	if cerr != nil {
		t.Fatalf("client handshake: %v", cerr)
	}
	s := <-sch
	if s.err != nil {
		t.Fatalf("server handshake: %v", s.err)
	}
	go ccon.Write([]byte("hello"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(s.conn, buf); err == nil {
		t.Fatal("expected decryption to fail with mismatched keys")
	}
}

// Server en texto plano + cliente que exige cifrado: el cliente rechaza.
func TestSecureClientRequiresEnc(t *testing.T) {
	cc, sc := net.Pipe()
	go secureServerHandshake(sc, []byte("k"), false) // plaintext server
	if _, _, err := secureClientHandshake(cc, []byte("k"), true); err == nil {
		t.Fatal("client with --encrypt must refuse a plaintext server")
	}
}
