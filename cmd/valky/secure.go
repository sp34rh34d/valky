package main

// Optional transport encryption for the client<->server link. When the server is
// started with --encrypt, it offers an authenticated, forward-secret channel:
//
//   - ephemeral X25519 key exchange (fresh per connection) for forward secrecy;
//   - the pre-shared key (config.ini `key` / the client's --passwd) is mixed into
//     the key derivation, so a man-in-the-middle without the key cannot derive the
//     session keys — the first record simply fails to decrypt;
//   - AES-256-GCM per-record AEAD (confidentiality + integrity).
//
// A short hello negotiates the mode, so a plaintext server and client still
// interoperate. All of this uses only the standard library (no new dependencies),
// keeping valky a single self-contained binary.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	secMagic            = "VLKY"
	secVersion          = 1
	secModePlain        = 0
	secModeEnc          = 1
	secFlagEncCapable   = 0x01
	secHelloLen         = 54 // magic(4) ver(1) mode/flags(1) ephPub(32) nonce(16)
	secMaxRecord        = 16384
	secHandshakeTimeout = 10 * time.Second
)

// writeHello sends the 54-byte greeting. modeOrFlags carries the client's
// capability flags (client hello) or the server's chosen mode (server hello).
func writeHello(conn net.Conn, modeOrFlags byte, ephPub, nonce []byte) error {
	buf := make([]byte, 0, secHelloLen)
	buf = append(buf, secMagic...)
	buf = append(buf, secVersion, modeOrFlags)
	buf = append(buf, ephPub...)
	buf = append(buf, nonce...)
	_, err := conn.Write(buf)
	return err
}

func readHello(conn net.Conn) (modeOrFlags byte, ephPub, nonce []byte, err error) {
	buf := make([]byte, secHelloLen)
	if _, err = io.ReadFull(conn, buf); err != nil {
		return 0, nil, nil, err
	}
	if string(buf[:4]) != secMagic {
		return 0, nil, nil, errors.New("secure: bad magic (not a valky peer, or protocol mismatch)")
	}
	if buf[4] != secVersion {
		return 0, nil, nil, fmt.Errorf("secure: unsupported protocol version %d", buf[4])
	}
	return buf[5], buf[6:38], buf[38:54], nil
}

// deriveKeys mixes the ECDH shared secret with the pre-shared key and both
// nonces, yielding one key per direction. Both peers compute the same salt and
// ikm, so they agree on the keys only if they share the pre-shared key.
func deriveKeys(shared, psk, clientNonce, serverNonce []byte) (c2s, s2c []byte, err error) {
	salt := append(append([]byte{}, clientNonce...), serverNonce...)
	ikm := append(append([]byte{}, shared...), psk...)
	if c2s, err = hkdf.Key(sha256.New, ikm, salt, "valky c2s v1", 32); err != nil {
		return nil, nil, err
	}
	if s2c, err = hkdf.Key(sha256.New, ikm, salt, "valky s2c v1", 32); err != nil {
		return nil, nil, err
	}
	return c2s, s2c, nil
}

// secureClientHandshake offers encryption and follows the server's choice. If
// requireEnc is set it refuses a plaintext server (downgrade protection). It
// returns the connection to use for all subsequent frames (wrapped when encrypted)
// and whether encryption is active.
func secureClientHandshake(conn net.Conn, psk []byte, requireEnc bool) (net.Conn, bool, error) {
	conn.SetDeadline(time.Now().Add(secHandshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, false, err
	}
	cNonce := make([]byte, 16)
	if _, err := rand.Read(cNonce); err != nil {
		return nil, false, err
	}
	if err := writeHello(conn, secFlagEncCapable, priv.PublicKey().Bytes(), cNonce); err != nil {
		return nil, false, err
	}
	mode, sPub, sNonce, err := readHello(conn)
	if err != nil {
		return nil, false, err
	}
	if mode != secModeEnc {
		if requireEnc {
			return nil, false, errors.New("secure: --encrypt is set but the server offered a plaintext link")
		}
		return conn, false, nil
	}
	remote, err := curve.NewPublicKey(sPub)
	if err != nil {
		return nil, false, err
	}
	shared, err := priv.ECDH(remote)
	if err != nil {
		return nil, false, err
	}
	c2s, s2c, err := deriveKeys(shared, psk, cNonce, sNonce)
	if err != nil {
		return nil, false, err
	}
	sc, err := newSecureConn(conn, s2c /*read*/, c2s /*write*/)
	return sc, true, err
}

// secureServerHandshake reads the client hello and, when wantEnc is set and the
// client is capable, establishes an encrypted channel. When wantEnc is false it
// stays plaintext. If wantEnc is set but the client cannot encrypt, it refuses.
func secureServerHandshake(conn net.Conn, psk []byte, wantEnc bool) (net.Conn, bool, error) {
	conn.SetDeadline(time.Now().Add(secHandshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	flags, cPub, cNonce, err := readHello(conn)
	if err != nil {
		return nil, false, err
	}
	if !wantEnc {
		if err := writeHello(conn, secModePlain, make([]byte, 32), make([]byte, 16)); err != nil {
			return nil, false, err
		}
		return conn, false, nil
	}
	if flags&secFlagEncCapable == 0 {
		_ = writeHello(conn, secModePlain, make([]byte, 32), make([]byte, 16))
		return nil, false, errors.New("secure: server requires encryption but the client does not support it")
	}
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, false, err
	}
	sNonce := make([]byte, 16)
	if _, err := rand.Read(sNonce); err != nil {
		return nil, false, err
	}
	if err := writeHello(conn, secModeEnc, priv.PublicKey().Bytes(), sNonce); err != nil {
		return nil, false, err
	}
	remote, err := curve.NewPublicKey(cPub)
	if err != nil {
		return nil, false, err
	}
	shared, err := priv.ECDH(remote)
	if err != nil {
		return nil, false, err
	}
	c2s, s2c, err := deriveKeys(shared, psk, cNonce, sNonce)
	if err != nil {
		return nil, false, err
	}
	sc, err := newSecureConn(conn, c2s /*read*/, s2c /*write*/)
	return sc, true, err
}

// secureConn wraps a net.Conn with per-record AES-GCM. Each record is a 2-byte
// big-endian ciphertext length followed by the ciphertext; the 96-bit nonce is a
// per-direction counter (not transmitted). Keys are fresh per connection, so the
// counters safely restart at zero on every (re)connect.
type secureConn struct {
	net.Conn
	enc, dec cipher.AEAD
	wmu      sync.Mutex
	wseq     uint64
	rmu      sync.Mutex
	rseq     uint64
	rbuf     []byte // decrypted plaintext not yet consumed by Read
}

func newSecureConn(conn net.Conn, readKey, writeKey []byte) (*secureConn, error) {
	rb, err := aes.NewCipher(readKey)
	if err != nil {
		return nil, err
	}
	dec, err := cipher.NewGCM(rb)
	if err != nil {
		return nil, err
	}
	wb, err := aes.NewCipher(writeKey)
	if err != nil {
		return nil, err
	}
	enc, err := cipher.NewGCM(wb)
	if err != nil {
		return nil, err
	}
	return &secureConn{Conn: conn, enc: enc, dec: dec}, nil
}

func secNonce(seq uint64) []byte {
	var n [12]byte
	binary.BigEndian.PutUint64(n[4:], seq)
	return n[:]
}

func (s *secureConn) Write(p []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > secMaxRecord {
			n = secMaxRecord
		}
		ct := s.enc.Seal(nil, secNonce(s.wseq), p[:n], nil)
		s.wseq++
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(len(ct)))
		if _, err := s.Conn.Write(hdr[:]); err != nil {
			return total, err
		}
		if _, err := s.Conn.Write(ct); err != nil {
			return total, err
		}
		p = p[n:]
		total += n
	}
	return total, nil
}

func (s *secureConn) Read(p []byte) (int, error) {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	if len(s.rbuf) == 0 {
		var hdr [2]byte
		if _, err := io.ReadFull(s.Conn, hdr[:]); err != nil {
			return 0, err
		}
		clen := int(binary.BigEndian.Uint16(hdr[:]))
		if clen == 0 || clen > secMaxRecord+16 {
			return 0, errors.New("secure: invalid record length")
		}
		ct := make([]byte, clen)
		if _, err := io.ReadFull(s.Conn, ct); err != nil {
			return 0, err
		}
		pt, err := s.dec.Open(nil, secNonce(s.rseq), ct, nil)
		if err != nil {
			return 0, errors.New("secure: decryption failed (wrong key or tampered data)")
		}
		s.rseq++
		s.rbuf = pt
	}
	n := copy(p, s.rbuf)
	s.rbuf = s.rbuf[n:]
	return n, nil
}
