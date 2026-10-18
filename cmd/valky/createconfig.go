package main

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

// randomMD5Key returns a random 32-char hex key (MD5 of random bytes).
func randomMD5Key() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	sum := md5.Sum(b)
	return hex.EncodeToString(sum[:]), nil
}

// createConfig writes a server config.ini with a random MD5 key. It refuses to
// overwrite an existing file.
func createConfig(path string) error {
	if path == "" {
		path = "config.ini"
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists; remove it first or choose another path", path)
	}
	key, err := randomMD5Key()
	if err != nil {
		return err
	}
	content := fmt.Sprintf(`# ---- valky SERVER configuration ----
[server]
# Listen address for agents (any port you choose)
listen  = 0.0.0.0:9000
# Shared key; agents pass it with --passwd (random MD5)
key     = %s
# Virtual (overlay) network from which agent IPs are assigned
overlay = 10.9.0.0/24
# Require an encrypted link with agents (also settable with --encrypt).
# X25519 key exchange + AES-256-GCM, authenticated by the shared key above.
encrypt = false

# Rules/ACL are configured live from the interactive console
# (commands: ls, route, forward, socks).
`, key)

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return err
	}
	fmt.Printf("%s wrote %s\n", paint(cGreen, "created:"), paint(cCyan, path))
	fmt.Printf("  %s %s\n", paint(cGray, "key:"), paint(cYellow, key))
	fmt.Printf("  %s\n", paint(cGray, "start it with: valky server --config "+path))
	return nil
}
