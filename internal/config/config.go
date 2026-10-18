// Package config parses the valky server INI configuration. Clients no longer
// use a config file; they pass --ip/--port/--passwd on the command line and
// receive their virtual IP and routes from the server at runtime.
package config

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// ServerConfig is the validated server configuration.
type ServerConfig struct {
	Listen  string     // host:port to listen on
	Key     string     // shared secret clients must present
	Overlay *net.IPNet // virtual network from which client IPs are allocated
	Encrypt bool       // require an encrypted transport (also settable via --encrypt)
}

// LoadServer reads and validates the server config.
//
//	[server]
//	listen  = 0.0.0.0:9000
//	key     = change-me
//	overlay = 10.9.0.0/24
func LoadServer(path string) (*ServerConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	vals := map[string]string{}
	var section string
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		i := strings.Index(line, "=")
		if i < 0 {
			return nil, fmt.Errorf("config: line %d: expected 'key = value'", n)
		}
		key := strings.ToLower(strings.TrimSpace(line[:i]))
		val := strings.TrimSpace(line[i+1:])
		vals[section+"."+key] = val
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	cfg := &ServerConfig{
		Listen: vals["server.listen"],
		Key:    vals["server.key"],
	}
	if cfg.Listen == "" {
		return nil, fmt.Errorf("config: [server] listen is required")
	}
	if cfg.Key == "" {
		return nil, fmt.Errorf("config: [server] key is required")
	}
	overlay := vals["server.overlay"]
	if overlay == "" {
		return nil, fmt.Errorf("config: [server] overlay (e.g. 10.9.0.0/24) is required")
	}
	_, nd, err := net.ParseCIDR(overlay)
	if err != nil {
		return nil, fmt.Errorf("config: invalid overlay %q: %w", overlay, err)
	}
	cfg.Overlay = nd
	switch strings.ToLower(vals["server.encrypt"]) {
	case "1", "true", "yes", "on":
		cfg.Encrypt = true
	}
	return cfg, nil
}
