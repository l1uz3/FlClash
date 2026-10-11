package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// PUNCH_* environment variables override the file, so a unit can change one key.
type config struct {
	values map[string]string
}

func loadConfig(path string) (*config, error) {
	c := &config{values: map[string]string{}}
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for n := 1; sc.Scan(); n++ {
			l := strings.TrimSpace(sc.Text())
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			k, v, ok := strings.Cut(l, "=")
			if !ok {
				return nil, fmt.Errorf("%s:%d: expected KEY=VALUE", path, n)
			}
			c.values[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok && strings.HasPrefix(k, "PUNCH_") {
			c.values[k] = v
		}
	}
	return c, nil
}

func (c *config) str(key, def string) string {
	if v := c.values[key]; v != "" {
		return v
	}
	return def
}

func (c *config) need(key string) (string, error) {
	if v := c.values[key]; v != "" {
		return v, nil
	}
	return "", fmt.Errorf("%s is required", key)
}

func (c *config) int(key string, def int) (int, error) {
	v := c.values[key]
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a number", key, v)
	}
	return n, nil
}

type coordConfig struct {
	Listen     string
	PublicAddr string
	ProbePorts [2]string
	Agent      string
	AgentKey   string
	ServerIP   string // public IP of the firewalled server, as clients reach it
	LearnPort  int    // port on the server clients send their sacrificial SYNs to
	ConePorts  [2]int // source-port range the agent dials back from for cone NAT clients
	Tokens     string
	State      string
	Firewall   firewall
	FanHi      int
	RemoveWait int
}

func coordFromConfig(c *config) (*coordConfig, error) {
	cc := &coordConfig{
		Listen:     c.str("PUNCH_LISTEN", ":48080"),
		PublicAddr: c.str("PUNCH_PUBLIC_ADDR", ""),
		ProbePorts: [2]string{c.str("PUNCH_PROBE_A", ":48082"), c.str("PUNCH_PROBE_B", ":48084")},
		Tokens:     c.str("PUNCH_TOKENS", "/etc/punch/tokens"),
		State:      c.str("PUNCH_STATE", "/var/lib/punch"),
	}
	var err error
	if cc.Agent, err = c.need("PUNCH_AGENT"); err != nil {
		return nil, err
	}
	if cc.AgentKey, err = c.need("PUNCH_AGENT_KEY"); err != nil {
		return nil, err
	}
	if cc.ServerIP, err = c.need("PUNCH_SERVER_IP"); err != nil {
		return nil, err
	}
	if cc.LearnPort, err = c.int("PUNCH_LEARN_PORT", 45000); err != nil {
		return nil, err
	}
	if cc.ConePorts[0], err = c.int("PUNCH_CONE_PORT_BASE", 49000); err != nil {
		return nil, err
	}
	if cc.ConePorts[1], err = c.int("PUNCH_CONE_PORT_COUNT", 500); err != nil {
		return nil, err
	}
	if cc.FanHi, err = c.int("PUNCH_FAN_WINDOW", 300); err != nil {
		return nil, err
	}
	// A fresh SYN that beats a slow removal is admitted as allow-listed and dies with the entry.
	if cc.RemoveWait, err = c.int("PUNCH_REMOVE_WAIT", 6); err != nil {
		return nil, err
	}
	if cc.Firewall, err = firewallFromConfig(c); err != nil {
		return nil, err
	}
	return cc, nil
}

type agentConfig struct {
	Listen    string
	Key       string
	Iface     string
	Target    string
	WindowKiB int
}

func agentFromConfig(c *config) (*agentConfig, error) {
	ac := &agentConfig{Iface: c.str("PUNCH_IFACE", "eth0")}
	var err error
	if ac.Listen, err = c.need("PUNCH_AGENT_LISTEN"); err != nil {
		return nil, err
	}
	if ac.Key, err = c.need("PUNCH_AGENT_KEY"); err != nil {
		return nil, err
	}
	if ac.Target, err = c.need("PUNCH_TARGET"); err != nil {
		return nil, err
	}
	// yamux's 256 KiB default caps a stream at ~26 Mbit/s over 100 ms; 16 MiB measured ~200.
	if ac.WindowKiB, err = c.int("PUNCH_WINDOW_KIB", 16384); err != nil {
		return nil, err
	}
	if ac.WindowKiB < 256 {
		ac.WindowKiB = 256
	}
	return ac, nil
}
