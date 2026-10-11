package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type nodeTemplate struct {
	Name     string
	Cipher   string
	Password string
	Smux     bool
}

const (
	keyNodeName     = "PUNCH_NODE_NAME"
	keyNodeCipher   = "PUNCH_NODE_CIPHER"
	keyNodePassword = "PUNCH_NODE_PASSWORD"
	keyNodeSmux     = "PUNCH_NODE_SMUX"
	keyPublicAddr   = "PUNCH_PUBLIC_ADDR"
)

func templateFromConfig(c *config) nodeTemplate {
	return nodeTemplate{
		Name:     c.str(keyNodeName, "punch"),
		Cipher:   c.str(keyNodeCipher, "2022-blake3-aes-256-gcm"),
		Password: c.str(keyNodePassword, ""),
		Smux:     c.str(keyNodeSmux, "true") != "false",
	}
}

type clientInfo struct {
	Coordinator string
	Fingerprint string
	ProbePorts  [2]int
}

func probePort(listen string) int {
	_, p, err := splitHostPortLoose(listen)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

func splitHostPortLoose(addr string) (string, string, error) {
	i := strings.LastIndexByte(addr, ':')
	if i < 0 {
		return "", "", fmt.Errorf("缺少端口: %q", addr)
	}
	return addr[:i], addr[i+1:], nil
}

// renderClientYAML is a complete profile, not just the node: a bare proxies list imports into
// FlClash but sends everything DIRECT under the default rule mode, which looks broken.
func renderClientYAML(t nodeTemplate, ci clientInfo, u user) string {
	var b strings.Builder
	q := strconv.Quote
	fmt.Fprintf(&b, "proxies:\n")
	fmt.Fprintf(&b, "  - name: %s\n", q(t.Name))
	fmt.Fprintf(&b, "    type: ss\n")
	fmt.Fprintf(&b, "    server: 0.0.0.0\n")
	fmt.Fprintf(&b, "    port: 1\n")
	fmt.Fprintf(&b, "    cipher: %s\n", t.Cipher)
	fmt.Fprintf(&b, "    password: %s\n", q(t.Password))
	fmt.Fprintf(&b, "    udp: true\n")
	if t.Smux {
		fmt.Fprintf(&b, "    smux:\n")
		fmt.Fprintf(&b, "      enabled: true\n")
		fmt.Fprintf(&b, "      protocol: h2mux\n")
		fmt.Fprintf(&b, "      max-connections: 1\n")
		fmt.Fprintf(&b, "      padding: false\n")
	}
	fmt.Fprintf(&b, "    punch:\n")
	fmt.Fprintf(&b, "      coordinator: %s\n", ci.Coordinator)
	fmt.Fprintf(&b, "      fingerprint: %s\n", ci.Fingerprint)
	fmt.Fprintf(&b, "      token: %s\n", q(u.Token))
	if ci.ProbePorts != [2]int{48082, 48084} {
		fmt.Fprintf(&b, "      probe-ports: [%d, %d]\n", ci.ProbePorts[0], ci.ProbePorts[1])
	}
	fmt.Fprintf(&b, "\nproxy-groups:\n")
	fmt.Fprintf(&b, "  - name: PROXY\n")
	fmt.Fprintf(&b, "    type: select\n")
	fmt.Fprintf(&b, "    proxies: [%s, DIRECT]\n", q(t.Name))
	fmt.Fprintf(&b, "\nrules:\n")
	fmt.Fprintf(&b, "  - GEOIP,LAN,DIRECT,no-resolve\n")
	fmt.Fprintf(&b, "  - GEOIP,CN,DIRECT\n")
	fmt.Fprintf(&b, "  - MATCH,PROXY\n")
	return b.String()
}

// Fails while setup is incomplete rather than printing a config that cannot connect.
func clientInfoFor(c *config) (clientInfo, error) {
	pub := c.str(keyPublicAddr, "")
	if pub == "" {
		return clientInfo{}, fmt.Errorf("还没有设置本机对外地址（%s），请先运行初始化", keyPublicAddr)
	}
	fp, err := certFingerprint(statePath(c, "coord.crt"))
	if err != nil {
		return clientInfo{}, fmt.Errorf("还没有证书，请先启动协调服务器")
	}
	return clientInfo{
		Coordinator: pub,
		Fingerprint: fp,
		ProbePorts: [2]int{
			probePort(c.str("PUNCH_PROBE_A", ":48082")),
			probePort(c.str("PUNCH_PROBE_B", ":48084")),
		},
	}, nil
}

func userConfig(c *config, u user) (string, error) {
	t := templateFromConfig(c)
	if t.Password == "" {
		return "", fmt.Errorf("节点模板还没有设置 SS 密码，请在菜单「节点模板」里设置")
	}
	ci, err := clientInfoFor(c)
	if err != nil {
		return "", err
	}
	return renderClientYAML(t, ci, u), nil
}

func statePath(c *config, name string) string {
	return strings.TrimRight(c.str("PUNCH_STATE", "/var/lib/punch"), "/") + "/" + name
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
