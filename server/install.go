package main

import (
	"bufio"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Written by the panel, served by the coordinator: they are separate processes. Holds the agent key.
type installTicket struct {
	Code    string    `json:"code"`
	Expires time.Time `json:"expires"`
	Listen  string    `json:"listen"`
	Key     string    `json:"key"`
	Target  string    `json:"target"`
}

const ticketTTL = 10 * time.Minute

var ticketMu sync.Mutex

func ticketPath(state string) string { return strings.TrimRight(state, "/") + "/install_ticket.json" }

func writeTicket(state string, t installTicket) error {
	b, _ := json.Marshal(t)
	return writeFileAtomic(ticketPath(state), b, 0600)
}

// consume closes the window as soon as the script reports done, so a code cannot be replayed.
func takeTicket(state, code string, consume bool) (installTicket, bool) {
	ticketMu.Lock()
	defer ticketMu.Unlock()
	var t installTicket
	b, err := os.ReadFile(ticketPath(state))
	if err != nil || json.Unmarshal(b, &t) != nil {
		return t, false
	}
	if time.Now().After(t.Expires) {
		os.Remove(ticketPath(state))
		return t, false
	}
	if len(code) != len(t.Code) || subtle.ConstantTimeCompare([]byte(code), []byte(t.Code)) != 1 {
		return t, false
	}
	if consume {
		os.Remove(ticketPath(state))
	}
	return t, true
}

func isHTTP(br *bufio.Reader) bool {
	b, err := br.Peek(4)
	return err == nil && string(b) == "GET "
}

func (co *coordinator) serveInstall(c net.Conn, br *bufio.Reader) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Minute))
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	notFound := func() { io.WriteString(c, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") }
	parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	if len(parts) < 2 || parts[0] != "install" {
		notFound()
		return
	}
	code, what := parts[1], "script"
	if len(parts) == 3 {
		what = parts[2]
	}
	t, ok := takeTicket(co.cfg.State, code, what == "done")
	if !ok {
		notFound()
		return
	}
	host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	var body []byte
	ctype := "text/plain; charset=utf-8"
	switch what {
	case "script":
		logf("coord", "agent install script fetched from %s", host)
		body = []byte(agentScript(co.cfg.PublicAddr, t))
	case "punch":
		self, err := selfPath()
		if err == nil {
			body, err = os.ReadFile(self)
		}
		if err != nil {
			notFound()
			return
		}
		ctype = "application/octet-stream"
	case "done":
		logf("coord", "agent install finished on %s; install link closed", host)
		body = []byte("ok\n")
	default:
		notFound()
		return
	}
	fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", ctype, len(body))
	c.Write(body)
}

// Serves this host's own binary, so both ends run one version; another arch fails the version check.
func agentScript(pub string, t installTicket) string {
	base := "http://" + pub + "/install/" + t.Code
	return `#!/usr/bin/env bash
set -euo pipefail
red() { printf '\033[31m%s\033[0m\n' "$*" >&2; }
[ "$(id -u)" = 0 ] || { red "请用 root 运行"; exit 1; }
command -v systemctl >/dev/null || { red "需要 systemd"; exit 1; }
if ! command -v tcpdump >/dev/null || ! command -v iptables >/dev/null; then
  if command -v apt-get >/dev/null; then
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tcpdump iptables >/dev/null
  elif command -v dnf >/dev/null; then dnf install -y -q tcpdump iptables
  elif command -v yum >/dev/null; then yum install -y -q tcpdump iptables
  else red "请先手动安装 tcpdump 和 iptables"; exit 1; fi
fi
tmp="$(mktemp)"
curl -fsS -o "$tmp" "` + base + `/punch"
chmod 755 "$tmp"
"$tmp" version >/dev/null 2>&1 || { rm -f "$tmp"; red "程序无法在这台机器上运行（架构和本机不同？）"; exit 1; }
install -d -m 700 /etc/punch
[ -f /usr/local/bin/punch ] && cp -p /usr/local/bin/punch /usr/local/bin/punch.bak
install -m 755 "$tmp" /usr/local/bin/punch
rm -f "$tmp"
iface="$(ip route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')"
umask 077
cat >/etc/punch/punch.env <<EOF
PUNCH_AGENT_LISTEN=` + t.Listen + `
PUNCH_AGENT_KEY=` + t.Key + `
PUNCH_TARGET=` + t.Target + `
PUNCH_IFACE=${iface:-eth0}
EOF
echo agent >/etc/punch/role
cat >/etc/systemd/system/punch-agent.service <<EOF
[Unit]
Description=punch agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/punch agent -config /etc/punch/punch.env
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable punch-agent >/dev/null
systemctl restart punch-agent
sleep 1
systemctl is-active --quiet punch-agent || { red "启动失败：journalctl -u punch-agent -n 30"; exit 1; }
curl -fsS -o /dev/null "` + base + `/done" || true
printf '\033[32m%s\033[0m\n' "已安装并运行。回到另一台机器的面板查看连接状态。"
`
}

// tlsListener hands TLS connections to the coordinator and diverts plain HTTP install fetches, so
// installs need no extra port. Sniffing runs per connection, so a slow client cannot stall Accept.
type tlsListener struct {
	net.Listener
	cfg     *tls.Config
	install func(net.Conn, *bufio.Reader)
	conns   chan net.Conn
	errs    chan error
}

func newTLSListener(ln net.Listener, cfg *tls.Config, install func(net.Conn, *bufio.Reader)) *tlsListener {
	l := &tlsListener{Listener: ln, cfg: cfg, install: install, conns: make(chan net.Conn), errs: make(chan error, 1)}
	go l.loop()
	return l
}

func (l *tlsListener) loop() {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			l.errs <- err
			return
		}
		go func() {
			br := bufio.NewReader(c)
			c.SetReadDeadline(time.Now().Add(15 * time.Second))
			plain := isHTTP(br)
			c.SetReadDeadline(time.Time{})
			if plain {
				l.install(&bufConn{Conn: c, r: br}, br)
				return
			}
			l.conns <- tls.Server(&bufConn{Conn: c, r: br}, l.cfg)
		}()
	}
}

func (l *tlsListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case err := <-l.errs:
		return nil, err
	}
}
