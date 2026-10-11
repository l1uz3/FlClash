package main

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type coordinator struct {
	cfg     *coordConfig
	relays  *relays
	pending *pending
	seq     atomic.Int64
}

func runCoordinator(cfg *coordConfig) error {
	tlsCfg, fp, err := coordTLS(cfg.State)
	if err != nil {
		return fmt.Errorf("TLS setup: %v", err)
	}
	logf("coord", "certificate fingerprint (clients pin this): %s", fp)
	raw, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	// Plaintext NAT probes: each echoes the public ip:port it sees. The same local port showing up
	// with one public port on both tells the client its NAT preserves ports (cone).
	for _, pp := range cfg.ProbePorts {
		pl, err := net.Listen("tcp", pp)
		if err != nil {
			return fmt.Errorf("probe %s: %v", pp, err)
		}
		go serveProbe(pl)
	}
	co := &coordinator{cfg: cfg, relays: newRelays(), pending: newPending(cfg.State, cfg.Firewall)}
	if cfg.Firewall.enabled() {
		go co.pending.janitor()
	} else {
		logf("coord", "PUNCH_FW_ADD_URL not set: only clients behind port-preserving NAT can connect")
	}
	ln := newTLSListener(raw, tlsCfg, co.serveInstall)
	logf("coord", "listening on %s, agent %s, server %s", cfg.Listen, cfg.Agent, cfg.ServerIP)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go co.handle(c, co.seq.Add(1))
	}
}

func serveProbe(pl net.Listener) {
	for {
		c, err := pl.Accept()
		if err != nil {
			continue
		}
		fmt.Fprintf(c, "SEEN %s\n", c.RemoteAddr())
		c.Close()
	}
}

func (co *coordinator) handle(c net.Conn, sess int64) {
	handedOff := false
	defer func() {
		if !handedOff {
			c.Close()
		}
	}()
	br := bufio.NewReader(c)
	hello, _ := readLine(c, br, 15*time.Second)
	f := strings.Fields(hello)
	if len(f) == 2 && f[0] == "RELAY" {
		var rc net.Conn = c
		if br.Buffered() > 0 {
			rc = &bufConn{Conn: c, r: br}
		}
		handedOff = co.relays.deliver(f[1], rc)
		return
	}
	if len(f) < 3 || f[0] != "HELLO" {
		logf("coord", "bad hello from %s", c.RemoteAddr())
		return
	}
	user := userForToken(co.cfg.Tokens, f[1])
	if user == "" {
		logf("coord", "bad hello from %s", c.RemoteAddr())
		return
	}
	host, port, _ := net.SplitHostPort(c.RemoteAddr().String())
	logf("coord", "session %d user %s mode %s from %s:%s", sess, user, f[2], host, port)
	switch f[2] {
	case "ctunnel":
		co.cone(c, br, sess, host, port)
	case "tunnel":
		co.symmetric(c, br, f, user, host)
	default:
		fmt.Fprintf(c, "ERR unknown mode\n")
	}
}

// cone: the client's NAT keeps its local port, so the public port the coordinator sees is the one
// the server must dial. No allow-listing is involved.
func (co *coordinator) cone(c net.Conn, br *bufio.Reader, sess int64, host, port string) {
	agent, err := co.dialAgent()
	if err != nil {
		fmt.Fprintf(c, "ERR agent unreachable\n")
		return
	}
	defer agent.Close()
	src := co.cfg.ConePorts[0] + int(sess)%co.cfg.ConePorts[1]
	fmt.Fprintf(c, "ASSIGN %s %d %s\n", co.cfg.ServerIP, src, c.RemoteAddr())
	time.Sleep(300 * time.Millisecond)
	fmt.Fprintf(agent, "CTUN %s %s %s %d\n", co.cfg.AgentKey, host, port, src)
	relayLogs(c, br, agent)
}

// symmetric: the client's NAT picks a new public port per destination, so the server has to see
// one. The client is allow-listed just long enough to send two sacrificial SYNs; the agent learns
// the port and how fast the NAT climbs, the entry is removed, and the agent dials back the fresh
// tuples it predicts. Those survive because the server initiated them.
func (co *coordinator) symmetric(c net.Conn, br *bufio.Reader, f []string, user, host string) {
	fw := co.cfg.Firewall
	if !fw.enabled() {
		fmt.Fprintf(c, "ERR this server only accepts port-preserving NAT\n")
		return
	}
	// HELLO <token> tunnel <window> <wait> <attempts> ...: the client opens <attempts> fresh tuples.
	want := 4
	if len(f) >= 6 {
		if n, err := strconv.Atoi(f[5]); err == nil && n >= 1 && n <= 16 {
			want = n
		}
	}
	agent, err := co.dialAgent()
	if err != nil {
		fmt.Fprintf(c, "ERR agent unreachable\n")
		return
	}
	defer agent.Close()
	abr := bufio.NewReader(agent)

	cidr := prefixOf(host, fw.Prefix)
	added := false
	defer func() {
		if added {
			logf("coord", "cleanup: removing %s after aborted session: %s", cidr, fw.remove(cidr))
			co.pending.done(cidr)
		}
	}()
	addHP, _, _ := fw.addTarget()
	rid, relayCh := co.relays.expect()
	defer co.relays.drop(rid)
	fmt.Fprintf(c, "WLRELAY %s %s %s %d\n", rid, addHP, co.cfg.ServerIP, co.cfg.LearnPort)
	var relay net.Conn
	select {
	case relay = <-relayCh:
	case <-time.After(20 * time.Second):
		logf("coord", "user %s: no allow-list relay arrived", user)
		return
	}
	co.pending.mark(cidr)
	added = true
	got, err := fw.addVia(relay)
	if err != nil {
		logf("coord", "user %s: allow-list via relay failed: %v", user, err)
		fmt.Fprintf(c, "ERR allow-list failed\n")
		return
	}
	if got != cidr { // carrier NAT pools can present another address to the endpoint
		co.pending.done(cidr)
		cidr = got
		co.pending.mark(cidr)
	}
	fmt.Fprintf(c, "WLOK %s\n", cidr)

	fmt.Fprintf(agent, "LEARN %s %s %d\n", co.cfg.AgentKey, cidr, co.cfg.LearnPort)
	if l, _ := readLine(agent, abr, 15*time.Second); l != "READY" {
		logf("coord", "agent not ready: %q", l)
		return
	}
	fmt.Fprintf(c, "GO\n")
	learned, _ := readLine(agent, abr, 25*time.Second)
	lf := strings.Fields(learned)
	if len(lf) != 3 || lf[0] != "LEARNED" {
		logf("coord", "agent did not learn a port: %q", learned)
		fmt.Fprintf(agent, "ABORT\n")
		return
	}
	xip, xport := lf[1], lf[2]

	logf("coord", "removing %s: %s", cidr, fw.remove(cidr))
	co.pending.done(cidr)
	added = false
	time.Sleep(time.Duration(co.cfg.RemoveWait) * time.Second)

	fmt.Fprintf(c, "PREDICT %s %d %s:%s\n", co.cfg.ServerIP, co.cfg.LearnPort, xip, xport)
	if fr, _ := readLine(c, br, 15*time.Second); !strings.HasPrefix(fr, "FRESH") {
		logf("coord", "client opened no fresh tuples: %q", fr)
		fmt.Fprintf(agent, "ABORT\n")
		return
	}
	hi := co.cfg.FanHi
	lo := max(-hi/6, -50)
	time.Sleep(300 * time.Millisecond)
	// The agent serves every tuple that lands; the client keeps the first few and closes the rest.
	fmt.Fprintf(agent, "TUNNEL %s %s %d %d %d\n", xip, xport, lo, hi, want)
	relayLogs(c, br, agent)
}

func (co *coordinator) dialAgent() (net.Conn, error) {
	return net.DialTimeout("tcp", co.cfg.Agent, 5*time.Second)
}

// relayLogs keeps both control connections open until either side hangs up, logging the agent's
// result lines.
func relayLogs(c net.Conn, cbr *bufio.Reader, agent net.Conn) {
	go func() {
		r := bufio.NewReader(agent)
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				c.Close()
				return
			}
			logf("coord", "agent: %s", strings.TrimSpace(l))
		}
	}()
	for {
		if _, err := cbr.ReadString('\n'); err != nil {
			return
		}
	}
}
