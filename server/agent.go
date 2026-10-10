package main

import (
	"bufio"
	"crypto/subtle"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hashicorp/yamux"
)

type agent struct{ cfg *agentConfig }

func runAgent(cfg *agentConfig) error {
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	logf("agent", "listening for the coordinator on %s, forwarding to %s", cfg.Listen, cfg.Target)
	a := &agent{cfg: cfg}
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go a.handle(c)
	}
}

func (a *agent) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	line, err := readLine(c, br, 15*time.Second)
	if err != nil {
		return
	}
	f := strings.Fields(line)
	if len(f) < 2 || subtle.ConstantTimeCompare([]byte(f[1]), []byte(a.cfg.Key)) != 1 {
		logf("agent", "bad request from %s", c.RemoteAddr())
		return
	}
	switch {
	case f[0] == "CTUN" && len(f) == 5: // CTUN key clientIP clientPort srcPort
		src, _ := strconv.Atoi(f[4])
		remote := net.JoinHostPort(f[2], f[3])
		conn, err := punchDial(src, remote, 10*time.Second)
		if err != nil {
			fmt.Fprintf(c, "punch FAIL %v\n", err)
			return
		}
		fmt.Fprintf(c, "tunnel OK direct %s <-> %s\n", conn.LocalAddr(), conn.RemoteAddr())
		go a.serve("cone", conn)
	case f[0] == "LEARN" && len(f) == 4: // LEARN key cidr port
		port, _ := strconv.Atoi(f[3])
		a.learn(c, br, f[2], port)
	}
}

func (a *agent) serve(role string, conn net.Conn) {
	sess, err := yamux.Server(conn, yamuxCfg(a.cfg.WindowKiB))
	if err != nil {
		conn.Close()
		return
	}
	logf(role, "tunnel up %s", conn.RemoteAddr())
	streams := 0
	for {
		st, err := sess.Accept()
		if err != nil {
			logf(role, "tunnel down %s after %d streams: %v", conn.RemoteAddr(), streams, err)
			sess.Close()
			return
		}
		streams++
		go func() {
			up, err := net.DialTimeout("tcp", a.cfg.Target, 10*time.Second)
			if err != nil {
				st.Close()
				return
			}
			splice(st, up)
		}()
	}
}

var synLine = regexp.MustCompile(`IP\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>`)

type synSeen struct {
	ip   string
	port int
	ts   float64
}

func (a *agent) learn(c net.Conn, br *bufio.Reader, cidr string, port int) {
	// The sacrificial SYNs are dropped so the kernel does not RST them: a reset would tear down
	// the client's pending connect and the NAT mapping we are trying to observe.
	rule := []string{"-p", "tcp", "-s", cidr, "--dport", strconv.Itoa(port),
		"--tcp-flags", "SYN,ACK,FIN,RST", "SYN", "-j", "DROP"}
	exec.Command("iptables", append([]string{"-I", "INPUT"}, rule...)...).Run()
	defer exec.Command("iptables", append([]string{"-D", "INPUT"}, rule...)...).Run()

	filter := fmt.Sprintf("tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0 and src net %s and dst port %d", cidr, port)
	td := exec.Command("timeout", "25", "tcpdump", "-nn", "-tt", "-l", "-i", a.cfg.Iface, filter)
	out, err := td.StdoutPipe()
	if err != nil {
		fmt.Fprintf(c, "LEARNFAIL %v\n", err)
		return
	}
	if err := td.Start(); err != nil {
		fmt.Fprintf(c, "LEARNFAIL tcpdump: %v\n", err)
		return
	}
	time.Sleep(500 * time.Millisecond) // tcpdump must be attached before the client sends
	fmt.Fprintf(c, "READY\n")

	first, second := captureSYNs(out)
	if td.Process != nil {
		td.Process.Signal(syscall.SIGTERM)
	}
	td.Wait()
	if first.port == 0 {
		fmt.Fprintf(c, "LEARNFAIL no SYN seen\n")
		return
	}
	captured, rate := climb(first, second)
	at := time.Now()
	logf("agent", "learned %s port %d, NAT climbing %.1f ports/s", first.ip, captured, rate)
	fmt.Fprintf(c, "LEARNED %s %d\n", first.ip, captured)

	cmd, err := readLine(c, br, 30*time.Second)
	df := strings.Fields(cmd)
	if err != nil || len(df) != 6 || df[0] != "TUNNEL" {
		return
	}
	lo, _ := strconv.Atoi(df[3])
	hi, _ := strconv.Atoi(df[4])
	want, _ := strconv.Atoi(df[5])
	center, lo, hi := predict(captured, rate, time.Since(at).Seconds(), lo, hi)
	logf("agent", "dialing %s:%d%+d..%+d for %d tuples", df[1], center, lo, hi, want)
	n := 0
	fanDial(port, df[1], center, lo, hi, want, 20*time.Second, 4*time.Second, func(i int, conn net.Conn) {
		n++
		go a.serve(fmt.Sprintf("tun#%d", i+1), conn)
	})
	if n == 0 {
		fmt.Fprintf(c, "punch FAIL no predicted port answered\n")
		return
	}
	fmt.Fprintf(c, "tunnel OK %d/%d sessions\n", n, want)
}

// Retransmits of the first SYN reuse its port, so the second capture must differ.
func captureSYNs(out interface{ Read([]byte) (int, error) }) (synSeen, synSeen) {
	seen := make(chan synSeen, 32)
	go func() {
		r := bufio.NewReader(out)
		for {
			l, err := r.ReadString('\n')
			if m := synLine.FindStringSubmatch(l); m != nil {
				var ts float64
				fmt.Sscanf(l, "%g", &ts)
				p, _ := strconv.Atoi(m[2])
				seen <- synSeen{m[1], p, ts}
			}
			if err != nil {
				close(seen)
				return
			}
		}
	}()
	var first, second synSeen
	var wait <-chan time.Time
	for {
		select {
		case s, ok := <-seen:
			if !ok {
				return first, second
			}
			if first.port == 0 {
				first, wait = s, time.After(5*time.Second)
			} else if s.port != first.port {
				return first, s
			}
		case <-wait:
			return first, second
		}
	}
}

// An idle NAT moves a few ports between the SYNs; divided by ~2s that rate is noise.
func climb(first, second synSeen) (int, float64) {
	if second.port == 0 || second.ts <= first.ts {
		return first.port, 0
	}
	gap := second.port - first.port
	if gap < -20000 { // wrapped from the top of the range back to low ports
		gap += 64512
	}
	if gap < 30 {
		return second.port, 0
	}
	return second.port, float64(gap) / (second.ts - first.ts)
}

func predict(captured int, rate, elapsed float64, lo, hi int) (int, int, int) {
	center := captured + int(rate*elapsed)
	if rate > 2 {
		slack := int(rate*1.5) + 50
		lo = max(min(lo, -slack), -1200)
		hi = min(max(hi, slack*2), 2500)
	}
	if center > 65535 {
		center = 1024 + (center-65536)%64512
	}
	return center, lo, hi
}

func fanDial(src int, ip string, center, lo, hi, want int, dur, extra time.Duration, onConn func(int, net.Conn)) {
	ctx, cancel := withTimeout(dur)
	defer cancel()
	ch := make(chan net.Conn, hi-lo+2)
	d := reuseDialer(src, 0)
	idx := 0
	for off := lo; off <= hi; off++ {
		p := center + off
		if p < 1 || p > 65535 {
			continue
		}
		delay := time.Duration(idx%100) * 10 * time.Millisecond
		if off >= -8 && off <= 16 {
			delay = 0
		}
		idx++
		go func(p int, delay time.Duration) {
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
			remote := net.JoinHostPort(ip, strconv.Itoa(p))
			for ctx.Err() == nil {
				actx, acancel := withTimeout(3 * time.Second)
				conn, err := d.DialContext(actx, "tcp", remote)
				acancel()
				if err == nil {
					ch <- conn
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(300 * time.Millisecond):
				}
			}
		}(p, delay)
	}
	n := 0
	var extraC <-chan time.Time
collect:
	for n < want {
		select {
		case conn := <-ch:
			onConn(n, conn)
			n++
			if extraC == nil {
				extraC = time.After(extra)
			}
		case <-extraC:
			break collect
		case <-ctx.Done():
			break collect
		}
	}
	cancel()
	go func() { // close tuples that land after we stopped collecting
		t := time.After(6 * time.Second)
		for {
			select {
			case conn := <-ch:
				conn.Close()
			case <-t:
				return
			}
		}
	}()
}
