package main

import (
	"bufio"
	"context"
	"io"
	"log"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/hashicorp/yamux"
)

func logf(role, f string, a ...any) { log.Printf("%-5s "+f, append([]any{role}, a...)...) }

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func readLine(c net.Conn, br *bufio.Reader, d time.Duration) (string, error) {
	c.SetReadDeadline(time.Now().Add(d))
	l, err := br.ReadString('\n')
	c.SetReadDeadline(time.Time{})
	return strings.TrimSpace(l), err
}

// Simultaneous open needs every SYN of a round to leave from the port the NAT already mapped.
func reuseDialer(localPort int, timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		LocalAddr: &net.TCPAddr{Port: localPort},
		Timeout:   timeout,
		Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) { serr = setReuse(fd) }); err != nil {
				return err
			}
			return serr
		},
	}
}

func punchDial(localPort int, remote string, dur time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(dur)
	d := reuseDialer(localPort, 2*time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := d.Dial("tcp", remote)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		time.Sleep(200 * time.Millisecond)
	}
	return nil, lastErr
}

func yamuxCfg(windowKiB int) *yamux.Config {
	c := yamux.DefaultConfig()
	c.MaxStreamWindowSize = uint32(windowKiB) * 1024
	c.EnableKeepAlive = true
	c.KeepAliveInterval = 10 * time.Second // doubles as the NAT keepalive
	c.ConnectionWriteTimeout = 20 * time.Second
	c.LogOutput = io.Discard
	return c
}

func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		a.Close()
		b.Close()
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
}

// A relayed TLS ClientHello can arrive in the same read as the "RELAY <id>" line.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func withTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
