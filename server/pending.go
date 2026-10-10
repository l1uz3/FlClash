package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// pending records every CIDR a session may have allow-listed, before the client is told to add
// it, so a coordinator that is killed mid-session (and never runs its deferred cleanup) still
// removes it: on start and every 30s, entries older than a minute are removed.
type pending struct {
	mu   sync.Mutex
	path string
	fw   firewall
}

func newPending(stateDir string, fw firewall) *pending {
	return &pending{path: filepath.Join(stateDir, "wl_pending"), fw: fw}
}

func (p *pending) load() map[string]int64 {
	m := map[string]int64{}
	b, err := os.ReadFile(p.path)
	if err != nil {
		return m
	}
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) == 2 {
			t, _ := strconv.ParseInt(f[1], 10, 64)
			m[f[0]] = t
		}
	}
	return m
}

func (p *pending) save(m map[string]int64) {
	os.MkdirAll(filepath.Dir(p.path), 0700)
	var sb strings.Builder
	for k, v := range m {
		fmt.Fprintf(&sb, "%s %d\n", k, v)
	}
	os.WriteFile(p.path+".tmp", []byte(sb.String()), 0600)
	os.Rename(p.path+".tmp", p.path)
}

func (p *pending) mark(cidr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	m := p.load()
	m[cidr] = time.Now().Unix()
	p.save(m)
}

func (p *pending) done(cidr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	m := p.load()
	delete(m, cidr)
	p.save(m)
}

func (p *pending) janitor() {
	for {
		p.mu.Lock()
		var stale []string
		for k, t := range p.load() {
			if time.Now().Unix()-t > 60 {
				stale = append(stale, k)
			}
		}
		p.mu.Unlock()
		for _, k := range stale {
			logf("coord", "janitor: removing stale allow-list entry %s: %s", k, p.fw.remove(k))
			p.done(k)
		}
		time.Sleep(30 * time.Second)
	}
}
