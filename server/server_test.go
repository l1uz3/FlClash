package main

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) *config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "punch.env")
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestConfigEnvOverridesFile(t *testing.T) {
	t.Setenv("PUNCH_LISTEN", ":1")
	c := writeConfig(t, "# comment\nPUNCH_LISTEN=:2\nPUNCH_AGENT=\"10.0.0.2:48081\"\n")
	if got := c.str("PUNCH_LISTEN", ""); got != ":1" {
		t.Fatalf("environment must win over the file, got %q", got)
	}
	if got := c.str("PUNCH_AGENT", ""); got != "10.0.0.2:48081" {
		t.Fatalf("quotes not stripped: %q", got)
	}
}

func TestCoordinatorNeedsCoreSettings(t *testing.T) {
	if _, err := coordFromConfig(writeConfig(t, "PUNCH_AGENT=a:1\nPUNCH_AGENT_KEY=k\n")); err == nil {
		t.Fatal("missing PUNCH_SERVER_IP must be an error")
	}
	cc, err := coordFromConfig(writeConfig(t, "PUNCH_AGENT=a:1\nPUNCH_AGENT_KEY=k\nPUNCH_SERVER_IP=203.0.113.10\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cc.Firewall.enabled() {
		t.Fatal("no add URL must mean cone-only")
	}
}

// Without a pin a client could terminate TLS on its side of the relay and read the URL's secret.
func TestFirewallRefusesUnpinnedAddURL(t *testing.T) {
	base := "PUNCH_AGENT=a:1\nPUNCH_AGENT_KEY=k\nPUNCH_SERVER_IP=203.0.113.10\nPUNCH_FW_ADD_URL=https://198.51.100.1/add/SECRET\nPUNCH_FW_REMOVE=/bin/true\n"
	if _, err := coordFromConfig(writeConfig(t, base)); err == nil {
		t.Fatal("an add URL without a pin must be rejected")
	}
	cc, err := coordFromConfig(writeConfig(t, base+"PUNCH_FW_ADD_PIN="+strings.Repeat("ab", 32)+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	hp, _, path := cc.Firewall.addTarget()
	if hp != "198.51.100.1:443" || strings.Contains(hp, "SECRET") || path != "/add/SECRET" {
		t.Fatalf("client must only learn host:port: hp=%q path=%q", hp, path)
	}
}

func TestFirewallRemoveSubstitutesCIDR(t *testing.T) {
	fw := firewall{Remove: []string{"echo", "rm", "{cidr}", "now"}}
	if got := fw.remove("203.0.113.0/24"); got != "rm 203.0.113.0/24 now" {
		t.Fatalf("placeholder: %q", got)
	}
	fw.Remove = []string{"echo", "rm"}
	if got := fw.remove("203.0.113.0/24"); got != "rm 203.0.113.0/24" {
		t.Fatalf("appended: %q", got)
	}
}

func TestPrefixOf(t *testing.T) {
	if got := prefixOf("203.0.113.77", 24); got != "203.0.113.0/24" {
		t.Fatal(got)
	}
}

func TestClimbIgnoresIdleNAT(t *testing.T) {
	if _, rate := climb(synSeen{port: 1000, ts: 1}, synSeen{port: 1010, ts: 3.2}); rate != 0 {
		t.Fatalf("a 10-port gap is noise, got rate %v", rate)
	}
	port, rate := climb(synSeen{port: 1000, ts: 1}, synSeen{port: 1440, ts: 3.2})
	if port != 1440 || rate < 199 || rate > 201 {
		t.Fatalf("port %d rate %v", port, rate)
	}
	if _, rate := climb(synSeen{port: 65400, ts: 1}, synSeen{port: 1500, ts: 3}); rate <= 0 {
		t.Fatal("a wrap back to low ports is still a climb")
	}
}

func TestPredictWidensForClimbingNAT(t *testing.T) {
	c, lo, hi := predict(10000, 0, 9, -50, 300)
	if c != 10000 || lo != -50 || hi != 300 {
		t.Fatalf("idle NAT must keep the window: %d %d %d", c, lo, hi)
	}
	c, lo, hi = predict(10000, 100, 9, -50, 300)
	if c != 10900 || lo != -200 || hi != 400 {
		t.Fatalf("climbing NAT: %d %d %d", c, lo, hi)
	}
}

func TestTokensAddAndRevoke(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tokens")
	if _, err := addUser(p, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := addUser(p, "alice"); err == nil {
		t.Fatal("duplicate user must be refused")
	}
	b, _ := os.ReadFile(p)
	tok := strings.Fields(string(b))[1]
	if userForToken(p, tok) != "alice" || userForToken(p, tok+"x") != "" || userForToken(p, "") != "" {
		t.Fatal("token lookup")
	}
	os.WriteFile(p, []byte("# revoked\n"), 0600)
	if userForToken(p, tok) != "" {
		t.Fatal("removing the line must revoke the user")
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0600 {
		t.Fatalf("tokens file mode %v", fi.Mode().Perm())
	}
}

func TestRelaysDeliverOnce(t *testing.T) {
	r := newRelays()
	id, ch := r.expect()
	a, b := net.Pipe()
	defer b.Close()
	if !r.deliver(id, a) || r.deliver(id, a) {
		t.Fatal("a relay id must be usable exactly once")
	}
	if <-ch != a {
		t.Fatal("wrong connection delivered")
	}
}

func TestCoordinatorCertIsStable(t *testing.T) {
	dir := t.TempDir()
	_, fp1, err := coordTLS(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, fp2, _ := coordTLS(dir)
	fp3, _ := certFingerprint(filepath.Join(dir, "coord.crt"))
	if fp1 != fp2 || fp1 != fp3 || len(fp1) != 64 {
		t.Fatal("clients pin this fingerprint; it must not change across restarts")
	}
}

func TestRemoveUserRevokes(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tokens")
	a, _ := addUser(p, "alice")
	b, _ := addUser(p, "bob")
	if err := removeUser(p, "alice"); err != nil {
		t.Fatal(err)
	}
	if userForToken(p, a.Token) != "" || userForToken(p, b.Token) != "bob" {
		t.Fatal("only alice must be revoked")
	}
	if err := removeUser(p, "alice"); err == nil {
		t.Fatal("removing a missing user must be an error")
	}
}

// The panel edits the operator's config file; comments and keys it does not manage must survive.
func TestSetEnvKeysKeepsOtherLines(t *testing.T) {
	p := filepath.Join(t.TempDir(), "punch.env")
	os.WriteFile(p, []byte("# keep me\nPUNCH_AGENT=a:1\nPUNCH_OTHER=x\n"), 0600)
	if err := setEnvKeys(p, map[string]string{"PUNCH_AGENT": "b:2", "PUNCH_NEW": "y"}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	want := "# keep me\nPUNCH_AGENT=b:2\nPUNCH_OTHER=x\nPUNCH_NEW=y\n"
	if string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestRenderClientYAMLLoadsAsProfile(t *testing.T) {
	tpl := nodeTemplate{Name: "my node", Cipher: "2022-blake3-aes-256-gcm", Password: "pw"}
	ci := clientInfo{Coordinator: "203.0.113.20:48080", Fingerprint: strings.Repeat("ab", 32), ProbePorts: [2]int{48082, 48084}}
	y := renderClientYAML(tpl, ci, user{"alice", "tok"})
	for _, want := range []string{"name: \"my node\"", "token: \"tok\"", "coordinator: 203.0.113.20:48080", "max-connections: 1", "MATCH,PROXY"} {
		if !strings.Contains(y, want) {
			t.Fatalf("missing %q in:\n%s", want, y)
		}
	}
	if strings.Contains(y, "probe-ports") {
		t.Fatal("default probe ports must not be written out")
	}
	ci.ProbePorts = [2]int{58082, 58084}
	if !strings.Contains(renderClientYAML(tpl, ci, user{"a", "t"}), "probe-ports: [58082, 58084]") {
		t.Fatal("non-default probe ports must be written out")
	}
}

func TestUserConfigNeedsSetup(t *testing.T) {
	c := writeConfig(t, "PUNCH_SINGBOX_CONFIG=off\nPUNCH_STATE="+t.TempDir()+"\n")
	if _, err := userConfig(c, user{"a", "t"}); err == nil {
		t.Fatal("a config without SS password must not be printed")
	}
}

func writeSingBox(t *testing.T, dir, file, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, file), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSingBoxNodeFollowsInbound(t *testing.T) {
	dir := t.TempDir()
	writeSingBox(t, dir, "00-log.json", `{"log":{"level":"info"}}`)
	writeSingBox(t, dir, "10-in.json", `{"inbounds":[
		{"type":"vless","listen_port":443},
		{"type":"shadowsocks","tag":"ss-34120","listen_port":34120,"method":"2022-blake3-aes-256-gcm","password":"srv","multiplex":{"enabled":true}},
		{"type":"shadowsocks","listen_port":8388,"method":"aes-128-gcm","password":"p2"},
		{"type":"shadowsocks","listen_port":9000,"method":"2022-blake3-aes-128-gcm","password":"srv","users":[{"name":"a","password":"u1"}],"multiplex":{"enabled":true}},
		{"type":"shadowsocks","listen_port":9100,"method":"aes-128-gcm","password":"x","network":"udp"}]}`)

	n, err := singBoxNode(dir, "198.51.100.1:34120", "node")
	if err != nil {
		t.Fatal(err)
	}
	if n.Cipher != "2022-blake3-aes-256-gcm" || n.Password != "srv" || n.Name != "node" {
		t.Fatalf("34120: %+v", n)
	}
	if n, _ := singBoxNode(dir, "198.51.100.1:9000", "x"); n.Password != "srv:u1" {
		t.Fatalf("multi-user 2022 needs server:user PSK, got %q", n.Password)
	}
	for target, why := range map[string]string{
		"198.51.100.1:1":    "no inbound on that port",
		"198.51.100.1:443":  "not shadowsocks",
		"198.51.100.1:9100": "UDP only",
		"198.51.100.1:8388": "multiplex off: the client always uses smux",
		"no-port":           "bad target",
	} {
		if _, err := singBoxNode(dir, target, "x"); err == nil {
			t.Errorf("%s: expected an error (%s)", target, why)
		}
	}
}

func TestResolveNodeSingBoxThenTemplate(t *testing.T) {
	dir := t.TempDir()
	writeSingBox(t, dir, "config.json", `{"inbounds":[{"type":"shadowsocks","listen_port":34120,"method":"m","password":"from-singbox","multiplex":{"enabled":true}}]}`)
	base := "PUNCH_TARGET_HINT=198.51.100.1:34120\nPUNCH_NODE_PASSWORD=from-template\n"

	n, err := resolveNode(writeConfig(t, base+"PUNCH_SINGBOX_CONFIG="+dir+"\n"))
	if err != nil || n.Password != "from-singbox" {
		t.Fatalf("sing-box must win: %+v %v", n, err)
	}
	n, err = resolveNode(writeConfig(t, base+"PUNCH_SINGBOX_CONFIG=off\n"))
	if err != nil || n.Password != "from-template" {
		t.Fatalf("off must use the template: %+v %v", n, err)
	}
	// A sing-box config that exists but has no matching inbound is an error, never a silent
	// fallback to a template that may be stale.
	bad := "PUNCH_TARGET_HINT=198.51.100.1:9\nPUNCH_NODE_PASSWORD=x\nPUNCH_SINGBOX_CONFIG=" + dir + "\n"
	if _, err := resolveNode(writeConfig(t, bad)); err == nil {
		t.Fatal("mismatched sing-box must be reported")
	}
}

func TestRenderAlwaysUsesSmux(t *testing.T) {
	ci := clientInfo{Coordinator: "203.0.113.20:48080", Fingerprint: strings.Repeat("ab", 32), ProbePorts: [2]int{48082, 48084}}
	y := renderClientYAML(nodeTemplate{Name: "n", Cipher: "c", Password: "p"}, ci, user{"a", "t"})
	for _, want := range []string{"udp: true", "enabled: true", "protocol: h2mux", "max-connections: 1"} {
		if !strings.Contains(y, want) {
			t.Fatalf("missing %q:\n%s", want, y)
		}
	}
}

func TestInstallTicketSingleUseAndExpiry(t *testing.T) {
	dir := t.TempDir()
	tk := installTicket{Code: strings.Repeat("c", 32), Expires: time.Now().Add(time.Minute), Key: "k"}
	if err := writeTicket(dir, tk); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(ticketPath(dir)); fi.Mode().Perm() != 0600 {
		t.Fatal("the ticket holds the agent key and must be root-only")
	}
	if _, ok := takeTicket(dir, strings.Repeat("d", 32), false); ok {
		t.Fatal("wrong code accepted")
	}
	if _, ok := takeTicket(dir, tk.Code, false); !ok {
		t.Fatal("valid code refused")
	}
	if _, ok := takeTicket(dir, tk.Code, true); !ok {
		t.Fatal("done call refused")
	}
	if _, ok := takeTicket(dir, tk.Code, false); ok {
		t.Fatal("a consumed ticket must not be reusable")
	}
	tk.Expires = time.Now().Add(-time.Second)
	writeTicket(dir, tk)
	if _, ok := takeTicket(dir, tk.Code, false); ok {
		t.Fatal("expired ticket accepted")
	}
}

func TestCoordinatorPortServesInstallAndTLS(t *testing.T) {
	state := t.TempDir()
	tlsCfg, _, err := coordTLS(state)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	co := &coordinator{cfg: &coordConfig{State: state, PublicAddr: raw.Addr().String()}}
	ln := newTLSListener(raw, tlsCfg, co.serveInstall)
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { c.(*tls.Conn).Handshake(); c.Write([]byte("tls-ok\n")); c.Close() }()
		}
	}()
	code := strings.Repeat("e", 32)
	writeTicket(state, installTicket{Code: code, Expires: time.Now().Add(time.Minute), Listen: "10.0.0.2:48081", Key: "secret", Target: "127.0.0.1:1"})

	get := func(path string) (int, string) {
		r, err := http.Get("http://" + raw.Addr().String() + path)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, string(b)
	}
	if st, _ := get("/install/" + strings.Repeat("x", 32)); st != 404 {
		t.Fatalf("wrong code: %d", st)
	}
	st, body := get("/install/" + code)
	if st != 200 || !strings.Contains(body, "PUNCH_AGENT_KEY=secret") || !strings.Contains(body, "/install/"+code+"/punch") {
		t.Fatalf("script: %d\n%s", st, body)
	}
	if st, _ := get("/install/" + code + "/done"); st != 200 {
		t.Fatalf("done: %d", st)
	}
	if st, _ := get("/install/" + code); st != 404 {
		t.Fatal("the link must close once the install reports done")
	}

	c, err := tls.Dial("tcp", raw.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("TLS clients must still reach the coordinator: %v", err)
	}
	l, _ := bufio.NewReader(c).ReadString('\n')
	c.Close()
	if l != "tls-ok\n" {
		t.Fatalf("tls: %q", l)
	}
}
