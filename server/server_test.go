package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	if err := addUser(p, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := addUser(p, "alice"); err == nil {
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
