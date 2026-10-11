package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// The add endpoint allow-lists whoever calls it, so the request must come from the client's
// address; the client relays a raw socket and TLS runs here, keeping the URL's secret off it.
type firewall struct {
	AddURL    string
	AddPin    string         // SHA-256 of the add endpoint's certificate
	AddResult *regexp.Regexp // pulls the allow-listed CIDR or IP out of the response body
	Remove    []string       // argv; "{cidr}" is replaced, or the CIDR is appended
	Prefix    int            // CIDR width when the endpoint reports a bare IP
}

func firewallFromConfig(c *config) (firewall, error) {
	fw := firewall{AddURL: c.str("PUNCH_FW_ADD_URL", "")}
	if fw.AddURL == "" {
		return fw, nil // cone-NAT clients only: symmetric clients get a clear refusal
	}
	if _, err := url.Parse(fw.AddURL); err != nil {
		return fw, fmt.Errorf("PUNCH_FW_ADD_URL: %v", err)
	}
	fw.AddPin = normalizePin(c.str("PUNCH_FW_ADD_PIN", ""))
	if len(fw.AddPin) != 64 {
		return fw, fmt.Errorf("PUNCH_FW_ADD_PIN is required with PUNCH_FW_ADD_URL: without it a client could terminate TLS itself and read the URL")
	}
	re, err := regexp.Compile(c.str("PUNCH_FW_ADD_RESULT", `"currentIp":"([0-9.]+)\\?/(\d+)"`))
	if err != nil {
		return fw, fmt.Errorf("PUNCH_FW_ADD_RESULT: %v", err)
	}
	fw.AddResult = re
	rm, err := c.need("PUNCH_FW_REMOVE")
	if err != nil {
		return fw, fmt.Errorf("%v when PUNCH_FW_ADD_URL is set: entries must be removed", err)
	}
	fw.Remove = strings.Fields(rm)
	if fw.Prefix, err = c.int("PUNCH_FW_PREFIX", 24); err != nil {
		return fw, err
	}
	return fw, nil
}

func (fw firewall) enabled() bool { return fw.AddURL != "" }

func normalizePin(s string) string { return strings.ToLower(strings.ReplaceAll(s, ":", "")) }

func (fw firewall) addTarget() (hostport, sni, path string) {
	u, _ := url.Parse(fw.AddURL)
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(u.Hostname(), port), u.Hostname(), u.RequestURI()
}

func (fw firewall) addVia(relay net.Conn) (string, error) {
	defer relay.Close()
	_, sni, path := fw.addTarget()
	tc := tls.Client(relay, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // endpoints are often self-signed on a bare IP; trust is the pin
		VerifyPeerCertificate: func(certs [][]byte, _ [][]*x509.Certificate) error {
			if len(certs) == 0 {
				return fmt.Errorf("no certificate")
			}
			got := sha256.Sum256(certs[0])
			if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(got[:])), []byte(fw.AddPin)) != 1 {
				return fmt.Errorf("certificate mismatch: the relay is not reaching the add endpoint")
			}
			return nil
		},
	})
	tc.SetDeadline(time.Now().Add(20 * time.Second))
	if err := tc.Handshake(); err != nil {
		return "", fmt.Errorf("TLS via relay: %v", err)
	}
	req := "GET " + path + " HTTP/1.1\r\nHost: " + sni + "\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(tc, req); err != nil {
		return "", err
	}
	body, _ := io.ReadAll(io.LimitReader(tc, 64<<10))
	m := fw.AddResult.FindSubmatch(body)
	if m == nil {
		return "", fmt.Errorf("add response has no allow-listed address (%q)", firstLine(string(body)))
	}
	if len(m) >= 3 && len(m[2]) > 0 {
		return string(m[1]) + "/" + string(m[2]), nil
	}
	return prefixOf(string(m[1]), fw.Prefix), nil
}

func (fw firewall) remove(cidr string) string {
	out, err := fw.removeErr(cidr)
	if err != nil {
		return "remove failed: " + err.Error() + " " + out
	}
	return out
}

func (fw firewall) removeErr(cidr string) (string, error) {
	argv := make([]string, 0, len(fw.Remove)+1)
	replaced := false
	for _, a := range fw.Remove {
		if strings.Contains(a, "{cidr}") {
			a = strings.ReplaceAll(a, "{cidr}", cidr)
			replaced = true
		}
		argv = append(argv, a)
	}
	if !replaced {
		argv = append(argv, cidr)
	}
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
	return firstLine(string(out)), err
}

func prefixOf(ip string, bits int) string {
	addr := net.ParseIP(ip).To4()
	if addr == nil {
		return ip
	}
	return (&net.IPNet{IP: addr.Mask(net.CIDRMask(bits, 32)), Mask: net.CIDRMask(bits, 32)}).String()
}
