package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// userForToken looks tok up in the tokens file ("name token" per line). The file is re-read on
// every login so a user can be added or revoked without restarting the coordinator.
func userForToken(path, tok string) string {
	if tok == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Fields(l)
		if len(f) == 2 && subtle.ConstantTimeCompare([]byte(f[1]), []byte(tok)) == 1 {
			return f[0]
		}
	}
	return ""
}

func newToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// coordTLS loads the coordinator's self-signed certificate, creating it on first start, and
// returns the SHA-256 fingerprint clients pin.
func coordTLS(stateDir string) (*tls.Config, string, error) {
	certPath, keyPath := filepath.Join(stateDir, "coord.crt"), filepath.Join(stateDir, "coord.key")
	if _, err := os.Stat(certPath); err != nil {
		if err := genSelfSigned(stateDir, certPath, keyPath); err != nil {
			return nil, "", err
		}
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, "", err
	}
	fp := sha256.Sum256(cert.Certificate[0])
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}, hex.EncodeToString(fp[:]), nil
}

func certFingerprint(certPath string) (string, error) {
	b, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return "", os.ErrInvalid
	}
	fp := sha256.Sum256(blk.Bytes)
	return hex.EncodeToString(fp[:]), nil
}

func genSelfSigned(dir, certPath, keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "punch-coordinator"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(20, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0600); err != nil {
		return err
	}
	return os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644)
}

// relays pairs a client's "RELAY <id>" connection with the session waiting for it.
type relays struct {
	mu sync.Mutex
	m  map[string]chan net.Conn
}

func newRelays() *relays { return &relays{m: map[string]chan net.Conn{}} }

func (r *relays) expect() (string, chan net.Conn) {
	b := make([]byte, 16)
	rand.Read(b)
	id := hex.EncodeToString(b)
	ch := make(chan net.Conn, 1)
	r.mu.Lock()
	r.m[id] = ch
	r.mu.Unlock()
	return id, ch
}

func (r *relays) drop(id string) {
	r.mu.Lock()
	delete(r.m, id)
	r.mu.Unlock()
}

func (r *relays) deliver(id string, c net.Conn) bool {
	r.mu.Lock()
	ch, ok := r.m[id]
	delete(r.m, id)
	r.mu.Unlock()
	if ok {
		ch <- c
	}
	return ok
}
