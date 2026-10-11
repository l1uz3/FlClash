package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const maxBinary = 64 << 20

func selfPath() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(p)
}

// The restarted process answers the coordinator's next PING, which is how it learns the update took.
func (a *agent) receivePush(c net.Conn, br *bufio.Reader, f []string) {
	size, err := strconv.ParseInt(f[2], 10, 64)
	if err != nil || size <= 0 || size > maxBinary {
		fmt.Fprintf(c, "PUSHFAIL bad size\n")
		return
	}
	want := strings.ToLower(f[3])
	self, err := selfPath()
	if err != nil {
		fmt.Fprintf(c, "PUSHFAIL %v\n", err)
		return
	}
	tmp := self + ".push"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
	if err != nil {
		fmt.Fprintf(c, "PUSHFAIL %v\n", err)
		return
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Minute))
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(br, size))
	out.Close()
	c.SetReadDeadline(time.Time{})
	if err != nil || n != size {
		os.Remove(tmp)
		fmt.Fprintf(c, "PUSHFAIL short read\n")
		return
	}
	if hex.EncodeToString(h.Sum(nil)) != want {
		os.Remove(tmp)
		fmt.Fprintf(c, "PUSHFAIL checksum mismatch\n")
		return
	}
	if v, err := exec.Command(tmp, "version").Output(); err != nil || strings.TrimSpace(string(v)) != f[4] {
		os.Remove(tmp)
		fmt.Fprintf(c, "PUSHFAIL binary does not run on this host\n")
		return
	}
	if err := os.Rename(self, self+".bak"); err != nil {
		os.Remove(tmp)
		fmt.Fprintf(c, "PUSHFAIL %v\n", err)
		return
	}
	if err := os.Rename(tmp, self); err != nil {
		os.Rename(self+".bak", self)
		fmt.Fprintf(c, "PUSHFAIL %v\n", err)
		return
	}
	fmt.Fprintf(c, "PUSHOK %s\n", f[4])
	c.Close()
	logf("agent", "updated to %s, restarting", f[4])
	unit := os.Getenv("PUNCH_UNIT")
	if unit == "" {
		unit = unitAgent
	}
	exec.Command("systemctl", "--no-block", "restart", unit).Run()
}

// pushToAgent sends binPath to the agent and waits for it to answer on the new version. The agent
// keeps the previous binary as .bak, so a version that never answers can be rolled back.
func pushToAgent(addr, key, binPath, ver string) error {
	b, err := os.ReadFile(binPath)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("连不上白名单服务器 %s：%v", addr, err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Minute))
	fmt.Fprintf(c, "PUSH %s %d %s %s\n", key, len(b), hex.EncodeToString(sum[:]), ver)
	if _, err := c.Write(b); err != nil {
		return fmt.Errorf("发送失败：%v", err)
	}
	l, err := readLine(c, bufio.NewReader(c), time.Minute)
	if err != nil {
		return fmt.Errorf("白名单服务器没有回应：%v", err)
	}
	if !strings.HasPrefix(l, "PUSHOK") {
		return fmt.Errorf("白名单服务器拒绝更新：%s", strings.TrimPrefix(l, "PUSHFAIL "))
	}
	for i := 0; i < 20; i++ {
		time.Sleep(time.Second)
		if agentVersion(addr, key) == ver {
			return nil
		}
	}
	return fmt.Errorf("白名单服务器已收到 %s，但重启后没有回应", ver)
}
