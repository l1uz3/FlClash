package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	unitCoordinator = "punch-coordinator"
	unitAgent       = "punch-agent"
)

func systemctl(args ...string) (string, error) {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func unitActive(unit string) bool {
	s, _ := systemctl("is-active", unit)
	return s == "active"
}

func unitInstalled(unit string) bool {
	return fileExists("/etc/systemd/system/" + unit + ".service")
}

// A wrong key connects and gets no reply; a dead agent does not connect at all.
func pingAgent(addr, key string) error {
	c, err := net.DialTimeout("tcp", addr, 4*time.Second)
	if err != nil {
		return fmt.Errorf("连不上白名单服务器 %s：%v（检查内网是否互通、那台机器上的安装命令是否运行成功）", addr, err)
	}
	defer c.Close()
	fmt.Fprintf(c, "PING %s\n", key)
	l, err := readLine(c, bufio.NewReader(c), 4*time.Second)
	if err != nil || !strings.HasPrefix(l, "PONG") {
		return fmt.Errorf("连上了白名单服务器 %s，但它没有回应（多半是两边的密钥不一致，重新运行一次菜单 5 给出的命令）", addr)
	}
	return nil
}

func agentVersion(addr, key string) string {
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return ""
	}
	defer c.Close()
	fmt.Fprintf(c, "PING %s\n", key)
	l, _ := readLine(c, bufio.NewReader(c), 3*time.Second)
	if f := strings.Fields(l); len(f) == 2 && f[0] == "PONG" {
		return f[1]
	}
	return ""
}

func pendingCount(c *config) int {
	b, err := os.ReadFile(statePath(c, "wl_pending"))
	if err != nil {
		return 0
	}
	n := 0
	for _, l := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	return n
}

// Called directly rather than through a relay, the endpoint allow-lists this host, not a client.
func testFirewall(fw firewall) (added string, err error) {
	hp, _, _ := fw.addTarget()
	conn, err := net.DialTimeout("tcp", hp, 8*time.Second)
	if err != nil {
		return "", fmt.Errorf("连不上加白地址 %s：%v", hp, err)
	}
	added, err = fw.addVia(conn)
	if err != nil {
		return "", fmt.Errorf("加白失败：%v", err)
	}
	out, rmErr := fw.removeErr(added)
	if rmErr != nil {
		return added, fmt.Errorf("加白成功（%s），但删白失败：%s\n  这个网段现在还在白名单里，请手动删除", added, out)
	}
	return added, nil
}
