package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const keySingBoxConfig = "PUNCH_SINGBOX_CONFIG"

type sbUser struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type sbInbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	ListenPort int    `json:"listen_port"`
	Method     string `json:"method"`
	Password   string `json:"password"`
	Network    string `json:"network"`
	Users      []sbUser
	Multiplex  *struct {
		Enabled bool `json:"enabled"`
	} `json:"multiplex"`
	source string
}

// UnmarshalJSON keeps users optional: single-password and multi-user inbounds share the type.
func (in *sbInbound) UnmarshalJSON(b []byte) error {
	type plain sbInbound
	var aux struct {
		plain
		Users []sbUser `json:"users"`
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*in = sbInbound(aux.plain)
	in.Users = aux.Users
	return nil
}

// singBoxFiles mirrors how sing-box loads -c FILE or -C DIR: a directory contributes every *.json
// in it, merged, so an inbound can live in any of them.
func singBoxFiles(path string) ([]string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return []string{path}, nil
	}
	files, err := filepath.Glob(filepath.Join(path, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, fmt.Errorf("%s 里没有 .json 文件", path)
	}
	return files, nil
}

func singBoxInbounds(path string) ([]sbInbound, error) {
	files, err := singBoxFiles(path)
	if err != nil {
		return nil, err
	}
	var all []sbInbound
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var doc struct {
			Inbounds []sbInbound `json:"inbounds"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			return nil, fmt.Errorf("%s 不是合法的 JSON：%v", f, err)
		}
		for i := range doc.Inbounds {
			doc.Inbounds[i].source = f
		}
		all = append(all, doc.Inbounds...)
	}
	return all, nil
}

// singBoxNode builds the client node from the sing-box inbound the agent forwards to, so the
// cipher, password and multiplexing can never drift from what the server actually runs.
func singBoxNode(path, target, name string) (nodeTemplate, error) {
	_, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nodeTemplate{}, fmt.Errorf("转发地址 %q 不对，要是 IP:端口", target)
	}
	port, _ := strconv.Atoi(portStr)
	ins, err := singBoxInbounds(path)
	if err != nil {
		return nodeTemplate{}, fmt.Errorf("读取 sing-box 配置失败：%v", err)
	}
	var hit *sbInbound
	for i := range ins {
		if ins[i].ListenPort == port {
			hit = &ins[i]
			break
		}
	}
	if hit == nil {
		return nodeTemplate{}, fmt.Errorf("sing-box 配置里没有监听 %d 端口的入站", port)
	}
	if hit.Type != "shadowsocks" {
		return nodeTemplate{}, fmt.Errorf("端口 %d 是 %s 入站，暂时只支持 shadowsocks", port, hit.Type)
	}
	pw := hit.Password
	if len(hit.Users) > 0 {
		// A multi-user 2022 inbound takes "serverPSK:userPSK" from clients.
		pw = hit.Password + ":" + hit.Users[0].Password
	}
	if pw == "" || hit.Method == "" {
		return nodeTemplate{}, fmt.Errorf("端口 %d 的入站缺少加密方式或密码", port)
	}
	if hit.Network == "udp" {
		return nodeTemplate{}, fmt.Errorf("端口 %d 的入站只开了 UDP，打洞隧道只能承载 TCP", port)
	}
	return nodeTemplate{
		Name:     name,
		Cipher:   hit.Method,
		Password: pw,
		Smux:     hit.Multiplex != nil && hit.Multiplex.Enabled,
		Source:   fmt.Sprintf("sing-box %s（%s）", strings.TrimSpace(firstNonEmpty(hit.Tag, portStr)), hit.source),
	}, nil
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// defaultSingBoxConfig is where distro packages put it; the systemd unit runs `-C /etc/sing-box`.
func defaultSingBoxConfig() string {
	for _, p := range []string{"/etc/sing-box", "/usr/local/etc/sing-box"} {
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			return p
		}
	}
	return ""
}
