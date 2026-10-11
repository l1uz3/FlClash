package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func randomHex(n int) string { return newToken()[:n] }

// detectPublicIP asks an echo service; it is only a default the operator confirms.
func detectPublicIP() string {
	cl := &http.Client{Timeout: 5 * time.Second}
	for _, u := range []string{"https://api.ipify.org", "https://ifconfig.me/ip"} {
		r, err := cl.Get(u)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(r.Body, 64))
		r.Body.Close()
		if ip := strings.TrimSpace(string(b)); net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}

func (p *panel) setup() {
	c := p.cfg()
	fmt.Println("\n== 初始化 ==")
	fmt.Println("只问几个必须由你决定的问题，其余自动生成。直接回车使用方括号里的值。")
	fmt.Println("前提：本机和被保护的服务器必须内网互通。")
	def := c.str(keyPublicAddr, "")
	if def == "" {
		if ip := detectPublicIP(); ip != "" {
			def = ip + ":48080"
		}
	}
	pub := p.ask("\n1) 客户端连接本机用的地址（公网IP:端口）", def)
	server := p.ask("2) 被保护服务器的公网 IP（客户端要连到它）", c.str("PUNCH_SERVER_IP", ""))
	agent := p.ask("3) agent 的内网地址（被保护服务器的内网IP:端口）", c.str("PUNCH_AGENT", ""))
	if pub == "" || server == "" || agent == "" {
		fmt.Println(cRed + "三项都要填，已取消。" + cReset)
		p.pause()
		return
	}
	if _, port, err := splitHostPortLoose(pub); err != nil || port == "" {
		fmt.Println(cRed + "第 1 项要带端口，例如 1.2.3.4:48080" + cReset)
		p.pause()
		return
	}
	_, port, _ := splitHostPortLoose(pub)
	kv := map[string]string{
		keyPublicAddr:     pub,
		"PUNCH_LISTEN":    ":" + port,
		"PUNCH_SERVER_IP": server,
		"PUNCH_AGENT":     agent,
		"PUNCH_TOKENS":    c.str("PUNCH_TOKENS", "/etc/punch/tokens"),
		"PUNCH_STATE":     c.str("PUNCH_STATE", "/var/lib/punch"),
	}
	if c.str("PUNCH_AGENT_KEY", "") == "" {
		kv["PUNCH_AGENT_KEY"] = randomHex(48)
	}
	if err := setEnvKeys(p.cfgPath, kv); err != nil {
		fmt.Println(cRed + "写配置失败：" + err.Error() + cReset)
		p.pause()
		return
	}
	os.MkdirAll(kv["PUNCH_STATE"], 0700)
	fmt.Println(cGreen + "\n已保存到 " + p.cfgPath + cReset)
	if unitInstalled(unitCoordinator) {
		systemctl("enable", unitCoordinator)
		if _, err := systemctl("restart", unitCoordinator); err == nil {
			fmt.Println(cGreen + "协调服务器已启动。" + cReset)
		} else {
			fmt.Println(cRed + "协调服务器启动失败，看「查看日志」。" + cReset)
		}
	}
	fmt.Println("\n下一步：")
	fmt.Println("  · 菜单 5：在被保护的服务器上装 agent")
	fmt.Println("  · 菜单 7：设置节点的 SS 密码等")
	fmt.Println("  · 需要支持手机流量时，菜单 6 设置防火墙")
	p.pause()
}

func (p *panel) agentSetup() {
	c := p.cfg()
	agent, key := c.str("PUNCH_AGENT", ""), c.str("PUNCH_AGENT_KEY", "")
	if agent == "" || key == "" {
		fmt.Println(cRed + "请先初始化（菜单 8）。" + cReset)
		p.pause()
		return
	}
	fmt.Println("\n== 接入被保护的服务器 ==")
	target := p.ask("agent 把流量转发到哪（代理服务端地址，如 sing-box）", c.str("PUNCH_TARGET_HINT", "127.0.0.1:34120"))
	setEnvKeys(p.cfgPath, map[string]string{"PUNCH_TARGET_HINT": target})
	fmt.Print("\n在" + cBold + "被保护的服务器" + cReset + "上用 root 运行下面这一行（已包含密钥）：\n\n")
	fmt.Printf("%s\n", agentInstallCommand(agent, key, target))
	fmt.Println("\n它会安装 tcpdump、iptables 和 agent，并设为开机自启。")
	if p.confirm("\n运行完后按 y 测试连接") {
		if err := pingAgent(agent, key); err != nil {
			fmt.Println(cRed + "✗ " + err.Error() + cReset)
		} else {
			fmt.Println(cGreen + "✓ agent 已连接" + cReset)
		}
	}
	p.pause()
}

func agentInstallCommand(listen, key, target string) string {
	return fmt.Sprintf("curl -fsSL %s | bash -s -- agent --listen %s --key %s --target %s",
		installScriptURL, listen, key, target)
}

func (p *panel) firewallSetup() {
	c := p.cfg()
	fmt.Println("\n== 防火墙设置 ==")
	fmt.Println("只有客户端在对称型 NAT 后（大多数手机流量）才需要。家宽可以不设。")
	fmt.Println("需要两样东西：")
	fmt.Println("  · 加白地址：一个 HTTPS 地址，谁访问它就把谁加进白名单")
	fmt.Println("  · 删白命令：本机上的一条命令，参数是要删除的网段，删掉后返回 0")
	if c.str("PUNCH_FW_ADD_URL", "") != "" {
		fmt.Println(cGreen + "\n当前已启用。" + cReset)
		if p.confirm("关闭防火墙支持（只接受锥型 NAT）") {
			setEnvKeys(p.cfgPath, map[string]string{"PUNCH_FW_ADD_URL": ""})
			fmt.Println("已关闭，重启协调服务器后生效（菜单 10）。")
			p.pause()
			return
		}
	}
	addURL := p.ask("\n加白地址（https://…）", c.str("PUNCH_FW_ADD_URL", ""))
	if addURL == "" {
		return
	}
	u, err := url.Parse(addURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		fmt.Println(cRed + "要以 https:// 开头的完整地址。" + cReset)
		p.pause()
		return
	}
	pin, err := fetchPin(u)
	if err != nil {
		fmt.Println(cRed + "取证书失败：" + err.Error() + cReset)
		p.pause()
		return
	}
	fmt.Printf("证书指纹：%s\n", pin)
	rm := p.ask("删白命令（{cidr} 会被替换成网段）", c.str("PUNCH_FW_REMOVE", "/etc/punch/fw-remove.sh {cidr}"))
	result := p.ask("从加白响应里取 IP 的正则（不懂就回车）", c.str("PUNCH_FW_ADD_RESULT", `"currentIp":"([0-9.]+)\\?/(\d+)"`))
	kv := map[string]string{
		"PUNCH_FW_ADD_URL":    addURL,
		"PUNCH_FW_ADD_PIN":    pin,
		"PUNCH_FW_REMOVE":     rm,
		"PUNCH_FW_ADD_RESULT": result,
	}
	tmp := &config{values: map[string]string{}}
	for k, v := range c.values {
		tmp.values[k] = v
	}
	for k, v := range kv {
		tmp.values[k] = v
	}
	fw, err := firewallFromConfig(tmp)
	if err != nil {
		fmt.Println(cRed + "配置不完整：" + err.Error() + cReset)
		p.pause()
		return
	}
	fmt.Println("\n现在测试一次：把本机加白，再删掉。这会真的改一次防火墙，几秒内恢复。")
	if !p.confirm("开始测试") {
		fmt.Println("没有保存。")
		p.pause()
		return
	}
	added, err := testFirewall(fw)
	if err != nil {
		fmt.Println(cRed + "✗ " + err.Error() + cReset)
		fmt.Println("没有保存，请改正后重试。")
		p.pause()
		return
	}
	fmt.Println(cGreen + "✓ 加白成功：" + added + cReset)
	fmt.Println(cGreen + "✓ 删白成功" + cReset)
	if err := setEnvKeys(p.cfgPath, kv); err != nil {
		fmt.Println(cRed + "保存失败：" + err.Error() + cReset)
	} else {
		fmt.Println(cGreen + "已保存。重启协调服务器后生效（菜单 10）。" + cReset)
	}
	p.pause()
}

// fetchPin reads the endpoint's leaf certificate without calling the add path, so fetching the pin
// never allow-lists this host.
func fetchPin(u *url.URL) (string, error) {
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 8 * time.Second}, "tcp", host,
		&tls.Config{ServerName: u.Hostname(), InsecureSkipVerify: true})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", fmt.Errorf("对方没有提供证书")
	}
	sum := sha256.Sum256(certs[0].Raw)
	return hex.EncodeToString(sum[:]), nil
}

func (p *panel) templateSetup() {
	c := p.cfg()
	t := templateFromConfig(c)
	fmt.Println("\n== 节点模板 ==")
	fmt.Println("这里的设置会用在之后输出的每一份用户配置里。要和代理服务端（sing-box 等）一致。")
	name := p.ask("\n节点名", t.Name)
	cipher := p.ask("加密方式", t.Cipher)
	pw := p.ask("SS 密码", t.Password)
	smux := "true"
	if a := strings.ToLower(p.ask("开启 smux？推荐开启，UDP 需要它（Y/n）", "y")); a == "n" || a == "no" {
		smux = "false"
	}
	if pw == "" {
		fmt.Println(cRed + "SS 密码不能为空。" + cReset)
		p.pause()
		return
	}
	if err := setEnvKeys(p.cfgPath, map[string]string{
		keyNodeName: name, keyNodeCipher: cipher, keyNodePassword: pw, keyNodeSmux: smux,
	}); err != nil {
		fmt.Println(cRed + err.Error() + cReset)
	} else {
		fmt.Println(cGreen + "已保存。" + cReset)
	}
	p.pause()
}
