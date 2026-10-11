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

func withDefaultPort(addr, port string) string {
	if addr == "" || strings.Contains(addr, ":") {
		return addr
	}
	return addr + ":" + port
}

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
	fmt.Println("这里说的「白名单服务器」，就是防火墙只放行白名单、用户实际要连的那台机器。")
	fmt.Println("前提：本机和白名单服务器必须内网互通（比如同一家云、同一个地域）。")
	def := c.str(keyPublicAddr, "")
	if def == "" {
		if ip := detectPublicIP(); ip != "" {
			def = ip + ":48080"
		}
	}
	pub := p.ask("\n1) 本机的公网地址（公网IP:端口，用户的 App 会连这里）", def)
	server := p.ask("2) 白名单服务器的公网 IP", c.str("PUNCH_SERVER_IP", ""))
	agent := withDefaultPort(p.ask("3) 白名单服务器的内网 IP（本机通过内网访问它）", c.str("PUNCH_AGENT", "")), "48081")
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
			fmt.Println(cGreen + "本机服务已启动。" + cReset)
		} else {
			fmt.Println(cRed + "本机服务启动失败，看「查看日志」。" + cReset)
		}
	}
	fmt.Println("\n下一步：")
	fmt.Println("  · 菜单 5：连接白名单服务器")
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
	fmt.Println("\n== 连接白名单服务器 ==")
	target := p.ask("用户的流量最终交给哪个节点（你的 sing-box / Xray 等的 IP:端口）", c.str("PUNCH_TARGET_HINT", "127.0.0.1:34120"))
	setEnvKeys(p.cfgPath, map[string]string{"PUNCH_TARGET_HINT": target})
	fmt.Print("\n登录" + cBold + "白名单服务器" + cReset + "，用 root 运行下面这一行（已包含密钥）：\n\n")
	fmt.Printf("%s\n", agentInstallCommand(agent, key, target))
	fmt.Println("\n它会在那台机器上装好需要的程序，并设为开机自启。")
	if p.confirm("\n运行完后按 y 测试连接") {
		if err := pingAgent(agent, key); err != nil {
			fmt.Println(cRed + "✗ " + err.Error() + cReset)
		} else {
			fmt.Println(cGreen + "✓ 白名单服务器已连接" + cReset)
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
	fmt.Println("让用户在手机流量下也能连才需要设置。只在家宽 WiFi 下用的话可以跳过。")
	fmt.Println("需要两样东西：")
	fmt.Println("  · 加白地址：一个 HTTPS 地址，谁访问它就把谁加进白名单")
	fmt.Println("  · 删白命令：本机上的一条命令，参数是要删除的网段，删掉后返回 0")
	if c.str("PUNCH_FW_ADD_URL", "") != "" {
		fmt.Println(cGreen + "\n当前已启用。" + cReset)
		if p.confirm("关闭手机流量支持（之后只支持家宽）") {
			setEnvKeys(p.cfgPath, map[string]string{"PUNCH_FW_ADD_URL": ""})
			fmt.Println("已关闭，重启本机服务后生效（菜单 10）。")
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
		fmt.Println(cGreen + "已保存。重启本机服务后生效（菜单 10）。" + cReset)
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
	fmt.Println("\n== 节点模板 ==")
	if path := singBoxPath(c); path != "" {
		p.templateFromSingBox(c, path)
		return
	}
	p.manualTemplate(c)
}

func (p *panel) templateFromSingBox(c *config, path string) {
	fmt.Printf("加密方式和密码自动读取本机 sing-box（%s），改了 sing-box 后输出的配置会自动跟着变。\n", path)
	fmt.Println("sing-box 的这个入站必须开启多路复用（multiplex）。")
	t, err := resolveNode(c)
	if err != nil {
		fmt.Println(cRed + "✗ " + err.Error() + cReset)
		fmt.Println("如果是端口不对，检查菜单 5 里填的转发地址是否和 sing-box 的入站端口一致。")
	} else {
		fmt.Printf("\n来源      %s\n加密方式  %s\n密码      %s\n多路复用  已开启\n", t.Source, t.Cipher, mask(t.Password))
	}
	name := p.ask("\n节点名", c.str(keyNodeName, "punch"))
	if err := setEnvKeys(p.cfgPath, map[string]string{keyNodeName: name}); err != nil {
		fmt.Println(cRed + err.Error() + cReset)
	} else {
		fmt.Println(cGreen + "已保存。" + cReset)
	}
	if p.confirm("\n改成手动填写（不再读取 sing-box）") {
		setEnvKeys(p.cfgPath, map[string]string{keySingBoxConfig: "off"})
		p.manualTemplate(p.cfg())
		return
	}
	p.pause()
}

func (p *panel) manualTemplate(c *config) {
	t := templateFromConfig(c)
	fmt.Println("没有读取 sing-box，手动填写。要和你的代理节点一致，代理节点必须开启多路复用（smux）。")
	if c.str(keySingBoxConfig, "") == "off" && defaultSingBoxConfig() != "" &&
		p.confirm("本机有 sing-box 配置，改回自动读取") {
		setEnvKeys(p.cfgPath, map[string]string{keySingBoxConfig: ""})
		p.templateFromSingBox(p.cfg(), singBoxPath(p.cfg()))
		return
	}
	name := p.ask("\n节点名", t.Name)
	cipher := p.ask("加密方式", t.Cipher)
	pw := p.ask("SS 密码", t.Password)
	if pw == "" {
		fmt.Println(cRed + "SS 密码不能为空。" + cReset)
		p.pause()
		return
	}
	if err := setEnvKeys(p.cfgPath, map[string]string{
		keyNodeName: name, keyNodeCipher: cipher, keyNodePassword: pw,
	}); err != nil {
		fmt.Println(cRed + err.Error() + cReset)
	} else {
		fmt.Println(cGreen + "已保存。" + cReset)
	}
	p.pause()
}

func mask(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "…" + s[len(s)-4:]
}
