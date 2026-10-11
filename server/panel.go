package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// version is set at build time with -ldflags "-X main.version=..."; "dev" means a local build.
var version = "dev"

const (
	cReset  = "\033[0m"
	cRed    = "\033[31m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cBold   = "\033[1m"
)

type panel struct {
	cfgPath string
	in      *bufio.Reader
}

func (p *panel) cfg() *config {
	c, err := loadConfig(p.cfgPath)
	if err != nil {
		return &config{values: map[string]string{}}
	}
	return c
}

func (p *panel) ask(prompt, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]：", prompt, def)
	} else {
		fmt.Printf("%s：", prompt)
	}
	l, _ := p.in.ReadString('\n')
	l = strings.TrimSpace(l)
	if l == "" {
		return def
	}
	return l
}

func (p *panel) confirm(prompt string) bool {
	a := strings.ToLower(p.ask(prompt+"（y/N）", ""))
	return a == "y" || a == "yes"
}

func (p *panel) pause() {
	fmt.Print("\n按回车返回菜单…")
	p.in.ReadString('\n')
}

func dot(ok bool, yes, no string) string {
	if ok {
		return cGreen + "● " + yes + cReset
	}
	return cRed + "● " + no + cReset
}

func (p *panel) header() {
	c := p.cfg()
	fmt.Print("\033[H\033[2J")
	fmt.Printf("%s======== punch 管理面板 %s ========%s\n", cBold, version, cReset)
	coordOK := unitActive(unitCoordinator)
	agentAddr, key := c.str("PUNCH_AGENT", ""), c.str("PUNCH_AGENT_KEY", "")
	agentState := cYellow + "● 未配置" + cReset
	if agentAddr != "" && key != "" {
		if v := agentVersion(agentAddr, key); v != "" {
			agentState = cGreen + "● 已连接 " + v + cReset
		} else {
			agentState = cRed + "● 连不上" + cReset
		}
	}
	us, _ := listUsers(c.str("PUNCH_TOKENS", "/etc/punch/tokens"))
	fw := cYellow + "只支持家宽" + cReset
	if c.str("PUNCH_FW_ADD_URL", "") != "" {
		fw = cGreen + "已启用（支持手机流量）" + cReset
	}
	fmt.Printf("本机服务 %s   白名单服务器 %s\n", dot(coordOK, "运行中", "未运行"), agentState)
	fmt.Printf("用户 %d 个   防火墙 %s   白名单残留 %d\n", len(us), fw, pendingCount(c))
	fmt.Println("------------------------------------")
}

func (p *panel) run() {
	if !fileExists(p.cfgPath) {
		fmt.Println("还没有初始化，先进入初始化向导。")
		p.setup()
	}
	for {
		p.header()
		fmt.Println(" 1. 添加用户（输出配置）")
		fmt.Println(" 2. 查看用户配置")
		fmt.Println(" 3. 删除用户")
		fmt.Println(" 4. 用户列表")
		fmt.Println("------------------------------------")
		fmt.Println(" 5. 连接白名单服务器")
		fmt.Println(" 6. 防火墙设置（加白 / 删白）")
		fmt.Println(" 7. 节点模板")
		fmt.Println(" 8. 重新初始化")
		fmt.Println("------------------------------------")
		fmt.Println(" 9. 查看日志")
		fmt.Println("10. 启动 / 重启服务")
		fmt.Println("11. 停止服务")
		fmt.Println(" 0. 退出")
		switch p.ask("\n请选择", "") {
		case "1":
			p.addUser()
		case "2":
			p.showUser()
		case "3":
			p.delUser()
		case "4":
			p.listUsers()
		case "5":
			p.agentSetup()
		case "6":
			p.firewallSetup()
		case "7":
			p.templateSetup()
		case "8":
			p.setup()
		case "9":
			p.logs()
		case "10":
			p.restart()
		case "11":
			p.stop()
		case "0", "q":
			return
		}
	}
}

func (p *panel) tokensPath() string { return p.cfg().str("PUNCH_TOKENS", "/etc/punch/tokens") }

func (p *panel) printConfig(u user) {
	y, err := userConfig(p.cfg(), u)
	if err != nil {
		fmt.Println(cRed + err.Error() + cReset)
		return
	}
	fmt.Printf("\n%s---- %s 的配置（整段复制给对方，在 FlClash 里存成 .yaml 导入） ----%s\n\n", cBold, u.Name, cReset)
	fmt.Print(y)
	fmt.Printf("\n%s---- 结束 ----%s\n", cBold, cReset)
}

func (p *panel) addUser() {
	name := p.ask("新用户名", "")
	if name == "" {
		return
	}
	u, err := addUser(p.tokensPath(), name)
	if err != nil {
		fmt.Println(cRed + err.Error() + cReset)
	} else {
		fmt.Println(cGreen + "已添加用户 " + name + cReset)
		p.printConfig(u)
	}
	p.pause()
}

func (p *panel) pickUser(prompt string) (user, bool) {
	us, _ := listUsers(p.tokensPath())
	if len(us) == 0 {
		fmt.Println("还没有用户。")
		return user{}, false
	}
	for i, u := range us {
		fmt.Printf("%2d. %s\n", i+1, u.Name)
	}
	a := p.ask(prompt+"（序号或名字）", "")
	for i, u := range us {
		if a == u.Name || a == fmt.Sprint(i+1) {
			return u, true
		}
	}
	if a != "" {
		fmt.Println("没有这个用户。")
	}
	return user{}, false
}

func (p *panel) showUser() {
	if u, ok := p.pickUser("查看哪个用户"); ok {
		p.printConfig(u)
	}
	p.pause()
}

func (p *panel) delUser() {
	u, ok := p.pickUser("删除哪个用户")
	if ok && p.confirm("确定删除 "+u.Name+"？删除后他的配置立即失效") {
		if err := removeUser(p.tokensPath(), u.Name); err != nil {
			fmt.Println(cRed + err.Error() + cReset)
		} else {
			fmt.Println(cGreen + "已删除 " + u.Name + "。已经连着的隧道会在一两分钟内断开。" + cReset)
		}
	}
	p.pause()
}

func (p *panel) listUsers() {
	us, _ := listUsers(p.tokensPath())
	if len(us) == 0 {
		fmt.Println("还没有用户。")
	}
	for i, u := range us {
		fmt.Printf("%2d. %s\n", i+1, u.Name)
	}
	p.pause()
}

func (p *panel) logs() {
	cmd := exec.Command("journalctl", "-u", unitCoordinator, "-n", "40", "--no-pager", "-o", "cat")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Run()
	p.pause()
}

func (p *panel) restart() {
	if _, err := systemctl("restart", unitCoordinator); err != nil {
		fmt.Println(cRed + "重启失败，看「查看日志」找原因" + cReset)
	} else {
		fmt.Println(cGreen + "本机服务已重启" + cReset)
	}
	p.pause()
}

func (p *panel) stop() {
	if p.confirm("停止后所有用户都会断开，确定") {
		systemctl("stop", unitCoordinator)
		fmt.Println("本机服务已停止")
	}
	p.pause()
}
