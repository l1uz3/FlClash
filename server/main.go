// Command punch-server is the server side of the FlClash punch dialer: a coordinator on a public
// host and an agent on the firewalled server. Run without arguments for the management panel.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
)

const usage = `用法：punch [命令] [-config 文件]

不带命令运行进入管理面板。

用户：
  punch user add 名字        添加用户并输出配置
  punch user show 名字       输出已有用户的配置
  punch user del 名字        删除用户（立即失效）
  punch user list            用户列表

服务：
  punch status               服务状态
  punch fingerprint          协调服务器证书指纹
  punch install-cmd          输出在白名单服务器上运行的安装命令（10 分钟内有效）
  punch push-agent           把本机的版本推送给白名单服务器
  punch version              版本

由 systemd 调用（不用手动运行）：
  punch coordinator          本机服务
  punch agent                白名单服务器上的服务
`

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	fs := flag.NewFlagSet("punch", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/punch/punch.env", "配置文件")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	// flag stops at the first positional argument; keep parsing after it so
	// "user add NAME -config FILE" works as well as "-config FILE user add NAME".
	var args []string
	for rest := os.Args[1:]; ; {
		fs.Parse(rest)
		if fs.NArg() == 0 {
			break
		}
		args = append(args, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if len(args) == 0 {
		requireRoot()
		(&panel{cfgPath: *cfgPath, in: bufio.NewReader(os.Stdin)}).run()
		return
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil && args[0] != "version" && args[0] != "help" {
		fail(fmt.Errorf("读取配置 %s 失败：%v（先运行 punch 初始化）", *cfgPath, err))
	}
	switch args[0] {
	case "coordinator":
		cc, err := coordFromConfig(cfg)
		if err != nil {
			fail(err)
		}
		fail(runCoordinator(cc))
	case "agent":
		ac, err := agentFromConfig(cfg)
		if err != nil {
			fail(err)
		}
		fail(runAgent(ac))
	case "user":
		fail(userCmd(cfg, args[1:]))
	case "add-user": // kept for scripts written against the first release
		fail(userCmd(cfg, append([]string{"add"}, args[1:]...)))
	case "fingerprint":
		fp, err := certFingerprint(statePath(cfg, "coord.crt"))
		if err != nil {
			fail(fmt.Errorf("还没有证书，请先启动本机服务"))
		}
		fmt.Println(fp)
	case "status":
		printStatus(cfg)
	case "install-cmd":
		cmd, err := issueInstall(cfg)
		if err != nil {
			fail(err)
		}
		fmt.Println(cmd)
	case "push-agent":
		fail(pushAgentFromConfig(cfg))
	case "version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	os.Exit(0)
}

func userCmd(cfg *config, args []string) error {
	tokens := cfg.str("PUNCH_TOKENS", "/etc/punch/tokens")
	if len(args) == 0 {
		return fmt.Errorf("用法：punch user add|show|del|list [名字]")
	}
	needName := func() (string, error) {
		if len(args) != 2 {
			return "", fmt.Errorf("用法：punch user %s 名字", args[0])
		}
		return args[1], nil
	}
	switch args[0] {
	case "add":
		name, err := needName()
		if err != nil {
			return err
		}
		if err := checkCanRender(cfg); err != nil {
			return err
		}
		u, err := addUser(tokens, name)
		if err != nil {
			return err
		}
		out, err := userConfig(cfg, u)
		if err != nil {
			return err
		}
		fmt.Print(out)
	case "show":
		name, err := needName()
		if err != nil {
			return err
		}
		u, ok := findUser(tokens, name)
		if !ok {
			return fmt.Errorf("用户 %s 不存在", name)
		}
		out, err := userConfig(cfg, u)
		if err != nil {
			return err
		}
		fmt.Print(out)
	case "del", "rm", "remove":
		name, err := needName()
		if err != nil {
			return err
		}
		return removeUser(tokens, name)
	case "list", "ls":
		us, err := listUsers(tokens)
		if err != nil {
			return err
		}
		for _, u := range us {
			fmt.Println(u.Name)
		}
	default:
		return fmt.Errorf("未知命令 user %s", args[0])
	}
	return nil
}

// checkCanRender fails before a user is created when no config could be printed for them, so a
// half-configured server does not leave behind users nobody received a config for.
func checkCanRender(cfg *config) error {
	_, err := userConfig(cfg, user{Name: "-", Token: "-"})
	return err
}

func printStatus(cfg *config) {
	fmt.Printf("版本          %s\n", version)
	fmt.Printf("本机服务      %s\n", map[bool]string{true: "运行中", false: "未运行"}[unitActive(unitCoordinator)])
	agent, key := cfg.str("PUNCH_AGENT", ""), cfg.str("PUNCH_AGENT_KEY", "")
	switch {
	case agent == "" || key == "":
		fmt.Println("白名单服务器  未配置")
	default:
		if v := agentVersion(agent, key); v != "" {
			fmt.Printf("白名单服务器  已连接（%s，%s）\n", agent, v)
		} else {
			fmt.Printf("白名单服务器  连不上（%s）\n", agent)
		}
	}
	if t, err := resolveNode(cfg); err != nil {
		fmt.Printf("代理节点      有问题：%v\n", err)
	} else {
		fmt.Printf("代理节点      %s，%s\n", t.Source, t.Cipher)
	}
	us, _ := listUsers(cfg.str("PUNCH_TOKENS", "/etc/punch/tokens"))
	fmt.Printf("用户          %d\n", len(us))
	if cfg.str("PUNCH_FW_ADD_URL", "") != "" {
		fmt.Println("防火墙        已启用（支持手机流量）")
	} else {
		fmt.Println("防火墙        未启用（只支持家宽，不支持手机流量）")
	}
	fmt.Printf("白名单残留    %d\n", pendingCount(cfg))
}

func requireRoot() {
	if os.Geteuid() != 0 {
		fail(fmt.Errorf("管理面板需要 root 运行"))
	}
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "punch:", err)
		os.Exit(1)
	}
	os.Exit(0)
}
