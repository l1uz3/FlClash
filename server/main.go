// Command punch-server is the server side of the FlClash punch dialer: a coordinator on a public
// host and an agent on the firewalled server. Example configs and units are in server/deploy.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

const usage = `usage: punch-server <command> [-config FILE]

commands:
  coordinator         run the rendezvous server
  agent               run the dial-back agent on the firewalled server
  add-user NAME       add a client token to the tokens file and print it
  fingerprint         print the coordinator certificate fingerprint clients pin
`

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/punch/punch.env", "KEY=VALUE config file")
	// flag stops at the first positional argument; parse what follows it too so
	// "add-user NAME -config FILE" works as well as "add-user -config FILE NAME".
	var args []string
	for rest := os.Args[2:]; ; {
		fs.Parse(rest)
		if fs.NArg() == 0 {
			break
		}
		args = append(args, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fail(err)
	}
	switch os.Args[1] {
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
	case "add-user":
		if len(args) != 1 || strings.ContainsAny(args[0], " \t\n#") {
			fail(fmt.Errorf("add-user needs one NAME without spaces"))
		}
		fail(addUser(cfg.str("PUNCH_TOKENS", "/etc/punch/tokens"), args[0]))
	case "fingerprint":
		fp, err := certFingerprint(filepath.Join(cfg.str("PUNCH_STATE", "/var/lib/punch"), "coord.crt"))
		if err != nil {
			fail(fmt.Errorf("no certificate yet (start the coordinator once): %v", err))
		}
		fmt.Println(fp)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func addUser(path, name string) error {
	if b, err := os.ReadFile(path); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if f := strings.Fields(l); len(f) == 2 && f[0] == name {
				return fmt.Errorf("user %s already exists; delete its line in %s to revoke it first", name, path)
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	tok := newToken()
	if _, err := fmt.Fprintf(f, "%s %s\n", name, tok); err != nil {
		return err
	}
	fmt.Println(tok)
	return nil
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "punch-server:", err)
		os.Exit(1)
	}
	os.Exit(0)
}
