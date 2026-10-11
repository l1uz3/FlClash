package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type user struct{ Name, Token string }

func validUserName(name string) error {
	if name == "" || strings.ContainsAny(name, " \t\n#") {
		return fmt.Errorf("用户名不能为空，也不能包含空格或 #")
	}
	return nil
}

func listUsers(path string) ([]user, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var us []user
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if f := strings.Fields(l); len(f) == 2 {
			us = append(us, user{f[0], f[1]})
		}
	}
	sort.Slice(us, func(i, j int) bool { return us[i].Name < us[j].Name })
	return us, nil
}

func findUser(path, name string) (user, bool) {
	us, _ := listUsers(path)
	for _, u := range us {
		if u.Name == name {
			return u, true
		}
	}
	return user{}, false
}

func addUser(path, name string) (user, error) {
	if err := validUserName(name); err != nil {
		return user{}, err
	}
	if _, ok := findUser(path, name); ok {
		return user{}, fmt.Errorf("用户 %s 已存在", name)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return user{}, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return user{}, err
	}
	defer f.Close()
	u := user{name, newToken()}
	if _, err := fmt.Fprintf(f, "%s %s\n", u.Name, u.Token); err != nil {
		return user{}, err
	}
	return u, nil
}

// removeUser rewrites the tokens file without name's line. The coordinator re-reads the file on
// every login, so the user is revoked immediately; tunnels already up stay until they expire.
func removeUser(path, name string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var out []string
	found := false
	for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == name {
			found = true
			continue
		}
		out = append(out, l)
	}
	if !found {
		return fmt.Errorf("用户 %s 不存在", name)
	}
	return writeFileAtomic(path, []byte(strings.Join(out, "\n")+"\n"), 0600)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// setEnvKeys updates KEY=VALUE lines in place, appending keys that are missing, so comments and
// keys the panel does not manage survive an edit.
func setEnvKeys(path string, kv map[string]string) error {
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(b) == 0 {
		lines = nil
	}
	done := map[string]bool{}
	for i, l := range lines {
		k, _, ok := strings.Cut(strings.TrimSpace(l), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		if v, want := kv[strings.TrimSpace(k)]; want {
			lines[i] = k + "=" + v
			done[k] = true
		}
	}
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !done[k] {
			lines = append(lines, k+"="+kv[k])
		}
	}
	return writeFileAtomic(path, []byte(strings.Join(lines, "\n")+"\n"), 0600)
}
