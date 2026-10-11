#!/usr/bin/env bash
# punch 服务端安装 / 更新脚本。
#
#   协调服务器：bash <(curl -fsSL https://github.com/l1uz3/FlClash/releases/latest/download/install.sh)
#   agent     ：由管理面板「接入被保护的服务器」生成，形如
#               curl -fsSL .../install.sh | bash -s -- agent --listen 内网IP:端口 --key 密钥 --target 地址
#   更新      ：bash install.sh update   （自动更新定时器每天调用一次）
set -euo pipefail

REPO="l1uz3/FlClash"
BIN=/usr/local/bin/punch
ETC=/etc/punch
STATE=/var/lib/punch

red() { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
die() { red "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "请用 root 运行"
command -v systemctl >/dev/null || die "需要 systemd"

arch() {
  case "$(uname -m)" in
    x86_64 | amd64) echo amd64 ;;
    aarch64 | arm64) echo arm64 ;;
    *) die "不支持的架构：$(uname -m)" ;;
  esac
}

# Only punch-v* releases carry server binaries; ordinary pushes to main never reach a server.
latest_tag() {
  curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=20" |
    grep -oE '"tag_name": *"punch-v[^"]+"' | head -1 | sed -E 's/.*"(punch-v[^"]+)"/\1/'
}

# Downloads the binary for tag, checks it against the release's SHA256SUMS and installs it, keeping
# the previous binary as $BIN.bak so a bad release can be rolled back.
install_bin() {
  local tag="$1" a tmp ok=0
  a="$(arch)"
  tmp="$(mktemp -d)"
  # Not a RETURN trap: those stay set after the function and fire again in the caller, where $tmp
  # no longer exists and set -u aborts the script.
  fetch_verify "$tag" "$a" "$tmp" && ok=1
  if [ "$ok" = 1 ]; then
    [ -f "$BIN" ] && cp -p "$BIN" "$BIN.bak"
    install -m 755 "$tmp/punch" "$BIN"
  fi
  rm -rf "$tmp"
  [ "$ok" = 1 ] || die "下载或校验失败（$tag），没有安装"
}

fetch_verify() {
  local tag="$1" a="$2" dir="$3"
  local base="https://github.com/$REPO/releases/download/$tag"
  curl -fsSL -o "$dir/punch" "$base/punch-server-linux-$a" || return 1
  curl -fsSL -o "$dir/SHA256SUMS" "$base/SHA256SUMS" || return 1
  (cd "$dir" && grep " punch-server-linux-$a\$" SHA256SUMS | sed "s#punch-server-linux-$a#punch#" | sha256sum -c --quiet) || return 1
  chmod 755 "$dir/punch"
}

write_unit() {
  local name="$1" role="$2"
  cat >"/etc/systemd/system/$name.service" <<EOF
[Unit]
Description=punch $role
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$BIN $role -config $ETC/punch.env
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
}

write_updater() {
  cat >/etc/systemd/system/punch-update.service <<EOF
[Unit]
Description=punch auto update

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'curl -fsSL https://github.com/$REPO/releases/latest/download/install.sh | bash -s -- update'
EOF
  cat >/etc/systemd/system/punch-update.timer <<'EOF'
[Unit]
Description=punch daily update

[Timer]
OnCalendar=daily
RandomizedDelaySec=3h
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now punch-update.timer >/dev/null
}

cmd_coordinator() {
  local tag
  tag="$(latest_tag)"
  [ -n "$tag" ] || die "还没有发布 punch-v* 版本"
  install_bin "$tag"
  install -d -m 700 "$ETC" "$STATE"
  write_unit punch-coordinator coordinator
  echo coordinator >"$ETC/role"
  write_updater
  green "已安装 $tag。接下来进入管理面板完成初始化。"
  exec "$BIN"
}

cmd_agent() {
  local listen="" key="" target=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --listen) listen="$2"; shift 2 ;;
      --key) key="$2"; shift 2 ;;
      --target) target="$2"; shift 2 ;;
      *) die "未知参数：$1" ;;
    esac
  done
  [ -n "$listen" ] && [ -n "$key" ] && [ -n "$target" ] || die "缺少 --listen / --key / --target"
  if ! command -v tcpdump >/dev/null || ! command -v iptables >/dev/null; then
    if command -v apt-get >/dev/null; then
      apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tcpdump iptables >/dev/null
    elif command -v dnf >/dev/null; then
      dnf install -y -q tcpdump iptables
    elif command -v yum >/dev/null; then
      yum install -y -q tcpdump iptables
    else
      die "请先手动安装 tcpdump 和 iptables"
    fi
  fi
  local tag
  tag="$(latest_tag)"
  [ -n "$tag" ] || die "还没有发布 punch-v* 版本"
  install_bin "$tag"
  install -d -m 700 "$ETC"
  umask 077
  cat >"$ETC/punch.env" <<EOF
PUNCH_AGENT_LISTEN=$listen
PUNCH_AGENT_KEY=$key
PUNCH_TARGET=$target
PUNCH_IFACE=$(ip route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')
EOF
  write_unit punch-agent agent
  echo agent >"$ETC/role"
  write_updater
  systemctl daemon-reload
  systemctl enable punch-agent >/dev/null
  systemctl restart punch-agent
  sleep 1
  systemctl is-active --quiet punch-agent || die "启动失败，查看原因：journalctl -u punch-agent -n 30"
  green "已安装并运行（$tag），监听 $listen。回到另一台机器的面板，按 y 测试连接。"
}

# Replaces the binary only when a newer release exists, restarts the service, and puts the old
# binary back if the service does not come up.
cmd_update() {
  local role unit tag cur
  role="$(cat "$ETC/role" 2>/dev/null || true)"
  case "$role" in
    coordinator) unit=punch-coordinator ;;
    agent) unit=punch-agent ;;
    *) die "没有找到已安装的 punch（$ETC/role）" ;;
  esac
  tag="$(latest_tag)"
  [ -n "$tag" ] || exit 0
  cur="$("$BIN" version 2>/dev/null || true)"
  if [ "$cur" = "$tag" ]; then
    sync_agent
    exit 0
  fi
  install_bin "$tag"
  systemctl restart "$unit"
  sleep 3
  if ! systemctl is-active --quiet "$unit"; then
    red "$tag 启动失败，回滚到 $cur"
    install -m 755 "$BIN.bak" "$BIN"
    systemctl restart "$unit"
    exit 1
  fi
  green "已从 $cur 更新到 $tag"
  sync_agent
}

# The whitelisted server usually cannot reach GitHub, so the coordinator hands it its own binary.
# Also run when the coordinator is already current, which retries an agent that missed a push.
sync_agent() {
  [ "$(cat "$ETC/role" 2>/dev/null)" = coordinator ] || return 0
  "$BIN" push-agent >/dev/null 2>&1 && return 0
  red "白名单服务器没有更新成功，运行 punch push-agent 查看原因"
}

cmd_uninstall() {
  for u in punch-coordinator punch-agent punch-update.timer punch-update; do
    systemctl disable --now "$u" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/$u.service" "/etc/systemd/system/$u"
  done
  rm -f /etc/systemd/system/punch-update.timer
  systemctl daemon-reload
  rm -f "$BIN" "$BIN.bak"
  green "已卸载程序。配置和用户保留在 $ETC、$STATE，确认不要了再手动删除。"
}

case "${1:-coordinator}" in
  coordinator) shift || true; cmd_coordinator "$@" ;;
  agent) shift; cmd_agent "$@" ;;
  update) cmd_update ;;
  uninstall) cmd_uninstall ;;
  *) die "用法：install.sh [coordinator|agent|update|uninstall]" ;;
esac
