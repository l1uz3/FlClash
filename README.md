<div align="center">

<img src="assets/images/icon.png" alt="FlClash Punch" width="88">

# FlClash Punch

在 FlClash 的基础上加了**打洞拨号器**：服务器前面的防火墙只放行它自己发起的连接时，客户端也能连上。

[原理](#原理) · [下载](#下载) · [客户端配置](#客户端配置) · [自建服务端](#自建服务端) · [与上游的差异](#与上游-flclash-的差异)

</div>

> 本仓库是 [chen08209/FlClash](https://github.com/chen08209/FlClash) 的非官方分支，与上游作者无关。
> 如果没有下面说的防火墙问题，请直接使用上游 FlClash。

## 适用场景

有些服务器的防火墙只放行**白名单 IP 发起的入站连接**，但**服务器自己发起的连接**，回包不查白名单。
手机流量和家宽的出口 IP 经常变，挨个加白名单不现实；而加白后再删白，已经建立的连接会立刻断掉。

本分支让**服务器主动回连客户端**：利用 TCP 同时打开（simultaneous open），这条连接在防火墙看来是服务器发起的，
因此不加白也能长期稳定使用。代价是要多部署一台协调服务器。

**使用前请确认满足下面三点，否则用不了：**

1. 被保护的服务器**主动发起**的 TCP 连接能收到回包，也就是防火墙按连接状态放行出站方向。
2. 有一台**有公网 IP** 的机器当协调服务器，客户端和被保护的服务器都能连到它。
3. 如果客户端在**对称型 NAT** 后面（大多数手机流量是这样），防火墙还要提供一个
   "**谁访问就给谁加白**"的 HTTPS 接口，以及一种**删白**的方式（API 或脚本都行）。
   只在家宽这类**锥型 NAT** 下使用的话，这一条不需要。

## 原理

```
FlClash ──SS 加密──▶ 打洞隧道（yamux 复用）──▶ agent（被保护服务器）──▶ 代理服务端（sing-box 等）──▶ 互联网
   │
   └──── TLS 控制连接 ────▶ 协调服务器 ──内网──▶ agent
```

- **协调服务器（coordinator）** 负责牵线，告诉 agent 去回连客户端的哪个地址、哪个端口。
- **agent** 运行在被保护的服务器上，按指令**主动**向客户端发 SYN。客户端同时也向它发 SYN，
  两边的内核把这两次连接请求合并成一条 TCP 连接，全程不需要白名单。
- **锥型 NAT**（家宽常见）：客户端的公网端口不变。协调服务器看到是多少，agent 就回连多少，直接打通。
- **对称型 NAT**（手机流量常见）：公网端口会变。做法是：
  1. 先短暂加白约 3 秒，让客户端的两个探测 SYN 到达服务器；
  2. agent 据此算出 NAT 当前的端口和**每秒分配速度**；
  3. **删白**，客户端发起一批新连接；
  4. agent 按推算出的端口范围回连，打通几条留几条。

  真正传数据的连接从不依赖白名单。
- NAT 会回收打通的连接，所以客户端大约每 60 秒提前打好一批新的，再平滑切换过去；换网时会自动重新打洞。
- 流量在 FlClash 和代理服务端之间端到端加密，协调服务器和 agent 只转发字节，看不到内容。

**安全设计**

- 每个用户一个独立口令。要吊销某个用户，删掉对应一行即可，不用重启。
- 客户端用证书指纹校验协调服务器：服务器用自签证书，客户端固定它的指纹。
- 防火墙的加白接口通常带密钥，但这个接口**永远不会下发给客户端**。客户端只把一条裸 TCP 连接转交给协调服务器，
  由协调服务器在这条连接里完成 TLS 和加白请求。加白接口看到的是客户端的 IP，密钥只存在协调服务器上。

## 下载

到 [Releases](https://github.com/l1uz3/FlClash/releases) 下载。还没有正式版时，去 [Actions](https://github.com/l1uz3/FlClash/actions)
打开对应工作流（`punch-android` / `punch-desktop` / `punch-server`）最近一次成功的运行，在页面底部下载。

| 平台 | 安装包 | 说明 |
| --- | --- | --- |
| Android | `arm64-v8a`、`armeabi-v7a`、`x86_64` 三种 APK | 包名是 `com.follow.clash.punch`，**可以和官方 FlClash 同时安装**。绝大多数手机选 `arm64-v8a`。 |
| Windows 10 及以上 | 安装版 `.exe` 或便携版 `.zip`（x64） | **会覆盖官方 FlClash**。安装包没有签名，SmartScreen 拦截时点"更多信息 → 仍要运行"。 |
| macOS 12 及以上 | Apple 芯片和 Intel 两种 `.dmg` | **会覆盖官方 FlClash**。没有签名，第一次打开时去"系统设置 → 隐私与安全性"点"仍要打开"；如果提示已损坏，运行 `xattr -cr /Applications/FlClash.app`。 |
| 服务端 | `punch-server-linux-amd64` / `arm64` | 协调服务器和 agent 用同一个程序，只支持 Linux。 |

## 客户端配置

在节点上加一段 `punch:`，FlClash 就改用打洞方式连接。节点的其他部分（加密方式、密码、smux 等）照常填写。

```yaml
proxies:
  - name: punch-ss
    type: ss
    server: 0.0.0.0        # 不会被使用，连接由打洞拨号器建立，但这个字段必填
    port: 1
    cipher: 2022-blake3-aes-256-gcm
    password: "<代理服务端的密码>"
    udp: true
    smux:                  # 打洞隧道只传 TCP，UDP 要靠 smux 封装进 TCP
      enabled: true
      protocol: h2mux
      max-connections: 1
      padding: false
    punch:
      coordinator: 203.0.113.20:48080
      fingerprint: <协调服务器证书的 SHA-256，64 位十六进制>
      token: "<服务端管理员发给你的口令>"
```

| 字段 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `coordinator` | 是 | | 协调服务器的 `IP:端口`（TLS 控制端口）。 |
| `fingerprint` | 是 | | 协调服务器的证书指纹，带不带冒号都行。对不上会拒绝连接。 |
| `token` | 是 | | 你的个人口令。 |
| `probe-ports` | 否 | `[48082, 48084]` | 协调服务器上的两个 NAT 探测端口，要和服务端一致。 |
| `attempts` | 否 | `4` | 对称型 NAT 下，每轮尝试打通几条连接。 |
| `keep` | 否 | `2` | 每轮保留几条。 |
| `refresh` | 否 | `60` | 最新一条连接存活多少秒后，提前打下一轮。 |
| `max-age` | 否 | `110` | 连接存活多少秒后，不再承接新请求。 |
| `window` | 否 | `16384` | 每条流的接收窗口（KiB）。默认值在 100 ms 延迟的链路上实测约 200 Mbit/s，改小会限速。 |
| `local-port-base` | 否 | `50111` | 打洞用的本地起始端口。 |

**注意**

- `punch:` 填错时节点会**直接报错**，不会退回普通直连。
- **保持 smux 开启，并设 `max-connections: 1`**。实测这样速度和延迟最稳。关掉 smux 改用 UDP over TCP，
  或者开多条 smux 连接，速度波动都更大。
- 打洞挂在所有协议共用的拨号环节上，理论上 VLESS、Trojan 等节点也能加 `punch:`，但目前只测过 Shadowsocks。

## 自建服务端

服务端涉及三个角色：

- **协调服务器**：要有公网 IP，开放 TLS 端口和两个探测端口。**不能放在被保护的服务器上**，因为客户端连它时还没加白。
- **agent**：装在被保护的服务器上，需要 root 权限，以及 `tcpdump`、`iptables`。它和协调服务器之间最好走内网。
- **代理服务端**：sing-box、Xray 等，agent 把隧道流量转给它，可以和 agent 在同一台机器上。

### 1. 安装

从 Releases 下载 `punch-server-linux-<架构>`，在协调服务器和被保护的服务器上都放到 `/usr/local/bin/punch-server`，
并加上执行权限。配置示例和 systemd 服务模板在 [`server/deploy/`](server/deploy)。

### 2. 协调服务器

```bash
install -d -m 700 /etc/punch /var/lib/punch
cp coordinator.env.example /etc/punch/punch.env && chmod 600 /etc/punch/punch.env
# 编辑 /etc/punch/punch.env，至少填 PUNCH_AGENT、PUNCH_AGENT_KEY、PUNCH_SERVER_IP
cp punch-coordinator.service /etc/systemd/system/
systemctl enable --now punch-coordinator
punch-server fingerprint          # 输出客户端要填的 fingerprint
punch-server add-user alice       # 输出 alice 的口令；要吊销就删掉 /etc/punch/tokens 里对应的那行
```

`PUNCH_AGENT_KEY` 是协调服务器和 agent 之间的共享密钥，可以用 `openssl rand -hex 32` 生成，两边填同一个值。

### 3. agent（被保护的服务器）

```bash
apt-get install -y tcpdump iptables
install -d -m 700 /etc/punch
cp agent.env.example /etc/punch/punch.env && chmod 600 /etc/punch/punch.env
# 填 PUNCH_AGENT_LISTEN（只监听内网地址）、PUNCH_AGENT_KEY、PUNCH_TARGET（代理服务端的地址）
cp punch-agent.service /etc/systemd/system/
systemctl enable --now punch-agent
```

`PUNCH_LEARN_PORT`（默认 45000）在被保护的服务器上**不能有程序监听**，客户端的探测 SYN 和回连都用这个端口。

### 4. 支持对称型 NAT（可选）

不配置这一步时，协调服务器只接受锥型 NAT 的客户端，对称型 NAT 的客户端会被明确拒绝。要支持手机流量，
在协调服务器的 `punch.env` 里补上：

| 配置项 | 说明 |
| --- | --- |
| `PUNCH_FW_ADD_URL` | 访问即加白的 HTTPS 地址，里面可以带密钥，客户端看不到。 |
| `PUNCH_FW_ADD_PIN` | 这个地址证书的 SHA-256。**必填**，不填协调服务器会拒绝启动。获取方法见示例文件里的注释。 |
| `PUNCH_FW_ADD_RESULT` | 一个正则，从加白接口的响应里取出被加白的 IP（以及可选的前缀长度）。 |
| `PUNCH_FW_REMOVE` | 删白命令，`{cidr}` 会被替换成要删的网段。**确实删掉之后才能返回 0**。参考 [`fw-remove.example.sh`](server/deploy/fw-remove.example.sh)。 |
| `PUNCH_REMOVE_WAIT` | 删白后等待多少秒再继续，默认 6。防火墙生效慢就调大。 |

协调服务器会把每个加过白的网段记在 `/var/lib/punch/wl_pending`。就算进程中途被杀，重启后一分钟内也会把残留的白名单删掉。

## 已知限制

- **Windows 上的打洞没有实测过**：Windows 的端口复用机制和 Linux、macOS 不一样。
- **桌面版会覆盖官方 FlClash**，Android 版可以和官方版共存。
- **桌面安装包没有签名**，因为没有代码签名证书。Android 版用本分支自己的密钥签名。
- **对称型 NAT 每打一轮洞大约要 10 秒**，其间该网段对被保护的服务器开放约 3 秒。
- **去掉了 Firebase 崩溃上报和统计**：本分支不向任何第三方发送数据。
- 应用内的"检查更新"指向本分支的 Releases，不会把你更新回没有打洞功能的官方版。

## 与上游 FlClash 的差异

同步上游时，照这张表检查冲突：

| 位置 | 改动 |
| --- | --- |
| `core/Clash.Meta`（子模块） | 指向 [l1uz3/Clash.Meta](https://github.com/l1uz3/Clash.Meta/tree/punch) 的 `punch` 分支：新增 `component/punch/`；`adapter/outbound/base.go` 加 `punch` 字段；TUN 默认网卡变化时调用 `punch.NetworkChanged()`。 |
| `core/lib.go` | Android 更新 DNS（也就是切换了网络）时，重置打洞连接。 |
| `server/` | 新增服务端 `punch-server`。 |
| `android/` | 包名改为 `com.follow.clash.punch`；去掉 Firebase 依赖和插件。 |
| `lib/` | 去掉崩溃上报开关、数据收集提示，以及免责声明里的 Firebase 部分；`repository` 改为本分支；检查更新兼容 `punch-v*` 标签。 |
| `.github/workflows/punch-*.yaml` | 新增 Android、桌面、服务端的构建与发布。上游的 `build.yaml` 没有改动。 |
| `README.md` | 本文件。删除了上游的 `README_zh_CN.md`。 |

## 构建

```bash
git clone --recursive https://github.com/l1uz3/FlClash.git
cd FlClash
flutter pub get
dart setup.dart android   # 或 windows、macos、linux
```

需要的工具链和上游一样，见[上游 README](https://github.com/chen08209/FlClash#build-from-source)。服务端：

```bash
cd server && go build -o punch-server .
```

## 许可证

和上游一样，以 [GPL-3.0 协议](LICENSE)发布。
