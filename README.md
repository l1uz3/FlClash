<div align="center">

<img src="assets/images/icon.png" alt="FlClash Punch" width="88">

# FlClash Punch

在 FlClash 的基础上加了**打洞拨号器**：服务器前面的防火墙只放行它自己发起的连接时，客户端也能连上。

[下载](#下载) · [使用](#使用) · [原理](#原理) · [节点配置](#节点配置) · [自建服务端](#自建服务端) · [与上游的差异](#与上游-flclash-的差异)

</div>

> 本仓库是 [chen08209/FlClash](https://github.com/chen08209/FlClash) 的非官方分支，与上游作者无关。
> 如果没有下面说的防火墙问题，请直接使用上游 FlClash。

## 适用场景

有些服务器的防火墙只放行**白名单 IP 发起的入站连接**，但**服务器自己发起的连接**，回包不查白名单。
手机流量和家宽的出口 IP 经常变，挨个加白名单不现实；而加白后再删白，已经建立的连接会立刻断掉。

本分支让**服务器主动回连客户端**：利用 TCP 同时打开（simultaneous open），这条连接在防火墙看来是服务器发起的，
因此不加白也能长期稳定使用。代价是要多部署一台协调服务器，服务端见 [l1uz3/punch-server](https://github.com/l1uz3/punch-server)。

## 下载

到 [Releases](https://github.com/l1uz3/FlClash/releases) 下载最新的 `app-v*` 版本。

| 平台 | 安装包 | 说明 |
| --- | --- | --- |
| Android | `arm64-v8a`、`armeabi-v7a`、`x86_64` 三种 APK | 绝大多数手机选 `arm64-v8a`。包名是 `com.follow.clash.punch`，**可以和官方 FlClash 同时安装**。 |
| Windows 10 及以上 | 安装版 `.exe` 或便携版 `.zip`（x64） | **会覆盖官方 FlClash**。安装包没有签名，SmartScreen 拦截时点"更多信息 → 仍要运行"。 |
| macOS 12 及以上 | Apple 芯片 `arm64` 和 Intel `amd64` 两种 `.dmg` | **会覆盖官方 FlClash**。没有签名，第一次打开时去"系统设置 → 隐私与安全性"点"仍要打开"；如果提示已损坏，运行 `xattr -cr /Applications/FlClash.app`。 |

版本号和上游一致。应用内的"检查更新"只看本分支的 `app-v*` 版本，不会把你更新回没有打洞功能的官方版。

## 使用

1. 向服务端管理员要一份配置。管理员在服务端面板里添加用户后，会得到一段完整的 YAML 配置。
2. 把它保存成 `.yaml` 文件，在 FlClash 里打开 **配置 → 添加配置 → 文件**，选中这个文件。
3. 选中这份配置，开启代理。第一次连接要先打洞，一两秒后就能用。

配置里已经包含节点、代理组和分流规则（国内直连，其余走代理），不用自己改。换了服务器的密码或地址时，
管理员重新发一份，替换掉旧的即可。

## 原理

```
FlClash ──SS 加密──▶ 打洞隧道（yamux 复用）──▶ 白名单服务器（agent）──▶ sing-box ──▶ 互联网
   │
   └──── TLS 控制连接 ────▶ 协调服务器 ──内网──▶ 白名单服务器（agent）
```

- **协调服务器**负责牵线，告诉白名单服务器去回连客户端的哪个地址、哪个端口。
- **白名单服务器**上的 agent 按指令**主动**向客户端发 SYN。客户端同时也向它发 SYN，
  两边的内核把这两次连接请求合并成一条 TCP 连接，全程不需要白名单。
- **家宽**（锥型 NAT）：客户端的公网端口不变。协调服务器看到是多少，就回连多少，直接打通。
- **手机流量**（对称型 NAT）：公网端口会变。做法是：
  1. 先短暂加白约 3 秒，让客户端的两个探测 SYN 到达服务器；
  2. 据此算出 NAT 当前的端口和**每秒分配速度**；
  3. **删白**，客户端发起一批新连接；
  4. 按推算出的端口范围回连，打通几条留几条。

  真正传数据的连接从不依赖白名单。
- NAT 会回收打通的连接，所以客户端大约每 60 秒提前打好一批新的，再平滑切换过去；换网时会自动重新打洞。
- 流量在 FlClash 和 sing-box 之间端到端加密，协调服务器和 agent 只转发字节，看不到内容。

**安全设计**

- 每个用户一个独立口令，管理员删除用户后立即失效。
- 客户端用证书指纹校验协调服务器：服务器用自签证书，客户端固定它的指纹。
- 防火墙的加白接口通常带密钥，但这个接口**永远不会下发给客户端**。客户端只把一条裸 TCP 连接转交给协调服务器，
  由协调服务器在这条连接里完成 TLS 和加白请求。加白接口看到的是客户端的 IP，密钥只存在协调服务器上。

## 节点配置

服务端面板生成的配置已经填好，**一般不需要看这一节**。自己写配置时，在节点上加一段 `punch:`，
FlClash 就改用打洞方式连接：

```yaml
proxies:
  - name: punch-ss
    type: ss
    server: 0.0.0.0        # 不会被使用，连接由打洞拨号器建立，但这个字段必填
    port: 1
    cipher: 2022-blake3-aes-256-gcm
    password: "<sing-box 的密码>"
    udp: true
    smux:                  # 打洞隧道只传 TCP，UDP 要靠 smux 封装进 TCP
      enabled: true
      protocol: h2mux
      max-connections: 1
      padding: false
    punch:
      coordinator: 203.0.113.20:48080
      fingerprint: <协调服务器证书的 SHA-256，64 位十六进制>
      token: "<你的口令>"
```

| 字段 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `coordinator` | 是 | | 协调服务器的 `IP:端口`。 |
| `fingerprint` | 是 | | 协调服务器的证书指纹，带不带冒号都行。对不上会拒绝连接。 |
| `token` | 是 | | 你的个人口令。 |
| `probe-ports` | 否 | `[48082, 48084]` | 协调服务器上的两个 NAT 探测端口，要和服务端一致。 |
| `attempts` | 否 | `4` | 手机流量下，每轮尝试打通几条连接。 |
| `keep` | 否 | `2` | 每轮保留几条。 |
| `refresh` | 否 | `60` | 最新一条连接存活多少秒后，提前打下一轮。 |
| `max-age` | 否 | `110` | 连接存活多少秒后，不再承接新请求。 |
| `window` | 否 | `16384` | 每条流的接收窗口（KiB）。默认值在 100 ms 延迟的链路上实测约 200 Mbit/s，改小会限速。 |
| `local-port-base` | 否 | `50111` | 打洞用的本地起始端口。 |

**注意**

- `punch:` 填错时节点会**直接报错**，不会退回普通直连。
- **必须开启 smux，并设 `max-connections: 1`**。服务端的 sing-box 也必须开启多路复用。
  实测这样速度和延迟最稳；关掉 smux 改用 UDP over TCP，或者开多条 smux 连接，速度波动都更大。
- 打洞挂在所有协议共用的拨号环节上，理论上 VLESS、Trojan 等节点也能加 `punch:`，但目前只测过 Shadowsocks。

## 自建服务端

服务端在单独的仓库 **[l1uz3/punch-server](https://github.com/l1uz3/punch-server)**，包括协调服务器、白名单服务器上的
agent 和控制台管理面板。在协调服务器上运行一次安装脚本，之后输入 `punch` 进入面板，按提示完成初始化、
连接白名单服务器、添加用户。

需要满足：

1. **白名单服务器主动发起**的 TCP 连接能收到回包，也就是防火墙按连接状态放行出站方向。
2. **协调服务器**有公网 IP，**不能和白名单服务器是同一台**，因为客户端连它时还没加白。
3. **白名单服务器**和协调服务器**内网互通**（云厂商之间的专线也算）。它不需要访问外网，安装和更新都由协调服务器提供。
4. 协调服务器上装有 **sing-box**，Shadowsocks 入站**必须开启多路复用**（`"multiplex": {"enabled": true}`）。
   面板会自动读取它的加密方式和密码来生成用户配置。Xray 的多路复用和 smux 不兼容，不能用。
5. 要支持**手机流量**，防火墙还要提供一个"**谁访问就给谁加白**"的 HTTPS 接口，以及一种**删白**的方式（API 或脚本）。
   只在家宽下使用的话不需要。

## 已知限制

- **Windows 上的打洞没有实测过**：Windows 的端口复用机制和 Linux、macOS 不一样。
- **桌面版会覆盖官方 FlClash**，Android 版可以和官方版共存。
- **桌面安装包没有签名**，因为没有代码签名证书。Android 版用本分支自己的密钥签名，不能和官方版互相覆盖升级。
- **手机流量下每打一轮洞大约要 10 秒**，其间该网段对白名单服务器开放约 3 秒。
- **去掉了 Firebase 崩溃上报和统计**：本分支不向任何第三方发送数据。

## 与上游 FlClash 的差异

同步上游时，照这张表检查冲突：

| 位置 | 改动 |
| --- | --- |
| `core/Clash.Meta`（子模块） | 指向 [l1uz3/Clash.Meta](https://github.com/l1uz3/Clash.Meta/tree/punch) 的 `punch` 分支：新增 `component/punch/`；`adapter/outbound/base.go` 加 `punch` 字段；TUN 默认网卡变化时调用 `punch.NetworkChanged()`。 |
| `core/lib.go` | Android 更新 DNS（也就是切换了网络）时，重置打洞连接。 |
| `android/` | 包名改为 `com.follow.clash.punch`；去掉 Firebase 依赖和插件。 |
| `lib/` | 去掉崩溃上报开关、数据收集提示，以及免责声明里的 Firebase 部分；`repository` 改为本分支；检查更新只认 `app-v*` 标签。 |
| `.github/workflows/punch-*.yaml` | 新增 Android、桌面的构建与发布，打 `app-v*` 标签时发版。上游的 `build.yaml` 没有改动。 |
| `README.md` | 本文件。删除了上游的 `README_zh_CN.md`。 |

## 构建与发版

```bash
git clone --recursive https://github.com/l1uz3/FlClash.git
cd FlClash
flutter pub get
dart setup.dart android   # 或 windows、macos、linux
```

需要的工具链和上游一样，见[上游 README](https://github.com/chen08209/FlClash#build-from-source)。

版本号和上游一致，不要改 `pubspec.yaml`。发版时在 `main` 上打 `app-v<版本号>` 标签，例如 `app-v0.8.99`，
标签和版本号不一致时打包会直接失败。同一个上游版本只能发一次，客户端的改动随下次同步上游一起发。

## 许可证

和上游一样，以 [GPL-3.0 协议](LICENSE)发布。
