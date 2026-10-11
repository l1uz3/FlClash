<div align="center">

<img src="assets/images/icon.png" alt="FlClash Punch" width="88">

# FlClash Punch

FlClash 的非官方分支，加了**打洞**：服务器的防火墙只放行白名单时，不用加白也能连上。

</div>

> 与上游作者 [chen08209/FlClash](https://github.com/chen08209/FlClash) 无关。没有这类防火墙的话，直接用官方 FlClash 就行。

## 下载

到 [Releases](https://github.com/l1uz3/FlClash/releases) 下载最新的 `app-v*` 版本：

- **Android**：绝大多数手机选 `arm64-v8a`。可以和官方 FlClash 同时安装。
- **Windows**：`setup.exe`（安装版）或 `.zip`（免安装）。会覆盖官方 FlClash。
- **macOS**：M 芯片选 `arm64`，Intel 选 `amd64`。会覆盖官方 FlClash。

桌面版没有签名，系统拦截时：Windows 点"更多信息 → 仍要运行"；macOS 到"系统设置 → 隐私与安全性"点"仍要打开"。

## 使用

1. 找服务端管理员要一份配置。
2. 存成 `.yaml` 文件，在 FlClash 里 **配置 → 添加配置 → 文件** 导入。
3. 选中这份配置，开启代理。

第一次连接要先打洞，等一两秒就能用。

## 搭建服务端

见 [l1uz3/punch-server](https://github.com/l1uz3/punch-server)。

## 更多

原理、手写节点的字段、服务端要求、已知限制、和上游的差异、构建方法，见 [详细说明](DETAILS.md)。

以 [GPL-3.0 协议](LICENSE)发布。
