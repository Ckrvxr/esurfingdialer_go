# ESurfingDialer Go

ESurfingDialer 的 Go 语言移植版。无需 JRE。纯 Go 实现，零外部依赖，支持 Linux / Windows / macOS 全平台，支持 x86 / arm64 / mips 多种架构。

程序大小 1MB 左右，峰值内存消耗 13MB 左右，平时内存消耗 12MB，所以运行平台至少需要 64 MB RAM。

## 使用

```bash
./esurfingdialer -u 12345678901 -p 你的密码
```

可选参数：

```
-u <user>       登录账号（手机号）
-p <password>   登录密码
-s <sms>        短信验证码（仅需验证码时）
-c <path>       配置文件路径（默认：~/.config/esurfingdialer_go/config.json）
```

## 配置文件

JSON 格式，默认路径 `~/.config/esurfingdialer_go/config.json`：

```json
{
  "user": "17727272821",
  "password": "xxx",
  "sms_code": ""
}
```

CLI 参数优先级高于配置文件。

```bash
# 写入配置后直接运行
echo '{"user":"12345678901","password":"你的密码"}' > ~/.config/esurfingdialer_go/config.json
./esurfingdialer

# CLI 参数覆盖配置中的字段
./esurfingdialer -p 新密码

# 指定其他路径
./esurfingdialer -c /etc/esurfingdialer_go/config.json
```

## Linux Systemd （只针对 deb 包）

对于 Linux Systemd，配置文件路径为 `/etc/esurfingdialer_go/config.json`。

安装 deb 包后：

```bash
# 创建配置文件
echo '{"user":"12345678901","password":"你的密码"}' > /etc/esurfingdialer_go/config.json

# 启用并启动
systemctl enable --now esurfingdialer
systemctl status esurfingdialer
```

服务文件位于 `/usr/lib/systemd/system/esurfingdialer.service`。
配置文件位于 `/etc/esurfingdialer_go/config.json`。

## 构建

```bash
# 全部平台
bash build.sh

# 仅当前平台
CGO_ENABLED=0 go build -tags="nethttpomithttp2" -ldflags="-s -w" -trimpath -o esurfingdialer .
```

## 构建依赖

- Go 1.24+
- UPX 5.x（可选，用于压缩二进制）
