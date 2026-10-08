# Chained Proxy (链式代理节点管理服务端)

专为 Linux VPS 服务器打造的极简、轻量、高可用 `sing-box` 链式代理与多 IP 节点管理工具（基于 Go 纯标准库开发，0 第三方依赖）。

---

## ⚡ 一键极速安装与启动

> [!NOTE]
> **关于全新精简版服务器缺少 `curl` 的说明：**  
> 部分云厂商提供的最小化 Linux 系统镜像（尤其是 **Debian / Ubuntu Minimal**）默认没有预装 `curl` 或 `wget`，直接运行安装命令可能会提示 `command not found: curl`。  
> 若遇到该提示，请先执行下方对应系统的更新与安装命令：
> ```bash
> # Ubuntu / Debian 系统：
> apt-get update -y && apt-get install -y curl wget
> 
> # CentOS / AlmaLinux / Rocky / RHEL 系统：
> yum install -y curl wget || dnf install -y curl wget
> 
> # Alpine Linux 系统：
> apk add --no-cache curl wget bash
> ```

---

### 🚀 安装命令（复制即用）

#### 方式一：极速一键安装（推荐，原生终端模式）
```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/santian666/chained-proxy/main/install.sh)"
```

#### 方式二：管道一键安装（兼容模式）
```bash
curl -fsSL https://raw.githubusercontent.com/santian666/chained-proxy/main/install.sh | bash
```

#### 方式三：使用 wget 直接安装（若系统预装了 wget）
```bash
bash -c "$(wget -qO- https://raw.githubusercontent.com/santian666/chained-proxy/main/install.sh)"
```

#### 方式四：全自动防呆一行流（自适应检测，缺少 curl/wget 自动更新 apt/yum 并安装）
```bash
(command -v curl >/dev/null 2>&1 || (apt-get update -y && apt-get install -y curl || yum install -y curl)) && bash -c "$(curl -fsSL https://raw.githubusercontent.com/santian666/chained-proxy/main/install.sh)"
```

*(备用地址：若 GitHub 仓库名未变更也可将上方链接中的 `chained-proxy` 替换为 `vps-management`)*

---

### 💡 全局快捷命令
程序运行后会自动向系统注册全局快捷命令。今后无论您在哪个目录下，只要在终端输入：
```bash
vps
# 或者
chained-proxy
```
按下回车即可直接秒进管理菜单！

---

## 🌟 核心底层保障与架构亮点

### 1. 自动部署与强制升级至官方最新版 Sing-box 内核
* **环境初始化**：自动检测基础环境，若未安装自动拉取脚本配置好 systemd 服务单元及开启 **BBR 原生加速**。
* **官方最新内核升级**：程序自动请求 GitHub API（`SagerNet/sing-box`）获取最新正式发布版本，若本地版本落后或不支持 AnyTLS，自动下载最新静态二进制包覆盖升级。
* **TLS 证书自动就绪**：使用 Go 标准库自动生成 10 年期的自签名 TLS 证书（`/etc/sing-box/bin/tls.cer` 与 `tls.key`），保障 `AnyTLS` 协议 100% 开箱即用。

### 2. 四重日志与缓存防爆盘保护体系
针对 VPS 小硬盘、高并发代理日志易写满磁盘导致死机的痛点，设计了 4 道坚固防线：
1. **JSON 配置源头降级**：强制限制配置中的日志级别为 `"level": "warn"`，完全屏蔽日常海量的并发访问日志，仅记录必要警告。
2. **Systemd Journal 严格限额**：注入 `/etc/systemd/journald.conf.d/90-singbox-limit.conf`，限制系统日志最大占用 `50MB`。
3. **Logrotate 每日 10MB 自动截断**：单文件达到 10MB 立即截断压缩，最多保留 3 份。
4. **Systemd Timer + Cron 双定时守护**：每 2 小时后台自动轮询清理，单文件 >10MB 立即清空，自动清除 3 天前日志与临时缓存；并且**在每次菜单操作重启服务时，均会实时触发一次清理**。

### 3. 多网卡源进源出与内核网络优化
* 自动设置 `net.ipv4.conf.all.rp_filter = 0`，解除反向路径过滤，保障多 IP 站群服务器副 IP 的“源进源出”稳定连通。
* 自动开启 `net.ipv4.ip_nonlocal_bind = 1`。
* 自动放行 `ufw` / `firewalld` 对应监听端口段，并将 systemd 最大连接文件句柄数提升至 `1048576`。

### 4. 无论执行何种操作，最后强制重启一次 Sing-box 生效
任何菜单功能（新增节点、新增多IP节点、修改落地、节点列表、配置编辑、删除节点）执行完毕后，系统均统一执行：
$$\text{清理超限缓存} \longrightarrow \text{sing-box check 语法校验} \longrightarrow \text{放行防火墙端口} \longrightarrow \text{重启服务并刷新运行状态}$$

---

## 📋 菜单界面与详细功能使用指南

```text
====================================================================
              Chained Proxy 链式代理节点管理 (服务端版)
  本机主IP: 1.2.3.4 (共 3 个公网IP) | 内核: v1.12.x
  服务状态: 运行中 (active)         | 当前节点数: 12
====================================================================
  1. 新增节点
  2. 新增多IP节点 (纯直连)
  3. 修改落地 (按IP匹配更新 SOCKS5 端口/账号/密码)
  4. 节点列表
  5. 配置编辑
  6. 删除节点
  0. 退出 (输入 0 或 7 退出)
====================================================================
```

---

### 菜单 1：新增节点

* **第一步：选择入站协议（Inbound，精简为 3 种主流协议）**
  1. `VLESS + Reality`：自动生成 UUID、`flow: xtls-rprx-vision`、X25519 公私钥对与 8 位 short_id，默认伪装域名 `stock.adobe.com`（支持回车默认或自定义）。
  2. `AnyTLS`：基于 TLS 证书的高抗封锁协议，默认 SNI `bing.com`。
  3. `SOCKS5`：自动生成 8 位随机字母账号与 8 位随机字母密码。
* **第二步：选择出站协议（Outbound，严格限定 2 种）**
  1. **Direct（直连）**：
     * 输入生成节点数量（默认 1）与起始端口（回车默认从 20000 起自动寻找空闲端口）。
     * 以 **本机IP** 作为节点协议名。
     * 输出格式：`本机IP----协议链接`。
  2. **SOCKS5（落地代理）**：
     * 支持多行批量粘贴 SOCKS5 列表（支持 `ip:port:user:pass` 或 `socks5://...`，连续两次回车结束）。
     * **1.5 秒并发快速连通性验活**：自动测试每条 SOCKS5 的端口与账密连通性，若有异常会标明并由您选择是全量写入还是仅保留正常节点。
     * 自动提取每条 SOCKS5 的 **IP** 作为该节点的协议名。
     * 输出格式：`完整socks5----协议链接`（如 `9.9.9.9:1080:user:pass----vless://...#9.9.9.9`）。
* **自动生效与统一单文件留存**：
  * 自动重启 `sing-box` 使配置生效。
  * 终端打印本次生成的结果，并统一汇总导出至单个文件 `/home/nodes.txt`（无多余分散文件，全部节点集中在同一个文件中）。

---

### 菜单 2：新增多IP节点（纯直连）

专为拥有多个公网 IPv4 的站群/多 IP 服务器打造，实现极致简洁的“单 IP 进、单 IP 出”：
* **固定纯直连**：不设复杂的外部出站，出站强制设置 `inet4_bind_address: 该IP`，哪个 IP 收到请求就从哪个 IP 出站。
* **自动化流程**：
  1. 自动扫描网卡绑定的全部公网 IP，智能计算已创建和未创建节点的 IP 数量。
  2. 优先提供“仅未创建节点的 IP”选项，避免重复创建。
  3. 选择入站协议（`VLESS-Reality` / `AnyTLS` / `SOCKS5`）。
  4. 设置起始端口（回车默认 20000 起连续顺延）。
  5. 自动重启生效，终端按 `本机IP----协议链接` 逐行输出，并统一导出至单个文件 `/home/nodes.txt`。

---

### 菜单 3：修改落地（按 IP 自动匹配更新 SOCKS5 出口）

专为已存在的 SOCKS5 落地代理发生变动（端口变更、账密续期）设计：
* **核心价值**：**完全不改动原入站节点的协议、端口、UUID/密码**，客户端无需重新分发导入链接！
* **操作流程**：
  1. 直接粘贴新购买或变更后的 SOCKS5 列表（每行一条 `ip:port:user:pass`）。
  2. 程序自动提取每行 SOCKS5 的 **IP**，在现有出站为 SOCKS5 的节点中寻找相同 IP 的节点。
  3. **原地更新其出站 `server_port`（端口）、`username`（账号）、`password`（密码）**。
  4. 自动重启生效，打印匹配成功的数量及更新后的 `完整新socks5----原协议链接`，并同步更新至单个文件 `/home/nodes.txt`。

---

### 菜单 4：节点列表

* **总览显示格式**：
  ```text
  --------------------------------------------------------------------
  1---1.2.3.4----vless://xxxx@1.2.3.4:20000?encryption=none&...#1.2.3.4
  2---9.9.9.9----vless://yyyy@1.2.3.4:20001?encryption=none&...#9.9.9.9
  --------------------------------------------------------------------
  ```
  * 严格按 **`节点序号---节点IP----协议`** 输出。
  * 直连节点的“节点IP”显示为本机 IP，SOCKS5 出站节点的“节点IP”显示为对应的 SOCKS5 落地 IP。
* **全量导出支持**：
  * 输入 `1` 回车：在屏幕输出服务器上**全部节点**的标准交付格式，并统一导出保存到单个文件 `/home/nodes.txt`（绝不按节点拆分文件，全部节点统一收录在一个文件中）。
  * 直接按回车：返回主菜单（退出前同样自动执行一次重启检查确保服务活跃）。

---

### 菜单 5：配置编辑

直接人工修改底层 `/etc/sing-box/conf/all.json` 完整配置，内置保姆级防呆提示：
* **打开编辑器前醒目打印操作快捷键**：
  * `nano` 保存法：**按 `Ctrl + O` 再按【回车键】保存，按 `Ctrl + X` 退出**。
  * `vi/vim` 保存法：**按 `Esc` 输入 `:wq` 回车保存，输入 `:q!` 放弃修改**。
* **改错语法自动拦截与回滚保护**：
  * 保存退出后自动运行 `sing-box check` 校验 JSON 语法。
  * 若格式无误，自动重启生效。
  * 若改错（少写逗号、花括号不匹配等），终端立即打印具体报错行，并提供选项：`[1] 重新打开编辑器继续修改  [2] 放弃修改并自动恢复修改前备份`，彻底防止改坏文件导致失联。

---

### 菜单 6：删除节点

* 自动列出当前全部节点（序号与对应 IP）。
* **多模式快速删除**：
  * **按序号删**：支持单个序号（如 `2`）、多选（如 `1,3,5`）或连续范围（如 `1-10`）。
  * **按 IP 快速删**：直接输入 IP（支持输入本机 IP 或 SOCKS5 的落地 IP），程序自动找出所有匹配该 IP 的节点一键移除。
  * **清空全部**：输入 `all`，二次确认输入 `y` 后清空。
* 自动保存并重启生效。

---

## 📁 节点交付文件输出规则

每次导出**只生成单个带时间戳的文件**，里面汇聚服务器上的**全部节点**（绝不按节点拆分，全部节点收录在这一份文件中，无多余固定文件）：

* **文件路径**：`/home/nodes_YYYYMMDD_HHMMSS.txt`（例如 `/home/nodes_20261008_185400.txt`）
* **优势**：文件名自带年月日_时分秒，一眼分辨导出时间；文件内部包含当前全部节点，方便整份直接交付或复制。

| 触发操作 | 统一导出保存路径 | 文件内部格式 | 说明 |
| :--- | :--- | :--- | :--- |
| **菜单 1 新增节点** | `/home/nodes_时间戳.txt` | 直连: `本机IP----协议`<br>SOCKS: `完整socks5----协议` | 单文件自动汇总全部节点 |
| **菜单 2 新增多IP节点** | `/home/nodes_时间戳.txt` | `本机IP----协议` | 单文件自动汇总全部节点 |
| **菜单 3 修改落地** | `/home/nodes_时间戳.txt` | `完整新socks5----协议` | 单文件自动汇总全部节点 |
| **菜单 4 导出全部** | `/home/nodes_时间戳.txt` | 全量标准交付行 | 单文件集中导出全部节点 |
| **菜单 6 删除节点** | `/home/nodes_时间戳.txt` | 同步刷新剩余节点 | 自动剔除已删除节点并保存最新全量 |

---

## 🛠️ 自行源码编译指南

本项目使用纯 Go 标准库（Go 1.20+）构建，无任何外部 CGO 或第三方库依赖，编译速度快、体积小：

```bash
# 1. 克隆本仓库
git clone https://github.com/santian666/chained-proxy.git
cd chained-proxy

# 2. 运行自动化单元测试
go test -v ./...

# 3. 静态交叉编译 Linux 64位二进制文件
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/vps .

# 4. 静态交叉编译 Linux ARM64 二进制文件
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o bin/vps-arm64 .
```
