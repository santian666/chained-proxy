#!/bin/bash
set -e

# ====================================================================
# Chained Proxy (链式代理节点管理服务端) 一键安装脚本
# ====================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
PLAIN='\033[0m'

if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}错误：请以 root 身份运行此脚本！${PLAIN}"
    exit 1
fi

# 自动检测并安装 curl / wget（防止精简版系统缺少网络下载工具）
if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    echo -e "${YELLOW}检测到系统缺少 curl 与 wget 下载工具，正在自动安装...${PLAIN}"
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y && apt-get install -y curl wget
    elif command -v yum >/dev/null 2>&1; then
        yum install -y curl wget
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y curl wget
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache curl wget
    fi
fi

ARCH="amd64"
case "$(uname -m)" in
    x86_64|amd64)
        ARCH="amd64"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        ;;
    *)
        echo -e "${RED}暂不支持当前架构: $(uname -m)${PLAIN}"
        exit 1
        ;;
esac

echo -e "${GREEN}检测到系统架构: ${ARCH}${PLAIN}"

BIN_NAME="vps"
if [ "$ARCH" = "arm64" ]; then
    BIN_NAME="vps-arm64"
fi

INSTALL_PATH="/usr/local/bin/vps"
ALIAS_PATH="/usr/local/bin/chained-proxy"
mkdir -p /usr/local/bin

echo -e "${GREEN}正在从 GitHub 下载 Chained Proxy 最新版本...${PLAIN}"

download_file() {
    local target_path="$1"
    local url1="https://raw.githubusercontent.com/santian666/chained-proxy/main/bin/${BIN_NAME}"
    local url2="https://raw.githubusercontent.com/santian666/vps-management/main/bin/${BIN_NAME}"

    if command -v curl >/dev/null 2>&1; then
        if ! curl -fsSL --connect-timeout 10 --retry 3 "$url1" -o "$target_path" 2>/dev/null; then
            curl -fsSL --connect-timeout 10 --retry 3 "$url2" -o "$target_path"
        fi
    elif command -v wget >/dev/null 2>&1; then
        if ! wget -qO "$target_path" --timeout=15 --tries=3 "$url1" 2>/dev/null; then
            wget -qO "$target_path" --timeout=15 --tries=3 "$url2"
        fi
    else
        echo -e "${RED}错误：未找到 curl 或 wget，无法下载程序文件！${PLAIN}"
        exit 1
    fi
}

download_file "$INSTALL_PATH"
chmod +x "$INSTALL_PATH"
cp -f "$INSTALL_PATH" "$ALIAS_PATH" 2>/dev/null || true
chmod +x "$ALIAS_PATH" 2>/dev/null || true

echo -e "===================================================================="
echo -e "${GREEN}Chained Proxy 安装成功！${PLAIN}"
echo -e "以后无论在哪个目录，直接输入 ${YELLOW}vps${PLAIN} 或 ${YELLOW}chained-proxy${PLAIN} 回车即可打开管理菜单！"
echo -e "===================================================================="
echo ""

# 自动运行管理程序
if [ -t 0 ]; then
    # 当前已处于交互终端中
    exec "$INSTALL_PATH"
elif [ -e /dev/tty ]; then
    # 通过管道 (curl ... | bash) 执行时，将标准输入重定向回终端 /dev/tty，防止输入流断开导致死循环与无法键入
    exec "$INSTALL_PATH" </dev/tty
else
    echo -e "安装完成！请在终端输入 ${YELLOW}vps${PLAIN} 打开管理菜单。"
fi
