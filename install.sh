#!/bin/bash
set -e

# ====================================================================
# VPS Sing-box 节点管理服务端 一键安装脚本
# ====================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
PLAIN='\033[0m'

if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}错误：请以 root 身份运行此脚本！${PLAIN}"
    exit 1
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

BIN_URL="https://raw.githubusercontent.com/santian666/vps-management/main/bin/vps"
if [ "$ARCH" = "arm64" ]; then
    BIN_URL="https://raw.githubusercontent.com/santian666/vps-management/main/bin/vps-arm64"
fi

INSTALL_PATH="/usr/local/bin/vps"
echo -e "${GREEN}正在从 GitHub 下载最新版本...${PLAIN}"
curl -fsSL --connect-timeout 10 --retry 3 "$BIN_URL" -o "$INSTALL_PATH"
chmod +x "$INSTALL_PATH"

echo -e "===================================================================="
echo -e "${GREEN}安装成功！${PLAIN}"
echo -e "以后无论在哪个目录，直接输入 ${YELLOW}vps${PLAIN} 回车即可打开管理菜单！"
echo -e "===================================================================="
echo ""

# 自动运行管理程序
exec "$INSTALL_PATH"
