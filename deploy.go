package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	singboxDir        = "/etc/sing-box"
	singboxConfDir    = "/etc/sing-box/conf"
	singboxBackupDir  = "/etc/sing-box/bk"
	singboxBinDir     = "/etc/sing-box/bin"
	singboxBinPath    = "/etc/sing-box/bin/sing-box"
	singboxMainConfig = "/etc/sing-box/config.json"
	singboxAllJSON    = "/etc/sing-box/conf/all.json"
	singboxMetaJSON   = "/etc/sing-box/vps_nodes_meta.json"
	tlsCertPath       = "/etc/sing-box/bin/tls.cer"
	tlsKeyPath        = "/etc/sing-box/bin/tls.key"
	logDirPath        = "/var/log/sing-box"
	logFilePath       = "/var/log/sing-box/sing-box.log"
)

// EnsureEnvironment 启动时自动检测并部署最新版 sing-box、TLS 证书、四重日志防爆盘及系统调优
func EnsureEnvironment() {
	if runtime.GOOS != "linux" {
		fmt.Println("⚠️  当前非 Linux 环境，仅运行本地演示模式（跳过 systemd/内核部署）。")
		return
	}

	installGlobalShortcut()
	_ = os.MkdirAll(singboxConfDir, 0755)
	_ = os.MkdirAll(singboxBackupDir, 0755)
	_ = os.MkdirAll(singboxBinDir, 0755)
	_ = os.MkdirAll(logDirPath, 0755)

	fmt.Println("====================================================================")
	fmt.Println("正在执行 Chained Proxy 环境自检与部署保护...")

	// 1. 若尚未安装基础框架，先执行基础部署或创建 systemd 服务
	if !isSingboxInstalled() {
		fmt.Println("-> 未检测到 sing-box，正在安装基础环境与 BBR...")
		runBaseInstallScript()
	}

	// 2. 检查并强制升级到 GitHub 官方最新正式版 sing-box 内核（保障 AnyTLS 等最新协议支持）
	ensureLatestSingboxBinary()

	// 3. 确保主配置文件 /etc/sing-box/config.json 和 /etc/sing-box/conf/all.json 存在且启用日志防爆盘级别
	ensureBaseConfigFiles()

	// 4. 确保 systemd 服务文件存在且开启高并发句柄限制 LimitNOFILE
	ensureSystemdService()

	// 5. 确保 AnyTLS 所需的自签名证书 (/etc/sing-box/bin/tls.cer & tls.key) 存在
	if err := ensureSelfSignedTLSCert(); err != nil {
		fmt.Printf("⚠️  生成自签名证书警告: %v\n", err)
	}

	// 6. 部署四重日志与缓存自动清理防爆盘机制
	setupLogProtectionAndCleaners()

	// 7. 优化多 IP 源进源出内核参数 (rp_filter=0, ip_nonlocal_bind=1)
	optimizeKernelNetwork()

	// 8. 启动并检查服务
	_ = restartSingboxQuiet()
	fmt.Println("✅ 环境自检与防爆盘保护已完成！")
}

// installGlobalShortcut 将程序自身注册为 /usr/local/bin/vps 和 /usr/local/bin/chained-proxy
func installGlobalShortcut() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	exe, _ = filepath.EvalSymlinks(exe)
	data, err := os.ReadFile(exe)
	if err != nil || len(data) == 0 {
		return
	}
	for _, target := range []string{"/usr/local/bin/vps", "/usr/local/bin/chained-proxy"} {
		if exe != target {
			_ = os.WriteFile(target, data, 0755)
		}
	}
	fmt.Println("💡 已注册全局快捷指令：今后在任意目录输入 vps 或 chained-proxy 回车即可打开本管理菜单。")
}

func isSingboxInstalled() bool {
	for _, p := range []string{singboxBinPath, "/usr/local/bin/sing-box", "/usr/bin/sing-box"} {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return true
		}
	}
	_, err := exec.LookPath("sing-box")
	return err == nil
}

func resolveSingboxBin() string {
	for _, p := range []string{singboxBinPath, "/usr/local/bin/sing-box", "/usr/bin/sing-box"} {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	if p, err := exec.LookPath("sing-box"); err == nil {
		return p
	}
	return singboxBinPath
}

func runBaseInstallScript() {
	script := `
cd /
export TERM=xterm
install_url='https://github.com/233boy/sing-box/raw/main/install.sh'
tmp_file=$(mktemp /tmp/vps-mgmt-sb-install.XXXXXX)
trap 'rm -f "$tmp_file"' EXIT
if command -v curl >/dev/null 2>&1; then
  curl -fsSL --connect-timeout 10 --max-time 60 "$install_url" -o "$tmp_file" || true
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$tmp_file" --timeout=30 "$install_url" || true
fi
if [ -s "$tmp_file" ]; then
  bash "$tmp_file" || true
fi
sb_path=$(command -v sb 2>/dev/null || true)
if [ -x "$sb_path" ]; then
  "$sb_path" bbr >/dev/null 2>&1 || true
fi
`
	runBashCommand(script, 300*time.Second)
}

func getLocalSingboxVersion() string {
	bin := resolveSingboxBin()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "version").CombinedOutput()
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`sing-box version ([0-9]+\.[0-9]+\.[0-9]+(?:\-[a-zA-Z0-9\.]+)?)`)
	if m := re.FindStringSubmatch(string(out)); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) > 0 {
		return strings.TrimSpace(lines[0])
	}
	return ""
}

type githubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func ensureLatestSingboxBinary() {
	localVer := getLocalSingboxVersion()
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", "https://api.github.com/repos/SagerNet/sing-box/releases/latest", nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "vps-management-go-server/1.0")
	resp, err := client.Do(req)
	if err != nil {
		if localVer != "" {
			fmt.Printf("-> 当前本机 sing-box 版本: v%s (GitHub 版本检查跳过)\n", strings.TrimPrefix(localVer, "v"))
		}
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil || release.TagName == "" {
		return
	}
	latestVer := strings.TrimPrefix(strings.TrimSpace(release.TagName), "v")
	cleanLocal := strings.TrimPrefix(strings.TrimSpace(localVer), "v")
	if cleanLocal != "" && cleanLocal == latestVer {
		fmt.Printf("-> 当前 sing-box 内核已是官方最新版: v%s\n", latestVer)
		return
	}

	arch := "amd64"
	switch runtime.GOARCH {
	case "arm64":
		arch = "arm64"
	case "arm":
		arch = "armv7"
	case "386":
		arch = "386"
	}
	expectedSuffix := fmt.Sprintf("linux-%s.tar.gz", arch)
	var downloadURL string
	for _, asset := range release.Assets {
		if strings.HasSuffix(asset.Name, expectedSuffix) && !strings.Contains(asset.Name, "musl") {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}
	if downloadURL == "" {
		downloadURL = fmt.Sprintf("https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-linux-%s.tar.gz", latestVer, latestVer, arch)
	}

	fmt.Printf("-> 正在升级/安装官方最新版 sing-box 内核 (v%s -> v%s)...\n", emptyFallback(cleanLocal, "未安装"), latestVer)
	if err := downloadAndInstallSingboxTarGz(downloadURL); err != nil {
		fmt.Printf("⚠️  自动下载最新版 sing-box 失败: %v\n", err)
		return
	}
	fmt.Printf("✅ 已成功升级至 sing-box 最新版: v%s\n", getLocalSingboxVersion())
}

func downloadAndInstallSingboxTarGz(url string) error {
	client := &http.Client{Timeout: 180 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP 状态码 %d", resp.StatusCode)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var binaryData []byte
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag == tar.TypeReg && filepath.Base(hdr.Name) == "sing-box" {
			binaryData, err = io.ReadAll(tr)
			if err != nil {
				return err
			}
			break
		}
	}
	if len(binaryData) == 0 {
		return fmt.Errorf("压缩包中未找到 sing-box 可执行文件")
	}
	_ = os.MkdirAll(singboxBinDir, 0755)
	targets := []string{singboxBinPath, "/usr/local/bin/sing-box"}
	if _, err := os.Stat("/usr/bin/sing-box"); err == nil {
		targets = append(targets, "/usr/bin/sing-box")
	}
	for _, target := range targets {
		tmp := target + ".tmp"
		if err := os.WriteFile(tmp, binaryData, 0755); err == nil {
			_ = os.Rename(tmp, target)
			_ = os.Chmod(target, 0755)
		}
	}
	return nil
}

func ensureBaseConfigFiles() {
	_ = os.MkdirAll(singboxConfDir, 0755)
	_ = os.MkdirAll(logDirPath, 0755)

	dnsDirect := map[string]any{
		"servers": []any{
			map[string]any{
				"tag":    "dns-direct",
				"type":   "local",
				"detour": "direct",
			},
		},
	}

	mainCfg := map[string]any{
		"log": map[string]any{
			"disabled":  false,
			"level":     "warn",
			"output":    logFilePath,
			"timestamp": true,
		},
		"dns":       dnsDirect,
		"inbounds":  []any{},
		"outbounds": []any{map[string]any{"tag": "direct", "type": "direct"}},
		"route": map[string]any{
			"default_domain_resolver": "dns-direct",
			"rules":                   []any{},
		},
	}
	if data, err := os.ReadFile(singboxMainConfig); err == nil && len(data) > 0 {
		var parsed map[string]any
		if json.Unmarshal(data, &parsed) == nil {
			parsed["log"] = mainCfg["log"]
			parsed["dns"] = dnsDirect
			if parsed["route"] == nil {
				parsed["route"] = map[string]any{}
			}
			if r, ok := parsed["route"].(map[string]any); ok {
				r["default_domain_resolver"] = "dns-direct"
				if r["rules"] == nil {
					r["rules"] = []any{}
				}
			}
			if out, ok := parsed["outbounds"].([]any); !ok || len(out) == 0 {
				parsed["outbounds"] = mainCfg["outbounds"]
			}
			mainCfg = parsed
		}
	}
	_ = writeFormattedJSON(singboxMainConfig, mainCfg)

	if _, err := os.Stat(singboxAllJSON); os.IsNotExist(err) {
		initialAll := map[string]any{
			"log": map[string]any{
				"disabled":  false,
				"level":     "warn",
				"output":    logFilePath,
				"timestamp": true,
			},
			"dns":       dnsDirect,
			"inbounds":  []any{},
			"outbounds": []any{},
			"route": map[string]any{
				"default_domain_resolver": "dns-direct",
				"rules":                   []any{},
			},
		}
		_ = writeFormattedJSON(singboxAllJSON, initialAll)
	}
}

func ensureSystemdService() {
	servicePath := "/etc/systemd/system/sing-box.service"
	bin := resolveSingboxBin()
	if _, err := os.Stat(servicePath); os.IsNotExist(err) {
		unit := fmt.Sprintf(`[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ExecStart=%s run -c %s -C %s
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`, bin, singboxMainConfig, singboxConfDir)
		_ = os.WriteFile(servicePath, []byte(unit), 0644)
	}

	dropInDir := "/etc/systemd/system/sing-box.service.d"
	_ = os.MkdirAll(dropInDir, 0755)
	// 使用 ExecStart= 强制清除官方包可能遗漏 -C 的默认参数，锁定必须加载 /etc/sing-box/conf
	dropIn := fmt.Sprintf(`[Service]
LogsDirectory=sing-box
ExecStart=
ExecStart=%s run -c %s -C %s
LimitNOFILE=1048576
StandardOutput=append:/var/log/sing-box/service.log
StandardError=append:/var/log/sing-box/service.log
`, bin, singboxMainConfig, singboxConfDir)
	_ = os.WriteFile(filepath.Join(dropInDir, "90-vps-management-log.conf"), []byte(dropIn), 0644)
	runBashCommand("systemctl daemon-reload >/dev/null 2>&1 || true; systemctl enable sing-box >/dev/null 2>&1 || true", 15*time.Second)
}

// ensureSelfSignedTLSCert 生成 10 年期自签名证书供 AnyTLS 协议使用
func ensureSelfSignedTLSCert() error {
	if info1, err1 := os.Stat(tlsCertPath); err1 == nil && info1.Size() > 0 {
		if info2, err2 := os.Stat(tlsKeyPath); err2 == nil && info2.Size() > 0 {
			return nil
		}
	}
	_ = os.MkdirAll(filepath.Dir(tlsCertPath), 0755)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "bing.com",
			Organization: []string{"Microsoft Corporation"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"bing.com", "*.bing.com"},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	certOut, err := os.OpenFile(tlsCertPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	keyOut, err := os.OpenFile(tlsKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	return pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
}

// setupLogProtectionAndCleaners 部署 4 重日志与缓存自动清理机制
func setupLogProtectionAndCleaners() {
	// 1. Journald 50M 限额
	_ = os.MkdirAll("/etc/systemd/journald.conf.d", 0755)
	journalConf := `[Journal]
SystemMaxUse=50M
RuntimeMaxUse=30M
MaxRetentionSec=3day
`
	_ = os.WriteFile("/etc/systemd/journald.conf.d/90-singbox-limit.conf", []byte(journalConf), 0644)

	// 2. Logrotate 配置
	_ = os.MkdirAll("/etc/logrotate.d", 0755)
	logrotateConf := `/var/log/sing-box.log /var/log/sing-box/*.log {
  daily
  maxsize 10M
  rotate 3
  compress
  dateext
  dateformat -%Y%m%d%H%M%S
  missingok
  notifempty
  copytruncate
}
`
	_ = os.WriteFile("/etc/logrotate.d/vps-management-singbox", []byte(logrotateConf), 0644)

	// 3. 定时清理脚本 (/usr/local/sbin/vps-management-singbox-log-clean)
	_ = os.MkdirAll("/usr/local/sbin", 0755)
	cleanScript := `#!/bin/sh
set -eu
max_bytes=10485760
for log_file in /var/log/sing-box.log /var/log/sing-box/*.log; do
  [ -f "$log_file" ] || continue
  log_size=$(wc -c < "$log_file" 2>/dev/null || echo 0)
  if [ "$log_size" -gt "$max_bytes" ]; then
    : > "$log_file"
  fi
done
find /var/log/sing-box -maxdepth 1 -type f -name '*.log.*' -mtime +3 -delete 2>/dev/null || true
find /var/log -maxdepth 1 -type f -name 'sing-box.log.*' -mtime +3 -delete 2>/dev/null || true
rm -rf /tmp/sb_node_ip /tmp/vps-mgmt-* /tmp/vps-management-* 2>/dev/null || true
if command -v journalctl >/dev/null 2>&1; then
  journalctl --vacuum-size=50M >/dev/null 2>&1 || true
fi
`
	_ = os.WriteFile("/usr/local/sbin/vps-management-singbox-log-clean", []byte(cleanScript), 0755)

	// 4. Systemd Timer (每 2 小时自动执行一次) + Cron 兜底
	serviceUnit := `[Unit]
Description=清理并截断 sing-box 日志与缓存

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vps-management-singbox-log-clean
StandardOutput=null
StandardError=null
`
	timerUnit := `[Unit]
Description=每 2 小时自动清理 sing-box 日志与缓存防爆盘

[Timer]
OnBootSec=5min
OnUnitActiveSec=2h
Persistent=true
Unit=vps-management-singbox-log-clean.service

[Install]
WantedBy=timers.target
`
	_ = os.WriteFile("/etc/systemd/system/vps-management-singbox-log-clean.service", []byte(serviceUnit), 0644)
	_ = os.WriteFile("/etc/systemd/system/vps-management-singbox-log-clean.timer", []byte(timerUnit), 0644)
	_ = os.MkdirAll("/etc/cron.d", 0755)
	_ = os.WriteFile("/etc/cron.d/vps-management-singbox-clean", []byte("0 */2 * * * root /usr/local/sbin/vps-management-singbox-log-clean >/dev/null 2>&1\n"), 0644)

	runBashCommand(`
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl restart systemd-journald >/dev/null 2>&1 || true
systemctl enable --now vps-management-singbox-log-clean.timer >/dev/null 2>&1 || true
/usr/local/sbin/vps-management-singbox-log-clean >/dev/null 2>&1 || true
`, 20*time.Second)

	CleanLogsAndCacheNow()
}

// CleanLogsAndCacheNow 立即清理超限日志与临时缓存（在每次菜单操作及重启前自动调用）
func CleanLogsAndCacheNow() {
	if runtime.GOOS != "linux" {
		return
	}
	const maxLogBytes = 10 * 1024 * 1024 // 10MB
	files, _ := filepath.Glob("/var/log/sing-box/*.log")
	files = append(files, "/var/log/sing-box.log")
	for _, f := range files {
		if info, err := os.Stat(f); err == nil && info.Size() > maxLogBytes {
			_ = os.Truncate(f, 0)
		}
	}
	// 清理历史备份过多文件（保留最近 30 份备份，防止 bk 目录膨胀）
	if entries, err := os.ReadDir(singboxBackupDir); err == nil && len(entries) > 30 {
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Name() < entries[j].Name()
		})
		for i := 0; i < len(entries)-30; i++ {
			_ = os.Remove(filepath.Join(singboxBackupDir, entries[i].Name()))
		}
	}
}

func optimizeKernelNetwork() {
	if runtime.GOOS != "linux" {
		return
	}
	sysctlConf := `net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.ip_nonlocal_bind = 1
fs.file-max = 1048576
`
	_ = os.MkdirAll("/etc/sysctl.d", 0755)
	_ = os.WriteFile("/etc/sysctl.d/99-vps-singbox.conf", []byte(sysctlConf), 0644)
	runBashCommand("sysctl --system >/dev/null 2>&1 || true", 10*time.Second)
}

// AllowFirewallPorts 自动在防火墙放行节点监听端口
func AllowFirewallPorts(ports []int) {
	if runtime.GOOS != "linux" || len(ports) == 0 {
		return
	}
	minPort, maxPort := ports[0], ports[0]
	for _, p := range ports {
		if p < minPort {
			minPort = p
		}
		if p > maxPort {
			maxPort = p
		}
	}
	if minPort <= 0 {
		return
	}
	portRange := strconv.Itoa(minPort)
	if maxPort > minPort {
		portRange = fmt.Sprintf("%d:%d", minPort, maxPort)
	}
	cmd := fmt.Sprintf(`
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow %s/tcp >/dev/null 2>&1 || true
  ufw allow %s/udp >/dev/null 2>&1 || true
fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --add-port=%s/tcp --permanent >/dev/null 2>&1 || true
  firewall-cmd --add-port=%s/udp --permanent >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true
fi
`, portRange, portRange, strings.ReplaceAll(portRange, ":", "-"), strings.ReplaceAll(portRange, ":", "-"))
	runBashCommand(cmd, 15*time.Second)
}

// ValidateSingboxConfig 调用 sing-box check 检验配置合法性
func ValidateSingboxConfig() error {
	if runtime.GOOS != "linux" {
		return nil
	}
	bin := resolveSingboxBin()
	if _, err := os.Stat(bin); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "check", "-c", singboxMainConfig, "-C", singboxConfDir).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// ApplyAndRestartSingbox 无论执行哪个菜单功能，最后统一清理缓存、校验配置并重启 sing-box 生效
func ApplyAndRestartSingbox(reason string) {
	fmt.Println("--------------------------------------------------------------------")
	CleanLogsAndCacheNow()

	if runtime.GOOS != "linux" {
		fmt.Printf("🔄 [%s] 本地模式：已模拟清理日志缓存并重启 sing-box 生效。\n", reason)
		fmt.Println("--------------------------------------------------------------------")
		return
	}

	// 清理 /etc/sing-box/conf 下除 all.json 以外的残留碎片文件，避免冲突
	if entries, err := os.ReadDir(singboxConfDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") && e.Name() != "all.json" {
				_ = os.Remove(filepath.Join(singboxConfDir, e.Name()))
			}
		}
	}

	if err := ValidateSingboxConfig(); err != nil {
		fmt.Printf("❌ [配置校验失败] sing-box check 报错:\n%v\n", err)
		fmt.Println("--------------------------------------------------------------------")
		return
	}

	// 自动放行监听端口
	if nodes, err := LoadCurrentNodes(); err == nil && len(nodes) > 0 {
		var ports []int
		for _, n := range nodes {
			if n.ListenPort > 0 {
				ports = append(ports, n.ListenPort)
			}
		}
		AllowFirewallPorts(ports)
	}

	_ = restartSingboxQuiet()
	status := GetSingboxStatusText()
	fmt.Printf("✅ [%s] 已自动清理日志缓存并重启 sing-box 生效！(当前状态: %s)\n", reason, status)
	fmt.Println("--------------------------------------------------------------------")
}

func restartSingboxQuiet() error {
	cmd := `
if command -v systemctl >/dev/null 2>&1; then
  systemctl restart sing-box >/dev/null 2>&1 && exit 0
fi
for p in /usr/local/bin/sb /usr/bin/sb /bin/sb /etc/sing-box/sb; do
  if [ -x "$p" ]; then "$p" restart >/dev/null 2>&1 && exit 0; fi
done
if command -v service >/dev/null 2>&1; then
  service sing-box restart >/dev/null 2>&1 && exit 0
fi
`
	runBashCommand(cmd, 30*time.Second)
	return nil
}

func GetSingboxStatusText() string {
	if runtime.GOOS != "linux" {
		return "演示运行中 (active)"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "systemctl", "is-active", "sing-box").CombinedOutput(); err == nil {
		s := strings.TrimSpace(string(out))
		if s == "active" {
			return "运行中 (active)"
		}
	}
	if out, err := exec.CommandContext(ctx, "pgrep", "-x", "sing-box").CombinedOutput(); err == nil && len(bytes.TrimSpace(out)) > 0 {
		return "运行中 (pid:" + strings.ReplaceAll(strings.TrimSpace(string(out)), "\n", ",") + ")"
	}
	return "未运行 (stopped)"
}

// DetectLocalPublicIPs 探测本机所有公网 IPv4 地址（主 IP 排在第一位）
func DetectLocalPublicIPs() (string, []string) {
	seen := map[string]bool{}
	var ips []string
	addIP := func(raw string) {
		raw = strings.TrimSpace(raw)
		parsed := net.ParseIP(raw)
		if parsed == nil || parsed.To4() == nil || parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() || parsed.IsUnspecified() {
			return
		}
		ipStr := parsed.String()
		if !seen[ipStr] {
			seen[ipStr] = true
			ips = append(ips, ipStr)
		}
	}

	// 1. 先探测默认路由网卡或外部公网出口主 IP
	for _, url := range []string{"https://api.ipify.org", "https://ipinfo.io/ip", "https://icanhazip.com"} {
		client := &http.Client{Timeout: 3 * time.Second}
		if resp, err := client.Get(url); err == nil {
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			addIP(string(b))
			if len(ips) > 0 {
				break
			}
		}
	}

	// 2. 枚举本机所有网卡上的全球范围公网 IPv4
	if addrs, err := net.InterfaceAddrs(); err == nil {
		var ifaceIPs []string
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() {
				ifaceIPs = append(ifaceIPs, ip.String())
			}
		}
		sort.Strings(ifaceIPs)
		for _, ip := range ifaceIPs {
			addIP(ip)
		}
	}

	primary := "127.0.0.1"
	if len(ips) > 0 {
		primary = ips[0]
	}
	return primary, ips
}

func runBashCommand(script string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", script)
	out, _ := cmd.CombinedOutput()
	return string(out)
}
