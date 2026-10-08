package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

var stdinReader = bufio.NewReader(os.Stdin)

func main() {
	// 0. 接管控制终端输入（防止因 curl | bash 管道传入导致 EOF 死循环与按键无法读取）
	initTerminalStdin()

	// 1. 启动时自动执行环境部署、升级最新 sing-box、自签名证书及 4 重日志防爆盘守护
	EnsureEnvironment()

	// 2. 进入交互主菜单循环
	for {
		primaryIP, allIPs := DetectLocalPublicIPs()
		nodes, _ := LoadCurrentNodes()
		ver := emptyFallback(getLocalSingboxVersion(), "latest")
		status := GetSingboxStatusText()

		fmt.Println()
		fmt.Println("====================================================================")
		fmt.Println("              Chained Proxy 链式代理节点管理 (服务端版)")
		fmt.Printf("  本机主IP: %s (共 %d 个公网IP) | 内核: v%s\n", primaryIP, maxInt(len(allIPs), 1), strings.TrimPrefix(ver, "v"))
		fmt.Printf("  服务状态: %-22s | 当前节点数: %d\n", status, len(nodes))
		fmt.Println("====================================================================")
		fmt.Println("  1. 新增节点")
		fmt.Println("  2. 新增多IP节点 (纯直连)")
		fmt.Println("  3. 修改落地 (按IP匹配更新 SOCKS5 端口/账号/密码)")
		fmt.Println("  4. 节点列表")
		fmt.Println("  5. 配置编辑")
		fmt.Println("  6. 删除节点")
		fmt.Println("  0. 退出 (输入 0 或 7 退出)")
		fmt.Println("====================================================================")

		choice := promptLine("请输入菜单选项 [0-7]: ")
		if choice == "" {
			continue
		}
		switch choice {
		case "1":
			handleMenuAddNode(primaryIP)
		case "2":
			handleMenuAddMultiIPNodes(primaryIP, allIPs)
		case "3":
			handleMenuModifySocks5Outbound(primaryIP)
		case "4":
			handleMenuNodeList(primaryIP)
		case "5":
			handleMenuEditConfig()
		case "6":
			handleMenuDeleteNodes(primaryIP)
		case "0", "7", "q", "exit", "quit":
			fmt.Println("👋 已退出 Chained Proxy 节点管理程序（后台 sing-box 服务保持运行）。")
			return
		default:
			fmt.Println("⚠️  无效的菜单选项，请输入 1 ~ 6，或输入 0 / 7 退出。")
		}
	}
}

// ==================== 菜单 1：新增节点 ====================
func handleMenuAddNode(primaryIP string) {
	fmt.Println("\n-------------------- [ 1. 新增节点 ] --------------------")
	inboundProto, realitySNI, ok := promptInboundProtocol()
	if !ok {
		return
	}

	fmt.Println("\n请选择出站协议 (Outbound，仅限以下 2 种):")
	fmt.Println("  1) Direct（直连 - 以本机IP作为协议名）")
	fmt.Println("  2) SOCKS5（落地 - 以SOCKS5的IP作为协议名）")
	outChoice := promptLine("请输入出站协议序号 [1-2，回车默认 1]: ")
	if outChoice == "" {
		outChoice = "1"
	}
	if outChoice != "1" && outChoice != "2" {
		fmt.Println("⚠️  已取消：无效的出站协议选项。")
		return
	}

	nodes, err := LoadCurrentNodes()
	if err != nil {
		fmt.Printf("❌ 读取现有节点失败: %v\n", err)
		return
	}

	var created []ServerNode

	if outChoice == "1" {
		// Direct 直连模式
		countStr := promptLine("请输入生成节点数量 [回车默认 1]: ")
		count, err := strconv.Atoi(countStr)
		if err != nil || count <= 0 {
			count = 1
		}
		defaultPort := NextAvailableStartPort(nodes, count, 20000)
		portStr := promptLine(fmt.Sprintf("请输入起始监听端口 [回车默认 %d]: ", defaultPort))
		startPort, err := strconv.Atoi(portStr)
		if err != nil || startPort <= 0 || startPort+count-1 > 65535 {
			startPort = defaultPort
		}

		for i := 0; i < count; i++ {
			port := startPort + i
			n := BuildNewNode(inboundProto, "::", port, realitySNI, "direct", "", nil, primaryIP)
			nodes = append(nodes, n)
			created = append(created, n)
		}
	} else {
		// SOCKS5 落地出站模式
		fmt.Println("\n请粘贴 SOCKS5 落地列表（支持一行一条或直接多行批量粘贴，输入完成按【回车键】确认）：")
		lines := readMultiLines()
		socksList := ParseSocks5Lines(lines)
		if len(socksList) == 0 {
			fmt.Println("⚠️  未识别到有效的 SOCKS5 落地，已取消。")
			return
		}

		// 1.5秒并发快速探活提醒
		socksList = confirmSocks5Liveness(socksList)
		if len(socksList) == 0 {
			fmt.Println("⚠️  没有可用的 SOCKS5 节点，已取消。")
			return
		}

		defaultCount := len(socksList)
		countStr := promptLine(fmt.Sprintf("请输入生成节点数量 [回车默认 %d 个，与 SOCKS5 数量一致]: ", defaultCount))
		count, err := strconv.Atoi(countStr)
		if err != nil || count <= 0 {
			count = defaultCount
		}
		defaultPort := NextAvailableStartPort(nodes, count, 20000)
		portStr := promptLine(fmt.Sprintf("请输入起始监听端口 [回车默认 %d]: ", defaultPort))
		startPort, err := strconv.Atoi(portStr)
		if err != nil || startPort <= 0 || startPort+count-1 > 65535 {
			startPort = defaultPort
		}

		for i := 0; i < count; i++ {
			port := startPort + i
			ep := socksList[i%len(socksList)]
			n := BuildNewNode(inboundProto, "::", port, realitySNI, "socks", "", &ep, primaryIP)
			nodes = append(nodes, n)
			created = append(created, n)
		}
	}

	if err := SaveNodesToAllJSON(nodes); err != nil {
		fmt.Printf("❌ 保存配置失败: %v\n", err)
		return
	}

	// 强制重启一次 sing-box 生效
	ApplyAndRestartSingbox("1.新增节点")

	// 打印本次生成的节点结果并保存带时间戳文件
	printAndSaveOperationNodes("新增", created, primaryIP)
}

// ==================== 菜单 2：新增多IP节点（纯直连） ====================
func handleMenuAddMultiIPNodes(primaryIP string, allIPs []string) {
	fmt.Println("\n-------------------- [ 2. 新增多IP节点 (纯直连) ] --------------------")
	if len(allIPs) == 0 {
		allIPs = []string{primaryIP}
	}
	nodes, err := LoadCurrentNodes()
	if err != nil {
		fmt.Printf("❌ 读取现有节点失败: %v\n", err)
		return
	}

	usedIPs := map[string]bool{}
	for _, n := range nodes {
		if n.ListenHost != "" && n.ListenHost != "::" && n.ListenHost != "0.0.0.0" {
			usedIPs[n.ListenHost] = true
		}
		if n.BindIP != "" {
			usedIPs[n.BindIP] = true
		}
	}

	var uncreatedIPs []string
	for _, ip := range allIPs {
		if !usedIPs[ip] {
			uncreatedIPs = append(uncreatedIPs, ip)
		}
	}

	fmt.Printf("检测到本机公网 IPv4 共 %d 个（已创建节点: %d 个，未创建节点: %d 个）\n",
		len(allIPs), len(allIPs)-len(uncreatedIPs), len(uncreatedIPs))
	fmt.Printf("本机公网 IP 列表: %s\n", strings.Join(allIPs, ", "))

	targetIPs := uncreatedIPs
	if len(uncreatedIPs) > 0 && len(uncreatedIPs) < len(allIPs) {
		fmt.Println("请选择要创建节点的本机 IP 范围:")
		fmt.Printf("  1) 仅未创建节点的 %d 个 IP (默认)\n", len(uncreatedIPs))
		fmt.Printf("  2) 本机全部 %d 个公网 IP\n", len(allIPs))
		scope := promptLine("请选择 [1-2，回车默认 1]: ")
		if scope == "2" {
			targetIPs = allIPs
		}
	} else if len(uncreatedIPs) == 0 {
		fmt.Println("💡 当前所有公网 IP 均已创建过节点。")
		confirm := promptLine("是否继续为本机全部公网 IP 新增一批端口节点？[y/N]: ")
		if !strings.EqualFold(confirm, "y") && !strings.EqualFold(confirm, "yes") {
			return
		}
		targetIPs = allIPs
	}

	inboundProto, realitySNI, ok := promptInboundProtocol()
	if !ok {
		return
	}

	defaultPort := NextAvailableStartPort(nodes, len(targetIPs), 20000)
	portStr := promptLine(fmt.Sprintf("请输入起始监听端口 [回车默认 %d]: ", defaultPort))
	startPort, err := strconv.Atoi(portStr)
	if err != nil || startPort <= 0 || startPort+len(targetIPs)-1 > 65535 {
		startPort = defaultPort
	}

	var created []ServerNode
	for i, ip := range targetIPs {
		port := startPort + i
		// 多IP节点固定为 Direct 直连，且入站监听该 IP、出站绑定 inet4_bind_address 为该 IP
		n := BuildNewNode(inboundProto, ip, port, realitySNI, "direct", ip, nil, primaryIP)
		nodes = append(nodes, n)
		created = append(created, n)
	}

	if err := SaveNodesToAllJSON(nodes); err != nil {
		fmt.Printf("❌ 保存配置失败: %v\n", err)
		return
	}

	// 强制重启一次 sing-box 生效
	ApplyAndRestartSingbox("2.新增多IP节点")

	// 打印本次新增的多IP节点结果并保存带时间戳文件
	printAndSaveOperationNodes("多IP", created, primaryIP)
}

// ==================== 菜单 3：修改落地（仅针对出站 SOCKS5 按 IP 自动匹配更新端口/账号/密码） ====================
func handleMenuModifySocks5Outbound(primaryIP string) {
	fmt.Println("\n-------------------- [ 3. 修改落地 (仅针对出站 SOCKS5) ] --------------------")
	fmt.Println("💡 说明：保持原入站节点协议、端口、UUID/密码完全不变；")
	fmt.Println("         直接粘贴新的 SOCKS5，程序自动按 SOCKS5 的 IP 匹配节点并更新端口、账号、密码。")

	nodes, err := LoadCurrentNodes()
	if err != nil {
		fmt.Printf("❌ 读取现有节点失败: %v\n", err)
		return
	}

	socksCount := 0
	for _, n := range nodes {
		if strings.EqualFold(n.OutboundType, "socks") {
			socksCount++
		}
	}
	if socksCount == 0 {
		fmt.Println("⚠️  当前没有任何出站为 SOCKS5 的节点可供修改。")
		ApplyAndRestartSingbox("3.修改落地")
		return
	}

	fmt.Printf("当前共有 %d 个 SOCKS5 出站节点。请粘贴新的 SOCKS5 列表（支持一行一条或直接多行批量粘贴，输入完成按【回车键】确认）：\n", socksCount)
	lines := readMultiLines()
	updates := ParseSocks5Lines(lines)
	if len(updates) == 0 {
		fmt.Println("⚠️  未识别到有效的 SOCKS5 格式，已取消。")
		return
	}

	updates = confirmSocks5Liveness(updates)
	if len(updates) == 0 {
		fmt.Println("⚠️  已取消修改。")
		return
	}

	allNodes, updatedNodes, unmatched := UpdateSocks5OutboundsByIP(nodes, updates)
	if len(updatedNodes) == 0 {
		fmt.Println("⚠️  未能匹配到任何相同 SOCKS5 IP 的节点，未发生更改。")
		if len(unmatched) > 0 {
			var ips []string
			for _, u := range unmatched {
				ips = append(ips, u.Host)
			}
			fmt.Printf("   未匹配的 SOCKS5 IP: %s\n", strings.Join(ips, ", "))
		}
		ApplyAndRestartSingbox("3.修改落地")
		return
	}

	if err := SaveNodesToAllJSON(allNodes); err != nil {
		fmt.Printf("❌ 保存更新后的配置失败: %v\n", err)
		return
	}

	fmt.Printf("\n✅ 成功匹配 IP 并更新了 %d 个节点的 SOCKS5 出口参数（原入站协议与链接保持不变）！\n", len(updatedNodes))
	if len(unmatched) > 0 {
		fmt.Printf("ℹ️  另有 %d 条输入的 SOCKS5 未在现有节点中找到对应 IP。\n", len(unmatched))
	}

	// 强制重启一次 sing-box 生效
	ApplyAndRestartSingbox("3.修改落地")

	// 打印本次修改落地涉及的节点结果并保存带时间戳文件
	printAndSaveOperationNodes("改落地", updatedNodes, primaryIP)
}

// ==================== 菜单 4：节点列表 ====================
func handleMenuNodeList(primaryIP string) {
	fmt.Println("\n-------------------- [ 4. 节点列表 ] --------------------")
	nodes, err := LoadCurrentNodes()
	if err != nil {
		fmt.Printf("❌ 读取节点失败: %v\n", err)
		return
	}
	if len(nodes) == 0 {
		fmt.Println("当前没有任何节点。")
		ApplyAndRestartSingbox("4.节点列表")
		return
	}

	fmt.Printf("当前共有 %d 个节点 (显示格式：节点序号---节点IP----协议)：\n", len(nodes))
	fmt.Println("--------------------------------------------------------------------")
	for i, n := range nodes {
		fmt.Println(n.ListViewLine(i+1, primaryIP))
	}
	sub := promptLine("输入 [1] 导出全部节点到单个文件 (/home/nodes.txt)，直接按 [回车] 返回主菜单: ")
	if strings.TrimSpace(sub) == "1" {
		printAndSaveOperationNodes("全部", nodes, primaryIP)
	}

	// 无论操作哪个功能，最后统一重启一次 sing-box 生效
	ApplyAndRestartSingbox("4.节点列表")
}

// ==================== 菜单 5：配置编辑 ====================
func handleMenuEditConfig() {
	fmt.Println("\n-------------------- [ 5. 配置编辑 ] --------------------")
	_ = os.MkdirAll(singboxConfDir, 0755)
	if _, err := os.Stat(singboxAllJSON); os.IsNotExist(err) {
		ensureBaseConfigFiles()
	}

	origData, _ := os.ReadFile(singboxAllJSON)
	editor := resolveFriendlyEditor()

	for {
		fmt.Println("====================================================================")
		fmt.Printf("即将使用 [%s] 打开配置文件: %s\n", editor, singboxAllJSON)
		fmt.Println("【重要保存与退出提示 - 请务必牢记】")
		if strings.Contains(editor, "nano") {
			fmt.Println("  👉 1. 保存修改：按 Ctrl + O (字母O)，然后直接按【回车键】确认保存")
			fmt.Println("  👉 2. 退出编辑：按 Ctrl + X 即可退回本菜单")
		} else {
			fmt.Println("  👉 1. 进入编辑：按字母 i 键开始修改内容")
			fmt.Println("  👉 2. 保存退出：先按 Esc 键，输入 :wq 然后按【回车键】保存并退出")
			fmt.Println("  👉 3. 放弃修改：先按 Esc 键，输入 :q! 然后按【回车键】强制退出")
		}
		fmt.Println("====================================================================")
		goIn := promptLine("请按【回车键】打开编辑器 (输入 0 取消并返回主菜单): ")
		if strings.TrimSpace(goIn) == "0" {
			ApplyAndRestartSingbox("5.配置编辑")
			return
		}

		if runtime.GOOS == "linux" {
			cmd := exec.Command(editor, singboxAllJSON)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			_ = cmd.Run()
			stdinReader = bufio.NewReader(os.Stdin)
		} else {
			fmt.Println("ℹ️  当前非 Linux 终端，跳过外部编辑器调用。")
		}

		// 检查 JSON 合法性及 sing-box check
		newData, err := os.ReadFile(singboxAllJSON)
		if err != nil {
			fmt.Printf("❌ 读取修改后的文件失败: %v\n", err)
			break
		}
		var tmp map[string]any
		if jsonErr := json.Unmarshal(newData, &tmp); jsonErr != nil {
			fmt.Printf("\n❌ 检测到 JSON 格式语法错误: %v\n", jsonErr)
		} else if checkErr := ValidateSingboxConfig(); checkErr != nil {
			fmt.Printf("\n❌ sing-box 配置校验未通过:\n%v\n", checkErr)
		} else {
			// 强制保留日志防爆盘级别
			tmp["log"] = map[string]any{
				"disabled":  false,
				"level":     "warn",
				"output":    logFilePath,
				"timestamp": true,
			}
			_ = writeFormattedJSON(singboxAllJSON, tmp)
			fmt.Println("\n✅ 配置文件语法校验通过！")
			break
		}

		fmt.Println("请选择如何处理:")
		fmt.Println("  1) 重新打开编辑器修复错误")
		fmt.Println("  2) 放弃本次修改，自动恢复修改前的正常配置")
		fixChoice := promptLine("请输入 [1-2，默认 2 恢复正常配置]: ")
		if fixChoice == "1" {
			continue
		}
		if len(origData) > 0 {
			_ = os.WriteFile(singboxAllJSON, origData, 0644)
			fmt.Println("✅ 已自动恢复为修改前的正常配置。")
		}
		break
	}

	// 强制重启一次 sing-box 生效
	ApplyAndRestartSingbox("5.配置编辑")
}

// ==================== 菜单 6：删除节点 ====================
func handleMenuDeleteNodes(primaryIP string) {
	fmt.Println("\n-------------------- [ 6. 删除节点 ] --------------------")
	nodes, err := LoadCurrentNodes()
	if err != nil {
		fmt.Printf("❌ 读取节点失败: %v\n", err)
		return
	}
	if len(nodes) == 0 {
		fmt.Println("当前没有任何节点可删除。")
		ApplyAndRestartSingbox("6.删除节点")
		return
	}

	fmt.Printf("当前共有 %d 个节点：\n", len(nodes))
	fmt.Println("--------------------------------------------------------------------")
	for i, n := range nodes {
		fmt.Println(n.ListViewLine(i+1, primaryIP))
	}
	fmt.Println("--------------------------------------------------------------------")
	fmt.Println("💡 支持输入【节点序号】(如 1 或 1,3 或 1-5) 或【节点IP】(本机IP / SOCKS5的IP)，输入 all 清空全部：")
	expr := promptLine("请输入要删除的序号或 IP (直接回车取消): ")
	if strings.TrimSpace(expr) == "" {
		fmt.Println("已取消删除。")
		ApplyAndRestartSingbox("6.删除节点")
		return
	}
	if strings.EqualFold(strings.TrimSpace(expr), "all") {
		confirm := promptLine("确认清空全部节点吗？请输入 y 确认: ")
		if !strings.EqualFold(confirm, "y") && !strings.EqualFold(confirm, "yes") {
			fmt.Println("已取消清空。")
			ApplyAndRestartSingbox("6.删除节点")
			return
		}
	}

	remaining, deleted := FilterDeleteNodes(nodes, expr, primaryIP)
	if len(deleted) == 0 {
		fmt.Println("⚠️  未找到匹配该序号或 IP 的节点，未删除任何节点。")
		ApplyAndRestartSingbox("6.删除节点")
		return
	}

	if err := SaveNodesToAllJSON(remaining); err != nil {
		fmt.Printf("❌ 保存配置失败: %v\n", err)
		return
	}

	if len(remaining) > 0 {
		_, _ = ExportAllNodesToFile(remaining, primaryIP)
	} else {
		_ = os.Remove("/home/nodes.txt")
	}

	fmt.Printf("✅ 已成功删除 %d 个节点（剩余 %d 个节点，已同步更新 /home/nodes.txt）！\n", len(deleted), len(remaining))
	// 强制重启一次 sing-box 生效
	ApplyAndRestartSingbox("6.删除节点")
}

// ==================== 交互与打印辅助函数 ====================

func promptInboundProtocol() (proto string, realitySNI string, ok bool) {
	fmt.Println("请选择入站协议 (Inbound，仅限以下 3 种):")
	fmt.Println("  1) VLESS + Reality")
	fmt.Println("  2) AnyTLS")
	fmt.Println("  3) SOCKS5（自动生成 8 位随机账号与密码）")
	inChoice := promptLine("请输入入站协议序号 [1-3，回车默认 1]: ")
	if inChoice == "" {
		inChoice = "1"
	}
	switch inChoice {
	case "1":
		sni := promptLine("请输入 Reality 伪装域名 SNI [回车默认 stock.adobe.com]: ")
		if sni == "" {
			sni = "stock.adobe.com"
		}
		return "vless-reality", sni, true
	case "2":
		return "anytls", "bing.com", true
	case "3":
		return "socks", "", true
	default:
		fmt.Println("⚠️  无效的入站协议选项。")
		return "", "", false
	}
}

func confirmSocks5Liveness(items []Socks5Endpoint) []Socks5Endpoint {
	fmt.Printf("正在并发检测 %d 条 SOCKS5 落地的连通性...\n", len(items))
	alive, dead := CheckSocks5List(items)
	if len(dead) == 0 {
		fmt.Printf("✅ 全部 %d 条 SOCKS5 落地检测正常！\n", len(alive))
		return items
	}
	fmt.Printf("⚠️  注意：共 %d 条 SOCKS5 中，正常 %d 条，无法连接 %d 条：\n", len(items), len(alive), len(dead))
	for _, d := range dead {
		fmt.Printf("   - 无法连接: %s\n", d.FullText())
	}
	if len(alive) == 0 {
		choice := promptLine("所有 SOCKS5 暂时均未连通，是否仍强制写入配置？[Y/n]: ")
		if strings.EqualFold(choice, "n") || strings.EqualFold(choice, "no") {
			return nil
		}
		return items
	}
	choice := promptLine("请选择：[回车] 照常全部写入  [1] 仅写入检测正常的 SOCKS5: ")
	if strings.TrimSpace(choice) == "1" {
		return alive
	}
	return items
}

func printAndSaveOperationNodes(actionLabel string, nodes []ServerNode, primaryIP string) {
	if len(nodes) == 0 {
		return
	}
	fmt.Printf("\n================ [ 本次%s节点输出结果 (%d个) ] ================\n", actionLabel, len(nodes))
	for _, n := range nodes {
		fmt.Println(n.DeliveryLine(primaryIP))
	}
	fmt.Println("====================================================================")

	// 统一获取服务器当前全部节点，确保所有节点全部汇总在唯一的 /home/nodes.txt 单个文件中，绝不按节点分散保存
	allNodes, err := LoadCurrentNodes()
	if err != nil || len(allNodes) == 0 {
		allNodes = nodes
	}
	if savedPath, err := ExportAllNodesToFile(allNodes, primaryIP); err == nil {
		fmt.Printf("📁 服务器全部 %d 个节点已统一汇总导出至单个文件: %s（所有节点均在此文件中，无多余分散文件）\n", len(allNodes), savedPath)
	} else {
		var lines []string
		for _, n := range allNodes {
			lines = append(lines, n.DeliveryLine(primaryIP))
		}
		if savedPath, err := SaveTimestampedResultFile(actionLabel, lines); err == nil {
			fmt.Printf("📁 全部节点已保存至单个文件: %s\n", savedPath)
		} else {
			fmt.Printf("⚠️  保存结果文件失败: %v\n", err)
		}
	}
}

func resolveFriendlyEditor() string {
	for _, ed := range []string{"nano", "vim", "vi"} {
		if p, err := exec.LookPath(ed); err == nil && p != "" {
			return ed
		}
	}
	if runtime.GOOS == "linux" {
		runBashCommand("if command -v apt-get >/dev/null 2>&1; then apt-get update -y && apt-get install -y nano; elif command -v yum >/dev/null 2>&1; then yum install -y nano; fi", 30*1e9)
		if p, err := exec.LookPath("nano"); err == nil && p != "" {
			return "nano"
		}
	}
	return "vi"
}

// initTerminalStdin 当检测到非控制终端时（例如通过 curl ... | bash 管道传入），自动接管 /dev/tty
func initTerminalStdin() {
	if runtime.GOOS != "linux" {
		return
	}
	fi, err := os.Stdin.Stat()
	if err != nil || (fi.Mode()&os.ModeCharDevice) == 0 {
		if tty, openErr := os.OpenFile("/dev/tty", os.O_RDWR, 0); openErr == nil {
			os.Stdin = tty
			stdinReader = bufio.NewReader(os.Stdin)
		}
	}
}

func promptLine(prompt string) string {
	fmt.Print(prompt)
	for {
		line, err := stdinReader.ReadString('\n')
		if err != nil {
			// 若当前是非字符终端或读到了 EOF（管道被对端关闭）
			if runtime.GOOS == "linux" {
				if tty, openErr := os.OpenFile("/dev/tty", os.O_RDWR, 0); openErr == nil {
					os.Stdin = tty
					stdinReader = bufio.NewReader(os.Stdin)
					continue
				}
			}
			// 确属无可用交互终端（如非交互脚本或用户主动 Ctrl+D），安全退出，杜绝死循环刷屏
			fmt.Println("\n👋 检测到输入流终止 (EOF)，退出程序。请在终端输入 vps 启动。")
			os.Exit(0)
		}
		return strings.TrimSpace(line)
	}
}

func readMultiLines() []string {
	var lines []string
	for {
		line, err := stdinReader.ReadString('\n')
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			// 若当前缓冲区中仍有未读取的数据（用户一次性批量粘贴了包含空行的内容），跳过该空行并继续读取后续行
			if stdinReader.Buffered() > 0 {
				continue
			}
			// 缓冲区已空，且读取到空回车 -> 输入完成
			break
		}
		lines = append(lines, trimmed)
		if err != nil {
			break
		}
	}
	return lines
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
