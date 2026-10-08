package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ServerNode 表示当前服务器上的一个完整节点（对应 all.json 中的一对 inbound + outbound + route rule）
type ServerNode struct {
	InboundTag   string         // all.json 内部唯一 tag，例如 "1.2.3.4_20000"
	ProtocolName string         // 协议显示名（直连为本机IP，SOCKS5出站为SOCKS5的IP）
	InboundType  string         // "vless-reality", "anytls", "socks" (兼容已有其他类型)
	ListenHost   string         // 监听地址 "::" 或特定本机多网卡IP
	ListenPort   int            // 监听端口
	UUID         string         // VLESS UUID 或 AnyTLS 密码
	Username     string         // 入站 SOCKS5 账号
	Password     string         // 入站 SOCKS5 密码
	ServerName   string         // TLS/Reality SNI
	PublicKey    string         // Reality 公钥 (可由私钥自动推导)
	PrivateKey   string         // Reality 私钥
	ShortID      string         // Reality short_id
	OutboundType string         // "direct" 或 "socks"
	BindIP       string         // Direct 绑定的 inet4_bind_address
	SocksHost    string         // 出站 SOCKS5 IP
	SocksPort    int            // 出站 SOCKS5 端口
	SocksUser    string         // 出站 SOCKS5 账号
	SocksPass    string         // 出站 SOCKS5 密码
	RawInbound   map[string]any // 原始 inbound JSON
	RawOutbound  map[string]any // 原始 outbound JSON
}

// Socks5Endpoint 表示解析后的 SOCKS5 代理条目
type Socks5Endpoint struct {
	Raw      string
	Host     string
	Port     int
	Username string
	Password string
}

func (s Socks5Endpoint) FullText() string {
	if s.Username != "" || s.Password != "" {
		return fmt.Sprintf("%s:%d:%s:%s", s.Host, s.Port, s.Username, s.Password)
	}
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

// NodeIP 返回节点的“节点IP”：直连模式返回本机IP，SOCKS5出站模式返回SOCKS5的IP
func (n ServerNode) NodeIP(primaryLocalIP string) string {
	if strings.EqualFold(n.OutboundType, "socks") && n.SocksHost != "" {
		return n.SocksHost
	}
	if n.BindIP != "" {
		return n.BindIP
	}
	if n.ListenHost != "" && n.ListenHost != "::" && n.ListenHost != "0.0.0.0" {
		return n.ListenHost
	}
	return primaryLocalIP
}

// EntryHost 返回客户端连接该节点时使用的服务器入口 IP
func (n ServerNode) EntryHost(primaryLocalIP string) string {
	if n.ListenHost != "" && n.ListenHost != "::" && n.ListenHost != "0.0.0.0" {
		return n.ListenHost
	}
	if n.BindIP != "" {
		return n.BindIP
	}
	return primaryLocalIP
}

// FullSocks5OutboundText 返回完整出站 socks5 字符串 (ip:port:user:pass)
func (n ServerNode) FullSocks5OutboundText() string {
	if !strings.EqualFold(n.OutboundType, "socks") || n.SocksHost == "" {
		return ""
	}
	if n.SocksUser != "" || n.SocksPass != "" {
		return fmt.Sprintf("%s:%d:%s:%s", n.SocksHost, n.SocksPort, n.SocksUser, n.SocksPass)
	}
	return fmt.Sprintf("%s:%d", n.SocksHost, n.SocksPort)
}

// ShareLink 生成标准协议分享链接，链接 # 后面的名称固定为节点 IP（直连为本机IP，SOCKS5出为SOCKS5的IP）
func (n ServerNode) ShareLink(primaryLocalIP string) string {
	host := n.EntryHost(primaryLocalIP)
	nodeIP := n.NodeIP(primaryLocalIP)
	remark := url.QueryEscape(nodeIP)

	switch strings.ToLower(n.InboundType) {
	case "vless-reality", "vless":
		pubKey := n.PublicKey
		if pubKey == "" && n.PrivateKey != "" {
			pubKey = realityPublicKeyFromPrivate(n.PrivateKey)
		}
		if pubKey != "" {
			sni := emptyFallback(n.ServerName, "stock.adobe.com")
			return fmt.Sprintf("vless://%s@%s:%d?encryption=none&flow=xtls-rprx-vision&fp=firefox&pbk=%s&security=reality&sid=%s&sni=%s&type=tcp#%s",
				n.UUID, host, n.ListenPort, pubKey, n.ShortID, url.QueryEscape(sni), remark)
		}
		return fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=tls&sni=%s&type=tcp#%s",
			n.UUID, host, n.ListenPort, url.QueryEscape(emptyFallback(n.ServerName, host)), remark)

	case "anytls":
		sni := emptyFallback(n.ServerName, "bing.com")
		pass := emptyFallback(n.UUID, n.Password)
		return fmt.Sprintf("anytls://%s@%s:%d?allowInsecure=1&insecure=1&security=tls&sni=%s#%s",
			pass, host, n.ListenPort, url.QueryEscape(sni), remark)

	case "socks":
		return fmt.Sprintf("%s:%d:%s:%s", host, n.ListenPort, n.Username, n.Password)

	default:
		return fmt.Sprintf("%s://%s@%s:%d#%s", n.InboundType, emptyFallback(n.UUID, n.Password), host, n.ListenPort, remark)
	}
}

// DeliveryLine 生成交付输出行：
// - 直连模式：本机IP----协议链接
// - SOCKS5出站模式：完整socks5----协议链接
func (n ServerNode) DeliveryLine(primaryLocalIP string) string {
	link := n.ShareLink(primaryLocalIP)
	if strings.EqualFold(n.OutboundType, "socks") && n.SocksHost != "" {
		return fmt.Sprintf("%s----%s", n.FullSocks5OutboundText(), link)
	}
	return fmt.Sprintf("%s----%s", n.NodeIP(primaryLocalIP), link)
}

// ListViewLine 生成菜单 4 节点列表显示行：
// 格式：节点序号---节点IP----协议
func (n ServerNode) ListViewLine(index int, primaryLocalIP string) string {
	return fmt.Sprintf("%d---%s----%s", index, n.NodeIP(primaryLocalIP), n.ShareLink(primaryLocalIP))
}

// LoadCurrentNodes 从 /etc/sing-box/conf/all.json 加载并解析所有节点
func LoadCurrentNodes() ([]ServerNode, error) {
	return LoadNodesFromPath(singboxAllJSON)
}

func LoadNodesFromPath(path string) ([]ServerNode, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []ServerNode{}, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return []ServerNode{}, nil
	}

	var all map[string]any
	if err := json.Unmarshal(data, &all); err != nil {
		return nil, fmt.Errorf("解析 all.json 失败: %w", err)
	}

	inbounds, _ := all["inbounds"].([]any)
	outbounds, _ := all["outbounds"].([]any)
	route, _ := all["route"].(map[string]any)
	rules, _ := route["rules"].([]any)

	outboundByTag := map[string]map[string]any{}
	for _, raw := range outbounds {
		if ob, ok := raw.(map[string]any); ok {
			tag := asString(ob["tag"])
			if tag != "" {
				outboundByTag[tag] = ob
			}
		}
	}

	routeByInbound := map[string]string{}
	for _, raw := range rules {
		if rule, ok := raw.(map[string]any); ok {
			outTag := asString(rule["outbound"])
			if inList, ok := rule["inbound"].([]any); ok {
				for _, inTag := range inList {
					routeByInbound[asString(inTag)] = outTag
				}
			} else if inStr := asString(rule["inbound"]); inStr != "" {
				routeByInbound[inStr] = outTag
			}
		}
	}

	var nodes []ServerNode
	for _, raw := range inbounds {
		ib, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		inTag := asString(ib["tag"])
		if inTag == "" {
			continue
		}
		outTag := routeByInbound[inTag]
		if outTag == "" {
			outTag = inTag + "-out"
		}
		ob, ok := outboundByTag[outTag]
		if !ok {
			ob = map[string]any{"tag": outTag, "type": "direct"}
		}
		nodes = append(nodes, parseServerNodePair(ib, ob))
	}

	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].ListenPort != nodes[j].ListenPort {
			return nodes[i].ListenPort < nodes[j].ListenPort
		}
		return nodes[i].InboundTag < nodes[j].InboundTag
	})
	return nodes, nil
}

func parseServerNodePair(ib, ob map[string]any) ServerNode {
	n := ServerNode{
		InboundTag:   asString(ib["tag"]),
		InboundType:  strings.ToLower(asString(ib["type"])),
		ListenHost:   asString(ib["listen"]),
		ListenPort:   asInt(ib["listen_port"]),
		OutboundType: strings.ToLower(emptyFallback(asString(ob["type"]), "direct")),
		BindIP:       asString(ob["inet4_bind_address"]),
		RawInbound:   cloneMap(ib),
		RawOutbound:  cloneMap(ob),
	}

	if users, ok := ib["users"].([]any); ok && len(users) > 0 {
		if u, ok := users[0].(map[string]any); ok {
			n.UUID = emptyFallback(asString(u["uuid"]), asString(u["password"]))
			n.Username = asString(u["username"])
			n.Password = asString(u["password"])
		}
	}

	if tlsObj, ok := ib["tls"].(map[string]any); ok {
		n.ServerName = asString(tlsObj["server_name"])
		if realityObj, ok := tlsObj["reality"].(map[string]any); ok && asBool(realityObj["enabled"]) {
			n.InboundType = "vless-reality"
			n.PrivateKey = asString(realityObj["private_key"])
			n.PublicKey = realityPublicKeyFromPrivate(n.PrivateKey)
			if sids, ok := realityObj["short_id"].([]any); ok && len(sids) > 0 {
				n.ShortID = asString(sids[0])
			} else {
				n.ShortID = asString(realityObj["short_id"])
			}
		}
	}

	if n.OutboundType == "socks" {
		n.SocksHost = asString(ob["server"])
		n.SocksPort = asInt(ob["server_port"])
		n.SocksUser = asString(ob["username"])
		n.SocksPass = asString(ob["password"])
		n.ProtocolName = n.SocksHost
	} else {
		n.ProtocolName = emptyFallback(n.BindIP, n.ListenHost)
	}
	return n
}

// SaveNodesToAllJSON 将节点列表合成为标准 /etc/sing-box/conf/all.json 并自动备份旧配置
func SaveNodesToAllJSON(nodes []ServerNode) error {
	return SaveNodesToPath(singboxAllJSON, singboxBackupDir, nodes)
}

func SaveNodesToPath(allJSONPath, backupDir string, nodes []ServerNode) error {
	_ = os.MkdirAll(filepath.Dir(allJSONPath), 0755)
	if backupDir != "" {
		_ = os.MkdirAll(backupDir, 0755)
		if oldData, err := os.ReadFile(allJSONPath); err == nil && len(oldData) > 0 {
			stamp := time.Now().Format("20060102_150405")
			bkFile := filepath.Join(backupDir, fmt.Sprintf("all_%s.json", stamp))
			_ = os.WriteFile(bkFile, oldData, 0644)
		}
	}

	inbounds := make([]any, 0, len(nodes))
	outbounds := make([]any, 0, len(nodes))
	rules := make([]any, 0, len(nodes))

	for _, n := range nodes {
		inTag := n.InboundTag
		outTag := inTag + "-out"
		ib := cloneMap(n.RawInbound)
		ib["tag"] = inTag
		ob := cloneMap(n.RawOutbound)
		ob["tag"] = outTag

		inbounds = append(inbounds, ib)
		outbounds = append(outbounds, ob)
		rules = append(rules, map[string]any{
			"inbound":  []any{inTag},
			"outbound": outTag,
		})
	}

	all := map[string]any{
		"log": map[string]any{
			"disabled":  false,
			"level":     "warn",
			"output":    logFilePath,
			"timestamp": true,
		},
		"dns": map[string]any{
			"servers": []any{
				map[string]any{
					"tag":    "dns-direct",
					"type":   "local",
					"detour": "direct",
				},
			},
		},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route": map[string]any{
			"default_domain_resolver": "dns-direct",
			"rules":                   rules,
		},
	}
	return writeFormattedJSON(allJSONPath, all)
}

// BuildNewNode 构建单个新节点（支持入站：vless-reality / anytls / socks；出站：direct / socks）
func BuildNewNode(inboundProto string, listenHost string, port int, realitySNI string, outboundProto string, bindIP string, socks *Socks5Endpoint, primaryLocalIP string) ServerNode {
	var protocolName string
	if strings.EqualFold(outboundProto, "socks") && socks != nil {
		protocolName = socks.Host
	} else if bindIP != "" {
		protocolName = bindIP
	} else if listenHost != "" && listenHost != "::" && listenHost != "0.0.0.0" {
		protocolName = listenHost
	} else {
		protocolName = primaryLocalIP
	}

	// 内部 tag 带上端口号防止同 IP 多节点在 sing-box 中报 duplicate tag 错误
	inTag := fmt.Sprintf("%s_%d", protocolName, port)
	outTag := inTag + "-out"

	actualListen := listenHost
	if actualListen == "" {
		actualListen = "::"
	}

	uuid := randomUUID()
	socksUser := randomLetters(8)
	socksPass := randomLetters(8)
	privKey, pubKey := realityKeyPair()
	shortID := randomHex(8)
	if strings.TrimSpace(realitySNI) == "" {
		realitySNI = "stock.adobe.com"
	}

	var ib map[string]any
	switch strings.ToLower(inboundProto) {
	case "vless-reality", "1":
		inboundProto = "vless-reality"
		ib = map[string]any{
			"tag":         inTag,
			"type":        "vless",
			"listen":      actualListen,
			"listen_port": port,
			"users": []any{
				map[string]any{
					"uuid": uuid,
					"flow": "xtls-rprx-vision",
				},
			},
			"tls": map[string]any{
				"enabled":     true,
				"server_name": realitySNI,
				"reality": map[string]any{
					"enabled": true,
					"handshake": map[string]any{
						"server":      realitySNI,
						"server_port": 443,
					},
					"private_key": privKey,
					"short_id":    []any{shortID},
				},
			},
		}
	case "anytls", "2":
		inboundProto = "anytls"
		ib = map[string]any{
			"tag":         inTag,
			"type":        "anytls",
			"listen":      actualListen,
			"listen_port": port,
			"users": []any{
				map[string]any{
					"name":     protocolName,
					"password": uuid,
				},
			},
			"tls": map[string]any{
				"enabled":          true,
				"server_name":      "bing.com",
				"certificate_path": tlsCertPath,
				"key_path":         tlsKeyPath,
			},
		}
	case "socks", "3":
		inboundProto = "socks"
		ib = map[string]any{
			"tag":         inTag,
			"type":        "socks",
			"listen":      actualListen,
			"listen_port": port,
			"users": []any{
				map[string]any{
					"username": socksUser,
					"password": socksPass,
				},
			},
		}
	}

	var ob map[string]any
	if strings.EqualFold(outboundProto, "socks") && socks != nil {
		ob = map[string]any{
			"tag":         outTag,
			"type":        "socks",
			"server":      socks.Host,
			"server_port": socks.Port,
			"network":     "tcp",
		}
		if socks.Username != "" {
			ob["username"] = socks.Username
		}
		if socks.Password != "" {
			ob["password"] = socks.Password
		}
	} else {
		outboundProto = "direct"
		ob = map[string]any{
			"tag":  outTag,
			"type": "direct",
		}
		if bindIP != "" {
			ob["inet4_bind_address"] = bindIP
		}
	}

	node := parseServerNodePair(ib, ob)
	node.PublicKey = pubKey
	return node
}

// UpdateSocks5OutboundsByIP 按新输入的 SOCKS5 IP 自动匹配现有出站为 SOCKS5 的节点，原地更新端口、账号、密码
func UpdateSocks5OutboundsByIP(nodes []ServerNode, updates []Socks5Endpoint) ([]ServerNode, []ServerNode, []Socks5Endpoint) {
	updatesByIP := map[string][]Socks5Endpoint{}
	for _, u := range updates {
		updatesByIP[u.Host] = append(updatesByIP[u.Host], u)
	}
	usedPerIP := map[string]int{}
	matchedIPs := map[string]bool{}
	var updatedNodes []ServerNode

	for i := range nodes {
		n := &nodes[i]
		if !strings.EqualFold(n.OutboundType, "socks") || n.SocksHost == "" {
			continue
		}
		candidates, ok := updatesByIP[n.SocksHost]
		if !ok || len(candidates) == 0 {
			continue
		}
		idx := usedPerIP[n.SocksHost] % len(candidates)
		usedPerIP[n.SocksHost]++
		chosen := candidates[idx]
		matchedIPs[n.SocksHost] = true

		// 原地更新出站端口、账号、密码，不改变入站协议与链接
		n.SocksPort = chosen.Port
		n.SocksUser = chosen.Username
		n.SocksPass = chosen.Password
		n.RawOutbound["server"] = chosen.Host
		n.RawOutbound["server_port"] = chosen.Port
		if chosen.Username != "" {
			n.RawOutbound["username"] = chosen.Username
		} else {
			delete(n.RawOutbound, "username")
		}
		if chosen.Password != "" {
			n.RawOutbound["password"] = chosen.Password
		} else {
			delete(n.RawOutbound, "password")
		}
		updatedNodes = append(updatedNodes, *n)
	}

	var unmatched []Socks5Endpoint
	for _, u := range updates {
		if !matchedIPs[u.Host] {
			unmatched = append(unmatched, u)
		}
	}
	return nodes, updatedNodes, unmatched
}

// FilterDeleteNodes 支持按 节点序号(1, 1-3, 2,4) 或 节点IP(本机IP / SOCKS5 IP) 或 all 快速删除
func FilterDeleteNodes(nodes []ServerNode, expr string, primaryLocalIP string) (remaining []ServerNode, deleted []ServerNode) {
	expr = strings.TrimSpace(expr)
	if strings.EqualFold(expr, "all") {
		return []ServerNode{}, nodes
	}

	deleteIndices := map[int]bool{}
	deleteIPs := map[string]bool{}

	tokens := strings.FieldsFunc(expr, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ';'
	})
	for _, tok := range tokens {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		// 检查是否为 IP 地址
		if net.ParseIP(tok) != nil {
			deleteIPs[tok] = true
			continue
		}
		// 检查是否为范围 1-5
		if strings.Contains(tok, "-") && !strings.Contains(tok, ".") {
			parts := strings.SplitN(tok, "-", 2)
			start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 == nil && err2 == nil && start > 0 && end >= start {
				for idx := start; idx <= end; idx++ {
					deleteIndices[idx] = true
				}
				continue
			}
		}
		// 检查是否为单个序号
		if idx, err := strconv.Atoi(tok); err == nil && idx > 0 {
			deleteIndices[idx] = true
			continue
		}
		// 其他情况也放入 IP/名称匹配表
		deleteIPs[tok] = true
	}

	for i, n := range nodes {
		seq := i + 1
		nodeIP := n.NodeIP(primaryLocalIP)
		entryIP := n.EntryHost(primaryLocalIP)
		if deleteIndices[seq] || deleteIPs[nodeIP] || deleteIPs[entryIP] || deleteIPs[n.SocksHost] || deleteIPs[n.InboundTag] {
			deleted = append(deleted, n)
		} else {
			remaining = append(remaining, n)
		}
	}
	return remaining, deleted
}

func isPortFreeOnHost(port int) bool {
	if port <= 0 || port > 65535 {
		return false
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// NextAvailableStartPort 自动计算从 defaultStart (20000) 起的第一个连续空闲端口（兼顾已建节点与宿主机物理占用）
func NextAvailableStartPort(nodes []ServerNode, count int, defaultStart int) int {
	if defaultStart <= 0 {
		defaultStart = 20000
	}
	if count <= 0 {
		count = 1
	}
	used := map[int]bool{}
	maxPort := 0
	for _, n := range nodes {
		if n.ListenPort > 0 {
			used[n.ListenPort] = true
			if n.ListenPort > maxPort {
				maxPort = n.ListenPort
			}
		}
	}
	candidate := defaultStart
	if maxPort >= defaultStart {
		candidate = maxPort + 1
	}
	for candidate+count-1 <= 65535 {
		ok := true
		for i := 0; i < count; i++ {
			p := candidate + i
			if used[p] || !isPortFreeOnHost(p) {
				ok = false
				candidate = p + 1
				break
			}
		}
		if ok {
			return candidate
		}
	}
	for p := defaultStart; p <= 65535-count+1; p++ {
		ok := true
		for i := 0; i < count; i++ {
			if used[p+i] || !isPortFreeOnHost(p+i) {
				ok = false
				break
			}
		}
		if ok {
			return p
		}
	}
	return defaultStart
}

// ParseSocks5Lines 解析多行 SOCKS5 输入（支持一行一个、一行多个以空格/分号隔开、或者不同格式混杂）
func ParseSocks5Lines(lines []string) []Socks5Endpoint {
	var result []Socks5Endpoint
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// 若单行内包含空格或分号隔开的多个节点，切分后逐一解析
		tokens := strings.FieldsFunc(line, func(r rune) bool {
			return r == ' ' || r == ';'
		})
		for _, tok := range tokens {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			if ep, ok := parseSingleSocks5(tok); ok {
				result = append(result, ep)
			}
		}
	}
	return result
}

func parseSingleSocks5(line string) (Socks5Endpoint, bool) {
	lower := strings.ToLower(line)
	if strings.HasPrefix(lower, "socks5://") || strings.HasPrefix(lower, "socks://") {
		u, err := url.Parse(line)
		if err != nil || u.Hostname() == "" {
			return Socks5Endpoint{}, false
		}
		port, _ := strconv.Atoi(u.Port())
		if port <= 0 || port > 65535 {
			return Socks5Endpoint{}, false
		}
		user := ""
		pass := ""
		if u.User != nil {
			user = u.User.Username()
			pass, _ = u.User.Password()
		}
		return Socks5Endpoint{
			Raw:      line,
			Host:     u.Hostname(),
			Port:     port,
			Username: user,
			Password: pass,
		}, true
	}

	parts := strings.FieldsFunc(line, func(r rune) bool {
		return r == ':' || r == '|' || r == ',' || r == '\t'
	})
	if len(parts) < 2 {
		return Socks5Endpoint{}, false
	}
	host := strings.TrimSpace(parts[0])
	port, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if host == "" || err != nil || port <= 0 || port > 65535 {
		return Socks5Endpoint{}, false
	}
	ep := Socks5Endpoint{
		Raw:  line,
		Host: host,
		Port: port,
	}
	if len(parts) >= 3 {
		ep.Username = strings.TrimSpace(parts[2])
	}
	if len(parts) >= 4 {
		ep.Password = strings.TrimSpace(parts[3])
	}
	return ep, true
}

// CheckSocks5List 并发 1.5 秒快速探活 SOCKS5 列表（验证 TCP 连接与 SOCKS5 认证握手）
func CheckSocks5List(items []Socks5Endpoint) (alive []Socks5Endpoint, dead []Socks5Endpoint) {
	if len(items) == 0 {
		return nil, nil
	}
	statuses := make([]bool, len(items))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)
	for i, ep := range items {
		wg.Add(1)
		go func(idx int, target Socks5Endpoint) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			statuses[idx] = probeSocks5(target, 1800*time.Millisecond)
		}(i, ep)
	}
	wg.Wait()
	for i, ok := range statuses {
		if ok {
			alive = append(alive, items[i])
		} else {
			dead = append(dead, items[i])
		}
	}
	return alive, dead
}

func probeSocks5(ep Socks5Endpoint, timeout time.Duration) bool {
	addr := net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if ep.Username != "" || ep.Password != "" {
		if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
			return false
		}
	} else {
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			return false
		}
	}
	resp := make([]byte, 2)
	if _, err := conn.Read(resp); err != nil || resp[0] != 0x05 {
		return false
	}
	if resp[1] == 0x02 {
		// 用户名密码子协商 (RFC 1929)
		uBytes := []byte(ep.Username)
		pBytes := []byte(ep.Password)
		if len(uBytes) > 255 || len(pBytes) > 255 {
			return false
		}
		authPacket := make([]byte, 0, 3+len(uBytes)+len(pBytes))
		authPacket = append(authPacket, 0x01, byte(len(uBytes)))
		authPacket = append(authPacket, uBytes...)
		authPacket = append(authPacket, byte(len(pBytes)))
		authPacket = append(authPacket, pBytes...)
		if _, err := conn.Write(authPacket); err != nil {
			return false
		}
		authResp := make([]byte, 2)
		if _, err := conn.Read(authResp); err != nil || authResp[1] != 0x00 {
			return false
		}
		return true
	}
	return resp[1] == 0x00
}

// SaveTimestampedResultFile 将本次操作的节点结果独立保存到 /home/nodes_<动作>_YYYYMMDD_HHMMSS.txt
func SaveTimestampedResultFile(actionLabel string, lines []string) (string, error) {
	if len(lines) == 0 {
		return "", errors.New("没有可保存的节点结果")
	}
	stamp := time.Now().Format("20060102_150405")
	fileName := fmt.Sprintf("nodes_%s_%s.txt", actionLabel, stamp)
	dir := "/home"
	_ = os.MkdirAll(dir, 0755)
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		dir, _ = os.Getwd()
	}
	fullPath := filepath.Join(dir, fileName)
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
		return "", err
	}
	return fullPath, nil
}

// 辅助函数
func realityKeyPair() (string, string) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", ""
	}
	priv := base64.RawURLEncoding.EncodeToString(key.Bytes())
	pub := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	return priv, pub
}

func realityPublicKeyFromPrivate(privateKey string) string {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(privateKey))
	if err != nil {
		return ""
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
}

func randomUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func randomHex(size int) string {
	b := make([]byte, size)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randomLetters(size int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	if size <= 0 {
		size = 8
	}
	b := make([]byte, size)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}

func writeFormattedJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0644)
}

func cloneMap(input map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range input {
		out[k] = v
	}
	return out
}

func asString(value any) string {
	if value == nil {
		return ""
	}
	switch v := value.(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	default:
		return fmt.Sprint(v)
	}
}

func asInt(value any) int {
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(v))
		return n
	default:
		return 0
	}
}

func asBool(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true") || v == "1"
	default:
		return false
	}
}

func emptyFallback(val, fallback string) string {
	if strings.TrimSpace(val) == "" {
		return fallback
	}
	return val
}
