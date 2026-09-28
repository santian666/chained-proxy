package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildAndFormatDirectAndSocksNodes(t *testing.T) {
	primaryIP := "103.45.67.89"

	// 1. 测试 Direct 直连模式 VLESS + Reality
	directNode := BuildNewNode("vless-reality", "::", 20000, "stock.adobe.com", "direct", "", nil, primaryIP)
	if directNode.NodeIP(primaryIP) != primaryIP {
		t.Fatalf("expected direct node IP %s, got %s", primaryIP, directNode.NodeIP(primaryIP))
	}
	directDelivery := directNode.DeliveryLine(primaryIP)
	if !strings.HasPrefix(directDelivery, primaryIP+"----vless://") {
		t.Fatalf("unexpected direct delivery format: %s", directDelivery)
	}
	if !strings.HasSuffix(directDelivery, "#"+primaryIP) {
		t.Fatalf("expected direct link remark #%s, got: %s", primaryIP, directDelivery)
	}

	// 2. 测试 SOCKS5 落地模式 AnyTLS
	socksEP := &Socks5Endpoint{
		Host:     "8.8.4.4",
		Port:     1080,
		Username: "u123",
		Password: "p456",
	}
	socksOutNode := BuildNewNode("anytls", "::", 20001, "bing.com", "socks", "", socksEP, primaryIP)
	if socksOutNode.NodeIP(primaryIP) != "8.8.4.4" {
		t.Fatalf("expected socks outbound node IP 8.8.4.4, got %s", socksOutNode.NodeIP(primaryIP))
	}
	socksDelivery := socksOutNode.DeliveryLine(primaryIP)
	expectedPrefix := "8.8.4.4:1080:u123:p456----anytls://"
	if !strings.HasPrefix(socksDelivery, expectedPrefix) {
		t.Fatalf("expected prefix %s, got: %s", expectedPrefix, socksDelivery)
	}
	if !strings.HasSuffix(socksDelivery, "#8.8.4.4") {
		t.Fatalf("expected link remark #8.8.4.4, got: %s", socksDelivery)
	}

	// 3. 测试入站 SOCKS5 (8位随机账号密码)
	inboundSocksNode := BuildNewNode("socks", "103.45.67.90", 20002, "", "direct", "103.45.67.90", nil, primaryIP)
	if len(inboundSocksNode.Username) != 8 || len(inboundSocksNode.Password) != 8 {
		t.Fatalf("expected 8-char random username/password, got %q / %q", inboundSocksNode.Username, inboundSocksNode.Password)
	}
	listLine := inboundSocksNode.ListViewLine(3, primaryIP)
	if !strings.HasPrefix(listLine, "3---103.45.67.90----103.45.67.90:20002:") {
		t.Fatalf("unexpected list view line: %s", listLine)
	}
}

func TestSaveReloadAndModifySocks5Outbound(t *testing.T) {
	tmpDir := t.TempDir()
	allPath := filepath.Join(tmpDir, "all.json")
	bkDir := filepath.Join(tmpDir, "bk")
	primaryIP := "103.45.67.89"

	ep1 := &Socks5Endpoint{Host: "9.9.9.9", Port: 1080, Username: "olduser", Password: "oldpass"}
	n1 := BuildNewNode("vless-reality", "::", 20000, "stock.adobe.com", "socks", "", ep1, primaryIP)
	origShareLink := n1.ShareLink(primaryIP)

	n2 := BuildNewNode("anytls", "103.45.67.91", 20001, "bing.com", "direct", "103.45.67.91", nil, primaryIP)

	if err := SaveNodesToPath(allPath, bkDir, []ServerNode{n1, n2}); err != nil {
		t.Fatalf("SaveNodesToPath failed: %v", err)
	}

	loaded, err := LoadNodesFromPath(allPath)
	if err != nil || len(loaded) != 2 {
		t.Fatalf("LoadNodesFromPath failed: %v, len=%d", err, len(loaded))
	}

	// 验证从 all.json 重新加载后 Reality 公钥自动由私钥推导一致
	if loaded[0].ShareLink(primaryIP) != origShareLink {
		t.Fatalf("reloaded share link mismatch:\ngot:  %s\nwant: %s", loaded[0].ShareLink(primaryIP), origShareLink)
	}

	// 测试 3. 修改落地：输入新的 SOCKS5 (同 IP 9.9.9.9，但端口/账号/密码改变)
	updates := ParseSocks5Lines([]string{"9.9.9.9:2080:newuser:newpass"})
	allUpdated, changed, unmatched := UpdateSocks5OutboundsByIP(loaded, updates)
	if len(changed) != 1 || len(unmatched) != 0 {
		t.Fatalf("expected 1 changed and 0 unmatched, got changed=%d, unmatched=%d", len(changed), len(unmatched))
	}
	// 验证入站链接完全没变，但完整 socks5 出口已变为新端口和新账密
	if changed[0].ShareLink(primaryIP) != origShareLink {
		t.Fatalf("inbound share link should remain unchanged after modifying outbound")
	}
	if !strings.HasPrefix(changed[0].DeliveryLine(primaryIP), "9.9.9.9:2080:newuser:newpass----") {
		t.Fatalf("expected updated socks5 prefix in delivery line, got: %s", changed[0].DeliveryLine(primaryIP))
	}

	// 测试 6. 删除节点：按 IP (9.9.9.9) 删除
	rem, del := FilterDeleteNodes(allUpdated, "9.9.9.9", primaryIP)
	if len(del) != 1 || len(rem) != 1 {
		t.Fatalf("FilterDeleteNodes by IP failed: del=%d, rem=%d", len(del), len(rem))
	}
	if rem[0].NodeIP(primaryIP) != "103.45.67.91" {
		t.Fatalf("unexpected remaining node IP: %s", rem[0].NodeIP(primaryIP))
	}
}

func TestSocks5Parser(t *testing.T) {
	input := []string{
		"1.1.1.1:1080:user:pass\r",
		"2.2.2.2:1081",
		"socks5://user2:pass2@3.3.3.3:1082",
		"socks://4.4.4.4:1083",
		"  5.5.5.5:1084:u5:p5  ",
		"",
		// 测试单行多个节点（空格与分号分隔）
		"6.6.6.6:1085:u6:p6 7.7.7.7:1086; socks5://u8:p8@8.8.8.8:1087",
		"invalid-string",
		"999.999.999.999:invalidport",
	}
	parsed := ParseSocks5Lines(input)
	if len(parsed) != 8 {
		t.Fatalf("expected 8 parsed socks endpoints, got %d", len(parsed))
	}
	if parsed[0].Host != "1.1.1.1" || parsed[0].Port != 1080 || parsed[0].Username != "user" || parsed[0].Password != "pass" {
		t.Fatalf("unexpected parsed[0]: %+v", parsed[0])
	}
	if parsed[1].Host != "2.2.2.2" || parsed[1].Port != 1081 || parsed[1].Username != "" {
		t.Fatalf("unexpected parsed[1]: %+v", parsed[1])
	}
	if parsed[2].Host != "3.3.3.3" || parsed[2].Port != 1082 || parsed[2].Username != "user2" || parsed[2].Password != "pass2" {
		t.Fatalf("unexpected parsed[2]: %+v", parsed[2])
	}
	if parsed[3].Host != "4.4.4.4" || parsed[3].Port != 1083 {
		t.Fatalf("unexpected parsed[3]: %+v", parsed[3])
	}
	if parsed[4].Host != "5.5.5.5" || parsed[4].Port != 1084 || parsed[4].Username != "u5" {
		t.Fatalf("unexpected parsed[4]: %+v", parsed[4])
	}
	if parsed[5].Host != "6.6.6.6" || parsed[5].Port != 1085 || parsed[5].Username != "u6" || parsed[5].Password != "p6" {
		t.Fatalf("unexpected parsed[5]: %+v", parsed[5])
	}
	if parsed[6].Host != "7.7.7.7" || parsed[6].Port != 1086 {
		t.Fatalf("unexpected parsed[6]: %+v", parsed[6])
	}
	if parsed[7].Host != "8.8.8.8" || parsed[7].Port != 1087 || parsed[7].Username != "u8" || parsed[7].Password != "p8" {
		t.Fatalf("unexpected parsed[7]: %+v", parsed[7])
	}
}

func TestDeleteFilterMultiModes(t *testing.T) {
	primaryIP := "103.45.67.89"
	n1 := BuildNewNode("vless-reality", "::", 20000, "", "direct", "", nil, primaryIP)
	n2 := BuildNewNode("vless-reality", "::", 20001, "", "direct", "", nil, primaryIP)
	n3 := BuildNewNode("vless-reality", "::", 20002, "", "socks", "", &Socks5Endpoint{Host: "8.8.8.8", Port: 1080}, primaryIP)
	n4 := BuildNewNode("vless-reality", "::", 20003, "", "direct", "", nil, primaryIP)
	n5 := BuildNewNode("vless-reality", "::", 20004, "", "direct", "", nil, primaryIP)
	nodes := []ServerNode{n1, n2, n3, n4, n5}

	// 1. 测试单个序号删除 "2"
	rem, del := FilterDeleteNodes(nodes, "2", primaryIP)
	if len(del) != 1 || len(rem) != 4 || del[0].ListenPort != 20001 {
		t.Fatalf("delete index 2 failed: del=%d, rem=%d", len(del), len(rem))
	}

	// 2. 测试多序号删除 "1, 3"
	rem, del = FilterDeleteNodes(nodes, "1, 3", primaryIP)
	if len(del) != 2 || len(rem) != 3 {
		t.Fatalf("delete multi indices failed: del=%d, rem=%d", len(del), len(rem))
	}

	// 3. 测试范围删除 "2-4"
	rem, del = FilterDeleteNodes(nodes, "2-4", primaryIP)
	if len(del) != 3 || len(rem) != 2 {
		t.Fatalf("delete range 2-4 failed: del=%d, rem=%d", len(del), len(rem))
	}

	// 4. 测试按落地 IP 删除 "8.8.8.8"
	rem, del = FilterDeleteNodes(nodes, "8.8.8.8", primaryIP)
	if len(del) != 1 || len(rem) != 4 || del[0].SocksHost != "8.8.8.8" {
		t.Fatalf("delete by socks IP failed: del=%d, rem=%d", len(del), len(rem))
	}

	// 5. 测试全部清空 "all"
	rem, del = FilterDeleteNodes(nodes, "all", primaryIP)
	if len(del) != 5 || len(rem) != 0 {
		t.Fatalf("delete all failed: del=%d, rem=%d", len(del), len(rem))
	}
}

func TestNextAvailableStartPort(t *testing.T) {
	primaryIP := "103.45.67.89"
	// 空列表默认 20000
	if p := NextAvailableStartPort(nil, 5, 20000); p != 20000 {
		t.Fatalf("expected 20000 on empty nodes, got %d", p)
	}

	// 占用 20000-20002
	n1 := BuildNewNode("vless-reality", "::", 20000, "", "direct", "", nil, primaryIP)
	n2 := BuildNewNode("vless-reality", "::", 20001, "", "direct", "", nil, primaryIP)
	n3 := BuildNewNode("vless-reality", "::", 20002, "", "direct", "", nil, primaryIP)
	nodes := []ServerNode{n1, n2, n3}

	if p := NextAvailableStartPort(nodes, 2, 20000); p != 20003 {
		t.Fatalf("expected 20003, got %d", p)
	}
}

func TestAllJSONFormatAndValidation(t *testing.T) {
	tmpDir := t.TempDir()
	allPath := filepath.Join(tmpDir, "all.json")
	bkDir := filepath.Join(tmpDir, "bk")
	primaryIP := "1.2.3.4"

	n1 := BuildNewNode("vless-reality", "::", 20000, "stock.adobe.com", "direct", "", nil, primaryIP)
	n2 := BuildNewNode("anytls", "1.2.3.5", 20001, "bing.com", "direct", "1.2.3.5", nil, primaryIP)
	n3 := BuildNewNode("socks", "::", 20002, "", "socks", "", &Socks5Endpoint{Host: "8.8.8.8", Port: 1080, Username: "u", Password: "p"}, primaryIP)

	if err := SaveNodesToPath(allPath, bkDir, []ServerNode{n1, n2, n3}); err != nil {
		t.Fatalf("SaveNodesToPath failed: %v", err)
	}

	data, err := os.ReadFile(allPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	// 验证 log 字段安全级别为 warn
	logObj, ok := root["log"].(map[string]any)
	if !ok || logObj["level"] != "warn" {
		t.Fatalf("expected log level warn, got: %+v", logObj)
	}

	// 验证 inbounds / outbounds / route.rules 数量一致且一对一映射
	inbounds, _ := root["inbounds"].([]any)
	outbounds, _ := root["outbounds"].([]any)
	route, _ := root["route"].(map[string]any)
	rules, _ := route["rules"].([]any)

	// 验证 dns 与 route.default_domain_resolver 兼容 sing-box 1.14+
	dnsObj, ok := root["dns"].(map[string]any)
	if !ok || dnsObj["servers"] == nil {
		t.Fatalf("expected dns block, got: %+v", root["dns"])
	}
	if route["default_domain_resolver"] != "dns-direct" {
		t.Fatalf("expected route.default_domain_resolver == 'dns-direct', got: %v", route["default_domain_resolver"])
	}

	if len(inbounds) != 3 || len(outbounds) != 3 || len(rules) != 3 {
		t.Fatalf("expected 3 inbounds/outbounds/rules, got %d/%d/%d", len(inbounds), len(outbounds), len(rules))
	}

	for i := 0; i < 3; i++ {
		ib := inbounds[i].(map[string]any)
		ob := outbounds[i].(map[string]any)
		rule := rules[i].(map[string]any)
		inTag := ib["tag"].(string)
		outTag := ob["tag"].(string)

		if outTag != inTag+"-out" {
			t.Fatalf("outTag %s does not match inTag %s", outTag, inTag)
		}
		inList := rule["inbound"].([]any)
		if len(inList) == 0 || inList[0].(string) != inTag {
			t.Fatalf("rule inbound mismatch: %+v", rule)
		}
		if rule["outbound"].(string) != outTag {
			t.Fatalf("rule outbound mismatch: %+v", rule)
		}
	}
}
