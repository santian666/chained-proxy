package main

import (
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
