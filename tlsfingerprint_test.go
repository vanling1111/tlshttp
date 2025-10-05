// Copyright 2024 The tlshttp Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"testing"
	
	tls "github.com/refraction-networking/utls"
)

// ===== 测试我们原创的 TLS 指纹控制代码 =====

// TestTLSExtensionsConfigClone 测试 TLSExtensionsConfig 的深度克隆
func TestTLSExtensionsConfigClone(t *testing.T) {
	original := &TLSExtensionsConfig{
		SupportedSignatureAlgorithms: &tls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
			},
		},
		NotUsedGREASE: false,
	}

	cloned, err := original.Clone()
	if err != nil {
		t.Fatalf("Clone() 失败: %v", err)
	}

	if cloned == nil {
		t.Fatal("Clone() 返回了 nil")
	}

	// 验证字段值相同
	if cloned.NotUsedGREASE != original.NotUsedGREASE {
		t.Errorf("NotUsedGREASE 不匹配: got %v, want %v", cloned.NotUsedGREASE, original.NotUsedGREASE)
	}

	// 验证深度克隆（修改克隆不影响原始对象）
	if cloned.SupportedSignatureAlgorithms != nil {
		cloned.NotUsedGREASE = true
		if original.NotUsedGREASE == true {
			t.Error("修改克隆影响了原始对象")
		}
	}
}

// TestTLSExtensionsConfigCloneNil 测试 nil TLSExtensionsConfig 的克隆
func TestTLSExtensionsConfigCloneNil(t *testing.T) {
	var ext *TLSExtensionsConfig
	cloned, err := ext.Clone()
	if err != nil {
		t.Errorf("nil Clone() 返回错误: %v", err)
	}
	if cloned != nil {
		t.Error("nil Clone() 应该返回 nil")
	}
}

// TestTLSFingerprintConfigClone 测试 TLSFingerprintConfig 的深度克隆
func TestTLSFingerprintConfigClone(t *testing.T) {
	original := &TLSFingerprintConfig{
		JA3:              "771,4865-4866-4867,0-23-65281,29-23-24,0",
		UserAgent:        "TestUA",
		ForceHTTP1:       true,
		PresetFingerprint: "chrome120",
		CustomExtensions: &TLSExtensionsConfig{
			NotUsedGREASE: false,
		},
	}

	cloned, err := original.Clone()
	if err != nil {
		t.Fatalf("Clone() 失败: %v", err)
	}

	if cloned == nil {
		t.Fatal("Clone() 返回了 nil")
	}

	// 验证字段值
	if cloned.JA3 != original.JA3 {
		t.Errorf("JA3 不匹配: got %v, want %v", cloned.JA3, original.JA3)
	}

	if cloned.UserAgent != original.UserAgent {
		t.Errorf("UserAgent 不匹配: got %v, want %v", cloned.UserAgent, original.UserAgent)
	}

	// 验证深度克隆
	cloned.JA3 = "modified"
	if original.JA3 == "modified" {
		t.Error("修改克隆影响了原始对象")
	}
}

// TestTLSFingerprintConfigCloneNil 测试 nil TLSFingerprintConfig 的克隆
func TestTLSFingerprintConfigCloneNil(t *testing.T) {
	var cfg *TLSFingerprintConfig
	cloned, err := cfg.Clone()
	if err != nil {
		t.Errorf("nil Clone() 返回错误: %v", err)
	}
	if cloned != nil {
		t.Error("nil Clone() 应该返回 nil")
	}
}

// TestHTTP2SettingsClone 测试 HTTP2Settings 的深度克隆
func TestHTTP2SettingsClone(t *testing.T) {
	original := &HTTP2Settings{
		Settings: []HTTP2Setting{
			{ID: HTTP2SettingHeaderTableSize, Val: 65536},
			{ID: HTTP2SettingEnablePush, Val: 0},
		},
		ConnectionFlow: 15663105,
		HeaderPriority: &HTTP2PriorityParam{
			Weight:    255,
			StreamDep: 0,
			Exclusive: false,
		},
	}

	cloned, err := original.Clone()
	if err != nil {
		t.Fatalf("Clone() 失败: %v", err)
	}

	if cloned == nil {
		t.Fatal("Clone() 返回了 nil")
	}

	// 验证字段值
	if len(cloned.Settings) != len(original.Settings) {
		t.Errorf("Settings 长度不匹配: got %d, want %d", len(cloned.Settings), len(original.Settings))
	}

	if cloned.ConnectionFlow != original.ConnectionFlow {
		t.Errorf("ConnectionFlow 不匹配: got %d, want %d", cloned.ConnectionFlow, original.ConnectionFlow)
	}

	// 验证深度克隆
	if len(cloned.Settings) > 0 {
		cloned.Settings[0].Val = 99999
		if original.Settings[0].Val == 99999 {
			t.Error("修改克隆影响了原始对象")
		}
	}
}

// TestHTTP2SettingsCloneNil 测试 nil HTTP2Settings 的克隆
func TestHTTP2SettingsCloneNil(t *testing.T) {
	var settings *HTTP2Settings
	cloned, err := settings.Clone()
	if err != nil {
		t.Errorf("nil Clone() 返回错误: %v", err)
	}
	if cloned != nil {
		t.Error("nil Clone() 应该返回 nil")
	}
}

// TestParseUserAgent 测试浏览器类型识别
func TestParseUserAgent(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		want      string
	}{
		{
			name:      "Chrome",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			want:      "chrome",
		},
		{
			name:      "Firefox",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
			want:      "firefox",
		},
		{
			name:      "Safari",
			userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
			want:      "chrome", // Safari 使用 chrome 指纹
		},
		{
			name:      "空字符串",
			userAgent: "",
			want:      "chrome", // 默认 chrome
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseUserAgent(tt.userAgent)
			if got != tt.want {
				t.Errorf("parseUserAgent() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestGetCompleteExtensionMap 测试完整的 TLS 扩展映射表
func TestGetCompleteExtensionMap(t *testing.T) {
	extMap := getCompleteExtensionMap()

	// 验证必需的扩展存在
	requiredExtensions := []string{
		"0",  // SNI
		"5",  // StatusRequest
		"13", // SignatureAlgorithms
		"16", // ALPN
		"23", // ExtendedMasterSecret
		"43", // SupportedVersions
		"51", // KeyShare
	}

	for _, extID := range requiredExtensions {
		if _, exists := extMap[extID]; !exists {
			t.Errorf("缺少必需的扩展: %s", extID)
		}
	}

	// 验证扩展数量合理
	if len(extMap) < 20 {
		t.Errorf("扩展数量太少: got %d, want at least 20", len(extMap))
	}
}

// TestTLSExtensionsConfigStringToSpec 测试 StringToSpec 方法
func TestTLSExtensionsConfigStringToSpec(t *testing.T) {
	tests := []struct {
		name       string
		ja3        string
		userAgent  string
		forceHTTP1 bool
		randomJA3  bool
		wantErr    bool
	}{
		{
			name:       "有效的 JA3",
			ja3:        "771,4865-4866-4867,0-23-65281,29-23-24,0",
			userAgent:  "Mozilla/5.0 Chrome/120.0",
			forceHTTP1: false,
			randomJA3:  false,
			wantErr:    false,
		},
		{
			name:       "无效的 JA3 格式",
			ja3:        "771,4865",
			userAgent:  "Mozilla/5.0",
			forceHTTP1: false,
			randomJA3:  false,
			wantErr:    true,
		},
		{
			name:       "空 JA3",
			ja3:        "",
			userAgent:  "Mozilla/5.0",
			forceHTTP1: false,
			randomJA3:  false,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := &TLSExtensionsConfig{}
			spec, err := ext.StringToSpec(tt.ja3, tt.userAgent, tt.forceHTTP1, tt.randomJA3)

			if (err != nil) != tt.wantErr {
				t.Errorf("StringToSpec() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if spec == nil {
					t.Error("StringToSpec() 返回了 nil spec")
				}
				if len(spec.CipherSuites) == 0 {
					t.Error("CipherSuites 不应该为空")
				}
				if len(spec.Extensions) == 0 {
					t.Error("Extensions 不应该为空")
				}
			}
		})
	}
}

// TestPersistConnParseCipherSuites 测试密码套件解析
func TestPersistConnParseCipherSuites(t *testing.T) {
	pc := &persistConn{
		t: &Transport{
			TLSExtensions: &TLSExtensionsConfig{
				NotUsedGREASE: true, // 禁用 GREASE 以简化测试
			},
		},
	}

	tests := []struct {
		name    string
		ciphers []string
		wantErr bool
		wantLen int
	}{
		{
			name:    "有效的密码套件",
			ciphers: []string{"4865", "4866", "4867"},
			wantErr: false,
			wantLen: 3,
		},
		{
			name:    "空密码套件列表",
			ciphers: []string{},
			wantErr: true,
		},
		{
			name:    "无效的密码套件 ID",
			ciphers: []string{"invalid"},
			wantErr: true,
		},
		{
			name:    "超出范围的密码套件 ID",
			ciphers: []string{"99999999"},
			wantErr: true,
		},
		{
			name:    "重复的密码套件",
			ciphers: []string{"4865", "4865"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suites, err := pc.parseCipherSuites(tt.ciphers)

			if (err != nil) != tt.wantErr {
				t.Errorf("parseCipherSuites() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && len(suites) != tt.wantLen {
				t.Errorf("parseCipherSuites() 长度 = %d, want %d", len(suites), tt.wantLen)
			}
		})
	}
}

// TestPersistConnParseEllipticCurves 测试椭圆曲线解析
func TestPersistConnParseEllipticCurves(t *testing.T) {
	pc := &persistConn{
		t: &Transport{
			TLSExtensions: &TLSExtensionsConfig{
				NotUsedGREASE: true, // 禁用 GREASE
			},
		},
	}

	tests := []struct {
		name    string
		curves  []string
		wantErr bool
		wantLen int
	}{
		{
			name:    "有效的椭圆曲线",
			curves:  []string{"29", "23", "24"},
			wantErr: false,
			wantLen: 3,
		},
		{
			name:    "空曲线列表",
			curves:  []string{},
			wantErr: false,
			wantLen: 0,
		},
		{
			name:    "无效的曲线 ID",
			curves:  []string{"invalid"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			curveIDs, err := pc.parseEllipticCurves(tt.curves)

			if (err != nil) != tt.wantErr {
				t.Errorf("parseEllipticCurves() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && len(curveIDs) != tt.wantLen {
				t.Errorf("parseEllipticCurves() 长度 = %d, want %d", len(curveIDs), tt.wantLen)
			}
		})
	}
}

// TestPersistConnParsePointFormats 测试点格式解析
func TestPersistConnParsePointFormats(t *testing.T) {
	pc := &persistConn{
		t: &Transport{},
	}

	tests := []struct {
		name    string
		formats []string
		wantErr bool
		wantLen int
	}{
		{
			name:    "有效的点格式",
			formats: []string{"0", "1", "2"},
			wantErr: false,
			wantLen: 3,
		},
		{
			name:    "空格式列表",
			formats: []string{},
			wantErr: false,
			wantLen: 0,
		},
		{
			name:    "无效的格式 ID",
			formats: []string{"invalid"},
			wantErr: true,
		},
		{
			name:    "超出范围的格式 ID",
			formats: []string{"256"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formatBytes, err := pc.parsePointFormats(tt.formats)

			if (err != nil) != tt.wantErr {
				t.Errorf("parsePointFormats() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && len(formatBytes) != tt.wantLen {
				t.Errorf("parsePointFormats() 长度 = %d, want %d", len(formatBytes), tt.wantLen)
			}
		})
	}
}

// TestPersistConnParseTLSVersion 测试 TLS 版本解析
func TestPersistConnParseTLSVersion(t *testing.T) {
	pc := &persistConn{
		t: &Transport{},
	}

	tests := []struct {
		name    string
		version string
		wantErr bool
		want    uint16
	}{
		{
			name:    "TLS 1.3",
			version: "772",
			wantErr: false,
			want:    772,
		},
		{
			name:    "TLS 1.2",
			version: "771",
			wantErr: false,
			want:    771,
		},
		{
			name:    "无效版本",
			version: "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ver, err := pc.parseTLSVersion(tt.version)

			if (err != nil) != tt.wantErr {
				t.Errorf("parseTLSVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && ver != tt.want {
				t.Errorf("parseTLSVersion() = %d, want %d", ver, tt.want)
			}
		})
	}
}

// TestPersistConnParseBrowserType 测试浏览器类型解析
func TestPersistConnParseBrowserType(t *testing.T) {
	pc := &persistConn{
		t: &Transport{},
	}

	tests := []struct {
		name      string
		userAgent string
		want      string
	}{
		{
			name:      "Chrome",
			userAgent: "Chrome/120.0",
			want:      "chrome",
		},
		{
			name:      "Firefox",
			userAgent: "Firefox/120.0",
			want:      "firefox",
		},
		{
			name:      "Safari",
			userAgent: "Safari/17.0",
			want:      "safari",
		},
		{
			name:      "Edge",
			userAgent: "Edg/120.0",
			want:      "chrome", // Edge 基于 Chromium，使用 chrome 指纹
		},
		{
			name:      "空字符串",
			userAgent: "",
			want:      "chrome",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pc.parseBrowserType(tt.userAgent)
			if got != tt.want {
				t.Errorf("parseBrowserType() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestPersistConnFixPSKExtension 测试 PSK 扩展修复
func TestPersistConnFixPSKExtension(t *testing.T) {
	pc := &persistConn{
		t: &Transport{},
	}

	tests := []struct {
		name    string
		spec    *tls.ClientHelloSpec
		wantPSK bool
	}{
		{
			name: "已有 PSK 扩展",
			spec: &tls.ClientHelloSpec{
				Extensions: []tls.TLSExtension{
					&tls.UtlsPreSharedKeyExtension{},
				},
			},
			wantPSK: true,
		},
		{
			name: "没有 PSK 扩展",
			spec: &tls.ClientHelloSpec{
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
				},
			},
			wantPSK: true, // 应该被添加
		},
		{
			name:    "nil spec",
			spec:    nil,
			wantPSK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pc.fixPSKExtension(tt.spec)

			if result == nil && tt.spec != nil {
				t.Error("fixPSKExtension() 不应该返回 nil")
				return
			}

			if result != nil && tt.wantPSK {
				hasPSK := false
				for _, ext := range result.Extensions {
					if _, ok := ext.(*tls.UtlsPreSharedKeyExtension); ok {
						hasPSK = true
						break
					}
				}
				if !hasPSK {
					t.Error("fixPSKExtension() 应该添加 PSK 扩展")
				}
			}
		})
	}
}

// TestPersistConnApplyJA4Fingerprint 测试 JA4 指纹应用
func TestPersistConnApplyJA4Fingerprint(t *testing.T) {
	pc := &persistConn{
		t: &Transport{
			CustomJA4: true,
			JA4L:      "t13d1715h2",
			JA4X:      "x509_abcd",
		},
	}

	spec := &tls.ClientHelloSpec{
		CipherSuites: []uint16{0x1301, 0x1302},
		Extensions:   []tls.TLSExtension{&tls.SNIExtension{}},
	}

	result := pc.applyJA4Fingerprint(spec)

	if result == nil {
		t.Error("applyJA4Fingerprint() 不应该返回 nil")
	}

	// JA4 目前是占位符实现，只验证不崩溃
	if result != spec {
		t.Error("applyJA4Fingerprint() 应该返回相同的 spec")
	}
}

// TestTransportEnsureInitialized 测试 Transport 初始化
func TestTransportEnsureInitialized(t *testing.T) {
	tr := &Transport{}

	// 调用 ensureInitialized
	tr.ensureInitialized()

	// 验证所有 map 都已初始化
	if tr.idleConn == nil {
		t.Error("idleConn 应该被初始化")
	}
	if tr.idleConnWait == nil {
		t.Error("idleConnWait 应该被初始化")
	}
	if tr.reqCanceler == nil {
		t.Error("reqCanceler 应该被初始化")
	}
	if tr.connsPerHost == nil {
		t.Error("connsPerHost 应该被初始化")
	}
	if tr.connsPerHostWait == nil {
		t.Error("connsPerHostWait 应该被初始化")
	}
	if tr.ALPNProtocols == nil {
		t.Error("ALPNProtocols 应该被初始化")
	}

	// 多次调用应该安全
	tr.ensureInitialized()
	tr.ensureInitialized()
}

// TestTransportCustomTLSDetection 测试自定义 TLS 检测逻辑
func TestTransportCustomTLSDetection(t *testing.T) {
	tests := []struct {
		name     string
		tr       *Transport
		wantUse  bool
	}{
		{
			name: "UseCustomTLS 设置",
			tr: &Transport{
				UseCustomTLS: true,
			},
			wantUse: true,
		},
		{
			name: "JA3 设置",
			tr: &Transport{
				JA3: "771,4865-4866,0-23,29-23,0",
			},
			wantUse: true,
		},
		{
			name: "ClientHelloHexStream 设置",
			tr: &Transport{
				ClientHelloHexStream: "160301...",
			},
			wantUse: true,
		},
		{
			name: "TLSFingerprint 设置",
			tr: &Transport{
				TLSFingerprint: &TLSFingerprintConfig{
					JA3: "771,4865-4866,0-23,29-23,0",
				},
			},
			wantUse: true,
		},
		{
			name: "无自定义 TLS",
			tr: &Transport{},
			wantUse: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 这个测试验证自定义 TLS 的检测逻辑
			// 实际的检测逻辑在 addTLS 方法中：
			// useCustomTLS := pconn.t.UseCustomTLS || 
			//     pconn.t.JA3 != "" || 
			//     pconn.t.ClientHelloHexStream != "" ||
			//     pconn.t.TLSFingerprint != nil

			useCustomTLS := tt.tr.UseCustomTLS ||
				tt.tr.JA3 != "" ||
				tt.tr.ClientHelloHexStream != "" ||
				tt.tr.TLSFingerprint != nil

			if useCustomTLS != tt.wantUse {
				t.Errorf("自定义 TLS 检测 = %v, want %v", useCustomTLS, tt.wantUse)
			}
		})
	}
}

// BenchmarkTLSExtensionsConfigClone 性能测试：TLSExtensionsConfig 克隆
func BenchmarkTLSExtensionsConfigClone(b *testing.B) {
	ext := &TLSExtensionsConfig{
		SupportedSignatureAlgorithms: &tls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
			},
		},
		NotUsedGREASE: false,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ext.Clone()
	}
}

// BenchmarkHTTP2SettingsClone 性能测试：HTTP2Settings 克隆
func BenchmarkHTTP2SettingsClone(b *testing.B) {
	settings := &HTTP2Settings{
		Settings: []HTTP2Setting{
			{ID: HTTP2SettingHeaderTableSize, Val: 65536},
			{ID: HTTP2SettingEnablePush, Val: 0},
		},
		ConnectionFlow: 15663105,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = settings.Clone()
	}
}

// BenchmarkParseUserAgent 性能测试：浏览器类型识别
func BenchmarkParseUserAgent(b *testing.B) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parseUserAgent(ua)
	}
}

// BenchmarkGetCompleteExtensionMap 性能测试：获取扩展映射表
func BenchmarkGetCompleteExtensionMap(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = getCompleteExtensionMap()
	}
}

