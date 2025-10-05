// Copyright 2024 The tlshttp Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package presets

import (
	"testing"
	
	http "github.com/vanling1111/tlshttp"
)

// TestBrowserFingerprintsExist 测试所有预设浏览器指纹是否存在
func TestBrowserFingerprintsExist(t *testing.T) {
	fingerprints := []struct {
		name        string
		fingerprint BrowserFingerprint
	}{
		{"Chrome120Windows", Chrome120Windows},
		{"Chrome117Windows", Chrome117Windows},
		{"Chrome133Windows", Chrome133Windows},
		{"Firefox120Windows", Firefox120Windows},
		{"SafariiOS17", SafariiOS17},
		{"Edge120Windows", Edge120Windows},
	}

	for _, fp := range fingerprints {
		t.Run(fp.name, func(t *testing.T) {
			if fp.fingerprint.Name == "" {
				t.Error("Name 不应该为空")
			}
			if fp.fingerprint.JA3 == "" {
				t.Error("JA3 不应该为空")
			}
			if fp.fingerprint.UserAgent == "" {
				t.Error("UserAgent 不应该为空")
			}
		})
	}
}

// TestBrowserFingerprintNewTransport 测试 NewTransport 方法
func TestBrowserFingerprintNewTransport(t *testing.T) {
	tests := []struct {
		name        string
		fingerprint BrowserFingerprint
	}{
		{"Chrome120Windows", Chrome120Windows},
		{"Firefox120Windows", Firefox120Windows},
		{"SafariiOS17", SafariiOS17},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := tt.fingerprint.NewTransport()
			
			if tr == nil {
				t.Fatal("Transport 不应该为 nil")
			}
			
			if tr.JA3 != tt.fingerprint.JA3 {
				t.Errorf("JA3 = %v, want %v", tr.JA3, tt.fingerprint.JA3)
			}
			
			if tr.UserAgent != tt.fingerprint.UserAgent {
				t.Errorf("UserAgent = %v, want %v", tr.UserAgent, tt.fingerprint.UserAgent)
			}
		})
	}
}

// TestBrowserFingerprintApplyToTransport 测试 ApplyToTransport 方法
func TestBrowserFingerprintApplyToTransport(t *testing.T) {
	// 创建一个空的 Transport
	tr := &http.Transport{}
	
	// 应用 Chrome120Windows 指纹
	Chrome120Windows.ApplyToTransport(tr)
	
	if tr.JA3 != Chrome120Windows.JA3 {
		t.Errorf("JA3 = %v, want %v", tr.JA3, Chrome120Windows.JA3)
	}
	
	if tr.UserAgent != Chrome120Windows.UserAgent {
		t.Errorf("UserAgent = %v, want %v", tr.UserAgent, Chrome120Windows.UserAgent)
	}
	
	if tr.HTTP2Settings == nil {
		t.Error("HTTP2Settings 不应该为 nil")
	}
}

// TestBrowserFingerprintHTTP2Settings 测试 HTTP/2 设置
func TestBrowserFingerprintHTTP2Settings(t *testing.T) {
	tests := []struct {
		name        string
		fingerprint BrowserFingerprint
		wantSettings int
	}{
		{"Chrome120Windows", Chrome120Windows, 4},
		{"Firefox120Windows", Firefox120Windows, 3},
		{"SafariiOS17", SafariiOS17, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.fingerprint.HTTP2 == nil {
				t.Fatal("HTTP2 不应该为 nil")
			}
			
			if len(tt.fingerprint.HTTP2.Settings) != tt.wantSettings {
				t.Errorf("Settings 数量 = %d, want %d", 
					len(tt.fingerprint.HTTP2.Settings), tt.wantSettings)
			}
			
			if tt.fingerprint.HTTP2.HeaderPriority == nil {
				t.Error("HeaderPriority 不应该为 nil")
			}
		})
	}
}

// TestChromeFingerprints 测试 Chrome 系列指纹
func TestChromeFingerprints(t *testing.T) {
	chromes := []BrowserFingerprint{
		Chrome120Windows,
		Chrome117Windows,
		Chrome133Windows,
	}

	for i, chrome := range chromes {
		t.Run(chrome.Name, func(t *testing.T) {
			// Chrome 指纹应该有相似的模式
			if chrome.HTTP2 == nil {
				t.Error("Chrome HTTP2 settings 不应该为 nil")
			}
			
			// Chrome 应该有 HeaderPriority
			if chrome.HTTP2.HeaderPriority == nil {
				t.Error("Chrome HeaderPriority 不应该为 nil")
			}
			
			// Chrome 的 Weight 应该是 255
			if chrome.HTTP2.HeaderPriority.Weight != 255 {
				t.Errorf("Chrome[%d] Weight = %d, want 255", 
					i, chrome.HTTP2.HeaderPriority.Weight)
			}
		})
	}
}

// TestFirefoxFingerprints 测试 Firefox 系列指纹
func TestFirefoxFingerprints(t *testing.T) {
	firefoxes := []BrowserFingerprint{
		Firefox120Windows,
	}

	for _, firefox := range firefoxes {
		t.Run(firefox.Name, func(t *testing.T) {
			// Firefox 指纹应该有相似的模式
			if firefox.HTTP2 == nil {
				t.Error("Firefox HTTP2 settings 不应该为 nil")
			}
			
			// Firefox 的 Settings 应该是 3 个
			if len(firefox.HTTP2.Settings) != 3 {
				t.Errorf("Firefox Settings 数量 = %d, want 3", 
					len(firefox.HTTP2.Settings))
			}
		})
	}
}

// TestSafariFingerprint 测试 Safari 指纹
func TestSafariFingerprint(t *testing.T) {
	safari := SafariiOS17
	
	if safari.HTTP2 == nil {
		t.Fatal("Safari HTTP2 settings 不应该为 nil")
	}
	
	// Safari 的特征检查
	if len(safari.HTTP2.Settings) != 5 {
		t.Errorf("Safari Settings 数量 = %d, want 5", 
			len(safari.HTTP2.Settings))
	}
}

// TestEdgeFingerprint 测试 Edge 指纹
func TestEdgeFingerprint(t *testing.T) {
	edge := Edge120Windows
	
	if edge.HTTP2 == nil {
		t.Fatal("Edge HTTP2 settings 不应该为 nil")
	}
	
	// Edge 基于 Chromium，应该有类似 Chrome 的特征
	if edge.HTTP2.HeaderPriority == nil {
		t.Error("Edge HeaderPriority 不应该为 nil")
	}
}

// TestJA3Format 测试 JA3 格式的有效性
func TestJA3Format(t *testing.T) {
	fingerprints := []BrowserFingerprint{
		Chrome120Windows,
		Firefox120Windows,
		SafariiOS17,
	}

	for _, fp := range fingerprints {
		t.Run(fp.Name, func(t *testing.T) {
			ja3 := fp.JA3
			
			// JA3 格式: version,ciphers,extensions,curves,pointFormats
			// 应该有 4 个逗号分隔的部分
			count := 0
			for _, c := range ja3 {
				if c == ',' {
					count++
				}
			}
			
			if count != 4 {
				t.Errorf("JA3 格式错误: 应该有 4 个逗号，实际有 %d 个", count)
			}
			
			// JA3 不应该为空
			if len(ja3) < 10 {
				t.Error("JA3 字符串太短")
			}
		})
	}
}

// TestUserAgentFormat 测试 UserAgent 格式
func TestUserAgentFormat(t *testing.T) {
	fingerprints := []BrowserFingerprint{
		Chrome120Windows,
		Firefox120Windows,
		SafariiOS17,
	}

	for _, fp := range fingerprints {
		t.Run(fp.Name, func(t *testing.T) {
			ua := fp.UserAgent
			
			// UserAgent 应该包含 Mozilla/5.0
			if len(ua) < 20 {
				t.Error("UserAgent 字符串太短")
			}
			
			// 所有现代浏览器的 UserAgent 都应该以 Mozilla/5.0 开头
			if ua[:11] != "Mozilla/5.0" {
				t.Errorf("UserAgent 应该以 Mozilla/5.0 开头，实际: %s", ua[:11])
			}
		})
	}
}

// TestHTTP2SettingValues 测试 HTTP/2 Setting 值的有效性
func TestHTTP2SettingValues(t *testing.T) {
	fingerprints := []BrowserFingerprint{
		Chrome120Windows,
		Firefox120Windows,
		SafariiOS17,
	}

	for _, fp := range fingerprints {
		t.Run(fp.Name, func(t *testing.T) {
			if fp.HTTP2 == nil {
				t.Fatal("HTTP2 不应该为 nil")
			}
			
			// 检查每个 Setting 的值
			for i, setting := range fp.HTTP2.Settings {
				// Setting ID 应该在有效范围内 (1-6)
				if setting.ID < 1 || setting.ID > 6 {
					t.Errorf("Setting[%d] ID = %d，超出有效范围 (1-6)", i, setting.ID)
				}
			}
			
			// ConnectionFlow 应该是正数
			if fp.HTTP2.ConnectionFlow <= 0 {
				t.Errorf("ConnectionFlow = %d，应该是正数", fp.HTTP2.ConnectionFlow)
			}
		})
	}
}

// BenchmarkNewTransport 性能测试：创建新 Transport
func BenchmarkNewTransport(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Chrome120Windows.NewTransport()
	}
}

// BenchmarkApplyToTransport 性能测试：应用指纹到 Transport
func BenchmarkApplyToTransport(b *testing.B) {
	tr := &http.Transport{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Chrome120Windows.ApplyToTransport(tr)
	}
}

