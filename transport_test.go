// Copyright 2024 The tlshttp Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"net"
	"net/url"
	"testing"
	"time"
	
	tls "github.com/refraction-networking/utls"
)

// TestTransportCreation 测试 Transport 的创建
func TestTransportCreation(t *testing.T) {
	tests := []struct {
		name string
		tr   *Transport
	}{
		{
			name: "空 Transport",
			tr:   &Transport{},
		},
		{
			name: "带 JA3 的 Transport",
			tr: &Transport{
				JA3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
			},
		},
		{
			name: "带 UserAgent 的 Transport",
			tr: &Transport{
				UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.tr == nil {
				t.Fatal("Transport 不应该为 nil")
			}
		})
	}
}

// TestTransportClone 测试 Transport 的克隆功能
func TestTransportClone(t *testing.T) {
	original := &Transport{
		JA3:              "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
		RandomJA3:        true,
		UserAgent:        "TestUA",
		ForceHTTP1:       true,
		MaxIdleConns:     100,
		IdleConnTimeout:  90 * time.Second,
		UseCustomTLS:     true,
		ALPNProtocols:    []string{"h2", "http/1.1"},
		CustomALPN:       true,
	}

	cloned := original.Clone()

	// 验证克隆的基本字段
	if cloned.JA3 != original.JA3 {
		t.Errorf("JA3 克隆失败: got %v, want %v", cloned.JA3, original.JA3)
	}

	if cloned.RandomJA3 != original.RandomJA3 {
		t.Errorf("RandomJA3 克隆失败: got %v, want %v", cloned.RandomJA3, original.RandomJA3)
	}

	if cloned.UserAgent != original.UserAgent {
		t.Errorf("UserAgent 克隆失败: got %v, want %v", cloned.UserAgent, original.UserAgent)
	}

	if cloned.ForceHTTP1 != original.ForceHTTP1 {
		t.Errorf("ForceHTTP1 克隆失败: got %v, want %v", cloned.ForceHTTP1, original.ForceHTTP1)
	}

	if cloned.UseCustomTLS != original.UseCustomTLS {
		t.Errorf("UseCustomTLS 克隆失败: got %v, want %v", cloned.UseCustomTLS, original.UseCustomTLS)
	}

	if cloned.CustomALPN != original.CustomALPN {
		t.Errorf("CustomALPN 克隆失败: got %v, want %v", cloned.CustomALPN, original.CustomALPN)
	}

	// 验证深度克隆（修改克隆不影响原始对象）
	if len(cloned.ALPNProtocols) != len(original.ALPNProtocols) {
		t.Errorf("ALPNProtocols 克隆失败: got %d, want %d", len(cloned.ALPNProtocols), len(original.ALPNProtocols))
	}

	// 修改克隆的 ALPNProtocols
	if len(cloned.ALPNProtocols) > 0 {
		cloned.ALPNProtocols[0] = "modified"
		if original.ALPNProtocols[0] == "modified" {
			t.Error("ALPNProtocols 不是深度克隆：修改克隆影响了原始对象")
		}
	}
}

// TestTransportCloneNil 测试 nil Transport 的克隆
func TestTransportCloneNil(t *testing.T) {
	var tr *Transport
	if tr.Clone() != nil {
		t.Error("nil Transport 的克隆应该返回 nil")
	}
}

// TestProtocols 测试 Protocols 类型
func TestProtocols(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*Protocols)
		want  struct {
			http1            bool
			http2            bool
			unencryptedHTTP2 bool
		}
	}{
		{
			name: "默认协议",
			setup: func(p *Protocols) {
				// 不设置
			},
			want: struct {
				http1            bool
				http2            bool
				unencryptedHTTP2 bool
			}{false, false, false},
		},
		{
			name: "仅 HTTP/1",
			setup: func(p *Protocols) {
				p.SetHTTP1(true)
			},
			want: struct {
				http1            bool
				http2            bool
				unencryptedHTTP2 bool
			}{true, false, false},
		},
		{
			name: "HTTP/1 和 HTTP/2",
			setup: func(p *Protocols) {
				p.SetHTTP1(true)
				p.SetHTTP2(true)
			},
			want: struct {
				http1            bool
				http2            bool
				unencryptedHTTP2 bool
			}{true, true, false},
		},
		{
			name: "所有协议",
			setup: func(p *Protocols) {
				p.SetHTTP1(true)
				p.SetHTTP2(true)
				p.SetUnencryptedHTTP2(true)
			},
			want: struct {
				http1            bool
				http2            bool
				unencryptedHTTP2 bool
			}{true, true, true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Protocols{}
			tt.setup(p)

			if p.HTTP1() != tt.want.http1 {
				t.Errorf("HTTP1() = %v, want %v", p.HTTP1(), tt.want.http1)
			}
			if p.HTTP2() != tt.want.http2 {
				t.Errorf("HTTP2() = %v, want %v", p.HTTP2(), tt.want.http2)
			}
			if p.UnencryptedHTTP2() != tt.want.unencryptedHTTP2 {
				t.Errorf("UnencryptedHTTP2() = %v, want %v", p.UnencryptedHTTP2(), tt.want.unencryptedHTTP2)
			}
		})
	}
}

// TestDefaultTransportDialContext 测试默认拨号上下文
func TestDefaultTransportDialContext(t *testing.T) {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	dialFunc := defaultTransportDialContext(dialer)
	if dialFunc == nil {
		t.Fatal("defaultTransportDialContext 返回了 nil")
	}
}

// TestAdjustNextProtos 测试 ALPN 协议调整
func TestAdjustNextProtos(t *testing.T) {
	tests := []struct {
		name       string
		nextProtos []string
		protocols  Protocols
		want       []string
	}{
		{
			name:       "空协议列表",
			nextProtos: []string{},
			protocols:  Protocols{http1: true, http2: true},
			want:       []string{},
		},
		{
			name:       "移除 HTTP/1.1",
			nextProtos: []string{"h2", "http/1.1"},
			protocols:  Protocols{http1: false, http2: true},
			want:       []string{"h2"},
		},
		{
			name:       "移除 h2",
			nextProtos: []string{"h2", "http/1.1"},
			protocols:  Protocols{http1: true, http2: false},
			want:       []string{"http/1.1"},
		},
		{
			name:       "保留所有",
			nextProtos: []string{"h2", "http/1.1"},
			protocols:  Protocols{http1: true, http2: true},
			want:       []string{"h2", "http/1.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := adjustNextProtos(tt.nextProtos, tt.protocols)
			if len(got) != len(tt.want) {
				t.Errorf("adjustNextProtos() 长度 = %v, want %v", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("adjustNextProtos()[%d] = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestTransportJA3Fields 测试 JA3 相关字段
func TestTransportJA3Fields(t *testing.T) {
	tr := &Transport{
		JA3:       "771,4865-4866-4867,0-23-65281,29-23-24,0",
		RandomJA3: true,
		UserAgent: "Mozilla/5.0",
	}

	if tr.JA3 == "" {
		t.Error("JA3 字段应该被设置")
	}

	if !tr.RandomJA3 {
		t.Error("RandomJA3 字段应该为 true")
	}

	if tr.UserAgent == "" {
		t.Error("UserAgent 字段应该被设置")
	}
}

// TestTransportALPNFields 测试 ALPN 相关字段
func TestTransportALPNFields(t *testing.T) {
	tr := &Transport{
		ALPNProtocols: []string{"h2", "http/1.1"},
		CustomALPN:    true,
	}

	if len(tr.ALPNProtocols) != 2 {
		t.Errorf("ALPNProtocols 长度 = %d, want 2", len(tr.ALPNProtocols))
	}

	if !tr.CustomALPN {
		t.Error("CustomALPN 应该为 true")
	}
}

// TestTransportJA4Fields 测试 JA4 相关字段
func TestTransportJA4Fields(t *testing.T) {
	tr := &Transport{
		JA4L:      "t13d1715h2_c02f",
		JA4X:      "x509_abcd1234",
		CustomJA4: true,
	}

	if tr.JA4L == "" {
		t.Error("JA4L 字段应该被设置")
	}

	if tr.JA4X == "" {
		t.Error("JA4X 字段应该被设置")
	}

	if !tr.CustomJA4 {
		t.Error("CustomJA4 应该为 true")
	}
}

// TestTransportHTTP2Settings 测试 HTTP2Settings 字段
func TestTransportHTTP2Settings(t *testing.T) {
	settings := &HTTP2Settings{
		Settings: []HTTP2Setting{
			{ID: HTTP2SettingHeaderTableSize, Val: 65536},
			{ID: HTTP2SettingEnablePush, Val: 0},
		},
		ConnectionFlow: 15663105,
	}

	tr := &Transport{
		HTTP2Settings: settings,
	}

	if tr.HTTP2Settings == nil {
		t.Fatal("HTTP2Settings 不应该为 nil")
	}

	if len(tr.HTTP2Settings.Settings) != 2 {
		t.Errorf("Settings 长度 = %d, want 2", len(tr.HTTP2Settings.Settings))
	}

	if tr.HTTP2Settings.ConnectionFlow != 15663105 {
		t.Errorf("ConnectionFlow = %d, want 15663105", tr.HTTP2Settings.ConnectionFlow)
	}
}

// TestTransportProxyURL 测试代理 URL 函数
func TestTransportProxyURL(t *testing.T) {
	proxyURL, err := url.Parse("http://proxy.example.com:8080")
	if err != nil {
		t.Fatalf("解析代理 URL 失败: %v", err)
	}

	tr := &Transport{
		Proxy: ProxyURL(proxyURL),
	}

	if tr.Proxy == nil {
		t.Fatal("Proxy 函数不应该为 nil")
	}

	// 测试代理函数
	req := &Request{
		URL: &url.URL{
			Scheme: "http",
			Host:   "example.com",
		},
	}

	gotProxy, err := tr.Proxy(req)
	if err != nil {
		t.Fatalf("Proxy 函数返回错误: %v", err)
	}

	if gotProxy.String() != proxyURL.String() {
		t.Errorf("Proxy URL = %v, want %v", gotProxy, proxyURL)
	}
}

// TestTransportTLSClientConfig 测试 TLS 客户端配置
func TestTransportTLSClientConfig(t *testing.T) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.com",
	}

	tr := &Transport{
		TLSClientConfig: tlsConfig,
	}

	if tr.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig 不应该为 nil")
	}

	if !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify 应该为 true")
	}

	if tr.TLSClientConfig.ServerName != "example.com" {
		t.Errorf("ServerName = %v, want example.com", tr.TLSClientConfig.ServerName)
	}
}

// TestTransportTimeouts 测试超时设置
func TestTransportTimeouts(t *testing.T) {
	tr := &Transport{
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	if tr.IdleConnTimeout != 90*time.Second {
		t.Errorf("IdleConnTimeout = %v, want 90s", tr.IdleConnTimeout)
	}

	if tr.TLSHandshakeTimeout != 10*time.Second {
		t.Errorf("TLSHandshakeTimeout = %v, want 10s", tr.TLSHandshakeTimeout)
	}

	if tr.ExpectContinueTimeout != 1*time.Second {
		t.Errorf("ExpectContinueTimeout = %v, want 1s", tr.ExpectContinueTimeout)
	}

	if tr.ResponseHeaderTimeout != 30*time.Second {
		t.Errorf("ResponseHeaderTimeout = %v, want 30s", tr.ResponseHeaderTimeout)
	}
}

// BenchmarkTransportClone 性能测试：Transport 克隆
func BenchmarkTransportClone(b *testing.B) {
	tr := &Transport{
		JA3:           "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
		RandomJA3:     true,
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		ALPNProtocols: []string{"h2", "http/1.1"},
		CustomALPN:    true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tr.Clone()
	}
}

// BenchmarkAdjustNextProtos 性能测试：ALPN 协议调整
func BenchmarkAdjustNextProtos(b *testing.B) {
	nextProtos := []string{"h2", "http/1.1", "http/1.0"}
	protocols := Protocols{http1: true, http2: true}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = adjustNextProtos(nextProtos, protocols)
	}
}

