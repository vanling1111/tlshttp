// Copyright 2025 The tlshttp Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package presets 提供预设的浏览器指纹配置
// 包括 JA3 字符串、User-Agent、HTTP/2 设置等
//
// 这个包的设计理念：
// - 提供常见浏览器的真实指纹配置
// - 简化用户使用，无需手动构造复杂的配置
// - 保持更新，确保指纹的有效性
package presets

import (
	"github.com/vanling1111/tlshttp"
)

// BrowserFingerprint 浏览器指纹配置
type BrowserFingerprint struct {
	Name       string                 // 浏览器名称
	JA3        string                 // JA3 指纹字符串
	UserAgent  string                 // User-Agent 字符串
	HTTP2      *http.HTTP2Settings    // HTTP/2 设置
}

// ===== Chrome 浏览器指纹 =====

// Chrome120Windows 是 Chrome 120 (Windows 10) 的指纹配置
var Chrome120Windows = BrowserFingerprint{
	Name:      "Chrome 120 (Windows 10)",
	JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
	UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	HTTP2: &http.HTTP2Settings{
		Settings: []http.HTTP2Setting{
			{ID: http.HTTP2SettingHeaderTableSize, Val: 65536},
			{ID: http.HTTP2SettingEnablePush, Val: 0},
			{ID: http.HTTP2SettingInitialWindowSize, Val: 6291456},
			{ID: http.HTTP2SettingMaxHeaderListSize, Val: 262144},
		},
		ConnectionFlow: 15663105,
		HeaderPriority: &http.HTTP2PriorityParam{
			Weight:    255,
			StreamDep: 0,
			Exclusive: true,
		},
	},
}

// Chrome117Windows 是 Chrome 117 (Windows 10) 的指纹配置
var Chrome117Windows = BrowserFingerprint{
	Name:      "Chrome 117 (Windows 10)",
	JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-5-10-0-43-35-17613-23-18-65037-11-13-16-27-65281-51-41,4588-29-23-24,0",
	UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
	HTTP2: &http.HTTP2Settings{
		Settings: []http.HTTP2Setting{
			{ID: http.HTTP2SettingHeaderTableSize, Val: 65536},
			{ID: http.HTTP2SettingEnablePush, Val: 0},
			{ID: http.HTTP2SettingInitialWindowSize, Val: 6291456},
			{ID: http.HTTP2SettingMaxHeaderListSize, Val: 262144},
		},
		ConnectionFlow: 15663105,
		HeaderPriority: &http.HTTP2PriorityParam{
			Weight:    255,
			StreamDep: 0,
			Exclusive: true,
		},
	},
}

// Chrome133Windows 是 Chrome 133 (Windows 10) 的指纹配置
var Chrome133Windows = BrowserFingerprint{
	Name:      "Chrome 133 (Windows 10)",
	JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
	UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
	HTTP2: &http.HTTP2Settings{
		Settings: []http.HTTP2Setting{
			{ID: http.HTTP2SettingHeaderTableSize, Val: 65536},
			{ID: http.HTTP2SettingEnablePush, Val: 0},
			{ID: http.HTTP2SettingInitialWindowSize, Val: 6291456},
			{ID: http.HTTP2SettingMaxHeaderListSize, Val: 262144},
		},
		ConnectionFlow: 15663105,
		HeaderPriority: &http.HTTP2PriorityParam{
			Weight:    255,
			StreamDep: 0,
			Exclusive: true,
		},
	},
}

// ===== Firefox 浏览器指纹 =====

// Firefox120Windows 是 Firefox 120 (Windows 10) 的指纹配置
var Firefox120Windows = BrowserFingerprint{
	Name:      "Firefox 120 (Windows 10)",
	JA3:       "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,51-10-23-34-65281-13-18-35-11-27-43-5-0-45-16-65037-28-41,29-23-24-25-256-257,0",
	UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
	HTTP2: &http.HTTP2Settings{
		Settings: []http.HTTP2Setting{
			{ID: http.HTTP2SettingHeaderTableSize, Val: 65536},
			{ID: http.HTTP2SettingInitialWindowSize, Val: 131072},
			{ID: http.HTTP2SettingMaxFrameSize, Val: 16384},
		},
		ConnectionFlow: 12517377,
		HeaderPriority: &http.HTTP2PriorityParam{
			Weight:    42,
			StreamDep: 13,
			Exclusive: false,
		},
	},
}

// ===== Safari/iOS 浏览器指纹 =====

// SafariiOS17 是 Safari (iOS 17) 的指纹配置
var SafariiOS17 = BrowserFingerprint{
	Name:      "Safari (iOS 17)",
	JA3:       "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
	UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
	HTTP2: &http.HTTP2Settings{
		Settings: []http.HTTP2Setting{
			{ID: http.HTTP2SettingHeaderTableSize, Val: 4096},
			{ID: http.HTTP2SettingEnablePush, Val: 0},
			{ID: http.HTTP2SettingInitialWindowSize, Val: 2097152},
			{ID: http.HTTP2SettingMaxFrameSize, Val: 16384},
			{ID: http.HTTP2SettingMaxConcurrentStreams, Val: 100},
		},
		ConnectionFlow: 10485760,
		HeaderPriority: &http.HTTP2PriorityParam{
			Weight:    255,
			StreamDep: 0,
			Exclusive: false,
		},
	},
}

// ===== Edge 浏览器指纹 =====

// Edge120Windows 是 Edge 120 (Windows 10) 的指纹配置
var Edge120Windows = BrowserFingerprint{
	Name:      "Edge 120 (Windows 10)",
	JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,35-23-0-21-27-13-65281-65037-17513-45-10-43-5-16-18-51-11-41,29-23-24,0",
	UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	HTTP2: &http.HTTP2Settings{
		Settings: []http.HTTP2Setting{
			{ID: http.HTTP2SettingHeaderTableSize, Val: 65536},
			{ID: http.HTTP2SettingEnablePush, Val: 0},
			{ID: http.HTTP2SettingInitialWindowSize, Val: 6291456},
			{ID: http.HTTP2SettingMaxHeaderListSize, Val: 262144},
		},
		ConnectionFlow: 15663105,
		HeaderPriority: &http.HTTP2PriorityParam{
			Weight:    255,
			StreamDep: 0,
			Exclusive: true,
		},
	},
}

// ===== 便捷的预设列表 =====

// AllPresets 包含所有预设的浏览器指纹
var AllPresets = map[string]*BrowserFingerprint{
	"chrome120":   &Chrome120Windows,
	"chrome117":   &Chrome117Windows,
	"chrome133":   &Chrome133Windows,
	"firefox120":  &Firefox120Windows,
	"safari_ios17": &SafariiOS17,
	"edge120":     &Edge120Windows,
}

// GetPreset 根据名称获取预设指纹
// 支持的名称：chrome120, chrome117, chrome133, firefox120, safari_ios17, edge120
func GetPreset(name string) *BrowserFingerprint {
	if preset, ok := AllPresets[name]; ok {
		return preset
	}
	return nil
}

// ApplyToTransport 将浏览器指纹应用到 Transport
func (bf *BrowserFingerprint) ApplyToTransport(transport *http.Transport) {
	if transport == nil {
		return
	}
	
	transport.JA3 = bf.JA3
	transport.UserAgent = bf.UserAgent
	
	if bf.HTTP2 != nil {
		// 深度克隆 HTTP2Settings
		clonedHTTP2, err := bf.HTTP2.Clone()
		if err == nil {
			transport.HTTP2Settings = clonedHTTP2
		}
	}
}

// NewTransport 创建一个使用指定浏览器指纹的 Transport
func (bf *BrowserFingerprint) NewTransport() *http.Transport {
	transport := &http.Transport{
		JA3:       bf.JA3,
		UserAgent: bf.UserAgent,
	}
	
	if bf.HTTP2 != nil {
		// 深度克隆 HTTP2Settings
		clonedHTTP2, err := bf.HTTP2.Clone()
		if err == nil {
			transport.HTTP2Settings = clonedHTTP2
		}
	}
	
	return transport
}

