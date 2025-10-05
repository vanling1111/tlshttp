// Copyright 2025 The tlshttp Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// 使用预设浏览器指纹的示例
package main

import (
	"fmt"
	"io"
	
	http "github.com/vanling1111/tlshttp"
	"github.com/vanling1111/tlshttp/presets"
)

func main() {
	fmt.Println("========== 示例 1: 使用 Chrome 120 指纹 ==========")
	exampleChrome120()
	
	fmt.Println("\n========== 示例 2: 使用 Firefox 120 指纹 ==========")
	exampleFirefox120()
	
	fmt.Println("\n========== 示例 3: 使用 Safari iOS 指纹 ==========")
	exampleSafariIOS()
	
	fmt.Println("\n========== 示例 4: 通过名称获取预设 ==========")
	exampleGetPreset()
	
	fmt.Println("\n========== 示例 5: 应用到现有 Transport ==========")
	exampleApplyToTransport()
	
	fmt.Println("\n========== 示例 6: 组合使用预设和自定义配置 ==========")
	exampleCombineWithCustomConfig()
	
	fmt.Println("\n========== 示例 7: 遍历所有预设 ==========")
	exampleListAllPresets()
}

// 示例 1: 使用 Chrome 120 指纹
func exampleChrome120() {
	// 创建使用 Chrome 120 指纹的 Transport
	transport := presets.Chrome120Windows.NewTransport()
	
	// 创建 HTTP 客户端
	client := &http.Client{Transport: transport}
	
	// 发起请求
	resp, err := client.Get("https://tls.peet.ws/api/all")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
	
	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Protocol: %s\n", resp.Proto)
	fmt.Printf("Body length: %d bytes\n", len(body))
}

// 示例 2: 使用 Firefox 120 指纹
func exampleFirefox120() {
	// 创建使用 Firefox 120 指纹的 Transport
	transport := presets.Firefox120Windows.NewTransport()
	
	// 创建 HTTP 客户端
	client := &http.Client{Transport: transport}
	
	// 发起请求
	resp, err := client.Get("https://tls.peet.ws/api/all")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
	
	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Protocol: %s\n", resp.Proto)
}

// 示例 3: 使用 Safari iOS 指纹
func exampleSafariIOS() {
	// 创建使用 Safari iOS 17 指纹的 Transport
	transport := presets.SafariiOS17.NewTransport()
	
	// 创建 HTTP 客户端
	client := &http.Client{Transport: transport}
	
	// 发起请求
	resp, err := client.Get("https://tls.peet.ws/api/all")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
	
	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Protocol: %s\n", resp.Proto)
}

// 示例 4: 通过名称获取预设
func exampleGetPreset() {
	// 通过名称获取预设指纹
	preset := presets.GetPreset("chrome133")
	if preset == nil {
		fmt.Println("Preset not found")
		return
	}
	
	// 打印指纹信息
	fmt.Printf("Name: %s\n", preset.Name)
	fmt.Printf("JA3: %s...\n", preset.JA3[:50])
	fmt.Printf("User-Agent: %s...\n", preset.UserAgent[:50])
	
	// 创建 Transport
	transport := preset.NewTransport()
	client := &http.Client{Transport: transport}
	
	// 发起请求
	resp, err := client.Get("https://tls.peet.ws/api/all")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
	
	fmt.Printf("Status: %s\n", resp.Status)
}

// 示例 5: 应用到现有 Transport
func exampleApplyToTransport() {
	// 创建自定义的 Transport
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
	}
	
	// 应用 Edge 120 的指纹
	presets.Edge120Windows.ApplyToTransport(transport)
	
	// 创建 HTTP 客户端
	client := &http.Client{Transport: transport}
	
	// 发起请求
	resp, err := client.Get("https://tls.peet.ws/api/all")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
	
	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Max Idle Conns: %d\n", transport.MaxIdleConns)
}

// 示例 6: 组合使用预设和自定义配置
func exampleCombineWithCustomConfig() {
	// 使用 Chrome 120 的指纹
	transport := presets.Chrome120Windows.NewTransport()
	
	// 添加自定义配置
	transport.RandomJA3 = true              // 启用 JA3 随机化
	transport.ForceHTTP1 = false            // 允许 HTTP/2
	transport.MaxIdleConns = 100            // 设置最大空闲连接数
	transport.MaxIdleConnsPerHost = 10      // 设置每个主机的最大空闲连接数
	
	// 创建 HTTP 客户端
	client := &http.Client{Transport: transport}
	
	// 发起请求
	resp, err := client.Get("https://tls.peet.ws/api/all")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
	
	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Protocol: %s\n", resp.Proto)
	fmt.Printf("Random JA3: %v\n", transport.RandomJA3)
}

// 示例 7: 遍历所有预设
func exampleListAllPresets() {
	fmt.Println("Available presets:")
	for name, preset := range presets.AllPresets {
		fmt.Printf("  - %s: %s\n", name, preset.Name)
		fmt.Printf("    JA3: %s...\n", preset.JA3[:50])
		fmt.Printf("    User-Agent: %s...\n", preset.UserAgent[:50])
		fmt.Println()
	}
}

