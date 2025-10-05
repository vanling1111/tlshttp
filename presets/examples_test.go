// Copyright 2025 The tlshttp Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package presets_test

import (
	"fmt"
	"io"
	
	"github.com/vanling1111/tlshttp"
	"github.com/vanling1111/tlshttp/presets"
)

// 示例1：使用预设指纹创建 Transport（最简单的方式）
func ExampleBrowserFingerprint_NewTransport() {
	// 创建一个使用 Chrome 120 指纹的 Transport
	transport := presets.Chrome120Windows.NewTransport()
	
	// 创建 HTTP 客户端
	client := &http.Client{Transport: transport}
	
	// 发起请求
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
	
	fmt.Println("Status:", resp.Status)
}

// 示例2：应用预设指纹到现有的 Transport
func ExampleBrowserFingerprint_ApplyToTransport() {
	// 创建自定义的 Transport
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
	}
	
	// 应用 Firefox 120 的指纹
	presets.Firefox120Windows.ApplyToTransport(transport)
	
	// 创建 HTTP 客户端
	client := &http.Client{Transport: transport}
	
	// 发起请求
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
	
	body, _ := io.ReadAll(resp.Body)
	fmt.Println("Body length:", len(body))
}

// 示例3：通过名称获取预设指纹
func ExampleGetPreset() {
	// 通过名称获取预设
	preset := presets.GetPreset("chrome133")
	if preset == nil {
		fmt.Println("Preset not found")
		return
	}
	
	// 打印指纹信息
	fmt.Println("Name:", preset.Name)
	fmt.Println("JA3:", preset.JA3[:50]+"...") // 只打印前50个字符
	fmt.Println("User-Agent:", preset.UserAgent[:50]+"...")
	
	// 创建 Transport
	transport := preset.NewTransport()
	client := &http.Client{Transport: transport}
	
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
	
	fmt.Println("Status:", resp.StatusCode)
}

// 示例4：使用 Safari iOS 指纹
func Example_safariIOS() {
	// 使用 Safari iOS 17 的指纹
	transport := presets.SafariiOS17.NewTransport()
	
	// 创建 HTTP 客户端
	client := &http.Client{Transport: transport}
	
	// 发起请求
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
	
	fmt.Println("Status:", resp.Status)
	fmt.Println("Protocol:", resp.Proto)
}

// 示例5：遍历所有预设指纹
func ExampleAllPresets() {
	fmt.Println("Available presets:")
	for name, preset := range presets.AllPresets {
		fmt.Printf("- %s: %s\n", name, preset.Name)
	}
}

// 示例6：使用 Edge 浏览器指纹
func Example_edgeWindows() {
	// 使用 Edge 120 的指纹
	transport := presets.Edge120Windows.NewTransport()
	
	// 添加额外的配置
	transport.RandomJA3 = true // 启用 JA3 随机化
	
	// 创建 HTTP 客户端
	client := &http.Client{Transport: transport}
	
	// 发起请求
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
	
	fmt.Println("Status:", resp.Status)
}

// 示例7：组合使用预设指纹和自定义配置
func Example_combinedConfig() {
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
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
	
	fmt.Println("Status:", resp.Status)
	fmt.Println("Protocol:", resp.Proto)
}

