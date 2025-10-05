# 预设浏览器指纹 (Browser Fingerprint Presets)

`presets` 包提供了常见浏览器的预设指纹配置，包括 JA3 字符串、User-Agent 和 HTTP/2 设置，让你可以轻松模拟各种浏览器的 TLS 指纹。

## 🚀 快速开始

### 方式 1: 使用预设指纹创建 Transport

```go
import (
    "github.com/vanling1111/tlshttp"
    "github.com/vanling1111/tlshttp/presets"
)

// 创建一个使用 Chrome 120 指纹的 Transport
transport := presets.Chrome120Windows.NewTransport()

// 创建 HTTP 客户端
client := &http.Client{Transport: transport}

// 发起请求
resp, err := client.Get("https://example.com")
```

### 方式 2: 应用预设指纹到现有的 Transport

```go
// 创建自定义的 Transport
transport := &http.Transport{
    MaxIdleConns:        100,
    MaxIdleConnsPerHost: 10,
}

// 应用 Firefox 120 的指纹
presets.Firefox120Windows.ApplyToTransport(transport)

client := &http.Client{Transport: transport}
```

### 方式 3: 通过名称获取预设指纹

```go
// 通过名称获取预设
preset := presets.GetPreset("chrome133")

// 创建 Transport
transport := preset.NewTransport()
client := &http.Client{Transport: transport}
```

## 📋 可用的预设指纹

| 预设名称 | 浏览器 | 描述 |
|---------|--------|------|
| `chrome120` | Chrome 120 (Windows 10) | 最新的 Chrome 浏览器指纹 |
| `chrome117` | Chrome 117 (Windows 10) | Chrome 117 稳定版指纹 |
| `chrome133` | Chrome 133 (Windows 10) | Chrome 133 最新版指纹 |
| `firefox120` | Firefox 120 (Windows 10) | Firefox 120 稳定版指纹 |
| `safari_ios17` | Safari (iOS 17) | Safari iOS 17 移动版指纹 |
| `edge120` | Edge 120 (Windows 10) | Edge 120 浏览器指纹 |

## 📚 详细使用示例

### 示例 1: 使用 Chrome 指纹

```go
package main

import (
    "fmt"
    "io"
    "github.com/vanling1111/tlshttp"
    "github.com/vanling1111/tlshttp/presets"
)

func main() {
    // 使用 Chrome 120 的指纹
    transport := presets.Chrome120Windows.NewTransport()
    
    // 创建 HTTP 客户端
    client := &http.Client{Transport: transport}
    
    // 发起请求
    resp, err := client.Get("https://tls.peet.ws/api/all")
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()
    
    body, _ := io.ReadAll(resp.Body)
    fmt.Println(string(body))
}
```

### 示例 2: 使用 Firefox 指纹

```go
// 使用 Firefox 120 的指纹
transport := presets.Firefox120Windows.NewTransport()

client := &http.Client{Transport: transport}
resp, _ := client.Get("https://example.com")
```

### 示例 3: 使用 Safari iOS 指纹

```go
// 使用 Safari iOS 17 的指纹
transport := presets.SafariiOS17.NewTransport()

client := &http.Client{Transport: transport}
resp, _ := client.Get("https://example.com")
```

### 示例 4: 组合使用预设指纹和自定义配置

```go
// 使用 Chrome 120 的指纹
transport := presets.Chrome120Windows.NewTransport()

// 添加自定义配置
transport.RandomJA3 = true              // 启用 JA3 随机化
transport.ForceHTTP1 = false            // 允许 HTTP/2
transport.MaxIdleConns = 100            // 设置最大空闲连接数
transport.MaxIdleConnsPerHost = 10      // 设置每个主机的最大空闲连接数

// 创建 HTTP 客户端
client := &http.Client{Transport: transport}
resp, _ := client.Get("https://example.com")
```

### 示例 5: 遍历所有预设指纹

```go
import "github.com/vanling1111/tlshttp/presets"

// 打印所有可用的预设指纹
for name, preset := range presets.AllPresets {
    fmt.Printf("Name: %s\n", name)
    fmt.Printf("Browser: %s\n", preset.Name)
    fmt.Printf("JA3: %s\n", preset.JA3)
    fmt.Printf("User-Agent: %s\n\n", preset.UserAgent)
}
```

## 🔧 自定义配置

每个预设指纹都包含以下配置：

```go
type BrowserFingerprint struct {
    Name       string                 // 浏览器名称
    JA3        string                 // JA3 指纹字符串
    UserAgent  string                 // User-Agent 字符串
    HTTP2      *http.HTTP2Settings    // HTTP/2 设置
}
```

你可以直接访问这些字段：

```go
preset := presets.Chrome120Windows

fmt.Println("Browser:", preset.Name)
fmt.Println("JA3:", preset.JA3)
fmt.Println("User-Agent:", preset.UserAgent)
fmt.Println("HTTP/2 Settings:", preset.HTTP2.Settings)
```

## 🎯 高级用法

### 1. 动态切换浏览器指纹

```go
presets := []string{"chrome120", "firefox120", "safari_ios17"}

for _, name := range presets {
    preset := presets.GetPreset(name)
    transport := preset.NewTransport()
    client := &http.Client{Transport: transport}
    
    resp, _ := client.Get("https://example.com")
    fmt.Printf("Using %s: %s\n", preset.Name, resp.Status)
}
```

### 2. 结合自定义 TLS 扩展

```go
import utls "github.com/refraction-networking/utls"

// 使用 Chrome 120 的指纹
transport := presets.Chrome120Windows.NewTransport()

// 自定义 TLS 扩展
transport.TLSExtensions = &http.TLSExtensionsConfig{
    SupportedSignatureAlgorithms: &utls.SignatureAlgorithmsExtension{
        SupportedSignatureAlgorithms: []utls.SignatureScheme{
            utls.ECDSAWithP256AndSHA256,
            utls.PSSWithSHA256,
        },
    },
}

client := &http.Client{Transport: transport}
```

### 3. 启用 JA3 随机化

```go
// 使用 Chrome 120 的指纹，并启用随机化
transport := presets.Chrome120Windows.NewTransport()
transport.RandomJA3 = true  // 每次请求都会随机化 TLS 扩展顺序

client := &http.Client{Transport: transport}
```

## 📊 项目特色

| 特性 | 说明 |
|------|------|
| **预设指纹库** | ✅ 独立的 presets 包，开箱即用 |
| **JA3 字符串** | ✅ 完整的 JA3 指纹支持 |
| **User-Agent** | ✅ 真实的浏览器 User-Agent |
| **HTTP/2 设置** | ✅ 完整的 HTTP/2 配置 |
| **API 设计** | ✅ 简洁易用，一行代码创建 |
| **深度克隆** | ✅ CBOR 深拷贝支持 |

## 🔐 安全性说明

这些预设指纹基于真实浏览器的 TLS 指纹，可以有效绕过基于 TLS 指纹的反爬虫检测。但请注意：

1. **合法使用**: 仅用于合法的 Web 爬虫和测试用途
2. **定期更新**: 浏览器指纹会随着浏览器版本更新而变化
3. **组合使用**: 建议结合 User-Agent、HTTP 头部、Cookie 等其他技术
4. **遵守规则**: 遵守网站的 robots.txt 和使用条款

## 📝 贡献

如果你发现某个浏览器的指纹已经过时，或者想要添加新的浏览器指纹，欢迎提交 PR！

## 📄 许可证

BSD-style license

