# 预设浏览器指纹使用指南

`presets` 包提供了多种使用方式，让你可以轻松模拟真实浏览器指纹。

## 🎯 8种使用方式

### 方式 1: 直接使用预设变量

```go
import (
    http "github.com/vanling1111/tlshttp"
    "github.com/vanling1111/tlshttp/presets"
)

// Chrome 120 Windows
transport := presets.Chrome120Windows.NewTransport()
client := &http.Client{Transport: transport}
resp, err := client.Get("https://httpbin.org/headers")
```

### 方式 2: 通过名称动态获取预设

```go
// 支持的预设名称：chrome120, chrome117, chrome133, firefox120, safari_ios17, edge120
preset := presets.GetPreset("chrome120")
if preset != nil {
    transport := preset.NewTransport()
    client := &http.Client{Transport: transport}
    resp, err := client.Get("https://httpbin.org/headers")
}
```

### 方式 3: 应用到现有 Transport

```go
// 创建自定义 Transport
transport := &http.Transport{
    MaxIdleConns:        100,
    MaxIdleConnsPerHost: 10,
}

// 应用浏览器指纹
presets.Chrome120Windows.ApplyToTransport(transport)
client := &http.Client{Transport: transport}
```

### 方式 4: 获取指纹信息

```go
preset := presets.Chrome120Windows
fmt.Printf("浏览器: %s\n", preset.Name)
fmt.Printf("JA3: %s\n", preset.JA3)
fmt.Printf("User-Agent: %s\n", preset.UserAgent)
if preset.HTTP2 != nil {
    fmt.Printf("HTTP/2 设置数量: %d\n", len(preset.HTTP2.Settings))
}
```

### 方式 5: 遍历所有可用预设

```go
for name, preset := range presets.AllPresets {
    fmt.Printf("预设名称: %s, 浏览器: %s\n", name, preset.Name)
}
```

### 方式 6: 实际使用示例

```go
package main

import (
    "fmt"
    "log"
    http "github.com/vanling1111/tlshttp"
    "github.com/vanling1111/tlshttp/presets"
)

func main() {
    transport := presets.Chrome120Windows.NewTransport()
    client := &http.Client{Transport: transport}
    
    resp, err := client.Get("https://httpbin.org/headers")
    if err != nil {
        log.Fatal(err)
    }
    defer resp.Body.Close()
    
    fmt.Printf("状态码: %d\n", resp.StatusCode)
}
```

### 方式 7: 批量测试不同指纹

```go
func testAllPresets() {
    presets := map[string]*presets.BrowserFingerprint{
        "Chrome 120":  &presets.Chrome120Windows,
        "Chrome 117":  &presets.Chrome117Windows,
        "Chrome 133":  &presets.Chrome133Windows,
        "Firefox 120": &presets.Firefox120Windows,
        "Safari iOS":  &presets.SafariiOS17,
        "Edge 120":    &presets.Edge120Windows,
    }
    
    for name, preset := range presets {
        transport := preset.NewTransport()
        client := &http.Client{Transport: transport}
        
        resp, err := client.Get("https://tls.peet.ws/api/all")
        if err != nil {
            log.Printf("%s: 请求失败 - %v\n", name, err)
            continue
        }
        fmt.Printf("✅ %s: 状态码 %d\n", name, resp.StatusCode)
    }
}
```

### 方式 8: 自定义配置结合预设

```go
transport := presets.Chrome120Windows.NewTransport()
transport.RandomJA3 = true              // 启用 JA3 随机化
transport.ForceHTTP1 = false            // 允许 HTTP/2
transport.MaxIdleConns = 100            // 设置最大空闲连接数
transport.MaxIdleConnsPerHost = 10      // 设置每个主机的最大空闲连接数

client := &http.Client{
    Transport: transport,
    Timeout:   30 * time.Second,
}
```

## 📋 可用的预设指纹

| 预设名称 | 变量名 | 浏览器版本 | 平台 |
|---------|--------|------------|------|
| `chrome120` | `Chrome120Windows` | Chrome 120 | Windows 10 |
| `chrome117` | `Chrome117Windows` | Chrome 117 | Windows 10 |
| `chrome133` | `Chrome133Windows` | Chrome 133 | Windows 10 |
| `firefox120` | `Firefox120Windows` | Firefox 120 | Windows 10 |
| `safari_ios17` | `SafariiOS17` | Safari | iOS 17 |
| `edge120` | `Edge120Windows` | Edge 120 | Windows 10 |

## 🎯 presets 包的优势

1. **✅ 开箱即用** - 无需手动配置复杂的 TLS 参数
2. **✅ 真实指纹** - 基于真实浏览器抓包数据
3. **✅ 多浏览器支持** - Chrome、Firefox、Safari、Edge
4. **✅ 版本覆盖** - 支持不同版本的浏览器指纹
5. **✅ 完整配置** - 包含 JA3、User-Agent、HTTP/2 设置
6. **✅ 灵活使用** - 多种使用方式满足不同需求
7. **✅ 持续更新** - 跟随浏览器版本更新

## 🎯 选择建议

- **Chrome 120** - 推荐用于一般爬虫场景
- **Chrome 133** - 最新版本，适合高要求场景
- **Firefox 120** - 适合需要多样化指纹的场景
- **Safari iOS** - 适合模拟移动端访问
- **Edge 120** - 适合模拟企业环境

## 📚 更多文档

- [高级配置指南](ADVANCED_USAGE.md)
- [架构设计说明](ARCHITECTURE.md)
- [完整 API 文档](API_REFERENCE.md)
