# 高级配置指南

## Session 管理

```go
import http "github.com/vanling1111/tlshttp"

// 创建带 Session 的客户端
client := &http.Client{
    Transport: &http.Transport{
        JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
        UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    },
    Jar: &http.CookieJar{}, // 启用 Cookie 管理
}

// 第一次请求 - 登录
resp1, _ := client.PostForm("https://example.com/login", url.Values{
    "username": {"user"},
    "password": {"pass"},
})

// 第二次请求 - 自动携带 Cookie
resp2, _ := client.Get("https://example.com/dashboard")
```

## 自定义 TLS 指纹

### 基础 JA3 配置

```go
transport := &http.Transport{
    JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
    UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
}
```

### 高级 TLS 配置

```go
transport := &http.Transport{
    TLSFingerprint: &http.TLSFingerprintConfig{
        JA3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
        TLSConfig: &http.TLSConfig{
            MinVersion: tls.VersionTLS12,
            MaxVersion: tls.VersionTLS13,
        },
        TLSExtensions: &http.TLSExtensionsConfig{
            SNI:        true,
            ALPN:       []string{"h2", "http/1.1"},
            SignatureAlgorithms: []tls.SignatureScheme{
                tls.PSSWithSHA256,
                tls.ECDSAWithP256AndSHA256,
                tls.PKCS1WithSHA256,
            },
        },
    },
    UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
}
```

### HTTP/2 配置

```go
transport := &http.Transport{
    TLSFingerprint: &http.TLSFingerprintConfig{
        JA3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
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
    },
}
```

## 自定义请求头

```go
transport := &http.Transport{
    JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
    UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
}

client := &http.Client{Transport: transport}

req, _ := http.NewRequest("GET", "https://example.com", nil)
req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
req.Header.Set("Accept-Language", "en-US,en;q=0.5")
req.Header.Set("Accept-Encoding", "gzip, deflate, br")
req.Header.Set("Cache-Control", "no-cache")
req.Header.Set("Pragma", "no-cache")

resp, _ := client.Do(req)
```

## 代理配置

```go
import (
    "net/url"
    http "github.com/vanling1111/tlshttp"
)

// HTTP 代理
proxyURL, _ := url.Parse("http://proxy.example.com:8080")
transport := &http.Transport{
    JA3:   "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
    Proxy: http.ProxyURL(proxyURL),
}

// SOCKS5 代理
socksURL, _ := url.Parse("socks5://127.0.0.1:1080")
transport.Proxy = http.ProxyURL(socksURL)

client := &http.Client{Transport: transport}
```

## 超时配置

```go
client := &http.Client{
    Transport: &http.Transport{
        JA3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
    },
    Timeout: 30 * time.Second,
}

// 或者使用 Context 超时
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

req, _ := http.NewRequestWithContext(ctx, "GET", "https://example.com", nil)
resp, _ := client.Do(req)
```

## 连接池配置

```go
transport := &http.Transport{
    JA3:                    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
    MaxIdleConns:           100,
    MaxIdleConnsPerHost:    10,
    MaxConnsPerHost:        20,
    IdleConnTimeout:        90 * time.Second,
    TLSHandshakeTimeout:    10 * time.Second,
    ExpectContinueTimeout:  1 * time.Second,
    ResponseHeaderTimeout:  10 * time.Second,
}
```

## 错误处理

```go
client := &http.Client{
    Transport: &http.Transport{
        JA3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
    },
    Timeout: 30 * time.Second,
}

resp, err := client.Get("https://example.com")
if err != nil {
    if urlErr, ok := err.(*url.Error); ok {
        if urlErr.Timeout() {
            log.Println("请求超时")
        } else if urlErr.Temporary() {
            log.Println("临时错误，可以重试")
        }
    }
    log.Fatal(err)
}
defer resp.Body.Close()

if resp.StatusCode != 200 {
    log.Printf("HTTP 错误: %d %s", resp.StatusCode, resp.Status)
}
```

## 调试和监控

```go
// 启用详细日志
transport := &http.Transport{
    JA3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
}

// 添加请求跟踪
req, _ := http.NewRequest("GET", "https://example.com", nil)
trace := &httptrace.ClientTrace{
    GotConn: func(connInfo httptrace.GotConnInfo) {
        fmt.Printf("连接信息: %+v\n", connInfo)
    },
    DNSStart: func(dnsInfo httptrace.DNSStartInfo) {
        fmt.Printf("DNS 查询开始: %s\n", dnsInfo.Host)
    },
}
req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

resp, _ := client.Do(req)
```

## 最佳实践

1. **选择合适的指纹** - 根据目标网站选择相应的浏览器指纹
2. **合理设置超时** - 避免长时间等待
3. **使用连接池** - 提高并发性能
4. **错误重试机制** - 处理网络波动
5. **监控和日志** - 便于调试和优化

## 相关文档

- [预设指纹使用指南](PRESETS_GUIDE.md)
- [架构设计说明](ARCHITECTURE.md)
- [完整 API 文档](API_REFERENCE.md)
