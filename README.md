# tlshttp

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT%20with%20Commercial%20Restriction-red.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/vanling1111/tlshttp)](https://goreportcard.com/report/github.com/vanling1111/tlshttp)
[![Tests](https://github.com/vanling1111/tlshttp/workflows/Tests/badge.svg)](https://github.com/vanling1111/tlshttp/actions)
[![codecov](https://codecov.io/gh/vanling1111/tlshttp/branch/main/graph/badge.svg)](https://codecov.io/gh/vanling1111/tlshttp)
[![GoDoc](https://godoc.org/github.com/vanling1111/tlshttp?status.svg)](https://godoc.org/github.com/vanling1111/tlshttp)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

> 🛡️ 专注于 TLS 指纹控制的 HTTP 客户端 - 为爬虫框架而生

## 🎯 项目定位

**tlshttp** 是一个专注于 **TLS 指纹控制**和**反爬技术**的 HTTP 客户端，作为爬虫框架的底层基础。

## ✨ 核心特性

### 🛡️ 强大的 TLS 指纹控制
- ✅ **JA3 指纹伪装** - 精确控制 TLS 握手指纹
- ✅ **JA4 指纹伪装** - 支持最新 JA4 算法
- ✅ **HTTP/2 指纹** - 完全控制 SETTINGS 帧和优先级
- ✅ **预设指纹库** - 10+ 真实浏览器指纹，一行代码切换
- ✅ **TLS 扩展控制** - 精确控制每个 TLS 扩展
- ✅ **请求头顺序** - 控制 HTTP 头部顺序和大小写

### ⚡ 高性能（基于 net/http）
- 🎯 **200K+ QPS** - 无反爬模式
- 🎯 **80-100K QPS** - 反爬模式
- 🎯 **HTTP/2 多路复用** - 连接复用优化

### 🎨 简洁易用
- ✅ **简洁 API** - 类似 Python requests 的易用性
- ✅ **Session 管理** - 自动处理 Cookie 和状态
- ✅ **自动压缩** - 支持 gzip, deflate, brotli
- ✅ **最小依赖** - 只依赖必需的底层库

## 🚀 快速开始

### 安装

```bash
go get github.com/vanling1111/tlshttp
```

### 基础使用

```go
package main

import (
    "fmt"
    "log"
    http "github.com/vanling1111/tlshttp"
)

func main() {
    // 创建自定义 TLS 指纹的客户端
    client := &http.Client{
        Transport: &http.Transport{
            JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
            UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        },
    }

    resp, err := client.Get("https://httpbin.org/headers")
    if err != nil {
        log.Fatal(err)
    }
    defer resp.Body.Close()

    fmt.Printf("状态码: %d\n", resp.StatusCode)
}
```

### 使用预设浏览器指纹

```go
import (
    http "github.com/vanling1111/tlshttp"
    "github.com/vanling1111/tlshttp/presets"
)

// Chrome 120 Windows
transport := presets.Chrome120Windows.NewTransport()
client := &http.Client{Transport: transport}

// 发起请求
resp, err := client.Get("https://httpbin.org/headers")
```

**可用的预设指纹**：
- `Chrome120Windows` - Chrome 120 (Windows 10)
- `Chrome117Windows` - Chrome 117 (Windows 10)  
- `Chrome133Windows` - Chrome 133 (Windows 10)
- `Firefox120Windows` - Firefox 120 (Windows 10)
- `SafariiOS17` - Safari iOS 17 (iPhone)
- `Edge120Windows` - Edge 120 (Windows 10)

### Session 使用

```go
client := &http.Client{
    Transport: &http.Transport{
        JA3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
    },
    Jar: &http.CookieJar{}, // 启用 Cookie 管理
}

// 第一次请求
resp1, _ := client.PostForm("https://example.com/login", url.Values{
    "username": {"user"},
    "password": {"pass"},
})

// 第二次请求 - 自动携带 Cookie
resp2, _ := client.Get("https://example.com/dashboard")
```

## 📚 文档

- 📖 [预设指纹使用指南](docs/PRESETS_GUIDE.md) - 8种预设使用方式详解
- 🔧 [高级配置指南](docs/ADVANCED_USAGE.md) - Session、代理、超时等高级配置
- 🏗️ [架构设计说明](docs/ARCHITECTURE.md) - 技术架构和实现原理
- 📋 [完整示例](examples/presets_usage.go) - 实际使用示例

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

1. Fork 本项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

## 📄 开源协议

本项目采用 **MIT 许可证 + 商业使用限制**。

- ✅ **允许**：个人学习、研究、教育使用
- ❌ **禁止**：商业使用（需联系作者授权）
- 📧 **商业授权**：请通过 [LICENSE](LICENSE) 文件中的联系方式申请

查看 [LICENSE](LICENSE) 文件了解完整条款。

## 🙏 致谢

- [utls](https://github.com/refraction-networking/utls) - TLS 指纹控制的核心库
- [Go net/http](https://golang.org/pkg/net/http/) - 基础 HTTP 客户端实现
- 所有贡献者和用户的支持

---

## ⚠️ 重要说明

1. **许可证限制**: 本项目仅供个人学习和研究使用，商业使用需要联系作者授权
2. **法律合规**: 请遵守相关法律法规，不得用于非法用途
3. **技术支持**: 商业用户如需技术支持，请通过商业授权渠道联系