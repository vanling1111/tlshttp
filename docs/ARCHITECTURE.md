# 架构设计

## 🏗️ 整体架构

tlshttp 基于 Go 标准库的 `net/http` 进行 Fork 和扩展，专注于 TLS 指纹控制功能。

```
┌─────────────────────────────────────────────────────────────┐
│                    tlshttp 架构图                           │
├─────────────────────────────────────────────────────────────┤
│  Application Layer                                          │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │   User Code     │  │  Third-party    │                  │
│  │                 │  │  Frameworks     │                  │
│  └─────────────────┘  └─────────────────┘                  │
│           │                       │                        │
├─────────────────────────────────────────────────────────────┤
│  API Layer                                                   │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │   Client        │  │   Transport     │                  │
│  │                 │  │                 │                  │
│  └─────────────────┘  └─────────────────┘                  │
│           │                       │                        │
├─────────────────────────────────────────────────────────────┤
│  TLS Fingerprint Layer                                       │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │   JA3/JA4       │  │   HTTP/2        │                  │
│  │   Control       │  │   Settings      │                  │
│  └─────────────────┘  └─────────────────┘                  │
│           │                       │                        │
├─────────────────────────────────────────────────────────────┤
│  Core Layer (Forked from net/http)                          │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │   TLS           │  │   HTTP/2        │                  │
│  │   (utls)        │  │   Bundle        │                  │
│  └─────────────────┘  └─────────────────┘                  │
│           │                       │                        │
├─────────────────────────────────────────────────────────────┤
│  Network Layer                                               │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │   TCP           │  │   DNS           │                  │
│  │   Connection    │  │   Resolution    │                  │
│  └─────────────────┘  └─────────────────┘                  │
└─────────────────────────────────────────────────────────────┘
```

## 📦 核心组件

### 1. Transport 层

**文件**: `transport.go`

```go
type Transport struct {
    // 基础配置
    TLSClientConfig    *tls.Config
    TLSFingerprint     *TLSFingerprintConfig
    UserAgent          string
    
    // TLS 指纹配置
    JA3                string
    JA4                string
    ClientHelloHexStream string
    
    // HTTP/2 配置
    HTTP2              *HTTP2Config
    
    // 连接管理
    MaxIdleConns       int
    MaxIdleConnsPerHost int
}
```

**职责**:
- 管理 HTTP 连接池
- 配置 TLS 指纹参数
- 处理 HTTP/2 设置
- 管理请求生命周期

### 2. TLS 指纹控制

**文件**: `transport.go` (TLS 相关方法)

```go
type TLSFingerprintConfig struct {
    JA3                string
    JA4                string
    ClientHelloHexStream string
    TLSConfig          *tls.Config
    TLSExtensions      *TLSExtensionsConfig
    HTTP2              *HTTP2Settings
}
```

**职责**:
- 解析 JA3/JA4 字符串
- 构建 ClientHello 消息
- 配置 TLS 扩展
- 处理 GREASE 值

### 3. HTTP/2 支持

**文件**: `h2_bundle.go`

**职责**:
- HTTP/2 连接管理
- SETTINGS 帧配置
- 流优先级控制
- 多路复用处理

### 4. 预设指纹库

**文件**: `presets/fingerprints.go`

```go
type BrowserFingerprint struct {
    Name      string
    JA3       string
    UserAgent string
    HTTP2     *HTTP2Settings
}
```

**职责**:
- 提供预配置的浏览器指纹
- 管理不同浏览器版本
- 简化用户配置

## 🔄 请求流程

### 1. 连接建立流程

```
用户请求 → Transport.Dial → TLS 握手 → HTTP/2 协商 → 连接就绪
    │           │              │            │
    │           │              │            └─ 配置 HTTP/2 SETTINGS
    │           │              └─ 使用 utls 构建 ClientHello
    │           └─ 创建 TCP 连接
    └─ 解析 URL 和配置
```

### 2. TLS 握手流程

```
ClientHello 构建 → 发送握手 → ServerHello → 证书交换 → 握手完成
       │               │            │           │
       │               │            │           └─ 验证证书
       │               │            └─ 解析服务器响应
       │               └─ 发送自定义 ClientHello
       └─ 根据 JA3/JA4 配置构建
```

### 3. HTTP/2 协商流程

```
ALPN 协商 → HTTP/2 连接 → SETTINGS 交换 → 流创建 → 数据传输
    │           │              │            │
    │           │              │            └─ 创建 HTTP/2 流
    │           │              └─ 发送/接收 SETTINGS 帧
    │           └─ 升级到 HTTP/2 协议
    └─ 协商应用层协议
```

## 🛠️ 技术实现

### 1. utls 集成

tlshttp 使用 `github.com/refraction-networking/utls` 库来构建自定义的 TLS ClientHello 消息。

```go
// 创建自定义 TLS 连接
func (pc *persistConn) createCustomTLSConn(conn net.Conn, config *tls.Config) (*tls.UConn, error) {
    utlsConfig := &tls.Config{
        ServerName:         config.ServerName,
        InsecureSkipVerify: config.InsecureSkipVerify,
        OmitEmptyPsk:       true, // 修复 PSK 问题
    }
    
    uConn := tls.UClient(conn, utlsConfig, tls.HelloCustom)
    
    // 根据 JA3 构建 ClientHello
    spec, err := pc.buildClientHelloFromJA3(pc.t.JA3)
    if err != nil {
        return nil, err
    }
    
    err = uConn.ApplyPreset(spec)
    return uConn, err
}
```

### 2. JA3 解析

```go
func (pc *persistConn) buildClientHelloFromJA3(ja3 string) (*tls.ClientHelloSpec, error) {
    parts := strings.Split(ja3, ",")
    if len(parts) != 5 {
        return nil, fmt.Errorf("无效的 JA3 字符串")
    }
    
    // 解析各个组件
    tlsVersion := parseTLSVersion(parts[0])
    cipherSuites := parseCipherSuites(parts[1])
    extensions := parseExtensions(parts[2])
    curves := parseEllipticCurves(parts[3])
    pointFormats := parsePointFormats(parts[4])
    
    // 构建 ClientHelloSpec
    spec := &tls.ClientHelloSpec{
        TLSVersMin: tlsVersion,
        TLSVersMax: tlsVersion,
        CipherSuites: cipherSuites,
        Extensions: extensions,
        GetSessionID: nil,
    }
    
    return spec, nil
}
```

### 3. HTTP/2 配置

```go
func (t *Transport) configureHTTP2() {
    if t.HTTP2 != nil {
        // 配置 HTTP/2 SETTINGS
        for _, setting := range t.HTTP2.Settings {
            t.H2Transport.Settings = append(t.H2Transport.Settings, http2.Setting{
                ID:  http2.SettingID(setting.ID),
                Val: setting.Val,
            })
        }
        
        // 配置连接流控制
        t.H2Transport.ConnectionFlow = t.HTTP2.ConnectionFlow
        
        // 配置头部优先级
        if t.HTTP2.HeaderPriority != nil {
            t.H2Transport.HeaderPriority = &http2.PriorityParam{
                Weight:    t.HTTP2.HeaderPriority.Weight,
                StreamDep: t.HTTP2.HeaderPriority.StreamDep,
                Exclusive: t.HTTP2.HeaderPriority.Exclusive,
            }
        }
    }
}
```

## 🔧 扩展点

### 1. 自定义指纹解析器

```go
type CustomFingerprintParser interface {
    ParseJA3(ja3 string) (*tls.ClientHelloSpec, error)
    ParseJA4(ja4 string) (*tls.ClientHelloSpec, error)
    ParseHexStream(hexStream string) (*tls.ClientHelloSpec, error)
}
```

### 2. 自定义 HTTP/2 设置

```go
type CustomHTTP2Configurer interface {
    ConfigureSettings(transport *HTTP2Transport) error
    ConfigurePriority(transport *HTTP2Transport) error
}
```

### 3. 自定义连接池管理

```go
type CustomConnectionPool interface {
    GetConnection(host string) (net.Conn, error)
    PutConnection(conn net.Conn) error
    Close() error
}
```

## 📊 性能优化

### 1. 连接复用

- 使用 `persistConn` 管理长连接
- HTTP/2 多路复用减少连接数
- 智能连接池管理

### 2. 内存优化

- 对象池复用 TLS 配置
- 零拷贝字符串处理
- 延迟初始化重型对象

### 3. 并发优化

- 无锁数据结构
- 原子操作更新状态
- 协程池管理

## 🔍 调试和监控

### 1. 内置调试

```go
transport := &http.Transport{
    JA3: "771,4865-4866-4867...",
    // 启用调试模式
    Debug: true,
}
```

### 2. 性能指标

- 连接建立时间
- TLS 握手时间
- HTTP/2 协商时间
- 请求响应时间

### 3. 错误追踪

- 详细的错误信息
- 堆栈跟踪
- 上下文信息

## 📚 相关文档

- [预设指纹使用指南](PRESETS_GUIDE.md)
- [高级配置指南](ADVANCED_USAGE.md)
- [完整 API 文档](API_REFERENCE.md)
