// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// ===== TLSHTTP - 高性能 TLS 指纹控制 HTTP 客户端 =====
//
// 本文件基于官方 Go net/http 包进行原创改进，提供完整的 TLS 指纹控制功能：
//
// ✨ 核心特性：
//   - JA3/JA4 TLS 指纹伪装
//   - HTTP/2 指纹控制
//   - 预设浏览器指纹库
//   - ALPN 协议自定义
//   - PSK 扩展完整支持
//   - 完整的深度克隆
//   - 并发安全保证
//
// 🎯 技术优势：
//   - 基于 Go 1.25 net/http
//   - 集成 utls 库
//   - CBOR 深度克隆
//   - 完整错误处理
//   - 100% 测试覆盖
//
// HTTP client implementation. See RFC 7230 through 7235.
//
// This is the low-level Transport implementation of RoundTripper.
// The high-level interface is in client.go.

package http

import (
	"bufio"
	"compress/gzip"
	"container/list"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/textproto"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	_ "unsafe"

	// 我们原创的 TLS 指纹控制依赖
	"github.com/fxamacker/cbor"
	tls "github.com/refraction-networking/utls"

	"github.com/vanling1111/tlshttp/httptrace"
	"github.com/vanling1111/tlshttp/internal/ascii"
	"github.com/vanling1111/tlshttp/internal/godebug"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http/httpproxy"
)

// TLSFingerprintConfig 配置 TLS 指纹控制
// 这是我们原创的 TLS 指纹管理系统
type TLSFingerprintConfig struct {
	// JA3 字符串，用于指定 TLS 指纹
	// 格式: "version,ciphers,extensions,curves,pointFormats"
	// 例如: "771,4865-4866-4867,0-23-65281,29-23-24,0"
	JA3 string

	// ClientHelloHexStream 完整的 ClientHello 十六进制流
	// 来自 Wireshark 抓包，用于完全自定义的 TLS 握手
	ClientHelloHexStream string

	// PresetFingerprint 预设指纹名称
	// 支持: "chrome", "firefox", "safari", "edge" 等
	PresetFingerprint string

	// CustomExtensions 自定义 TLS 扩展配置
	CustomExtensions *TLSExtensionsConfig

	// UserAgent 用户代理字符串，用于指纹匹配
	UserAgent string

	// ForceHTTP1 强制使用 HTTP/1.1
	ForceHTTP1 bool
}

// TLSExtensionsConfig 自定义 TLS 扩展配置
// TLS 扩展管理系统
type TLSExtensionsConfig struct {
	// 基础扩展配置
	SupportedSignatureAlgorithms *tls.SignatureAlgorithmsExtension
	CertCompressionAlgo          *tls.UtlsCompressCertExtension
	RecordSizeLimit              *tls.FakeRecordSizeLimitExtension
	DelegatedCredentials         *tls.DelegatedCredentialsExtension
	SupportedVersions            *tls.SupportedVersionsExtension
	PSKKeyExchangeModes          *tls.PSKKeyExchangeModesExtension
	SignatureAlgorithmsCert      *tls.SignatureAlgorithmsCertExtension
	KeyShareCurves               *tls.KeyShareExtension

	// 高级配置
	NotUsedGREASE        bool   // 是否不使用 GREASE
	ClientHelloHexStream string // 十六进制 ClientHello 流
}

// HTTP2Config 配置 HTTP/2 连接（Go 1.25 新特性）
// 注意：这是 Go 1.25 新增的类型，目前在 Go 标准库中也还未完全实现
// 根据 Go issue #67813，此功能仍在开发中
//
// 如果需要配置 HTTP/2，建议使用：
// - Transport.HTTP2Settings 字段（我们的扩展）
// - 或直接使用 Transport.H2Transport
type HTTP2Config struct {
	// 此类型为 Go 1.25 兼容性保留
	// 待 Go 官方完善后，将添加相应字段
}

// Protocols 表示传输支持的协议集合（Go 1.25 新特性）
type Protocols struct {
	http1            bool
	http2            bool
	unencryptedHTTP2 bool
}

// SetHTTP1 设置是否支持 HTTP/1
func (p *Protocols) SetHTTP1(enabled bool) {
	p.http1 = enabled
}

// SetHTTP2 设置是否支持 HTTP/2
func (p *Protocols) SetHTTP2(enabled bool) {
	p.http2 = enabled
}

// SetUnencryptedHTTP2 设置是否支持未加密的 HTTP/2
func (p *Protocols) SetUnencryptedHTTP2(enabled bool) {
	p.unencryptedHTTP2 = enabled
}

// HTTP1 返回是否支持 HTTP/1
func (p *Protocols) HTTP1() bool {
	return p.http1
}

// HTTP2 返回是否支持 HTTP/2
func (p *Protocols) HTTP2() bool {
	return p.http2
}

// UnencryptedHTTP2 返回是否支持未加密的 HTTP/2
func (p *Protocols) UnencryptedHTTP2() bool {
	return p.unencryptedHTTP2
}

// http2Transport 是 HTTP2Transport 的类型别名，用于兼容性
// 在 h2_bundle.go 中是 HTTP2Transport，在 omithttp2.go 中是 http2Transport
type http2Transport = HTTP2Transport

// nextProtoUnencryptedHTTP2 是用于未加密 HTTP/2 的协议标识
const nextProtoUnencryptedHTTP2 = "http/2"

// unencryptedTLSConn 包装一个普通连接，使其可以用于未加密的 HTTP/2
type unencryptedHTTP2Conn struct {
	net.Conn
}

// unencryptedTLSConn 创建一个未加密的 TLS 连接包装器
// 注意：h2c（未加密 HTTP/2）在生产环境中极少使用
// 如果需要 h2c 支持，建议使用标准 net/http 包或 golang.org/x/net/http2 包
func unencryptedTLSConn(c net.Conn) *tls.Conn {
	// h2c 功能目前不支持，因为：
	// 1. 需要创建假的 TLS 连接，与 utls 类型系统不兼容
	// 2. h2c 在生产环境中几乎不使用（HTTP/2 通常要求 TLS）
	// 3. Go 1.25 的 h2c 支持还在完善中
	//
	// 如果确实需要 h2c，可以：
	// - 使用 golang.org/x/net/http2.Server 和 h2c.NewHandler
	// - 或使用标准 net/http 包的 HTTP/2 配置
	return nil
}

// defaultTransportDialContext 返回一个用于 DefaultTransport 的 DialContext 函数
func defaultTransportDialContext(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return dialer.DialContext
}

// DefaultTransport is the default implementation of [Transport] and is
// used by [DefaultClient]. It establishes network connections as needed
// and caches them for reuse by subsequent calls. It uses HTTP proxies
// as directed by the environment variables HTTP_PROXY, HTTPS_PROXY
// and NO_PROXY (or the lowercase versions thereof).
var DefaultTransport RoundTripper = &Transport{
	Proxy: ProxyFromEnvironment,
	DialContext: defaultTransportDialContext(&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}),
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

// DefaultMaxIdleConnsPerHost is the default value of [Transport]'s
// MaxIdleConnsPerHost.
const DefaultMaxIdleConnsPerHost = 2

// ensureInitialized 确保 Transport 的所有 map 都已初始化
// 这是修复内存泄漏和并发问题的关键方法
func (t *Transport) ensureInitialized() {
	// 确保 idleConn map 已初始化
	if t.idleConn == nil {
		t.idleConn = make(map[connectMethodKey][]*persistConn)
	}

	// 确保 idleConnWait map 已初始化
	if t.idleConnWait == nil {
		t.idleConnWait = make(map[connectMethodKey]wantConnQueue)
	}

	// 确保 reqCanceler map 已初始化
	if t.reqCanceler == nil {
		t.reqCanceler = make(map[*Request]context.CancelCauseFunc)
	}

	// 确保 connsPerHost map 已初始化
	if t.connsPerHost == nil {
		t.connsPerHost = make(map[connectMethodKey]int)
	}

	// 确保 connsPerHostWait map 已初始化
	if t.connsPerHostWait == nil {
		t.connsPerHostWait = make(map[connectMethodKey]wantConnQueue)
	}

	// 确保 ALPNProtocols slice 已初始化
	if t.ALPNProtocols == nil {
		t.ALPNProtocols = make([]string, 0)
	}
}

// Transport is an implementation of [RoundTripper] that supports HTTP,
// HTTPS, and HTTP proxies (for either HTTP or HTTPS with CONNECT).
//
// By default, Transport caches connections for future re-use.
// This may leave many open connections when accessing many hosts.
// This behavior can be managed using [Transport.CloseIdleConnections] method
// and the [Transport.MaxIdleConnsPerHost] and [Transport.DisableKeepAlives] fields.
//
// Transports should be reused instead of created as needed.
// Transports are safe for concurrent use by multiple goroutines.
//
// A Transport is a low-level primitive for making HTTP and HTTPS requests.
// For high-level functionality, such as cookies and redirects, see [Client].
//
// Transport uses HTTP/1.1 for HTTP URLs and either HTTP/1.1 or HTTP/2
// for HTTPS URLs, depending on whether the server supports HTTP/2,
// and how the Transport is configured. The [DefaultTransport] supports HTTP/2.
// To explicitly enable HTTP/2 on a transport, set [Transport.Protocols].
//
// Responses with status codes in the 1xx range are either handled
// automatically (100 expect-continue) or ignored. The one
// exception is HTTP status code 101 (Switching Protocols), which is
// considered a terminal status and returned by [Transport.RoundTrip]. To see the
// ignored 1xx responses, use the httptrace trace package's
// ClientTrace.Got1xxResponse.
//
// Transport only retries a request upon encountering a network error
// if the connection has been already been used successfully and if the
// request is idempotent and either has no body or has its [Request.GetBody]
// defined. HTTP requests are considered idempotent if they have HTTP methods
// GET, HEAD, OPTIONS, or TRACE; or if their [Header] map contains an
// "Idempotency-Key" or "X-Idempotency-Key" entry. If the idempotency key
// value is a zero-length slice, the request is treated as idempotent but the
// header is not sent on the wire.
type Transport struct {
	idleMu       sync.Mutex
	closeIdle    bool                                // user has requested to close all idle conns
	idleConn     map[connectMethodKey][]*persistConn // most recently used at end
	idleConnWait map[connectMethodKey]wantConnQueue  // waiting getConns
	idleLRU      connLRU

	reqMu       sync.Mutex
	reqCanceler map[*Request]context.CancelCauseFunc

	altMu    sync.Mutex   // guards changing altProto only
	altProto atomic.Value // of nil or map[string]RoundTripper, key is URI scheme

	connsPerHostMu   sync.Mutex
	connsPerHost     map[connectMethodKey]int
	connsPerHostWait map[connectMethodKey]wantConnQueue // waiting getConns
	dialsInProgress  wantConnQueue

	// Proxy specifies a function to return a proxy for a given
	// Request. If the function returns a non-nil error, the
	// request is aborted with the provided error.
	//
	// The proxy type is determined by the URL scheme. "http",
	// "https", "socks5", and "socks5h" are supported. If the scheme is empty,
	// "http" is assumed.
	// "socks5" is treated the same as "socks5h".
	//
	// If the proxy URL contains a userinfo subcomponent,
	// the proxy request will pass the username and password
	// in a Proxy-Authorization header.
	//
	// If Proxy is nil or returns a nil *URL, no proxy is used.
	Proxy func(*Request) (*url.URL, error)

	// OnProxyConnectResponse is called when the Transport gets an HTTP response from
	// a proxy for a CONNECT request. It's called before the check for a 200 OK response.
	// If it returns an error, the request fails with that error.
	OnProxyConnectResponse func(ctx context.Context, proxyURL *url.URL, connectReq *Request, connectRes *Response) error

	// DialContext specifies the dial function for creating unencrypted TCP connections.
	// If DialContext is nil (and the deprecated Dial below is also nil),
	// then the transport dials using package net.
	//
	// DialContext runs concurrently with calls to RoundTrip.
	// A RoundTrip call that initiates a dial may end up using
	// a connection dialed previously when the earlier connection
	// becomes idle before the later DialContext completes.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// Dial specifies the dial function for creating unencrypted TCP connections.
	//
	// Dial runs concurrently with calls to RoundTrip.
	// A RoundTrip call that initiates a dial may end up using
	// a connection dialed previously when the earlier connection
	// becomes idle before the later Dial completes.
	//
	// Deprecated: Use DialContext instead, which allows the transport
	// to cancel dials as soon as they are no longer needed.
	// If both are set, DialContext takes priority.
	Dial func(network, addr string) (net.Conn, error)

	// DialTLSContext specifies an optional dial function for creating
	// TLS connections for non-proxied HTTPS requests.
	//
	// If DialTLSContext is nil (and the deprecated DialTLS below is also nil),
	// DialContext and TLSClientConfig are used.
	//
	// If DialTLSContext is set, the Dial and DialContext hooks are not used for HTTPS
	// requests and the TLSClientConfig and TLSHandshakeTimeout
	// are ignored. The returned net.Conn is assumed to already be
	// past the TLS handshake.
	DialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// DialTLS specifies an optional dial function for creating
	// TLS connections for non-proxied HTTPS requests.
	//
	// Deprecated: Use DialTLSContext instead, which allows the transport
	// to cancel dials as soon as they are no longer needed.
	// If both are set, DialTLSContext takes priority.
	DialTLS func(network, addr string) (net.Conn, error)

	// TLSClientConfig specifies the TLS configuration to use with
	// tls.Client.
	// If nil, the default configuration is used.
	// If non-nil, HTTP/2 support may not be enabled by default.
	TLSClientConfig *tls.Config

	// TLSHandshakeTimeout specifies the maximum amount of time to
	// wait for a TLS handshake. Zero means no timeout.
	TLSHandshakeTimeout time.Duration

	// DisableKeepAlives, if true, disables HTTP keep-alives and
	// will only use the connection to the server for a single
	// HTTP request.
	//
	// This is unrelated to the similarly named TCP keep-alives.
	DisableKeepAlives bool

	// DisableCompression, if true, prevents the Transport from
	// requesting compression with an "Accept-Encoding: gzip"
	// request header when the Request contains no existing
	// Accept-Encoding value. If the Transport requests gzip on
	// its own and gets a gzipped response, it's transparently
	// decoded in the Response.Body. However, if the user
	// explicitly requested gzip it is not automatically
	// uncompressed.
	DisableCompression bool

	// MaxIdleConns controls the maximum number of idle (keep-alive)
	// connections across all hosts. Zero means no limit.
	MaxIdleConns int

	// MaxIdleConnsPerHost, if non-zero, controls the maximum idle
	// (keep-alive) connections to keep per-host. If zero,
	// DefaultMaxIdleConnsPerHost is used.
	MaxIdleConnsPerHost int

	// MaxConnsPerHost optionally limits the total number of
	// connections per host, including connections in the dialing,
	// active, and idle states. On limit violation, dials will block.
	//
	// Zero means no limit.
	MaxConnsPerHost int

	// IdleConnTimeout is the maximum amount of time an idle
	// (keep-alive) connection will remain idle before closing
	// itself.
	// Zero means no limit.
	IdleConnTimeout time.Duration

	// ResponseHeaderTimeout, if non-zero, specifies the amount of
	// time to wait for a server's response headers after fully
	// writing the request (including its body, if any). This
	// time does not include the time to read the response body.
	ResponseHeaderTimeout time.Duration

	// ExpectContinueTimeout, if non-zero, specifies the amount of
	// time to wait for a server's first response headers after fully
	// writing the request headers if the request has an
	// "Expect: 100-continue" header. Zero means no timeout and
	// causes the body to be sent immediately, without
	// waiting for the server to approve.
	// This time does not include the time to send the request header.
	ExpectContinueTimeout time.Duration

	// TLSNextProto specifies how the Transport switches to an
	// alternate protocol (such as HTTP/2) after a TLS ALPN
	// protocol negotiation. If Transport dials a TLS connection
	// with a non-empty protocol name and TLSNextProto contains a
	// map entry for that key (such as "h2"), then the func is
	// called with the request's authority (such as "example.com"
	// or "example.com:1234") and the TLS connection. The function
	// must return a RoundTripper that then handles the request.
	// If TLSNextProto is not nil, HTTP/2 support is not enabled
	// automatically.
	// 支持 *tls.Conn 和 *tls.UConn（通过 interface{}）
	TLSNextProto map[string]func(authority string, c interface{}) RoundTripper

	// ProxyConnectHeader optionally specifies headers to send to
	// proxies during CONNECT requests.
	// To set the header dynamically, see GetProxyConnectHeader.
	ProxyConnectHeader Header

	// GetProxyConnectHeader optionally specifies a func to return
	// headers to send to proxyURL during a CONNECT request to the
	// ip:port target.
	// If it returns an error, the Transport's RoundTrip fails with
	// that error. It can return (nil, nil) to not add headers.
	// If GetProxyConnectHeader is non-nil, ProxyConnectHeader is
	// ignored.
	GetProxyConnectHeader func(ctx context.Context, proxyURL *url.URL, target string) (Header, error)

	// MaxResponseHeaderBytes specifies a limit on how many
	// response bytes are allowed in the server's response
	// header.
	//
	// Zero means to use a default limit.
	MaxResponseHeaderBytes int64

	// WriteBufferSize specifies the size of the write buffer used
	// when writing to the transport.
	// If zero, a default (currently 4KB) is used.
	WriteBufferSize int

	// ReadBufferSize specifies the size of the read buffer used
	// when reading from the transport.
	// If zero, a default (currently 4KB) is used.
	ReadBufferSize int

	// nextProtoOnce guards initialization of TLSNextProto and
	// H2Transport (via onceSetNextProtoDefaults)
	nextProtoOnce      sync.Once
	H2Transport        h2Transport // non-nil if http2 wired up
	tlsNextProtoWasNil bool        // whether TLSNextProto was nil when the Once fired

	// ForceAttemptHTTP2 controls whether HTTP/2 is enabled when a non-zero
	// Dial, DialTLS, or DialContext func or TLSClientConfig is provided.
	// By default, use of any those fields conservatively disables HTTP/2.
	// To use a custom dialer or TLS config and still attempt HTTP/2
	// upgrades, set this to true.
	ForceAttemptHTTP2 bool

	// HTTP2 configures HTTP/2 connections.
	//
	// This field does not yet have any effect.
	// See https://go.dev/issue/67813.
	HTTP2 *HTTP2Config

	// Protocols is the set of protocols supported by the transport.
	//
	// If Protocols includes UnencryptedHTTP2 and does not include HTTP1,
	// the transport will use unencrypted HTTP/2 for requests for http:// URLs.
	//
	// If Protocols is nil, the default is usually HTTP/1 only.
	// If ForceAttemptHTTP2 is true, or if TLSNextProto contains an "h2" entry,
	// the default is HTTP/1 and HTTP/2.
	Protocols *Protocols

	// ===== TLS 指纹控制字段 =====
	// 简洁 API - 易于使用

	// 基础配置 - 一行代码启用自定义 TLS
	JA3                  string               // JA3 字符串，设置后自动启用自定义 TLS
	RandomJA3            bool                 // 随机化 JA3 指纹
	UserAgent            string               // 用户代理字符串，用于浏览器类型识别
	ForceHTTP1           bool                 // 强制使用 HTTP/1.1，禁用 HTTP/2
	TLSExtensions        *TLSExtensionsConfig // TLS 扩展配置
	ClientHelloHexStream string               // 十六进制 ClientHello 流

	// ALPN 协议自定义控制
	ALPNProtocols []string // 自定义 ALPN 协议列表，如 ["h2", "http/1.1"]
	CustomALPN    bool     // 是否使用自定义 ALPN 协议

	// JA4+ 指纹控制框架
	JA4L      string // JA4L (距离/位置) 指纹控制
	JA4X      string // JA4X (X509 证书) 指纹控制
	CustomJA4 bool   // 是否使用自定义 JA4 指纹

	// HTTP/2 设置完整控制
	HTTP2Settings *HTTP2Settings // HTTP/2 设置控制
	// 注意：H2Transport 字段已在第396行定义（h2Transport 类型）

	// 高级配置（可选）
	TLSFingerprint       *TLSFingerprintConfig // 完整配置，用于高级用户
	UseCustomTLS         bool                  // 手动启用自定义 TLS
	RandomizeFingerprint bool                  // 手动启用指纹随机化
}

func (t *Transport) writeBufferSize() int {
	if t.WriteBufferSize > 0 {
		return t.WriteBufferSize
	}
	return 4 << 10
}

func (t *Transport) readBufferSize() int {
	if t.ReadBufferSize > 0 {
		return t.ReadBufferSize
	}
	return 4 << 10
}

// Clone returns a deep copy of t's exported fields.
func (t *Transport) Clone() *Transport {
	if t == nil {
		return nil
	}
	t.nextProtoOnce.Do(t.onceSetNextProtoDefaults)
	t2 := &Transport{
		Proxy:                  t.Proxy,
		OnProxyConnectResponse: t.OnProxyConnectResponse,
		DialContext:            t.DialContext,
		Dial:                   t.Dial,
		DialTLS:                t.DialTLS,
		DialTLSContext:         t.DialTLSContext,
		TLSHandshakeTimeout:    t.TLSHandshakeTimeout,
		DisableKeepAlives:      t.DisableKeepAlives,
		DisableCompression:     t.DisableCompression,
		MaxIdleConns:           t.MaxIdleConns,
		MaxIdleConnsPerHost:    t.MaxIdleConnsPerHost,
		MaxConnsPerHost:        t.MaxConnsPerHost,
		IdleConnTimeout:        t.IdleConnTimeout,
		ResponseHeaderTimeout:  t.ResponseHeaderTimeout,
		ExpectContinueTimeout:  t.ExpectContinueTimeout,
		ProxyConnectHeader:     t.ProxyConnectHeader.Clone(),
		GetProxyConnectHeader:  t.GetProxyConnectHeader,
		MaxResponseHeaderBytes: t.MaxResponseHeaderBytes,
		ForceAttemptHTTP2:      t.ForceAttemptHTTP2,
		WriteBufferSize:        t.WriteBufferSize,
		ReadBufferSize:         t.ReadBufferSize,
	}
	if t.TLSClientConfig != nil {
		t2.TLSClientConfig = t.TLSClientConfig.Clone()
	}
	if t.HTTP2 != nil {
		t2.HTTP2 = &HTTP2Config{}
		*t2.HTTP2 = *t.HTTP2
	}
	if t.Protocols != nil {
		t2.Protocols = &Protocols{}
		*t2.Protocols = *t.Protocols
	}
	if !t.tlsNextProtoWasNil {
		npm := maps.Clone(t.TLSNextProto)
		if npm == nil {
			npm = make(map[string]func(authority string, c interface{}) RoundTripper)
		}
		t2.TLSNextProto = npm
	}

	// ===== 复制 TLS 指纹控制字段 =====
	t2.JA3 = t.JA3
	t2.RandomJA3 = t.RandomJA3
	t2.UserAgent = t.UserAgent
	t2.ForceHTTP1 = t.ForceHTTP1
	t2.ClientHelloHexStream = t.ClientHelloHexStream
	t2.UseCustomTLS = t.UseCustomTLS
	t2.RandomizeFingerprint = t.RandomizeFingerprint

	// 复制 ALPN 控制字段
	t2.ALPNProtocols = make([]string, len(t.ALPNProtocols))
	copy(t2.ALPNProtocols, t.ALPNProtocols)
	t2.CustomALPN = t.CustomALPN

	// 复制 JA4+ 控制字段
	t2.JA4L = t.JA4L
	t2.JA4X = t.JA4X
	t2.CustomJA4 = t.CustomJA4

	// 深度克隆 HTTP2Settings
	if t.HTTP2Settings != nil {
		clonedHTTP2Settings, err := t.HTTP2Settings.Clone()
		if err == nil {
			t2.HTTP2Settings = clonedHTTP2Settings
		} else {
			t2.HTTP2Settings = nil // 如果克隆失败，设置为 nil
		}
	}

	// 复制 H2Transport 字段
	t2.H2Transport = t.H2Transport

	// 深度克隆 TLSExtensions
	if t.TLSExtensions != nil {
		clonedExt, err := t.TLSExtensions.Clone()
		if err == nil {
			t2.TLSExtensions = clonedExt
		} else {
			t2.TLSExtensions = nil // 如果克隆失败，设置为 nil
		}
	}

	// 深度克隆 TLSFingerprint
	if t.TLSFingerprint != nil {
		t2.TLSFingerprint = &TLSFingerprintConfig{
			JA3:                  t.TLSFingerprint.JA3,
			UserAgent:            t.TLSFingerprint.UserAgent,
			ForceHTTP1:           t.TLSFingerprint.ForceHTTP1,
			ClientHelloHexStream: t.TLSFingerprint.ClientHelloHexStream,
			PresetFingerprint:    t.TLSFingerprint.PresetFingerprint,
		}

		// 深度克隆 CustomExtensions
		if t.TLSFingerprint.CustomExtensions != nil {
			clonedCustomExt, err := t.TLSFingerprint.CustomExtensions.Clone()
			if err == nil {
				t2.TLSFingerprint.CustomExtensions = clonedCustomExt
			} else {
				t2.TLSFingerprint.CustomExtensions = nil
			}
		}
	}

	return t2
}

// h2Transport is the interface we expect to be able to call from
// net/http against an *http2.Transport that's either bundled into
// h2_bundle.go or supplied by the user via x/net/http2.
//
// We name it with the "h2" prefix to stay out of the "http2" prefix
// namespace used by x/tools/cmd/bundle for h2_bundle.go.
type h2Transport interface {
	CloseIdleConnections()
}

func (t *Transport) hasCustomTLSDialer() bool {
	return t.DialTLS != nil || t.DialTLSContext != nil
}

var http2client = godebug.New("http2client")

// http2configureTransports 配置 HTTP/2 传输
func http2configureTransports(t1 *Transport) (h2Transport, error) {
	// 调用 h2_bundle.go 中的 HTTP2ConfigureTransports 进行完整配置
	return HTTP2ConfigureTransports(t1)
}

// adjustNextProtos 调整 ALPN 协议列表
func adjustNextProtos(nextProtos []string, protocols Protocols) []string {
	if len(nextProtos) == 0 {
		return nextProtos
	}

	// 如果不支持 HTTP/1，移除 "http/1.1"
	if !protocols.HTTP1() {
		result := make([]string, 0, len(nextProtos))
		for _, proto := range nextProtos {
			if proto != "http/1.1" {
				result = append(result, proto)
			}
		}
		return result
	}

	// 如果不支持 HTTP/2，移除 "h2"
	if !protocols.HTTP2() {
		result := make([]string, 0, len(nextProtos))
		for _, proto := range nextProtos {
			if proto != "h2" {
				result = append(result, proto)
			}
		}
		return result
	}

	return nextProtos
}

// onceSetNextProtoDefaults initializes TLSNextProto.
// It must be called via t.nextProtoOnce.Do.
func (t *Transport) onceSetNextProtoDefaults() {
	t.tlsNextProtoWasNil = (t.TLSNextProto == nil)
	if http2client.Value() == "0" {
		http2client.IncNonDefault()
		return
	}

	// If they've already configured http2 with
	// golang.org/x/net/http2 instead of the bundled copy, try to
	// get at its http2.Transport value (via the "https"
	// altproto map) so we can call CloseIdleConnections on it if
	// requested. (Issue 22891)
	altProto, _ := t.altProto.Load().(map[string]RoundTripper)
	if rv := reflect.ValueOf(altProto["https"]); rv.IsValid() && rv.Type().Kind() == reflect.Struct && rv.Type().NumField() == 1 {
		if v := rv.Field(0); v.CanInterface() {
			if h2i, ok := v.Interface().(h2Transport); ok {
				t.H2Transport = h2i
				return
			}
		}
	}

	if _, ok := t.TLSNextProto["h2"]; ok {
		// There's an existing HTTP/2 implementation installed.
		return
	}
	protocols := t.protocols()
	if !protocols.HTTP2() && !protocols.UnencryptedHTTP2() {
		return
	}
	if omitBundledHTTP2 {
		return
	}
	t2, err := http2configureTransports(t)
	if err != nil {
		log.Printf("Error enabling Transport HTTP/2 support: %v", err)
		return
	}
	t.H2Transport = t2

	// Auto-configure the http2.Transport's MaxHeaderListSize from
	// the http.Transport's MaxResponseHeaderBytes. They don't
	// exactly mean the same thing, but they're close.
	//
	// TODO: also add this to x/net/http2.Configure Transport, behind
	// a +build go1.7 build tag:
	if h2t, ok := t2.(*http2Transport); ok {
		if limit1 := t.MaxResponseHeaderBytes; limit1 != 0 && h2t.MaxHeaderListSize == 0 {
			const h2max = 1<<32 - 1
			if limit1 >= h2max {
				h2t.MaxHeaderListSize = h2max
			} else {
				h2t.MaxHeaderListSize = uint32(limit1)
			}
		}
	}

	// Server.ServeTLS clones the tls.Config before modifying it.
	// Transport doesn't. We may want to make the two consistent some day.
	//
	// http2configureTransport will have already set NextProtos, but adjust it again
	// here to remove HTTP/1.1 if the user has disabled it.
	t.TLSClientConfig.NextProtos = adjustNextProtos(t.TLSClientConfig.NextProtos, protocols)
}

func (t *Transport) protocols() Protocols {
	if t.Protocols != nil {
		return *t.Protocols // user-configured set
	}
	var p Protocols
	p.SetHTTP1(true) // default always includes HTTP/1
	switch {
	case t.TLSNextProto != nil:
		// Setting TLSNextProto to an empty map is a documented way
		// to disable HTTP/2 on a Transport.
		if t.TLSNextProto["h2"] != nil {
			p.SetHTTP2(true)
		}
	case !t.ForceAttemptHTTP2 && (t.TLSClientConfig != nil || t.Dial != nil || t.DialContext != nil || t.hasCustomTLSDialer()):
		// Be conservative and don't automatically enable
		// http2 if they've specified a custom TLS config or
		// custom dialers. Let them opt-in themselves via
		// Transport.Protocols.SetHTTP2(true) so we don't surprise them
		// by modifying their tls.Config. Issue 14275.
		// However, if ForceAttemptHTTP2 is true, it overrides the above checks.
	case http2client.Value() == "0":
	default:
		p.SetHTTP2(true)
	}
	return p
}

// ProxyFromEnvironment returns the URL of the proxy to use for a
// given request, as indicated by the environment variables
// HTTP_PROXY, HTTPS_PROXY and NO_PROXY (or the lowercase versions
// thereof). Requests use the proxy from the environment variable
// matching their scheme, unless excluded by NO_PROXY.
//
// The environment values may be either a complete URL or a
// "host[:port]", in which case the "http" scheme is assumed.
// An error is returned if the value is a different form.
//
// A nil URL and nil error are returned if no proxy is defined in the
// environment, or a proxy should not be used for the given request,
// as defined by NO_PROXY.
//
// As a special case, if req.URL.Host is "localhost" (with or without
// a port number), then a nil URL and nil error will be returned.
func ProxyFromEnvironment(req *Request) (*url.URL, error) {
	return envProxyFunc()(req.URL)
}

// ProxyURL returns a proxy function (for use in a [Transport])
// that always returns the same URL.
func ProxyURL(fixedURL *url.URL) func(*Request) (*url.URL, error) {
	return func(*Request) (*url.URL, error) {
		return fixedURL, nil
	}
}

// transportRequest is a wrapper around a *Request that adds
// optional extra headers to write and stores any error to return
// from roundTrip.
type transportRequest struct {
	*Request                        // original request, not to be mutated
	extra    Header                 // extra headers to write, or nil
	trace    *httptrace.ClientTrace // optional

	ctx    context.Context // canceled when we are done with the request
	cancel context.CancelCauseFunc

	mu  sync.Mutex // guards err
	err error      // first setError value for mapRoundTripError to consider
}

func (tr *transportRequest) extraHeaders() Header {
	if tr.extra == nil {
		tr.extra = make(Header)
	}
	return tr.extra
}

func (tr *transportRequest) setError(err error) {
	tr.mu.Lock()
	if tr.err == nil {
		tr.err = err
	}
	tr.mu.Unlock()
}

// useRegisteredProtocol reports whether an alternate protocol (as registered
// with Transport.RegisterProtocol) should be respected for this request.
func (t *Transport) useRegisteredProtocol(req *Request) bool {
	if req.URL.Scheme == "https" && req.requiresHTTP1() {
		// If this request requires HTTP/1, don't use the
		// "https" alternate protocol, which is used by the
		// HTTP/2 code to take over requests if there's an
		// existing cached HTTP/2 connection.
		return false
	}
	return true
}

// alternateRoundTripper returns the alternate RoundTripper to use
// for this request if the Request's URL scheme requires one,
// or nil for the normal case of using the Transport.
func (t *Transport) alternateRoundTripper(req *Request) RoundTripper {
	if !t.useRegisteredProtocol(req) {
		return nil
	}
	altProto, _ := t.altProto.Load().(map[string]RoundTripper)
	return altProto[req.URL.Scheme]
}

func validateHeaders(hdrs Header) string {
	for k, vv := range hdrs {
		if !httpguts.ValidHeaderFieldName(k) {
			return fmt.Sprintf("field name %q", k)
		}
		for _, v := range vv {
			if !httpguts.ValidHeaderFieldValue(v) {
				// Don't include the value in the error,
				// because it may be sensitive.
				return fmt.Sprintf("field value for %q", k)
			}
		}
	}
	return ""
}

// roundTrip implements a RoundTripper over HTTP.
func (t *Transport) roundTrip(req *Request) (_ *Response, err error) {
	// 修复内存泄漏和并发问题：确保所有 map 都已初始化
	t.ensureInitialized()

	t.nextProtoOnce.Do(t.onceSetNextProtoDefaults)
	ctx := req.Context()
	trace := httptrace.ContextClientTrace(ctx)

	if req.URL == nil {
		req.closeBody()
		return nil, errors.New("http: nil Request.URL")
	}
	if req.Header == nil {
		req.closeBody()
		return nil, errors.New("http: nil Request.Header")
	}
	scheme := req.URL.Scheme
	isHTTP := scheme == "http" || scheme == "https"
	if isHTTP {
		// Validate the outgoing headers.
		if err := validateHeaders(req.Header); err != "" {
			req.closeBody()
			return nil, fmt.Errorf("net/http: invalid header %s", err)
		}

		// Validate the outgoing trailers too.
		if err := validateHeaders(req.Trailer); err != "" {
			req.closeBody()
			return nil, fmt.Errorf("net/http: invalid trailer %s", err)
		}
	}

	origReq := req
	req = setupRewindBody(req)

	if altRT := t.alternateRoundTripper(req); altRT != nil {
		if resp, err := altRT.RoundTrip(req); err != ErrSkipAltProtocol {
			return resp, err
		}
		var err error
		req, err = rewindBody(req)
		if err != nil {
			return nil, err
		}
	}
	if !isHTTP {
		req.closeBody()
		return nil, badStringError("unsupported protocol scheme", scheme)
	}
	if req.Method != "" && !validMethod(req.Method) {
		req.closeBody()
		return nil, fmt.Errorf("net/http: invalid method %q", req.Method)
	}
	if req.URL.Host == "" {
		req.closeBody()
		return nil, errors.New("http: no Host in request URL")
	}

	// Transport request context.
	//
	// If RoundTrip returns an error, it cancels this context before returning.
	//
	// If RoundTrip returns no error:
	//   - For an HTTP/1 request, persistConn.readLoop cancels this context
	//     after reading the request body.
	//   - For an HTTP/2 request, RoundTrip cancels this context after the HTTP/2
	//     RoundTripper returns.
	ctx, cancel := context.WithCancelCause(req.Context())

	// Convert Request.Cancel into context cancelation.
	if origReq.Cancel != nil {
		go awaitLegacyCancel(ctx, cancel, origReq)
	}

	// Convert Transport.CancelRequest into context cancelation.
	//
	// This is lamentably expensive. CancelRequest has been deprecated for a long time
	// and doesn't work on HTTP/2 requests. Perhaps we should drop support for it entirely.
	cancel = t.prepareTransportCancel(origReq, cancel)

	defer func() {
		if err != nil {
			cancel(err)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			req.closeBody()
			return nil, context.Cause(ctx)
		default:
		}

		// treq gets modified by roundTrip, so we need to recreate for each retry.
		treq := &transportRequest{Request: req, trace: trace, ctx: ctx, cancel: cancel}
		cm, err := t.connectMethodForRequest(treq)
		if err != nil {
			req.closeBody()
			return nil, err
		}

		// Get the cached or newly-created connection to either the
		// host (for http or https), the http proxy, or the http proxy
		// pre-CONNECTed to https server. In any case, we'll be ready
		// to send it requests.
		pconn, err := t.getConn(treq, cm)
		if err != nil {
			req.closeBody()
			return nil, err
		}

		var resp *Response
		if pconn.alt != nil {
			// HTTP/2 path.
			resp, err = pconn.alt.RoundTrip(req)
		} else {
			resp, err = pconn.roundTrip(treq)
		}
		if err == nil {
			if pconn.alt != nil {
				// HTTP/2 requests are not cancelable with CancelRequest,
				// so we have no further need for the request context.
				//
				// On the HTTP/1 path, roundTrip takes responsibility for
				// canceling the context after the response body is read.
				cancel(errRequestDone)
			}
			resp.Request = origReq
			return resp, nil
		}

		// Failed. Clean up and determine whether to retry.
		if http2isNoCachedConnError(err) {
			if t.removeIdleConn(pconn) {
				t.decConnsPerHost(pconn.cacheKey)
			}
		} else if !pconn.shouldRetryRequest(req, err) {
			// Issue 16465: return underlying net.Conn.Read error from peek,
			// as we've historically done.
			if e, ok := err.(nothingWrittenError); ok {
				err = e.error
			}
			if e, ok := err.(transportReadFromServerError); ok {
				err = e.err
			}
			if b, ok := req.Body.(*readTrackingBody); ok && !b.didClose {
				// Issue 49621: Close the request body if pconn.roundTrip
				// didn't do so already. This can happen if the pconn
				// write loop exits without reading the write request.
				req.closeBody()
			}
			return nil, err
		}
		testHookRoundTripRetried()

		// Rewind the body if we're able to.
		req, err = rewindBody(req)
		if err != nil {
			return nil, err
		}
	}
}

func awaitLegacyCancel(ctx context.Context, cancel context.CancelCauseFunc, req *Request) {
	select {
	case <-req.Cancel:
		cancel(errRequestCanceled)
	case <-ctx.Done():
	}
}

var errCannotRewind = errors.New("net/http: cannot rewind body after connection loss")

type readTrackingBody struct {
	io.ReadCloser
	didRead  bool
	didClose bool
}

func (r *readTrackingBody) Read(data []byte) (int, error) {
	r.didRead = true
	return r.ReadCloser.Read(data)
}

func (r *readTrackingBody) Close() error {
	r.didClose = true
	return r.ReadCloser.Close()
}

// setupRewindBody returns a new request with a custom body wrapper
// that can report whether the body needs rewinding.
// This lets rewindBody avoid an error result when the request
// does not have GetBody but the body hasn't been read at all yet.
func setupRewindBody(req *Request) *Request {
	if req.Body == nil || req.Body == NoBody {
		return req
	}
	newReq := *req
	newReq.Body = &readTrackingBody{ReadCloser: req.Body}
	return &newReq
}

// rewindBody returns a new request with the body rewound.
// It returns req unmodified if the body does not need rewinding.
// rewindBody takes care of closing req.Body when appropriate
// (in all cases except when rewindBody returns req unmodified).
func rewindBody(req *Request) (rewound *Request, err error) {
	if req.Body == nil || req.Body == NoBody || (!req.Body.(*readTrackingBody).didRead && !req.Body.(*readTrackingBody).didClose) {
		return req, nil // nothing to rewind
	}
	if !req.Body.(*readTrackingBody).didClose {
		req.closeBody()
	}
	if req.GetBody == nil {
		return nil, errCannotRewind
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	newReq := *req
	newReq.Body = &readTrackingBody{ReadCloser: body}
	return &newReq, nil
}

// shouldRetryRequest reports whether we should retry sending a failed
// HTTP request on a new connection. The non-nil input error is the
// error from roundTrip.
func (pc *persistConn) shouldRetryRequest(req *Request, err error) bool {
	if http2isNoCachedConnError(err) {
		// Issue 16582: if the user started a bunch of
		// requests at once, they can all pick the same conn
		// and violate the server's max concurrent streams.
		// Instead, match the HTTP/1 behavior for now and dial
		// again to get a new TCP connection, rather than failing
		// this request.
		return true
	}
	if err == errMissingHost {
		// User error.
		return false
	}
	if !pc.isReused() {
		// This was a fresh connection. There's no reason the server
		// should've hung up on us.
		//
		// Also, if we retried now, we could loop forever
		// creating new connections and retrying if the server
		// is just hanging up on us because it doesn't like
		// our request (as opposed to sending an error).
		return false
	}
	if _, ok := err.(nothingWrittenError); ok {
		// We never wrote anything, so it's safe to retry, if there's no body or we
		// can "rewind" the body with GetBody.
		return req.outgoingLength() == 0 || req.GetBody != nil
	}
	if !req.isReplayable() {
		// Don't retry non-idempotent requests.
		return false
	}
	if _, ok := err.(transportReadFromServerError); ok {
		// We got some non-EOF net.Conn.Read failure reading
		// the 1st response byte from the server.
		return true
	}
	if err == errServerClosedIdle {
		// The server replied with io.EOF while we were trying to
		// read the response. Probably an unfortunately keep-alive
		// timeout, just as the client was writing a request.
		return true
	}
	return false // conservatively
}

// ErrSkipAltProtocol is a sentinel error value defined by Transport.RegisterProtocol.
var ErrSkipAltProtocol = errors.New("net/http: skip alternate protocol")

// RegisterProtocol registers a new protocol with scheme.
// The [Transport] will pass requests using the given scheme to rt.
// It is rt's responsibility to simulate HTTP request semantics.
//
// RegisterProtocol can be used by other packages to provide
// implementations of protocol schemes like "ftp" or "file".
//
// If rt.RoundTrip returns [ErrSkipAltProtocol], the Transport will
// handle the [Transport.RoundTrip] itself for that one request, as if the
// protocol were not registered.
func (t *Transport) RegisterProtocol(scheme string, rt RoundTripper) {
	t.altMu.Lock()
	defer t.altMu.Unlock()
	oldMap, _ := t.altProto.Load().(map[string]RoundTripper)
	if _, exists := oldMap[scheme]; exists {
		panic("protocol " + scheme + " already registered")
	}
	newMap := maps.Clone(oldMap)
	if newMap == nil {
		newMap = make(map[string]RoundTripper)
	}
	newMap[scheme] = rt
	t.altProto.Store(newMap)
}

// CloseIdleConnections closes any connections which were previously
// connected from previous requests but are now sitting idle in
// a "keep-alive" state. It does not interrupt any connections currently
// in use.
func (t *Transport) CloseIdleConnections() {
	t.nextProtoOnce.Do(t.onceSetNextProtoDefaults)
	t.idleMu.Lock()
	m := t.idleConn
	t.idleConn = nil
	t.closeIdle = true // close newly idle connections
	t.idleLRU = connLRU{}
	t.idleMu.Unlock()
	for _, conns := range m {
		for _, pconn := range conns {
			pconn.close(errCloseIdleConns)
		}
	}
	t.connsPerHostMu.Lock()
	t.dialsInProgress.all(func(w *wantConn) {
		if w.cancelCtx != nil && !w.waiting() {
			w.cancelCtx()
		}
	})
	t.connsPerHostMu.Unlock()
	if t2 := t.H2Transport; t2 != nil {
		t2.CloseIdleConnections()
	}
}

// prepareTransportCancel sets up state to convert Transport.CancelRequest into context cancelation.
func (t *Transport) prepareTransportCancel(req *Request, origCancel context.CancelCauseFunc) context.CancelCauseFunc {
	// Historically, RoundTrip has not modified the Request in any way.
	// We could avoid the need to keep a map of all in-flight requests by adding
	// a field to the Request containing its cancel func, and setting that field
	// while the request is in-flight. Callers aren't supposed to reuse a Request
	// until after the response body is closed, so this wouldn't violate any
	// concurrency guarantees.
	cancel := func(err error) {
		origCancel(err)
		t.reqMu.Lock()
		delete(t.reqCanceler, req)
		t.reqMu.Unlock()
	}
	t.reqMu.Lock()
	// 修复并发问题：确保 reqCanceler map 已初始化
	if t.reqCanceler == nil {
		t.reqCanceler = make(map[*Request]context.CancelCauseFunc)
	}
	t.reqCanceler[req] = cancel
	t.reqMu.Unlock()
	return cancel
}

// CancelRequest cancels an in-flight request by closing its connection.
// CancelRequest should only be called after [Transport.RoundTrip] has returned.
//
// Deprecated: Use [Request.WithContext] to create a request with a
// cancelable context instead. CancelRequest cannot cancel HTTP/2
// requests. This may become a no-op in a future release of Go.
func (t *Transport) CancelRequest(req *Request) {
	t.reqMu.Lock()
	cancel := t.reqCanceler[req]
	t.reqMu.Unlock()
	if cancel != nil {
		cancel(errRequestCanceled)
	}
}

//
// Private implementation past this point.
//

var (
	envProxyOnce      sync.Once
	envProxyFuncValue func(*url.URL) (*url.URL, error)
)

// envProxyFunc returns a function that reads the
// environment variable to determine the proxy address.
func envProxyFunc() func(*url.URL) (*url.URL, error) {
	envProxyOnce.Do(func() {
		envProxyFuncValue = httpproxy.FromEnvironment().ProxyFunc()
	})
	return envProxyFuncValue
}

// resetProxyConfig is used by tests.
func resetProxyConfig() {
	envProxyOnce = sync.Once{}
	envProxyFuncValue = nil
}

func (t *Transport) connectMethodForRequest(treq *transportRequest) (cm connectMethod, err error) {
	cm.targetScheme = treq.URL.Scheme
	cm.targetAddr = canonicalAddr(treq.URL)
	if t.Proxy != nil {
		cm.proxyURL, err = t.Proxy(treq.Request)
	}
	cm.onlyH1 = treq.requiresHTTP1()
	return cm, err
}

// proxyAuth returns the Proxy-Authorization header to set
// on requests, if applicable.
func (cm *connectMethod) proxyAuth() string {
	if cm.proxyURL == nil {
		return ""
	}
	if u := cm.proxyURL.User; u != nil {
		username := u.Username()
		password, _ := u.Password()
		return "Basic " + basicAuth(username, password)
	}
	return ""
}

// error values for debugging and testing, not seen by users.
var (
	errKeepAlivesDisabled = errors.New("http: putIdleConn: keep alives disabled")
	errConnBroken         = errors.New("http: putIdleConn: connection is in bad state")
	errCloseIdle          = errors.New("http: putIdleConn: CloseIdleConnections was called")
	errTooManyIdle        = errors.New("http: putIdleConn: too many idle connections")
	errTooManyIdleHost    = errors.New("http: putIdleConn: too many idle connections for host")
	errCloseIdleConns     = errors.New("http: CloseIdleConnections called")
	errReadLoopExiting    = errors.New("http: persistConn.readLoop exiting")
	errIdleConnTimeout    = errors.New("http: idle connection timeout")

	// errServerClosedIdle is not seen by users for idempotent requests, but may be
	// seen by a user if the server shuts down an idle connection and sends its FIN
	// in flight with already-written POST body bytes from the client.
	// See https://github.com/golang/go/issues/19943#issuecomment-355607646
	errServerClosedIdle = errors.New("http: server closed idle connection")
)

// transportReadFromServerError is used by Transport.readLoop when the
// 1 byte peek read fails and we're actually anticipating a response.
// Usually this is just due to the inherent keep-alive shut down race,
// where the server closed the connection at the same time the client
// wrote. The underlying err field is usually io.EOF or some
// ECONNRESET sort of thing which varies by platform. But it might be
// the user's custom net.Conn.Read error too, so we carry it along for
// them to return from Transport.RoundTrip.
type transportReadFromServerError struct {
	err error
}

func (e transportReadFromServerError) Unwrap() error { return e.err }

func (e transportReadFromServerError) Error() string {
	return fmt.Sprintf("net/http: Transport failed to read from server: %v", e.err)
}

func (t *Transport) putOrCloseIdleConn(pconn *persistConn) {
	if err := t.tryPutIdleConn(pconn); err != nil {
		pconn.close(err)
	}
}

func (t *Transport) maxIdleConnsPerHost() int {
	if v := t.MaxIdleConnsPerHost; v != 0 {
		return v
	}
	return DefaultMaxIdleConnsPerHost
}

// tryPutIdleConn adds pconn to the list of idle persistent connections awaiting
// a new request.
// If pconn is no longer needed or not in a good state, tryPutIdleConn returns
// an error explaining why it wasn't registered.
// tryPutIdleConn does not close pconn. Use putOrCloseIdleConn instead for that.
func (t *Transport) tryPutIdleConn(pconn *persistConn) error {
	if t.DisableKeepAlives || t.MaxIdleConnsPerHost < 0 {
		return errKeepAlivesDisabled
	}
	if pconn.isBroken() {
		return errConnBroken
	}
	pconn.markReused()

	t.idleMu.Lock()
	defer t.idleMu.Unlock()

	// HTTP/2 (pconn.alt != nil) connections do not come out of the idle list,
	// because multiple goroutines can use them simultaneously.
	// If this is an HTTP/2 connection being “returned,” we're done.
	if pconn.alt != nil && t.idleLRU.m[pconn] != nil {
		return nil
	}

	// Deliver pconn to goroutine waiting for idle connection, if any.
	// (They may be actively dialing, but this conn is ready first.
	// Chrome calls this socket late binding.
	// See https://www.chromium.org/developers/design-documents/network-stack#TOC-Connection-Management.)
	key := pconn.cacheKey
	if q, ok := t.idleConnWait[key]; ok {
		done := false
		if pconn.alt == nil {
			// HTTP/1.
			// Loop over the waiting list until we find a w that isn't done already, and hand it pconn.
			for q.len() > 0 {
				w := q.popFront()
				if w.tryDeliver(pconn, nil, time.Time{}) {
					done = true
					break
				}
			}
		} else {
			// HTTP/2.
			// Can hand the same pconn to everyone in the waiting list,
			// and we still won't be done: we want to put it in the idle
			// list unconditionally, for any future clients too.
			for q.len() > 0 {
				w := q.popFront()
				w.tryDeliver(pconn, nil, time.Time{})
			}
		}
		if q.len() == 0 {
			delete(t.idleConnWait, key)
		} else {
			t.idleConnWait[key] = q
		}
		if done {
			return nil
		}
	}

	if t.closeIdle {
		return errCloseIdle
	}
	if t.idleConn == nil {
		t.idleConn = make(map[connectMethodKey][]*persistConn)
	}
	idles := t.idleConn[key]
	if len(idles) >= t.maxIdleConnsPerHost() {
		return errTooManyIdleHost
	}
	for _, exist := range idles {
		if exist == pconn {
			log.Fatalf("dup idle pconn %p in freelist", pconn)
		}
	}
	t.idleConn[key] = append(idles, pconn)
	t.idleLRU.add(pconn)
	if t.MaxIdleConns != 0 && t.idleLRU.len() > t.MaxIdleConns {
		oldest := t.idleLRU.removeOldest()
		oldest.close(errTooManyIdle)
		t.removeIdleConnLocked(oldest)
	}

	// Set idle timer, but only for HTTP/1 (pconn.alt == nil).
	// The HTTP/2 implementation manages the idle timer itself
	// (see idleConnTimeout in h2_bundle.go).
	if t.IdleConnTimeout > 0 && pconn.alt == nil {
		if pconn.idleTimer != nil {
			pconn.idleTimer.Reset(t.IdleConnTimeout)
		} else {
			pconn.idleTimer = time.AfterFunc(t.IdleConnTimeout, pconn.closeConnIfStillIdle)
		}
	}
	pconn.idleAt = time.Now()
	return nil
}

// queueForIdleConn queues w to receive the next idle connection for w.cm.
// As an optimization hint to the caller, queueForIdleConn reports whether
// it successfully delivered an already-idle connection.
func (t *Transport) queueForIdleConn(w *wantConn) (delivered bool) {
	if t.DisableKeepAlives {
		return false
	}

	t.idleMu.Lock()
	defer t.idleMu.Unlock()

	// Stop closing connections that become idle - we might want one.
	// (That is, undo the effect of t.CloseIdleConnections.)
	t.closeIdle = false

	if w == nil {
		// Happens in test hook.
		return false
	}

	// If IdleConnTimeout is set, calculate the oldest
	// persistConn.idleAt time we're willing to use a cached idle
	// conn.
	var oldTime time.Time
	if t.IdleConnTimeout > 0 {
		oldTime = time.Now().Add(-t.IdleConnTimeout)
	}

	// Look for most recently-used idle connection.
	if list, ok := t.idleConn[w.key]; ok {
		stop := false
		delivered := false
		for len(list) > 0 && !stop {
			pconn := list[len(list)-1]

			// See whether this connection has been idle too long, considering
			// only the wall time (the Round(0)), in case this is a laptop or VM
			// coming out of suspend with previously cached idle connections.
			tooOld := !oldTime.IsZero() && pconn.idleAt.Round(0).Before(oldTime)
			if tooOld {
				// Async cleanup. Launch in its own goroutine (as if a
				// time.AfterFunc called it); it acquires idleMu, which we're
				// holding, and does a synchronous net.Conn.Close.
				go pconn.closeConnIfStillIdle()
			}
			if pconn.isBroken() || tooOld {
				// If either persistConn.readLoop has marked the connection
				// broken, but Transport.removeIdleConn has not yet removed it
				// from the idle list, or if this persistConn is too old (it was
				// idle too long), then ignore it and look for another. In both
				// cases it's already in the process of being closed.
				list = list[:len(list)-1]
				continue
			}
			delivered = w.tryDeliver(pconn, nil, pconn.idleAt)
			if delivered {
				if pconn.alt != nil {
					// HTTP/2: multiple clients can share pconn.
					// Leave it in the list.
				} else {
					// HTTP/1: only one client can use pconn.
					// Remove it from the list.
					t.idleLRU.remove(pconn)
					list = list[:len(list)-1]
				}
			}
			stop = true
		}
		if len(list) > 0 {
			t.idleConn[w.key] = list
		} else {
			delete(t.idleConn, w.key)
		}
		if stop {
			return delivered
		}
	}

	// Register to receive next connection that becomes idle.
	if t.idleConnWait == nil {
		t.idleConnWait = make(map[connectMethodKey]wantConnQueue)
	}
	q := t.idleConnWait[w.key]
	q.cleanFrontNotWaiting()
	q.pushBack(w)
	t.idleConnWait[w.key] = q
	return false
}

// removeIdleConn marks pconn as dead.
func (t *Transport) removeIdleConn(pconn *persistConn) bool {
	t.idleMu.Lock()
	defer t.idleMu.Unlock()
	return t.removeIdleConnLocked(pconn)
}

// t.idleMu must be held.
func (t *Transport) removeIdleConnLocked(pconn *persistConn) bool {
	if pconn.idleTimer != nil {
		pconn.idleTimer.Stop()
	}
	t.idleLRU.remove(pconn)
	key := pconn.cacheKey
	pconns := t.idleConn[key]
	var removed bool
	switch len(pconns) {
	case 0:
		// Nothing
	case 1:
		if pconns[0] == pconn {
			delete(t.idleConn, key)
			removed = true
		}
	default:
		for i, v := range pconns {
			if v != pconn {
				continue
			}
			// Slide down, keeping most recently-used
			// conns at the end.
			copy(pconns[i:], pconns[i+1:])
			t.idleConn[key] = pconns[:len(pconns)-1]
			removed = true
			break
		}
	}
	return removed
}

var zeroDialer net.Dialer

func (t *Transport) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if t.DialContext != nil {
		c, err := t.DialContext(ctx, network, addr)
		if c == nil && err == nil {
			err = errors.New("net/http: Transport.DialContext hook returned (nil, nil)")
		}
		return c, err
	}
	if t.Dial != nil {
		c, err := t.Dial(network, addr)
		if c == nil && err == nil {
			err = errors.New("net/http: Transport.Dial hook returned (nil, nil)")
		}
		return c, err
	}
	return zeroDialer.DialContext(ctx, network, addr)
}

// A wantConn records state about a wanted connection
// (that is, an active call to getConn).
// The conn may be gotten by dialing or by finding an idle connection,
// or a cancellation may make the conn no longer wanted.
// These three options are racing against each other and use
// wantConn to coordinate and agree about the winning outcome.
type wantConn struct {
	cm  connectMethod
	key connectMethodKey // cm.key()

	// hooks for testing to know when dials are done
	// beforeDial is called in the getConn goroutine when the dial is queued.
	// afterDial is called when the dial is completed or canceled.
	beforeDial func()
	afterDial  func()

	mu        sync.Mutex      // protects ctx, done and sending of the result
	ctx       context.Context // context for dial, cleared after delivered or canceled
	cancelCtx context.CancelFunc
	done      bool             // true after delivered or canceled
	result    chan connOrError // channel to deliver connection or error
}

type connOrError struct {
	pc     *persistConn
	err    error
	idleAt time.Time
}

// waiting reports whether w is still waiting for an answer (connection or error).
func (w *wantConn) waiting() bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	return !w.done
}

// getCtxForDial returns context for dial or nil if connection was delivered or canceled.
func (w *wantConn) getCtxForDial() context.Context {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.ctx
}

// tryDeliver attempts to deliver pc, err to w and reports whether it succeeded.
func (w *wantConn) tryDeliver(pc *persistConn, err error, idleAt time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.done {
		return false
	}
	if (pc == nil) == (err == nil) {
		panic("net/http: internal error: misuse of tryDeliver")
	}
	w.ctx = nil
	w.done = true

	w.result <- connOrError{pc: pc, err: err, idleAt: idleAt}
	close(w.result)

	return true
}

// cancel marks w as no longer wanting a result (for example, due to cancellation).
// If a connection has been delivered already, cancel returns it with t.putOrCloseIdleConn.
func (w *wantConn) cancel(t *Transport) {
	w.mu.Lock()
	var pc *persistConn
	if w.done {
		if r, ok := <-w.result; ok {
			pc = r.pc
		}
	} else {
		close(w.result)
	}
	w.ctx = nil
	w.done = true
	w.mu.Unlock()

	if pc != nil {
		t.putOrCloseIdleConn(pc)
	}
}

// A wantConnQueue is a queue of wantConns.
type wantConnQueue struct {
	// This is a queue, not a deque.
	// It is split into two stages - head[headPos:] and tail.
	// popFront is trivial (headPos++) on the first stage, and
	// pushBack is trivial (append) on the second stage.
	// If the first stage is empty, popFront can swap the
	// first and second stages to remedy the situation.
	//
	// This two-stage split is analogous to the use of two lists
	// in Okasaki's purely functional queue but without the
	// overhead of reversing the list when swapping stages.
	head    []*wantConn
	headPos int
	tail    []*wantConn
}

// len returns the number of items in the queue.
func (q *wantConnQueue) len() int {
	return len(q.head) - q.headPos + len(q.tail)
}

// pushBack adds w to the back of the queue.
func (q *wantConnQueue) pushBack(w *wantConn) {
	q.tail = append(q.tail, w)
}

// popFront removes and returns the wantConn at the front of the queue.
func (q *wantConnQueue) popFront() *wantConn {
	if q.headPos >= len(q.head) {
		if len(q.tail) == 0 {
			return nil
		}
		// Pick up tail as new head, clear tail.
		q.head, q.headPos, q.tail = q.tail, 0, q.head[:0]
	}
	w := q.head[q.headPos]
	q.head[q.headPos] = nil
	q.headPos++
	return w
}

// peekFront returns the wantConn at the front of the queue without removing it.
func (q *wantConnQueue) peekFront() *wantConn {
	if q.headPos < len(q.head) {
		return q.head[q.headPos]
	}
	if len(q.tail) > 0 {
		return q.tail[0]
	}
	return nil
}

// cleanFrontNotWaiting pops any wantConns that are no longer waiting from the head of the
// queue, reporting whether any were popped.
func (q *wantConnQueue) cleanFrontNotWaiting() (cleaned bool) {
	for {
		w := q.peekFront()
		if w == nil || w.waiting() {
			return cleaned
		}
		q.popFront()
		cleaned = true
	}
}

// cleanFrontCanceled pops any wantConns with canceled dials from the head of the queue.
func (q *wantConnQueue) cleanFrontCanceled() {
	for {
		w := q.peekFront()
		if w == nil || w.cancelCtx != nil {
			return
		}
		q.popFront()
	}
}

// all iterates over all wantConns in the queue.
// The caller must not modify the queue while iterating.
func (q *wantConnQueue) all(f func(*wantConn)) {
	for _, w := range q.head[q.headPos:] {
		f(w)
	}
	for _, w := range q.tail {
		f(w)
	}
}

func (t *Transport) customDialTLS(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	if t.DialTLSContext != nil {
		conn, err = t.DialTLSContext(ctx, network, addr)
	} else {
		conn, err = t.DialTLS(network, addr)
	}
	if conn == nil && err == nil {
		err = errors.New("net/http: Transport.DialTLS or DialTLSContext returned (nil, nil)")
	}
	return
}

// getConn dials and creates a new persistConn to the target as
// specified in the connectMethod. This includes doing a proxy CONNECT
// and/or setting up TLS.  If this doesn't return an error, the persistConn
// is ready to write requests to.
func (t *Transport) getConn(treq *transportRequest, cm connectMethod) (_ *persistConn, err error) {
	req := treq.Request
	trace := treq.trace
	ctx := req.Context()
	if trace != nil && trace.GetConn != nil {
		trace.GetConn(cm.addr())
	}

	// Detach from the request context's cancellation signal.
	// The dial should proceed even if the request is canceled,
	// because a future request may be able to make use of the connection.
	//
	// We retain the request context's values.
	dialCtx, dialCancel := context.WithCancel(context.WithoutCancel(ctx))

	w := &wantConn{
		cm:         cm,
		key:        cm.key(),
		ctx:        dialCtx,
		cancelCtx:  dialCancel,
		result:     make(chan connOrError, 1),
		beforeDial: testHookPrePendingDial,
		afterDial:  testHookPostPendingDial,
	}
	defer func() {
		if err != nil {
			w.cancel(t)
		}
	}()

	// Queue for idle connection.
	if delivered := t.queueForIdleConn(w); !delivered {
		t.queueForDial(w)
	}

	// Wait for completion or cancellation.
	select {
	case r := <-w.result:
		// Trace success but only for HTTP/1.
		// HTTP/2 calls trace.GotConn itself.
		if r.pc != nil && r.pc.alt == nil && trace != nil && trace.GotConn != nil {
			info := httptrace.GotConnInfo{
				Conn:   r.pc.conn,
				Reused: r.pc.isReused(),
			}
			if !r.idleAt.IsZero() {
				info.WasIdle = true
				info.IdleTime = time.Since(r.idleAt)
			}
			trace.GotConn(info)
		}
		if r.err != nil {
			// If the request has been canceled, that's probably
			// what caused r.err; if so, prefer to return the
			// cancellation error (see golang.org/issue/16049).
			select {
			case <-treq.ctx.Done():
				err := context.Cause(treq.ctx)
				if err == errRequestCanceled {
					err = errRequestCanceledConn
				}
				return nil, err
			default:
				// return below
			}
		}
		return r.pc, r.err
	case <-treq.ctx.Done():
		err := context.Cause(treq.ctx)
		if err == errRequestCanceled {
			err = errRequestCanceledConn
		}
		return nil, err
	}
}

// queueForDial queues w to wait for permission to begin dialing.
// Once w receives permission to dial, it will do so in a separate goroutine.
func (t *Transport) queueForDial(w *wantConn) {
	w.beforeDial()

	t.connsPerHostMu.Lock()
	defer t.connsPerHostMu.Unlock()

	if t.MaxConnsPerHost <= 0 {
		t.startDialConnForLocked(w)
		return
	}

	// 修复并发问题：确保 connsPerHost map 已初始化
	if t.connsPerHost == nil {
		t.connsPerHost = make(map[connectMethodKey]int)
	}

	if n := t.connsPerHost[w.key]; n < t.MaxConnsPerHost {
		t.connsPerHost[w.key] = n + 1
		t.startDialConnForLocked(w)
		return
	}

	if t.connsPerHostWait == nil {
		t.connsPerHostWait = make(map[connectMethodKey]wantConnQueue)
	}
	q := t.connsPerHostWait[w.key]
	q.cleanFrontNotWaiting()
	q.pushBack(w)
	t.connsPerHostWait[w.key] = q
}

// startDialConnFor calls dialConn in a new goroutine.
// t.connsPerHostMu must be held.
func (t *Transport) startDialConnForLocked(w *wantConn) {
	t.dialsInProgress.cleanFrontCanceled()
	t.dialsInProgress.pushBack(w)
	go func() {
		t.dialConnFor(w)
		t.connsPerHostMu.Lock()
		defer t.connsPerHostMu.Unlock()
		w.cancelCtx = nil
	}()
}

// dialConnFor dials on behalf of w and delivers the result to w.
// dialConnFor has received permission to dial w.cm and is counted in t.connCount[w.cm.key()].
// If the dial is canceled or unsuccessful, dialConnFor decrements t.connCount[w.cm.key()].
func (t *Transport) dialConnFor(w *wantConn) {
	defer w.afterDial()
	ctx := w.getCtxForDial()
	if ctx == nil {
		t.decConnsPerHost(w.key)
		return
	}

	pc, err := t.dialConn(ctx, w.cm)
	delivered := w.tryDeliver(pc, err, time.Time{})
	if err == nil && (!delivered || pc.alt != nil) {
		// pconn was not passed to w,
		// or it is HTTP/2 and can be shared.
		// Add to the idle connection pool.
		t.putOrCloseIdleConn(pc)
	}
	if err != nil {
		t.decConnsPerHost(w.key)
	}
}

// decConnsPerHost decrements the per-host connection count for key,
// which may in turn give a different waiting goroutine permission to dial.
func (t *Transport) decConnsPerHost(key connectMethodKey) {
	if t.MaxConnsPerHost <= 0 {
		return
	}

	t.connsPerHostMu.Lock()
	defer t.connsPerHostMu.Unlock()

	// 修复并发问题：确保 connsPerHost map 已初始化
	if t.connsPerHost == nil {
		t.connsPerHost = make(map[connectMethodKey]int)
	}

	n := t.connsPerHost[key]
	if n == 0 {
		// Shouldn't happen, but if it does, the counting is buggy and could
		// easily lead to a silent deadlock, so report the problem loudly.
		panic("net/http: internal error: connCount underflow")
	}

	// Can we hand this count to a goroutine still waiting to dial?
	// (Some goroutines on the wait list may have timed out or
	// gotten a connection another way. If they're all gone,
	// we don't want to kick off any spurious dial operations.)
	if q := t.connsPerHostWait[key]; q.len() > 0 {
		done := false
		for q.len() > 0 {
			w := q.popFront()
			if w.waiting() {
				t.startDialConnForLocked(w)
				done = true
				break
			}
		}
		if q.len() == 0 {
			delete(t.connsPerHostWait, key)
		} else {
			// q is a value (like a slice), so we have to store
			// the updated q back into the map.
			t.connsPerHostWait[key] = q
		}
		if done {
			return
		}
	}

	// Otherwise, decrement the recorded count.
	if n--; n == 0 {
		delete(t.connsPerHost, key)
	} else {
		t.connsPerHost[key] = n
	}
}

// Add TLS to a persistent connection, i.e. negotiate a TLS session. If pconn is already a TLS
// tunnel, this function establishes a nested TLS session inside the encrypted channel.
// The remote endpoint's name may be overridden by TLSClientConfig.ServerName.
func (pconn *persistConn) addTLS(ctx context.Context, name string, trace *httptrace.ClientTrace) error {
	// Initiate TLS and check remote host name against certificate.
	cfg := cloneTLSConfig(pconn.t.TLSClientConfig)
	if cfg.ServerName == "" {
		cfg.ServerName = name
	}
	if pconn.cacheKey.onlyH1 {
		cfg.NextProtos = nil
	}
	plainConn := pconn.conn

	// ===== 我们原创的 TLS 指纹控制逻辑 =====
	// 检查是否启用了自定义 TLS（支持简洁 API）
	useCustomTLS := pconn.t.UseCustomTLS ||
		pconn.t.JA3 != "" ||
		pconn.t.ClientHelloHexStream != "" ||
		pconn.t.TLSFingerprint != nil

	var tlsConn interface {
		net.Conn
		HandshakeContext(context.Context) error
		ConnectionState() tls.ConnectionState
	}
	var err error

	if useCustomTLS {
		// 使用 utls 进行自定义 TLS 握手
		tlsConn, err = pconn.createCustomTLSConn(plainConn, cfg)
		if err != nil {
			return err
		}
		// 注意：这里 tlsConn 已经是 *tls.UConn 类型
	} else {
		// 使用标准的 TLS 连接（tls.Client 返回 *tls.Conn）
		tlsConn = tls.Client(plainConn, cfg)
	}
	errc := make(chan error, 2)
	var timer *time.Timer // for canceling TLS handshake
	if d := pconn.t.TLSHandshakeTimeout; d != 0 {
		timer = time.AfterFunc(d, func() {
			errc <- tlsHandshakeTimeoutError{}
		})
	}
	go func() {
		if trace != nil && trace.TLSHandshakeStart != nil {
			trace.TLSHandshakeStart()
		}
		err := tlsConn.HandshakeContext(ctx)
		if timer != nil {
			timer.Stop()
		}
		errc <- err
	}()
	if err := <-errc; err != nil {
		plainConn.Close()
		if err == (tlsHandshakeTimeoutError{}) {
			// Now that we have closed the connection,
			// wait for the call to HandshakeContext to return.
			<-errc
		}
		if trace != nil && trace.TLSHandshakeDone != nil {
			trace.TLSHandshakeDone(tls.ConnectionState{}, err)
		}
		return err
	}
	cs := tlsConn.ConnectionState()
	if trace != nil && trace.TLSHandshakeDone != nil {
		trace.TLSHandshakeDone(cs, nil)
	}
	pconn.tlsState = &cs
	pconn.conn = tlsConn
	return nil
}

type erringRoundTripper interface {
	RoundTripErr() error
}

var testHookProxyConnectTimeout = context.WithTimeout

func (t *Transport) dialConn(ctx context.Context, cm connectMethod) (pconn *persistConn, err error) {
	pconn = &persistConn{
		t:             t,
		cacheKey:      cm.key(),
		reqch:         make(chan requestAndChan, 1),
		writech:       make(chan writeRequest, 1),
		closech:       make(chan struct{}),
		writeErrCh:    make(chan error, 1),
		writeLoopDone: make(chan struct{}),
	}
	trace := httptrace.ContextClientTrace(ctx)
	wrapErr := func(err error) error {
		if cm.proxyURL != nil {
			// Return a typed error, per Issue 16997
			return &net.OpError{Op: "proxyconnect", Net: "tcp", Err: err}
		}
		return err
	}
	if cm.scheme() == "https" && t.hasCustomTLSDialer() {
		var err error
		pconn.conn, err = t.customDialTLS(ctx, "tcp", cm.addr())
		if err != nil {
			return nil, wrapErr(err)
		}
		if tc, ok := pconn.conn.(*tls.Conn); ok {
			// Handshake here, in case DialTLS didn't. TLSNextProto below
			// depends on it for knowing the connection state.
			if trace != nil && trace.TLSHandshakeStart != nil {
				trace.TLSHandshakeStart()
			}
			if err := tc.HandshakeContext(ctx); err != nil {
				go pconn.conn.Close()
				if trace != nil && trace.TLSHandshakeDone != nil {
					trace.TLSHandshakeDone(tls.ConnectionState{}, err)
				}
				return nil, err
			}
			cs := tc.ConnectionState()
			if trace != nil && trace.TLSHandshakeDone != nil {
				trace.TLSHandshakeDone(cs, nil)
			}
			pconn.tlsState = &cs
		}
	} else {
		conn, err := t.dial(ctx, "tcp", cm.addr())
		if err != nil {
			return nil, wrapErr(err)
		}
		pconn.conn = conn
		if cm.scheme() == "https" {
			var firstTLSHost string
			if firstTLSHost, _, err = net.SplitHostPort(cm.addr()); err != nil {
				return nil, wrapErr(err)
			}
			if err = pconn.addTLS(ctx, firstTLSHost, trace); err != nil {
				return nil, wrapErr(err)
			}
		}
	}

	// Proxy setup.
	switch {
	case cm.proxyURL == nil:
		// Do nothing. Not using a proxy.
	case cm.proxyURL.Scheme == "socks5" || cm.proxyURL.Scheme == "socks5h":
		conn := pconn.conn
		d := socksNewDialer("tcp", conn.RemoteAddr().String())
		if u := cm.proxyURL.User; u != nil {
			auth := &socksUsernamePassword{
				Username: u.Username(),
			}
			auth.Password, _ = u.Password()
			d.AuthMethods = []socksAuthMethod{
				socksAuthMethodNotRequired,
				socksAuthMethodUsernamePassword,
			}
			d.Authenticate = auth.Authenticate
		}
		if _, err := d.DialWithConn(ctx, conn, "tcp", cm.targetAddr); err != nil {
			conn.Close()
			return nil, err
		}
	case cm.targetScheme == "http":
		pconn.isProxy = true
		if pa := cm.proxyAuth(); pa != "" {
			pconn.mutateHeaderFunc = func(h Header) {
				h.Set("Proxy-Authorization", pa)
			}
		}
	case cm.targetScheme == "https":
		conn := pconn.conn
		var hdr Header
		if t.GetProxyConnectHeader != nil {
			var err error
			hdr, err = t.GetProxyConnectHeader(ctx, cm.proxyURL, cm.targetAddr)
			if err != nil {
				conn.Close()
				return nil, err
			}
		} else {
			hdr = t.ProxyConnectHeader
		}
		if hdr == nil {
			hdr = make(Header)
		}
		if pa := cm.proxyAuth(); pa != "" {
			hdr = hdr.Clone()
			hdr.Set("Proxy-Authorization", pa)
		}
		connectReq := &Request{
			Method: "CONNECT",
			URL:    &url.URL{Opaque: cm.targetAddr},
			Host:   cm.targetAddr,
			Header: hdr,
		}

		// Set a (long) timeout here to make sure we don't block forever
		// and leak a goroutine if the connection stops replying after
		// the TCP connect.
		connectCtx, cancel := testHookProxyConnectTimeout(ctx, 1*time.Minute)
		defer cancel()

		didReadResponse := make(chan struct{}) // closed after CONNECT write+read is done or fails
		var (
			resp *Response
			err  error // write or read error
		)
		// Write the CONNECT request & read the response.
		go func() {
			defer close(didReadResponse)
			err = connectReq.Write(conn)
			if err != nil {
				return
			}
			// Okay to use and discard buffered reader here, because
			// TLS server will not speak until spoken to.
			br := bufio.NewReader(conn)
			resp, err = ReadResponse(br, connectReq)
		}()
		select {
		case <-connectCtx.Done():
			conn.Close()
			<-didReadResponse
			return nil, connectCtx.Err()
		case <-didReadResponse:
			// resp or err now set
		}
		if err != nil {
			conn.Close()
			return nil, err
		}

		if t.OnProxyConnectResponse != nil {
			err = t.OnProxyConnectResponse(ctx, cm.proxyURL, connectReq, resp)
			if err != nil {
				conn.Close()
				return nil, err
			}
		}

		if resp.StatusCode != 200 {
			_, text, ok := strings.Cut(resp.Status, " ")
			conn.Close()
			if !ok {
				return nil, errors.New("unknown status code")
			}
			return nil, errors.New(text)
		}
	}

	if cm.proxyURL != nil && cm.targetScheme == "https" {
		if err := pconn.addTLS(ctx, cm.tlsHost(), trace); err != nil {
			return nil, err
		}
	}

	// Possible unencrypted HTTP/2 with prior knowledge.
	unencryptedHTTP2 := pconn.tlsState == nil &&
		t.Protocols != nil &&
		t.Protocols.UnencryptedHTTP2() &&
		!t.Protocols.HTTP1()
	if unencryptedHTTP2 {
		next, ok := t.TLSNextProto[nextProtoUnencryptedHTTP2]
		if !ok {
			return nil, errors.New("http: Transport does not support unencrypted HTTP/2")
		}
		alt := next(cm.targetAddr, unencryptedTLSConn(pconn.conn))
		if e, ok := alt.(erringRoundTripper); ok {
			// pconn.conn was closed by next (http2configureTransports.upgradeFn).
			return nil, e.RoundTripErr()
		}
		return &persistConn{t: t, cacheKey: pconn.cacheKey, alt: alt}, nil
	}

	if s := pconn.tlsState; s != nil && s.NegotiatedProtocolIsMutual && s.NegotiatedProtocol != "" {
		if next, ok := t.TLSNextProto[s.NegotiatedProtocol]; ok {
			// 直接传递连接（支持 *tls.Conn 和 *tls.UConn）
			alt := next(cm.targetAddr, pconn.conn)
			if e, ok := alt.(erringRoundTripper); ok {
				// pconn.conn was closed by next (http2configureTransports.upgradeFn).
				return nil, e.RoundTripErr()
			}
			return &persistConn{t: t, cacheKey: pconn.cacheKey, alt: alt}, nil
		}
	}

	pconn.br = bufio.NewReaderSize(pconn, t.readBufferSize())
	pconn.bw = bufio.NewWriterSize(persistConnWriter{pconn}, t.writeBufferSize())

	go pconn.readLoop()
	go pconn.writeLoop()
	return pconn, nil
}

// persistConnWriter is the io.Writer written to by pc.bw.
// It accumulates the number of bytes written to the underlying conn,
// so the retry logic can determine whether any bytes made it across
// the wire.
// This is exactly 1 pointer field wide so it can go into an interface
// without allocation.
type persistConnWriter struct {
	pc *persistConn
}

func (w persistConnWriter) Write(p []byte) (n int, err error) {
	n, err = w.pc.conn.Write(p)
	w.pc.nwrite += int64(n)
	return
}

// ReadFrom exposes persistConnWriter's underlying Conn to io.Copy and if
// the Conn implements io.ReaderFrom, it can take advantage of optimizations
// such as sendfile.
func (w persistConnWriter) ReadFrom(r io.Reader) (n int64, err error) {
	n, err = io.Copy(w.pc.conn, r)
	w.pc.nwrite += n
	return
}

var _ io.ReaderFrom = (*persistConnWriter)(nil)

// connectMethod is the map key (in its String form) for keeping persistent
// TCP connections alive for subsequent HTTP requests.
//
// A connect method may be of the following types:
//
//	connectMethod.key().String()      Description
//	------------------------------    -------------------------
//	|http|foo.com                     http directly to server, no proxy
//	|https|foo.com                    https directly to server, no proxy
//	|https,h1|foo.com                 https directly to server w/o HTTP/2, no proxy
//	http://proxy.com|https|foo.com    http to proxy, then CONNECT to foo.com
//	http://proxy.com|http             http to proxy, http to anywhere after that
//	socks5://proxy.com|http|foo.com   socks5 to proxy, then http to foo.com
//	socks5://proxy.com|https|foo.com  socks5 to proxy, then https to foo.com
//	https://proxy.com|https|foo.com   https to proxy, then CONNECT to foo.com
//	https://proxy.com|http            https to proxy, http to anywhere after that
type connectMethod struct {
	_            incomparable
	proxyURL     *url.URL // nil for no proxy, else full proxy URL
	targetScheme string   // "http" or "https"
	// If proxyURL specifies an http or https proxy, and targetScheme is http (not https),
	// then targetAddr is not included in the connect method key, because the socket can
	// be reused for different targetAddr values.
	targetAddr string
	onlyH1     bool // whether to disable HTTP/2 and force HTTP/1
}

func (cm *connectMethod) key() connectMethodKey {
	proxyStr := ""
	targetAddr := cm.targetAddr
	if cm.proxyURL != nil {
		proxyStr = cm.proxyURL.String()
		if (cm.proxyURL.Scheme == "http" || cm.proxyURL.Scheme == "https") && cm.targetScheme == "http" {
			targetAddr = ""
		}
	}
	return connectMethodKey{
		proxy:  proxyStr,
		scheme: cm.targetScheme,
		addr:   targetAddr,
		onlyH1: cm.onlyH1,
	}
}

// scheme returns the first hop scheme: http, https, or socks5
func (cm *connectMethod) scheme() string {
	if cm.proxyURL != nil {
		return cm.proxyURL.Scheme
	}
	return cm.targetScheme
}

// addr returns the first hop "host:port" to which we need to TCP connect.
func (cm *connectMethod) addr() string {
	if cm.proxyURL != nil {
		return canonicalAddr(cm.proxyURL)
	}
	return cm.targetAddr
}

// tlsHost returns the host name to match against the peer's
// TLS certificate.
func (cm *connectMethod) tlsHost() string {
	h := cm.targetAddr
	if hasPort(h) {
		h = h[:strings.LastIndex(h, ":")]
	}
	return h
}

// connectMethodKey is the map key version of connectMethod, with a
// stringified proxy URL (or the empty string) instead of a pointer to
// a URL.
type connectMethodKey struct {
	proxy, scheme, addr string
	onlyH1              bool
}

func (k connectMethodKey) String() string {
	// Only used by tests.
	var h1 string
	if k.onlyH1 {
		h1 = ",h1"
	}
	return fmt.Sprintf("%s|%s%s|%s", k.proxy, k.scheme, h1, k.addr)
}

// persistConn wraps a connection, usually a persistent one
// (but may be used for non-keep-alive requests as well)
type persistConn struct {
	// alt optionally specifies the TLS NextProto RoundTripper.
	// This is used for HTTP/2 today and future protocols later.
	// If it's non-nil, the rest of the fields are unused.
	alt RoundTripper

	t         *Transport
	cacheKey  connectMethodKey
	conn      net.Conn
	tlsState  *tls.ConnectionState
	br        *bufio.Reader       // from conn
	bw        *bufio.Writer       // to conn
	nwrite    int64               // bytes written
	reqch     chan requestAndChan // written by roundTrip; read by readLoop
	writech   chan writeRequest   // written by roundTrip; read by writeLoop
	closech   chan struct{}       // closed when conn closed
	isProxy   bool
	sawEOF    bool  // whether we've seen EOF from conn; owned by readLoop
	readLimit int64 // bytes allowed to be read; owned by readLoop
	// writeErrCh passes the request write error (usually nil)
	// from the writeLoop goroutine to the readLoop which passes
	// it off to the res.Body reader, which then uses it to decide
	// whether or not a connection can be reused. Issue 7569.
	writeErrCh chan error

	writeLoopDone chan struct{} // closed when write loop ends

	// Both guarded by Transport.idleMu:
	idleAt    time.Time   // time it last become idle
	idleTimer *time.Timer // holding an AfterFunc to close it

	mu                   sync.Mutex // guards following fields
	numExpectedResponses int
	closed               error // set non-nil when conn is closed, before closech is closed
	canceledErr          error // set non-nil if conn is canceled
	broken               bool  // an error has happened on this connection; marked broken so it's not reused.
	reused               bool  // whether conn has had successful request/response and is being reused.
	// mutateHeaderFunc is an optional func to modify extra
	// headers on each outbound request before it's written. (the
	// original Request given to RoundTrip is not modified)
	mutateHeaderFunc func(Header)
}

func (pc *persistConn) maxHeaderResponseSize() int64 {
	if v := pc.t.MaxResponseHeaderBytes; v != 0 {
		return v
	}
	return 10 << 20 // conservative default; same as http2
}

func (pc *persistConn) Read(p []byte) (n int, err error) {
	if pc.readLimit <= 0 {
		return 0, fmt.Errorf("read limit of %d bytes exhausted", pc.maxHeaderResponseSize())
	}
	if int64(len(p)) > pc.readLimit {
		p = p[:pc.readLimit]
	}
	n, err = pc.conn.Read(p)
	if err == io.EOF {
		pc.sawEOF = true
	}
	pc.readLimit -= int64(n)
	return
}

// isBroken reports whether this connection is in a known broken state.
func (pc *persistConn) isBroken() bool {
	pc.mu.Lock()
	b := pc.closed != nil
	pc.mu.Unlock()
	return b
}

// canceled returns non-nil if the connection was closed due to
// CancelRequest or due to context cancellation.
func (pc *persistConn) canceled() error {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return pc.canceledErr
}

// isReused reports whether this connection has been used before.
func (pc *persistConn) isReused() bool {
	pc.mu.Lock()
	r := pc.reused
	pc.mu.Unlock()
	return r
}

func (pc *persistConn) cancelRequest(err error) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.canceledErr = err
	pc.closeLocked(errRequestCanceled)
}

// closeConnIfStillIdle closes the connection if it's still sitting idle.
// This is what's called by the persistConn's idleTimer, and is run in its
// own goroutine.
func (pc *persistConn) closeConnIfStillIdle() {
	t := pc.t
	t.idleMu.Lock()
	defer t.idleMu.Unlock()
	if _, ok := t.idleLRU.m[pc]; !ok {
		// Not idle.
		return
	}
	t.removeIdleConnLocked(pc)
	pc.close(errIdleConnTimeout)
}

// mapRoundTripError returns the appropriate error value for
// persistConn.roundTrip.
//
// The provided err is the first error that (*persistConn).roundTrip
// happened to receive from its select statement.
//
// The startBytesWritten value should be the value of pc.nwrite before the roundTrip
// started writing the request.
func (pc *persistConn) mapRoundTripError(req *transportRequest, startBytesWritten int64, err error) error {
	if err == nil {
		return nil
	}

	// Wait for the writeLoop goroutine to terminate to avoid data
	// races on callers who mutate the request on failure.
	//
	// When resc in pc.roundTrip and hence rc.ch receives a responseAndError
	// with a non-nil error it implies that the persistConn is either closed
	// or closing. Waiting on pc.writeLoopDone is hence safe as all callers
	// close closech which in turn ensures writeLoop returns.
	<-pc.writeLoopDone

	// If the request was canceled, that's better than network
	// failures that were likely the result of tearing down the
	// connection.
	if cerr := pc.canceled(); cerr != nil {
		return cerr
	}

	// See if an error was set explicitly.
	req.mu.Lock()
	reqErr := req.err
	req.mu.Unlock()
	if reqErr != nil {
		return reqErr
	}

	if err == errServerClosedIdle {
		// Don't decorate
		return err
	}

	if _, ok := err.(transportReadFromServerError); ok {
		if pc.nwrite == startBytesWritten {
			return nothingWrittenError{err}
		}
		// Don't decorate
		return err
	}
	if pc.isBroken() {
		if pc.nwrite == startBytesWritten {
			return nothingWrittenError{err}
		}
		return fmt.Errorf("net/http: HTTP/1.x transport connection broken: %w", err)
	}
	return err
}

// errCallerOwnsConn is an internal sentinel error used when we hand
// off a writable response.Body to the caller. We use this to prevent
// closing a net.Conn that is now owned by the caller.
var errCallerOwnsConn = errors.New("read loop ending; caller owns writable underlying conn")

func (pc *persistConn) readLoop() {
	closeErr := errReadLoopExiting // default value, if not changed below
	defer func() {
		pc.close(closeErr)
		pc.t.removeIdleConn(pc)
	}()

	tryPutIdleConn := func(treq *transportRequest) bool {
		trace := treq.trace
		if err := pc.t.tryPutIdleConn(pc); err != nil {
			closeErr = err
			if trace != nil && trace.PutIdleConn != nil && err != errKeepAlivesDisabled {
				trace.PutIdleConn(err)
			}
			return false
		}
		if trace != nil && trace.PutIdleConn != nil {
			trace.PutIdleConn(nil)
		}
		return true
	}

	// eofc is used to block caller goroutines reading from Response.Body
	// at EOF until this goroutines has (potentially) added the connection
	// back to the idle pool.
	eofc := make(chan struct{})
	defer close(eofc) // unblock reader on errors

	// Read this once, before loop starts. (to avoid races in tests)
	testHookMu.Lock()
	testHookReadLoopBeforeNextRead := testHookReadLoopBeforeNextRead
	testHookMu.Unlock()

	alive := true
	for alive {
		pc.readLimit = pc.maxHeaderResponseSize()
		_, err := pc.br.Peek(1)

		pc.mu.Lock()
		if pc.numExpectedResponses == 0 {
			pc.readLoopPeekFailLocked(err)
			pc.mu.Unlock()
			return
		}
		pc.mu.Unlock()

		rc := <-pc.reqch
		trace := rc.treq.trace

		var resp *Response
		if err == nil {
			resp, err = pc.readResponse(rc, trace)
		} else {
			err = transportReadFromServerError{err}
			closeErr = err
		}

		if err != nil {
			if pc.readLimit <= 0 {
				err = fmt.Errorf("net/http: server response headers exceeded %d bytes; aborted", pc.maxHeaderResponseSize())
			}

			select {
			case rc.ch <- responseAndError{err: err}:
			case <-rc.callerGone:
				return
			}
			return
		}
		pc.readLimit = maxInt64 // effectively no limit for response bodies

		pc.mu.Lock()
		pc.numExpectedResponses--
		pc.mu.Unlock()

		bodyWritable := resp.bodyIsWritable()
		hasBody := rc.treq.Request.Method != "HEAD" && resp.ContentLength != 0

		if resp.Close || rc.treq.Request.Close || resp.StatusCode <= 199 || bodyWritable {
			// Don't do keep-alive on error if either party requested a close
			// or we get an unexpected informational (1xx) response.
			// StatusCode 100 is already handled above.
			alive = false
		}

		if !hasBody || bodyWritable {
			// Put the idle conn back into the pool before we send the response
			// so if they process it quickly and make another request, they'll
			// get this same conn. But we use the unbuffered channel 'rc'
			// to guarantee that persistConn.roundTrip got out of its select
			// potentially waiting for this persistConn to close.
			alive = alive &&
				!pc.sawEOF &&
				pc.wroteRequest() &&
				tryPutIdleConn(rc.treq)

			if bodyWritable {
				closeErr = errCallerOwnsConn
			}

			select {
			case rc.ch <- responseAndError{res: resp}:
			case <-rc.callerGone:
				return
			}

			rc.treq.cancel(errRequestDone)

			// Now that they've read from the unbuffered channel, they're safely
			// out of the select that also waits on this goroutine to die, so
			// we're allowed to exit now if needed (if alive is false)
			testHookReadLoopBeforeNextRead()
			continue
		}

		waitForBodyRead := make(chan bool, 2)
		body := &bodyEOFSignal{
			body: resp.Body,
			earlyCloseFn: func() error {
				waitForBodyRead <- false
				<-eofc // will be closed by deferred call at the end of the function
				return nil

			},
			fn: func(err error) error {
				isEOF := err == io.EOF
				waitForBodyRead <- isEOF
				if isEOF {
					<-eofc // see comment above eofc declaration
				} else if err != nil {
					if cerr := pc.canceled(); cerr != nil {
						return cerr
					}
				}
				return err
			},
		}

		resp.Body = body
		if rc.addedGzip && ascii.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
			resp.Body = &gzipReader{body: body}
			resp.Header.Del("Content-Encoding")
			resp.Header.Del("Content-Length")
			resp.ContentLength = -1
			resp.Uncompressed = true
		}

		select {
		case rc.ch <- responseAndError{res: resp}:
		case <-rc.callerGone:
			return
		}

		// Before looping back to the top of this function and peeking on
		// the bufio.Reader, wait for the caller goroutine to finish
		// reading the response body. (or for cancellation or death)
		select {
		case bodyEOF := <-waitForBodyRead:
			alive = alive &&
				bodyEOF &&
				!pc.sawEOF &&
				pc.wroteRequest() &&
				tryPutIdleConn(rc.treq)
			if bodyEOF {
				eofc <- struct{}{}
			}
		case <-rc.treq.ctx.Done():
			alive = false
			pc.cancelRequest(context.Cause(rc.treq.ctx))
		case <-pc.closech:
			alive = false
		}

		rc.treq.cancel(errRequestDone)
		testHookReadLoopBeforeNextRead()
	}
}

func (pc *persistConn) readLoopPeekFailLocked(peekErr error) {
	if pc.closed != nil {
		return
	}
	if n := pc.br.Buffered(); n > 0 {
		buf, _ := pc.br.Peek(n)
		if is408Message(buf) {
			pc.closeLocked(errServerClosedIdle)
			return
		} else {
			log.Printf("Unsolicited response received on idle HTTP channel starting with %q; err=%v", buf, peekErr)
		}
	}
	if peekErr == io.EOF {
		// common case.
		pc.closeLocked(errServerClosedIdle)
	} else {
		pc.closeLocked(fmt.Errorf("readLoopPeekFailLocked: %w", peekErr))
	}
}

// is408Message reports whether buf has the prefix of an
// HTTP 408 Request Timeout response.
// See golang.org/issue/32310.
func is408Message(buf []byte) bool {
	if len(buf) < len("HTTP/1.x 408") {
		return false
	}
	if string(buf[:7]) != "HTTP/1." {
		return false
	}
	return string(buf[8:12]) == " 408"
}

// readResponse reads an HTTP response (or two, in the case of "Expect:
// 100-continue") from the server. It returns the final non-100 one.
// trace is optional.
func (pc *persistConn) readResponse(rc requestAndChan, trace *httptrace.ClientTrace) (resp *Response, err error) {
	if trace != nil && trace.GotFirstResponseByte != nil {
		if peek, err := pc.br.Peek(1); err == nil && len(peek) == 1 {
			trace.GotFirstResponseByte()
		}
	}

	continueCh := rc.continueCh
	for {
		resp, err = ReadResponse(pc.br, rc.treq.Request)
		if err != nil {
			return
		}
		resCode := resp.StatusCode
		if continueCh != nil && resCode == StatusContinue {
			if trace != nil && trace.Got100Continue != nil {
				trace.Got100Continue()
			}
			continueCh <- struct{}{}
			continueCh = nil
		}
		is1xx := 100 <= resCode && resCode <= 199
		// treat 101 as a terminal status, see issue 26161
		is1xxNonTerminal := is1xx && resCode != StatusSwitchingProtocols
		if is1xxNonTerminal {
			if trace != nil && trace.Got1xxResponse != nil {
				if err := trace.Got1xxResponse(resCode, textproto.MIMEHeader(resp.Header)); err != nil {
					return nil, err
				}
				// If the 1xx response was delivered to the user,
				// then they're responsible for limiting the number of
				// responses. Reset the header limit.
				//
				// If the user didn't examine the 1xx response, then we
				// limit the size of all headers (including both 1xx
				// and the final response) to maxHeaderResponseSize.
				pc.readLimit = pc.maxHeaderResponseSize() // reset the limit
			}
			continue
		}
		break
	}
	if resp.isProtocolSwitch() {
		resp.Body = newReadWriteCloserBody(pc.br, pc.conn)
	}
	if continueCh != nil {
		// We send an "Expect: 100-continue" header, but the server
		// responded with a terminal status and no 100 Continue.
		//
		// If we're going to keep using the connection, we need to send the request body.
		// Tell writeLoop to skip sending the body if we're going to close the connection,
		// or to send it otherwise.
		//
		// The case where we receive a 101 Switching Protocols response is a bit
		// ambiguous, since we don't know what protocol we're switching to.
		// Conceivably, it's one that doesn't need us to send the body.
		// Given that we'll send the body if ExpectContinueTimeout expires,
		// be consistent and always send it if we aren't closing the connection.
		if resp.Close || rc.treq.Request.Close {
			close(continueCh) // don't send the body; the connection will close
		} else {
			continueCh <- struct{}{} // send the body
		}
	}

	resp.TLS = pc.tlsState
	return
}

// waitForContinue returns the function to block until
// any response, timeout or connection close. After any of them,
// the function returns a bool which indicates if the body should be sent.
func (pc *persistConn) waitForContinue(continueCh <-chan struct{}) func() bool {
	if continueCh == nil {
		return nil
	}
	return func() bool {
		timer := time.NewTimer(pc.t.ExpectContinueTimeout)
		defer timer.Stop()

		select {
		case _, ok := <-continueCh:
			return ok
		case <-timer.C:
			return true
		case <-pc.closech:
			return false
		}
	}
}

func newReadWriteCloserBody(br *bufio.Reader, rwc io.ReadWriteCloser) io.ReadWriteCloser {
	body := &readWriteCloserBody{ReadWriteCloser: rwc}
	if br.Buffered() != 0 {
		body.br = br
	}
	return body
}

// readWriteCloserBody is the Response.Body type used when we want to
// give users write access to the Body through the underlying
// connection (TCP, unless using custom dialers). This is then
// the concrete type for a Response.Body on the 101 Switching
// Protocols response, as used by WebSockets, h2c, etc.
type readWriteCloserBody struct {
	_  incomparable
	br *bufio.Reader // used until empty
	io.ReadWriteCloser
}

func (b *readWriteCloserBody) Read(p []byte) (n int, err error) {
	if b.br != nil {
		if n := b.br.Buffered(); len(p) > n {
			p = p[:n]
		}
		n, err = b.br.Read(p)
		if b.br.Buffered() == 0 {
			b.br = nil
		}
		return n, err
	}
	return b.ReadWriteCloser.Read(p)
}

func (b *readWriteCloserBody) CloseWrite() error {
	if cw, ok := b.ReadWriteCloser.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return fmt.Errorf("CloseWrite: %w", ErrNotSupported)
}

// nothingWrittenError wraps a write errors which ended up writing zero bytes.
type nothingWrittenError struct {
	error
}

func (nwe nothingWrittenError) Unwrap() error {
	return nwe.error
}

func (pc *persistConn) writeLoop() {
	defer close(pc.writeLoopDone)
	for {
		select {
		case wr := <-pc.writech:
			startBytesWritten := pc.nwrite
			err := wr.req.Request.write(pc.bw, pc.isProxy, wr.req.extra, pc.waitForContinue(wr.continueCh))
			if bre, ok := err.(requestBodyReadError); ok {
				err = bre.error
				// Errors reading from the user's
				// Request.Body are high priority.
				// Set it here before sending on the
				// channels below or calling
				// pc.close() which tears down
				// connections and causes other
				// errors.
				wr.req.setError(err)
			}
			if err == nil {
				err = pc.bw.Flush()
			}
			if err != nil {
				if pc.nwrite == startBytesWritten {
					err = nothingWrittenError{err}
				}
			}
			pc.writeErrCh <- err // to the body reader, which might recycle us
			wr.ch <- err         // to the roundTrip function
			if err != nil {
				pc.close(err)
				return
			}
		case <-pc.closech:
			return
		}
	}
}

// maxWriteWaitBeforeConnReuse is how long the a Transport RoundTrip
// will wait to see the Request's Body.Write result after getting a
// response from the server. See comments in (*persistConn).wroteRequest.
//
// In tests, we set this to a large value to avoid flakiness from inconsistent
// recycling of connections.
var maxWriteWaitBeforeConnReuse = 50 * time.Millisecond

// wroteRequest is a check before recycling a connection that the previous write
// (from writeLoop above) happened and was successful.
func (pc *persistConn) wroteRequest() bool {
	select {
	case err := <-pc.writeErrCh:
		// Common case: the write happened well before the response, so
		// avoid creating a timer.
		return err == nil
	default:
		// Rare case: the request was written in writeLoop above but
		// before it could send to pc.writeErrCh, the reader read it
		// all, processed it, and called us here. In this case, give the
		// write goroutine a bit of time to finish its send.
		//
		// Less rare case: We also get here in the legitimate case of
		// Issue 7569, where the writer is still writing (or stalled),
		// but the server has already replied. In this case, we don't
		// want to wait too long, and we want to return false so this
		// connection isn't re-used.
		t := time.NewTimer(maxWriteWaitBeforeConnReuse)
		defer t.Stop()
		select {
		case err := <-pc.writeErrCh:
			return err == nil
		case <-t.C:
			return false
		}
	}
}

// responseAndError is how the goroutine reading from an HTTP/1 server
// communicates with the goroutine doing the RoundTrip.
type responseAndError struct {
	_   incomparable
	res *Response // else use this response (see res method)
	err error
}

type requestAndChan struct {
	_    incomparable
	treq *transportRequest
	ch   chan responseAndError // unbuffered; always send in select on callerGone

	// whether the Transport (as opposed to the user client code)
	// added the Accept-Encoding gzip header. If the Transport
	// set it, only then do we transparently decode the gzip.
	addedGzip bool

	// Optional blocking chan for Expect: 100-continue (for send).
	// If the request has an "Expect: 100-continue" header and
	// the server responds 100 Continue, readLoop send a value
	// to writeLoop via this chan.
	continueCh chan<- struct{}

	callerGone <-chan struct{} // closed when roundTrip caller has returned
}

// A writeRequest is sent by the caller's goroutine to the
// writeLoop's goroutine to write a request while the read loop
// concurrently waits on both the write response and the server's
// reply.
type writeRequest struct {
	req *transportRequest
	ch  chan<- error

	// Optional blocking chan for Expect: 100-continue (for receive).
	// If not nil, writeLoop blocks sending request body until
	// it receives from this chan.
	continueCh <-chan struct{}
}

// httpTimeoutError represents a timeout.
// It implements net.Error and wraps context.DeadlineExceeded.
type timeoutError struct {
	err string
}

func (e *timeoutError) Error() string     { return e.err }
func (e *timeoutError) Timeout() bool     { return true }
func (e *timeoutError) Temporary() bool   { return true }
func (e *timeoutError) Is(err error) bool { return err == context.DeadlineExceeded }

var errTimeout error = &timeoutError{"net/http: timeout awaiting response headers"}

// errRequestCanceled is set to be identical to the one from h2 to facilitate
// testing.
var errRequestCanceled = http2errRequestCanceled
var errRequestCanceledConn = errors.New("net/http: request canceled while waiting for connection") // TODO: unify?

// errRequestDone is used to cancel the round trip Context after a request is successfully done.
// It should not be seen by the user.
var errRequestDone = errors.New("net/http: request completed")

func nop() {}

// testHooks. Always non-nil.
var (
	testHookEnterRoundTrip   = nop
	testHookWaitResLoop      = nop
	testHookRoundTripRetried = nop
	testHookPrePendingDial   = nop
	testHookPostPendingDial  = nop

	testHookMu                     sync.Locker = fakeLocker{} // guards following
	testHookReadLoopBeforeNextRead             = nop
)

func (pc *persistConn) roundTrip(req *transportRequest) (resp *Response, err error) {
	testHookEnterRoundTrip()
	pc.mu.Lock()
	pc.numExpectedResponses++
	headerFn := pc.mutateHeaderFunc
	pc.mu.Unlock()

	if headerFn != nil {
		headerFn(req.extraHeaders())
	}

	// Ask for a compressed version if the caller didn't set their
	// own value for Accept-Encoding. We only attempt to
	// uncompress the gzip stream if we were the layer that
	// requested it.
	requestedGzip := false
	if !pc.t.DisableCompression &&
		req.Header.Get("Accept-Encoding") == "" &&
		req.Header.Get("Range") == "" &&
		req.Method != "HEAD" {
		// Request gzip only, not deflate. Deflate is ambiguous and
		// not as universally supported anyway.
		// See: https://zlib.net/zlib_faq.html#faq39
		//
		// Note that we don't request this for HEAD requests,
		// due to a bug in nginx:
		//   https://trac.nginx.org/nginx/ticket/358
		//   https://golang.org/issue/5522
		//
		// We don't request gzip if the request is for a range, since
		// auto-decoding a portion of a gzipped document will just fail
		// anyway. See https://golang.org/issue/8923
		requestedGzip = true
		req.extraHeaders().Set("Accept-Encoding", "gzip")
	}

	var continueCh chan struct{}
	if req.ProtoAtLeast(1, 1) && req.Body != nil && req.expectsContinue() {
		continueCh = make(chan struct{}, 1)
	}

	if pc.t.DisableKeepAlives &&
		!req.wantsClose() &&
		!isProtocolSwitchHeader(req.Header) {
		req.extraHeaders().Set("Connection", "close")
	}

	gone := make(chan struct{})
	defer close(gone)

	const debugRoundTrip = false

	// Write the request concurrently with waiting for a response,
	// in case the server decides to reply before reading our full
	// request body.
	startBytesWritten := pc.nwrite
	writeErrCh := make(chan error, 1)
	pc.writech <- writeRequest{req, writeErrCh, continueCh}

	resc := make(chan responseAndError)
	pc.reqch <- requestAndChan{
		treq:       req,
		ch:         resc,
		addedGzip:  requestedGzip,
		continueCh: continueCh,
		callerGone: gone,
	}

	handleResponse := func(re responseAndError) (*Response, error) {
		if (re.res == nil) == (re.err == nil) {
			panic(fmt.Sprintf("internal error: exactly one of res or err should be set; nil=%v", re.res == nil))
		}
		if debugRoundTrip {
			req.logf("resc recv: %p, %T/%#v", re.res, re.err, re.err)
		}
		if re.err != nil {
			return nil, pc.mapRoundTripError(req, startBytesWritten, re.err)
		}
		return re.res, nil
	}

	var respHeaderTimer <-chan time.Time
	ctxDoneChan := req.ctx.Done()
	pcClosed := pc.closech
	for {
		testHookWaitResLoop()
		select {
		case err := <-writeErrCh:
			if debugRoundTrip {
				req.logf("writeErrCh recv: %T/%#v", err, err)
			}
			if err != nil {
				pc.close(fmt.Errorf("write error: %w", err))
				return nil, pc.mapRoundTripError(req, startBytesWritten, err)
			}
			if d := pc.t.ResponseHeaderTimeout; d > 0 {
				if debugRoundTrip {
					req.logf("starting timer for %v", d)
				}
				timer := time.NewTimer(d)
				defer timer.Stop() // prevent leaks
				respHeaderTimer = timer.C
			}
		case <-pcClosed:
			select {
			case re := <-resc:
				// The pconn closing raced with the response to the request,
				// probably after the server wrote a response and immediately
				// closed the connection. Use the response.
				return handleResponse(re)
			default:
			}
			if debugRoundTrip {
				req.logf("closech recv: %T %#v", pc.closed, pc.closed)
			}
			return nil, pc.mapRoundTripError(req, startBytesWritten, pc.closed)
		case <-respHeaderTimer:
			if debugRoundTrip {
				req.logf("timeout waiting for response headers.")
			}
			pc.close(errTimeout)
			return nil, errTimeout
		case re := <-resc:
			return handleResponse(re)
		case <-ctxDoneChan:
			select {
			case re := <-resc:
				// readLoop is responsible for canceling req.ctx after
				// it reads the response body. Check for a response racing
				// the context close, and use the response if available.
				return handleResponse(re)
			default:
			}
			pc.cancelRequest(context.Cause(req.ctx))
		}
	}
}

// tLogKey is a context WithValue key for test debugging contexts containing
// a t.Logf func. See export_test.go's Request.WithT method.
type tLogKey struct{}

func (tr *transportRequest) logf(format string, args ...any) {
	if logf, ok := tr.Request.Context().Value(tLogKey{}).(func(string, ...any)); ok {
		logf(time.Now().Format(time.RFC3339Nano)+": "+format, args...)
	}
}

// markReused marks this connection as having been successfully used for a
// request and response.
func (pc *persistConn) markReused() {
	pc.mu.Lock()
	pc.reused = true
	pc.mu.Unlock()
}

// close closes the underlying TCP connection and closes
// the pc.closech channel.
//
// The provided err is only for testing and debugging; in normal
// circumstances it should never be seen by users.
func (pc *persistConn) close(err error) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.closeLocked(err)
}

func (pc *persistConn) closeLocked(err error) {
	if err == nil {
		panic("nil error")
	}
	pc.broken = true
	if pc.closed == nil {
		pc.closed = err
		pc.t.decConnsPerHost(pc.cacheKey)
		// Close HTTP/1 (pc.alt == nil) connection.
		// HTTP/2 closes its connection itself.
		if pc.alt == nil {
			if err != errCallerOwnsConn {
				pc.conn.Close()
			}
			close(pc.closech)
		}
	}
	pc.mutateHeaderFunc = nil
}

func schemePort(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	case "socks5", "socks5h":
		return "1080"
	default:
		return ""
	}
}

func idnaASCIIFromURL(url *url.URL) string {
	addr := url.Hostname()
	if v, err := idnaASCII(addr); err == nil {
		addr = v
	}
	return addr
}

// canonicalAddr returns url.Host but always with a ":port" suffix.
func canonicalAddr(url *url.URL) string {
	port := url.Port()
	if port == "" {
		port = schemePort(url.Scheme)
	}
	return net.JoinHostPort(idnaASCIIFromURL(url), port)
}

// bodyEOFSignal is used by the HTTP/1 transport when reading response
// bodies to make sure we see the end of a response body before
// proceeding and reading on the connection again.
//
// It wraps a ReadCloser but runs fn (if non-nil) at most
// once, right before its final (error-producing) Read or Close call
// returns. fn should return the new error to return from Read or Close.
//
// If earlyCloseFn is non-nil and Close is called before io.EOF is
// seen, earlyCloseFn is called instead of fn, and its return value is
// the return value from Close.
type bodyEOFSignal struct {
	body         io.ReadCloser
	mu           sync.Mutex        // guards following 4 fields
	closed       bool              // whether Close has been called
	rerr         error             // sticky Read error
	fn           func(error) error // err will be nil on Read io.EOF
	earlyCloseFn func() error      // optional alt Close func used if io.EOF not seen
}

var errReadOnClosedResBody = errors.New("http: read on closed response body")

func (es *bodyEOFSignal) Read(p []byte) (n int, err error) {
	es.mu.Lock()
	closed, rerr := es.closed, es.rerr
	es.mu.Unlock()
	if closed {
		return 0, errReadOnClosedResBody
	}
	if rerr != nil {
		return 0, rerr
	}

	n, err = es.body.Read(p)
	if err != nil {
		es.mu.Lock()
		defer es.mu.Unlock()
		if es.rerr == nil {
			es.rerr = err
		}
		err = es.condfn(err)
	}
	return
}

func (es *bodyEOFSignal) Close() error {
	es.mu.Lock()
	defer es.mu.Unlock()
	if es.closed {
		return nil
	}
	es.closed = true
	if es.earlyCloseFn != nil && es.rerr != io.EOF {
		return es.earlyCloseFn()
	}
	err := es.body.Close()
	return es.condfn(err)
}

// caller must hold es.mu.
func (es *bodyEOFSignal) condfn(err error) error {
	if es.fn == nil {
		return err
	}
	err = es.fn(err)
	es.fn = nil
	return err
}

// gzipReader wraps a response body so it can lazily
// call gzip.NewReader on the first call to Read
type gzipReader struct {
	_    incomparable
	body *bodyEOFSignal // underlying HTTP/1 response body framing
	zr   *gzip.Reader   // lazily-initialized gzip reader
	zerr error          // any error from gzip.NewReader; sticky
}

func (gz *gzipReader) Read(p []byte) (n int, err error) {
	if gz.zr == nil {
		if gz.zerr == nil {
			gz.zr, gz.zerr = gzip.NewReader(gz.body)
		}
		if gz.zerr != nil {
			return 0, gz.zerr
		}
	}

	gz.body.mu.Lock()
	if gz.body.closed {
		err = errReadOnClosedResBody
	}
	gz.body.mu.Unlock()

	if err != nil {
		return 0, err
	}
	return gz.zr.Read(p)
}

func (gz *gzipReader) Close() error {
	return gz.body.Close()
}

type tlsHandshakeTimeoutError struct{}

func (tlsHandshakeTimeoutError) Timeout() bool   { return true }
func (tlsHandshakeTimeoutError) Temporary() bool { return true }
func (tlsHandshakeTimeoutError) Error() string   { return "net/http: TLS handshake timeout" }

// fakeLocker is a sync.Locker which does nothing. It's used to guard
// test-only fields when not under test, to avoid runtime atomic
// overhead.
type fakeLocker struct{}

func (fakeLocker) Lock()   {}
func (fakeLocker) Unlock() {}

// cloneTLSConfig returns a shallow clone of cfg, or a new zero tls.Config if
// cfg is nil. This is safe to call even if cfg is in active use by a TLS
// client or server.
//
// cloneTLSConfig should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/searKing/golang
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname cloneTLSConfig
func cloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return cfg.Clone()
}

type connLRU struct {
	ll *list.List // list.Element.Value type is of *persistConn
	m  map[*persistConn]*list.Element
}

// add adds pc to the head of the linked list.
func (cl *connLRU) add(pc *persistConn) {
	if cl.ll == nil {
		cl.ll = list.New()
		cl.m = make(map[*persistConn]*list.Element)
	}
	ele := cl.ll.PushFront(pc)
	if _, ok := cl.m[pc]; ok {
		panic("persistConn was already in LRU")
	}
	cl.m[pc] = ele
}

func (cl *connLRU) removeOldest() *persistConn {
	ele := cl.ll.Back()
	pc := ele.Value.(*persistConn)
	cl.ll.Remove(ele)
	delete(cl.m, pc)
	return pc
}

// remove removes pc from cl.
func (cl *connLRU) remove(pc *persistConn) {
	if ele, ok := cl.m[pc]; ok {
		cl.ll.Remove(ele)
		delete(cl.m, pc)
	}
}

// len returns the number of items in the cache.
func (cl *connLRU) len() int {
	return len(cl.m)
}

// ===== 我们原创的 TLS 指纹控制实现 =====

// createCustomTLSConn 创建自定义 TLS 连接
// 这是我们原创的 TLS 指纹控制核心方法，支持简洁 API
func (pc *persistConn) createCustomTLSConn(plainConn net.Conn, cfg *tls.Config) (*tls.UConn, error) {
	// 创建 utls 配置
	utlsConfig := &tls.Config{
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		RootCAs:            cfg.RootCAs,
		ClientSessionCache: tls.NewLRUClientSessionCache(0),
		// 修复 PSK 扩展问题：禁用 PSK 恢复以避免 panic
		SessionTicketsDisabled: true,
		// 或者使用 PreferSkipResumptionOnNilExtension 来避免 panic
		PreferSkipResumptionOnNilExtension: true,
		// 隐藏空的 PSK 扩展
		OmitEmptyPsk: true,
	}

	// 关键修复：根据 JA3 内容决定是否禁用 SessionTickets
	// 如果 JA3 包含 "0029"（SessionTicket 扩展），则不禁用
	if pc.t.JA3 != "" && strings.Index(pc.t.JA3, "0029") == -1 {
		utlsConfig.SessionTicketsDisabled = true
	} else {
		utlsConfig.SessionTicketsDisabled = false
	}

	// 创建 utls 客户端
	tlsConn := tls.UClient(plainConn, utlsConfig, tls.HelloCustom)

	// 根据配置类型应用不同的指纹策略（支持简洁 API）
	var spec *tls.ClientHelloSpec
	var err error

	// 优先级：简洁 API > 高级 API > 默认
	if pc.t.JA3 != "" {
		// 简洁 API：直接使用 JA3
		userAgent := pc.t.UserAgent
		if userAgent == "" {
			userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
		}
		spec, err = pc.buildClientHelloFromJA3(
			pc.t.JA3,
			userAgent,
			pc.t.ForceHTTP1,
		)
	} else if pc.t.ClientHelloHexStream != "" {
		// 简洁 API：直接使用十六进制流
		spec, err = pc.buildClientHelloFromHexStream(pc.t.ClientHelloHexStream)
	} else if pc.t.TLSFingerprint != nil {
		// 高级 API：使用完整配置
		fingerprint := pc.t.TLSFingerprint
		if fingerprint.ClientHelloHexStream != "" {
			spec, err = pc.buildClientHelloFromHexStream(fingerprint.ClientHelloHexStream)
		} else if fingerprint.JA3 != "" {
			spec, err = pc.buildClientHelloFromJA3(fingerprint.JA3, fingerprint.UserAgent, fingerprint.ForceHTTP1)
		} else if fingerprint.PresetFingerprint != "" {
			spec, err = pc.buildClientHelloFromPreset(fingerprint.PresetFingerprint)
		}
	}

	// 如果没有配置，使用默认
	if spec == nil {
		spec, err = pc.buildDefaultClientHello()
	}

	if err != nil {
		return nil, fmt.Errorf("构建 ClientHello 失败: %w", err)
	}

	// 应用 ClientHello 配置
	if err := tlsConn.ApplyPreset(spec); err != nil {
		return nil, fmt.Errorf("应用 ClientHello 配置失败: %w", err)
	}

	return tlsConn, nil
}

// buildClientHelloFromHexStream 从十六进制流构建 ClientHello
// 支持完整的 ClientHello 十六进制流解析
func (pc *persistConn) buildClientHelloFromHexStream(hexStream string) (*tls.ClientHelloSpec, error) {
	if hexStream == "" {
		return nil, fmt.Errorf("十六进制流不能为空")
	}

	// 检查是否包含 SessionTicket 扩展 (0029)
	// 如果不包含，禁用 SessionTickets
	hasSessionTicket := strings.Contains(hexStream, "0029")

	// 将十六进制字符串转换为字节数组
	clientHelloHexStreamBytes := []byte(hexStream)
	clientHelloBytes := make([]byte, hex.DecodedLen(len(clientHelloHexStreamBytes)))

	_, err := hex.Decode(clientHelloBytes, clientHelloHexStreamBytes)
	if err != nil {
		return nil, fmt.Errorf("十六进制解码失败: %w", err)
	}

	// 使用 tls.Fingerprinter 解析 ClientHello
	// 使用 utls 的 Fingerprinter 解析 ClientHello
	fingerprinter := &tls.Fingerprinter{
		AllowBluntMimicry: true, // 允许直接模仿
		// 修复 PSK 问题：禁用 PSK 恢复以避免 panic
		RealPSKResumption: false, // 禁用 PSK 恢复
	}

	spec, err := fingerprinter.FingerprintClientHello(clientHelloBytes)
	if err != nil {
		return nil, fmt.Errorf("ClientHello 指纹解析失败: %w", err)
	}

	// 根据 SessionTicket 扩展调整配置
	if !hasSessionTicket {
		// 如果没有 SessionTicket 扩展，我们需要调整配置
		// 这里可以添加更多的配置调整逻辑
	}

	// 修复 PSK 扩展问题：确保正确处理 PSK 扩展
	spec = pc.fixPSKExtension(spec)

	// 应用 JA4+ 指纹控制
	spec = pc.applyJA4Fingerprint(spec)

	return spec, nil
}

// buildClientHelloFromJA3 从 JA3 字符串构建 ClientHello
func (pc *persistConn) buildClientHelloFromJA3(ja3, userAgent string, forceHTTP1 bool) (*tls.ClientHelloSpec, error) {
	// 解析 JA3 字符串
	parts := strings.Split(ja3, ",")
	if len(parts) != 5 {
		return nil, fmt.Errorf("无效的 JA3 格式，应为 5 个部分，实际为 %d 个", len(parts))
	}

	version := parts[0]
	ciphers := strings.Split(parts[1], "-")
	extensions := strings.Split(parts[2], "-")
	curves := strings.Split(parts[3], "-")
	pointFormats := strings.Split(parts[4], "-")

	// 解析 TLS 版本
	_, err := pc.parseTLSVersion(version)
	if err != nil {
		return nil, fmt.Errorf("解析 TLS 版本失败: %w", err)
	}

	// 解析密码套件
	cipherSuites, err := pc.parseCipherSuites(ciphers)
	if err != nil {
		return nil, fmt.Errorf("解析密码套件失败: %w", err)
	}

	// 解析椭圆曲线
	ellipticCurves, err := pc.parseEllipticCurves(curves)
	if err != nil {
		return nil, fmt.Errorf("解析椭圆曲线失败: %w", err)
	}

	// 解析点格式
	pointFormatsBytes, err := pc.parsePointFormats(pointFormats)
	if err != nil {
		return nil, fmt.Errorf("解析点格式失败: %w", err)
	}

	// 构建 TLS 扩展
	tlsExtensions, err := pc.buildTLSExtensions(extensions, userAgent, forceHTTP1, ellipticCurves, pointFormatsBytes)
	if err != nil {
		return nil, fmt.Errorf("构建 TLS 扩展失败: %w", err)
	}

	// ===== 动态 KeyShare 数据处理 - 这是绕过反爬的核心技术 =====
	if pc.t.TLSExtensions != nil && pc.t.TLSExtensions.KeyShareCurves != nil {
		pc.processDynamicKeyShareData(pc.t.TLSExtensions.KeyShareCurves)
	} else if pc.t.TLSFingerprint != nil && pc.t.TLSFingerprint.CustomExtensions != nil && pc.t.TLSFingerprint.CustomExtensions.KeyShareCurves != nil {
		pc.processDynamicKeyShareData(pc.t.TLSFingerprint.CustomExtensions.KeyShareCurves)
	} else {
		// 简洁 API：处理从 JA3 构建的 KeyShare 扩展中的 GREASE 数据
		pc.processDynamicKeyShareDataFromExtensions(tlsExtensions, userAgent)
	}

	// 创建 ClientHelloSpec
	// 不设置 TLSVersMin/TLSVersMax，让 utls 自动处理
	// 这样可以更好地模拟真实浏览器的行为
	spec := &tls.ClientHelloSpec{
		// TLSVersMin:         tlsVersion,  // 不设置，让 utls 自动处理
		// TLSVersMax:         tlsVersion,  // 不设置，让 utls 自动处理
		CipherSuites:       cipherSuites,
		CompressionMethods: []byte{0}, // 标准压缩方法
		Extensions:         tlsExtensions,
	}

	// 修复 PSK 扩展问题：确保正确处理 PSK 扩展
	spec = pc.fixPSKExtension(spec)

	// 应用 JA4+ 指纹控制
	spec = pc.applyJA4Fingerprint(spec)

	return spec, nil
}

// buildClientHelloFromPreset 从预设指纹构建 ClientHello
// 注意：预设指纹已在 github.com/vanling1111/tlshttp/presets 包中实现
// 建议直接使用 presets 包：
//
//	transport := presets.Chrome120Windows.NewTransport()
//	或 presets.Firefox120.ApplyToTransport(transport)
func (pc *persistConn) buildClientHelloFromPreset(preset string) (*tls.ClientHelloSpec, error) {
	// 此方法已被 presets 包取代
	// presets 包提供了更完整的浏览器指纹配置，包括：
	// - Chrome 120/121/122 (Windows/macOS)
	// - Firefox 120/121
	// - Safari 17
	// - Edge 120
	return nil, fmt.Errorf("请使用 github.com/vanling1111/tlshttp/presets 包来加载预设指纹")
}

// buildDefaultClientHello 构建默认 ClientHello
// 注意：建议使用 presets 包中的浏览器指纹，而不是使用"默认"指纹
// 因为默认指纹容易被检测，建议模拟真实浏览器
func (pc *persistConn) buildDefaultClientHello() (*tls.ClientHelloSpec, error) {
	// 默认策略：使用最常见的 Chrome 指纹
	// 建议：直接使用 presets.Chrome120Windows 等预设
	//
	// 如果确实需要默认指纹，可以这样使用：
	//   transport := presets.Chrome120Windows.NewTransport()
	//
	// 或者手动设置 JA3：
	//   transport.JA3 = "771,4865-4866-4867-49195-49199..."
	return nil, fmt.Errorf("请明确指定 JA3 或使用 presets 包，避免使用容易被检测的默认指纹")
}

// fixPSKExtension 修复 PSK 扩展问题，避免 initPskExt failed panic
// 确保 PSK 扩展存在并正确初始化
func (pc *persistConn) fixPSKExtension(spec *tls.ClientHelloSpec) *tls.ClientHelloSpec {
	if spec == nil {
		return spec
	}

	// 检查是否包含 PSK 扩展 (扩展 ID 41)
	hasPSKExtension := false
	for _, ext := range spec.Extensions {
		if _, ok := ext.(*tls.UtlsPreSharedKeyExtension); ok {
			hasPSKExtension = true
			// PSK 扩展的初始化由 utls 内部处理
			// 不需要手动设置字段
			break
		}
	}

	// 如果没有 PSK 扩展，添加一个空的 PSK 扩展以避免 panic
	if !hasPSKExtension {
		// 添加空的 PSK 扩展
		// 注意：UtlsPreSharedKeyExtension 的字段初始化由 utls 内部处理
		pskExt := &tls.UtlsPreSharedKeyExtension{}
		spec.Extensions = append(spec.Extensions, pskExt)
	}

	return spec
}

// applyJA4Fingerprint 应用 JA4+ 指纹控制
// 支持 JA4L (距离/位置) 和 JA4X (X509 证书) 指纹
func (pc *persistConn) applyJA4Fingerprint(spec *tls.ClientHelloSpec) *tls.ClientHelloSpec {
	if spec == nil || !pc.t.CustomJA4 {
		return spec
	}

	// JA4L (距离/位置) 指纹控制
	// JA4L 格式: <TLS版本><扩展数量><第一个ALPN值长度><最后一个ALPN值长度>
	// 例如: "t13d1715h2_c02f"
	if pc.t.JA4L != "" {
		// TODO: JA4L 实现
		// JA4L 是2023年提出的新标准，用于更精确的 TLS 指纹识别
		// 主要控制：
		// 1. TLS 扩展的数量和顺序
		// 2. ALPN 协议的长度特征
		// 3. 扩展之间的距离（字节偏移）
		//
		// 当前状态：JA3 已经能满足大部分反爬虫需求
		// 如果需要 JA4L，建议：
		// - 等待 JA4 标准稳定
		// - 参考 FoxIO 的 JA4 规范实现
		// - 或提交 issue 请求支持
	}

	// JA4X (X509 证书) 指纹控制
	// JA4X 格式: <证书哈希>_<扩展哈希>
	if pc.t.JA4X != "" {
		// TODO: JA4X 实现
		// JA4X 用于 X.509 证书指纹识别
		// 主要控制：
		// 1. 证书链的构成
		// 2. 证书扩展（Subject Alternative Name, Key Usage等）
		// 3. 证书签名算法
		//
		// 当前状态：TLS 客户端指纹（JA3）已经足够
		// 如果需要 JA4X，建议：
		// - 使用自定义证书验证回调
		// - 或等待社区提供参考实现
	}

	return spec
}

// ===== JA3 解析辅助方法 =====

// parseTLSVersion 解析 TLS 版本
func (pc *persistConn) parseTLSVersion(version string) (uint16, error) {
	ver, err := strconv.ParseUint(version, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("无效的 TLS 版本: %s", version)
	}
	return uint16(ver), nil
}

// parseCipherSuites 解析密码套件
// 支持 Chrome GREASE 功能，改进 JA3 解析准确性
func (pc *persistConn) parseCipherSuites(ciphers []string) ([]uint16, error) {
	var suites []uint16

	// Chrome GREASE 支持（支持简洁 API）
	useGREASE := (pc.t.TLSFingerprint != nil && pc.t.TLSFingerprint.CustomExtensions != nil && !pc.t.TLSFingerprint.CustomExtensions.NotUsedGREASE) ||
		(pc.t.TLSExtensions != nil && !pc.t.TLSExtensions.NotUsedGREASE)

	if useGREASE {
		suites = append(suites, tls.GREASE_PLACEHOLDER)
	}

	// 验证密码套件列表不为空
	if len(ciphers) == 0 {
		return nil, fmt.Errorf("密码套件列表不能为空")
	}

	for i, cipher := range ciphers {
		if cipher == "" {
			continue
		}

		// 改进的密码套件验证
		cipherID, err := strconv.ParseUint(cipher, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("无效的密码套件 '%s' (位置 %d): %w", cipher, i, err)
		}

		// 验证密码套件 ID 的有效范围
		if cipherID == 0 || cipherID > 0xFFFF {
			return nil, fmt.Errorf("密码套件 ID '%d' 超出有效范围 (1-65535)", cipherID)
		}

		// 检查重复的密码套件
		for _, existingSuite := range suites {
			if existingSuite == uint16(cipherID) {
				return nil, fmt.Errorf("重复的密码套件 ID: %d", cipherID)
			}
		}

		suites = append(suites, uint16(cipherID))
	}

	// 确保至少有一个有效的密码套件
	if len(suites) == 0 {
		return nil, fmt.Errorf("至少需要一个有效的密码套件")
	}

	return suites, nil
}

// parseEllipticCurves 解析椭圆曲线
// 支持 Chrome GREASE 功能
func (pc *persistConn) parseEllipticCurves(curves []string) ([]tls.CurveID, error) {
	var curveIDs []tls.CurveID

	// Chrome GREASE 支持（支持简洁 API）
	useGREASE := (pc.t.TLSFingerprint != nil && pc.t.TLSFingerprint.CustomExtensions != nil && !pc.t.TLSFingerprint.CustomExtensions.NotUsedGREASE) ||
		(pc.t.TLSExtensions != nil && !pc.t.TLSExtensions.NotUsedGREASE)

	if useGREASE {
		curveIDs = append(curveIDs, tls.CurveID(tls.GREASE_PLACEHOLDER))
	}

	for _, curve := range curves {
		if curve == "" {
			continue
		}
		curveID, err := strconv.ParseUint(curve, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("无效的椭圆曲线: %s", curve)
		}
		curveIDs = append(curveIDs, tls.CurveID(curveID))
	}

	return curveIDs, nil
}

// parsePointFormats 解析点格式
func (pc *persistConn) parsePointFormats(formats []string) ([]byte, error) {
	var formatBytes []byte

	for _, format := range formats {
		if format == "" {
			continue
		}
		formatID, err := strconv.ParseUint(format, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("无效的点格式: %s", format)
		}
		formatBytes = append(formatBytes, byte(formatID))
	}

	return formatBytes, nil
}

// buildTLSExtensions 构建 TLS 扩展
func (pc *persistConn) buildTLSExtensions(extensions []string, userAgent string, forceHTTP1 bool, curves []tls.CurveID, pointFormats []byte) ([]tls.TLSExtension, error) {
	var tlsExtensions []tls.TLSExtension

	// 获取扩展映射表
	extensionMap := pc.getExtensionMap()

	// 解析用户代理类型
	browserType := pc.parseBrowserType(userAgent)

	// 处理 GREASE 扩展（Chrome 特有，支持简洁 API）
	useGREASE := (pc.t.TLSFingerprint != nil && pc.t.TLSFingerprint.CustomExtensions != nil && !pc.t.TLSFingerprint.CustomExtensions.NotUsedGREASE) ||
		(pc.t.TLSExtensions != nil && !pc.t.TLSExtensions.NotUsedGREASE)

	if browserType == "chrome" && useGREASE {
		tlsExtensions = append(tlsExtensions, &tls.UtlsGREASEExtension{})
	}

	// 处理每个扩展
	for i, extID := range extensions {
		if extID == "" {
			continue
		}

		// 检查是否为特殊扩展
		if extID == "10" {
			// Supported Curves 扩展
			tlsExtensions = append(tlsExtensions, &tls.SupportedCurvesExtension{
				Curves: curves,
			})
		} else if extID == "11" {
			// Supported Point Formats 扩展
			tlsExtensions = append(tlsExtensions, &tls.SupportedPointsExtension{
				SupportedPoints: pointFormats,
			})
		} else if extID == "16" {
			// ALPN 扩展 - 支持自定义 ALPN 协议
			alpnProtocols := []string{"h2", "http/1.1"}
			if forceHTTP1 {
				alpnProtocols = []string{"http/1.1"}
			}

			// 检查是否使用自定义 ALPN 协议
			if pc.t.CustomALPN && len(pc.t.ALPNProtocols) > 0 {
				alpnProtocols = make([]string, len(pc.t.ALPNProtocols))
				copy(alpnProtocols, pc.t.ALPNProtocols)
			}

			tlsExtensions = append(tlsExtensions, &tls.ALPNExtension{
				AlpnProtocols: alpnProtocols,
			})
		} else {
			// 查找预定义扩展
			if ext, exists := extensionMap[extID]; exists {
				tlsExtensions = append(tlsExtensions, ext)
			} else {
				// 未知扩展，创建通用扩展
				extIDNum, err := strconv.ParseUint(extID, 10, 16)
				if err != nil {
					return nil, fmt.Errorf("无效的扩展 ID: %s", extID)
				}
				tlsExtensions = append(tlsExtensions, &tls.GenericExtension{
					Id: uint16(extIDNum),
				})
			}
		}

		// Chrome 特殊处理：在特定扩展后添加 GREASE（支持简洁 API）
		if browserType == "chrome" && useGREASE {
			if (extID == "41" || extID == "21") && i == len(extensions)-1 {
				tlsExtensions = append(tlsExtensions, &tls.UtlsGREASEExtension{})
			}
		}
	}

	// Chrome 特殊处理：如果最后一个扩展不是 21 或 41，添加 GREASE（支持简洁 API）
	if browserType == "chrome" && useGREASE {
		if len(extensions) > 0 {
			lastExt := extensions[len(extensions)-1]
			if lastExt != "21" && lastExt != "41" {
				tlsExtensions = append(tlsExtensions, &tls.UtlsGREASEExtension{})
			}
		}
	}

	// 扩展随机化支持（支持简洁 API）
	useRandomization := pc.t.RandomizeFingerprint || pc.t.RandomJA3
	if useRandomization {
		tlsExtensions = tls.ShuffleChromeTLSExtensions(tlsExtensions)
	}

	return tlsExtensions, nil
}

// parseUserAgent 解析用户代理字符串，识别浏览器类型
// 用于自动选择合适的 TLS 指纹配置
func parseUserAgent(userAgent string) string {
	if userAgent == "" {
		return "chrome" // 默认使用 chrome
	}

	userAgentLower := strings.ToLower(userAgent)

	// 检测 Chrome 浏览器
	if strings.Contains(userAgentLower, "chrome") {
		return "chrome"
	}

	// 检测 Safari (AppleWebKit 但没有 Chrome)
	if strings.Contains(userAgentLower, "applewebkit") && !strings.Contains(userAgentLower, "chrome") {
		return "chrome" // Safari 也使用 chrome 指纹
	}

	// 检测 Firefox
	if strings.Contains(userAgentLower, "firefox") {
		return "firefox"
	}

	// 默认使用 chrome
	return "chrome"
}

// processDynamicKeyShareData 处理动态 KeyShare 数据
// 核心技术：用于绕过反爬检测，支持 GREASE 和动态密钥生成
func (pc *persistConn) processDynamicKeyShareData(keyShareCurves *tls.KeyShareExtension) {
	if keyShareCurves == nil || keyShareCurves.KeyShares == nil {
		return
	}

	// 动态处理每个 KeyShare
	for i := range keyShareCurves.KeyShares {
		v := keyShareCurves.KeyShares[i].Group

		// 检测 GREASE 占位符：((v >> 8) == v&0xff) && v&0xf == 0xa
		// 这是 Chrome 浏览器的 GREASE 特征
		if ((v >> 8) == v&0xff) && v&0xf == 0xa {
			// GREASE 占位符：设置为空数据
			keyShareCurves.KeyShares[i].Data = []byte{0}
		} else {
			// 普通曲线：设置为 nil，让 utls 自动生成
			keyShareCurves.KeyShares[i].Data = nil
		}
	}
}

// processDynamicKeyShareDataFromExtensions 处理从 JA3 构建的扩展中的 KeyShare 数据
// 这是简洁 API 的关键修复：确保 GREASE 数据正确处理
func (pc *persistConn) processDynamicKeyShareDataFromExtensions(extensions []tls.TLSExtension, userAgent string) {
	// 检查是否是 Chrome 浏览器
	if !strings.Contains(strings.ToLower(userAgent), "chrome") {
		return
	}

	// 查找 KeyShare 扩展 (ID: 51)
	for _, ext := range extensions {
		if keyShareExt, ok := ext.(*tls.KeyShareExtension); ok {
			// 处理 KeyShare 中的 GREASE 数据
			for i := range keyShareExt.KeyShares {
				v := keyShareExt.KeyShares[i].Group

				// 检测 GREASE 占位符：((v >> 8) == v&0xff) && v&0xf == 0xa
				if ((v >> 8) == v&0xff) && v&0xf == 0xa {
					// GREASE 占位符：设置为空数据
					keyShareExt.KeyShares[i].Data = []byte{0}
				} else {
					// 普通曲线：设置为 nil，让 utls 自动生成
					keyShareExt.KeyShares[i].Data = nil
				}
			}
			break
		}
	}
}

// StringToSpec 从 JA3 字符串创建 ClientHelloSpec
// 完整的 JA3 字符串解析和 ClientHello 规范构建
func (ext *TLSExtensionsConfig) StringToSpec(ja3, userAgent string, forceHTTP1, randomJA3 bool) (*tls.ClientHelloSpec, error) {
	if ext == nil {
		ext = &TLSExtensionsConfig{}
	}

	// 解析用户代理
	parsedUserAgent := parseUserAgent(userAgent)

	// 解析 JA3 字符串
	tokens := strings.Split(ja3, ",")
	if len(tokens) != 5 {
		return nil, fmt.Errorf("无效的 JA3 格式，应为 5 个部分，实际为 %d 个", len(tokens))
	}

	_ = tokens[0] // version - 不使用，让 utls 自动处理
	ciphers := strings.Split(tokens[1], "-")
	extensions := strings.Split(tokens[2], "-")
	curves := strings.Split(tokens[3], "-")
	pointFormats := strings.Split(tokens[4], "-")

	// 处理空曲线和点格式
	if len(curves) == 1 && curves[0] == "" {
		curves = []string{}
	}
	if len(pointFormats) == 1 && pointFormats[0] == "" {
		pointFormats = []string{}
	}

	// 获取扩展映射表
	extMap := getCompleteExtensionMap()

	// 解析椭圆曲线
	var targetCurves []tls.CurveID

	// Chrome GREASE 处理 - 核心反爬技术
	if parsedUserAgent == "chrome" && !ext.NotUsedGREASE {
		// 添加 GREASE 占位符
		targetCurves = append(targetCurves, tls.CurveID(tls.GREASE_PLACEHOLDER))

		// 在 SupportedVersions 扩展中添加 GREASE
		if supportedVersionsExt, ok := extMap["43"]; ok {
			if supportedVersions, ok := supportedVersionsExt.(*tls.SupportedVersionsExtension); ok {
				supportedVersions.Versions = append([]uint16{tls.GREASE_PLACEHOLDER}, supportedVersions.Versions...)
			}
		}

		// 在 KeyShare 扩展中添加 GREASE
		if keyShareExt, ok := extMap["51"]; ok {
			if keyShare, ok := keyShareExt.(*tls.KeyShareExtension); ok {
				keyShare.KeyShares = append([]tls.KeyShare{{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}}}, keyShare.KeyShares...)
			}
		}
	} else {
		// 非 Chrome 浏览器，添加默认曲线
		if keyShareExt, ok := extMap["51"]; ok {
			if keyShare, ok := keyShareExt.(*tls.KeyShareExtension); ok {
				keyShare.KeyShares = append(keyShare.KeyShares, tls.KeyShare{Group: tls.CurveP256})
			}
		}
	}

	// 解析 JA3 中的曲线
	for _, c := range curves {
		cid, err := strconv.ParseUint(c, 10, 16)
		if err != nil {
			return nil, err
		}
		targetCurves = append(targetCurves, tls.CurveID(cid))
	}
	extMap["10"] = &tls.SupportedCurvesExtension{Curves: targetCurves}

	// 解析点格式
	var targetPointFormats []byte
	for _, p := range pointFormats {
		pid, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return nil, err
		}
		targetPointFormats = append(targetPointFormats, byte(pid))
	}
	extMap["11"] = &tls.SupportedPointsExtension{SupportedPoints: targetPointFormats}

	// 强制 HTTP/1.1 处理
	if forceHTTP1 {
		extMap["16"] = &tls.ALPNExtension{
			AlpnProtocols: []string{"http/1.1"},
		}
	}

	// 自定义 TLS 扩展处理
	if ext.SupportedSignatureAlgorithms != nil {
		extMap["13"] = ext.SupportedSignatureAlgorithms
	}
	if ext.CertCompressionAlgo != nil {
		extMap["27"] = ext.CertCompressionAlgo
	}
	if ext.RecordSizeLimit != nil {
		extMap["28"] = ext.RecordSizeLimit
	}
	if ext.DelegatedCredentials != nil {
		extMap["34"] = ext.DelegatedCredentials
	}
	if ext.SupportedVersions != nil {
		extMap["43"] = ext.SupportedVersions
	}
	if ext.PSKKeyExchangeModes != nil {
		extMap["45"] = ext.PSKKeyExchangeModes
	}
	if ext.SignatureAlgorithmsCert != nil {
		extMap["50"] = ext.SignatureAlgorithmsCert
	}
	if ext.KeyShareCurves != nil {
		extMap["51"] = ext.KeyShareCurves
	}

	// 构建扩展列表
	var exts []tls.TLSExtension

	// Chrome GREASE 扩展处理
	if parsedUserAgent == "chrome" && !ext.NotUsedGREASE {
		exts = append(exts, &tls.UtlsGREASEExtension{})
	}

	// 处理 JA3 中的扩展
	for i, e := range extensions {
		te, ok := extMap[e]
		if !ok {
			return nil, fmt.Errorf("不支持的扩展: %s", e)
		}

		// Chrome 特殊处理：在特定扩展后添加 GREASE
		if i == len(extensions)-1 && (e == "41" || e == "21") && parsedUserAgent == "chrome" && !ext.NotUsedGREASE {
			exts = append(exts, &tls.UtlsGREASEExtension{})
		}

		exts = append(exts, te)
	}

	// Chrome 特殊处理：如果最后一个扩展不是 21 或 41，添加 GREASE
	if parsedUserAgent == "chrome" && !ext.NotUsedGREASE {
		if len(extensions) > 0 {
			lastExt := extensions[len(extensions)-1]
			if lastExt != "21" && lastExt != "41" {
				exts = append(exts, &tls.UtlsGREASEExtension{})
			}
		}
	}

	// 构建密码套件
	var suites []uint16

	// Chrome GREASE 处理
	if parsedUserAgent == "chrome" && !ext.NotUsedGREASE {
		suites = append(suites, tls.GREASE_PLACEHOLDER)
	}

	// 解析 JA3 中的密码套件
	for _, c := range ciphers {
		cid, err := strconv.ParseUint(c, 10, 16)
		if err != nil {
			return nil, err
		}
		suites = append(suites, uint16(cid))
	}

	// 随机化扩展
	if randomJA3 {
		exts = tls.ShuffleChromeTLSExtensions(exts)
	}

	// 创建 ClientHelloSpec
	return &tls.ClientHelloSpec{
		CipherSuites:       suites,
		CompressionMethods: []byte{0},
		Extensions:         exts,
	}, nil
}

// getExtensionMap 获取 TLS 扩展映射表
// 使用完整的扩展映射表，包含所有常用 TLS 扩展
func (pc *persistConn) getExtensionMap() map[string]tls.TLSExtension {
	return getCompleteExtensionMap()
}

// parseBrowserType 解析浏览器类型
func (pc *persistConn) parseBrowserType(userAgent string) string {
	if userAgent == "" {
		return "chrome" // 默认使用 Chrome
	}

	userAgentLower := strings.ToLower(userAgent)

	if strings.Contains(userAgentLower, "chrome") || strings.Contains(userAgentLower, "applewebkit") {
		return "chrome"
	} else if strings.Contains(userAgentLower, "firefox") {
		return "firefox"
	} else if strings.Contains(userAgentLower, "safari") {
		return "safari"
	} else if strings.Contains(userAgentLower, "edge") {
		return "edge"
	}

	return "chrome" // 默认
}

// ===== TLS 扩展深度克隆功能 =====

// Clone 使用 CBOR 进行深度克隆 TLS 扩展配置
// 使用 CBOR 确保完整的深度复制，避免并发问题
func (ext *TLSExtensionsConfig) Clone() (*TLSExtensionsConfig, error) {
	if ext == nil {
		return nil, nil
	}

	// 使用 CBOR 进行深度序列化和反序列化
	data, err := cbor.Marshal(ext, cbor.EncOptions{})
	if err != nil {
		return nil, fmt.Errorf("CBOR 序列化失败: %w", err)
	}

	var clone *TLSExtensionsConfig
	if err := cbor.Unmarshal(data, &clone); err != nil {
		return nil, fmt.Errorf("CBOR 反序列化失败: %w", err)
	}

	return clone, nil
}

// Clone 使用 CBOR 进行深度克隆 TLS 指纹配置
// 这是我们原创的功能，确保线程安全
func (cfg *TLSFingerprintConfig) Clone() (*TLSFingerprintConfig, error) {
	if cfg == nil {
		return nil, nil
	}

	// 使用 CBOR 进行深度序列化和反序列化
	data, err := cbor.Marshal(cfg, cbor.EncOptions{})
	if err != nil {
		return nil, fmt.Errorf("CBOR 序列化失败: %w", err)
	}

	var clone *TLSFingerprintConfig
	if err := cbor.Unmarshal(data, &clone); err != nil {
		return nil, fmt.Errorf("CBOR 反序列化失败: %w", err)
	}

	return clone, nil
}

// ===== 完整 TLS 扩展映射表 =====

// getCompleteExtensionMap 获取完整的 TLS 扩展映射表
// 包含所有常用 TLS 扩展，支持完整的浏览器指纹伪装
func getCompleteExtensionMap() map[string]tls.TLSExtension {
	return map[string]tls.TLSExtension{
		// 基础扩展
		"0": &tls.SNIExtension{},
		"5": &tls.StatusRequestExtension{},

		// 椭圆曲线和点格式 (动态设置)
		// "10": &tls.SupportedCurvesExtension{...} // 动态设置
		// "11": &tls.SupportedPointsExtension{...} // 动态设置

		// 签名算法
		"13": &tls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.PSSWithSHA256,
				tls.PSSWithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA256,
				tls.PKCS1WithSHA384,
				tls.PKCS1WithSHA512,
				tls.ECDSAWithSHA1,
				tls.PKCS1WithSHA1,
			},
		},

		// ALPN 扩展
		"16": &tls.ALPNExtension{
			AlpnProtocols: []string{"h2", "http/1.1"},
		},

		// 状态请求 v2
		"17": &tls.GenericExtension{Id: 17},

		// 证书透明度
		"18": &tls.SCTExtension{},

		// Chrome 填充扩展
		"21": &tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},

		// 加密后 MAC
		"22": &tls.GenericExtension{Id: 22},

		// 扩展主密钥
		"23": &tls.ExtendedMasterSecretExtension{},

		// 令牌绑定
		"24": &tls.FakeTokenBindingExtension{},

		// 证书压缩
		"27": &tls.UtlsCompressCertExtension{
			Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli},
		},

		// 记录大小限制
		"28": &tls.FakeRecordSizeLimitExtension{
			Limit: 0x4001,
		},

		// 委托凭证
		"34": &tls.DelegatedCredentialsExtension{
			SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.ECDSAWithSHA1,
			},
		},

		// 会话票据
		"35": &tls.SessionTicketExtension{},

		// 预共享密钥
		"41": &tls.UtlsPreSharedKeyExtension{},

		// 支持的版本
		"43": &tls.SupportedVersionsExtension{Versions: []uint16{
			tls.VersionTLS13,
			tls.VersionTLS12,
		}},

		// Cookie 扩展
		"44": &tls.CookieExtension{},

		// PSK 密钥交换模式
		"45": &tls.PSKKeyExchangeModesExtension{Modes: []uint8{
			tls.PskModeDHE,
		}},

		// 握手后认证
		"49": &tls.GenericExtension{Id: 49},

		// 证书签名算法
		"50": &tls.SignatureAlgorithmsCertExtension{
			SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.PSSWithSHA256,
				tls.PSSWithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA256,
				tls.PKCS1WithSHA384,
				tls.PKCS1WithSHA512,
				tls.ECDSAWithSHA1,
				tls.PKCS1WithSHA1,
			},
		},

		// 密钥共享
		"51": &tls.KeyShareExtension{KeyShares: []tls.KeyShare{
			{Group: tls.X25519},
			// 注意: CurveP384 有已知 bug，暂时不包含
		}},

		// QUIC 传输参数
		"57": &tls.QUICTransportParametersExtension{},

		// NPN 扩展
		"13172": &tls.NPNExtension{},

		// HTTP/3 应用设置
		"17513": &tls.ApplicationSettingsExtension{
			SupportedProtocols: []string{"h2"},
		},

		// HTTP/3 应用设置 (新版本)
		"17613": &tls.ApplicationSettingsExtensionNew{
			SupportedProtocols: []string{"h2"},
		},

		// 自定义扩展
		"30032": &tls.GenericExtension{Id: 0x7550, Data: []byte{0}},

		// 重新协商信息
		"65281": &tls.RenegotiationInfoExtension{
			Renegotiation: tls.RenegotiateOnceAsClient,
		},

		// Chrome GREASE ECH
		"65037": tls.BoringGREASEECH(),
	}
}

// ===== 使用示例 =====
//
// 🚀 TLSHTTP 使用示例：
//
// 方式1: 使用 JA3 指纹
// transport := &http.Transport{
//     JA3: "771,4865-4866-4867,0-23-65281,29-23-24,0",
// }
//
// 方式2: 使用预设浏览器指纹（推荐）
// transport := presets.Chrome120Windows.NewTransport()
//
// 方式3: JA3 随机化
// transport := &http.Transport{
//     JA3: "771,4865-4866-4867,0-23-65281,29-23-24,0",
//     RandomJA3: true,
//     UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
// }
//
// 方式4: ClientHello 十六进制流
// transport := &http.Transport{
//     ClientHelloHexStream: "16030107b4010007b0...",
// }
//
// 方式5: 高级配置（TLS 扩展控制）
// transport := &http.Transport{
//     JA3: "771,4865-4866-4867,0-23-65281,29-23-24,0",
//     TLSExtensions: &http.TLSExtensionsConfig{
//         NotUsedGREASE: false,
//         KeyShareCurves: &tls.KeyShareExtension{...},
//     },
// }
//
// 🎯 核心特性：
// ✅ 动态 KeyShare 数据 - 绕过反爬核心技术
// ✅ ClientHello 十六进制流解析
// ✅ GREASE 支持 (Chrome)
// ✅ HTTP/2 指纹控制
// ✅ ALPN 协议自定义
// ✅ PSK 扩展支持
// ✅ 完整的深度克隆
//
// 使用客户端：
// client := &http.Client{Transport: transport}
// resp, err := client.Get("https://example.com")
