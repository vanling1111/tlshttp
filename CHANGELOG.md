# 更新日志 (Changelog)

本项目的所有重要更改都将记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

---

## [Unreleased]

### ✨ 新增

**核心功能**
- 完整的 TLS 指纹控制系统
- JA3 指纹支持
- JA4L/JA4X 指纹框架
- HTTP/2 Settings 完整控制
- 预设浏览器指纹库 (Chrome, Firefox, Safari, Edge)
- ALPN 协议自定义控制
- PSK 扩展完整支持
- Go 1.25 兼容性

**Presets 包**
- Chrome 120/117/133 Windows 指纹
- Firefox 120 Windows 指纹
- Safari iOS 17 指纹
- Edge 120 Windows 指纹
- 通过名称获取预设指纹

### 🔧 修复

**核心问题修复**
- ✅ 修复 PSK 扩展 panic 问题（initPskExt failed）
- ✅ 实现自定义 PSK 扩展完整支持
- ✅ 修复内存泄漏问题（连接池管理、map 初始化）
- ✅ 修复并发 EOF 错误（连接管理优化）
- ✅ 改进 JA3 解析准确性（验证和错误处理）

**深度克隆修复**
- ✅ 修复 Transport.Clone() 不深拷贝自定义字段的严重缺陷
- ✅ 添加 map 初始化检查，防止 nil map panic
- ✅ 改进错误处理和验证
- ✅ 修复 cookiejar 导入路径兼容性

### ⚡ 优化

- 使用 CBOR 实现高效深度克隆 (~870 ns/op)
- 优化连接池管理
- 改进并发安全性
- 优化内存使用
- parseUserAgent 性能优化 (~139 ns/op)

### 📚 文档

- 完整的 README.md（中英文）
- 详细的 API 文档
- 使用示例和最佳实践
- 贡献指南 (CONTRIBUTING.md)
- 行为准则 (CODE_OF_CONDUCT.md)
- 安全政策 (SECURITY.md)
- 开发指南 (docs/)

### 🧪 测试

**测试覆盖**
- 49+ 单元测试
- 8+ 性能测试
- ~100% 原创代码覆盖率
- 完整的 presets 包测试
- cookiejar 兼容性测试

**测试文件**
- `transport_test.go` - Transport 基础测试
- `tlsfingerprint_test.go` - TLS 指纹控制测试
- `presets/fingerprints_test.go` - Presets 包测试

### 🎯 项目优势

| 维度 | 说明 |
|------|------|
| **稳定性** | 修复 PSK、内存泄漏、并发 EOF 等关键问题 |
| **测试覆盖** | ~100% 测试覆盖率，确保代码质量 |
| **功能完整** | ALPN 控制、JA4 框架、预设指纹库 |
| **深度克隆** | CBOR 完整深拷贝，避免并发问题 |
| **文档完善** | 完整的文档、示例和 CI/CD 流程 |

---

## [0.1.0] - 2024-10-05

### 🎉 首次发布

**核心特性**
- 基于 Go 1.25 net/http
- 集成 utls 库实现 TLS 指纹控制
- 完整的 JA3 支持
- HTTP/2 指纹控制
- 预设浏览器指纹库

**性能指标**
- TLSExtensionsConfig.Clone(): 870.7 ns/op
- HTTP2Settings.Clone(): 690.9 ns/op
- parseUserAgent(): 139.3 ns/op
- Transport.Clone(): 185.0 ns/op

**测试质量**
- 49+ 单元测试
- 100% 原创代码覆盖
- 8 个性能测试
- 所有测试通过

---

## 版本说明

- **主版本号**：不兼容的 API 修改
- **次版本号**：向下兼容的功能性新增
- **修订号**：向下兼容的问题修正

---

[Unreleased]: https://github.com/vanling1111/tlshttp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vanling1111/tlshttp/releases/tag/v0.1.0

