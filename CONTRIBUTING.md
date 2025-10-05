# 贡献指南 (Contributing Guide)

感谢您对 tlshttp 项目的关注！我们欢迎所有形式的贡献。

[English](#english) | [中文](#中文)

---

## 中文

### 🤝 如何贡献

我们欢迎以下类型的贡献：

- 🐛 报告 Bug
- 💡 提出新功能建议
- 📝 改进文档
- 🔧 提交代码修复
- ✨ 添加新功能
- 🧪 添加测试用例
- ⚡ 性能优化

### 📋 贡献流程

1. **Fork 项目**
   ```bash
   # 在 GitHub 上 fork 本项目
   git clone https://github.com/YOUR_USERNAME/tlshttp.git
   cd tlshttp
   ```

2. **创建分支**
   ```bash
   git checkout -b feature/your-feature-name
   # 或
   git checkout -b fix/your-bug-fix
   ```

3. **进行开发**
   - 遵循项目代码规范
   - 添加必要的测试
   - 更新相关文档
   - 确保所有测试通过

4. **提交代码**
   ```bash
   git add .
   git commit -m "feat: 添加新功能 XXX"
   # 或
   git commit -m "fix: 修复 Bug XXX"
   ```

5. **推送到 GitHub**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **创建 Pull Request**
   - 在 GitHub 上创建 PR
   - 填写 PR 模板
   - 等待代码审查

### 📝 提交信息规范

我们使用 [Conventional Commits](https://www.conventionalcommits.org/) 规范：

- `feat:` 新功能
- `fix:` Bug 修复
- `docs:` 文档更新
- `style:` 代码格式调整（不影响功能）
- `refactor:` 代码重构
- `perf:` 性能优化
- `test:` 测试相关
- `chore:` 构建/工具相关

**示例：**
```
feat: 添加 JA4X 指纹支持
fix: 修复 PSK 扩展 panic 问题
docs: 更新 README 使用示例
test: 添加 TLS 扩展解析测试
```

### 🧪 测试要求

**所有代码必须包含测试！**

```bash
# 运行所有测试
go test ./...

# 运行特定包的测试
go test -v ./presets

# 运行性能测试
go test -bench=. -benchtime=2s

# 查看测试覆盖率
go test -cover ./...
```

**测试覆盖率要求：**
- 新增代码：>= 80%
- 原创核心代码：~100%

### 📖 代码规范

1. **Go 官方规范**
   - 遵循 [Effective Go](https://golang.org/doc/effective_go.html)
   - 使用 `gofmt` 格式化代码
   - 通过 `golint` 检查

2. **注释规范**
   - 所有导出函数必须有文档注释
   - 注释使用中文（本项目特色）
   - 复杂逻辑必须添加说明注释

3. **命名规范**
   - 变量/函数：驼峰命名 `getUserAgent`
   - 常量：大写下划线 `MAX_RETRY_COUNT`
   - 私有：小写开头 `parseJA3`
   - 公开：大写开头 `NewClient`

4. **文件组织**
   ```
   tlshttp/
   ├── transport.go          # Transport 实现
   ├── transport_test.go     # Transport 测试
   ├── tlsfingerprint_test.go # TLS 指纹测试
   ├── presets/              # 预设指纹
   │   ├── fingerprints.go
   │   └── fingerprints_test.go
   └── docs/                 # 文档
   ```

### 🐛 报告 Bug

使用 GitHub Issues 报告 Bug，请包含：

- **Bug 描述**：清晰描述问题
- **复现步骤**：详细的复现步骤
- **期望行为**：期望的正确行为
- **实际行为**：实际发生的错误行为
- **环境信息**：
  - Go 版本：`go version`
  - 操作系统：Windows/Linux/macOS
  - tlshttp 版本
- **最小复现代码**：最简单的复现代码

### 💡 功能建议

使用 GitHub Issues 提出功能建议，请包含：

- **功能描述**：清晰描述建议的功能
- **使用场景**：为什么需要这个功能
- **实现建议**：如何实现（可选）
- **参考资料**：相关的文档/项目（可选）

### 🔍 代码审查标准

提交的代码需要满足：

- ✅ 通过所有测试
- ✅ 代码覆盖率达标
- ✅ 遵循代码规范
- ✅ 包含完整文档注释
- ✅ 更新相关文档
- ✅ 没有明显的性能问题
- ✅ 没有安全漏洞

### 📚 开发环境设置

```bash
# 1. 克隆项目
git clone https://github.com/vanling1111/tlshttp.git
cd tlshttp

# 2. 安装依赖
go mod download

# 3. 运行测试
go test ./...

# 4. 运行示例
cd examples
go run presets_usage.go
```

### ❓ 获取帮助

- 📖 查看 [文档](./docs/)
- 💬 提交 [Issue](https://github.com/vanling1111/tlshttp/issues)
- 📧 联系维护者

### 🙏 致谢

感谢所有贡献者！

---

## English

### 🤝 How to Contribute

We welcome the following types of contributions:

- 🐛 Report bugs
- 💡 Suggest new features
- 📝 Improve documentation
- 🔧 Submit bug fixes
- ✨ Add new features
- 🧪 Add test cases
- ⚡ Performance optimization

### 📋 Contribution Workflow

1. **Fork the project**
   ```bash
   git clone https://github.com/YOUR_USERNAME/tlshttp.git
   cd tlshttp
   ```

2. **Create a branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Develop**
   - Follow code standards
   - Add necessary tests
   - Update documentation
   - Ensure all tests pass

4. **Commit**
   ```bash
   git commit -m "feat: add new feature XXX"
   ```

5. **Push**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create Pull Request**

### 📝 Commit Message Convention

We use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `test:` Tests
- `refactor:` Refactoring
- `perf:` Performance

### 🧪 Testing Requirements

**All code must include tests!**

```bash
go test ./...
go test -cover ./...
```

**Coverage requirements:**
- New code: >= 80%
- Core code: ~100%

### 🐛 Bug Reports

Please include:
- Bug description
- Reproduction steps
- Expected behavior
- Environment info

### 💡 Feature Requests

Please include:
- Feature description
- Use case
- Implementation suggestion (optional)

### ❓ Get Help

- 📖 Read [Documentation](./docs/)
- 💬 Open an [Issue](https://github.com/vanling1111/tlshttp/issues)

### 🙏 Acknowledgments

Thank you to all contributors!

