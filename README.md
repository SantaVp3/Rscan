# 🔒 Rscan - 综合网络安全扫描器

一款基于Rust开发的网络安全扫描工具，专注于内网环境的安全评估和渗透测试辅助。

## ⚠️ 免责声明

**本工具仅供授权的安全测试使用。未经授权扫描他人网络可能违法，使用者需自行承担法律责任。**

## ✨ 主要功能

### 🔍 信息收集
- **主机发现**: ICMP/TCP/UDP 存活检测
- **端口扫描**: TCP/UDP 端口扫描，支持自定义端口范围
- **服务识别**: 自动识别开放端口上运行的服务
- **Banner 抓取**: 获取服务版本信息

### 💥 漏洞扫描
- **已知漏洞检测**: MS17-010 (EternalBlue)、Heartbleed、Shellshock 等
- **基础Web检测**: 常见文件暴露、目录遍历等
- **服务配置检查**: Redis未授权访问、SMB空会话等
- **默认凭据检测**: 常见服务的默认用户名密码

### 🔓 暴力破解
- **SSH协议**: 基于密码的认证测试
- **数据库服务**: MySQL、Redis 连接认证
- **字典支持**: 内置和自定义用户名密码字典
- **速率控制**: 可配置的尝试间隔和延迟

### 🌐 Web 应用扫描
- **技术指纹**: 基础的CMS和框架识别 (WordPress、Drupal等)
- **目录发现**: 常见目录和文件的存在性检测
- **基础检测**: robots.txt、sitemap.xml等文件暴露
- **信息收集**: 页面标题、服务器信息提取

### 🎯 渗透利用
- **模拟利用**: 安全的漏洞利用模拟 (仅用于验证)
- **Redis利用**: SSH密钥注入、计划任务注入
- **SSH命令执行**: 基于已知凭据的命令执行
- **安全测试**: 专注于概念验证而非实际攻击

## 🚀 快速开始

### 安装要求

- Rust 1.70+
- 操作系统: Windows、Linux、macOS

### 编译安装

```bash
# 克隆项目
git clone https://github.com/your-repo/rscan.git
cd rscan

# 编译项目
cargo build --release

# 运行程序
./target/release/rscan --help
```

### 基本用法

```bash
# 主机发现
rscan --host 192.168.1.0/24

# 端口扫描
rscan --host 192.168.1.100 -p 80,443,22

# Web 应用扫描
rscan --host 192.168.1.100 -m web

# 漏洞扫描
rscan --host 192.168.1.100 -m vuln

# 全面扫描
rscan --host 192.168.1.100 -m all

# SSH 爆破
rscan --host 192.168.1.100 -m ssh -u admin -w passwords.txt
```

## 📋 详细用法

### 主机发现

```bash
# 扫描单个主机
rscan --host 192.168.1.100

# 扫描网段
rscan --host 192.168.1.0/24

# 扫描 IP 范围
rscan --host 192.168.1.1-100
```

### 端口扫描

```bash
# 扫描指定端口
rscan --host 192.168.1.100 -p 80,443,22,3389

# 扫描端口范围
rscan --host 192.168.1.100 -p 1-1000

# 全端口扫描
rscan --host 192.168.1.100 -p 1-65535
```

### 性能模式

```bash
# 快速模式 (适合内网)
rscan --host 192.168.1.0/24 --fast

# 隐蔽模式 (适合外网)
rscan --host target.com --stealth
```

### 服务爆破

```bash
# SSH 爆破
rscan --host 192.168.1.100 -m ssh -u root -w passwords.txt

# MySQL 爆破
rscan --host 192.168.1.100 -m mysql -u root --password ""

# RDP 爆破
rscan --host 192.168.1.100 -m rdp -u administrator -w passwords.txt
```

### 输出控制

```bash
# 指定输出目录
rscan --host 192.168.1.100 -o /tmp/scan_results

# 指定输出格式
rscan --host 192.168.1.100 --format json
rscan --host 192.168.1.100 --format html

# 详细输出
rscan --host 192.168.1.100 -v
rscan --host 192.168.1.100 -vv
rscan --host 192.168.1.100 -vvv
```

## ⚙️ 配置文件

使用配置文件可以预设扫描参数:

```bash
rscan --host 192.168.1.0/24 -c config.toml
```

配置文件示例 (`config.toml`):

```toml
[scan]
threads = 100
timeout = 10
ports = "1-1000"

[discovery]
ping_timeout = 1000
tcp_timeout = 3000

[brute_force]
max_attempts = 1000
delay = 100
```

## 📊 支持的协议和服务

### 网络协议
- TCP/UDP 端口扫描
- ICMP 主机发现
- ARP 扫描
- IPv4/IPv6 支持

### 应用协议
- **Web**: HTTP/HTTPS 基础扫描
- **远程访问**: SSH、RDP 暴力破解
- **文件共享**: SMB 基础检测
- **数据库**: MySQL、Redis 连接测试
- **其他**: 基于端口的服务识别

## 🛡️ 规避技术

- **时间延迟**: 可配置的请求间隔和随机延迟
- **User-Agent轮换**: 模拟不同浏览器请求
- **代理支持**: HTTP/SOCKS5 代理链
- **请求头随机化**: 避免指纹识别
- **诱饵流量**: 生成混淆流量

## 📈 性能特性

- **异步扫描**: 基于Tokio的异步I/O
- **并发控制**: 可配置的线程数量
- **超时管理**: 灵活的连接和读取超时
- **资源管理**: 合理的内存和网络资源使用
- **进度显示**: 实时扫描进度反馈

## 🔧 高级功能

### PoC 框架

提供基础的概念验证框架:

```bash
# 注意: PoC功能仍在开发中
rscan --host 192.168.1.100 -m vuln
```

### 报告生成

支持多种格式的扫描报告:

- JSON 格式 (机器可读)
- HTML 格式 (可视化报告)
- CSV 格式 (数据分析)
- XML 格式 (结构化数据)

### 模块化设计

采用模块化架构便于扩展:

```rust
// 扫描模块示例
pub struct VulnerabilityScanner {
    config: Config,
    cve_database: HashMap<String, CveInfo>,
}
```

## 📚 使用场景

### 内网渗透

```bash
# 1. 快速资产发现
rscan --host 192.168.1.0/24 --fast

# 2. 重点目标深度扫描
rscan --host 192.168.1.100 -m all

# 3. 服务爆破
rscan --host 192.168.1.100 -m ssh -w passwords.txt
```

### 外网测试

```bash
# 隐蔽扫描
rscan --host target.com --stealth -p 80,443,22

# Web 应用测试
rscan --host target.com -m web --stealth
```

### 安全评估

```bash
# 漏洞扫描
rscan --host 192.168.1.0/24 -m vuln

# 基础安全检查
rscan --host 192.168.1.0/24 -m vuln
```

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！

1. Fork 本项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🙏 致谢

感谢所有为本项目做出贡献的开发者和安全研究人员。

## 📞 联系方式

- 项目主页: [GitHub Repository](https://github.com/your-repo/rscan)
- 问题反馈: [Issues](https://github.com/your-repo/rscan/issues)
- 安全漏洞: security@example.com

---

**⚠️ 再次提醒：本工具仅供授权的安全测试使用，请遵守当地法律法规！**
