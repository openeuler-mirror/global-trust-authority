# GTA (global-trust-authority)

## 介绍
统一远程认证是一个开源保密计算项目，致力于为保密计算和可信计算远程认证提供统一的架构，促进保密计算生态系统的发展。该项目提供完整的远程认证解决方案，包括客户端代理和服务器端服务组件。
## 特点

### 1. 远程认证挑战生成与验证

远程认证挑战生成和验证是统一远程认证的核心功能。它包括以下步骤：
1. 客户端代理生成远程验证挑战。
2. 服务器验证远程验证挑战。

## 外部接口

有关外部接口，请参阅 [API 文档](./docs/api_documentation.md)

## 组件

| 目录                   | 描述            | 详细文档                                             |
|---------------------|---------------|--------------------------------------------------|
| attestation_agent   | 远程证明agent模块   | [开发指南](docs/attestation_agent.md)                 |
| attestation_service | 远程证明service模块 | [开发指南](docs/attestation_service.md) |
| attestation_common  | 远程证明common模块  | [开发指南](docs/attestation_common.md)  |

## 开发

### 环境准备
openEuler 21.03 或更高（生产环境）

### 依赖
* Rust 1.70.0 或更高
* PostgreSQL 14.0 或更高
* Mysql 8.0.4 或更高
* Redis 6.2或更高
* Kafka 3.8或更高
* OpenSSL development library
* libssl-dev (for OpenSSL)
* pkg-config

## 贡献指导
- fork该仓库
- 创建一个特性分支（ git checkout -b feature/AmazingFeature）
- 提交您的更改（ git commit -m 'Add some AmazingFeature' )
- 推送到分支（ git push origin feature/AmazingFeature）
- 创建拉取请求

## 许可证
本项目采用木兰 PSL v2 许可协议进行许可。

## 联系方式
- 项目 URL: https://gitee.com/openeuler/global-trust-authority
- Issue: https://gitee.com/openeuler/global-trust-authority/issues