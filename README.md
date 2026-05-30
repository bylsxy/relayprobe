<div align="center">

# RelayProbe

**Evidence-driven GPT-5.5 relay MITM audit console**

[![Next.js](https://img.shields.io/badge/Next.js-16-black?logo=nextdotjs)](https://nextjs.org/)
[![shadcn/ui](https://img.shields.io/badge/shadcn%2Fui-radix--nova-black)](https://ui.shadcn.com/blocks)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

[中文](#中文文档) | [English](#english) | [日本語](#日本語)

![RelayProbe dashboard](docs/assets/relayprobe-desktop.png)

</div>

## 中文文档

RelayProbe 是一个面向 OpenAI-compatible 中转站的防御性审计工具。它不做“口嗨式验真”，而是发送可复现、无害、带随机 canary 的测试请求，检查中转站是否出现可观察的篡改、泄漏、提示词注入、响应投毒、tool_calls 吞噬、隐藏 wrapper/token 计费异常等证据。

一句话定位：**不是证明谁有罪，而是把 GPT-5.5 中转链路里可疑的 MITM 行为变成可导出的证据。**

### 和已有项目的区别

已有项目做得很好，RelayProbe 吸收的是机制，不复制代码和语料：

- [danhiu/relayprobe](https://github.com/danhiu/relayprobe) 的长处是维度化检测、随机 probe、canary、tool use、token billing 和 dry-run 测试骨架。
- [AetherCore-Dev/relay-radar](https://github.com/AetherCore-Dev/relay-radar) 的长处是“被动监测 + 主动探测”、行为特征抽取、产品化包装和中英 README。
- [yyc.lat relayprobe](https://yyc.lat/tools/relayprobe) 的长处是一屏式中转真伪测试体验。

RelayProbe 的核心差异是：**网络攻防视角下的主动诱饵审计**。它把“看起来容易被攻击的测试请求”作为防御用 canary/honey prompt，观察中转站是否注入、改写、污染响应或跨请求泄漏，而不是只问模型“你是谁”。

### 检测矩阵

| 维度                 | 目的                                                     | 证据强度 |
| -------------------- | -------------------------------------------------------- | -------- |
| Schema lock          | 严格 JSON 契约是否被破坏                                 | 辅助证据 |
| Canary seal          | 假密钥是否出现在回复中                                   | 强证据   |
| Injection lure       | 不可信文档中的提示词注入是否突破隔离                     | 中强证据 |
| Cross-request        | 上一次请求的 canary 是否污染下一次请求                   | 强证据   |
| Response poison scan | 回复里是否出现执行命令、隐藏 Unicode、图片回调等投毒特征 | 强证据   |
| Tool-call integrity  | OpenAI `tool_calls` 是否被吞掉、改写或文本化             | 中强证据 |
| Wrapper token usage  | 极短请求是否出现异常 prompt/cache tokens                 | 辅助证据 |
| Identity hints       | 自报模型/壳/客户端关键词是否异常                         | 弱证据   |

### 快速开始

```bash
npm install
cp .env.example .env.local
npm run dev
```

打开 [http://localhost:3000](http://localhost:3000)，填入中转站 endpoint 和 relay key。默认目标模型与审计模型配置为 `gpt-5.5`，也可以在界面里改成其他 OpenAI-compatible 模型名。

如果服务端配置了 `OPENAI_API_KEY`，RelayProbe 会启用可选的官方 baseline 和 AI auditor pass；没有配置时仍会运行确定性启发式审计。

### 工作流

```mermaid
flowchart LR
  A["Randomized safe probes"] --> B["Relay endpoint"]
  A --> C["Optional official baseline"]
  B --> D["Canary, schema, poison, tool, usage checks"]
  C --> E["Differential comparison"]
  D --> F["GPT-5.5 auditor or heuristic mode"]
  E --> F
  F --> G["Portable JSON evidence report"]
```

### 安全边界

- 只使用假密钥、假文档、合成 canary。
- 不发送真实 `.env`、生产代码、商业文档、个人信息或私密聊天记录。
- 不扫描、不绕过、不逆向你无权测试的基础设施。
- 不把一次 noisy response 当作定罪证据。
- 不把“没发现异常”理解成“中转站绝对安全”。

### 开发与验证

```bash
npm run test
npm run lint
npm run typecheck
npm run build
```

项目使用 Next.js 16、TypeScript、Tailwind CSS v4 和 [shadcn/ui blocks](https://ui.shadcn.com/blocks)。核心逻辑在 `lib/audit-engine.ts` 和 `lib/audit-signals.ts`，API 路由在 `app/api/audit/route.ts`。

## English

RelayProbe is a defensive audit console for OpenAI-compatible API relays. It sends harmless randomized probes with canaries, then reports observable evidence of relay-side tampering, prompt-injection behavior, response poisoning, cross-request contamination, stripped `tool_calls`, and suspicious wrapper/token usage.

It is **not** a verdict engine. It does not prove that a relay is safe or malicious. It produces portable evidence that a human operator can review.

### Quick Start

```bash
npm install
cp .env.example .env.local
npm run dev
```

Open [http://localhost:3000](http://localhost:3000), enter an OpenAI-compatible relay endpoint, and run the audit. Set `OPENAI_API_KEY` on the server to enable the optional direct baseline and AI auditor pass.

### Why It Exists

Many public relay checkers focus on model authenticity: "Is this really Claude/GPT/Opus?" RelayProbe focuses on a narrower security question: **does the relay path show evidence consistent with MITM prompt injection or response manipulation?**

### Documents

- [Threat model](docs/threat-model.md)
- [Methodology](docs/methodology.md)
- [False positives](docs/false-positives.md)
- [Safe testing](docs/safe-testing.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## 日本語

RelayProbe は OpenAI 互換リレー向けの防御的な監査コンソールです。ランダムな canary と安全な誘導プロンプトを使い、リレー経路で観測できる改ざん、漏えい、応答汚染、`tool_calls` の欠落、異常な token 使用量を証拠として記録します。

これは「安全」または「悪意あり」を断定するツールではありません。人間が確認できる監査レポートを作るためのツールです。

## License

MIT
