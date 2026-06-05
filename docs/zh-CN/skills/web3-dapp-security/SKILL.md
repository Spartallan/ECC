---
name: web3-dapp-security
description: 面向 web3 dApp 的客户端与服务端安全模式——通过签名消息验证钱包所有权、在提交前验证交易，以及安全的签名用户体验。链无关的原则，附 Solana 示例。
origin: ECC
version: "1.0.0"
---

# Web3 dApp 安全

面向与区块链交互的应用的钱包与交易安全模式。本技能覆盖 dApp 层（在签名或提交前验证用户身份并校验交易），不涉及智能合约内部——Solidity 合约审计请参阅 `defi-amm-security`，代币精度陷阱请参阅 `evm-token-decimals`。

## 适用场景

* 通过钱包对用户进行身份验证（使用签名消息登录）
* 构建由应用为用户构造待签名交易的流程
* 审查接受来自客户端的钱包地址、签名或交易参数的 dApp 代码
* 为 dApp 添加支付、转账或铸造功能

## 工作原理

将来自客户端的一切——地址、签名、金额、收款人——都视为不可信输入。在服务端通过签名校验来验证钱包所有权，并在提交前将每个交易字段与服务端预期值进行比对。这些原则适用于任何链；下面的示例使用 Solana，对应的 EVM 等价方案是按 EIP-191/EIP-712 进行消息签名（例如 Sign-In with Ethereum，EIP-4361）。

## 示例

### 钱包所有权验证

切勿将裸钱包地址直接当作身份凭证。由服务端签发 nonce，让钱包对其签名，并在服务端验证签名：

```typescript
import nacl from 'tweetnacl'
import bs58 from 'bs58'
import { PublicKey } from '@solana/web3.js'

async function verifyWalletOwnership(
  publicKey: string,
  signature: string,
  message: string
) {
  try {
    const publicKeyBytes = new PublicKey(publicKey).toBytes()
    const signatureBytes = bs58.decode(signature)
    const messageBytes = new TextEncoder().encode(message)

    return nacl.sign.detached.verify(
      messageBytes,
      signatureBytes,
      publicKeyBytes
    )
  } catch (error) {
    return false
  }
}
```

Solana 钱包签名是对原始消息字节的 ed25519 签名；使用 `tweetnacl` 进行验证（`@solana/web3.js` 不导出签名验证器）。公钥和签名以 base58 编码传输，而非 base64。

在签名消息中使用一次性、带过期时间的 nonce，使被截获的签名无法被重放。

### 交易验证

在签名或提交前，将交易参数与服务端预期值进行比对——切勿与客户端回传的值比对：

```typescript
async function verifyTransaction(transaction: Transaction) {
  // Verify recipient
  if (transaction.to !== expectedRecipient) {
    throw new Error('Invalid recipient')
  }

  // Verify amount
  if (transaction.amount > maxAmount) {
    throw new Error('Amount exceeds limit')
  }

  // Verify user has sufficient balance
  const balance = await getBalance(transaction.from)
  if (balance < transaction.amount) {
    throw new Error('Insufficient balance')
  }

  return true
}
```

## 验证清单

* 钱包签名在服务端验证（使用一次性 nonce）
* 交易细节与服务端预期值比对验证
* 交易前进行余额检查
* 不进行盲签——向用户准确展示其所签内容
* 金额上限在服务端强制执行
* 签名消息具备重放保护（nonce 加过期时间）

## 相关技能

* `security-review`——通用的部署前安全检查清单；当项目涉及链上交互时，将本技能与其配合使用
* `defi-amm-security`——Solidity AMM 合约审计（重入、预言机操纵、滑点）
* `evm-token-decimals`——跨 EVM 链的代币精度陷阱
