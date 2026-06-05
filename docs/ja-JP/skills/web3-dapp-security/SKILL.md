---
name: web3-dapp-security
description: web3 dApp向けのクライアントサイドおよびサーバーサイドのセキュリティパターン。署名付きメッセージによるウォレット所有権の検証、送信前のトランザクション検証、安全な署名UXをカバー。Solanaの例を用いたチェーン非依存の原則。
origin: ECC
version: "1.0.0"
---

# Web3 dApp セキュリティ

ブロックチェーンと通信するアプリケーションのためのウォレットおよびトランザクションセキュリティパターン。本スキルが扱うのはdApp層（署名・送信される前のユーザー検証とトランザクション検証）であり、スマートコントラクト内部は対象外。Solidityコントラクト監査は `defi-amm-security`、トークン精度の落とし穴は `evm-token-decimals` を参照。

## 使用時期

- ウォレットによるユーザー認証（署名付きメッセージでのサインイン）
- アプリがユーザーの署名対象となるトランザクションを構築するフローの実装
- クライアントからウォレットアドレス、署名、トランザクションパラメータを受け取るdAppコードのレビュー
- dAppへの支払い、送金、ミント機能の追加

## 仕組み

クライアントから届くすべてのもの（アドレス、署名、金額、受取先）を信頼できない入力として扱う。ウォレットの所有権はサーバーサイドの署名チェックで検証し、送信前にすべてのトランザクションフィールドをサーバーサイドの期待値と照合する。同じ原則はどのチェーンにも適用できる。以下の例ではSolanaを使用しており、EVMにおける同等の手法はEIP-191/EIP-712によるメッセージ署名（例: Sign-In with Ethereum、EIP-4361）である。

## 例

### ウォレット所有権の検証

ウォレットアドレス単体をアイデンティティとして信頼してはならない。サーバー生成のノンスを発行し、ウォレットに署名させ、その署名をサーバーサイドで検証する。

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

Solanaのウォレット署名は生のメッセージバイトに対するed25519であり、`tweetnacl` で検証する（`@solana/web3.js` は署名検証器をエクスポートしていない）。鍵と署名はbase64ではなくbase58エンコードでやり取りされる。

署名対象のメッセージには単回使用かつ期限付きのノンスを含め、捕捉された署名がリプレイされないようにする。

### トランザクションの検証

署名・送信前に、トランザクションパラメータをサーバーサイドの期待値と照合して検証する。クライアントからエコーバックされた値と照合してはならない。

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

## 検証チェックリスト

- [ ] ウォレット署名をサーバーサイドで検証（単回使用ノンス付き）
- [ ] トランザクション詳細をサーバーサイドの期待値と照合して検証
- [ ] トランザクション前の残高チェック
- [ ] ブラインド署名の禁止 - ユーザーに署名内容を正確に表示
- [ ] 金額上限をサーバーサイドで強制
- [ ] 署名付きメッセージのリプレイ保護（ノンス + 有効期限）

## 関連スキル

- `security-review` - デプロイ前の一般的なセキュリティチェックリスト。プロジェクトがチェーンに関わる場合は本スキルと併用する
- `defi-amm-security` - Solidity AMMコントラクト監査（再入攻撃、オラクル操作、スリッページ）
- `evm-token-decimals` - EVMチェーン間のトークン精度の落とし穴
