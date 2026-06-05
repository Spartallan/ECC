---
name: web3-dapp-security
description: Client- and server-side security patterns for web3 dApps - wallet ownership verification via signed messages, transaction validation before submission, and safe signing UX. Chain-agnostic principles with Solana examples.
origin: ECC
version: "1.0.0"
---

# Web3 dApp Security

Wallet and transaction security patterns for applications that talk to a
blockchain. This covers the dApp layer (verifying users and validating
transactions before they are signed or submitted), not smart-contract
internals - see `defi-amm-security` for Solidity contract auditing and
`evm-token-decimals` for token-precision pitfalls.

## When to Use

- Authenticating users by wallet (sign-in with a signed message)
- Building flows where the app constructs transactions for users to sign
- Reviewing dApp code that accepts wallet addresses, signatures, or
  transaction parameters from the client
- Adding payment, transfer, or minting features to a dApp

## How It Works

Treat everything that arrives from the client - addresses, signatures,
amounts, recipients - as untrusted input. Verify wallet ownership
server-side with signature checks, and validate every transaction field
against server-side expectations before submission. The same principles
apply on any chain; the examples below use Solana, and the EVM equivalents
are message signing per EIP-191/EIP-712 (for example Sign-In with Ethereum,
EIP-4361).

## Examples

### Wallet ownership verification

Never trust a bare wallet address as identity. Issue a server-generated
nonce, have the wallet sign it, and verify the signature server-side:

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

Solana wallet signatures are ed25519 over the raw message bytes; verify
them with `tweetnacl` (`@solana/web3.js` does not export a signature
verifier). Keys and signatures travel base58-encoded, not base64.

Use a single-use, expiring nonce in the signed message so a captured
signature cannot be replayed.

### Transaction verification

Validate transaction parameters against server-side expectations before
signing or submitting - never against values echoed back by the client:

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

## Verification Checklist

- [ ] Wallet signatures verified server-side (with single-use nonce)
- [ ] Transaction details validated against server-side expectations
- [ ] Balance checks before transactions
- [ ] No blind transaction signing - show users exactly what they sign
- [ ] Amount limits enforced server-side
- [ ] Replay protection on signed messages (nonce + expiry)

## Related Skills

- `security-review` - general pre-deployment security checklist; apply this
  skill alongside it when the project touches a chain
- `defi-amm-security` - Solidity AMM contract auditing (reentrancy, oracle
  manipulation, slippage)
- `evm-token-decimals` - token-precision pitfalls across EVM chains
