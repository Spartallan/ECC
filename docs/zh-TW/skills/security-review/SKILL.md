---
name: security-review
description: Use this skill when adding authentication, handling user input, working with secrets, creating API endpoints, or implementing payment/sensitive features. Provides comprehensive security checklist and patterns.
---

# 安全性審查技能

此技能確保所有程式碼遵循安全性最佳實務並識別潛在漏洞。

## 何時啟用

- 實作認證或授權
- 處理使用者輸入或檔案上傳
- 建立新的 API 端點
- 處理密鑰或憑證
- 實作支付功能
- 儲存或傳輸敏感資料
- 整合第三方 API

## 安全性檢查清單

### 1. 密鑰管理

#### FAIL: 絕不這樣做
```typescript
const apiKey = "sk-proj-xxxxx"  // 寫死的密鑰
const dbPassword = "password123" // 在原始碼中
```

#### PASS: 總是這樣做
```typescript
const apiKey = process.env.OPENAI_API_KEY
const dbUrl = process.env.DATABASE_URL

// 驗證密鑰存在
if (!apiKey) {
  throw new Error('OPENAI_API_KEY not configured')
}
```

#### 驗證步驟
- [ ] 無寫死的 API 金鑰、Token 或密碼
- [ ] 所有密鑰在環境變數中
- [ ] `.env.local` 在 .gitignore 中
- [ ] git 歷史中無密鑰
- [ ] 生產密鑰在託管平台（Vercel、Railway）中

### 2. 輸入驗證

#### 總是驗證使用者輸入
```typescript
import { z } from 'zod'

// 定義驗證 schema
const CreateUserSchema = z.object({
  email: z.string().email(),
  name: z.string().min(1).max(100),
  age: z.number().int().min(0).max(150)
})

// 處理前驗證
export async function createUser(input: unknown) {
  try {
    const validated = CreateUserSchema.parse(input)
    return await db.users.create(validated)
  } catch (error) {
    if (error instanceof z.ZodError) {
      return { success: false, errors: error.errors }
    }
    throw error
  }
}
```

#### 檔案上傳驗證
```typescript
function validateFileUpload(file: File) {
  // 大小檢查（最大 5MB）
  const maxSize = 5 * 1024 * 1024
  if (file.size > maxSize) {
    throw new Error('File too large (max 5MB)')
  }

  // 類型檢查
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif']
  if (!allowedTypes.includes(file.type)) {
    throw new Error('Invalid file type')
  }

  // 副檔名檢查
  const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif']
  const extension = file.name.toLowerCase().match(/\.[^.]+$/)?.[0]
  if (!extension || !allowedExtensions.includes(extension)) {
    throw new Error('Invalid file extension')
  }

  return true
}
```

#### 驗證步驟
- [ ] 所有使用者輸入以 schema 驗證
- [ ] 檔案上傳受限（大小、類型、副檔名）
- [ ] 查詢中不直接使用使用者輸入
- [ ] 白名單驗證（非黑名單）
- [ ] 錯誤訊息不洩露敏感資訊

### 3. SQL 注入預防

#### FAIL: 絕不串接 SQL
```typescript
// 危險 - SQL 注入漏洞
const query = `SELECT * FROM users WHERE email = '${userEmail}'`
await db.query(query)
```

#### PASS: 總是使用參數化查詢
```typescript
// 安全 - 參數化查詢
const { data } = await supabase
  .from('users')
  .select('*')
  .eq('email', userEmail)

// 或使用原始 SQL
await db.query(
  'SELECT * FROM users WHERE email = $1',
  [userEmail]
)
```

#### 驗證步驟
- [ ] 所有資料庫查詢使用參數化查詢
- [ ] SQL 中無字串串接
- [ ] ORM/查詢建構器正確使用
- [ ] Supabase 查詢正確淨化

### 4. 認證與授權

#### JWT Token 處理
```typescript
// FAIL: 錯誤：localStorage（易受 XSS 攻擊）
localStorage.setItem('token', token)

// PASS: 正確：httpOnly cookies
res.setHeader('Set-Cookie',
  `token=${token}; HttpOnly; Secure; SameSite=Strict; Max-Age=3600`)
```

#### 授權檢查
```typescript
export async function deleteUser(userId: string, requesterId: string) {
  // 總是先驗證授權
  const requester = await db.users.findUnique({
    where: { id: requesterId }
  })

  if (requester.role !== 'admin') {
    return NextResponse.json(
      { error: 'Unauthorized' },
      { status: 403 }
    )
  }

  // 繼續刪除
  await db.users.delete({ where: { id: userId } })
}
```

#### Row Level Security（Supabase）
```sql
-- 在所有表格上啟用 RLS
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- 使用者只能查看自己的資料
CREATE POLICY "Users view own data"
  ON users FOR SELECT
  USING (auth.uid() = id);

-- 使用者只能更新自己的資料
CREATE POLICY "Users update own data"
  ON users FOR UPDATE
  USING (auth.uid() = id);
```

#### 驗證步驟
- [ ] Token 儲存在 httpOnly cookies（非 localStorage）
- [ ] 敏感操作前有授權檢查
- [ ] Supabase 已啟用 Row Level Security
- [ ] 已實作基於角色的存取控制
- [ ] 工作階段管理安全

### 5. XSS 預防

#### 淨化 HTML
```typescript
import DOMPurify from 'isomorphic-dompurify'

// 總是淨化使用者提供的 HTML
function renderUserContent(html: string) {
  const clean = DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p'],
    ALLOWED_ATTR: []
  })
  return <div dangerouslySetInnerHTML={{ __html: clean }} />
}
```

DOMPurify 是其中一種選擇；`sanitize-html` 是常見的替代方案。只有在確實需要渲染使用者撰寫的 HTML 時才進行淨化——如果只是顯示使用者文字，請直接以文字渲染（或在輸出時跳脫），而不要動用 `dangerouslySetInnerHTML` 加上淨化器。

#### Content Security Policy

先從嚴格設定開始，只有在有書面移除計畫時才放寬。不要預設使用 `'unsafe-inline'` 或 `'unsafe-eval'`；它們會使 CSP 的大部分保護失效，應被視為暫時的相容性債務。

```typescript
// next.config.js
const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value: `
      default-src 'self';
      base-uri 'self';
      object-src 'none';
      frame-ancestors 'none';
      script-src 'self';
      style-src 'self';
      img-src 'self' data: https:;
      font-src 'self';
      connect-src 'self' https://api.example.com;
    `.replace(/\s{2,}/g, ' ').trim()
  }
]
```

#### 驗證步驟
- [ ] 使用者提供的 HTML 已淨化
- [ ] CSP headers 已設定
- [ ] 無未驗證的動態內容渲染
- [ ] 使用 React 內建 XSS 保護

### 6. CSRF 保護

#### CSRF Tokens
```typescript
import { csrf } from '@/lib/csrf'

export async function POST(request: Request) {
  const token = request.headers.get('X-CSRF-Token')

  if (!csrf.verify(token)) {
    return NextResponse.json(
      { error: 'Invalid CSRF token' },
      { status: 403 }
    )
  }

  // 處理請求
}
```

#### SameSite Cookies
```typescript
res.setHeader('Set-Cookie',
  `session=${sessionId}; HttpOnly; Secure; SameSite=Strict`)
```

#### 驗證步驟
- [ ] 狀態變更操作有 CSRF tokens
- [ ] 所有 cookies 設定 SameSite=Strict
- [ ] 已實作 Double-submit cookie 模式

### 7. 速率限制

#### API 速率限制
```typescript
import rateLimit from 'express-rate-limit'

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 分鐘
  max: 100, // 每視窗 100 個請求
  message: 'Too many requests'
})

// 套用到路由
app.use('/api/', limiter)
```

#### 昂貴操作
```typescript
// 搜尋的積極速率限制
const searchLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 分鐘
  max: 10, // 每分鐘 10 個請求
  message: 'Too many search requests'
})

app.use('/api/search', searchLimiter)
```

#### Serverless 與邊緣執行環境

`express-rate-limit` 將計數器保存在程序記憶體中，這預設伺服器是長時間執行的。在 serverless 或邊緣平台上，每次呼叫都可能是全新的程序，因此請使用共享儲存或平台原生的控制機制：

```typescript
// Upstash Ratelimit - shared Redis-backed counters that work on
// serverless and edge runtimes. Module-scope init works on Vercel and
// Netlify; on Cloudflare Workers env bindings are only available inside
// the handler, so construct the client there instead.
import { Ratelimit } from '@upstash/ratelimit'
import { Redis } from '@upstash/redis'

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(100, '15 m')
})

export async function POST(request: Request) {
  const ip = request.headers.get('x-forwarded-for') ?? 'anonymous'
  const { success } = await ratelimit.limit(ip)

  if (!success) {
    return new Response('Too many requests', { status: 429 })
  }

  // Process request
}
```

如果無法新增依賴，請優先採用平台原生的速率限制：Cloudflare WAF 速率限制規則、Vercel WAF、AWS API Gateway 節流，或在應用程式前方使用 nginx `limit_req`。

#### 驗證步驟
- [ ] 所有 API 端點有速率限制
- [ ] 昂貴操作有更嚴格限制
- [ ] 基於 IP 的速率限制
- [ ] 基於使用者的速率限制（已認證）
- [ ] 速率限制器狀態可跨 serverless/edge 呼叫保留（共享儲存）

### 8. 敏感資料暴露

#### 日誌記錄
```typescript
// FAIL: 錯誤：記錄敏感資料
console.log('User login:', { email, password })
console.log('Payment:', { cardNumber, cvv })

// PASS: 正確：遮蔽敏感資料
console.log('User login:', { email, userId })
console.log('Payment:', { last4: card.last4, userId })
```

#### 錯誤訊息
```typescript
// FAIL: 錯誤：暴露內部細節
catch (error) {
  return NextResponse.json(
    { error: error.message, stack: error.stack },
    { status: 500 }
  )
}

// PASS: 正確：通用錯誤訊息
catch (error) {
  console.error('Internal error:', error)
  return NextResponse.json(
    { error: 'An error occurred. Please try again.' },
    { status: 500 }
  )
}
```

#### 驗證步驟
- [ ] 日誌中無密碼、token 或密鑰
- [ ] 使用者收到通用錯誤訊息
- [ ] 詳細錯誤只在伺服器日誌
- [ ] 不向使用者暴露堆疊追蹤

### 9. Web3 / 區塊鏈（如適用）

錢包所有權驗證、交易驗證與簽署 UX 已移至專屬的 `web3-dapp-security` 技能。智慧合約稽核請參閱 `defi-amm-security`，代幣精度陷阱請參閱 `evm-token-decimals`。當專案涉及區塊鏈時再套用這些技能；它們不屬於每次通用安全性審查的範圍。

### 10. 依賴安全

#### 定期更新
```bash
# 檢查漏洞
npm audit

# 自動修復可修復的問題
npm audit fix

# 更新依賴
npm update

# 檢查過時套件
npm outdated
```

#### Lock 檔案
```bash
# 總是 commit lock 檔案
git add package-lock.json

# 在 CI/CD 中使用以獲得可重現的建置
npm ci  # 而非 npm install
```

#### 驗證步驟
- [ ] 依賴保持最新
- [ ] 無已知漏洞（npm audit 乾淨）
- [ ] Lock 檔案已 commit
- [ ] GitHub 上已啟用 Dependabot
- [ ] 定期安全更新

## 安全測試

### 自動化安全測試
```typescript
// 測試認證
test('requires authentication', async () => {
  const response = await fetch('/api/protected')
  expect(response.status).toBe(401)
})

// 測試授權
test('requires admin role', async () => {
  const response = await fetch('/api/admin', {
    headers: { Authorization: `Bearer ${userToken}` }
  })
  expect(response.status).toBe(403)
})

// 測試輸入驗證
test('rejects invalid input', async () => {
  const response = await fetch('/api/users', {
    method: 'POST',
    body: JSON.stringify({ email: 'not-an-email' })
  })
  expect(response.status).toBe(400)
})

// 測試速率限制
test('enforces rate limits', async () => {
  const requests = Array(101).fill(null).map(() =>
    fetch('/api/endpoint')
  )

  const responses = await Promise.all(requests)
  const tooManyRequests = responses.filter(r => r.status === 429)

  expect(tooManyRequests.length).toBeGreaterThan(0)
})
```

## 部署前安全檢查清單

任何生產部署前：

- [ ] **密鑰**：無寫死密鑰，全在環境變數中
- [ ] **輸入驗證**：所有使用者輸入已驗證
- [ ] **SQL 注入**：所有查詢已參數化
- [ ] **XSS**：使用者內容已淨化
- [ ] **CSRF**：保護已啟用
- [ ] **認證**：正確的 token 處理
- [ ] **授權**：角色檢查已就位
- [ ] **速率限制**：所有端點已啟用
- [ ] **HTTPS**：生產環境強制使用
- [ ] **安全標頭**：CSP、X-Frame-Options 已設定
- [ ] **錯誤處理**：錯誤中無敏感資料
- [ ] **日誌記錄**：無敏感資料被記錄
- [ ] **依賴**：最新，無漏洞
- [ ] **Row Level Security**：Supabase 已啟用
- [ ] **CORS**：正確設定
- [ ] **檔案上傳**：已驗證（大小、類型）
- [ ] **錢包簽章**：已驗證（如果是區塊鏈——參閱 `web3-dapp-security`）

## 資源

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Next.js Security](https://nextjs.org/docs/security)
- [Supabase Security](https://supabase.com/docs/guides/auth)
- [Web Security Academy](https://portswigger.net/web-security)

---

**記住**：安全性不是可選的。一個漏洞可能危及整個平台。有疑慮時，選擇謹慎的做法。
