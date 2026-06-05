---
name: security-review
description: Kimlik doğrulama eklerken, kullanıcı girdisi işlerken, secret'larla çalışırken, API endpoint'leri oluştururken veya ödeme/hassas özellikler uygularken bu skill'i kullanın. Kapsamlı güvenlik kontrol listesi ve kalıplar sağlar.
origin: ECC
---

# Güvenlik İnceleme Skill'i

Bu skill tüm kodun güvenlik en iyi uygulamalarını takip etmesini sağlar ve potansiyel güvenlik açıklarını tanımlar.

## Ne Zaman Aktifleştirmelisiniz

- Kimlik doğrulama veya yetkilendirme uygularken
- Kullanıcı girdisi veya dosya yüklemeleri işlerken
- Yeni API endpoint'leri oluştururken
- Secret'lar veya kimlik bilgileriyle çalışırken
- Ödeme özellikleri uygularken
- Hassas veri saklarken veya iletirken
- Üçüncü taraf API'leri entegre ederken

## Güvenlik Kontrol Listesi

### 1. Secret Yönetimi

#### FAIL: ASLA Bunu Yapmayın
```typescript
const apiKey = "sk-proj-xxxxx"  // Hardcoded secret
const dbPassword = "password123" // Kaynak kodda
```

#### PASS: HER ZAMAN Bunu Yapın
```typescript
const apiKey = process.env.OPENAI_API_KEY
const dbUrl = process.env.DATABASE_URL

// Secret'ların var olduğunu doğrula
if (!apiKey) {
  throw new Error('OPENAI_API_KEY not configured')
}
```

#### Doğrulama Adımları
- [ ] Hardcoded API key, token veya şifre yok
- [ ] Tüm secret'lar environment variable'larda
- [ ] `.env.local` .gitignore'da
- [ ] Git history'de secret yok
- [ ] Production secret'ları hosting platformunda (Vercel, Railway)

### 2. Input Doğrulama

#### Her Zaman Kullanıcı Girdisini Doğrulayın
```typescript
import { z } from 'zod'

// Doğrulama şeması tanımla
const CreateUserSchema = z.object({
  email: z.string().email(),
  name: z.string().min(1).max(100),
  age: z.number().int().min(0).max(150)
})

// İşlemeden önce doğrula
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

#### Dosya Yükleme Doğrulama
```typescript
function validateFileUpload(file: File) {
  // Boyut kontrolü (5MB max)
  const maxSize = 5 * 1024 * 1024
  if (file.size > maxSize) {
    throw new Error('Dosya çok büyük (max 5MB)')
  }

  // Tip kontrolü
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif']
  if (!allowedTypes.includes(file.type)) {
    throw new Error('Geçersiz dosya tipi')
  }

  // Uzantı kontrolü
  const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif']
  const extension = file.name.toLowerCase().match(/\.[^.]+$/)?.[0]
  if (!extension || !allowedExtensions.includes(extension)) {
    throw new Error('Geçersiz dosya uzantısı')
  }

  return true
}
```

#### Doğrulama Adımları
- [ ] Tüm kullanıcı girdileri şema ile doğrulanmış
- [ ] Dosya yüklemeleri kısıtlanmış (boyut, tip, uzantı)
- [ ] Kullanıcı girdisi doğrudan sorgularda kullanılmıyor
- [ ] Whitelist doğrulama (blacklist değil)
- [ ] Hata mesajları hassas bilgi sızdırmıyor

### 3. SQL Injection Önleme

#### FAIL: ASLA SQL Concatenation Yapmayın
```typescript
// TEHLİKELİ - SQL Injection açığı
const query = `SELECT * FROM users WHERE email = '${userEmail}'`
await db.query(query)
```

#### PASS: HER ZAMAN Parametreli Sorgular Kullanın
```typescript
// Güvenli - parametreli sorgu
const { data } = await supabase
  .from('users')
  .select('*')
  .eq('email', userEmail)

// Veya raw SQL ile
await db.query(
  'SELECT * FROM users WHERE email = $1',
  [userEmail]
)
```

#### Doğrulama Adımları
- [ ] Tüm veritabanı sorguları parametreli
- [ ] SQL'de string concatenation yok
- [ ] ORM/query builder doğru kullanılıyor
- [ ] Supabase sorguları düzgün sanitize edilmiş

### 4. Kimlik Doğrulama ve Yetkilendirme

#### JWT Token İşleme
```typescript
// FAIL: YANLIŞ: localStorage (XSS'e karşı savunmasız)
localStorage.setItem('token', token)

// PASS: DOĞRU: httpOnly cookies
res.setHeader('Set-Cookie',
  `token=${token}; HttpOnly; Secure; SameSite=Strict; Max-Age=3600`)
```

#### Yetkilendirme Kontrolleri
```typescript
export async function deleteUser(userId: string, requesterId: string) {
  // HER ZAMAN önce yetkilendirmeyi doğrula
  const requester = await db.users.findUnique({
    where: { id: requesterId }
  })

  if (requester.role !== 'admin') {
    return NextResponse.json(
      { error: 'Unauthorized' },
      { status: 403 }
    )
  }

  // Silme işlemine devam et
  await db.users.delete({ where: { id: userId } })
}
```

#### Row Level Security (Supabase)
```sql
-- Tüm tablolarda RLS'yi aktifleştir
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- Kullanıcılar sadece kendi verilerini görebilir
CREATE POLICY "Users view own data"
  ON users FOR SELECT
  USING (auth.uid() = id);

-- Kullanıcılar sadece kendi verilerini güncelleyebilir
CREATE POLICY "Users update own data"
  ON users FOR UPDATE
  USING (auth.uid() = id);
```

#### Doğrulama Adımları
- [ ] Token'lar httpOnly cookie'lerde (localStorage'da değil)
- [ ] Hassas operasyonlardan önce yetkilendirme kontrolleri
- [ ] Supabase'de Row Level Security aktif
- [ ] Rol tabanlı erişim kontrolü uygulanmış
- [ ] Session yönetimi güvenli

### 5. XSS Önleme

#### HTML'i Sanitize Et
```typescript
import DOMPurify from 'isomorphic-dompurify'

// HER ZAMAN kullanıcı tarafından sağlanan HTML'i sanitize et
function renderUserContent(html: string) {
  const clean = DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p'],
    ALLOWED_ATTR: []
  })
  return <div dangerouslySetInnerHTML={{ __html: clean }} />
}
```

DOMPurify bir seçenektir; `sanitize-html` yaygın bir alternatiftir. Yalnızca kullanıcı tarafından yazılmış HTML'i gerçekten render etmeniz gerektiğinde sanitize edin - sadece kullanıcı metnini gösteriyorsanız, `dangerouslySetInnerHTML` artı bir sanitizer'a başvurmak yerine onu metin olarak render edin (veya çıktıda escape edin).

#### Content Security Policy

Sıkı başlayın ve yalnızca belgelenmiş bir kaldırma planıyla gevşetin. `'unsafe-inline'` veya `'unsafe-eval'` varsayılan olmamalıdır; CSP korumasının büyük kısmını etkisiz kılarlar ve geçici uyumluluk borcu olarak ele alınmalıdırlar.

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

#### Doğrulama Adımları
- [ ] Kullanıcı tarafından sağlanan HTML sanitize edilmiş
- [ ] CSP başlıkları yapılandırılmış
- [ ] Doğrulanmamış dinamik içerik render'ı yok
- [ ] React'in yerleşik XSS koruması kullanılıyor

### 6. CSRF Koruması

#### CSRF Token'ları
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

  // İsteği işle
}
```

#### SameSite Cookie'ler
```typescript
res.setHeader('Set-Cookie',
  `session=${sessionId}; HttpOnly; Secure; SameSite=Strict`)
```

#### Doğrulama Adımları
- [ ] State değiştiren operasyonlarda CSRF token'ları
- [ ] Tüm cookie'lerde SameSite=Strict
- [ ] Double-submit cookie pattern uygulanmış

### 7. Rate Limiting

#### API Rate Limiting
```typescript
import rateLimit from 'express-rate-limit'

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 dakika
  max: 100, // Pencere başına 100 istek
  message: 'Çok fazla istek'
})

// Route'lara uygula
app.use('/api/', limiter)
```

#### Pahalı Operasyonlar
```typescript
// Aramalar için agresif rate limiting
const searchLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 dakika
  max: 10, // Dakikada 10 istek
  message: 'Çok fazla arama isteği'
})

app.use('/api/search', searchLimiter)
```

#### Sunucusuz ve Edge Çalışma Zamanları

`express-rate-limit` sayaçlarını process belleğinde tutar; bu da uzun ömürlü bir sunucu varsayar. Sunucusuz veya edge platformlarda her çağrı yeni bir process olabilir, bu yüzden paylaşılan bir store veya platformun yerleşik kontrolünü kullanın:

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

Bağımlılık eklemek bir seçenek değilse, platforma özgü rate limiting'i tercih edin: Cloudflare WAF rate-limiting kuralları, Vercel WAF, AWS API Gateway throttling veya uygulamanın önünde nginx `limit_req`.

#### Doğrulama Adımları
- [ ] Tüm API endpoint'lerinde rate limiting
- [ ] Pahalı operasyonlarda daha sıkı limitler
- [ ] IP tabanlı rate limiting
- [ ] Kullanıcı tabanlı rate limiting (authenticated)
- [ ] Limiter durumu serverless/edge çağrıları boyunca korunuyor (paylaşılan store)

### 8. Hassas Veri İfşası

#### Loglama
```typescript
// FAIL: YANLIŞ: Hassas veri loglama
console.log('User login:', { email, password })
console.log('Payment:', { cardNumber, cvv })

// PASS: DOĞRU: Hassas veriyi gizle
console.log('User login:', { email, userId })
console.log('Payment:', { last4: card.last4, userId })
```

#### Hata Mesajları
```typescript
// FAIL: YANLIŞ: İç detayları açığa çıkarma
catch (error) {
  return NextResponse.json(
    { error: error.message, stack: error.stack },
    { status: 500 }
  )
}

// PASS: DOĞRU: Genel hata mesajları
catch (error) {
  console.error('Internal error:', error)
  return NextResponse.json(
    { error: 'Bir hata oluştu. Lütfen tekrar deneyin.' },
    { status: 500 }
  )
}
```

#### Doğrulama Adımları
- [ ] Loglarda şifre, token veya secret yok
- [ ] Kullanıcılar için genel hata mesajları
- [ ] Detaylı hatalar sadece sunucu loglarında
- [ ] Kullanıcılara stack trace gösterilmiyor

### 9. Web3 / Blockchain (uygulanabilirse)

Wallet sahipliği doğrulama, transaction doğrulama ve imzalama UX'i özel `web3-dapp-security` skill'ine taşındı. Smart contract denetimi için `defi-amm-security` skill'ine, token hassasiyeti tuzakları için `evm-token-decimals` skill'ine bakın. Proje bir chain'e dokunduğunda bu skill'leri uygulayın; her genel güvenlik incelemesine ait değiller.

### 10. Bağımlılık Güvenliği

#### Düzenli Güncellemeler
```bash
# Güvenlik açıklarını kontrol et
npm audit

# Otomatik düzeltilebilir sorunları düzelt
npm audit fix

# Bağımlılıkları güncelle
npm update

# Eski paketleri kontrol et
npm outdated
```

#### Lock Dosyaları
```bash
# HER ZAMAN lock dosyalarını commit et
git add package-lock.json

# CI/CD'de tekrarlanabilir build'ler için kullan
npm ci  # npm install yerine
```

#### Doğrulama Adımları
- [ ] Bağımlılıklar güncel
- [ ] Bilinen güvenlik açığı yok (npm audit clean)
- [ ] Lock dosyaları commit edilmiş
- [ ] GitHub'da Dependabot aktif
- [ ] Düzenli güvenlik güncellemeleri

## Güvenlik Testi

### Otomatik Güvenlik Testleri
```typescript
// Kimlik doğrulama testi
test('kimlik doğrulama gerektirir', async () => {
  const response = await fetch('/api/protected')
  expect(response.status).toBe(401)
})

// Yetkilendirme testi
test('admin rolü gerektirir', async () => {
  const response = await fetch('/api/admin', {
    headers: { Authorization: `Bearer ${userToken}` }
  })
  expect(response.status).toBe(403)
})

// Input doğrulama testi
test('geçersiz input'u reddeder', async () => {
  const response = await fetch('/api/users', {
    method: 'POST',
    body: JSON.stringify({ email: 'not-an-email' })
  })
  expect(response.status).toBe(400)
})

// Rate limiting testi
test('rate limit'leri zorlar', async () => {
  const requests = Array(101).fill(null).map(() =>
    fetch('/api/endpoint')
  )

  const responses = await Promise.all(requests)
  const tooManyRequests = responses.filter(r => r.status === 429)

  expect(tooManyRequests.length).toBeGreaterThan(0)
})
```

## Deployment Öncesi Güvenlik Kontrol Listesi

HERHANGİ bir production deployment'ından önce:

- [ ] **Secret'lar**: Hardcoded secret yok, hepsi env var'larda
- [ ] **Input Doğrulama**: Tüm kullanıcı girdileri validate edilmiş
- [ ] **SQL Injection**: Tüm sorgular parametreli
- [ ] **XSS**: Kullanıcı içeriği sanitize edilmiş
- [ ] **CSRF**: Koruma aktif
- [ ] **Kimlik Doğrulama**: Doğru token işleme
- [ ] **Yetkilendirme**: Rol kontrolleri yerinde
- [ ] **Rate Limiting**: Tüm endpoint'lerde aktif
- [ ] **HTTPS**: Production'da zorunlu
- [ ] **Güvenlik Başlıkları**: CSP, X-Frame-Options yapılandırılmış
- [ ] **Hata İşleme**: Hatalarda hassas veri yok
- [ ] **Loglama**: Hassas veri loglanmıyor
- [ ] **Bağımlılıklar**: Güncel, güvenlik açığı yok
- [ ] **Row Level Security**: Supabase'de aktif
- [ ] **CORS**: Düzgün yapılandırılmış
- [ ] **Dosya Yüklemeleri**: Validate edilmiş (boyut, tip)
- [ ] **Wallet İmzaları**: Doğrulanmış (blockchain varsa - bkz. `web3-dapp-security`)

## Kaynaklar

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Next.js Security](https://nextjs.org/docs/security)
- [Supabase Security](https://supabase.com/docs/guides/auth)
- [Web Security Academy](https://portswigger.net/web-security)

---

**Unutmayın**: Güvenlik opsiyonel değildir. Bir güvenlik açığı tüm platformu tehlikeye atabilir. Şüphe duyduğunuzda ihtiyatlı olun.
