require('dotenv').config();
const express = require('express'), helmet = require('helmet'), cors = require('cors'), rateLimit = require('express-rate-limit'),
  multer = require('multer'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'), path = require('path'), fs = require('fs'), crypto = require('crypto');
const db = require('./db');
const SECRET = process.env.JWT_SECRET;
if (!SECRET || SECRET.length < 32) { console.error('JWT_SECRET باید حداقل ۳۲ کاراکتر باشد'); process.exit(1); }
const UP = path.join(__dirname, '..', 'uploads');
['products', 'receipts', 'banners', 'campaigns', 'bundles'].forEach(d => fs.mkdirSync(path.join(UP, d), { recursive: true }));

const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PROD = NODE_ENV === 'production';
const FORCE_HTTPS = process.env.Force_Https === '1' || process.env.FORCE_HTTPS === '1';
const JWT_ISSUER = 'zibadoz';
const JWT_AUDIENCE = 'zibadoz-users';
const ADMIN_LOCKOUT_MS = 30 * 60 * 1000; // 30 دقیقه
const ADMIN_MAX_FAILS = 5;

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', process.env.TRUST_PROXY === '1' ? 1 : false);
app.set('etag', false);

// ---------- هدرهای امنیتی Helmet ----------
// script-src شامل 'unsafe-inline' است چون سایت و پنل مدیریت از اسکریپت‌های
// داخل‌صفحه‌ای معتبر خودشان استفاده می‌کنند. تمام ورودی‌های کاربر با تابع esc()
// به‌طور کامل escape می‌شوند و از eval/Function(string)/setTimeout(string) استفاده
// نمی‌شود، بنابراین خطر تزریق اسکریپت به حداقل رسیده است.
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
      imgSrc: ["'self'", 'data:', 'blob:'],
      connectSrc: ["'self'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'"],
      baseUri: ["'self'"],
      objectSrc: ["'none'"],
      scriptSrcAttr: ["'none'"],
      upgradeInsecureRequests: IS_PROD ? [] : null
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-site' },
  hsts: IS_PROD ? { maxAge: 63072000, includeSubDomains: true, preload: true } : false,
  frameguard: { action: 'deny' },
  noSniff: true,
  xssFilter: true,
  referrerPolicy: { policy: 'no-referrer' },
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
  ieNoOpen: true,
  dnsPrefetchControl: { allow: false }
}));

// ---------- هدرهای امنیتی اضافی ----------
app.use((q, s, n) => {
  s.setHeader('X-Content-Type-Options', 'nosniff');
  s.setHeader('X-Frame-Options', 'DENY');
  s.setHeader('Referrer-Policy', 'no-referrer');
  s.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()');
  s.setHeader('X-DNS-Prefetch-Control', 'off');
  s.removeHeader('X-Powered-By');
  n();
});

// ---------- هدایت به HTTPS در تولید ----------
if (IS_PROD && FORCE_HTTPS) {
  app.use((q, s, n) => {
    if (q.headers['x-forwarded-proto'] === 'https' || q.secure) return n();
    s.redirect(301, 'https://' + q.headers.host + q.originalUrl);
  });
}

// ---------- محدودیت نرخ عمومی و API ----------
const globalLimiter = rateLimit({
  windowMs: 60 * 1000, max: 120,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'تعداد درخواست‌ها بیش از حد مجاز است' }
});
app.use('/api', globalLimiter);
app.use('/api', cors({ origin: true, methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'], allowedHeaders: ['Content-Type', 'Authorization'], credentials: false, maxAge: 600 }));
app.use(express.json({ limit: '200kb' }));

// ---------- قفل حساب مدیر پس از چند شکست ----------
const adminLocks = new Map(); // username -> { fails, until }
function isLocked(username) {
  const l = adminLocks.get(username);
  if (!l) return false;
  if (l.until && Date.now() < l.until) return true;
  adminLocks.delete(username);
  return false;
}
function registerFail(username) {
  const l = adminLocks.get(username) || { fails: 0, until: 0 };
  l.fails++;
  if (l.fails >= ADMIN_MAX_FAILS) l.until = Date.now() + ADMIN_LOCKOUT_MS;
  adminLocks.set(username, l);
}
function clearFails(username) { adminLocks.delete(username); }
// پاک‌سازی دوره‌ای قفل‌های منقضی
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of adminLocks) if (v.until && v.until < now) adminLocks.delete(k);
}, 5 * 60 * 1000).unref();

class E extends Error { constructor(m, c = 400) { super(m); this.c = c; } }
const A = f => (q, s, n) => Promise.resolve(f(q, s, n)).catch(n);

const norm = value => String(value || '')
  .normalize('NFKC')
  .replace(/[\u064B-\u065F\u0670\u0640]/g, '')
  .replace(/[يى]/g, 'ی').replace(/ك/g, 'ک').replace(/[ۀة]/g, 'ه')
  .replace(/[أإآٱ]/g, 'ا')
  .replace(/[ؤ]/g, 'و').replace(/[ئ]/g, 'ی')
  .replace(/[۰-۹]/g, d => String('۰۱۲۳۴۵۶۷۸۹'.indexOf(d)))
  .replace(/[٠-٩]/g, d => String('٠١٢٣٤٥٦٧٨٩'.indexOf(d)))
  .replace(/[\u200e\u200f\u200c\u200dـ]/g, ' ')
  .replace(/[^\p{L}\p{N}\s]/gu, ' ')
  .replace(/\s+/g, ' ').trim().toLowerCase();



// ---------- حساب مشتری ----------
function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}
function normalizeMobile(value) {
  return norm(value).replace(/\D/g, '');
}
function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(value);
}
function customerToken(q) {
  const h = String(q.headers.authorization || '');
  if (!/^Bearer\s+/i.test(h)) return null;
  try {
    const payload = jwt.verify(h.replace(/^Bearer\s+/i, ''), SECRET, { issuer: JWT_ISSUER, audience: JWT_AUDIENCE });
    return payload.type === 'customer' && Number.isSafeInteger(Number(payload.uid))
      ? { id: Number(payload.uid) } : null;
  } catch { return null; }
}
const customerAuth = (q, s, n) => {
  const u = customerToken(q);
  if (!u) return s.status(401).json({ error: 'برای ادامه وارد حساب کاربری شوید' });
  q.customerAccount = u;
  n();
};
const optionalCustomerAuth = (q, s, n) => {
  q.customerAccount = customerToken(q);
  n();
};

const SEARCH_SYNONYMS = {
  'کیف': ['bag', 'bags', 'handbag', 'hand bag', 'purse', 'purses', 'luggage', 'کیف دستی', 'کیف زنانه', 'کیف مسافرتی', 'کیف پول', 'کیف آرایشی'],
  'bag': ['کیف', 'handbag', 'purse'], 'bags': ['کیف', 'bag', 'handbag', 'purse'],
  'handbag': ['کیف دستی', 'کیف', 'bag'], 'purse': ['کیف دستی', 'کیف پول', 'کیف'],
  'wallet': ['کیف پول', 'کیف'], 'luggage': ['چمدان', 'کیف مسافرتی', 'کیف'],
  'چمدان': ['luggage', 'suitcase', 'travel bag'], 'مسافرتی': ['travel', 'luggage'],
  'نظم دهنده': ['organizer', 'storage bag'], 'آرایشی': ['cosmetic', 'makeup'],
  'کیف زنانه': ['women bag', 'handbag', 'purse'],
  'suitcase': ['چمدان', 'کیف مسافرتی'], 'travel': ['مسافرتی', 'سفر', 'چمدان'],
  'cosmetic': ['آرایشی', 'لوازم آرایش'], 'organizer': ['نظم دهنده', 'نظم‌دهنده', 'ارگانایزر'],
  'کیف دستی': ['handbag', 'hand bag', 'purse'], 'کیف پول': ['wallet', 'purse'],
  'کیف مسافرتی': ['travel bag', 'luggage', 'suitcase'], 'کیف سفری': ['travel bag', 'luggage'],
  'کیف آرایشی': ['cosmetic bag', 'makeup bag'], 'کیف لوازم آرایش': ['cosmetic bag', 'makeup bag'],
  'کیف لباس': ['garment bag', 'clothes bag'], 'کیف نظم دهنده': ['organizer', 'storage bag'],
  'makeup': ['آرایش', 'لوازم آرایش'], 'garment': ['لباس', 'پوشاک'],
  'پرشین': ['persian'], 'persian': ['پرشین', 'کیف'], 'انگلیسی': ['english'], 'english': ['انگلیسی'],
  'فارسی': ['persian', 'farsi'], 'farsi': ['فارسی', 'persian'], 'کیف انگلیسی': ['english bag', 'bag'],
  'کیف فارسی': ['persian bag', 'farsi bag']
};

function expandSearchTerms(value) {
  const q = norm(value);
  const terms = new Set([q, ...q.split(' ').filter(Boolean)]);
  for (const [key, values] of Object.entries(SEARCH_SYNONYMS)) {
    const k = norm(key);
    if (k && (q === k || q.includes(k) || q.split(' ').includes(k))) {
      terms.add(k);
      for (const item of values) terms.add(norm(item));
    }
  }
  if (/^(keif|keyf|kif|kaif|kief|keef)$/.test(q)) {
    ['کیف', 'bag', 'bags', 'handbag', 'purse'].forEach(x => terms.add(x));
  }
  return [...terms].filter(Boolean);
}

function editDistance(a, b, maxDistance = Infinity) {
  if (Math.abs(a.length - b.length) > maxDistance) return maxDistance + 1;
  if (a === b) return 0;
  if (!a) return b.length;
  if (!b) return a.length;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let rowMin = cur[0];
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      if (cur[j] < rowMin) rowMin = cur[j];
    }
    if (rowMin > maxDistance) return maxDistance + 1;
    prev = cur;
  }
  return prev[b.length];
}

function searchScore(product, rawQuery) {
  const query = norm(rawQuery);
  if (!query) return 0;

  const name = norm(product.name);
  const category = norm(product.category_name);
  const shortDesc = norm(product.short_desc);
  const description = norm(product.description);
  const keywords = norm(product.search_keywords);
  const extra = norm(product.search_text);
  const allText = [name, category, shortDesc, description, keywords, extra].filter(Boolean).join(' ');
  const searchableWords = [...new Set([name, category, shortDesc, keywords].join(' ').split(' ').filter(Boolean))].slice(0, 100);
  const qTokens = [...new Set(query.split(' ').filter(Boolean))].slice(0, 8);
  const aliases = expandSearchTerms(query).filter(x => x !== query);

  let score = 0;
  if (name === query) score += 1600;
  else if (name.startsWith(query)) score += 1350;
  else if (name.includes(query)) score += 1150;
  else if (category === query) score += 950;
  else if (category.includes(query)) score += 800;
  else if (shortDesc.includes(query) || keywords.includes(query)) score += 650;
  else if (description.includes(query) || extra.includes(query)) score += 400;

  if (aliases.some(alias => name.includes(alias))) score += 500;
  else if (aliases.some(alias => category.includes(alias))) score += 350;
  else if (aliases.some(alias => allText.includes(alias))) score += 220;

  let matched = 0;
  for (const token of qTokens) {
    const tokenAliases = expandSearchTerms(token).filter(x => x !== token);
    const has = (field, needle) => field.split(' ').some(word => word === needle);
    if (has(name, token)) { score += 260; matched++; continue; }
    if (name.split(' ').some(word => word.startsWith(token))) { score += 205; matched++; continue; }
    if (has(category, token)) { score += 170; matched++; continue; }
    if (has(keywords, token)) { score += 160; matched++; continue; }
    if (has(shortDesc, token)) { score += 135; matched++; continue; }
    if (allText.includes(token)) { score += 85; matched++; continue; }
    if (tokenAliases.some(alias => allText.includes(alias))) { score += 115; matched++; continue; }

    if (token.length >= 3) {
      let best = 0;
      for (const candidate of searchableWords) {
        if (candidate.length < 3 || candidate.length > 40) continue;
        const allowed = token.length <= 4 ? 1 : token.length <= 7 ? 2 : 3;
        const distance = editDistance(token, candidate, allowed);
        if (distance <= allowed) {
          const ratio = 1 - distance / Math.max(token.length, candidate.length);
          if (ratio > best) best = ratio;
        }
      }
      const threshold = token.length <= 4 ? 0.67 : 0.70;
      if (best >= threshold) { score += Math.round(best * 125); matched++; }
    }
  }

  if (matched === qTokens.length) score += 260;
  else if (matched > 0) score += matched * 25;
  return score;
}

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024, files: 8 } });

function kind(b) {
  if (b[0] === 0xFF && b[1] === 0xD8) return 'jpg';
  if (b.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))) return 'png';
  if (b.slice(0, 4).toString() === 'RIFF' && b.slice(8, 12).toString() === 'WEBP') return 'webp';
  return null;
}

function saveFile(buf, dir) {
  const k = kind(buf); if (!k) throw new E('فقط تصویر JPEG/PNG/WebP مجاز است');
  const name = crypto.randomBytes(16).toString('hex') + '.' + k;
  fs.writeFileSync(path.join(UP, dir, name), buf); return name;
}

const rm = (dir, f) => fs.unlink(path.join(UP, dir, path.basename(f)), () => {});
const list = x => String(x || '').split(/[,،]/).map(t => t.trim()).filter(Boolean);

// تشخیص خودکار نوع ستون colors/sizes (jsonb یا text[]) — کش می‌شود تا فقط یک‌بار اجرا شود
let _variantTypesCache = null;
async function getVariantTypes() {
  if (_variantTypesCache) return _variantTypesCache;
  try {
    const r = await db.query(`
      select column_name, udt_name
      from information_schema.columns
      where table_schema = current_schema()
        and table_name = 'products'
        and column_name in ('colors', 'sizes')
    `);
    const types = { colors: 'jsonb', sizes: 'jsonb' };
    for (const row of r.rows) types[row.column_name] = row.udt_name;
    _variantTypesCache = types;
    return types;
  } catch (_) {
    _variantTypesCache = { colors: 'jsonb', sizes: 'jsonb' };
    return _variantTypesCache;
  }
}
async function settings() { return Object.fromEntries((await db.query('select key,value from store_settings')).rows.map(x => [x.key, x.value])); }
const PUBLIC = ['shop_name', 'phone', 'eitaa_link', 'footer_text', 'about_text', 'shipping_fee', 'min_order', 'shop_active', 'points_enabled', 'points_per_toman', 'points_min_redeem', 'points_value_toman'];
const ALLOWED = [...PUBLIC, 'card_number', 'card_owner'];
const payInfo = s => ({ card_number: s.card_number, card_owner: s.card_owner, eitaa_link: s.eitaa_link });


// ---------- ثبت‌نام و ورود مشتری ----------
const customerLoginLimit = rateLimit({
  windowMs: 15 * 60 * 1000, max: 12,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'تلاش‌های ورود زیاد بود؛ کمی بعد دوباره امتحان کنید' }
});

app.post('/api/account/register', customerLoginLimit, A(async (q, s) => {
  const b = q.body || {};
  const identifier = String(b.identifier || '').trim();
  const password = String(b.password || '');
  const name = String(b.name || '').trim();
  if (name.length < 2 || password.length < 8) {
    throw new E('نام را وارد کنید و رمز عبور باید حداقل ۸ کاراکتر باشد');
  }

  let email = null, mobile = null;
  if (identifier.includes('@')) {
    email = normalizeEmail(identifier);
    if (!validEmail(email)) throw new E('آدرس ایمیل معتبر نیست');
  } else {
    mobile = normalizeMobile(identifier);
    if (!/^09\d{9}$/.test(mobile)) throw new E('شماره موبایل باید با 09 و ۱۱ رقم وارد شود');
  }

  const passwordHash = await bcrypt.hash(password, 12);
  try {
    const r = await db.query(
      `insert into customer_accounts(name,email,mobile,password_hash)
       values($1,$2,$3,$4) returning id,name,email,mobile`,
      [name, email, mobile, passwordHash]
    );
    const account = r.rows[0];
    const token = jwt.sign({ uid: account.id, type: 'customer' }, SECRET, { expiresIn: '14d', issuer: JWT_ISSUER, audience: JWT_AUDIENCE });
    s.status(201).json({ token, account });
  } catch (e) {
    if (e.code === '23505') throw new E('این ایمیل یا شماره موبایل قبلاً ثبت شده است', 409);
    throw e;
  }
}));

app.post('/api/account/login', customerLoginLimit, A(async (q, s) => {
  const identifier = String((q.body || {}).identifier || '').trim();
  const password = String((q.body || {}).password || '');
  if (!identifier || !password) throw new E('ایمیل یا موبایل و رمز عبور را وارد کنید');

  let r;
  if (identifier.includes('@')) {
    const email = normalizeEmail(identifier);
    r = await db.query(
      'select id,name,email,mobile,password_hash from customer_accounts where email=$1',
      [email]
    );
  } else {
    const mobile = normalizeMobile(identifier);
    r = await db.query(
      'select id,name,email,mobile,password_hash from customer_accounts where mobile=$1',
      [mobile]
    );
  }
  const account = r.rows[0];
  if (!account || !(await bcrypt.compare(password, account.password_hash))) {
    throw new E('اطلاعات ورود صحیح نیست', 401);
  }
  delete account.password_hash;
  const token = jwt.sign({ uid: account.id, type: 'customer' }, SECRET, { expiresIn: '14d', issuer: JWT_ISSUER, audience: JWT_AUDIENCE });
  s.json({ token, account });
}));

app.get('/api/account/me', customerAuth, A(async (q, s) => {
  const r = await db.query(
    'select id,name,email,mobile,created_at from customer_accounts where id=$1',
    [q.customerAccount.id]
  );
  if (!r.rowCount) throw new E('حساب کاربری پیدا نشد', 404);
  s.json({ account: r.rows[0] });
}));

app.get('/api/account/orders', customerAuth, A(async (q, s) => {
  const r = await db.query(`
    select distinct o.order_number,o.total,o.status,o.tracking_code,o.created_at
    from orders o
    join customers c on c.id=o.customer_id
    where c.account_id=$1
    order by o.created_at desc
    limit 100
  `, [q.customerAccount.id]);
  s.json({ items: r.rows });
}));

app.patch('/api/account/profile', customerAuth, A(async (q, s) => {
  const b = q.body || {};
  const name = String(b.name || '').trim();
  if (name.length < 2) throw new E('نام معتبر نیست');
  const r = await db.query(
    'update customer_accounts set name=$1 where id=$2 returning id,name,email,mobile,created_at',
    [name, q.customerAccount.id]
  );
  if (!r.rowCount) throw new E('حساب کاربری پیدا نشد', 404);
  s.json({ account: r.rows[0] });
}));

// ---------- عمومی ----------
app.get('/api/settings', A(async (q, s) => { const st = await settings(); s.json(Object.fromEntries(PUBLIC.map(k => [k, st[k]]))); }));
app.get('/api/categories', A(async (q, s) => s.json((await db.query('select id,name,slug from categories order by sort,id')).rows)));
app.get('/api/products', A(async (q, s) => {
  const Q = q.query, w = ['p.published'], v = [];
  const add = (sql, val) => { v.push(val); w.push(sql.replace('?', '$' + v.length)); };
  const eff = 'coalesce(p.discount_price,p.price)';
  if (Q.category) add('c.slug = ?', String(Q.category));
  if (Q.min && Number.isFinite(+Q.min)) add(eff + ' >= ?', +Q.min);
  if (Q.max && Number.isFinite(+Q.max)) add(eff + ' <= ?', +Q.max);
  if (Q.instock === '1') w.push('p.stock>0');
  if (Q.discount === '1') w.push('p.discount_price is not null and p.discount_price<p.price');

  const ord = {
    new: 'p.created_at desc',
    cheap: eff + ' asc',
    exp: eff + ' desc',
    best: 'p.bestseller desc,p.sold desc',
    discount: '(case when p.discount_price<p.price then 1-p.discount_price::float/p.price else 0 end) desc'
  }[Q.sort] || 'p.created_at desc';

  const page = Math.max(parseInt(Q.page, 10) || 1, 1);
  const lim = Math.min(Math.max(parseInt(Q.limit, 10) || 24, 1), 100);

  const fields = `p.id,p.slug,p.name,p.short_desc,p.description,p.search_text,p.search_keywords,p.price,p.discount_price,p.stock,p.colors,p.sizes,p.featured,p.bestseller,p.created_at,c.name category_name,c.slug category_slug,
    (select file from product_images i where i.product_id=p.id order by i.is_main desc,i.sort,i.id limit 1) image`;

  if (Q.q && norm(String(Q.q).slice(0, 100))) {
    const all = await db.query(`select ${fields} from products p left join categories c on c.id=p.category_id
      where ${w.join(' and ')} order by ${ord} limit 10000`, v);

    const query = norm(String(Q.q).slice(0, 100));
    const ranked = all.rows.map(row => ({ row, score: searchScore(row, query) }))
      .filter(x => x.score > 0)
      .sort((a, b) => b.score - a.score || new Date(b.row.created_at) - new Date(a.row.created_at));

    const total = ranked.length;
    const items = ranked.slice((page - 1) * lim, page * lim).map(x => {
      const row = { ...x.row, search_score: x.score };
      delete row.search_text;
      delete row.search_keywords;
      delete row.description;
      // همیشه تنوع‌ها را با ساختار یکسان برگردان؛ حتی در نتایج جست‌وجو.
      // این کار باعث می‌شود قیمت اختصاصی هر سایز در فرانت‌اند قابل خواندن باشد.
      row.colors = normalizeVariants(row.colors, 'color');
      row.sizes = normalizeVariants(row.sizes, 'size');
      row.image = row.image ? '/uploads/products/' + row.image : null;
      return row;
    });

    return s.json({ items, total, page, limit: lim, has_more: page * lim < total, capped: all.rows.length === 10000 });
  }

  const count = await db.query(`select count(*)::int total from products p left join categories c on c.id=p.category_id where ${w.join(' and ')}`, v);
  const r = await db.query(`select ${fields} from products p left join categories c on c.id=p.category_id
    where ${w.join(' and ')} order by ${ord} limit ${lim} offset ${(page - 1) * lim}`, v);

  s.json({
    items: r.rows.map(x => {
      const row = { ...x, image: x.image ? '/uploads/products/' + x.image : null };
      delete row.search_text;
      delete row.search_keywords;
      delete row.description;
      // لیست عادی محصولات نیز باید قیمت/موجودی سایزها را نرمال‌شده برگرداند.
      row.colors = normalizeVariants(row.colors, 'color');
      row.sizes = normalizeVariants(row.sizes, 'size');
      return row;
    }),
    total: count.rows[0].total,
    page,
    limit: lim,
    has_more: page * lim < count.rows[0].total
  });
}));

app.get('/api/products/by-ids', A(async (q, s) => {
  const ids = String(q.query.ids || '').split(',').map(x => Number(x))
    .filter(x => Number.isSafeInteger(x) && x > 0).slice(0, 50);

  if (!ids.length) return s.json({ items: [] });

  const r = await db.query(`select p.id,p.slug,p.name,p.short_desc,p.price,p.discount_price,p.stock,p.colors,p.sizes,
    c.name category_name,(select file from product_images i where i.product_id=p.id order by i.is_main desc,i.sort,i.id limit 1) image
    from products p left join categories c on c.id=p.category_id where p.published and p.id=any($1::int[])`, [ids]);

  s.json({ items: r.rows.map(x => ({
    ...x,
    colors: normalizeVariants(x.colors, 'color'),
    sizes: normalizeVariants(x.sizes, 'size'),
    image: x.image ? '/uploads/products/' + x.image : null
  })) });
}));

app.get('/api/products/:slug', optionalCustomerAuth, A(async (q, s) => {
  const p = (await db.query('select p.*,c.name category_name from products p left join categories c on c.id=p.category_id where p.slug=$1 and p.published', [q.params.slug])).rows[0];
  if (!p) throw new E('محصول پیدا نشد', 404);

  delete p.search_text;
  delete p.search_keywords;

  p.images = (await db.query('select id,file from product_images where product_id=$1 order by is_main desc,sort,id', [p.id]))
    .rows.map(i => '/uploads/products/' + i.file);

  // نرمال‌سازی colors/sizes: پشتیبانی از هر دو فرمت (string ساده و object با stock/price_override)
  p.colors = normalizeVariants(p.colors, 'color');
  p.sizes  = normalizeVariants(p.sizes, 'size');

  // آمار نظرات: میانگین امتیاز و تعداد نظرات تأییدشده
  const reviewStats = (await db.query(
    `select coalesce(avg(rating),0)::float avg_rating,
            count(*)::int review_count
     from product_reviews
     where product_id=$1 and status='approved'`,
    [p.id]
  )).rows[0];
  p.avg_rating = Math.round(Number(reviewStats.avg_rating) * 10) / 10;
  p.review_count = reviewStats.review_count;

  // ثبت بازدید اگر کاربر وارد شده
  if (q.customerAccount) {
    try {
      await db.query(
        `insert into product_view_history(account_id, product_id, viewed_at)
         values($1, $2, now())
         on conflict do nothing`,
        [q.customerAccount.id, p.id]
      );
      // فقط ۵۰ بازدید آخر را نگه دار
      await db.query(
        `delete from product_view_history
         where account_id=$1 and id not in (
           select id from product_view_history
           where account_id=$1
           order by viewed_at desc
           limit 50
         )`,
        [q.customerAccount.id]
      );
    } catch (_) { /* fail silently */ }
  }

  s.json(p);
}));

// ---------- helper: نرمال‌سازی تنوع محصول ----------
// پشتیبانی از هر دو فرمت colors/sizes:
//   فرمت قدیمی: ["قرمز","آبی"]  (آرایه ساده string)
//   فرمت قدیمی‌تر: [{name:"قرمز",stock:5,price_override:null,image:null}]
//   فرمت جدید رنگ:  [{name:"زرد",hex:"#FFD700"}, ...]
//   فرمت جدید سایز:  [{name:"کوچک",price:100000,stock:10,active:true}, ...]
// خروجی همیشه فرمت جدید است.
function normalizeVariants(arr, kind = 'color') {
  if (!Array.isArray(arr)) return [];
  return arr.map(value => {
    let v = value;

    // در ستون‌های قدیمی PostgreSQL text[]، اشیای تنوع به‌صورت JSON string ذخیره می‌شوند.
    // آن‌ها را دوباره به object تبدیل می‌کنیم؛ رشته‌های معمولی قدیمی نیز حفظ می‌شوند.
    if (typeof v === 'string') {
      const raw = v.trim();
      if ((raw.startsWith('{') && raw.endsWith('}')) || (raw.startsWith('[') && raw.endsWith(']'))) {
        try {
          const parsed = JSON.parse(raw);
          if (parsed && typeof parsed === 'object') v = parsed;
        } catch (_) {}
      }
    }

    if (typeof v === 'string') {
      const name = v.trim();
      if (!name) return null;
      return kind === 'size'
        ? { name, price: null, stock: null, active: true }
        : { name, hex: guessHex(name) };
    }

    if (v && typeof v === 'object' && !Array.isArray(v)) {
      const name = String(v.name || '').trim();
      if (!name) return null;
      const isSize = kind === 'size' || (v.hex === undefined &&
        (v.price !== undefined || v.stock !== undefined || v.price_override !== undefined));
      if (!isSize) {
        return { name, hex: v.hex ? String(v.hex) : guessHex(name) };
      }
      const price = Number(v.price);
      const oldPrice = Number(v.price_override);
      const stock = Number(v.stock);
      return {
        name,
        price: Number.isFinite(price) && price > 0 ? price : (Number.isFinite(oldPrice) && oldPrice > 0 ? oldPrice : null),
        stock: v.stock === null || v.stock === '' || v.stock === undefined ? null : (Number.isFinite(stock) && stock >= 0 ? stock : null),
        active: v.active !== false
      };
    }
    return null;
  }).filter(Boolean);
}

// نوع واقعی ستون‌های colors/sizes را از دیتابیس فعال می‌خوانیم؛
// نسخه‌های قدیمی فروشگاه ممکن است text[] و نسخه‌های جدید jsonb داشته باشند.
async function getProductVariantColumnTypes() {
  const r = await db.query(`
    select column_name, udt_name
    from information_schema.columns
    where table_schema = current_schema()
      and table_name = 'products'
      and column_name in ('colors', 'sizes')
  `);
  const types = Object.fromEntries(r.rows.map(x => [x.column_name, x.udt_name]));
  for (const column of ['colors', 'sizes']) {
    if (!types[column] || !['_text', 'jsonb'].includes(types[column])) {
      throw new E('نوع ستون ' + column + ' در دیتابیس پشتیبانی نمی‌شود؛ ساختار دیتابیس را بررسی کنید', 500);
    }
  }
  return types;
}

function variantDbValue(items, udtName) {
  // text[]: هر object را به JSON string تبدیل می‌کنیم تا اطلاعات رنگ/سایز از بین نرود.
  // jsonb: کل آرایه به‌صورت JSON ذخیره می‌شود.
  return udtName === '_text' ? items.map(x => JSON.stringify(x)) : JSON.stringify(items);
}

// حدس HEX رنگ بر اساس نام فارسی/انگلیسی
function guessHex(name) {
  const map = {
    'قرمز': '#E53935', 'red': '#E53935',
    'آبی': '#1E88E5', 'blue': '#1E88E5',
    'سبز': '#43A047', 'green': '#43A047',
    'زرد': '#FDD835', 'yellow': '#FDD835',
    'مشکی': '#212121', 'black': '#212121',
    'سفید': '#FAFAFA', 'white': '#FAFAFA',
    'صورتی': '#EC407A', 'pink': '#EC407A',
    'بنفش': '#8E24AA', 'purple': '#8E24AA',
    'قهوه‌ای': '#6D4C41', 'brown': '#6D4C41',
    'نارنجی': '#FB8C00', 'orange': '#FB8C00',
    'طوسی': '#757575', 'gray': '#757575', 'خاکستری': '#757575',
    'فیروزه‌ای': '#00ACC1', 'teal': '#00ACC1',
    'طلایی': '#C9A45C', 'gold': '#C9A45C',
    'مارون': '#5D1049', 'maroon': '#5D1049',
    'کرم': '#FFF8E1', 'cream': '#FFF8E1',
    'بژ': '#D7CCC8', 'beige': '#D7CCC8',
    'یشمی': '#00695C',
    'لجنی': '#1565C0',
  };
  return map[String(name || '').trim().toLowerCase()] || '#999999';
}

// ---------- helper: استخراج موجودی/قیمت یک تنوع از JSONB نرمال‌شده ----------
// بر اساس نام (مثلاً "قرمز")، شیء تنوع را پیدا می‌کند.
function findVariant(arr, name) {
  if (!Array.isArray(arr) || !name) return null;
  return arr.find(v => (typeof v === 'string' ? v : v?.name) === name) || null;
}

// ---------- helper: بررسی خرید تأییدشده کاربر برای یک محصول ----------
// اگر کاربر حداقل یک سفارش تأییدشده با این محصول داشته باشد، true برمی‌گرداند.
async function isVerifiedBuyer(accountId, productId) {
  if (!accountId || !productId) return false;
  const r = await db.query(
    `select 1
     from orders o
     join customers c on c.id=o.customer_id
     join order_items oi on oi.order_id=o.id
     where c.account_id=$1 and oi.product_id=$2
       and o.status in ('payment_confirmed','preparing','ready','shipped','delivered')
     limit 1`,
    [accountId, productId]
  );
  return r.rowCount > 0;
}

// ---------- محصولات مرتبط (عمومی) ----------
// پیشنهادها: هم‌دسته + پرفروش + جدید، بدون تکرار محصول فعلی.
app.get('/api/products/:slug/related', A(async (q, s) => {
  const p = (await db.query('select id, category_id from products where slug=$1 and published', [q.params.slug])).rows[0];
  if (!p) throw new E('محصول پیدا نشد', 404);

  const fields = `p.id,p.slug,p.name,p.short_desc,p.price,p.discount_price,p.stock,
    c.name category_name,
    (select file from product_images i where i.product_id=p.id order by i.is_main desc,i.sort,i.id limit 1) image`;

  // ۱) هم‌دسته (حداکثر ۸)
  let related = [];
  if (p.category_id) {
    const sameCat = await db.query(
      `select ${fields} from products p left join categories c on c.id=p.category_id
       where p.published and p.category_id=$1 and p.id<>$2
       order by p.bestseller desc, p.sold desc, p.created_at desc
       limit 8`,
      [p.category_id, p.id]
    );
    related = sameCat.rows;
  }

  // ۲) پرفروش‌های کلی (تا ۸ مورد دیگر)
  const seen = new Set(related.map(r => r.id));
  seen.add(p.id);
  if (related.length < 8) {
    const best = await db.query(
      `select ${fields} from products p left join categories c on c.id=p.category_id
       where p.published and p.id<>$1
       order by p.bestseller desc, p.sold desc, p.created_at desc
       limit 12`,
      [p.id]
    );
    for (const r of best.rows) {
      if (related.length >= 8) break;
      if (!seen.has(r.id)) { related.push(r); seen.add(r.id); }
    }
  }

  s.json({
    items: related.map(x => ({
      ...x,
      image: x.image ? '/uploads/products/' + x.image : null
    }))
  });
}));

// ---------- علاقه‌مندی‌ها (Wishlist) ----------
// GET /api/wishlist — فهرست علاقه‌مندی‌های کاربر واردشده
app.get('/api/wishlist', customerAuth, A(async (q, s) => {
  const r = await db.query(
    `select w.product_id, w.created_at,
            p.id pid, p.slug, p.name, p.short_desc, p.price, p.discount_price, p.stock,
            c.name category_name,
            (select file from product_images i where i.product_id=p.id order by i.is_main desc,i.sort,i.id limit 1) image
     from wishlist w
     join products p on p.id=w.product_id
     left join categories c on c.id=p.category_id
     where w.account_id=$1 and p.published
     order by w.created_at desc`,
    [q.customerAccount.id]
  );
  s.json({
    items: r.rows.map(x => ({
      product_id: x.product_id,
      id: x.pid,
      slug: x.slug,
      name: x.name,
      short_desc: x.short_desc,
      price: x.price,
      discount_price: x.discount_price,
      stock: x.stock,
      category_name: x.category_name,
      image: x.image ? '/uploads/products/' + x.image : null,
      added_at: x.created_at
    }))
  });
}));

// POST /api/wishlist/:productId — افزودن محصول به علاقه‌مندی‌ها
app.post('/api/wishlist/:productId', customerAuth, A(async (q, s) => {
  const pid = +q.params.productId;
  if (!Number.isSafeInteger(pid) || pid <= 0) throw new E('شناسه محصول نامعتبر است');
  // بررسی وجود محصول
  const p = (await db.query('select 1 from products where id=$1 and published', [pid])).rows[0];
  if (!p) throw new E('محصول پیدا نشد', 404);
  await db.query(
    'insert into wishlist(account_id, product_id) values($1, $2) on conflict do nothing',
    [q.customerAccount.id, pid]
  );
  s.json({ ok: true });
}));

// DELETE /api/wishlist/:productId — حذف از علاقه‌مندی‌ها
app.delete('/api/wishlist/:productId', customerAuth, A(async (q, s) => {
  const pid = +q.params.productId;
  if (!Number.isSafeInteger(pid) || pid <= 0) throw new E('شناسه محصول نامعتبر است');
  await db.query(
    'delete from wishlist where account_id=$1 and product_id=$2',
    [q.customerAccount.id, pid]
  );
  s.json({ ok: true });
}));

// ---------- نظرات و امتیازدهی ----------
// GET /api/products/:slug/reviews — نظرات تأییدشده یک محصول
app.get('/api/products/:slug/reviews', A(async (q, s) => {
  const p = (await db.query('select id from products where slug=$1 and published', [q.params.slug])).rows[0];
  if (!p) throw new E('محصول پیدا نشد', 404);
  const sort = String(q.query.sort || 'new'); // new | helpful | rating
  const ord = {
    new: 'r.created_at desc',
    helpful: 'r.rating desc, r.created_at desc',
    rating: 'r.rating desc, r.created_at desc'
  }[sort] || 'r.created_at desc';

  const r = await db.query(
    `select r.id, r.title, r.body, r.rating, r.verified_buyer, r.created_at,
            ca.name author_name
     from product_reviews r
     join customer_accounts ca on ca.id=r.account_id
     where r.product_id=$1 and r.status='approved'
     order by ${ord}
     limit 100`,
    [p.id]
  );
  s.json({
    items: r.rows.map(x => ({
      ...x,
      author_name: x.author_name || 'کاربر زیبادوز'
    }))
  });
}));

// POST /api/products/:slug/reviews — ثبت نظر جدید (نیازمند ورود)
const reviewLimit = rateLimit({
  windowMs: 60 * 60 * 1000, max: 5, // حداکثر ۵ نظر در ساعت برای جلوگیری از اسپم
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'تعداد نظرات زیاد بود؛ بعداً دوباره امتحان کنید' }
});
app.post('/api/products/:slug/reviews', reviewLimit, customerAuth, A(async (q, s) => {
  const p = (await db.query('select id from products where slug=$1 and published', [q.params.slug])).rows[0];
  if (!p) throw new E('محصول پیدا نشد', 404);

  const b = q.body || {};
  const title = String(b.title || '').trim().slice(0, 200);
  const body = String(b.body || '').trim();
  const rating = Math.round(Number(b.rating));

  if (!body || body.length < 5) throw new E('متن نظر باید حداقل ۵ کاراکتر باشد');
  if (body.length > 2000) throw new E('متن نظر خیلی طولانی است (حداکثر ۲۰۰۰ کاراکتر)');
  if (!Number.isFinite(rating) || rating < 1 || rating > 5) throw new E('امتیاز باید بین ۱ تا ۵ باشد');

  // جلوگیری از تکرار: هر کاربر فقط یک نظر برای هر محصول
  const existing = await db.query(
    "select id from product_reviews where account_id=$1 and product_id=$2",
    [q.customerAccount.id, p.id]
  );
  if (existing.rowCount) {
    // ویرایش نظر موجود — انتشار فوری (approved)
    const verified = await isVerifiedBuyer(q.customerAccount.id, p.id);
    await db.query(
      `update product_reviews
       set title=$1, body=$2, rating=$3, verified_buyer=$4, status='approved', updated_at=now()
       where account_id=$5 and product_id=$6`,
      [title || null, body, rating, verified, q.customerAccount.id, p.id]
    );
    return s.json({ ok: true, message: 'نظر شما به‌روز شد' });
  }

  const verified = await isVerifiedBuyer(q.customerAccount.id, p.id);
  await db.query(
    `insert into product_reviews(product_id, account_id, title, body, rating, verified_buyer, status)
     values($1, $2, $3, $4, $5, $6, 'approved')`,
    [p.id, q.customerAccount.id, title || null, body, rating, verified]
  );
  s.json({ ok: true, message: 'نظر شما ثبت شد' });
}));

// ---------- پرسش و پاسخ ----------
// GET /api/products/:slug/questions — پرسش‌های پاسخ‌داده‌شده
app.get('/api/products/:slug/questions', A(async (q, s) => {
  const p = (await db.query('select id from products where slug=$1 and published', [q.params.slug])).rows[0];
  if (!p) throw new E('محصول پیدا نشد', 404);
  const r = await db.query(
    `select q.id, q.question, q.answer, q.created_at, q.answered_at,
            ca.name asker_name
     from product_questions q
     join customer_accounts ca on ca.id=q.account_id
     where q.product_id=$1 and q.status='answered'
     order by q.answered_at desc
     limit 100`,
    [p.id]
  );
  s.json({
    items: r.rows.map(x => ({
      ...x,
      asker_name: x.asker_name || 'کاربر زیبادوز'
    }))
  });
}));

// POST /api/products/:slug/questions — ثبت پرسش جدید
const questionLimit = rateLimit({
  windowMs: 60 * 60 * 1000, max: 10,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'تعداد پرسش‌ها زیاد بود؛ بعداً دوباره امتحان کنید' }
});
app.post('/api/products/:slug/questions', questionLimit, customerAuth, A(async (q, s) => {
  const p = (await db.query('select id from products where slug=$1 and published', [q.params.slug])).rows[0];
  if (!p) throw new E('محصول پیدا نشد', 404);

  const question = String((q.body || {}).question || '').trim();
  if (!question || question.length < 5) throw new E('پرسش باید حداقل ۵ کاراکتر باشد');
  if (question.length > 500) throw new E('پرسش خیلی طولانی است (حداکثر ۵۰۰ کاراکتر)');

  await db.query(
    'insert into product_questions(product_id, account_id, question, status) values($1, $2, $3, $4)',
    [p.id, q.customerAccount.id, question, 'pending']
  );
  s.json({ ok: true, message: 'پرسش شما ثبت شد و پس از پاسخ مدیر نمایش داده می‌شود' });
}));

// ---------- تاریخچه بازدید ----------
// GET /api/account/recent-views — محصولات اخیراً مشاهده‌شده توسط کاربر واردشده
app.get('/api/account/recent-views', customerAuth, A(async (q, s) => {
  const r = await db.query(
    `select distinct on (vh.product_id)
            vh.product_id, vh.viewed_at,
            p.id pid, p.slug, p.name, p.short_desc, p.price, p.discount_price, p.stock,
            c.name category_name,
            (select file from product_images i where i.product_id=p.id order by i.is_main desc,i.sort,i.id limit 1) image
     from product_view_history vh
     join products p on p.id=vh.product_id
     left join categories c on c.id=p.category_id
     where vh.account_id=$1 and p.published
     order by vh.product_id, vh.viewed_at desc
     limit 20`,
    [q.customerAccount.id]
  );
  // مرتب‌سازی بر اساس آخرین بازدید
  r.rows.sort((a, b) => new Date(b.viewed_at) - new Date(a.viewed_at));
  s.json({
    items: r.rows.map(x => ({
      id: x.pid,
      slug: x.slug,
      name: x.name,
      short_desc: x.short_desc,
      price: x.price,
      discount_price: x.discount_price,
      stock: x.stock,
      category_name: x.category_name,
      image: x.image ? '/uploads/products/' + x.image : null,
      viewed_at: x.viewed_at
    }))
  });
}));

// DELETE /api/account/recent-views — پاک‌کردن تاریخچه بازدید
app.delete('/api/account/recent-views', customerAuth, A(async (q, s) => {
  await db.query('delete from product_view_history where account_id=$1', [q.customerAccount.id]);
  s.json({ ok: true });
}));

// GET /api/account/wishlist — همان /api/wishlist ولی با مسیر account (برای یکپارچگی)
app.get('/api/account/wishlist', customerAuth, A(async (q, s) => {
  const r = await db.query(
    `select w.product_id, w.created_at,
            p.id pid, p.slug, p.name, p.short_desc, p.price, p.discount_price, p.stock,
            c.name category_name,
            (select file from product_images i where i.product_id=p.id order by i.is_main desc,i.sort,i.id limit 1) image
     from wishlist w
     join products p on p.id=w.product_id
     left join categories c on c.id=p.category_id
     where w.account_id=$1 and p.published
     order by w.created_at desc`,
    [q.customerAccount.id]
  );
  s.json({
    items: r.rows.map(x => ({
      product_id: x.product_id,
      id: x.pid,
      slug: x.slug,
      name: x.name,
      short_desc: x.short_desc,
      price: x.price,
      discount_price: x.discount_price,
      stock: x.stock,
      category_name: x.category_name,
      image: x.image ? '/uploads/products/' + x.image : null
    }))
  });
}));

// ---------- کمپین‌های فعال (عمومی) ----------
app.get('/api/campaigns', A(async (q, s) => {
  const r = await db.query(`
    select id, title, description, image, discount_type, discount_value,
           category_id, product_ids, starts_at, ends_at
    from campaigns
    where is_active = true and starts_at <= now()
      and (ends_at is null or ends_at >= now())
    order by created_at desc
  `);
  s.json({
    items: r.rows.map(x => ({
      ...x,
      image: x.image ? '/uploads/campaigns/' + x.image : null,
      product_ids: Array.isArray(x.product_ids) ? x.product_ids : []
    }))
  });
}));

// ---------- بسته‌های اقتصادی فعال (عمومی) ----------
app.get('/api/bundles', A(async (q, s) => {
  const r = await db.query(`
    select b.id, b.title, b.description, b.image, b.bundle_price, b.original_price, b.sort_order
    from product_bundles b
    where b.is_active = true
    order by b.sort_order asc, b.id desc
  `);
  // دریافت اقلام هر بسته
  const bundles = [];
  for (const b of r.rows) {
    const items = await db.query(`
      select bi.qty, p.id, p.slug, p.name, p.price, p.stock,
             (select file from product_images i where i.product_id=p.id order by i.is_main desc,i.sort,i.id limit 1) image
      from bundle_items bi
      join products p on p.id=bi.product_id
      where bi.bundle_id=$1 and p.published
    `, [b.id]);
    bundles.push({
      ...b,
      image: b.image ? '/uploads/bundles/' + b.image : null,
      items: items.rows.map(i => ({ ...i, image: i.image ? '/uploads/products/' + i.image : null }))
    });
  }
  s.json({ items: bundles });
}));

// ---------- ثبت آمار بنر (عمومی) ----------
// POST /api/banners/:id/stats — ثبت view یا click
const bannerStatsLimit = rateLimit({
  windowMs: 60 * 1000, max: 30,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'too many' }
});
app.post('/api/banners/:id/stats', bannerStatsLimit, A(async (q, s) => {
  const id = +q.params.id;
  const type = String((q.body || {}).type || '').trim();
  if (!Number.isSafeInteger(id) || id <= 0) throw new E('شناسه نامعتبر');
  if (!['view', 'click'].includes(type)) throw new E('نوع رویداد نامعتبر (view/click)');
  // بررسی وجود بنر
  const b = (await db.query('select 1 from banners where id=$1 and is_active=true', [id])).rows[0];
  if (!b) throw new E('بنر پیدا نشد', 404);
  await db.query('insert into banner_stats(banner_id, event_type) values($1, $2)', [id, type]);
  s.json({ ok: true });
}));

// ---------- روش‌های ارسال فعال (عمومی) ----------
app.get('/api/shipping-methods', A(async (q, s) => {
  const r = await db.query(`
    select id, name, description, base_cost, free_shipping_threshold, sort_order
    from shipping_methods
    where is_active = true
    order by sort_order asc, id asc
  `);
  s.json({ items: r.rows });
}));

// ---------- امتیاز باشگاه مشتریان ----------
// GET /api/account/points — موجودی و تاریخچه امتیاز
app.get('/api/account/points', customerAuth, A(async (q, s) => {
  const acc = (await db.query('select points_balance from customer_accounts where id=$1', [q.customerAccount.id])).rows[0];
  if (!acc) throw new E('حساب پیدا نشد', 404);
  const txns = await db.query(
    `select id, amount, type, reason, order_id, created_at
     from point_transactions where account_id=$1 order by created_at desc limit 50`,
    [q.customerAccount.id]
  );
  s.json({
    balance: acc.points_balance,
    transactions: txns.rows
  });
}));

// ---------- بنرهای تبلیغاتی (عمومی) ----------
// فقط بنرهای فعال را برمی‌گرداند، با JOIN به categories برای گرفتن slug و name.
// بنرهایی که category_id نامعتبر دارند (دسته‌بندی حذف شده) category_slug=null برمی‌گردانند
// تا سمت کلاینت بتواند لینک را خاموش کند.
app.get('/api/banners', A(async (q, s) => {
  const r = await db.query(`
    select b.id, b.title, b.image, b.category_id,
           c.name  category_name,
           c.slug  category_slug
    from banners b
    left join categories c on c.id = b.category_id
    where b.is_active = true
    order by b.sort_order asc, b.id asc
  `);
  s.json({
    items: r.rows.map(x => ({
      id: x.id,
      title: x.title,
      image: x.image ? '/uploads/banners/' + x.image : null,
      category_id: x.category_id,
      category_name: x.category_name,
      category_slug: x.category_slug
    }))
  });
}));

// صفحات جداگانه فروشگاه + صفحه اختصاصی محصول — همه همان index.html را می‌فرستند
// و سمت کلاینت بر اساس location.pathname صفحه مناسب را نمایش می‌دهد.
app.get(['/product/:slug', '/products', '/about', '/track'], (q, s) => {
  s.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// تولید شماره سفارش کوتاه: عدد ۴ رقمی تصادفی (با بررسی یکتایی)
async function generateOrderNumber() {
  for (let i = 0; i < 20; i++) {
    const num = String(1000 + Math.floor(Math.random() * 9000));
    const r = await db.query('select 1 from orders where order_number=$1', [num]);
    if (!r.rowCount) return num;
  }
  // در صورت تصادف نادر، fallback به ۶ رقم از timestamp
  return String(Date.now()).slice(-6);
}

const orderLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });

app.post('/api/coupons/validate', orderLimit, A(async (q, s) => {
  const code = String((q.body || {}).code || '').trim().toUpperCase();
  const subtotal = Number((q.body || {}).subtotal);
  if (!code || !Number.isFinite(subtotal) || subtotal <= 0) throw new E('کد تخفیف یا مبلغ سفارش نامعتبر است');
  const c = (await db.query('select * from coupons where upper(code)=$1 and active=true', [code])).rows[0];
  if (!c) throw new E('کد تخفیف معتبر نیست');
  if (c.expires_at && new Date(c.expires_at) < new Date()) throw new E('اعتبار این کد تخفیف به پایان رسیده است');
  if (c.usage_limit !== null && c.used_count >= c.usage_limit) throw new E('ظرفیت استفاده از این کد تخفیف تمام شده است');
  if (subtotal < Number(c.min_order || 0)) throw new E('حداقل مبلغ خرید برای این کد تخفیف رعایت نشده است');
  const discount = c.discount_type === 'percent' ? Math.floor(subtotal * Math.min(100, Number(c.discount_value))/100) : Math.min(subtotal, Number(c.discount_value));
  s.json({ valid:true, code:c.code, discount, discount_type:c.discount_type, discount_value:c.discount_value });
}));

app.post('/api/orders', orderLimit, customerAuth, A(async (q, s) => {
  const c = (q.body || {}).customer || {};
  const items = (q.body || {}).items;

  const name = String(c.name || '').trim();
  const mobile = norm(c.mobile).replace(/\D/g, '');
  const postalCode = norm(c.postal_code).replace(/\D/g, '');

  if (name.length < 3 || !/^09\d{9}$/.test(mobile) || !c.province || !c.city ||
      String(c.address || '').trim().length < 8 || !/^\d{10}$/.test(postalCode)) {
    throw new E('اطلاعات واردشده صحیح نیست');
  }

  if (!Array.isArray(items) || !items.length || items.length > 50) {
    throw new E('سبد خرید خالی است');
  }

  const st = await settings();
  if (st.shop_active !== '1') throw new E('فروشگاه موقتاً غیرفعال است');

  const cl = await db.connect();

  try {
    await cl.query('begin');

    let sub = 0;
    const rows = [];
    const grouped = new Map();
    const products = new Map();

    for (const it of items) {
      const qtyText = String(it.qty ?? '');
      const pidText = String(it.product_id ?? '');

      if (!/^\d+$/.test(qtyText) || !/^\d+$/.test(pidText)) {
        throw new E('اطلاعات سبد خرید نامعتبر است');
      }

      const qty = Number(qtyText);
      const pid = Number(pidText);

      if (!(qty > 0 && qty <= 100) || !Number.isSafeInteger(pid) || !pid) {
        throw new E('اطلاعات سبد خرید نامعتبر است');
      }

      grouped.set(pid, (grouped.get(pid) || 0) + qty);

      if (grouped.get(pid) > 100) {
        throw new E('تعداد یک محصول بیش از حد مجاز است');
      }

      rows.push({
        pid,
        qty,
        color: String(it.color || '').trim(),
        size: String(it.size || '').trim()
      });
    }

    // بررسی موجودی کل هر محصول
    for (const [pid, qty] of grouped) {
      const p = (await cl.query(
        'select * from products where id=$1 and published for update',
        [pid]
      )).rows[0];

      if (!p) throw new E('یکی از محصولات سبد دیگر موجود نیست');
      if (p.stock < qty) throw new E('موجودی «' + p.name + '» کافی نیست');

      products.set(pid, p);
    }

    // اعتبارسنجی رنگ و سایز هر ردیف سفارش
    // پشتیبانی از تنوع پیشرفته (JSONB با stock/price_override)
    for (const row of rows) {
      const p = products.get(row.pid);
      const colors = normalizeVariants(p.colors, 'color');
      const sizes = normalizeVariants(p.sizes, 'size');

      // اعتبارسنجی رنگ
      if (colors.length) {
        if (!row.color) throw new E('لطفاً رنگ محصول «' + p.name + '» را انتخاب کنید');
        const colorVariant = colors.find(c => c.name === row.color);
        if (!colorVariant) throw new E('رنگ انتخاب‌شده برای «' + p.name + '» معتبر نیست');
      } else {
        row.color = '';
      }

      // اعتبارسنجی سایز — قیمت و موجودی مستقل برای هر سایز
      let sizePrice = null;
      let sizeStock = null;
      if (sizes.length) {
        if (!row.size) throw new E('لطفاً سایز محصول «' + p.name + '» را انتخاب کنید');
        const sizeVariant = sizes.find(s => s.name === row.size);
        if (!sizeVariant) throw new E('سایز انتخاب‌شده برای «' + p.name + '» معتبر نیست');
        if (sizeVariant.active === false) throw new E('سایز «' + row.size + '» برای «' + p.name + '» غیرفعال است');
        sizePrice = sizeVariant.price; // قیمت مستقل سایز
        sizeStock = sizeVariant.stock; // موجودی مستقل سایز
        if (sizeStock !== null) {
          const usedForSize = rows.filter(r => r.pid === row.pid && r.color === row.color && r.size === row.size)
            .reduce((n, r) => n + r.qty, 0);
          if (usedForSize > sizeStock) {
            throw new E('موجودی سایز «' + row.size + '» برای «' + p.name + '» کافی نیست');
          }
        }
        // اگر همه سایزها ناموجود هستند، خرید مجاز نیست
        const anyAvailable = sizes.some(s => s.active !== false && (s.stock === null || s.stock > 0));
        if (!anyAvailable) throw new E('محصول «' + p.name + '» ناموجود است');
      } else {
        row.size = '';
      }

      // محاسبه قیمت واحد سمت سرور (امنیت قیمت)
      // اگر سایز انتخاب شده و قیمت مستقل دارد → از قیمت سایز استفاده کن
      // در غیر این صورت از قیمت اصلی محصول (با تخفیف اگر دارد) استفاده کن
      let unit;
      if (sizePrice !== null && sizePrice > 0) {
        unit = sizePrice;
      } else {
        unit = p.discount_price && p.discount_price < p.price ? p.discount_price : p.price;
      }

      sub += unit * row.qty;
      row.p = p;
      row.unit = unit;
    }

    if (sub < (+st.min_order || 0)) {
      throw new E('مبلغ سفارش کمتر از حداقل سفارش است');
    }

    // محاسبه هزینه ارسال از جدول shipping_methods
    // اگر کاربر shipping_method_id انتخاب کرده → از آن روش استفاده کن
    // در غیر این صورت → اولین روش فعال
    const reqShippingMethodId = Number((q.body || {}).shipping_method_id) || null;
    let shipMethod = null;
    if (reqShippingMethodId) {
      shipMethod = (await cl.query('select * from shipping_methods where id=$1 and is_active=true', [reqShippingMethodId])).rows[0];
    }
    if (!shipMethod) {
      shipMethod = (await cl.query('select * from shipping_methods where is_active=true order by sort_order, id limit 1')).rows[0];
    }
    let ship;
    if (shipMethod) {
      ship = Math.max(0, Number(shipMethod.base_cost) || 0);
      // اگر آستانه ارسال رایگان دارد و جمع سفارش از آن بیشتر است → ارسال رایگان
      if (shipMethod.free_shipping_threshold && sub >= Number(shipMethod.free_shipping_threshold)) {
        ship = 0;
      }
    } else {
      // fallback: از تنظیمات قدیمی shipping_fee استفاده کن
      ship = Math.max(0, Number(st.shipping_fee) || 150000);
    }
    const couponCode = String((q.body || {}).coupon_code || '').trim().toUpperCase();
    let discount = 0, coupon = null;
    if (couponCode) {
      coupon = (await cl.query('select * from coupons where upper(code)=$1 and active=true for update', [couponCode])).rows[0];
      if (!coupon) throw new E('کد تخفیف معتبر نیست یا غیرفعال شده است');
      if (coupon.expires_at && new Date(coupon.expires_at) < new Date()) throw new E('اعتبار این کد تخفیف به پایان رسیده است');
      if (coupon.usage_limit !== null && coupon.used_count >= coupon.usage_limit) throw new E('ظرفیت استفاده از این کد تخفیف تمام شده است');
      if (sub < Number(coupon.min_order || 0)) throw new E('حداقل مبلغ خرید برای این کد تخفیف رعایت نشده است');
      discount = coupon.discount_type === 'percent'
        ? Math.floor(sub * Math.min(100, Number(coupon.discount_value)) / 100)
        : Math.min(sub, Number(coupon.discount_value));
    }
    const total = Math.max(0, sub + ship - discount);

    let accountId = null;
    if (q.customerAccount) {
      const account = (await cl.query(
        'select id,mobile from customer_accounts where id=$1 for update',
        [q.customerAccount.id]
      )).rows[0];
      if (!account) throw new E('حساب کاربری معتبر نیست', 401);
      if (account.mobile && account.mobile !== mobile) {
        throw new E('شماره موبایل سفارش باید با شماره حساب کاربری یکسان باشد');
      }
      if (!account.mobile) {
        await cl.query('update customer_accounts set mobile=$1 where id=$2', [mobile, account.id]);
      }
      accountId = account.id;
    }

    const cu = (await cl.query(
      'insert into customers(name,mobile,province,city,address,postal_code,account_id) values($1,$2,$3,$4,$5,$6,$7) returning id',
      [
        name,
        mobile,
        String(c.province).slice(0, 60),
        String(c.city).slice(0, 60),
        String(c.address).slice(0, 500),
        postalCode,
        accountId
      ]
    )).rows[0].id;

    const num = await generateOrderNumber();

    const oid = (await cl.query(
      'insert into orders(order_number,customer_id,subtotal,shipping,discount,coupon_code,total,notes) values($1,$2,$3,$4,$5,$6,$7,$8) returning id',
      [num, cu, sub, ship, discount, couponCode || null, total, String(c.notes || '').slice(0, 500)]
    )).rows[0].id;

    // ثبت جداگانه هر ترکیب رنگ و سایز
    for (const r of rows) {
      await cl.query(
        'insert into order_items(order_id,product_id,name,unit_price,qty,color,size) values($1,$2,$3,$4,$5,$6,$7)',
        [oid, r.p.id, r.p.name, r.unit, r.qty, r.color, r.size]
      );
    }

    // کم کردن موجودی بر اساس مجموع تعداد محصول
    for (const [pid, qty] of grouped) {
      await cl.query('update products set stock=stock-$1 where id=$2', [qty, pid]);
    }

    await cl.query(
      'insert into order_status_history(order_id,status,note) values($1,$2,$3)',
      [oid, 'order_placed', 'سفارش ثبت شد']
    );

    await cl.query(
      'insert into order_status_history(order_id,status,note) values($1,$2,$3)',
      [oid, 'pending_payment', 'در انتظار تأیید پرداخت']
    );

    if (coupon) {
      await cl.query('update coupons set used_count=used_count+1 where id=$1', [coupon.id]);
      // ثبت استفاده در coupon_usage برای tracking per_customer_limit
      await cl.query(
        'insert into coupon_usage(coupon_id, account_id, order_id, customer_mobile) values($1,$2,$3,$4)',
        [coupon.id, accountId, oid, mobile]
      );
    }
    await cl.query('commit');

    s.json({
      order_number: num,
      total,
      subtotal: sub,
      shipping: ship,
      discount,
      coupon_code: couponCode || null,
      payment: payInfo(st)
    });

  } catch (e) {
    await cl.query('rollback');
    throw e;
  } finally {
    cl.release();
  }
}));
async function ownOrder(num, mobile) {
  const o = (await db.query(
    'select o.* from orders o join customers c on c.id=o.customer_id where o.order_number=$1 and c.mobile=$2',
    [String(num), norm(mobile).replace(/\D/g, '')]
  )).rows[0];

  if (!o) throw new E('سفارش پیدا نشد', 404);
  return o;
}

app.post('/api/orders/track', orderLimit, A(async (q, s) => {
  const o = await ownOrder((q.body || {}).order_number, (q.body || {}).mobile);

  const items = (await db.query(
    'select name,unit_price,qty,color,size from order_items where order_id=$1',
    [o.id]
  )).rows;

  const history = (await db.query(
    'select status,note,created_at from order_status_history where order_id=$1 order by id',
    [o.id]
  )).rows;

  const r = {
    order_number: o.order_number,
    status: o.status,
    total: o.total,
    tracking_code: o.tracking_code,
    created_at: o.created_at,
    items,
    history
  };

  if (['pending_payment', 'payment_rejected'].includes(o.status)) {
    r.payment = payInfo(await settings());
  }

  s.json(r);
}));

app.post('/api/orders/:num/receipt', orderLimit, upload.single('receipt'), A(async (q, s) => {
  if (!q.file) throw new E('تصویر رسید انتخاب نشده است');

  const cl = await db.connect();
  let saved = null;

  try {
    await cl.query('begin');

    const o = (await cl.query(
      `select o.id,o.status from orders o join customers c on c.id=o.customer_id
       where o.order_number=$1 and c.mobile=$2 for update of o`,
      [String(q.params.num), norm(q.body.mobile).replace(/\D/g, '')]
    )).rows[0];

    if (!o) throw new E('سفارش پیدا نشد', 404);

    if (!['pending_payment', 'payment_rejected'].includes(o.status)) {
      throw new E('برای این سفارش امکان ارسال رسید وجود ندارد');
    }

    saved = saveFile(q.file.buffer, 'receipts');

    await cl.query(
      'insert into payment_receipts(order_id,file) values($1,$2)',
      [o.id, saved]
    );

    await cl.query(
      "update orders set status='receipt_sent' where id=$1",
      [o.id]
    );

    await cl.query(
      'insert into order_status_history(order_id,status,note) values($1,$2,$3)',
      [o.id, 'receipt_sent', 'رسید توسط مشتری ارسال شد']
    );

    await cl.query('commit');
    s.json({ ok: true });

  } catch (e) {
    await cl.query('rollback');
    if (saved) rm('receipts', saved);
    throw e;
  } finally {
    cl.release();
  }
}));

// ---------- مدیر ----------
const auth = (q, s, n) => {
  try {
    const h = String(q.headers.authorization || '');
    if (!/^Bearer\s+/i.test(h)) throw new Error('no token');
    q.admin = jwt.verify(h.replace(/^Bearer\s+/i, ''), SECRET, { issuer: JWT_ISSUER, audience: JWT_AUDIENCE });
    n();
  } catch {
    s.status(401).json({ error: 'دسترسی غیرمجاز' });
  }
};

const log = (q, a, d) => db.query(
  'insert into admin_activity_logs(admin,action,detail) values($1,$2,$3)',
  [q.admin.u, a, String(d || '').slice(0, 300)]
).catch(() => {});

const loginLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'تلاش‌های ناموفق زیاد بود؛ بعداً دوباره امتحان کنید' }
});

app.post('/api/admin/login', loginLimit, A(async (q, s) => {
  const { username, password } = q.body || {};
  const uname = String(username || '').trim().slice(0, 60);

  // قفل حساب بعد از چند شکست متوالی
  if (isLocked(uname)) {
    throw new E('این حساب پس از چند تلاش ناموفق موقتاً قفل شد؛ حدود ۳۰ دقیقه بعد دوباره امتحان کنید', 429);
  }

  const r = (await db.query(
    'select * from admin_users where username=$1',
    [uname]
  )).rows[0];

  // مقایسه با bcrypt + زمان‌ثابت برای کاهش نشت اطلاعات timing
  const ok = r ? await bcrypt.compare(String(password || ''), r.password_hash) : false;
  if (!r || !ok) {
    registerFail(uname);
    // برای جلوگیری از تشخیص کاربر موجود/ناموجود، پیام یکسان برمی‌گردد
    throw new E('نام کاربری یا رمز عبور اشتباه است', 401);
  }

  clearFails(uname);

  s.json({
    token: jwt.sign(
      { id: r.id, u: r.username, type: 'admin' },
      SECRET,
      { expiresIn: '8h', issuer: JWT_ISSUER, audience: JWT_AUDIENCE, notBefore: 0 }
    )
  });
}));

const ad = express.Router();
ad.use(auth);
app.use('/api/admin', ad);

ad.get('/stats', A(async (q, s) => {
  const r = await db.query(`
    select
      (select count(*) from products) products,
      (select count(*) from products where published) active,
      (select count(*) from products where stock=0) out_of_stock,
      (select count(*) from orders where status='pending_payment') pending,
      (select count(*) from orders where status='receipt_sent') review,
      (select count(*) from orders where status='payment_confirmed') paid,
      (select count(*) from orders where status in('payment_confirmed','preparing','ready')) pending_completion,
      (select count(*) from orders where status in('preparing','ready')) preparing,
      (select count(*) from orders where status='shipped') shipped,
      (select coalesce(sum(total),0) from orders where paid_at is not null and status<>'cancelled') revenue
  `);

  s.json(r.rows[0]);
}));

ad.get('/categories', A(async (q, s) => {
  s.json((await db.query('select * from categories order by sort,id')).rows);
}));

ad.post('/categories', A(async (q, s) => {
  const n = String(q.body.name || '').trim();
  if (!n) throw new E('نام دسته‌بندی لازم است');

  await db.query(
    'insert into categories(name,slug,sort) values($1,$2,(select coalesce(max(sort),0)+1 from categories))',
    [n, n.replace(/\s+/g, '-') + '-' + crypto.randomBytes(2).toString('hex')]
  );

  log(q, 'category+', n);
  s.json({ ok: true });
}));

ad.put('/categories/:id', A(async (q, s) => {
  await db.query(
    'update categories set name=$1,sort=coalesce($2,sort) where id=$3',
    [String(q.body.name || '').trim(), q.body.sort ?? null, +q.params.id]
  );
  s.json({ ok: true });
}));

ad.delete('/categories/:id', A(async (q, s) => {
  await db.query('delete from categories where id=$1', [+q.params.id]);
  log(q, 'category-', q.params.id);
  s.json({ ok: true });
}));

ad.get('/products', A(async (q, s) => {
  const r = await db.query(`
    select p.*,
      (select file from product_images i where i.product_id=p.id order by is_main desc,sort,id limit 1) image,
      (select json_agg(json_build_object('id',i.id,'file',i.file,'is_main',i.is_main) order by i.is_main desc,i.id)
       from product_images i where i.product_id=p.id) images
    from products p
    order by p.id desc
  `);

  s.json(r.rows.map(p => {
    delete p.search_text;
    // نرمال‌سازی colors/sizes به فرمت پیشرفته
    p.colors = normalizeVariants(p.colors, 'color');
    p.sizes = normalizeVariants(p.sizes, 'size');
    return p;
  }));
}));

const saveProduct = A(async (q, s) => {
  const b = q.body;

  if (!String(b.name || '').trim() || !(+b.price > 0)) {
    throw new E('نام و قیمت الزامی است');
  }

  const files = Array.isArray(q.files) ? q.files : [];
  if (files.length > 8) throw new E('حداکثر ۸ تصویر برای هر محصول مجاز است');
  if (files.some(f => !kind(f.buffer))) {
    throw new E('فقط تصویر JPEG/PNG/WebP مجاز است');
  }

  const price = Math.round(+b.price);
  const dp = +b.discount_price > 0 && +b.discount_price < price
    ? Math.round(+b.discount_price)
    : null;

  // پشتیبانی از هر دو فرمت colors/sizes:
  //   - JSON string با ساختار پیشرفته [{name,hex}] برای رنگ و [{name,price,stock,active}] برای سایز
  //   - رشته ساده با ویرگول: "قرمز، آبی، مشکی"
  const parseVariants = (input, kind) => {
    if (!input) return [];
    if (Array.isArray(input)) return normalizeVariants(input, kind);
    const s = String(input).trim();
    if (!s) return [];
    if (s.startsWith('[')) {
      try {
        const parsed = JSON.parse(s);
        if (Array.isArray(parsed)) return normalizeVariants(parsed, kind);
      } catch (_) {}
    }
    // ورودی ساده با ویرگول؛ رنگ و سایز با ساختار درست خودشان ساخته می‌شوند.
    return s.split(/[,،]/).map(t => t.trim()).filter(Boolean).map(name =>
      kind === 'size'
        ? { name, price: null, stock: null, active: true }
        : { name, hex: guessHex(name) }
    );
  };

  const colors = parseVariants(b.colors, 'color');
  const sizes = parseVariants(b.sizes, 'size');

  // تشخیص نوع ستون و آماده‌سازی مقدار و کست مناسب
  const vt = await getVariantTypes();
  const colorsVal = vt.colors === '_text' ? colors.map(x => JSON.stringify(x)) : JSON.stringify(colors);
  const sizesVal = vt.sizes === '_text' ? sizes.map(x => JSON.stringify(x)) : JSON.stringify(sizes);
  const colorsCast = vt.colors === '_text' ? '::text[]' : '::jsonb';
  const sizesCast = vt.sizes === '_text' ? '::text[]' : '::jsonb';

  const v = [
    b.name.trim(),
    b.short_desc || '',
    b.description || '',
    price,
    dp,
    +b.category_id || null,
    Math.max(0, parseInt(b.stock) || 0),
    colorsVal,
    sizesVal,
    b.published === '1',
    b.featured === '1',
    b.bestseller === '1',
    norm([b.name, b.keywords, b.short_desc, b.description].join(' ')),
    String(b.keywords || '').slice(0, 2000)
  ];

  let id = q.params.id && +q.params.id;

  if (id) {
    await db.query(
      'update products set name=$1,short_desc=$2,description=$3,price=$4,discount_price=$5,category_id=$6,stock=$7,colors=$8'+colorsCast+',sizes=$9'+sizesCast+',published=$10,featured=$11,bestseller=$12,search_text=$13,search_keywords=$14,updated_at=now() where id=$15',
      [...v, id]
    );
  } else {
    const slug = (
      b.name.trim().replace(/\s+/g, '-').replace(/[^\u0600-\u06FFa-zA-Z0-9-]/g, '') || 'product'
    ) + '-' + crypto.randomBytes(2).toString('hex');

    id = (await db.query(
      'insert into products(name,short_desc,description,price,discount_price,category_id,stock,colors,sizes,published,featured,bestseller,search_text,search_keywords,slug) values($1,$2,$3,$4,$5,$6,$7,$8'+colorsCast+',$9'+sizesCast+',$10,$11,$12,$13,$14,$15) returning id',
      [...v, slug]
    )).rows[0].id;
  }

  for (const r of list(b.remove_images)) {
    const d = (await db.query(
      'delete from product_images where id=$1 and product_id=$2 returning file',
      [+r, id]
    )).rows[0];

    if (d) rm('products', d.file);
  }

  const hasMain = (await db.query(
    'select 1 from product_images where product_id=$1 and is_main',
    [id]
  )).rowCount > 0;

  let first = !hasMain;

  for (const f of files) {
    await db.query(
      'insert into product_images(product_id,file,is_main) values($1,$2,$3)',
      [id, saveFile(f.buffer, 'products'), first]
    );
    first = false;
  }

  if (+b.main_image) {
    await db.query(
      'update product_images set is_main=(id=$2) where product_id=$1',
      [id, +b.main_image]
    );
  }

  log(q, 'product', id + ' ' + b.name);
  s.json({ id });
});

// دریافت چند تصویر با هر نام فیلد فایل از فرم مدیریت (images، images[] و ...).
// فرم‌های قدیمی و جدید بدون نیاز به تغییر HTML پشتیبانی می‌شوند.
ad.post('/products', upload.any(), saveProduct);
ad.put('/products/:id', upload.any(), saveProduct);

ad.delete('/products/:id', A(async (q, s) => {
  const id = +q.params.id;

  const images = (await db.query(
    'select file from product_images where product_id=$1',
    [id]
  )).rows;

  const deleted = (await db.query(
    'delete from products where id=$1 returning id',
    [id]
  )).rowCount;

  if (deleted) images.forEach(x => rm('products', x.file));

  log(q, 'product-', id);
  s.json({ ok: !!deleted });
}));
ad.get('/orders', A(async (q, s) => {
  const v = [];
  const w = [];

  if (q.query.status) {
    v.push(q.query.status);
    w.push('o.status=$1');
  }

  const r = await db.query(`
    select o.id,o.order_number,o.total,o.status,o.created_at,c.name,c.mobile
    from orders o
    join customers c on c.id=o.customer_id
    ${w.length ? 'where ' + w.join(' and ') : ''}
    order by o.id desc
    limit 200
  `, v);

  s.json(r.rows);
}));

// حذف یک سفارش خاص (همراه با همه وابسته‌ها: items، status_history، receipts)
ad.delete('/orders/:id', A(async (q, s) => {
  const id = +q.params.id;
  if (!Number.isSafeInteger(id) || id <= 0) throw new E('شناسه سفارش نامعتبر است');
  const r = await db.query('delete from orders where id=$1 returning id', [id]);
  if (!r.rowCount) throw new E('سفارش پیدا نشد', 404);
  log(q, 'order-delete', String(id));
  s.json({ ok: true });
}));

// پاک‌کردن همه سفارش‌های تکمیل‌شده یا لغوشده (برای شروع تازه پنل)
ad.post('/orders/clear-finished', A(async (q, s) => {
  const r = await db.query(
    "delete from orders where status in ('delivered','cancelled') returning id"
  );
  log(q, 'orders-clear-finished', `${r.rowCount} سفارش`);
  s.json({ ok: true, deleted: r.rowCount });
}));

// ---------- مدیریت بنرهای تبلیغاتی ----------
// همه endpoint ها پشت auth مدیر هستند (ad.use(auth) در بالا).

// محدودیت حجم تصویر بنر: ۵ مگابایت (هماهنگ با محدودیت محصولات)
const bannerUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 1 }
});

// GET /api/admin/banners — فهرست همه بنرها (فعال و غیرفعال) برای پنل مدیریت
ad.get('/banners', A(async (q, s) => {
  const r = await db.query(`
    select b.id, b.title, b.image, b.category_id, b.is_active, b.sort_order,
           b.created_at, b.updated_at,
           c.name category_name
    from banners b
    left join categories c on c.id = b.category_id
    order by b.sort_order asc, b.id desc
  `);
  s.json(r.rows.map(x => ({
    ...x,
    image: x.image ? '/uploads/banners/' + x.image : null,
    raw_image: x.image
  })));
}));

// POST /api/admin/banners — ایجاد بنر جدید (با آپلود تصویر)
ad.post('/banners', bannerUpload.single('image'), A(async (q, s) => {
  const b = q.body || {};
  const title = String(b.title || '').trim();
  if (!title) throw new E('عنوان بنر الزامی است');
  if (title.length > 200) throw new E('عنوان بنر خیلی طولانی است');

  if (!q.file) throw new E('تصویر بنر را انتخاب کنید');
  // بررسی magic bytes (همان تابع kind)
  if (!kind(q.file.buffer)) throw new E('فقط تصویر JPEG/PNG/WebP مجاز است');

  const categoryId = b.category_id ? Number(b.category_id) : null;
  if (categoryId !== null && (!Number.isSafeInteger(categoryId) || categoryId <= 0)) {
    throw new E('شناسه دسته‌بندی نامعتبر است');
  }
  // بررسی وجود دسته‌بندی
  if (categoryId !== null) {
    const c = await db.query('select 1 from categories where id=$1', [categoryId]);
    if (!c.rowCount) throw new E('دسته‌بندی انتخاب‌شده وجود ندارد');
  }

  const isActive = b.is_active === '1' || b.is_active === 'true' || b.is_active === true;
  const sortOrder = Math.max(0, parseInt(b.sort_order, 10) || 0);

  const fileName = saveFile(q.file.buffer, 'banners');

  const r = await db.query(
    `insert into banners(title, image, category_id, is_active, sort_order)
     values($1, $2, $3, $4, $5) returning id`,
    [title, fileName, categoryId, isActive, sortOrder]
  );

  log(q, 'banner+', r.rows[0].id + ' ' + title);
  s.json({ id: r.rows[0].id });
}));

// PUT /api/admin/banners/:id — ویرایش بنر (با یا بدون تصویر جدید)
ad.put('/banners/:id', bannerUpload.single('image'), A(async (q, s) => {
  const id = +q.params.id;
  if (!Number.isSafeInteger(id) || id <= 0) throw new E('شناسه بنر نامعتبر است');

  const existing = (await db.query('select * from banners where id=$1', [id])).rows[0];
  if (!existing) throw new E('بنر پیدا نشد', 404);

  const b = q.body || {};
  const title = String(b.title || '').trim();
  if (!title) throw new E('عنوان بنر الزامی است');
  if (title.length > 200) throw new E('عنوان بنر خیلی طولانی است');

  const categoryId = b.category_id !== undefined && b.category_id !== '' && b.category_id !== null
    ? Number(b.category_id) : null;
  if (categoryId !== null && (!Number.isSafeInteger(categoryId) || categoryId <= 0)) {
    throw new E('شناسه دسته‌بندی نامعتبر است');
  }
  if (categoryId !== null) {
    const c = await db.query('select 1 from categories where id=$1', [categoryId]);
    if (!c.rowCount) throw new E('دسته‌بندی انتخاب‌شده وجود ندارد');
  }

  const isActive = b.is_active === '1' || b.is_active === 'true' || b.is_active === true;
  const sortOrder = Math.max(0, parseInt(b.sort_order, 10) || 0);

  let newFileName = existing.image;
  let oldToRemove = null;

  if (q.file) {
    if (!kind(q.file.buffer)) throw new E('فقط تصویر JPEG/PNG/WebP مجاز است');
    newFileName = saveFile(q.file.buffer, 'banners');
    oldToRemove = existing.image;
  }

  await db.query(
    `update banners
     set title=$1, category_id=$2, is_active=$3, sort_order=$4, image=$5, updated_at=now()
     where id=$6`,
    [title, categoryId, isActive, sortOrder, newFileName, id]
  );

  // حذف تصویر قدیمی فقط پس از commit موفقیت‌آمیز
  if (oldToRemove && oldToRemove !== newFileName) {
    rm('banners', oldToRemove);
  }

  log(q, 'banner-edit', String(id));
  s.json({ ok: true });
}));

// DELETE /api/admin/banners/:id — حذف بنر به‌همراه تصویر آن
ad.delete('/banners/:id', A(async (q, s) => {
  const id = +q.params.id;
  if (!Number.isSafeInteger(id) || id <= 0) throw new E('شناسه بنر نامعتبر است');

  const r = await db.query('delete from banners where id=$1 returning image', [id]);
  if (!r.rowCount) throw new E('بنر پیدا نشد', 404);

  if (r.rows[0].image) rm('banners', r.rows[0].image);

  log(q, 'banner-', String(id));
  s.json({ ok: true });
}));

ad.get('/orders/:id', A(async (q, s) => {
  const id = +q.params.id;

  const o = (await db.query(
    'select o.*,c.name,c.mobile,c.province,c.city,c.address,c.postal_code from orders o join customers c on c.id=o.customer_id where o.id=$1',
    [id]
  )).rows[0];

  if (!o) throw new E('سفارش پیدا نشد', 404);

  o.items = (await db.query(
    'select * from order_items where order_id=$1 order by id',
    [id]
  )).rows;

  o.receipts = (await db.query(
    'select id,status,reject_reason,created_at from payment_receipts where order_id=$1 order by id desc',
    [id]
  )).rows;

  o.history = (await db.query(
    'select status,note,by_admin,created_at from order_status_history where order_id=$1 order by id',
    [id]
  )).rows;

  s.json(o);
}));

ad.get('/receipts/:id/file', A(async (q, s) => {
  const r = (await db.query(
    'select file from payment_receipts where id=$1',
    [+q.params.id]
  )).rows[0];

  if (!r) throw new E('یافت نشد', 404);

  s.set('Cache-Control', 'private, no-store');
  s.sendFile(path.join(UP, 'receipts', path.basename(r.file)));
}));

const STATUSES = [
  'pending_payment',
  'receipt_sent',
  'payment_confirmed',
  'payment_rejected',
  'preparing',
  'ready',
  'shipped',
  'delivered',
  'cancelled'
];

async function setStatusInTx(cl, q, id, status, note, extra = {}) {
  const old = (await cl.query(
    'select status,paid_at from orders where id=$1 for update',
    [id]
  )).rows[0];

  if (!old) throw new E('سفارش پیدا نشد', 404);

  if (old.status === 'cancelled' && status !== 'cancelled') {
    throw new E('سفارش لغوشده قابل فعال‌سازی مجدد نیست؛ سفارش جدید ثبت کنید');
  }

  if (old.status === status) {
    await cl.query(
      'update orders set tracking_code=coalesce($1,tracking_code),admin_note=coalesce($2,admin_note) where id=$3',
      [extra.tracking ?? null, extra.admin_note ?? null, id]
    );
    return;
  }

  if (
    ['pending_payment', 'receipt_sent', 'payment_confirmed', 'payment_rejected'].includes(status) &&
    !extra.allowPayment
  ) {
    throw new E('وضعیت پرداخت فقط از مسیر ثبت رسید یا تأیید/رد پرداخت تغییر می‌کند');
  }

  const transitions = {
    pending_payment: ['cancelled'],
    receipt_sent: ['payment_confirmed', 'payment_rejected', 'cancelled'],
    payment_rejected: ['cancelled'],
    payment_confirmed: ['preparing', 'shipped', 'cancelled'],
    preparing: ['ready', 'shipped', 'cancelled'],
    ready: ['shipped', 'cancelled'],
    shipped: ['delivered'],
    delivered: [],
    cancelled: []
  };

  if (!(transitions[old.status] || []).includes(status)) {
    throw new E('این تغییر وضعیت در گردش کار سفارش مجاز نیست');
  }

  if (status === 'cancelled' && old.status !== 'cancelled') {
    await cl.query(`
      update products p
      set stock=p.stock+x.qty
      from (
        select product_id,sum(qty)::int qty
        from order_items
        where order_id=$1 and product_id is not null
        group by product_id
      ) x
      where x.product_id=p.id
    `, [id]);

    if (old.paid_at) {
      await cl.query(`
        update products p
        set sold=greatest(p.sold-x.qty,0)
        from (
          select product_id,sum(qty)::int qty
          from order_items
          where order_id=$1 and product_id is not null
          group by product_id
        ) x
        where x.product_id=p.id
      `, [id]);
    }
  }

  await cl.query(
    'update orders set status=$1,tracking_code=coalesce($2,tracking_code),admin_note=coalesce($3,admin_note),paid_at=coalesce($4,paid_at) where id=$5',
    [status, extra.tracking ?? null, extra.admin_note ?? null, extra.paid ?? null, id]
  );

  await cl.query(
    'insert into order_status_history(order_id,status,note,by_admin) values($1,$2,$3,$4)',
    [id, status, note || '', q.admin.u]
  );
}

async function setStatus(q, id, status, note, extra = {}) {
  const cl = await db.connect();

  try {
    await cl.query('begin');

    await setStatusInTx(cl, q, id, status, note, extra);

    await cl.query('commit');

    log(q, 'order-status', id + ' → ' + status);

  } catch (e) {
    await cl.query('rollback');
    throw e;

  } finally {
    cl.release();
  }
}

ad.patch('/orders/:id/status', A(async (q, s) => {
  const { status, note, tracking_code, admin_note } = q.body || {};

  if (!STATUSES.includes(status)) {
    throw new E('وضعیت نامعتبر است');
  }

  await setStatus(q, +q.params.id, status, note, {
    tracking: tracking_code,
    admin_note
  });

  s.json({ ok: true });
}));

ad.post('/orders/:id/payment', A(async (q, s) => {
  const id = +q.params.id;
  const { action, reason } = q.body || {};
  const cl = await db.connect();

  try {
    await cl.query('begin');

    const order = (await cl.query(
      'select status,paid_at from orders where id=$1 for update',
      [id]
    )).rows[0];

    if (!order) throw new E('سفارش پیدا نشد', 404);

    if (['cancelled', 'payment_confirmed', 'preparing', 'ready', 'shipped', 'delivered'].includes(order.status)) {
      throw new E('این سفارش در وضعیت فعلی قابل تغییر پرداخت نیست');
    }

    if (action === 'approve') {
      const receipt = await cl.query(
        "update payment_receipts set status='approved' where order_id=$1 and status='pending' returning id",
        [id]
      );

      if (!receipt.rowCount) {
        throw new E('رسید در انتظار تأیید برای این سفارش وجود ندارد');
      }

      await cl.query(`
        update products p
        set sold=p.sold+x.qty
        from (
          select product_id,sum(qty)::int qty
          from order_items
          where order_id=$1 and product_id is not null
          group by product_id
        ) x
        where x.product_id=p.id
      `, [id]);

      await setStatusInTx(
        cl,
        q,
        id,
        'payment_confirmed',
        'پرداخت تأیید شد',
        { paid: new Date(), allowPayment: true }
      );

      // اعطای امتیاز باشگاه مشتریان (فاز ۶)
      const st = await settings();
      if (st.points_enabled === '1') {
        const orderRow = (await cl.query('select total, customer_id from orders where id=$1', [id])).rows[0];
        if (orderRow) {
          const cust = (await cl.query('select account_id from customers where id=$1', [orderRow.customer_id])).rows[0];
          if (cust && cust.account_id) {
            const perToman = Math.max(1, parseInt(st.points_per_toman) || 1000);
            const earned = Math.floor(Number(orderRow.total) / perToman);
            if (earned > 0) {
              // بررسی اینکه قبلاً امتیاز داده نشده
              const already = await cl.query('select 1 from point_transactions where order_id=$1 and type=$2', [id, 'earn']);
              if (!already.rowCount) {
                await cl.query('update customer_accounts set points_balance=points_balance+$1 where id=$2', [earned, cust.account_id]);
                await cl.query('insert into point_transactions(account_id, amount, type, reason, order_id) values($1,$2,$3,$4,$5)',
                  [cust.account_id, earned, 'earn', `امتیاز خرید سفارش ${orderRow.order_number || id}`, id]);
              }
            }
          }
        }
      }

    } else if (action === 'reject') {
      if (!String(reason || '').trim()) {
        throw new E('دلیل رد پرداخت را بنویسید');
      }

      const receipt = await cl.query(
        "update payment_receipts set status='rejected',reject_reason=$2 where order_id=$1 and status='pending' returning id",
        [id, String(reason).slice(0, 500)]
      );

      if (!receipt.rowCount) {
        throw new E('رسید در انتظار بررسی برای این سفارش وجود ندارد');
      }

      await setStatusInTx(
        cl,
        q,
        id,
        'payment_rejected',
        'رد پرداخت: ' + String(reason).slice(0, 500),
        { allowPayment: true }
      );

    } else {
      throw new E('عملیات نامعتبر است');
    }

    await cl.query('commit');

    log(q, 'payment-' + action, id);
    s.json({ ok: true });

  } catch (e) {
    await cl.query('rollback');
    throw e;

  } finally {
    cl.release();
  }
}));

ad.get('/coupons', A(async (q, s) => {
  s.json((await db.query('select id,code,discount_type,discount_value,min_order,usage_limit,used_count,active,expires_at from coupons order by id desc')).rows);
}));
ad.post('/coupons', A(async (q, s) => {
  const b=q.body||{}, code=String(b.code||'').trim().toUpperCase(), type=String(b.discount_type||''), value=Number(b.discount_value), min=Number(b.min_order||0);
  if (!/^[A-Z0-9_-]{3,30}$/.test(code)) throw new E('کد باید ۳ تا ۳۰ حرف انگلیسی یا عدد باشد');
  if (!['percent','fixed'].includes(type) || !Number.isFinite(value) || value<=0 || (type==='percent'&&value>100) || !Number.isFinite(min) || min<0) throw new E('مقادیر تخفیف صحیح نیست');
  const limit=b.usage_limit===''||b.usage_limit==null?null:Number(b.usage_limit);
  if (limit!==null&&(!Number.isInteger(limit)||limit<1)) throw new E('محدودیت استفاده نامعتبر است');
  const expires=b.expires_at?new Date(b.expires_at):null;
  if (expires && Number.isNaN(expires.getTime())) throw new E('تاریخ انقضا نامعتبر است');
  const r=await db.query(`insert into coupons(code,discount_type,discount_value,min_order,usage_limit,active,expires_at)
    values($1,$2,$3,$4,$5,$6,$7) on conflict(code) do update set discount_type=excluded.discount_type,discount_value=excluded.discount_value,min_order=excluded.min_order,usage_limit=excluded.usage_limit,active=excluded.active,expires_at=excluded.expires_at
    returning id,code,discount_type,discount_value,min_order,usage_limit,used_count,active,expires_at`,[code,type,value,min,limit,b.active!==false,expires]);
  log(q,'coupon_save',code); s.json(r.rows[0]);
}));
ad.patch('/coupons/:id', A(async (q,s)=>{
  const active=!!(q.body||{}).active; const r=await db.query('update coupons set active=$1 where id=$2 returning id',[active,+q.params.id]);
  if(!r.rowCount) throw new E('کد تخفیف پیدا نشد',404); log(q,'coupon_toggle',String(q.params.id)); s.json({ok:true});
}));
ad.delete('/coupons/:id', A(async (q,s)=>{await db.query('delete from coupons where id=$1',[+q.params.id]);log(q,'coupon_delete',String(q.params.id));s.json({ok:true})}));

// ---------- مدیریت نظرات (فاز ۲) ----------
// نظرات اکنون انتشار فوری دارند (status='approved' هنگام ثبت).
// مدیر می‌تواند نظرات را فقط ببیند و در صورت نیاز حذف کند (مثلاً اسپم).
// فرایند تأیید/رد حذف شده است.

// GET /api/admin/reviews — فهرست همه نظرات
ad.get('/reviews', A(async (q, s) => {
  const r = await db.query(
    `select r.id, r.title, r.body, r.rating, r.status, r.verified_buyer,
            r.created_at, r.updated_at,
            r.product_id, p.name product_name, p.slug product_slug,
            r.account_id, ca.name author_name, ca.email author_email, ca.mobile author_mobile
     from product_reviews r
     join products p on p.id=r.product_id
     join customer_accounts ca on ca.id=r.account_id
     order by r.created_at desc
     limit 200`
  );
  s.json(r.rows);
}));

// DELETE /api/admin/reviews/:id — حذف نظر (فقط برای اسپم یا توهین)
ad.delete('/reviews/:id', A(async (q, s) => {
  const id = +q.params.id;
  if (!Number.isSafeInteger(id) || id <= 0) throw new E('شناسه نظر نامعتبر است');
  await db.query('delete from product_reviews where id=$1', [id]);
  log(q, 'review-delete', String(id));
  s.json({ ok: true });
}));

// ---------- مدیریت پرسش و پاسخ (فاز ۲) ----------
// GET /api/admin/questions — فهرست همه پرسش‌ها با فیلتر status
ad.get('/questions', A(async (q, s) => {
  const status = String(q.query.status || '').trim();
  const where = status ? 'where q.status=$1' : '';
  const params = status ? [status] : [];
  const r = await db.query(
    `select q.id, q.question, q.answer, q.status, q.created_at, q.answered_at, q.answered_by,
            q.product_id, p.name product_name, p.slug product_slug,
            q.account_id, ca.name asker_name, ca.email asker_email, ca.mobile asker_mobile
     from product_questions q
     join products p on p.id=q.product_id
     join customer_accounts ca on ca.id=q.account_id
     ${where}
     order by q.created_at desc
     limit 200`,
    params
  );
  s.json(r.rows);
}));

// PATCH /api/admin/questions/:id — پاسخ به پرسش یا تغییر وضعیت
ad.patch('/questions/:id', A(async (q, s) => {
  const id = +q.params.id;
  if (!Number.isSafeInteger(id) || id <= 0) throw new E('شناسه پرسش نامعتبر است');
  const b = q.body || {};
  const answer = String(b.answer || '').trim();
  const status = String(b.status || '').trim();

  if (status === 'answered') {
    if (!answer || answer.length < 1) throw new E('متن پاسخ لازم است');
    if (answer.length > 2000) throw new E('پاسخ خیلی طولانی است');
    await db.query(
      `update product_questions
       set answer=$1, status='answered', answered_by=$2, answered_at=now()
       where id=$3`,
      [answer.slice(0, 2000), q.admin.u, id]
    );
    log(q, 'question-answer', String(id));
  } else if (status === 'hidden') {
    await db.query(
      "update product_questions set status='hidden' where id=$1",
      [id]
    );
    log(q, 'question-hide', String(id));
  } else if (status === 'pending') {
    await db.query(
      "update product_questions set status='pending', answer=null, answered_by=null, answered_at=null where id=$1",
      [id]
    );
    log(q, 'question-reset', String(id));
  } else {
    throw new E('وضعیت نامعتبر است (answered/hidden/pending)');
  }
  s.json({ ok: true });
}));

// DELETE /api/admin/questions/:id — حذف پرسش
ad.delete('/questions/:id', A(async (q, s) => {
  const id = +q.params.id;
  if (!Number.isSafeInteger(id) || id <= 0) throw new E('شناسه پرسش نامعتبر است');
  await db.query('delete from product_questions where id=$1', [id]);
  log(q, 'question-delete', String(id));
  s.json({ ok: true });
}));

// ---------- مدیریت علاقه‌مندی‌ها (فقط گزارش خلاصه) ----------
// GET /api/admin/wishlist-stats — تعداد علاقه‌مندی به ازای هر محصول
ad.get('/wishlist-stats', A(async (q, s) => {
  const r = await db.query(
    `select p.id, p.name, count(w.id)::int wish_count
     from products p
     left join wishlist w on w.product_id=p.id
     group by p.id, p.name
     having count(w.id) > 0
     order by wish_count desc
     limit 50`
  );
  s.json(r.rows);
}));

// =====================================================
//  فاز ۳ — مدیریت کمپین‌ها، بسته‌ها، کوپن پیشرفته
// =====================================================

// ---------- مدیریت کمپین‌ها ----------
const campaignUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024, files: 1 } });

ad.get('/campaigns', A(async (q, s) => {
  const r = await db.query(`
    select c.*, cat.name category_name
    from campaigns c
    left join categories cat on cat.id=c.category_id
    order by c.created_at desc
  `);
  s.json(r.rows.map(x => ({
    ...x,
    image: x.image ? '/uploads/campaigns/' + x.image : null,
    raw_image: x.image,
    product_ids: Array.isArray(x.product_ids) ? x.product_ids : []
  })));
}));

ad.post('/campaigns', campaignUpload.single('image'), A(async (q, s) => {
  const b = q.body || {};
  const title = String(b.title || '').trim();
  if (!title) throw new E('عنوان کمپین الزامی است');
  const discount_type = String(b.discount_type || 'percent');
  if (!['percent', 'fixed'].includes(discount_type)) throw new E('نوع تخفیف نامعتبر');
  const discount_value = Number(b.discount_value);
  if (!Number.isFinite(discount_value) || discount_value <= 0) throw new E('مقدار تخفیف نامعتبر');
  if (discount_type === 'percent' && discount_value > 100) throw new E('درصد تخفیف نباید بیشتر از ۱۰۰ باشد');

  let fileName = null;
  if (q.file) {
    if (!kind(q.file.buffer)) throw new E('فقط تصویر JPEG/PNG/WebP مجاز است');
    fileName = saveFile(q.file.buffer, 'campaigns');
  }

  const categoryId = b.category_id ? Number(b.category_id) : null;
  const productIds = Array.isArray(b.product_ids) ? b.product_ids : (String(b.product_ids || '[]').startsWith('[') ? JSON.parse(b.product_ids) : []);
  const startsAt = b.starts_at ? new Date(b.starts_at) : new Date();
  const endsAt = b.ends_at ? new Date(b.ends_at) : null;

  const r = await db.query(
    `insert into campaigns(title, description, image, discount_type, discount_value, category_id, product_ids, starts_at, ends_at, is_active, show_on_homepage)
     values($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11) returning id`,
    [title, String(b.description || '').slice(0, 2000), fileName, discount_type, discount_value, categoryId,
     JSON.stringify(productIds), startsAt, endsAt, b.is_active !== '0' && b.is_active !== false, b.show_on_homepage === '1' || b.show_on_homepage === true]
  );
  log(q, 'campaign+', r.rows[0].id + ' ' + title);
  s.json({ id: r.rows[0].id });
}));

ad.put('/campaigns/:id', campaignUpload.single('image'), A(async (q, s) => {
  const id = +q.params.id;
  if (!Number.isSafeInteger(id) || id <= 0) throw new E('شناسه نامعتبر');
  const existing = (await db.query('select * from campaigns where id=$1', [id])).rows[0];
  if (!existing) throw new E('کمپین پیدا نشد', 404);

  const b = q.body || {};
  const title = String(b.title || '').trim();
  if (!title) throw new E('عنوان کمپین الزامی است');
  const discount_type = String(b.discount_type || 'percent');
  if (!['percent', 'fixed'].includes(discount_type)) throw new E('نوع تخفیف نامعتبر');
  const discount_value = Number(b.discount_value);
  if (!Number.isFinite(discount_value) || discount_value <= 0) throw new E('مقدار تخفیف نامعتبر');

  let fileName = existing.image;
  let oldToRemove = null;
  if (q.file) {
    if (!kind(q.file.buffer)) throw new E('فقط تصویر JPEG/PNG/WebP مجاز است');
    fileName = saveFile(q.file.buffer, 'campaigns');
    oldToRemove = existing.image;
  }

  const categoryId = b.category_id !== undefined && b.category_id !== '' ? Number(b.category_id) : null;
  const productIds = Array.isArray(b.product_ids) ? b.product_ids : (String(b.product_ids || '[]').startsWith('[') ? JSON.parse(b.product_ids || '[]') : []);
  const startsAt = b.starts_at ? new Date(b.starts_at) : existing.starts_at;
  const endsAt = b.ends_at ? new Date(b.ends_at) : null;

  await db.query(
    `update campaigns set title=$1, description=$2, image=$3, discount_type=$4, discount_value=$5,
     category_id=$6, product_ids=$7::jsonb, starts_at=$8, ends_at=$9, is_active=$10, show_on_homepage=$11, updated_at=now()
     where id=$12`,
    [title, String(b.description || '').slice(0, 2000), fileName, discount_type, discount_value, categoryId,
     JSON.stringify(productIds), startsAt, endsAt, b.is_active !== '0' && b.is_active !== false, b.show_on_homepage === '1' || b.show_on_homepage === true, id]
  );
  if (oldToRemove && oldToRemove !== fileName) rm('campaigns', oldToRemove);
  log(q, 'campaign-edit', String(id));
  s.json({ ok: true });
}));

ad.delete('/campaigns/:id', A(async (q, s) => {
  const id = +q.params.id;
  const r = await db.query('delete from campaigns where id=$1 returning image', [id]);
  if (!r.rowCount) throw new E('کمپین پیدا نشد', 404);
  if (r.rows[0].image) rm('campaigns', r.rows[0].image);
  log(q, 'campaign-', String(id));
  s.json({ ok: true });
}));

// ---------- مدیریت بسته‌های اقتصادی ----------
const bundleUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024, files: 1 } });

ad.get('/bundles', A(async (q, s) => {
  const r = await db.query('select * from product_bundles order by sort_order asc, id desc');
  const bundles = [];
  for (const b of r.rows) {
    const items = await db.query(`
      select bi.id, bi.qty, p.id product_id, p.name, p.slug, p.price, p.stock
      from bundle_items bi join products p on p.id=bi.product_id
      where bi.bundle_id=$1
    `, [b.id]);
    bundles.push({
      ...b,
      image: b.image ? '/uploads/bundles/' + b.image : null,
      raw_image: b.image,
      items: items.rows
    });
  }
  s.json(bundles);
}));

ad.post('/bundles', bundleUpload.single('image'), A(async (q, s) => {
  const b = q.body || {};
  const title = String(b.title || '').trim();
  if (!title) throw new E('عنوان بسته الزامی است');
  const bundlePrice = Math.round(Number(b.bundle_price));
  if (!(bundlePrice > 0)) throw new E('قیمت بسته نامعتبر');

  let fileName = null;
  if (q.file) {
    if (!kind(q.file.buffer)) throw new E('فقط تصویر مجاز است');
    fileName = saveFile(q.file.buffer, 'bundles');
  }

  // اقلام بسته: فرمت "product_id:qty,product_id:qty,..."
  const itemsRaw = String(b.items || '').split(/[,،]/).map(s => s.trim()).filter(Boolean);
  const items = [];
  for (const it of itemsRaw) {
    const [pidStr, qtyStr] = it.split(':');
    const pid = Number(pidStr);
    const qty = Math.max(1, parseInt(qtyStr) || 1);
    if (Number.isSafeInteger(pid) && pid > 0) items.push({ pid, qty });
  }
  if (!items.length) throw new E('حداقل یک محصول برای بسته لازم است');

  const cl = await db.connect();
  try {
    await cl.query('begin');
    // محاسبه قیمت اصلی (مجموع قیمت محصولات × تعداد)
    let originalPrice = 0;
    for (const it of items) {
      const p = (await cl.query('select price, discount_price, stock from products where id=$1', [it.pid])).rows[0];
      if (!p) throw new E('محصول بسته پیدا نشد: ' + it.pid);
      const unit = p.discount_price && p.discount_price < p.price ? p.discount_price : p.price;
      originalPrice += unit * it.qty;
    }
    const r = await cl.query(
      'insert into product_bundles(title, description, image, bundle_price, original_price, is_active, sort_order) values($1,$2,$3,$4,$5,$6,$7) returning id',
      [title, String(b.description || '').slice(0, 2000), fileName, bundlePrice, originalPrice,
       b.is_active !== '0' && b.is_active !== false, Math.max(0, parseInt(b.sort_order) || 0)]
    );
    const bid = r.rows[0].id;
    for (const it of items) {
      await cl.query('insert into bundle_items(bundle_id, product_id, qty) values($1,$2,$3) on conflict do nothing', [bid, it.pid, it.qty]);
    }
    await cl.query('commit');
    log(q, 'bundle+', String(bid));
    s.json({ id: bid });
  } catch (e) {
    await cl.query('rollback');
    if (fileName) rm('bundles', fileName);
    throw e;
  } finally { cl.release(); }
}));

ad.put('/bundles/:id', bundleUpload.single('image'), A(async (q, s) => {
  const id = +q.params.id;
  if (!Number.isSafeInteger(id) || id <= 0) throw new E('شناسه نامعتبر');
  const existing = (await db.query('select * from product_bundles where id=$1', [id])).rows[0];
  if (!existing) throw new E('بسته پیدا نشد', 404);

  const b = q.body || {};
  const title = String(b.title || '').trim();
  if (!title) throw new E('عنوان بسته الزامی است');
  const bundlePrice = Math.round(Number(b.bundle_price));
  if (!(bundlePrice > 0)) throw new E('قیمت بسته نامعتبر');

  let fileName = existing.image;
  let oldToRemove = null;
  if (q.file) {
    if (!kind(q.file.buffer)) throw new E('فقط تصویر مجاز است');
    fileName = saveFile(q.file.buffer, 'bundles');
    oldToRemove = existing.image;
  }

  const itemsRaw = String(b.items || '').split(/[,،]/).map(s => s.trim()).filter(Boolean);
  const items = [];
  for (const it of itemsRaw) {
    const [pidStr, qtyStr] = it.split(':');
    const pid = Number(pidStr);
    const qty = Math.max(1, parseInt(qtyStr) || 1);
    if (Number.isSafeInteger(pid) && pid > 0) items.push({ pid, qty });
  }

  const cl = await db.connect();
  try {
    await cl.query('begin');
    let originalPrice = 0;
    for (const it of items) {
      const p = (await cl.query('select price, discount_price from products where id=$1', [it.pid])).rows[0];
      if (!p) throw new E('محصول بسته پیدا نشد: ' + it.pid);
      const unit = p.discount_price && p.discount_price < p.price ? p.discount_price : p.price;
      originalPrice += unit * it.qty;
    }
    await cl.query(
      'update product_bundles set title=$1, description=$2, image=$3, bundle_price=$4, original_price=$5, is_active=$6, sort_order=$7, updated_at=now() where id=$8',
      [title, String(b.description || '').slice(0, 2000), fileName, bundlePrice, originalPrice,
       b.is_active !== '0' && b.is_active !== false, Math.max(0, parseInt(b.sort_order) || 0), id]
    );
    // جایگزینی اقلام
    await cl.query('delete from bundle_items where bundle_id=$1', [id]);
    for (const it of items) {
      await cl.query('insert into bundle_items(bundle_id, product_id, qty) values($1,$2,$3)', [id, it.pid, it.qty]);
    }
    await cl.query('commit');
    if (oldToRemove && oldToRemove !== fileName) rm('bundles', oldToRemove);
    log(q, 'bundle-edit', String(id));
    s.json({ ok: true });
  } catch (e) {
    await cl.query('rollback');
    if (oldToRemove && fileName !== existing.image) rm('bundles', fileName);
    throw e;
  } finally { cl.release(); }
}));

ad.delete('/bundles/:id', A(async (q, s) => {
  const id = +q.params.id;
  const r = await db.query('delete from product_bundles where id=$1 returning image', [id]);
  if (!r.rowCount) throw new E('بسته پیدا نشد', 404);
  if (r.rows[0].image) rm('bundles', r.rows[0].image);
  log(q, 'bundle-', String(id));
  s.json({ ok: true });
}));

// ---------- کوپن پیشرفته (به‌روزرسانی endpoint موجود) ----------
// بازنویسی POST /coupons با پشتیبانی از ستون‌های جدید
ad.post('/coupons/advanced', A(async (q, s) => {
  const b = q.body || {};
  const code = String(b.code || '').trim().toUpperCase();
  const type = String(b.discount_type || '');
  const value = Number(b.discount_value);
  if (!/^[A-Z0-9_-]{3,30}$/.test(code)) throw new E('کد باید ۳ تا ۳۰ حرف انگلیسی یا عدد باشد');
  if (!['percent', 'fixed'].includes(type) || !Number.isFinite(value) || value <= 0 || (type === 'percent' && value > 100)) throw new E('مقادیر تخفیف صحیح نیست');

  const maxDiscount = b.max_discount ? Number(b.max_discount) : null;
  const startsAt = b.starts_at ? new Date(b.starts_at) : null;
  const endsAt = b.expires_at ? new Date(b.expires_at) : null;
  const perCustomerLimit = b.per_customer_limit ? Math.max(1, parseInt(b.per_customer_limit)) : null;
  const firstOrderOnly = b.first_order_only === true || b.first_order_only === '1';
  const categoryId = b.category_id ? Number(b.category_id) : null;
  const productIds = Array.isArray(b.product_ids) ? b.product_ids.map(Number).filter(x => x > 0) : [];
  const minQty = Math.max(0, parseInt(b.min_qty) || 0);
  const usageLimit = b.usage_limit === '' || b.usage_limit == null ? null : Number(b.usage_limit);
  const minOrder = Math.max(0, Number(b.min_order) || 0);
  const active = b.active !== false && b.active !== '0';

  const r = await db.query(
    `insert into coupons(code, discount_type, discount_value, min_order, usage_limit, active, expires_at,
       max_discount, starts_at, per_customer_limit, first_order_only, category_id, product_ids, min_qty)
     values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14)
     on conflict(code) do update set
       discount_type=excluded.discount_type, discount_value=excluded.discount_value,
       min_order=excluded.min_order, usage_limit=excluded.usage_limit, active=excluded.active, expires_at=excluded.expires_at,
       max_discount=excluded.max_discount, starts_at=excluded.starts_at,
       per_customer_limit=excluded.per_customer_limit, first_order_only=excluded.first_order_only,
       category_id=excluded.category_id, product_ids=excluded.product_ids, min_qty=excluded.min_qty
     returning id`,
    [code, type, value, minOrder, usageLimit, active, endsAt, maxDiscount, startsAt, perCustomerLimit, firstOrderOnly, categoryId, JSON.stringify(productIds), minQty]
  );
  log(q, 'coupon-save', code);
  s.json({ id: r.rows[0].id });
}));

// گزارش استفاده از کوپن
ad.get('/coupons/:id/usage', A(async (q, s) => {
  const id = +q.params.id;
  const r = await db.query(`
    select cu.id, cu.used_at, cu.customer_mobile, o.order_number, o.total, o.status
    from coupon_usage cu
    left join orders o on o.id=cu.order_id
    where cu.coupon_id=$1
    order by cu.used_at desc
    limit 200
  `, [id]);
  s.json(r.rows);
}));

// =====================================================
//  فاز ۴ — مدیریت روش‌های ارسال
// =====================================================
ad.get('/shipping-methods', A(async (q, s) => {
  const r = await db.query('select * from shipping_methods order by sort_order, id');
  s.json(r.rows);
}));

ad.post('/shipping-methods', A(async (q, s) => {
  const b = q.body || {};
  const name = String(b.name || '').trim();
  if (!name) throw new E('نام روش ارسال الزامی است');
  const baseCost = Math.max(0, Math.round(Number(b.base_cost) || 0));
  const freeThreshold = b.free_shipping_threshold ? Math.round(Number(b.free_shipping_threshold)) : null;
  const r = await db.query(
    'insert into shipping_methods(name, description, base_cost, free_shipping_threshold, is_active, sort_order) values($1,$2,$3,$4,$5,$6) returning id',
    [name, String(b.description || '').slice(0, 500), baseCost, freeThreshold, b.is_active !== '0', Math.max(0, parseInt(b.sort_order) || 0)]
  );
  log(q, 'shipping+', name);
  s.json({ id: r.rows[0].id });
}));

ad.put('/shipping-methods/:id', A(async (q, s) => {
  const id = +q.params.id;
  const b = q.body || {};
  const name = String(b.name || '').trim();
  if (!name) throw new E('نام الزامی است');
  await db.query(
    'update shipping_methods set name=$1, description=$2, base_cost=$3, free_shipping_threshold=$4, is_active=$5, sort_order=$6 where id=$7',
    [name, String(b.description || '').slice(0, 500), Math.max(0, Math.round(Number(b.base_cost) || 0)),
     b.free_shipping_threshold ? Math.round(Number(b.free_shipping_threshold)) : null, b.is_active !== '0', Math.max(0, parseInt(b.sort_order) || 0), id]
  );
  s.json({ ok: true });
}));

ad.delete('/shipping-methods/:id', A(async (q, s) => {
  await db.query('delete from shipping_methods where id=$1', [+q.params.id]);
  s.json({ ok: true });
}));

// =====================================================
//  فاز ۵ — داشبورد پیشرفته و گزارش‌ها
// =====================================================

// داشبورد فروش با بازه زمانی
ad.get('/reports/dashboard', A(async (q, s) => {
  const days = Math.min(365, Math.max(1, parseInt(q.query.days) || 30));
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

  const r = await db.query(`
    select
      (select count(*) from orders where created_at >= $1 and status <> 'cancelled') orders_count,
      (select coalesce(sum(total),0)::bigint from orders where created_at >= $1 and paid_at is not null and status <> 'cancelled') revenue,
      (select coalesce(sum(discount),0)::bigint from orders where created_at >= $1 and status <> 'cancelled') total_discount,
      (select count(*) from customer_accounts where created_at >= $1) new_customers,
      (select count(*) from products where published) active_products,
      (select count(*) from products where stock = 0) out_of_stock,
      (select count(*) from products where stock > 0 and stock <= stock_threshold) low_stock,
      (select count(*) from orders where status = 'pending_payment') pending_orders,
      (select count(*) from orders where status in ('payment_confirmed','preparing','ready')) processing_orders,
      (select count(*) from product_reviews) total_reviews,
      (select count(*) from product_questions where status = 'pending') pending_questions
  `, [since]);

  // فروش امروز و این هفته
  const todayStart = new Date(); todayStart.setHours(0,0,0,0);
  const weekStart = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  const monthStart = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

  const todayRev = await db.query("select coalesce(sum(total),0)::bigint from orders where paid_at is not null and status<>'cancelled' and paid_at >= $1", [todayStart]);
  const weekRev = await db.query("select coalesce(sum(total),0)::bigint from orders where paid_at is not null and status<>'cancelled' and paid_at >= $1", [weekStart]);
  const monthRev = await db.query("select coalesce(sum(total),0)::bigint from orders where paid_at is not null and status<>'cancelled' and paid_at >= $1", [monthStart]);
  const totalRev = await db.query("select coalesce(sum(total),0)::bigint from orders where paid_at is not null and status<>'cancelled'");

  s.json({
    ...r.rows[0],
    revenue_today: todayRev.rows[0].coalesce,
    revenue_week: weekRev.rows[0].coalesce,
    revenue_month: monthRev.rows[0].coalesce,
    revenue_total: totalRev.rows[0].coalesce,
    avg_order: r.rows[0].orders_count > 0 ? Math.round(Number(r.rows[0].revenue) / r.rows[0].orders_count) : 0,
    days
  });
}));

// گزارش پرفروش‌ترین محصولات
ad.get('/reports/best-sellers', A(async (q, s) => {
  const days = Math.min(365, Math.max(1, parseInt(q.query.days) || 30));
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  const sortBy = String(q.query.sort || 'qty'); // qty | revenue

  const r = await db.query(`
    select p.id, p.name, p.slug, p.price, p.stock, p.sold,
           coalesce(sum(oi.qty),0)::int sold_qty,
           coalesce(sum(oi.qty * oi.unit_price),0)::bigint sold_revenue,
           (select file from product_images i where i.product_id=p.id order by i.is_main desc,i.sort,i.id limit 1) image
    from products p
    left join order_items oi on oi.product_id=p.id
    left join orders o on o.id=oi.order_id and o.created_at >= $1 and o.status <> 'cancelled'
    where p.published
    group by p.id, p.name, p.slug, p.price, p.stock, p.sold
    order by ${sortBy === 'revenue' ? 'sold_revenue' : 'sold_qty'} desc
    limit 50
  `, [since]);
  s.json(r.rows.map(x => ({ ...x, image: x.image ? '/uploads/products/' + x.image : null })));
}));

// گزارش محصولات کم‌موجود
ad.get('/reports/low-stock', A(async (q, s) => {
  const r = await db.query(`
    select id, name, slug, price, stock, stock_threshold,
           (select file from product_images i where i.product_id=products.id order by i.is_main desc,i.sort,i.id limit 1) image
    from products
    where published and stock <= stock_threshold
    order by stock asc
    limit 100
  `);
  s.json(r.rows.map(x => ({ ...x, image: x.image ? '/uploads/products/' + x.image : null })));
}));

// مدیریت مشتریان
ad.get('/customers', A(async (q, s) => {
  const r = await db.query(`
    select ca.id, ca.name, ca.email, ca.mobile, ca.points_balance, ca.created_at,
           (select count(*) from customers c where c.account_id=ca.id) orders_count,
           (select coalesce(sum(o.total),0)::bigint from orders o
            join customers c on c.id=o.customer_id
            where c.account_id=ca.id and o.status<>'cancelled') total_spent,
           (select max(o.created_at) from orders o
            join customers c on c.id=o.customer_id
            where c.account_id=ca.id) last_order_at
    from customer_accounts ca
    order by ca.created_at desc
    limit 200
  `);
  s.json(r.rows);
}));

ad.get('/customers/:id', A(async (q, s) => {
  const id = +q.params.id;
  const acc = (await db.query(`
    select ca.id, ca.name, ca.email, ca.mobile, ca.points_balance, ca.created_at
    from customer_accounts ca where ca.id=$1
  `, [id])).rows[0];
  if (!acc) throw new E('مشتری پیدا نشد', 404);

  const orders = await db.query(`
    select o.id, o.order_number, o.total, o.status, o.created_at, o.paid_at
    from orders o
    join customers c on c.id=o.customer_id
    where c.account_id=$1
    order by o.created_at desc
    limit 100
  `, [id]);
  s.json({ ...acc, orders: orders.rows });
}));

// آمار بنرها
ad.get('/banners-stats', A(async (q, s) => {
  const days = Math.min(365, Math.max(1, parseInt(q.query.days) || 30));
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  const r = await db.query(`
    select b.id, b.title, b.is_active,
           (select count(*) from banner_stats bs where bs.banner_id=b.id and bs.event_type='view' and bs.created_at >= $1) views,
           (select count(*) from banner_stats bs where bs.banner_id=b.id and bs.event_type='click' and bs.created_at >= $1) clicks
    from banners b
    order by b.sort_order, b.id
  `, [since]);
  s.json(r.rows.map(x => ({
    ...x,
    ctr: x.views > 0 ? Math.round(x.clicks / x.views * 1000) / 10 : 0
  })));
}));

// =====================================================
//  فاز ۶ — مدیریت امتیاز مشتریان
// =====================================================
// تنظیم دستی امتیاز
ad.post('/customers/:id/points', A(async (q, s) => {
  const id = +q.params.id;
  const b = q.body || {};
  const amount = Math.round(Number(b.amount));
  if (!Number.isFinite(amount) || amount === 0) throw new E('مقدار امتیاز نامعتبر');
  const reason = String(b.reason || 'تنظیم دستی').slice(0, 200);

  const cl = await db.connect();
  try {
    await cl.query('begin');
    const acc = (await cl.query('select points_balance from customer_accounts where id=$1 for update', [id])).rows[0];
    if (!acc) throw new E('مشتری پیدا نشد', 404);
    const newBalance = Math.max(0, acc.points_balance + amount);
    await cl.query('update customer_accounts set points_balance=$1 where id=$2', [newBalance, id]);
    await cl.query('insert into point_transactions(account_id, amount, type, reason) values($1,$2,$3,$4)',
      [id, amount, amount > 0 ? 'adjust' : 'adjust', reason]);
    await cl.query('commit');
    log(q, 'points-adjust', `${id} ${amount}`);
    s.json({ ok: true, new_balance: newBalance });
  } catch (e) {
    await cl.query('rollback'); throw e;
  } finally { cl.release(); }
}));

// تاریخچه امتیاز یک مشتری
ad.get('/customers/:id/points', A(async (q, s) => {
  const id = +q.params.id;
  const r = await db.query(`
    select pt.id, pt.amount, pt.type, pt.reason, pt.order_id, pt.created_at
    from point_transactions pt where pt.account_id=$1
    order by pt.created_at desc limit 100
  `, [id]);
  s.json(r.rows);
}));

ad.get('/settings', A(async (q, s) => {
  s.json(await settings());
}));

ad.put('/settings', A(async (q, s) => {
  for (const [k, v] of Object.entries(q.body || {})) {
    if (ALLOWED.includes(k)) {
      await db.query(
        'insert into store_settings(key,value) values($1,$2) on conflict(key) do update set value=$2',
        [k, String(v).slice(0, 1000)]
      );
    }
  }

  log(q, 'settings', Object.keys(q.body || {}).join(','));
  s.json({ ok: true });
}));

app.use('/uploads/products', express.static(path.join(UP, 'products'), { maxAge: '7d' }));
app.use('/uploads/banners', express.static(path.join(UP, 'banners'), { maxAge: '7d' }));
app.use('/uploads/campaigns', express.static(path.join(UP, 'campaigns'), { maxAge: '7d' }));
app.use('/uploads/bundles', express.static(path.join(UP, 'bundles'), { maxAge: '7d' }));
app.use('/admin', express.static(path.join(__dirname, '..', 'admin')));
app.use(express.static(path.join(__dirname, '..', 'public')));

app.use('/api', (q, s) => s.status(404).json({ error: 'یافت نشد' }));
app.use((q, s) => s.status(404).send('صفحه پیدا نشد (404)'));

app.use((e, q, s, n) => {
  if (e instanceof E) return s.status(e.c).json({ error: e.message });

  if (e instanceof multer.MulterError) {
    return s.status(400).json({ error: 'حجم یا تعداد فایل مجاز نیست (حداکثر ۵ مگابایت)' });
  }

  console.error(e);
  s.status(500).json({ error: 'خطای سرور؛ دوباره تلاش کنید' });
});

app.listen(process.env.PORT || 3000, () => {
  console.log('ZIBADOZ listening on', process.env.PORT || 3000);
});
