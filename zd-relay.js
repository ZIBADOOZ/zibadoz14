// =====================================================
//  لایه ارتباط با واسط ابری — ZIBADOZ zd-relay v2.2.0
// -----------------------------------------------------
//  حالت relay (پیش‌فرض روی GitHub Pages):
//    - نمایش‌ها (محصولات، دسته‌ها، بنرها، بسته‌ها، نظرات، وضعیت سفارش)
//      از اسنپ‌شات کاتالوگ که عامل محلی به واسط می‌فرستد خوانده می‌شود
//      و روی همین مرورگر جستجو/فیلتر/صفحه‌بندی می‌شود (سرعت لحظه‌ای،
//      حتی وقتی کامپیوتر فروشنده خاموش است).
//    - عملیات‌های زنده (ورود، ثبت سفارش، کوپن، رسید، علاقه‌مندی، نظر)
//      به‌صورت درخواستِ شناسه‌دار به صف امن واسط می‌روند و عامل محلی
//      آن‌ها را با همان API فروشگاه اجرا می‌کند.
//  حالت direct (اجرای محلی روی کامپیوتر فروشنده):
//    - همه‌چیز مانند نسخه 2.1.0 مستقیم به سرور محلی وصل می‌شود.
// =====================================================
(function () {
  'use strict';
  const MODE = window.ZD_MODE || 'relay';
  const RELAY = window.ZD_RELAY || '';
  const DIRECT_API = window.ZD_API || '';

  // ---------- حالت direct: رفتار قبلی ----------
  if (MODE === 'direct' || !RELAY) {
    window.ZD_RELAY_MODE = false;
    window.zdFetch = function (path, opts) { return fetch(DIRECT_API + path, opts); };
    window.zdPollOrder = async function () { throw new Error('در حالت محلی نیازی به پیگیری صف نیست'); };
    window.zdPaymentInfo = async function () { return null; };
    return;
  }
  window.ZD_RELAY_MODE = true;

  // ---------- ابزارهای پایه ----------
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const uid = () => (crypto.randomUUID ? crypto.randomUUID().replace(/-/g, '') :
    Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, '0')).join(''));

  function resp(status, data) {
    return { ok: status >= 200 && status < 300, status, json: async () => data };
  }
  function errResp(d, fallback) {
    return resp((d && d.http) || 500, { error: (d && (d.message || d.error)) || fallback || 'خطای ارتباط با واسط' });
  }

  async function gasGet(params) {
    const u = RELAY + '?' + new URLSearchParams(params).toString();
    const r = await fetch(u, { redirect: 'follow' });
    const d = await r.json().catch(() => ({ error: 'خطای واسط ابری' }));
    if (d && d.error && !d.orders && !d.products && !d.settings && !d.version) throw d;
    return d;
  }

  async function gasPost(body, timeoutMs = 60000) {
    const r = await fetch(RELAY, {
      method: 'POST', redirect: 'follow',
      headers: { 'Content-Type': 'text/plain;charset=UTF-8' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs)
    });
    return r.json().catch(() => ({ error: 'خطای واسط ابری' }));
  }

  // ---------- کش اسنپ‌شات‌ها ----------
  const LS = { cat: 'zd_cat_cache', catv: 'zd_cat_ver', rev: 'zd_rev_cache', revv: 'zd_rev_ver' };
  let catalog = null, reviews = null, catLoading = null, revLoading = null;

  function lsGet(k) { try { return localStorage.getItem(k); } catch (_) { return null; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); return true; } catch (_) { return false; } }

  async function ensureCatalog(force) {
    if (catalog && !force) return catalog;
    if (catLoading) return catLoading;
    catLoading = (async () => {
      try {
        const ver = await gasGet({ action: 'catalog_ver' });
        const cached = lsGet(LS.cat);
        if (!force && cached && ver.v && lsGet(LS.catv) === ver.v) {
          catalog = JSON.parse(cached);
        } else {
          catalog = await gasGet({ action: 'catalog' });
          lsSet(LS.catv, catalog.version || '');
          if (JSON.stringify(catalog).length < 2600000) lsSet(LS.cat, JSON.stringify(catalog));
        }
      } finally { catLoading = null; }
      window.dispatchEvent(new CustomEvent('zd:catalog'));
      return catalog;
    })();
    return catLoading;
  }

  async function ensureReviews(force) {
    if (reviews && !force) return reviews;
    if (revLoading) return revLoading;
    revLoading = (async () => {
      try {
        const ver = await gasGet({ action: 'catalog_ver' });
        const cached = lsGet(LS.rev);
        if (!force && cached && ver.rv && lsGet(LS.revv) === ver.rv) {
          reviews = JSON.parse(cached);
        } else {
          reviews = await gasGet({ action: 'reviews' });
          lsSet(LS.revv, reviews.version || '');
          if (JSON.stringify(reviews).length < 2600000) lsSet(LS.rev, JSON.stringify(reviews));
        }
      } finally { revLoading = null; }
      return reviews;
    })();
    return revLoading;
  }

  // ---------- جستجوی سمت مرورگر (پورت الگوریتم سرور) ----------
  function norm(value) {
    return String(value || '')
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
  }
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
    const extra = '';
    const allText = [name, category, shortDesc, description].filter(Boolean).join(' ');
    const searchableWords = [...new Set([name, category, shortDesc].join(' ').split(' ').filter(Boolean))].slice(0, 100);
    const qTokens = [...new Set(query.split(' ').filter(Boolean))].slice(0, 8);
    const aliases = expandSearchTerms(query).filter(x => x !== query);
    let score = 0;
    if (name === query) score += 1600;
    else if (name.startsWith(query)) score += 1350;
    else if (name.includes(query)) score += 1150;
    else if (category === query) score += 950;
    else if (category.includes(query)) score += 800;
    else if (shortDesc.includes(query)) score += 650;
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

  // ---------- ساخت ردیف‌های محصول مانند شکل سرور ----------
  function prodRows() {
    const c = catalog || { products: [] };
    return (c.products || []).map(p => ({
      id: p.id, slug: p.slug, name: p.name,
      short_desc: p.short_desc || '', description: p.description || '',
      price: p.price, discount_price: p.discount_price, stock: p.stock,
      colors: p.colors || [], sizes: p.sizes || [],
      featured: p.featured, bestseller: p.bestseller, sold: p.sold,
      created_at: p.created_at, category_name: p.category_name, category_slug: p.category_slug,
      image: (p.images && p.images[0]) || null,
      avg_rating: p.avg_rating || 0, review_count: p.review_count || 0,
      _images: p.images || []
    }));
  }
  const eff = r => (r.discount_price && r.discount_price < r.price) ? r.discount_price : r.price;

  function listProducts(qs) {
    const Q = {};
    for (const [k, v] of new URLSearchParams(qs)) Q[k] = v;
    let rows = prodRows();
    if (Q.category) rows = rows.filter(r => r.category_slug === Q.category);
    if (Q.instock === '1') rows = rows.filter(r => r.stock > 0);
    if (Q.discount === '1') rows = rows.filter(r => r.discount_price && r.discount_price < r.price);
    if (Q.min && Number.isFinite(+Q.min)) rows = rows.filter(r => eff(r) >= +Q.min);
    if (Q.max && Number.isFinite(+Q.max)) rows = rows.filter(r => eff(r) <= +Q.max);

    if (Q.q && norm(String(Q.q).slice(0, 100))) {
      const query = norm(String(Q.q).slice(0, 100));
      rows = rows.map(r => ({ r, score: searchScore(r, query) }))
        .filter(x => x.score > 0)
        .sort((a, b) => b.score - a.score || new Date(b.r.created_at) - new Date(a.r.created_at))
        .map(x => x.r);
    } else {
      const ord = {
        new: (a, b) => new Date(b.created_at) - new Date(a.created_at),
        cheap: (a, b) => eff(a) - eff(b),
        exp: (a, b) => eff(b) - eff(a),
        best: (a, b) => (Number(b.bestseller) - Number(a.bestseller)) || ((b.sold || 0) - (a.sold || 0)),
        discount: (a, b) => {
          const ra = (a.discount_price && a.price) ? 1 - a.discount_price / a.price : 0;
          const rb = (b.discount_price && b.price) ? 1 - b.discount_price / b.price : 0;
          return rb - ra;
        }
      }[Q.sort];
      if (ord) rows = [...rows].sort(ord);
    }

    const page = Math.max(parseInt(Q.page, 10) || 1, 1);
    const lim = Math.min(Math.max(parseInt(Q.limit, 10) || 24, 1), 100);
    const total = rows.length;
    const items = rows.slice((page - 1) * lim, page * lim).map(stripForList);
    return { items, total, page, limit: lim, has_more: page * lim < total };
  }

  function stripForList(r) {
    const { _images, ...rest } = r;
    return rest;
  }

  function productBySlug(slug) {
    return prodRows().find(r => r.slug === slug) || null;
  }
  function productDetail(slug) {
    const r = productBySlug(slug);
    if (!r) return null;
    return {
      ...stripForList(r),
      description: r.description,
      images: r._images,
      search_score: undefined
    };
  }
  function relatedProducts(slug) {
    const cur = productBySlug(slug);
    if (!cur) return [];
    const rows = prodRows().filter(r => r.slug !== slug && r.id !== cur.id);
    const related = [];
    if (cur.category_slug) {
      for (const r of rows.filter(r => r.category_slug === cur.category_slug)
        .sort((a, b) => (Number(b.bestseller) - Number(a.bestseller)) || ((b.sold || 0) - (a.sold || 0)) || (new Date(b.created_at) - new Date(a.created_at)))) {
        if (related.length >= 8) break;
        related.push(stripForList(r));
      }
    }
    const seen = new Set(related.map(r => r.id));
    seen.add(cur.id);
    if (related.length < 8) {
      for (const r of rows.sort((a, b) => (Number(b.bestseller) - Number(a.bestseller)) || ((b.sold || 0) - (a.sold || 0)) || (new Date(b.created_at) - new Date(a.created_at)))) {
        if (related.length >= 8) break;
        if (!seen.has(r.id)) { related.push(stripForList(r)); seen.add(r.id); }
      }
    }
    return related;
  }

  function reviewsFor(slug) {
    const rv = reviews || { reviews: [], questions: [] };
    return {
      items: (rv.reviews || []).filter(x => x.slug === slug),
      questions: (rv.questions || []).filter(x => x.slug === slug)
    };
  }

  // ---------- نگاشت RPC ----------
  function tokenOf(opts) {
    const h = (opts && opts.headers) || {};
    const a = h.Authorization || h.authorization || '';
    const m = String(a).match(/^Bearer\s+(.+)$/i);
    return m ? m[1] : '';
  }
  function rpcFor(path, method) {
    if (method === 'DELETE' && path === '/api/account/recent-views') return 'account.recent_views_clear';
    const map = {
      '/api/account/login': 'account.login',
      '/api/account/register': 'account.register',
      '/api/account/me': 'account.me',
      '/api/account/orders': 'account.orders',
      '/api/account/points': 'account.points',
      '/api/account/profile': 'account.profile',
      '/api/account/recent-views': 'account.recent_views',
      '/api/wishlist': 'wishlist.list',
      '/api/coupons/validate': 'coupons.validate'
    };
    if (map[path]) return map[path];
    if (/^\/api\/wishlist\/\d+$/.test(path)) return method === 'DELETE' ? 'wishlist.remove' : 'wishlist.add';
    if (/^\/api\/products\/[^/]+\/reviews$/.test(path)) return 'reviews.post';
    if (/^\/api\/products\/[^/]+\/questions$/.test(path)) return 'questions.post';
    if (path === '/api/orders') return 'orders.place';
    if (/^\/api\/orders\/[^/]+\/receipt$/.test(path)) return 'orders.receipt';
    if (/^\/api\/banners\/\d+\/stats$/.test(path)) return 'banners.stats';
    return null;
  }

  // فراخوانی RPC با انتظار و تلاش مجدد (poll)
  async function callRpc(rpc, payload, token, opts = {}) {
    const relay_id = uid();
    const wait = opts.wait !== undefined ? opts.wait : 20;
    const pollMs = opts.pollMs || 6000;
    const maxWaitMs = opts.maxWaitMs || 120000;
    let d = await gasPost({ action: 'call', rpc, payload, token, relay_id, wait });
    if (d.error) return { relay_id, error: d, done: false };
    if (d.done) return { relay_id, result: d.result, errorRes: d.error ? d : null, done: true };
    const deadline = Date.now() + maxWaitMs;
    while (Date.now() < deadline) {
      await sleep(pollMs);
      d = await gasPost({ action: 'call', rpc, payload: null, token, relay_id, wait: 0 });
      if (d.error) return { relay_id, error: d, done: false };
      if (d.done) return { relay_id, result: d.result, done: true };
    }
    return { relay_id, timeout: true, done: false };
  }

  // ---------- zdFetch: نقطه ورود همه فراخوانی‌های سایت ----------
  window.zdFetch = async function (path, opts = {}) {
    const method = String(opts.method || 'GET').toUpperCase();
    const u = new URL(RELAY);
    const qs = path.includes('?') ? path.slice(path.indexOf('?') + 1) : '';
    const clean = path.replace(/\?.*$/, '');

    try {
      // ----- GET های نمایشی از اسنپ‌شات -----
      if (method === 'GET') {
        await ensureCatalog();
        if (clean === '/api/settings') {
          const c = catalog;
          return resp(200, { ...c.settings, zd_relay: true, generated_at: c.generated_at });
        }
        if (clean === '/api/categories') return resp(200, catalog.categories || []);
        if (clean === '/api/products') return resp(200, listProducts(qs));
        if (clean === '/api/products/by-ids') {
          const ids = String(new URLSearchParams(qs).get('ids') || '').split(',').map(Number).filter(x => Number.isSafeInteger(x) && x > 0);
          const items = prodRows().filter(r => ids.includes(r.id)).map(stripForList);
          return resp(200, { items });
        }
        let m = clean.match(/^\/api\/products\/([^/]+)$/);
        if (m) {
          const p = productDetail(decodeURIComponent(m[1]));
          if (!p) return resp(404, { error: 'محصول پیدا نشد' });
          return resp(200, p);
        }
        m = clean.match(/^\/api\/products\/([^/]+)\/related$/);
        if (m) return resp(200, { items: relatedProducts(decodeURIComponent(m[1])) });
        m = clean.match(/^\/api\/products\/([^/]+)\/reviews$/);
        if (m) { await ensureReviews(); return resp(200, { items: reviewsFor(decodeURIComponent(m[1])).items }); }
        m = clean.match(/^\/api\/products\/([^/]+)\/questions$/);
        if (m) { await ensureReviews(); return resp(200, { items: reviewsFor(decodeURIComponent(m[1])).questions }); }
        if (clean === '/api/banners') return resp(200, { items: (catalog.banners || []).filter(b => b.image) });
        if (clean === '/api/campaigns') return resp(200, { items: catalog.campaigns || [] });
        if (clean === '/api/bundles') {
          const byId = new Map(prodRows().map(r => [r.id, r]));
          const items = (catalog.bundles || []).map(b => ({
            ...b,
            items: (b.items || []).map(it => {
              const p = byId.get(Number(it.product_id));
              return p ? { qty: it.qty, id: p.id, slug: p.slug, name: p.name, price: eff(p), stock: p.stock, image: p.image } : null;
            }).filter(Boolean)
          }));
          return resp(200, { items });
        }
        if (clean === '/api/shipping-methods') return resp(200, { items: catalog.shipping || [] });
      }

      // ----- پیگیری سفارش: از اسنپ‌شات وضعیت در خود واسط -----
      if (method === 'POST' && clean === '/api/orders/track') {
        const body = JSON.parse(opts.body || '{}');
        const d = await gasPost({ action: 'track', order_number: body.order_number, mobile: body.mobile });
        if (d.error) return errResp(d, 'سفارش پیدا نشد');
        if (d.queued) {
          return resp(200, {
            queued: true,
            status: 'pending_queue',
            order_number: body.order_number,
            history: [],
            items: [],
            message: d.message || 'سفارش شما در صف پردازش است.'
          });
        }
        return resp(200, d);
      }

      // ----- عملیات‌های زنده: صف RPC -----
      const rpc = rpcFor(clean, method);
      if (rpc) {
        let payload = {};
        try { payload = opts.body ? JSON.parse(opts.body) : {}; } catch (_) { payload = {}; }
        // شناسه بنر/محصول از مسیر
        let m;
        if ((m = clean.match(/^\/api\/wishlist\/(\d+)$/))) payload.product_id = +m[1];
        if ((m = clean.match(/^\/api\/products\/([^/]+)\/(reviews|questions)$/))) payload.slug = decodeURIComponent(m[1]);
        if ((m = clean.match(/^\/api\/banners\/(\d+)\/stats$/))) payload.banner_id = +m[1];
        if (rpc === 'orders.receipt') {
          const mm = clean.match(/^\/api\/orders\/([^/]+)\/receipt$/);
          payload.order_number = mm ? decodeURIComponent(mm[1]) : payload.order_number;
        }

        const token = tokenOf(opts);
        const isOrder = rpc === 'orders.place';
        const isReceipt = rpc === 'orders.receipt';
        const isMe = rpc === 'account.me';
        const out = await callRpc(rpc, payload, token, {
          wait: isOrder ? 0 : (isMe ? 3 : 20),
          pollMs: 6000,
          maxWaitMs: isOrder || isReceipt ? 180000 : (isMe ? 20000 : 120000)
        });

        if (out.error) return errResp(out.error);
        if (out.done) {
          if (out.result && out.result.error && out.result.http) return resp(out.result.http, out.result);
          return resp(200, out.result);
        }
        if (out.timeout) {
          if (isMe) {
            // بررسی خودکار حساب در بارگذاری صفحه؛ آفلاین بودن فروشنده نباید کاربر را خارج کند
            return resp(200, { account: null, zd_offline: true });
          }
          return resp(504, {
            error: isOrder
              ? 'سفارش شما در صف پردازش است؛ شماره سفارش به‌زودی از طریق «پیگیری سفارش» قابل مشاهده خواهد بود.'
              : 'پاسخی دریافت نشد؛ فروشنده آفلاین است یا ارتباط کند است. بعداً دوباره تلاش کنید.',
            pending: true, relay_id: out.relay_id
          });
        }
      }

      return resp(404, { error: 'یافت نشد' });
    } catch (e) {
      return resp(503, { error: (e && (e.message || e.error)) || 'ارتباط با واسط ابری برقرار نشد' });
    }
  };

  // ---------- ابزارهای پرداخت دورقه‌ای ----------
  // پس از دریافت pending از ثبت سفارش، با relay_id نتیجه پرسیده می‌شود
  window.zdPollOrder = async function (relay_id, maxWaitMs = 120000) {
    const deadline = Date.now() + maxWaitMs;
    while (Date.now() < deadline) {
      await sleep(6000);
      const d = await gasPost({ action: 'call', rpc: 'orders.place', payload: null, relay_id, wait: 0 });
      if (d.error) return { error: d };
      if (d.done && d.result) return { result: d.result };
      if (d.done && d.error) return { error: d };
    }
    return { timeout: true };
  };

  // اطلاعات پرداخت (شماره کارت) برای نمایش در مرحله انتظار سفارش
  window.zdPaymentInfo = async function () {
    try {
      await ensureCatalog();
      return catalog.payment || null;
    } catch (_) { return null; }
  };

  // نسخه اسنپ‌شات برای نمایش وضعیت همگام‌سازی
  window.zdSyncInfo = async function () {
    try {
      await ensureCatalog();
      return { generated_at: catalog.generated_at };
    } catch (_) { return null; }
  };
})();
