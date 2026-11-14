/* تست پذیرش کامل زیبادوز با PostgreSQL توکار — مرحله ۱۲ دستورکار
 * اجرا: node acceptance.mjs  (از داخل build/zibadoz14 تا ماژول‌ها resolve شوند)
 * خروجی: results JSON + چاپ خلاصه
 */
import EmbeddedPostgres from 'embedded-postgres';
import { Client } from 'pg';
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url))); // ریشه مخزن
const PGDATA = path.join(ROOT, 'pgdata-test');
const PORT = 3210;
const BASE = `http://127.0.0.1:${PORT}`;
const JWT_SECRET = 'x'.repeat(48);
const DB_URL = 'postgresql://postgres:testpw@127.0.0.1:5433/zibadoz';

const results = [];
function rec(id, name, ok, detail = '') {
  results.push({ id, name, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'} | ${id} | ${name}${detail ? ' | ' + detail : ''}`);
}
async function j(method, p, { token, body, raw, headers = {} } = {}) {
  const h = { ...headers };
  if (token) h.Authorization = 'Bearer ' + token;
  let payload;
  if (raw !== undefined) { payload = raw; }
  else if (body !== undefined) { h['Content-Type'] = 'application/json'; payload = JSON.stringify(body); }
  const r = await fetch(BASE + p, { method, headers: h, body: payload });
  const t = await r.text();
  let d = null; try { d = JSON.parse(t); } catch { d = t; }
  return { status: r.status, d, headers: r.headers };
}

const pg = new EmbeddedPostgres({
  databaseDir: PGDATA, user: 'postgres', password: 'testpw', port: 5433, persistent: false,
});
let server = null, serverLog = '';
try {
  console.log('== init db ==');
  rmSync(PGDATA, { recursive: true, force: true });
  await pg.initialise();
  await pg.start();
  await pg.createDatabase('zibadoz');

  const client = new Client({ connectionString: 'postgresql://postgres:testpw@127.0.0.1:5433/zibadoz' });
  await client.connect();
  await client.query(readFileSync(path.join(ROOT, 'database/schema.sql'), 'utf8'));
  for (const f of ['migrate-banners', 'migrate-phase2', 'migrate-phase3', 'migrate-phase4', 'migrate-phase6']) {
    await client.query(readFileSync(path.join(ROOT, `database/${f}.sql`), 'utf8'));
  }
  // داده تست: روش ارسال دوم با آستانه ارسال رایگان
  await client.query(`insert into shipping_methods(name, base_cost, free_shipping_threshold, is_active, sort_order)
    select 'پیک فوری', 80000, 5000000, true, 2 where not exists (select 1 from shipping_methods where name='پیک فوری')`);
  await client.end();
  console.log('== schema ready ==');

  // ساخت مدیر با اسکریپت پروژه
  await new Promise((res, rej) => {
    const p = spawn('node', ['scripts/create-admin.js', 'admin1', 'AdminPass#2026x'], {
      env: { ...process.env, DATABASE_URL: DB_URL }, stdio: 'pipe',
    });
    p.on('exit', c => c === 0 ? res() : rej(new Error('create-admin exit ' + c)));
  });
  await new Promise((res, rej) => {
    const p = spawn('node', ['scripts/create-admin.js', 'admin2', 'AdminPass#2026y'], {
      env: { ...process.env, DATABASE_URL: DB_URL }, stdio: 'pipe',
    });
    p.on('exit', c => c === 0 ? res() : rej(new Error('create-admin2 exit ' + c)));
  });

  console.log('== boot server ==');
  server = spawn('node', ['src/server.js'], {
    env: { ...process.env, PORT: String(PORT), DATABASE_URL: DB_URL, JWT_SECRET, NODE_ENV: 'development', TRUST_PROXY: '1' },
    stdio: 'pipe',
  });
  server.stdout.on('data', d => { serverLog += d; });
  server.stderr.on('data', d => { serverLog += d; });
  for (let i = 0; i < 60; i++) {
    try { const r = await fetch(BASE + '/api/settings'); if (r.ok) break; } catch {}
    await new Promise(r => setTimeout(r, 500));
  }

  // ---------- تنظیمات فروشگاه ----------
  const login = await j('POST', '/api/admin/login', { body: { username: 'admin1', password: 'AdminPass#2026x' } });
  rec('T-LOGIN', 'ورود مدیر با رمز صحیح', login.status === 200 && !!login.d?.token);
  const A = login.d.token;

  const st = await j('PUT', '/api/admin/settings', { token: A, body: {
    shop_active: '1', points_enabled: '1', points_per_toman: '1000', points_min_redeem: '100',
    points_value_toman: '100', shipping_fee: '150000', min_order: '0', card_number: '6037-9975-1234-5678', card_owner: 'مالک فروشگاه',
  }});
  rec('T-SET', 'به‌روزرسانی تنظیمات توسط مدیر', st.status === 200);

  // ---------- تست‌های امنیت بحرانی ----------
  // توکن مشتری: ثبت‌نام
  const reg = await j('POST', '/api/account/register', { body: { name: 'مشتری تست', identifier: 'cust1@test.ir', password: 'CustPass#123' } });
  rec('T-REG', 'ثبت‌نام مشتری', reg.status === 201 && !!reg.d?.token, 'status=' + reg.status);
  const C = reg.d.token;
  const dup = await j('POST', '/api/account/register', { body: { name: 'مشتری تست', identifier: 'cust1@test.ir', password: 'CustPass#123' } });
  rec('T-REG-DUP', 'ثبت‌نام تکراری رد می‌شود', dup.status === 409, 'status=' + dup.status);
  const logC = await j('POST', '/api/account/login', { body: { identifier: 'cust1@test.ir', password: 'CustPass#123' } });
  rec('T-REG-LOGIN', 'ورود مشتری', logC.status === 200 && !!logC.d?.token);

  // توکن دست‌کاری‌شده
  const tampered = C.slice(0, -3) + 'abc';
  const t1 = await j('GET', '/api/admin/stats', { token: tampered });
  rec('T-SEC-FORGED', 'توکن دست‌کاری‌شده روی API ادمین رد می‌شود', t1.status === 401 || t1.status === 403, 'status=' + t1.status);

  // توکن مشتری معتبر روی مسیرهای ادمین (بحرانی)
  const secTests = [
    ['GET', '/api/admin/stats'], ['GET', '/api/admin/products'], ['GET', '/api/admin/orders'], ['GET', '/api/admin/settings'],
    ['POST', '/api/admin/products'], ['DELETE', '/api/admin/orders/1'], ['POST', '/api/admin/coupons/advanced'],
  ];
  let secAll = true, secDetail = [];
  for (const [m, p] of secTests) {
    const r = await j(m, p, { token: C, body: m === 'POST' ? {} : undefined });
    const ok = r.status === 401 || r.status === 403;
    secAll = secAll && ok; secDetail.push(p + '=' + r.status);
  }
  rec('T-SEC-CUST-ADMIN', 'توکن مشتری به هیچ API مدیریتی دسترسی ندارد', secAll, secDetail.join(', '));

  // توکن مدیر واقعی
  const t2 = await j('GET', '/api/admin/stats', { token: A });
  rec('T-SEC-ADMIN-OK', 'توکن مدیر با APIهای مدیریتی کار می‌کند', t2.status === 200);
  const t3 = await j('GET', '/api/admin/settings', { token: A });
  rec('T-SEC-ADMIN-SET', 'تنظیمات مدیریتی شامل اطلاعات کارت', t3.status === 200 && !!t3.d?.card_number);
  const t4 = await j('GET', '/api/settings');
  rec('T-SET-PUBLIC', 'تنظیمات عمومی شماره کارت را لو نمی‌دهد', t4.status === 200 && t4.d?.card_number === undefined);

  // ---------- محصول با رنگ و سایز ----------
  const cats = (await j('GET', '/api/categories')).d;
  const catHand = cats.find(c => c.slug === 'handbag');
  const catWallet = cats.find(c => c.slug === 'wallet');
  const fd = new FormData();
  fd.set('name', 'کیف دستی تست'); fd.set('price', '2000000'); fd.set('discount_price', '');
  fd.set('category_id', String(catHand.id)); fd.set('stock', '50');
  fd.set('colors', JSON.stringify([{ name: 'قهوه‌ای', hex: '#6D4C41' }]));
  fd.set('sizes', JSON.stringify([{ name: 'کوچک', price: 1800000, stock: 20, active: true }, { name: 'بزرگ', price: null, stock: null, active: true }]));
  fd.set('short_desc', 'کیف دستی چرمی برای تست'); fd.set('description', 'توضیحات کامل تست'); fd.set('keywords', 'کیف, bag');
  fd.set('published', '1'); fd.set('featured', '1'); fd.set('bestseller', '0');
  const p1 = await j('POST', '/api/admin/products', { token: A, raw: fd });
  rec('T-PROD-CREATE', 'ایجاد محصول با رنگ/سایز', p1.status === 200, 'status=' + p1.status);
  const plist = (await j('GET', '/api/products')).d;
  const prod = plist.items.find(x => x.name === 'کیف دستی تست');
  rec('T-PROD-LIST', 'محصول در فهرست عمومی', !!prod);
  const byIds = (await j('GET', '/api/products/by-ids?ids=' + prod.id)).d;
  const sizePrices = (byIds.items?.[0]?.sizes || []).map(s => s);
  rec('T-PROD-SIZES', 'قیمت مستقل سایز در API عمومی', sizePrices.some(s => s.name === 'کوچک' && Number(s.price) === 1800000));

  // محصول دوم در دسته کیف پول (برای کوپن دسته‌ای)
  const fd2 = new FormData();
  fd2.set('name', 'کیف پول تست'); fd2.set('price', '900000'); fd2.set('category_id', String(catWallet.id));
  fd2.set('stock', '30'); fd2.set('published', '1');
  const p2 = await j('POST', '/api/admin/products', { token: A, raw: fd2 });
  rec('T-PROD-CREATE2', 'ایجاد محصول دوم', p2.status === 200);
  const plist2 = (await j('GET', '/api/products')).d;
  const prod2 = plist2.items.find(x => x.name === 'کیف پول تست');

  // ---------- ثبت سفارش با سایز ----------
  const orderBody = {
    customer: { name: 'مشتری تست', mobile: '09121234567', province: 'تهران', city: 'تهران', address: 'خیابان تست، پلاک ۱۲، واحد ۳', postal_code: '1234567890', notes: 'تست' },
    items: [{ product_id: prod.id, qty: 2, color: 'قهوه‌ای', size: 'کوچک' }],
    shipping_method_id: null,
  };
  // شناسه روش پیک (دوم) برای تست ذخیره روش
  const admShip = (await j('GET', '/api/admin/shipping-methods', { token: A })).d;
  const pick = Array.isArray(admShip) ? admShip.find(s => s.name === 'پیک فوری') : null;
  orderBody.shipping_method_id = pick?.id ?? null;
  const o1 = await j('POST', '/api/orders', { token: C, body: orderBody });
  rec('T-ORDER', 'ثبت سفارش با سایز قیمت‌دار', o1.status === 200, o1.status === 200 ? `total=${o1.d.total} ship=${o1.d.shipping} method=${o1.d.shipping_method_name}` : JSON.stringify(o1.d).slice(0, 120));
  rec('T-ORDER-PRICE', 'قیمت سایز سمت سرور اعمال شد', o1.d?.subtotal === 3600000, 'subtotal=' + o1.d?.subtotal);
  rec('T-ORDER-SHIP', 'هزینه ارسال از روش پیک (۸۰هزار)', o1.d?.shipping === 80000, 'ship=' + o1.d?.shipping);
  rec('T-ORDER-METHOD', 'نام روش ارسال در پاسخ', !!o1.d?.shipping_method_name, o1.d?.shipping_method_name);
  const orderNum = o1.d?.order_number;

  // رسید
  // JPEG کوچک معتبر:magic bytes JFIF
  const jpeg = Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x02, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xD9]);
  const rfd = new FormData();
  rfd.set('mobile', '09121234567');
  rfd.append('receipt', new Blob([jpeg], { type: 'image/jpeg' }), 'r.jpg');
  const rc = await fetch(BASE + `/api/orders/${orderNum}/receipt`, { method: 'POST', body: rfd });
  rec('T-RECEIPT', 'ارسال رسید معتبر', rc.status === 200, 'status=' + rc.status);
  const bad = new FormData();
  bad.set('mobile', '09121234567');
  bad.append('receipt', new Blob([Buffer.from('not an image at all')], { type: 'image/jpeg' }), 'fake.jpg');
  const badr = await fetch(BASE + `/api/orders/${orderNum}/receipt`, { method: 'POST', body: bad });
  rec('T-RECEIPT-BAD', 'فایل جعلی با magic bytes رد می‌شود', badr.status === 400, 'status=' + badr.status);

  // تأیید پرداخت توسط مدیر → امتیاز
  const dO = (await j('GET', '/api/admin/orders', { token: A })).d;
  const myOrder = dO.find(x => x.order_number === orderNum);
  const pay = await j('POST', `/api/admin/orders/${myOrder.id}/payment`, { token: A, body: { action: 'approve' } });
  rec('T-PAY', 'تأیید پرداخت توسط مدیر', pay.status === 200, 'status=' + pay.status);
  const pts = (await j('GET', '/api/account/points', { token: C })).d;
  rec('T-POINTS-EARN', 'امتیاز خرید اعطا شد floor(۳٬۶۸۰٬۰۰۰/۱۰۰۰)=۳۶۸۰', pts.balance === 3680, 'balance=' + pts.balance);
  const prodAfter = (await j('GET', '/api/products/by-ids?ids=' + prod.id)).d.items[0];
  rec('T-STOCK-DEC', 'موجودی پس از سفارش کم شد', Number(prodAfter.stock) === 48, 'stock=' + prodAfter.stock);

  // روش ارسال در جزئیات ادمین
  const det = (await j('GET', `/api/admin/orders/${myOrder.id}`, { token: A })).d;
  rec('T-ORDER-DET-METHOD', 'روش ارسال در جزئیات ادمین', det.shipping_method_name === 'پیک فوری', det.shipping_method_name);

  // ---------- کوپن پیشرفته ----------
  const mkCoup = async (body) => j('POST', '/api/admin/coupons/advanced', { token: A, body });
  // ۱) سقف تخفیف + محدودیت محصول + حداقل تعداد
  const c1 = await mkCoup({ code: 'CAP20', discount_type: 'percent', discount_value: 50, max_discount: 20000, per_customer_limit: 1, product_ids: [prod.id], min_qty: 1, min_order: 0, active: true });
  rec('T-COUP-CREATE', 'ایجاد کوپن پیشرفته', c1.status === 200, 'status=' + c1.status);
  const o2 = await j('POST', '/api/orders', { token: C, body: { ...orderBody, coupon_code: 'CAP20' } });
  rec('T-COUP-CAP', 'سقف max_discount اعمال شد (۵۰٪ از ۳.۶م = ۱.۸م → ۲۰هزار)', o2.d?.discount === 20000, 'discount=' + o2.d?.discount);
  const o3 = await j('POST', '/api/orders', { token: C, body: { ...orderBody, coupon_code: 'CAP20' } });
  rec('T-COUP-PER-CUST', 'سهمیه per_customer_limit=1 مصرف دوم را رد می‌کند', o3.status === 400, 'status=' + o3.status);
  // ۲) حداقل تعداد
  await mkCoup({ code: 'MINQ3', discount_type: 'fixed', discount_value: 10000, min_qty: 3, active: true });
  const o4 = await j('POST', '/api/orders', { token: C, body: { ...orderBody, coupon_code: 'MINQ3' } });
  rec('T-COUP-MINQTY', 'min_qty=3 با ۲ عدد رد می‌شود', o4.status === 400, 'status=' + o4.status);
  // ۳) محدودیت دسته — سبد شامل محصول دسته دیگر
  await mkCoup({ code: 'CATWAL', discount_type: 'percent', discount_value: 10, category_id: catWallet.id, active: true });
  const o5 = await j('POST', '/api/orders', { token: C, body: { customer: orderBody.customer, items: [{ product_id: prod.id, qty: 1, color: 'قهوه‌ای', size: 'کوچک' }], shipping_method_id: pick?.id ?? null, coupon_code: 'CATWAL' } });
  rec('T-COUP-CAT-SCOPE', 'کوپن دسته کیف پول روی محصول کیف دستی اعمال نمی‌شود', o5.status === 400, 'status=' + o5.status);
  const o6 = await j('POST', '/api/orders', { token: C, body: { customer: orderBody.customer, items: [{ product_id: prod2.id, qty: 1, color: '', size: '' }], shipping_method_id: pick?.id ?? null, coupon_code: 'CATWAL' } });
  rec('T-COUP-CAT-OK', 'کوپن دسته‌ای روی محصول همان دسته کار می‌کند', o6.status === 200 && o6.d?.discount === 90000, 'discount=' + o6.d?.discount);
  // ۴) فقط اولین سفارش — مشتری دوم
  await mkCoup({ code: 'FIRST1', discount_type: 'fixed', discount_value: 50000, first_order_only: true, active: true });
  const reg2 = await j('POST', '/api/account/register', { body: { name: 'مشتری دوم', identifier: 'cust2@test.ir', password: 'CustPass#456' } });
  const C2 = reg2.d.token;
  const o7 = await j('POST', '/api/orders', { token: C2, body: { customer: { ...orderBody.customer, mobile: '09129876543' }, items: [{ product_id: prod2.id, qty: 1, color: '', size: '' }], shipping_method_id: pick?.id ?? null, coupon_code: 'FIRST1' } });
  rec('T-COUP-FIRST', 'کوپن اولین سفارش برای مشتری جدید کار می‌کند', o7.status === 200 && o7.d?.discount === 50000, 'discount=' + o7.d?.discount);
  const o8 = await j('POST', '/api/orders', { token: C2, body: { customer: { ...orderBody.customer, mobile: '09129876543' }, items: [{ product_id: prod2.id, qty: 1, color: '', size: '' }], shipping_method_id: pick?.id ?? null, coupon_code: 'FIRST1' } });
  rec('T-COUP-FIRST-2', 'همان کوپن در سفارش دوم رد می‌شود', o8.status === 400, 'status=' + o8.status);

  // ---------- مصرف امتیاز ----------
  const o9 = await j('POST', '/api/orders', { token: C, body: { customer: orderBody.customer, items: [{ product_id: prod2.id, qty: 1, color: '', size: '' }], shipping_method_id: pick?.id ?? null, spend_points: 100 } });
  rec('T-POINTS-SPEND', 'مصرف ۱۰۰ امتیاز = ۱۰هزار تومان تخفیف', o9.status === 200 && o9.d?.points_used === 100 && o9.d?.points_value === 10000, JSON.stringify({ u: o9.d?.points_used, v: o9.d?.points_value, t: o9.d?.total }));
  const pts2 = (await j('GET', '/api/account/points', { token: C })).d;
  rec('T-POINTS-BAL', 'موجودی امتیاز پس از مصرف ۱۰۰ امتیاز: ۳۶۸۰−۱۰۰=۳۵۸۰', pts2.balance === 3580, 'balance=' + pts2.balance);
  const trk = (await j('POST', '/api/orders/track', { body: { order_number: o9.d.order_number, mobile: '09121234567' } })).d;
  rec('T-TRACK-POINTS', 'پیگیری سفارش امتیاز مصرفی را نشان می‌دهد', trk.points_used === 100, 'points_used=' + trk.points_used);
  const o10 = await j('POST', '/api/orders', { token: C, body: { customer: orderBody.customer, items: [{ product_id: prod2.id, qty: 1, color: '', size: '' }], shipping_method_id: pick?.id ?? null, spend_points: 999999999 } });
  rec('T-POINTS-CAP', 'درخواست امتیاز بیش از مبلغ قابل پرداخت رد می‌شود', o10.status === 400, 'status=' + o10.status);

  // ---------- لغو و بازگشت موجودی ----------
  const listA = (await j('GET', '/api/admin/orders', { token: A })).d;
  const cancelTarget = listA.find(x => x.order_number === o6.d.order_number);
  const cancel = await j('PATCH', `/api/admin/orders/${cancelTarget.id}/status`, { token: A, body: { status: 'cancelled', note: 'تست لغو' } });
  rec('T-CANCEL', 'لغو سفارش توسط مدیر', cancel.status === 200);
  const prodAfterCancel = (await j('GET', '/api/products/by-ids?ids=' + prod2.id)).d.items[0];
  rec('T-CANCEL-RESTOCK', 'موجودی پس از لغو برگشت (۳۰−۱−۱−۱+۱=۲۸)', Number(prodAfterCancel.stock) === 28, 'stock=' + prodAfterCancel.stock);
  const cancel2 = await j('PATCH', `/api/admin/orders/${cancelTarget.id}/status`, { token: A, body: { status: 'preparing' } });
  rec('T-CANCEL-AGAIN', 'سفارش لغوشده قابل فعال‌سازی مجدد نیست', cancel2.status === 400, 'status=' + cancel2.status);

  // ---------- نظرات: انتشار فوری + مدیریتی ----------
  const rv = await j('POST', `/api/products/${prod.slug}/reviews`, { token: C2, body: { rating: 5, body: 'کیف خیلی خوبی بود و کیفیت چرم عالی', title: 'عالی' } });
  rec('T-REVIEW', 'ثبت نظر با انتشار فوری', rv.status === 200);
  const pub1 = (await j('GET', `/api/products/${prod.slug}/reviews`)).d;
  rec('T-REVIEW-PUB', 'نظر در نمایش عمومی هست', (pub1.items || []).length > 0);
  const admRv = (await j('GET', '/api/admin/reviews', { token: A })).d;
  const myRv = admRv.find(x => x.product_name === 'کیف دستی تست');
  const hide = await j('PATCH', `/api/admin/reviews/${myRv.id}`, { token: A, body: { status: 'rejected', reject_reason: 'برای تست پنهان شد' } });
  rec('T-REVIEW-HIDE', 'رد نظر توسط مدیر', hide.status === 200);
  const pub2 = (await j('GET', `/api/products/${prod.slug}/reviews`)).d;
  rec('T-REVIEW-HIDDEN', 'نظر ردشده از نمایش عمومی حذف شد', !(pub2.items || []).some(x => x.id === myRv.id));
  const rejList = (await j('GET', '/api/admin/reviews?status=rejected', { token: A })).d;
  rec('T-REVIEW-FILTER', 'فیلتر وضعیت در API ادمین', rejList.some(x => x.id === myRv.id));
  const custHide = await j('PATCH', `/api/admin/reviews/${myRv.id}`, { token: C, body: { status: 'approved' } });
  rec('T-REVIEW-SEC', 'تغییر وضعیت نظر با توکن مشتری رد می‌شود', custHide.status === 401 || custHide.status === 403, 'status=' + custHide.status);

  // ---------- Rate Limit و IP مستقل (TRUST_PROXY=1) ----------
  async function burst(xff) {
    let got429 = false;
    for (let i = 0; i < 130; i++) {
      const r = await fetch(BASE + '/api/settings', { headers: xff ? { 'X-Forwarded-For': xff } : {} });
      if (r.status === 429) { got429 = true; break; }
    }
    return got429;
  }
  const rl1 = await burst('9.9.9.1');
  rec('T-RL-BUCKET1', 'IP اول بعد از ~۱۲۰ درخواست محدود می‌شود', rl1);
  const first2 = await fetch(BASE + '/api/settings', { headers: { 'X-Forwarded-For': '9.9.9.2' } });
  rec('T-RL-PROBE2', 'اولین درخواست IP دوم باید 200 باشد', first2.status === 200, 'status=' + first2.status);
  // سهمیه مستقل یعنی IP دوم هم باید بعد از ~۱۲۰ درخواستِ «خودش» محدود شود؛
  // اگر سهمیه مشترک بود، همان درخواست‌های اول 429 می‌گرفت.
  const rl2 = await burst('9.9.9.2');
  rec('T-RL-BUCKET2', 'سهمیه IP دوم مستقل و کامل مصرف شد (۴۲۹ بعد از ~۱۲۰)', rl2 === true);

  // ---------- قفل حساب مدیر (در انتها) ----------
  const lockStatuses = [], lockMsgs = [];
  for (let i = 0; i < 10; i++) {
    const r = await j('POST', '/api/admin/login', { body: { username: 'admin2', password: 'WrongPass#999' } });
    lockStatuses.push(r.status);
    lockMsgs.push(((r.d && r.d.error) || '').slice(0, 30));
  }
  const locked = lockStatuses.includes(429);
  rec('T-LOCKOUT', 'پس از شکست‌های مکرر، حساب مدیر قفل می‌شود', locked, 'statuses=' + lockStatuses.join(',') + ' msgs=' + lockMsgs.join(' / '));

} catch (e) {
  rec('FATAL', 'خطای غیرمنتظره', false, String(e && e.stack || e).slice(0, 300));
} finally {
  if (server) { try { server.kill(); } catch {} }
  try { await pg.stop(); } catch {}
  try { rmSync(PGDATA, { recursive: true, force: true }); } catch {}
}
writeFileSync(path.join(ROOT, '..', '..', 'acceptance-results.json'), JSON.stringify(results, null, 2));
const pass = results.filter(r => r.ok).length;
console.log(`\n===== ${pass}/${results.length} PASS =====`);
if (serverLog && results.some(r => !r.ok)) console.log('--- server tail ---\n' + serverLog.slice(-1200));
process.exit(results.some(r => !r.ok || r.id === 'FATAL') ? 1 : 0);
