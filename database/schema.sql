-- =====================================================
--  زیبادوز (ZIBADOZ) - ساختار پایگاه داده
--  PostgreSQL 13+
--  اجرا روی دیتابیس خالی یا موجود (با ADD COLUMN IF NOT EXISTS)
-- =====================================================

-- جدول مدیران
CREATE TABLE IF NOT EXISTS admin_users (
  id BIGSERIAL PRIMARY KEY,
  username VARCHAR(60) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- لاگ فعالیت مدیران
CREATE TABLE IF NOT EXISTS admin_activity_logs (
  id BIGSERIAL PRIMARY KEY,
  admin VARCHAR(60) NOT NULL,
  action VARCHAR(80) NOT NULL,
  detail TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_admin_logs_admin ON admin_activity_logs(admin);
CREATE INDEX IF NOT EXISTS idx_admin_logs_created ON admin_activity_logs(created_at);

-- تنظیمات فروشگاه (key/value)
CREATE TABLE IF NOT EXISTS store_settings (
  key VARCHAR(80) PRIMARY KEY,
  value TEXT NOT NULL DEFAULT ''
);

-- دسته‌بندی‌ها
CREATE TABLE IF NOT EXISTS categories (
  id BIGSERIAL PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  slug VARCHAR(140) UNIQUE NOT NULL,
  sort INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_categories_sort ON categories(sort);

-- محصولات
CREATE TABLE IF NOT EXISTS products (
  id BIGSERIAL PRIMARY KEY,
  slug VARCHAR(200) UNIQUE NOT NULL,
  name VARCHAR(200) NOT NULL,
  short_desc VARCHAR(500),
  description TEXT,
  search_text TEXT,
  search_keywords TEXT,
  price BIGINT NOT NULL DEFAULT 0,
  discount_price BIGINT,
  category_id BIGINT REFERENCES categories(id) ON DELETE SET NULL,
  stock INTEGER NOT NULL DEFAULT 0,
  stock_threshold INTEGER NOT NULL DEFAULT 5,
  colors JSONB NOT NULL DEFAULT '[]'::jsonb,
  sizes JSONB NOT NULL DEFAULT '[]'::jsonb,
  published BOOLEAN NOT NULL DEFAULT true,
  featured BOOLEAN NOT NULL DEFAULT false,
  bestseller BOOLEAN NOT NULL DEFAULT false,
  sold INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_products_published ON products(published);
CREATE INDEX IF NOT EXISTS idx_products_category ON products(category_id);
CREATE INDEX IF NOT EXISTS idx_products_stock ON products(stock);
CREATE INDEX IF NOT EXISTS idx_products_created ON products(created_at DESC);

-- تصاویر محصولات
CREATE TABLE IF NOT EXISTS product_images (
  id BIGSERIAL PRIMARY KEY,
  product_id BIGINT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  file VARCHAR(200) NOT NULL,
  is_main BOOLEAN NOT NULL DEFAULT false,
  sort INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_product_images_product ON product_images(product_id);
CREATE INDEX IF NOT EXISTS idx_product_images_main ON product_images(product_id, is_main DESC);

-- جدول کدهای تخفیف
CREATE TABLE IF NOT EXISTS coupons (
  id BIGSERIAL PRIMARY KEY,
  code VARCHAR(30) UNIQUE NOT NULL,
  discount_type VARCHAR(10) NOT NULL CHECK (discount_type IN ('percent','fixed')),
  discount_value NUMERIC(14,2) NOT NULL,
  min_order NUMERIC(14,2) NOT NULL DEFAULT 0,
  usage_limit INTEGER,
  used_count INTEGER NOT NULL DEFAULT 0,
  active BOOLEAN NOT NULL DEFAULT true,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- حساب کاربری مشتری
CREATE TABLE IF NOT EXISTS customer_accounts (
  id BIGSERIAL PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  email VARCHAR(254),
  mobile VARCHAR(20),
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT customer_accounts_email_or_mobile_required
    CHECK (email IS NOT NULL OR mobile IS NOT NULL)
);
CREATE UNIQUE INDEX IF NOT EXISTS customer_accounts_email_unique
  ON customer_accounts (LOWER(email)) WHERE email IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS customer_accounts_mobile_unique
  ON customer_accounts (mobile) WHERE mobile IS NOT NULL;

-- مشتریان (هر سفارش یک رکورد مشتری می‌سازد)
CREATE TABLE IF NOT EXISTS customers (
  id BIGSERIAL PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  mobile VARCHAR(20) NOT NULL,
  province VARCHAR(60),
  city VARCHAR(60),
  address TEXT,
  postal_code VARCHAR(10),
  account_id BIGINT REFERENCES customer_accounts(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_customers_mobile ON customers(mobile);
CREATE INDEX IF NOT EXISTS idx_customers_account ON customers(account_id);

-- سفارش‌ها
CREATE TABLE IF NOT EXISTS orders (
  id BIGSERIAL PRIMARY KEY,
  order_number VARCHAR(40) UNIQUE NOT NULL,
  customer_id BIGINT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  subtotal BIGINT NOT NULL DEFAULT 0,
  shipping BIGINT NOT NULL DEFAULT 0,
  discount BIGINT NOT NULL DEFAULT 0,
  coupon_code VARCHAR(30),
  total BIGINT NOT NULL DEFAULT 0,
  status VARCHAR(30) NOT NULL DEFAULT 'pending_payment',
  tracking_code VARCHAR(60),
  admin_note TEXT,
  notes TEXT,
  paid_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT orders_status_valid CHECK (
    status IN ('order_placed','pending_payment','receipt_sent','payment_confirmed',
               'payment_rejected','preparing','ready','shipped','delivered','cancelled')
  )
);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
CREATE INDEX IF NOT EXISTS idx_orders_customer ON orders(customer_id);
CREATE INDEX IF NOT EXISTS idx_orders_created ON orders(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_orders_paid ON orders(paid_at);

-- اقلام سفارش
CREATE TABLE IF NOT EXISTS order_items (
  id BIGSERIAL PRIMARY KEY,
  order_id BIGINT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  product_id BIGINT REFERENCES products(id) ON DELETE SET NULL,
  name VARCHAR(200) NOT NULL,
  unit_price BIGINT NOT NULL DEFAULT 0,
  qty INTEGER NOT NULL DEFAULT 1,
  color VARCHAR(60),
  size VARCHAR(60)
);
CREATE INDEX IF NOT EXISTS idx_order_items_order ON order_items(order_id);
CREATE INDEX IF NOT EXISTS idx_order_items_product ON order_items(product_id);

-- تاریخچه وضعیت سفارش
CREATE TABLE IF NOT EXISTS order_status_history (
  id BIGSERIAL PRIMARY KEY,
  order_id BIGINT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  status VARCHAR(30) NOT NULL,
  note TEXT,
  by_admin VARCHAR(60),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_order_status_history_order ON order_status_history(order_id);

-- رسیدهای پرداخت
CREATE TABLE IF NOT EXISTS payment_receipts (
  id BIGSERIAL PRIMARY KEY,
  order_id BIGINT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  file VARCHAR(200) NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'pending',
  reject_reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT receipts_status_valid CHECK (status IN ('pending','approved','rejected'))
);
CREATE INDEX IF NOT EXISTS idx_payment_receipts_order ON payment_receipts(order_id);
CREATE INDEX IF NOT EXISTS idx_payment_receipts_status ON payment_receipts(status);

-- =====================================================
--  بنرهای تبلیغاتی (V1 — Dynamic Banner Management)
-- =====================================================
CREATE TABLE IF NOT EXISTS banners (
  id BIGSERIAL PRIMARY KEY,
  title VARCHAR(200) NOT NULL,
  image VARCHAR(200) NOT NULL,
  category_id BIGINT REFERENCES categories(id) ON DELETE SET NULL,
  is_active BOOLEAN NOT NULL DEFAULT true,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_banners_active_sort ON banners(is_active, sort_order);
CREATE INDEX IF NOT EXISTS idx_banners_category ON banners(category_id);

-- =====================================================
--  فاز ۲ — زیرساخت قابلیت‌های مشتری
-- =====================================================

-- علاقه‌مندی‌ها
CREATE TABLE IF NOT EXISTS wishlist (
  id BIGSERIAL PRIMARY KEY,
  account_id BIGINT NOT NULL REFERENCES customer_accounts(id) ON DELETE CASCADE,
  product_id BIGINT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(account_id, product_id)
);
CREATE INDEX IF NOT EXISTS idx_wishlist_account ON wishlist(account_id);
CREATE INDEX IF NOT EXISTS idx_wishlist_product ON wishlist(product_id);

-- نظرات و امتیازدهی
CREATE TABLE IF NOT EXISTS product_reviews (
  id BIGSERIAL PRIMARY KEY,
  product_id BIGINT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  account_id BIGINT NOT NULL REFERENCES customer_accounts(id) ON DELETE CASCADE,
  title VARCHAR(200),
  body TEXT NOT NULL,
  rating SMALLINT NOT NULL CHECK (rating >= 1 AND rating <= 5),
  status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
  verified_buyer BOOLEAN NOT NULL DEFAULT false,
  reject_reason VARCHAR(300),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_reviews_product_status ON product_reviews(product_id, status);
CREATE INDEX IF NOT EXISTS idx_reviews_account ON product_reviews(account_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_reviews_account_product ON product_reviews(account_id, product_id);

-- پرسش و پاسخ
CREATE TABLE IF NOT EXISTS product_questions (
  id BIGSERIAL PRIMARY KEY,
  product_id BIGINT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  account_id BIGINT NOT NULL REFERENCES customer_accounts(id) ON DELETE CASCADE,
  question TEXT NOT NULL,
  answer TEXT,
  answered_by VARCHAR(60),
  status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','answered','hidden')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  answered_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_questions_product_status ON product_questions(product_id, status);
CREATE INDEX IF NOT EXISTS idx_questions_account ON product_questions(account_id);

-- تاریخچه بازدید
CREATE TABLE IF NOT EXISTS product_view_history (
  id BIGSERIAL PRIMARY KEY,
  account_id BIGINT NOT NULL REFERENCES customer_accounts(id) ON DELETE CASCADE,
  product_id BIGINT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  viewed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_view_history_account_time ON product_view_history(account_id, viewed_at DESC);
CREATE INDEX IF NOT EXISTS idx_view_history_product ON product_view_history(product_id);

-- =====================================================
--  فاز ۳ — فروش و بازاریابی
-- =====================================================
ALTER TABLE products ADD COLUMN IF NOT EXISTS related_ids JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE coupons ADD COLUMN IF NOT EXISTS max_discount NUMERIC(14,2);
ALTER TABLE coupons ADD COLUMN IF NOT EXISTS starts_at TIMESTAMPTZ;
ALTER TABLE coupons ADD COLUMN IF NOT EXISTS per_customer_limit INTEGER;
ALTER TABLE coupons ADD COLUMN IF NOT EXISTS first_order_only BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE coupons ADD COLUMN IF NOT EXISTS category_id BIGINT REFERENCES categories(id) ON DELETE SET NULL;
ALTER TABLE coupons ADD COLUMN IF NOT EXISTS product_ids JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE coupons ADD COLUMN IF NOT EXISTS min_qty INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS coupon_usage (
  id BIGSERIAL PRIMARY KEY, coupon_id BIGINT NOT NULL REFERENCES coupons(id) ON DELETE CASCADE,
  account_id BIGINT REFERENCES customer_accounts(id) ON DELETE SET NULL,
  order_id BIGINT REFERENCES orders(id) ON DELETE SET NULL,
  customer_mobile VARCHAR(20), used_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_coupon_usage_coupon ON coupon_usage(coupon_id);
CREATE INDEX IF NOT EXISTS idx_coupon_usage_account ON coupon_usage(account_id);

CREATE TABLE IF NOT EXISTS campaigns (
  id BIGSERIAL PRIMARY KEY, title VARCHAR(200) NOT NULL, description TEXT, image VARCHAR(200),
  discount_type VARCHAR(10) NOT NULL DEFAULT 'percent' CHECK (discount_type IN ('percent','fixed')),
  discount_value NUMERIC(14,2) NOT NULL,
  category_id BIGINT REFERENCES categories(id) ON DELETE SET NULL,
  product_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  starts_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), ends_at TIMESTAMPTZ,
  is_active BOOLEAN NOT NULL DEFAULT true, show_on_homepage BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_campaigns_active_dates ON campaigns(is_active, starts_at, ends_at);

CREATE TABLE IF NOT EXISTS product_bundles (
  id BIGSERIAL PRIMARY KEY, title VARCHAR(200) NOT NULL, description TEXT, image VARCHAR(200),
  bundle_price BIGINT NOT NULL, original_price BIGINT,
  is_active BOOLEAN NOT NULL DEFAULT true, sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_bundles_active_sort ON product_bundles(is_active, sort_order);

CREATE TABLE IF NOT EXISTS bundle_items (
  id BIGSERIAL PRIMARY KEY, bundle_id BIGINT NOT NULL REFERENCES product_bundles(id) ON DELETE CASCADE,
  product_id BIGINT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  qty INTEGER NOT NULL DEFAULT 1 CHECK (qty >= 1 AND qty <= 100),
  UNIQUE(bundle_id, product_id)
);
CREATE INDEX IF NOT EXISTS idx_bundle_items_bundle ON bundle_items(bundle_id);

CREATE TABLE IF NOT EXISTS banner_stats (
  id BIGSERIAL PRIMARY KEY, banner_id BIGINT NOT NULL REFERENCES banners(id) ON DELETE CASCADE,
  event_type VARCHAR(10) NOT NULL CHECK (event_type IN ('view','click')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_banner_stats_banner_type_time ON banner_stats(banner_id, event_type, created_at DESC);

-- =====================================================
--  فاز ۴ — سفارش و ارسال
-- =====================================================
CREATE TABLE IF NOT EXISTS shipping_methods (
  id BIGSERIAL PRIMARY KEY, name VARCHAR(120) NOT NULL, description TEXT,
  base_cost BIGINT NOT NULL DEFAULT 0, free_shipping_threshold BIGINT,
  is_active BOOLEAN NOT NULL DEFAULT true, sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_shipping_methods_active_sort ON shipping_methods(is_active, sort_order);
ALTER TABLE orders ADD COLUMN IF NOT EXISTS shipping_method_id BIGINT;

-- =====================================================
--  فاز ۶ — باشگاه مشتریان
-- =====================================================
ALTER TABLE customer_accounts ADD COLUMN IF NOT EXISTS points_balance INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS point_transactions (
  id BIGSERIAL PRIMARY KEY, account_id BIGINT NOT NULL REFERENCES customer_accounts(id) ON DELETE CASCADE,
  amount INTEGER NOT NULL, type VARCHAR(10) NOT NULL CHECK (type IN ('earn','spend','adjust')),
  reason VARCHAR(200), order_id BIGINT REFERENCES orders(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_point_txn_account ON point_transactions(account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_point_txn_order ON point_transactions(order_id);

-- =====================================================
--  مقادیر پیش‌فرض
-- =====================================================
INSERT INTO store_settings(key, value) VALUES
  ('shop_name', 'زیبادوز'),
  ('phone', ''),
  ('eitaa_link', ''),
  ('footer_text', '© زیبادوز — همه حقوق محفوظ است'),
  ('about_text', 'زیبادوز با الهام از هنر دوخت و چرم، محصولاتی کاربردی و زیبا برای نگهداری و حمل وسایل شما عرضه می‌کند.'),
  ('shipping_fee', '150000'),
  ('min_order', '0'),
  ('shop_active', '1'),
  ('card_number', ''),
  ('card_owner', ''),
  ('points_enabled', '0'),
  ('points_per_toman', '1000'),
  ('points_min_redeem', '100'),
  ('points_value_toman', '100')
ON CONFLICT (key) DO NOTHING;

-- دسته‌بندی‌های پیش‌فرض فروشگاه کیف و چرم
INSERT INTO categories(name, slug, sort) VALUES
  ('کیف دستی',      'handbag',      1),
  ('کیف آرایشی',    'cosmetic-bag', 2),
  ('کیف مسافرتی',   'travel-bag',   3),
  ('کیف لقمه',      'lunch-bag',    4),
  ('نظم‌دهنده',      'organizer',    5),
  ('کیف پول',       'wallet',       6)
ON CONFLICT (slug) DO NOTHING;

-- =====================================================
--  ستون‌های مهاجرتی برای نسخه‌های قدیمی
-- =====================================================
ALTER TABLE customers ADD COLUMN IF NOT EXISTS account_id BIGINT
  REFERENCES customer_accounts(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS customers_account_id_idx ON customers(account_id);
