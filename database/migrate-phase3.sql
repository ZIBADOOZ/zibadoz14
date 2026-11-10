-- =====================================================
--  فاز ۳ — فروش و بازاریابی
--  جداول: campaigns, product_bundles, bundle_items, coupon_usage, banner_stats
--  ستون‌های جدید coupons: max_discount, starts_at, per_customer_limit, first_order_only, category_id, product_ids, min_qty
--  ستون جدید products: related_ids (پیشنهاد دستی)
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
  id BIGSERIAL PRIMARY KEY,
  coupon_id BIGINT NOT NULL REFERENCES coupons(id) ON DELETE CASCADE,
  account_id BIGINT REFERENCES customer_accounts(id) ON DELETE SET NULL,
  order_id BIGINT REFERENCES orders(id) ON DELETE SET NULL,
  customer_mobile VARCHAR(20),
  used_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_coupon_usage_coupon ON coupon_usage(coupon_id);
CREATE INDEX IF NOT EXISTS idx_coupon_usage_account ON coupon_usage(account_id);
CREATE INDEX IF NOT EXISTS idx_coupon_usage_mobile ON coupon_usage(customer_mobile);

CREATE TABLE IF NOT EXISTS campaigns (
  id BIGSERIAL PRIMARY KEY,
  title VARCHAR(200) NOT NULL,
  description TEXT,
  image VARCHAR(200),
  discount_type VARCHAR(10) NOT NULL DEFAULT 'percent' CHECK (discount_type IN ('percent','fixed')),
  discount_value NUMERIC(14,2) NOT NULL,
  category_id BIGINT REFERENCES categories(id) ON DELETE SET NULL,
  product_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  starts_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ends_at TIMESTAMPTZ,
  is_active BOOLEAN NOT NULL DEFAULT true,
  show_on_homepage BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_campaigns_active_dates ON campaigns(is_active, starts_at, ends_at);
CREATE INDEX IF NOT EXISTS idx_campaigns_category ON campaigns(category_id);

CREATE TABLE IF NOT EXISTS product_bundles (
  id BIGSERIAL PRIMARY KEY,
  title VARCHAR(200) NOT NULL,
  description TEXT,
  image VARCHAR(200),
  bundle_price BIGINT NOT NULL,
  original_price BIGINT,
  is_active BOOLEAN NOT NULL DEFAULT true,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_bundles_active_sort ON product_bundles(is_active, sort_order);

CREATE TABLE IF NOT EXISTS bundle_items (
  id BIGSERIAL PRIMARY KEY,
  bundle_id BIGINT NOT NULL REFERENCES product_bundles(id) ON DELETE CASCADE,
  product_id BIGINT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  qty INTEGER NOT NULL DEFAULT 1 CHECK (qty >= 1 AND qty <= 100),
  UNIQUE(bundle_id, product_id)
);
CREATE INDEX IF NOT EXISTS idx_bundle_items_bundle ON bundle_items(bundle_id);
CREATE INDEX IF NOT EXISTS idx_bundle_items_product ON bundle_items(product_id);

CREATE TABLE IF NOT EXISTS banner_stats (
  id BIGSERIAL PRIMARY KEY,
  banner_id BIGINT NOT NULL REFERENCES banners(id) ON DELETE CASCADE,
  event_type VARCHAR(10) NOT NULL CHECK (event_type IN ('view','click')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_banner_stats_banner_type_time ON banner_stats(banner_id, event_type, created_at DESC);
