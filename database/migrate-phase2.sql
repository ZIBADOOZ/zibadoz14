-- =====================================================
--  فاز ۲ — زیرساخت قابلیت‌های مشتری
--  جداول: wishlist, product_reviews, product_questions, product_view_history
--  و ستون stock_threshold برای هشدار موجودی کم (فاز ۵ استفاده می‌شود)
--
--  اجرا روی دیتابیس zibadoz که قبلاً ساخته شده:
--    psql -U postgres -d zibadoz -f database\migrate-phase2.sql
--
--  این فایل فقط CREATE TABLE / ALTER TABLE است و جدول‌های دیگر را تغییر نمی‌دهد.
--  همه جداول IF NOT EXISTS دارند — اجرای دوباره بی‌خطر است.
-- =====================================================

-- ۱) علاقه‌مندی‌ها (Wishlist)
CREATE TABLE IF NOT EXISTS wishlist (
  id BIGSERIAL PRIMARY KEY,
  account_id BIGINT NOT NULL REFERENCES customer_accounts(id) ON DELETE CASCADE,
  product_id BIGINT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(account_id, product_id)
);
CREATE INDEX IF NOT EXISTS idx_wishlist_account ON wishlist(account_id);
CREATE INDEX IF NOT EXISTS idx_wishlist_product ON wishlist(product_id);

-- ۲) نظرات و امتیازدهی محصولات
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

-- ۳) پرسش و پاسخ محصولات
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

-- ۴) تاریخچه بازدید محصولات (برای کاربران واردشده)
CREATE TABLE IF NOT EXISTS product_view_history (
  id BIGSERIAL PRIMARY KEY,
  account_id BIGINT NOT NULL REFERENCES customer_accounts(id) ON DELETE CASCADE,
  product_id BIGINT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  viewed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_view_history_account_time ON product_view_history(account_id, viewed_at DESC);
CREATE INDEX IF NOT EXISTS idx_view_history_product ON product_view_history(product_id);

-- ۵) هشدار موجودی کم — ستون stock_threshold روی products
ALTER TABLE products ADD COLUMN IF NOT EXISTS stock_threshold INTEGER NOT NULL DEFAULT 5;

-- =====================================================
--  توجه: تنوع محصول با JSONB پیشرفته
--  در فاز ۲، فیلدهای colors و sizes از آرایه ساده به آرایه‌ای از اشیاء ارتقا می‌یابند:
--    colors: [{name:"قرمز", stock:5, price_override:null}, ...]
--    sizes:  [{name:"M",  stock:3, price_override:50000}, ...]
--  این تغییر در سطح برنامه خوانده می‌شود؛ migration روی داده‌های قبلی تأثیری ندارد
--  چون برنامه هر دو فرمت (string ساده و object) را هنگام خواندن پشتیبانی می‌کند.
-- =====================================================
