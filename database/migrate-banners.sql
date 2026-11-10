-- =====================================================
--  افزودن جدول بنرهای تبلیغاتی به دیتابیس موجود
--  اجرا روی دیتابیس zibadoz که قبلاً ساخته شده:
--    psql -U postgres -d zibadoz -f database\migrate-banners.sql
--  این فایل فقط CREATE TABLE است و جدول‌های دیگر را تغییر نمی‌دهد.
--  اگر جدول banners از قبل باشد، نادیده گرفته می‌شود (IF NOT EXISTS).
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
