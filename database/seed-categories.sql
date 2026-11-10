-- =====================================================
--  افزودن دسته‌بندی‌های پیش‌فرض به دیتابیس موجود
--  اجرا روی دیتابیس zibadoz که قبلاً ساخته شده:
--    psql -U postgres -d zibadoz -f database\seed-categories.sql
--  این فایل فقط INSERT است و جدول‌ها را تغییر نمی‌دهد.
--  اگر دسته‌بندی با همان slug از قبل باشد، نادیده گرفته می‌شود.
-- =====================================================

INSERT INTO categories(name, slug, sort) VALUES
  ('کیف دستی',      'handbag',      1),
  ('کیف آرایشی',    'cosmetic-bag', 2),
  ('کیف مسافرتی',   'travel-bag',   3),
  ('کیف لقمه',      'lunch-bag',    4),
  ('نظم‌دهنده',      'organizer',    5),
  ('کیف پول',       'wallet',       6)
ON CONFLICT (slug) DO NOTHING;
