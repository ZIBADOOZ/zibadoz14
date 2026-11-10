-- =====================================================
--  فاز ۴ — سفارش و ارسال
--  جدول: shipping_methods (روش‌های ارسال با شرایط)
--  ستون جدید orders: shipping_method_id
-- =====================================================

CREATE TABLE IF NOT EXISTS shipping_methods (
  id BIGSERIAL PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  description TEXT,
  base_cost BIGINT NOT NULL DEFAULT 0,
  free_shipping_threshold BIGINT,
  is_active BOOLEAN NOT NULL DEFAULT true,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_shipping_methods_active_sort ON shipping_methods(is_active, sort_order);

ALTER TABLE orders ADD COLUMN IF NOT EXISTS shipping_method_id BIGINT;

-- درج روش پیش‌فرض (پستی) اگر هیچ روشی وجود ندارد
INSERT INTO shipping_methods(name, description, base_cost, free_shipping_threshold, is_active, sort_order)
SELECT 'ارسال پستی', 'ارسال از طریق پست', 150000, NULL, true, 1
WHERE NOT EXISTS (SELECT 1 FROM shipping_methods);
