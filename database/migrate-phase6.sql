-- =====================================================
--  فاز ۶ — باشگاه مشتریان و امتیاز خرید
--  جدول: loyalty_points, point_transactions
--  ستون جدید customer_accounts: points_balance
-- =====================================================

ALTER TABLE customer_accounts ADD COLUMN IF NOT EXISTS points_balance INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS point_transactions (
  id BIGSERIAL PRIMARY KEY,
  account_id BIGINT NOT NULL REFERENCES customer_accounts(id) ON DELETE CASCADE,
  amount INTEGER NOT NULL,
  type VARCHAR(10) NOT NULL CHECK (type IN ('earn','spend','adjust')),
  reason VARCHAR(200),
  order_id BIGINT REFERENCES orders(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_point_txn_account ON point_transactions(account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_point_txn_order ON point_transactions(order_id);

-- تنظیمات پیش‌فرض باشگاه مشتریان در store_settings
INSERT INTO store_settings(key, value) VALUES
  ('points_enabled', '0'),
  ('points_per_toman', '1000'),
  ('points_min_redeem', '100'),
  ('points_value_toman', '100')
ON CONFLICT (key) DO NOTHING;
