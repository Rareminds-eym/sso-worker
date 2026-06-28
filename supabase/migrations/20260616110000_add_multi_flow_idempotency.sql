-- Ensure idempotent webhook processing for Addons and Bundles
CREATE UNIQUE INDEX IF NOT EXISTS "idx_unique_addon_payment" 
  ON "public"."addon_purchases" ("razorpay_payment_id") 
  WHERE ("razorpay_payment_id" IS NOT NULL);

CREATE UNIQUE INDEX IF NOT EXISTS "idx_unique_bundle_payment" 
  ON "public"."bundle_purchases" ("razorpay_payment_id") 
  WHERE ("razorpay_payment_id" IS NOT NULL);
