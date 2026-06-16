-- Ensure idempotent webhook processing
CREATE UNIQUE INDEX IF NOT EXISTS "idx_unique_transaction_payment" 
  ON "public"."transactions" ("razorpay_payment_id") 
  WHERE ("razorpay_payment_id" IS NOT NULL AND "status" = 'completed');

CREATE UNIQUE INDEX IF NOT EXISTS "idx_unique_subscription_payment" 
  ON "public"."subscriptions" ("razorpay_payment_id") 
  WHERE ("razorpay_payment_id" IS NOT NULL);
