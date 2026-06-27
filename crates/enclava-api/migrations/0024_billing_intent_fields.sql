-- Phase 10 full C11 billing fix.
--
-- The webhook must not trust mutable BTCPay metadata for tier/amount. These
-- fields are set from the authenticated API request at invoice creation and
-- are the only source used when a settlement webhook arrives.
--
-- Some hosted/PaaS databases were initialized after CAP's standalone billing
-- tables were removed, but before this historical migration was restored. Keep
-- the migration valid for both shapes of live database.
DO $$
BEGIN
    IF to_regclass('public.payments') IS NOT NULL THEN
        ALTER TABLE payments
            ADD COLUMN IF NOT EXISTS requested_tier text,
            ADD COLUMN IF NOT EXISTS expected_amount_sats bigint,
            ADD COLUMN IF NOT EXISTS purpose text;

        IF EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'payments'
              AND column_name = 'amount_sats'
        ) THEN
            UPDATE payments
            SET expected_amount_sats = amount_sats
            WHERE expected_amount_sats IS NULL;
        END IF;
    END IF;
END $$;
