-- Phase 10 full C11 billing fix.
--
-- The webhook must not trust mutable BTCPay metadata for tier/amount. These
-- fields are set from the authenticated API request at invoice creation and
-- are the only source used when a settlement webhook arrives.
ALTER TABLE payments
    ADD COLUMN requested_tier text,
    ADD COLUMN expected_amount_sats bigint,
    ADD COLUMN purpose text;

UPDATE payments
SET expected_amount_sats = amount_sats
WHERE expected_amount_sats IS NULL;
