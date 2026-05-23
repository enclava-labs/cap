// Domain types mirror the Rust enums in crates/enclava-api/src/models.rs.
// Kept manually in sync until we wire to the API.

export type Tier = 'Free' | 'Pro' | 'Enterprise';
export type Role = 'Owner' | 'Admin' | 'Member';
export type AppStatus = 'Creating' | 'Running' | 'Stopped' | 'Failed' | 'Deleting';
export type DeployStatus =
  | 'Pending'
  | 'Applying'
  | 'Watching'
  | 'Healthy'
  | 'Failed'
  | 'RolledBack';
export type DeployTrigger = 'Cli' | 'Api' | 'Rollback';
export type UnlockMode = 'Auto' | 'Password';
export type Provider = 'Email' | 'Nostr' | 'GitHub' | 'Google';
export type PaymentStatus = 'Pending' | 'Confirmed' | 'Expired';
export type SubscriptionStatus = 'Active' | 'Expired' | 'GracePeriod';

export interface User {
  id: string;
  display_name: string;
  email: string;
}

export interface Organization {
  id: string;
  name: string;
  display_name: string;
  tier: Tier;
  is_personal: boolean;
  role: Role;
}

export interface KeyringMember {
  pubkey: string;
  fingerprint: string;
  display_name: string;
  email_or_npub: string;
  role: Role;
  added_at: string;
  is_self: boolean;
}

export interface Keyring {
  version: number;
  org_id: string;
  members: KeyringMember[];
  signature: string;
  signed_by_fp: string;
  signed_at: string;
  verified: boolean;
}

export interface App {
  id: string;
  org_id: string;
  name: string;
  domain: string;
  namespace: string;
  instance_id: string;
  status: AppStatus;
  unlock_mode: UnlockMode;
  signer_subject: string;
  signer_issuer: string;
  cpu_limit: string;
  memory_limit: string;
  current_image_digest: string;
  cosign_verified: boolean;
  created_at: string;
}

export interface Deployment {
  id: string;
  app_name: string;
  image_digest: string;
  cosign_verified: boolean;
  trigger: DeployTrigger;
  triggered_by: string;
  status: DeployStatus;
  started_at: string;
  age: string;
  manifest_hash?: string;
  descriptor_id?: string;
  signer_fp?: string;
}

export interface TierInfo {
  name: Tier;
  price_sats: number;
  apps: string;
  cpu: string;
  memory: string;
  storage: string;
  features: string[];
  cta: string;
}

export interface Invoice {
  reference: string;
  amount_sats: number;
  bolt11: string;
  expires_in: string;
  period: string;
  tier: Tier;
  status: PaymentStatus;
}

export interface TeeState {
  platform: string;
  measurement: string;
  policy: string;
  last_attest: string;
  kbs_reachable: boolean;
}

export interface ConfigKey {
  name: string;
  sealed: boolean;
}

export interface LogLine {
  ts: string;
  level: 'I' | 'W' | 'E' | 'O';
  message: string;
}
