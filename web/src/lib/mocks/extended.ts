import type { Deployment } from '../types';
import { recentDeployments } from './base';

export const allDeployments: Deployment[] = [
  ...recentDeployments,
  {
    id: 'dep_0037',
    app_name: 'analytics-edge',
    image_digest: 'sha256:8a91…44de',
    cosign_verified: true,
    trigger: 'Cli',
    triggered_by: 'ci-deployer@flux',
    status: 'Healthy',
    started_at: '2026-05-23T14:30:11Z',
    age: '4h 4m'
  },
  {
    id: 'dep_0036',
    app_name: 'postgres-vault',
    image_digest: 'sha256:c011…12ab',
    cosign_verified: true,
    trigger: 'Cli',
    triggered_by: 'lio@enclave.dev',
    status: 'Healthy',
    started_at: '2026-05-23T11:22:08Z',
    age: '7h 12m'
  },
  {
    id: 'dep_0035',
    app_name: 'chat-relay',
    image_digest: 'sha256:11aa…ce21',
    cosign_verified: true,
    trigger: 'Cli',
    triggered_by: 'lio@enclave.dev',
    status: 'Healthy',
    started_at: '2026-05-22T19:08:00Z',
    age: '23h ago'
  },
  {
    id: 'dep_0034',
    app_name: 'sig-mailer',
    image_digest: 'sha256:0099…77ff',
    cosign_verified: true,
    trigger: 'Cli',
    triggered_by: 'lio@enclave.dev',
    status: 'Healthy',
    started_at: '2026-05-22T15:42:30Z',
    age: '1d ago'
  },
  {
    id: 'dep_0033',
    app_name: 'analytics-edge',
    image_digest: 'sha256:7791…22ab',
    cosign_verified: true,
    trigger: 'Api',
    triggered_by: 'api-key:ci-…',
    status: 'Healthy',
    started_at: '2026-05-21T18:12:09Z',
    age: '2d ago'
  }
];

export interface AuditEvent {
  id: string;
  ts: string;
  age: string;
  actor: string;
  action: string;
  target: string;
  category: 'deploy' | 'keyring' | 'member' | 'billing' | 'auth';
}

export const auditEvents: AuditEvent[] = [
  {
    id: 'evt_8801',
    ts: '2026-05-23T18:30:45Z',
    age: 'just now',
    actor: 'lio@enclave.dev',
    action: 'deployed',
    target: 'chat-relay · #dep_0042',
    category: 'deploy'
  },
  {
    id: 'evt_8800',
    ts: '2026-05-23T18:12:09Z',
    age: '22m ago',
    actor: 'lio@enclave.dev',
    action: 'deployed',
    target: 'analytics-edge · #dep_0041',
    category: 'deploy'
  },
  {
    id: 'evt_8799',
    ts: '2026-05-23T17:48:22Z',
    age: '52m ago',
    actor: 'system',
    action: 'rolled back',
    target: 'postgres-vault · #dep_0040',
    category: 'deploy'
  },
  {
    id: 'evt_8798',
    ts: '2026-05-23T17:02:11Z',
    age: '1h 38m ago',
    actor: 'lio@enclave.dev',
    action: 'deploy failed',
    target: 'sig-mailer · cosign verification failed',
    category: 'deploy'
  },
  {
    id: 'evt_8797',
    ts: '2026-05-23T08:14:00Z',
    age: '10h ago',
    actor: 'lio@enclave.dev',
    action: 'CLI session approved',
    target: 'studio-mbp · 89.142.211.5',
    category: 'auth'
  },
  {
    id: 'evt_8796',
    ts: '2026-05-21T11:02:30Z',
    age: '2d ago',
    actor: 'lio@enclave.dev',
    action: 'rotated keyring',
    target: 'v2 → v3 · added ci-deployer@flux',
    category: 'keyring'
  },
  {
    id: 'evt_8795',
    ts: '2026-04-09T13:45:00Z',
    age: '6w ago',
    actor: 'lio@enclave.dev',
    action: 'invited member',
    target: 'alice@studio.lab · role=member',
    category: 'member'
  },
  {
    id: 'evt_8794',
    ts: '2026-04-23T00:00:00Z',
    age: '4w ago',
    actor: 'system',
    action: 'subscription renewed',
    target: 'Pro · 100,000 sats · btcpay_2c10aa-9a82',
    category: 'billing'
  },
  {
    id: 'evt_8793',
    ts: '2026-02-14T09:18:00Z',
    age: '14w ago',
    actor: 'lio@enclave.dev',
    action: 'tier upgraded',
    target: 'Free → Pro',
    category: 'billing'
  },
  {
    id: 'evt_8792',
    ts: '2025-11-04T16:00:00Z',
    age: '29w ago',
    actor: 'lio@enclave.dev',
    action: 'org created',
    target: 'lio-a1b2c3d4 (personal)',
    category: 'member'
  }
];

export interface Payment {
  id: string;
  ts: string;
  amount_sats: number;
  period: string;
  status: 'Confirmed' | 'Pending' | 'Expired';
  invoice_ref: string;
}

export const payments: Payment[] = [
  {
    id: 'pay_2c11d4',
    ts: '2026-04-23T11:02:30Z',
    amount_sats: 100_000,
    period: 'Apr 2026',
    status: 'Confirmed',
    invoice_ref: 'btcpay_2c10aa-9a82'
  },
  {
    id: 'pay_2b9921',
    ts: '2026-03-23T11:02:30Z',
    amount_sats: 100_000,
    period: 'Mar 2026',
    status: 'Confirmed',
    invoice_ref: 'btcpay_1d3411-7c44'
  },
  {
    id: 'pay_2a4477',
    ts: '2026-02-14T09:18:00Z',
    amount_sats: 100_000,
    period: 'Feb 2026',
    status: 'Confirmed',
    invoice_ref: 'btcpay_001244-feab'
  }
];

export interface RecoveryState {
  seed_present: boolean;
  fingerprint: string;
  derived_at: string;
  last_backup_at: string | null;
  backup_kdf: string;
  derived_keys: { label: string; kind: string; fingerprint: string }[];
}

export const recoveryState: RecoveryState = {
  seed_present: true,
  fingerprint: '8e5a…a1b2',
  derived_at: '2025-11-04T16:00:00Z',
  last_backup_at: '2026-02-14T09:20:00Z',
  backup_kdf: 'argon2id · 19456 KiB · 2 iter',
  derived_keys: [
    {
      label: 'org-owner/lio-a1b2c3d4',
      kind: 'Ed25519 · org owner',
      fingerprint: '8e5a…a1b2'
    },
    {
      label: 'app-bootstrap/lio-a1b2c3d4/chat-relay',
      kind: 'Ed25519 · app bootstrap',
      fingerprint: '7c10…44de'
    },
    {
      label: 'app-bootstrap/lio-a1b2c3d4/analytics-edge',
      kind: 'Ed25519 · app bootstrap',
      fingerprint: 'b021…9a82'
    },
    {
      label: 'app-bootstrap/lio-a1b2c3d4/postgres-vault',
      kind: 'Ed25519 · app bootstrap',
      fingerprint: 'e9c0…12ab'
    }
  ]
};

export const orgSettings = {
  display_name: 'lio-a1b2c3d4',
  custom_domain: 'app.lio.dev',
  custom_domain_status: 'pending-txt' as 'verified' | 'pending-txt' | 'unset',
  default_signer_subject: 'lio@enclave.dev',
  default_signer_issuer: 'github',
  cluster_region: 'eu-west-1 · enclava-public',
  created_at: '2025-11-04T16:00:00Z'
};
