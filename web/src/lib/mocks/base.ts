import type {
  App,
  ConfigKey,
  Deployment,
  Invoice,
  Keyring,
  LogLine,
  Organization,
  TeeState,
  TierInfo,
  User
} from '../types';

export const currentUser: User = {
  id: 'usr_a39f2c11d4',
  display_name: 'lio',
  email: 'lio@enclave.dev'
};

export const orgs: Organization[] = [
  {
    id: 'org_7af3de91-2c11-04e2-9b7a',
    name: 'lio-a1b2c3d4',
    display_name: 'lio-a1b2c3d4',
    tier: 'Pro',
    is_personal: true,
    role: 'Owner'
  },
  {
    id: 'org_3c10aa42-1118-44de-1234',
    name: 'flux-labs',
    display_name: 'flux-labs',
    tier: 'Enterprise',
    is_personal: false,
    role: 'Admin'
  },
  {
    id: 'org_9d27c0fe-bbab-7110-aaaa',
    name: 'satoshi-cluster',
    display_name: 'satoshi-cluster',
    tier: 'Pro',
    is_personal: false,
    role: 'Member'
  }
];

export const activeOrg: Organization = orgs[0];

export const keyring: Keyring = {
  version: 3,
  org_id: orgs[0].id,
  signature: 'ed25519:9b88…2210',
  signed_by_fp: '8e5a…a1b2',
  signed_at: '2026-05-21T11:02:30Z',
  verified: true,
  members: [
    {
      pubkey: '8e5a1b4c9d273eaf…a1b2',
      fingerprint: '8e5a-1b4c-9d27-3eaf-…-a1b2',
      display_name: 'lio@enclave.dev',
      email_or_npub: 'primary identity · github oauth',
      role: 'Owner',
      added_at: '2025-11-04',
      is_self: true
    },
    {
      pubkey: '04a79e12bb88fc40…0ef1',
      fingerprint: '04a7-9e12-bb88-fc40-…-0ef1',
      display_name: 'ci-deployer @ flux',
      email_or_npub: 'CI key · created via cli',
      role: 'Owner',
      added_at: '2026-02-14',
      is_self: false
    },
    {
      pubkey: '12cdfffa77112200…8814',
      fingerprint: '12cd-fffa-7711-2200-…-8814',
      display_name: 'alice@studio.lab',
      email_or_npub: 'read-only collaborator',
      role: 'Member',
      added_at: '2026-04-09',
      is_self: false
    }
  ]
};

export const apps: App[] = [
  {
    id: 'app_chat_relay',
    org_id: orgs[0].id,
    name: 'chat-relay',
    domain: 'chat-relay.lio-a1b2c3d4.app.enclava.dev',
    namespace: 'ns-7af3de91',
    instance_id: 'inst-9d27c',
    status: 'Running',
    unlock_mode: 'Auto',
    signer_subject: 'lio@enclave.dev',
    signer_issuer: 'github',
    cpu_limit: '2 vCPU',
    memory_limit: '4 GiB',
    current_image_digest: 'sha256:a93f…ce21',
    cosign_verified: true,
    created_at: '2026-03-04T12:00:00Z'
  },
  {
    id: 'app_analytics',
    org_id: orgs[0].id,
    name: 'analytics-edge',
    domain: 'analytics-edge.lio-a1b2c3d4.app.enclava.dev',
    namespace: 'ns-7af3de91',
    instance_id: 'inst-7b12d',
    status: 'Creating',
    unlock_mode: 'Password',
    signer_subject: 'lio@enclave.dev',
    signer_issuer: 'github',
    cpu_limit: '1 vCPU',
    memory_limit: '2 GiB',
    current_image_digest: 'sha256:7b12…44de',
    cosign_verified: true,
    created_at: '2026-05-22T09:18:00Z'
  },
  {
    id: 'app_pg_vault',
    org_id: orgs[0].id,
    name: 'postgres-vault',
    domain: 'postgres-vault.lio-a1b2c3d4.app.enclava.dev',
    namespace: 'ns-7af3de91',
    instance_id: 'inst-e9c01',
    status: 'Running',
    unlock_mode: 'Password',
    signer_subject: 'lio@enclave.dev',
    signer_issuer: 'github',
    cpu_limit: '2 vCPU',
    memory_limit: '8 GiB',
    current_image_digest: 'sha256:e9c0…12ab',
    cosign_verified: true,
    created_at: '2026-04-10T08:11:00Z'
  },
  {
    id: 'app_sig_mailer',
    org_id: orgs[0].id,
    name: 'sig-mailer',
    domain: 'sig-mailer.lio-a1b2c3d4.app.enclava.dev',
    namespace: 'ns-7af3de91',
    instance_id: 'inst-bf089',
    status: 'Failed',
    unlock_mode: 'Auto',
    signer_subject: 'lio@enclave.dev',
    signer_issuer: 'github',
    cpu_limit: '1 vCPU',
    memory_limit: '1 GiB',
    current_image_digest: 'sha256:bf08…99ff',
    cosign_verified: false,
    created_at: '2026-05-12T14:20:00Z'
  }
];

export const deploymentsByApp: Record<string, Deployment[]> = {
  'chat-relay': [
    {
      id: 'dep_0042',
      app_name: 'chat-relay',
      image_digest: 'sha256:a93f…ce21',
      cosign_verified: true,
      trigger: 'Cli',
      triggered_by: 'lio@enclave.dev',
      status: 'Healthy',
      started_at: '2026-05-23T18:30:45Z',
      age: 'just now',
      manifest_hash: '9b88…2210',
      descriptor_id: 'desc_2c11d4',
      signer_fp: '8e5a…a1b2'
    },
    {
      id: 'dep_0041',
      app_name: 'chat-relay',
      image_digest: 'sha256:7b12…44de',
      cosign_verified: true,
      trigger: 'Cli',
      triggered_by: 'lio@enclave.dev',
      status: 'Applying',
      started_at: '2026-05-23T18:12:09Z',
      age: '22m'
    },
    {
      id: 'dep_0040',
      app_name: 'chat-relay',
      image_digest: 'sha256:e9c0…12ab',
      cosign_verified: true,
      trigger: 'Rollback',
      triggered_by: 'system',
      status: 'RolledBack',
      started_at: '2026-05-23T17:48:22Z',
      age: '52m'
    },
    {
      id: 'dep_0039',
      app_name: 'chat-relay',
      image_digest: 'sha256:bf08…99ff',
      cosign_verified: false,
      trigger: 'Cli',
      triggered_by: 'lio@enclave.dev',
      status: 'Failed',
      started_at: '2026-05-23T17:02:11Z',
      age: '1h 38m'
    },
    {
      id: 'dep_0038',
      app_name: 'chat-relay',
      image_digest: 'sha256:5d10…71aa',
      cosign_verified: true,
      trigger: 'Cli',
      triggered_by: 'lio@enclave.dev',
      status: 'Healthy',
      started_at: '2026-05-23T16:00:00Z',
      age: '2h 40m'
    }
  ]
};

export const recentDeployments: Deployment[] = [
  deploymentsByApp['chat-relay'][0],
  {
    id: 'dep_0099',
    app_name: 'analytics-edge',
    image_digest: 'sha256:7b12…44de',
    cosign_verified: true,
    trigger: 'Cli',
    triggered_by: 'lio@enclave.dev',
    status: 'Applying',
    started_at: '2026-05-23T18:12:09Z',
    age: '22m'
  },
  {
    id: 'dep_0098',
    app_name: 'postgres-vault',
    image_digest: 'sha256:e9c0…12ab',
    cosign_verified: true,
    trigger: 'Rollback',
    triggered_by: 'system',
    status: 'RolledBack',
    started_at: '2026-05-23T17:48:22Z',
    age: '52m'
  },
  {
    id: 'dep_0097',
    app_name: 'sig-mailer',
    image_digest: 'sha256:bf08…99ff',
    cosign_verified: false,
    trigger: 'Cli',
    triggered_by: 'lio@enclave.dev',
    status: 'Failed',
    started_at: '2026-05-23T17:02:11Z',
    age: '1h 38m'
  },
  deploymentsByApp['chat-relay'][4]
];

export const tiers: TierInfo[] = [
  {
    name: 'Free',
    price_sats: 0,
    apps: '1 app',
    cpu: '1 vCPU · 1 GiB RAM',
    memory: '5 GiB encrypted storage',
    storage: 'Public images only',
    features: ['1 app', '1 vCPU · 1 GiB RAM', '5 GiB encrypted storage', 'Public images only'],
    cta: 'CURRENT —'
  },
  {
    name: 'Pro',
    price_sats: 100_000,
    apps: '5 apps',
    cpu: '4 vCPU · 8 GiB RAM',
    memory: '50 GiB encrypted storage',
    storage: 'Custom signer identity',
    features: [
      '5 apps',
      '4 vCPU · 8 GiB RAM',
      '50 GiB encrypted storage',
      'Custom signer identity',
      'Email support'
    ],
    cta: 'PAY 100,000 SATS ›'
  },
  {
    name: 'Enterprise',
    price_sats: 500_000,
    apps: 'Unlimited apps',
    cpu: '32 vCPU · 64 GiB RAM',
    memory: '500 GiB encrypted storage',
    storage: 'Dedicated KBS policy bundle',
    features: [
      'Unlimited apps',
      '32 vCPU · 64 GiB RAM',
      '500 GiB encrypted storage',
      'Dedicated KBS policy bundle',
      'SLA · on-call'
    ],
    cta: 'CONTACT ›'
  }
];

export const pendingInvoice: Invoice = {
  reference: 'btcpay_2c11d4-9a82',
  amount_sats: 100_000,
  bolt11: 'lightning · lnbc1m1pjxk…6f7',
  expires_in: '14 m 28 s',
  period: '2026-05-23 → 2026-06-23',
  tier: 'Pro',
  status: 'Pending'
};

export const teeState: TeeState = {
  platform: 'AMD SEV-SNP',
  measurement: '8a2e…0c11',
  policy: 'strict-prod',
  last_attest: '24 s ago',
  kbs_reachable: true
};

export const configKeys: ConfigKey[] = [
  { name: 'DB_URL', sealed: true },
  { name: 'API_TOKEN', sealed: true },
  { name: 'JWT_SECRET', sealed: true },
  { name: 'PUB_URL', sealed: false }
];

export const sampleLogs: LogLine[] = [
  { ts: '18:30:45.011Z', level: 'I', message: 'kbs.attest ok measurement=8a2e…0c11 nonce=fd13…' },
  {
    ts: '18:30:45.022Z',
    level: 'I',
    message: 'sealed.config unlocked keys=DB_URL,API_TOKEN,JWT_SECRET'
  },
  { ts: '18:30:45.207Z', level: 'O', message: 'server listening 0.0.0.0:8080 tls=on' },
  { ts: '18:30:48.512Z', level: 'I', message: 'nostr.relay accepted conn from 178.42.11.9' },
  { ts: '18:31:02.114Z', level: 'W', message: 'ratelimit dropped npub=a93f…ce21 reason=burst' },
  { ts: '18:31:09.901Z', level: 'I', message: 'health.tee status=attested age=24s' },
  { ts: '18:31:14.300Z', level: 'O', message: 'backup.snap encrypted size=4.21MiB' }
];

export const deviceLogin = {
  code: 'ABCD-EFGH',
  client: 'enclava-cli v0.7.1 · darwin/arm64',
  source: 'studio-mbp · 89.142.211.5',
  scopes: 'apps:read · apps:deploy · orgs:read',
  expires_in: 'in 09 m 42 s'
};

export const dashboardKpis = {
  apps_deployed: 4,
  apps_max: 5,
  running_pods: 7,
  balance_sats: 214_820,
  renews_in_days: 11,
  keyring_version: 3,
  platform_release: 'v0.7.3-rc4',
  last_attestation: '2026-05-23T18:30:45Z'
};
