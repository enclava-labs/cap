import type { DeployStatus, AppStatus } from './types';

export function sats(n: number): string {
  return n.toLocaleString('en-US');
}

export function pad2(n: number): string {
  return n.toString().padStart(2, '0');
}

export function deployStatusLabel(s: DeployStatus): string {
  switch (s) {
    case 'RolledBack':
      return 'ROLLED BACK';
    default:
      return s.toUpperCase();
  }
}

export function appStatusLabel(s: AppStatus): string {
  return s.toUpperCase();
}

export function deployStatusBadgeClass(s: DeployStatus): string {
  switch (s) {
    case 'Healthy':
      return 'b-healthy';
    case 'Applying':
    case 'Watching':
      return 'b-applying';
    case 'Pending':
      return 'b-pending';
    case 'Failed':
      return 'b-failed';
    case 'RolledBack':
      return 'b-rolled';
    default:
      return 'b-stopped';
  }
}

export function appStatusBadgeClass(s: AppStatus): string {
  switch (s) {
    case 'Running':
      return 'b-healthy';
    case 'Creating':
      return 'b-applying';
    case 'Failed':
      return 'b-failed';
    case 'Deleting':
      return 'b-rolled';
    default:
      return 'b-stopped';
  }
}
