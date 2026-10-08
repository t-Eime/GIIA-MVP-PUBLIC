export type SystemState =
  | "ONLINE"
  | "DEGRADED"
  | "OFFLINE"
  | "COMPROMISED"
  | "RECOVERY";

export type RecoveryReason =
  | "CONNECTIVITY_LOSS"
  | "SERVICE_DEGRADATION"
  | "INTEGRITY_FAILURE"
  | "COMPROMISE_DETECTED"
  | "CRASH_RECOVERY"
  | "CORRUPTION_DETECTED"
  | "MANUAL_RECOVERY";

export type RecoveryAction =
  | "ENTER_DEGRADED"
  | "ENTER_OFFLINE"
  | "ENTER_COMPROMISED"
  | "BEGIN_RECOVERY"
  | "RESTORE_ONLINE"
  | "REMAIN_CONTAINED";

export interface StateTransition {
  id: string;
  from: SystemState;
  to: SystemState;
  reason: RecoveryReason;
  action: RecoveryAction;
  occurredAt: string;
  authorityId: string;
  evidenceRef: string;
  authorizationReceiptHash: string;
  previousTransitionHash?: string;
  transitionHash: string;
}

export interface RecoveryDecision {
  allowed: boolean;
  from: SystemState;
  to: SystemState;
  reason: string;
  requiresVerification: boolean;
}

export const CONSEQUENTIALLY_RESTRICTED_STATES: ReadonlySet<SystemState> =
  new Set(["COMPROMISED", "RECOVERY"]);
