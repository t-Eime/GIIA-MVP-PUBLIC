export type EntityKind =
  | "human"
  | "organization"
  | "device"
  | "service"
  | "ai_system"
  | "machine"
  | "other";

export type IdentityStatus =
  | "active"
  | "suspended"
  | "revoked"
  | "recovery"
  | "unknown";

export interface Identity {
  id: string;
  kind: EntityKind;
  status: IdentityStatus;
  provenance: string;
  createdAt: string;
}
