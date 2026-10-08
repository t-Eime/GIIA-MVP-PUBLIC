export type EvidenceKind =
  | "event"
  | "credential"
  | "document"
  | "attestation"
  | "measurement"
  | "observation"
  | "other";

export interface Evidence {
  id: string;
  kind: EvidenceKind;
  subject: string;
  authorizationRequestId?: string;
  action: string;
  occurredAt: string;
  recordedAt: string;
  source: string;
  contentHash: string;
  previousEvidenceHash?: string;
  provenance: string;
  recordHash: string;
}
