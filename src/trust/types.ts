export type TrustStatus =
  | "active"
  | "suspended"
  | "revoked"
  | "expired"
  | "unknown";

export interface TrustKey {
  id: string;
  algorithm: "Ed25519";
  purpose: "root" | "anchor" | "delegation" | "governance" | "execution";
  publicKeyPem: string;
  createdAt: string;
  notBefore: string;
  notAfter?: string;
  status: TrustStatus;
  provenance: string;
}

export interface TrustRoot {
  id: string;
  subject: string;
  signingKeyId: string;
  issuedAt: string;
  status: TrustStatus;
  provenance: string;
}

export interface TrustAnchor {
  id: string;
  subject: string;
  rootId: string;
  signingKeyId: string;
  constraints: string[];
  issuedAt: string;
  expiresAt?: string;
  status: TrustStatus;
  provenance: string;
  signature: string;
}

export interface TrustDelegation {
  id: string;
  issuerAnchorId: string;
  delegateeId: string;
  signingKeyId: string;
  constraints: string[];
  issuedAt: string;
  expiresAt?: string;
  status: TrustStatus;
  provenance: string;
  signature: string;
}

export interface TrustCredential {
  id: string;
  subject: string;
  issuerDelegationId: string;
  claims: Record<string, string>;
  issuedAt: string;
  expiresAt?: string;
  status: TrustStatus;
  provenance: string;
  signature: string;
}

export interface TrustVerificationResult {
  valid: boolean;
  reason: string;
  chain: string[];
}

export interface TrustRevocation {
  objectType: "key" | "root" | "anchor" | "delegation" | "credential";
  objectId: string;
  revokedAt: string;
  reason: string;
  authority: string;
  provenance: string;
}
