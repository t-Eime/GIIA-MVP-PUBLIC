export type AuthorityStatus =
  | "active"
  | "suspended"
  | "revoked"
  | "expired"
  | "unknown";

export interface Authority {
  id: string;
  holderIdentityId: string;
  /**
   * Trust credential that independently supports this authority.
   * Authority is not self-authenticating.
   */
  trustCredentialId: string;
  scope: string[];
  issuedAt: string;
  expiresAt?: string;
  status: AuthorityStatus;
  issuer: string;
  provenance: string;
}
