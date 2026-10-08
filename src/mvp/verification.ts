import type { MvpDecisionRecord } from "./types.js";
import { validateDecisionRecord } from "./validation.js";
import { verifyDecisionRecordSignature } from "./decision-record.js";

export function verifyDecisionRecord(
  value: unknown,
): { valid: boolean; reason: string } {
  try {
    const record = validateDecisionRecord(value);

    if (!verifyDecisionRecordSignature(record)) {
      return {
        valid: false,
        reason: "DECISION_SIGNATURE_INVALID",
      };
    }

    if (record.authoritative !== true) {
      return {
        valid: false,
        reason: "DECISION_NOT_AUTHORITATIVE",
      };
    }

    if (record.executionPermitted !== false) {
      return {
        valid: false,
        reason: "EXECUTION_AUTHORITY_FORBIDDEN",
      };
    }

    return {
      valid: true,
      reason: "DECISION_RECORD_VERIFIED",
    };
  } catch (error) {
    return {
      valid: false,
      reason:
        error instanceof Error
          ? error.message
          : "DECISION_VERIFICATION_FAILED",
    };
  }
}
