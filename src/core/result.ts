export type Decision = "ALLOW" | "DENY" | "DEFER";

export type Outcome =
  | "ALLOWED"
  | "DENIED"
  | "EVALUATED"
  | "EXECUTED"
  | "FAILED"
  | "DEFERRED"
  | "REJECTED";
