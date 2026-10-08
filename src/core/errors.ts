export class GIIAError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly details?: unknown,
  ) {
    super(message);
    this.name = "GIIAError";
  }
}

export function invariant(
  condition: boolean,
  code: string,
  message: string,
  details?: unknown,
): asserts condition {
  if (!condition) {
    throw new GIIAError(code, message, details);
  }
}
