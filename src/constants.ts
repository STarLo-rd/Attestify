export const ERROR_MESSAGES = {
  // State transition errors
  INVALID_STATE: (expected: string, got: string) =>
    `Invalid state transition. Expected ${expected}, got ${got}`,
  ALREADY_INITIATED: "Attestation is already initiated",

  // Signature errors
  MISSING_SIGNATURE: (type: string, state: string) =>
    `${type} signature required for ${state} state`,
  INVALID_SIGNATURE: (type: string) => `Invalid ${type} signature`,
  INVALID_SIGNATURE_TYPE: "Invalid signature type",
  SIGNATURE_VERIFICATION_FAILED: (details: string) =>
    `Signature verification failed: ${details}`,
  SIGNATURE_CREATION_FAILED: (details: string) =>
    `Failed to create signature: ${details}`,

  // Key errors
  INVALID_PUBLIC_KEY: "Invalid public key",
  INVALID_PUBLIC_KEY_FORMAT: (details: string) =>
    `Invalid public key format: ${details}`,
  PRIVATE_KEY_UNAVAILABLE: "Private key not available",

  // Derivation errors
  DERIVATION_FAILED: (details: string) =>
    `Failed to derive child public key: ${details}`,

  // Signing errors
  SIGNING_FAILED: (details: string) => `Failed to sign payload: ${details}`,
} as const;

export const ERROR_CODES = {
  INVALID_STATE: "INVALID_STATE",
  MISSING_SIGNATURE: "MISSING_SIGNATURE",
  INVALID_SIGNATURE: "INVALID_SIGNATURE",
  INVALID_SIGNATURE_TYPE: "INVALID_SIGNATURE_TYPE",
  SIGNATURE_VERIFICATION_FAILED: "SIGNATURE_VERIFICATION_FAILED",
  SIGNATURE_CREATION_FAILED: "SIGNATURE_CREATION_FAILED",
  INVALID_PUBLIC_KEY: "INVALID_PUBLIC_KEY",
  INVALID_PUBLIC_KEY_FORMAT: "INVALID_PUBLIC_KEY_FORMAT",
  DERIVATION_FAILED: "DERIVATION_FAILED",
  SIGNING_FAILED: "SIGNING_FAILED",
} as const;
