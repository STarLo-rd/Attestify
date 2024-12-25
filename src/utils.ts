export enum Attest {
    INITIATED = 'INITIATED',
    ACKNOWLEDGED = "ACKNOWLEDGED",
    EFFECTIVE = "EFFECTIVE",
    DISCHARGED = "DISCHARGED"
}

export class AttestationError extends Error {
    constructor(message: string, public code: string) {
      super(message);
      this.name = 'AttestationError';
    }
  }