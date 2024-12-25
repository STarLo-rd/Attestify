export declare enum Attest {
    INITIATED = "INITIATED",
    ACKNOWLEDGED = "ACKNOWLEDGED",
    EFFECTIVE = "EFFECTIVE",
    DISCHARGED = "DISCHARGED"
}
export declare class AttestationError extends Error {
    code: string;
    constructor(message: string, code: string);
}
