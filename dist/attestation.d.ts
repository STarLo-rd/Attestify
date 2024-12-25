import { Attest } from "./utils";
/**
 * Represents an attestation lifecycle, facilitating state transitions
 * and tracking relevant details like signatures and participants.
 */
export declare class Attestation {
    static HARDENED_OFFSET: number;
    /**
     * Unique identifier for the attestation.
     */
    attestationId: string;
    /**
     * Public key of the committer in extended format.
     */
    committerXpub: string;
    /**
     * Public key of the committee in extended format.
     */
    committeeXpub: string;
    /**
     * Public key of the committee specific to the attestation.
     */
    committer: string;
    /**
     * Public key of the committee specific to the attestation.
     */
    committee: string;
    /**
     * The BIP32 derivation path provided by the user.
     */
    derivationPath: string;
    /**
     * Current state of the attestation lifecycle.
     */
    commitmentState: Attest;
    /**
     * A JSON stringified representation of the data being attested.
     */
    attestationPayload: string;
    /**
     * Digital signature of the committee.
     */
    private committeeSignature;
    /**
     * Digital signature of the committer.
     */
    private committerSignature;
    /**
     * Digital signature of the committer for discharge.
     */
    private dischargeSignature;
    /**
     * Creates an instance of the Attestation class.
     *
     * @param attestationId - Unique identifier for the attestation.
     * @param committerXpub - Extended public key of the committer.
     * @param committeeXpub - Extended public key of the committee.
     * @param derivativePath - user's choice of HD derivative path  TODO
     */
    constructor(attestationId: string, committerXpub: string, committeeXpub: string, derivationPath: string, payload: string, committerSignature: string, committeeSignature: string, dischargeSignature: string, commitmentState: Attest);
    /**
     * Retrieves the committee's signature.
     *
     * @returns The digital signature of the committee.
     */
    getCommitteeSignature(): string;
    /**
     * Sets the committee's signature.
     *
     * @param signature - The digital signature to set.
     */
    setCommitteeSignature(signature: string): void;
    /**
     * Retrieves the committer's signature.
     *
     * @returns The digital signature of the committer.
     */
    getCommitterSignature(): string;
    /**
     * Sets the committer's signature.
     *
     * @param signature - The digital signature to set.
     */
    setCommitterSignature(signature: string): void;
    /**
     * Retrieves the discharge signature.
     *
     * @returns The digital signature for discharge.
     */
    getDischargeSignature(): string;
    /**
     * Sets the discharge signature.
     *
     * @param signature - The digital signature for discharge to set.
     */
    setDischargeSignature(signature: string): void;
    /**
      * Generates a deterministic index for HD path derivation from a string value
      * @param value - String value to generate index from
      * @returns A number between 0 and 2^31-1
      * @throws Error if the input value is empty or invalid
      */
    private generateHDPathIndex;
    /**
     * Derives a child public key from a parent extended public key using the attestation ID
     * @param parentXpub - Parent extended public key in base58 format
     * @param attestationId - Attestation ID to use for derivation
     * @returns Derived child public key in base58 format
     * @throws Error if derivation fails or inputs are invalid
     */
    deriveChildPubKey(parentXpub: string, attestationId: string): string;
    private verifySignature;
    /**
     * Initiates the attestation process.
     *
     * @throws Will throw an error if the attestation has already been initiated or the data provided in invalid.
     */
    initiateAttestation(): void;
    /**
     * Signs the attestation payload using the mnemonic.
     *
     * Derives a private key from the mnemonic using the adjusted derivation path
     * and signs the payload after hashing it with SHA-256.
     *
     * @throws Will throw an error if the derivation path is invalid, the private key
     * is unavailable, or the signing process fails.
     */
    sign(mnemonic: string): string;
    /**
     * Acknowledges the attestation, transitioning its state.
     *
     * @throws Will throw an error if the attestation is not in the "INITIATED" state or the data provided in invalid.
     */
    acknowledgeAttestation(): void;
    /**
     * Accepts the attestation, making it effective.
     *
     * @throws Will throw an error if the attestation is not in the "ACKNOWLEDGED" state or the data provided in invalid.
     */
    acceptAttestation(): void;
    /**
     * Discharges the attestation, marking it as completed.
     *
     * @throws Will throw an error if the attestation is not in the "EFFECTIVE" state or the data provided in invalid.
     */
    dischargeAttestation(): void;
}
