import { Attest, AttestationError } from "./utils";
import { v4 as uuidv4 } from "uuid";
import { createHash } from "crypto";
import * as bip39 from "bip39";
import { SignatureService } from "./siganture-service";
import { ERROR_CODES, ERROR_MESSAGES } from "./constants";

const { ec: EC } = require("elliptic");
const ec = new EC("secp256k1");

/**
 * Represents an attestation lifecycle, facilitating state transitions
 * and tracking relevant details like signatures and participants.
 */
export class Attestation {
  /**
   * Unique identifier for the attestation.
   */
  public attestationId: string;

  static HARDENED_OFFSET = 0x80000000;

  /**
   * Public key of the committer in extended format.
   */
  public committerXpub: string;

  /**
   * Public key of the committee in extended format.
   */
  public committeeXpub: string;

  /**
   * Public key of the committer specific to the attestation.
   */
  public committer: string;

  /**
   * Public key of the committee specific to the attestation.
   */
  public committee: string;

  /**
   * The BIP32 derivation path provided by the user.
   */
  public derivationPath: string;

  /**
   * Current state of the attestation lifecycle.
   */
  public commitmentState: Attest;

  /**
   * A JSON stringified representation of the data being attested.
   */
  public attestationPayload: string;

  /**
   * Digital signature of the committee.
   */
  private committeeSignature: string = "";

  /**
   * Digital signature of the committer.
   */
  private committerSignature: string = "";

  /**
   * Digital signature of the committer for discharge.
   */
  private dischargeSignature: string = "";

  /**
   * Creates an instance of the Attestation class.
   *
   * @param attestationId - Unique identifier for the attestation.
   * @param committerXpub - Extended public key of the committer.
   * @param committeeXpub - Extended public key of the committee.
   * @param derivativePath - user's choice of HD derivative path  TODO
   */
  constructor(
    committerXpub: string,
    committeeXpub: string,
    derivationPath: string,
    payload: string,
    committerSignature: string,
    committeeSignature: string,
    dischargeSignature: string,
    commitmentState: Attest,
    attestationId?: string,
  ) {
    this.committerXpub = committerXpub;
    this.committeeXpub = committeeXpub;
    this.attestationPayload = payload;
    this.derivationPath = derivationPath;

    // Generate UUID if attestationId is not provided
    this.attestationId = attestationId || uuidv4();

    // Derive specific keys for this attestation
    this.committer = this.deriveChildPubKey(committerXpub, this.attestationId);
    this.committee = this.deriveChildPubKey(committeeXpub, this.attestationId);

    if (committeeSignature) {
      if (!this.verifySignature("committer", committerSignature)) {
        throw new AttestationError(
          ERROR_MESSAGES.INVALID_SIGNATURE("committer"),
          ERROR_CODES.INVALID_SIGNATURE
        );
      }
    }
    if (committeeSignature) {
      if (!this.verifySignature("committee", committeeSignature)) {
        throw new AttestationError(
          ERROR_MESSAGES.INVALID_SIGNATURE("committee"),
          ERROR_CODES.INVALID_SIGNATURE
        );
      }
    }
    if (dischargeSignature) {
      if (!this.verifySignature("discharge", dischargeSignature)) {
        throw new AttestationError(
          ERROR_MESSAGES.INVALID_SIGNATURE("discharge"),
          ERROR_CODES.INVALID_SIGNATURE
        );
      }
    }

    this.committeeSignature = committeeSignature;
    this.committerSignature = committerSignature;
    this.dischargeSignature = dischargeSignature;

    this.commitmentState = commitmentState;
  }

  /**
   * Generates a deterministic index for HD path derivation from a string value
   * @param value - String value to generate index from
   * @returns A number between 0 and 2^31-1
   * @throws Error if the input value is empty or invalid
   */
  private generateHDPathIndex(value: string): number {
    if (!value || typeof value !== "string") {
      throw new Error("Input value must be a non-empty string");
    }
    try {
      const hash = createHash("sha256").update(value).digest("hex");

      // Use first 8 bytes (16 hex chars) for better distribution
      const number = parseInt(hash.slice(0, 16), 16);

      // Ensure we get a valid non-hardened derivation index
      return number % Attestation.HARDENED_OFFSET;
    } catch (error) {
      throw new Error(
        `Failed to generate HD path index: ${
          error instanceof Error ? error.message : "Unknown error"
        }`
      );
    }
  }

  /**
   * Derives a child public key from a parent extended public key using the attestation ID
   * @param parentXpub - Parent extended public key in base58 format
   * @param attestationId - Attestation ID to use for derivation
   * @returns Derived child public key in base58 format
   * @throws Error if derivation fails or inputs are invalid
   */
  public deriveChildPubKey(parentXpub: string, attestationId: string): string {
    if (!parentXpub || typeof parentXpub !== "string") {
      throw new Error("Parent xpub must be a non-empty string");
    }
    if (!attestationId || typeof attestationId !== "string") {
      throw new Error("Attestation ID must be a non-empty string");
    }
    try {
      const derivationIndex = this.generateHDPathIndex(attestationId);
      const parentNode = SignatureService.bip32.fromBase58(parentXpub);

      if (!parentNode.isNeutered()) {
        throw new Error("Parent key must be a public key (xpub)");
      }

      // Derive child node using calculated index
      const childNode = parentNode.derive(derivationIndex);
      const key = ec.keyFromPublic(childNode.publicKey);

      const compressedPubKey = key.getPublic(true, "hex");
      return compressedPubKey;
    } catch (error) {
      throw new Error(
        `Failed to derive child public key: ${
          error instanceof Error ? error.message : "Unknown error"
        }`
      );
    }
  }

  /**
   * Retrieves the committee's signature.
   *
   * @returns The digital signature of the committee.
   */
  getCommitteeSignature(): string {
    return this.committeeSignature;
  }

  /**
   * Sets the committee's signature.
   *
   * @param signature - The digital signature to set.
   */
  setCommitteeSignature(signature: string): void {
    this.committeeSignature = signature;
  }

  /**
   * Retrieves the committer's signature.
   *
   * @returns The digital signature of the committer.
   */
  getCommitterSignature(): string {
    return this.committerSignature;
  }

  /**
   * Sets the committer's signature.
   *
   * @param signature - The digital signature to set.
   */
  setCommitterSignature(signature: string): void {
    this.committerSignature = signature;
  }

  /**
   * Retrieves the discharge signature.
   *
   * @returns The digital signature for discharge.
   */
  getDischargeSignature(): string {
    return this.dischargeSignature;
  }

  /**
   * Sets the discharge signature.
   *
   * @param signature - The digital signature for discharge to set.
   */
  setDischargeSignature(signature: string): void {
    this.dischargeSignature = signature;
  }

  private verifySignature(
    type: "committee" | "committer" | "discharge",
    signature: string
  ): boolean {
    const pubkey = type === "committee" ? this.committee : this.committer;

    const isValid = SignatureService.verifySignature(
      this.attestationPayload,
      pubkey,
      signature
    );
    return isValid;
  }

  /**
   * Signs the attestation payload using the mnemonic.
   *
   * Derives a private key from the mnemonic using the adjusted derivation path
   * and signs the payload after hashing it with SHA-256.
   *
   * @throws Will throw an error if the derivation path is invalid, the private key
   * is unavailable, or the signing process fails.
   */
  sign(mnemonic: string): string {
    try {
      const seed = bip39.mnemonicToSeedSync(mnemonic);
      const root = SignatureService.bip32.fromSeed(seed);
      const derivationIndex = this.generateHDPathIndex(this.attestationId);
      const pathNode = root.derivePath("m/44'/60'/0'/0");
      const derivedPrivateNode = pathNode.derive(derivationIndex);

      const privateKey = derivedPrivateNode.privateKey;
      const signature = SignatureService.createSignature(
        this.attestationPayload,
        privateKey
      );
      return signature;
    } catch (error) {
      throw new AttestationError(
        ERROR_MESSAGES.SIGNING_FAILED((error as Error).message),
        ERROR_CODES.SIGNING_FAILED
      );
    }
  }

  /**
   * Validates state transition requirements and performs the transition
   * @param currentState - Required current state
   * @param newState - State to transition to
   * @param signatureType - Type of signature to validate
   * @private
   */
  private validateStateTransition(
    currentState: Attest,
    newState: Attest,
    signatureType: "committee" | "committer" | "discharge"
  ): void {
    // Validate current state
    if (this.commitmentState !== currentState) {
      throw new AttestationError(
        ERROR_MESSAGES.INVALID_STATE(currentState, this.commitmentState),
        ERROR_CODES.INVALID_STATE
      );
    }

    const signature = this.getSignatureForType(signatureType);
    if (!signature) {
      throw new AttestationError(
        ERROR_MESSAGES.MISSING_SIGNATURE(signatureType, newState),
        ERROR_CODES.MISSING_SIGNATURE
      );
    }

    // Verify signature
    if (!this.verifySignature(signatureType, signature)) {
      throw new AttestationError(
        ERROR_MESSAGES.INVALID_SIGNATURE(signatureType),
        ERROR_CODES.INVALID_SIGNATURE
      );
    }
  }

  /**
   * Helper method to get signature based on type
   * @private
   */
  private getSignatureForType(
    type: "committee" | "committer" | "discharge"
  ): string {
    switch (type) {
      case "committee":
        return this.committeeSignature;
      case "committer":
        return this.committerSignature;
      case "discharge":
        return this.dischargeSignature;
      default:
        throw new AttestationError(
          ERROR_MESSAGES.INVALID_SIGNATURE_TYPE,
          ERROR_CODES.INVALID_SIGNATURE_TYPE
        );
    }
  }

  /**
   * Initiates the attestation process.
   *
   * @throws Will throw an error if the attestation has already been initiated or the data provided in invalid.
   */
  initiateAttestation(): void {
    if (this.commitmentState !== Attest.INITIATED) {
      throw new AttestationError(
        ERROR_MESSAGES.ALREADY_INITIATED,
        ERROR_CODES.INVALID_STATE
      );
    }

    this.commitmentState = Attest.INITIATED;
  }

  /**
   * Acknowledges the attestation, transitioning its state.
   *
   * @throws Will throw an error if the attestation is not in the "INITIATED" state or the data provided in invalid.
   */
  acknowledgeAttestation(): void {
    this.validateStateTransition(
      Attest.INITIATED,
      Attest.ACKNOWLEDGED,
      "committee"
    );
    this.commitmentState = Attest.ACKNOWLEDGED;
  }

  /**
   * Accepts the attestation, making it effective.
   *
   * @throws Will throw an error if the attestation is not in the "ACKNOWLEDGED" state or the data provided in invalid.
   */
  acceptAttestation(): void {
    this.validateStateTransition(
      Attest.ACKNOWLEDGED,
      Attest.EFFECTIVE,
      "committer"
    );
    this.commitmentState = Attest.EFFECTIVE;
  }

  /**
   * Discharges the attestation, marking it as completed.
   *
   * @throws Will throw an error if the attestation is not in the "EFFECTIVE" state or the data provided in invalid.
   */
  dischargeAttestation(): void {
    this.validateStateTransition(
      Attest.EFFECTIVE,
      Attest.DISCHARGED,
      "discharge"
    );
    this.commitmentState = Attest.DISCHARGED;
  }
}
