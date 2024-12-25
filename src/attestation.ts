import { Attest, AttestationError } from "./utils";
import { v4 as uuidv4 } from "uuid";
import { createHash } from "crypto";
import * as bip39 from "bip39";
import { SignatureService } from "./siganture-service";
import * as ecc from "tiny-secp256k1";
import { BIP32Factory } from "bip32";
const bip32 = BIP32Factory(ecc);

/**
 * Represents an attestation lifecycle, facilitating state transitions
 * and tracking relevant details like signatures and participants.
 */
export class Attestation {
    static HARDENED_OFFSET = 2 ** 31
    /**
     * Unique identifier for the attestation.
     */
    public attestationId: string;

    /**
     * Public key of the committer in extended format.
     */
    public committerXpub: string;

    /**
     * Public key of the committee in extended format.
     */
    public committeeXpub: string;


  /**
   * Public key of the committee specific to the attestation.
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
    attestationId: string,
    committerXpub: string,
    committeeXpub: string,
    derivationPath: string,
    payload: string,
    committerSignature: string,
    committeeSignature: string,
    dischargeSignature: string,
    commitmentState: Attest
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
          "Invalid committer signature",
          "INVALID_SIGNATURE"
        );
      }
    }
    if (committeeSignature) {
      if (!this.verifySignature("committee", committeeSignature)) {
        throw new AttestationError(
          "Invalid committee signature",
          "INVALID_SIGNATURE"
        );
      }
    }
    if (dischargeSignature) {
      if (!this.verifySignature("discharge", dischargeSignature)) {
        throw new AttestationError(
          "Invalid discharge signature",
          "INVALID_SIGNATURE"
        );
      }
    }

    this.committeeSignature = committeeSignature;
    this.committerSignature = committerSignature;
    this.dischargeSignature = dischargeSignature;

    // TODO : validate status
    this.commitmentState = commitmentState;
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

   /**
     * Generates a deterministic index for HD path derivation from a string value
     * @param value - String value to generate index from
     * @returns A number between 0 and 2^31-1
     * @throws Error if the input value is empty or invalid
     */
   private generateHDPathIndex(value: string): number {
    if (!value || typeof value !== 'string') {
        throw new Error('Input value must be a non-empty string');
    }

    try {
        const hash = createHash('sha256')
            .update(value)
            .digest('hex');
        
        // Use first 8 bytes (16 hex chars) for better distribution
        const number = parseInt(hash.slice(0, 16), 16);
        
        // Ensure we get a valid non-hardened derivation index
        return number % Attestation.HARDENED_OFFSET;
    } catch (error) {
        throw new Error(`Failed to generate HD path index: ${error instanceof Error ? error.message : 'Unknown error'}`);
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
    if (!parentXpub || typeof parentXpub !== 'string') {
        throw new Error('Parent xpub must be a non-empty string');
    }

    if (!attestationId || typeof attestationId !== 'string') {
        throw new Error('Attestation ID must be a non-empty string');
    }

    try {
        const derivationIndex = this.generateHDPathIndex(attestationId);
        const parentNode = bip32.fromBase58(parentXpub);
        
        if (!parentNode.isNeutered()) {
            throw new Error('Parent key must be a public key (xpub)');
        }
        
        
        // Derive child node using calculated index

        // Derive child node using calculated index
        const childNode = parentNode.derive(derivationIndex);
        return childNode.neutered().toBase58();
    } catch (error) {
        throw new Error(
            `Failed to derive child public key: ${error instanceof Error ? error.message : 'Unknown error'}`
        );
    }
}

  private verifySignature(
    type: "committee" | "committer" | "discharge",
    signature: string
  ): boolean {
    const publicKey = type === "committee" ? this.committee : this.committer;
    return SignatureService.verifySignature(
      JSON.stringify(this.attestationPayload),
      publicKey,
      signature
    );
  }

  /**
   * Initiates the attestation process.
   *
   * @throws Will throw an error if the attestation has already been initiated or the data provided in invalid.
   */
  initiateAttestation(): void {
    if (this.commitmentState !== Attest.INITIATED) {
      throw new Error("Attestation is already initiated.");
    }
    this.commitmentState = Attest.INITIATED;
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
      const fullDerivationPath = `${this.derivationPath}/${derivationIndex}`;
      const node = root.derivePath(fullDerivationPath);

      if (!node.privateKey) {
        throw new Error("Private key not available");
      }
      const privateKeyBuffer = Buffer.from(node.privateKey);
      const signature = SignatureService.createSignature(
        JSON.stringify(this.attestationPayload),
        privateKeyBuffer
      );

      return Buffer.from(signature).toString("hex");
    } catch (error) {
      throw new AttestationError(
        `Failed to sign payload: ${(error as Error).message}`,
        "SIGNING_FAILED"
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
        `Invalid state transition. Expected ${currentState}, got ${this.commitmentState}`,
        "INVALID_STATE"
      );
    }

    const signature = this.getSignatureForType(signatureType);
    if (!signature) {
      throw new AttestationError(
        `${signatureType} signature required for ${newState} state`,
        "MISSING_SIGNATURE"
      );
    }

    // Verify signature
    if (!this.verifySignature(signatureType, signature)) {
      throw new AttestationError(
        `Invalid ${signatureType} signature`,
        "INVALID_SIGNATURE"
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
          "Invalid signature type",
          "INVALID_SIGNATURE_TYPE"
        );
    }
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
