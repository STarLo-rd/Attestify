import { Attest } from "./utils";
import { v4 as uuidv4 } from 'uuid';
import * as ecc from "tiny-secp256k1";
import { createHash } from 'crypto';
import { BIP32Factory } from "bip32";
const bip32 = BIP32Factory(ecc);

/**
 * Represents an attestation lifecycle, facilitating state transitions
 * and tracking relevant details like signatures and participants.
 */
export class Attestation {
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
     * Public key of the committer specific to the attestation.
     */
    public committer: string;

    /**
     * Public key of the committee specific to the attestation.
     */
    public committee: string;

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
        payload: string,
        committerSignature: string,
        committeeSignature: string,
        commitmentState: Attest
    ) {
        this.committerXpub = committerXpub;
        this.committeeXpub = committeeXpub;
        this.attestationPayload = payload;

        // Generate UUID if attestationId is not provided
        this.attestationId = attestationId || uuidv4();

        // Derive specific keys for this attestation
        this.committer = this.deriveChildPubKey(committerXpub, this.attestationId);
        this.committee = this.deriveChildPubKey(committeeXpub, this.attestationId);

        // TODO : verify signature before assigning
        this.committeeSignature = committeeSignature;
        this.committerSignature = committerSignature;

        // TODO : validate status
        this.commitmentState = commitmentState
    }

     /**
     * Converts a UUID into a deterministic BIP32 index.
     * The resulting index will be within the BIP32 hardened index range (0x80000000 to 0xFFFFFFFF)
     * 
     * @param uuid - The UUID to convert
     * @returns A deterministic number suitable for BIP32 derivation
     * @private
     */
     private uuidToDerivationIndex(uuid: string): number {
        // Remove hyphens and convert to Buffer
        const cleanUuid = Buffer.from(uuid.replace(/-/g, ''), 'hex');
        
        // Create SHA256 hash of UUID
        const hash = createHash('sha256').update(cleanUuid).digest();
        
        // Take the first 4 bytes and convert to number
        const index = hash.readUInt32BE(0);
        
        // Ensure the index is hardened (add 0x80000000)
        // This is standard practice for BIP32 key derivation
        return index | 0x80000000;
    }


     /**
     * Derives a child public key from a parent extended public key using the attestation ID.
     * 
     * @param parentXpub - The parent extended public key
     * @param attestationId - The attestation ID to use for derivation
     * @returns The derived child public key in base58 format
     * @private
     */
     private deriveChildPubKey(parentXpub: string, attestationId: string): string {
        try {
            // Convert UUID to derivation index
            const derivationIndex = this.uuidToDerivationIndex(attestationId);
            
            // Create parent node from xpub
            const parentNode = bip32.fromBase58(parentXpub);
            
            // Derive child node using calculated index
            const childNode = parentNode.derive(derivationIndex);
            
            // Return neutered (public-only) base58 string
            return childNode.neutered().toBase58();
        } catch (error) {
            throw new Error(`Failed to derive child public key: ${error}`);
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
     * Acknowledges the attestation, transitioning its state.
     * 
     * @throws Will throw an error if the attestation is not in the "INITIATED" state or the data provided in invalid.
     */
    acknowledgeAttestation(): void {
        // Validation
        // committee should call this
        // commitment status
        // validate committee signature
        if (this.commitmentState !== Attest.INITIATED) {
            throw new Error("Cannot acknowledge attestation. Invalid state.");
        }
        this.commitmentState = Attest.ACKNOWLEDGED;
    }

    /**
     * Accepts the attestation, making it effective.
     * 
     * @throws Will throw an error if the attestation is not in the "ACKNOWLEDGED" state or the data provided in invalid.
     */
    acceptAttestation(): void {
        // Validation
        // committer should call this
        // commitment status
        // validate committer signature 
        if (this.commitmentState !== Attest.ACKNOWLEDGED) {
            throw new Error("Cannot accept attestation. Invalid state.");
        }
        this.commitmentState = Attest.EFFECTIVE;
    }

    /**
     * Discharges the attestation, marking it as completed.
     * 
     * @throws Will throw an error if the attestation is not in the "EFFECTIVE" state or the data provided in invalid.
     */
    dischargeAttestation(): void {
        // Validation
        // committer should call this
        // commitment status
        // validate discharge signature 
        if (this.commitmentState !== Attest.EFFECTIVE) {
            throw new Error("Cannot discharge attestation. Invalid state.");
        }
        this.commitmentState = Attest.DISCHARGED;
    }
}
