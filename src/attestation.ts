import { Attest } from "./utils";

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
    private dischargeSignature: string = ""; // TODO getter and setter 

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

        // TODO : ID should be optional - generate a UUID if not provided
        this.attestationId = attestationId;

        // TODO : derive keys on the fly
        this.committer = "committer";
        this.committee = "committee";

        // TODO : verify signature before assigning
        this.committeeSignature = committeeSignature;
        this.committerSignature = committerSignature;

        // TODO : validate status
        this.commitmentState = commitmentState
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
