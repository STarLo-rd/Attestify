"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.Attestation = void 0;
const utils_1 = require("./utils");
const uuid_1 = require("uuid");
const crypto_1 = require("crypto");
const bip39 = __importStar(require("bip39"));
const siganture_service_1 = require("./siganture-service");
const ecc = __importStar(require("tiny-secp256k1"));
const bip32_1 = require("bip32");
const bip32 = (0, bip32_1.BIP32Factory)(ecc);
/**
 * Represents an attestation lifecycle, facilitating state transitions
 * and tracking relevant details like signatures and participants.
 */
class Attestation {
    /**
     * Creates an instance of the Attestation class.
     *
     * @param attestationId - Unique identifier for the attestation.
     * @param committerXpub - Extended public key of the committer.
     * @param committeeXpub - Extended public key of the committee.
     * @param derivativePath - user's choice of HD derivative path  TODO
     */
    constructor(attestationId, committerXpub, committeeXpub, derivationPath, payload, committerSignature, committeeSignature, dischargeSignature, commitmentState) {
        /**
         * Digital signature of the committee.
         */
        this.committeeSignature = "";
        /**
         * Digital signature of the committer.
         */
        this.committerSignature = "";
        /**
         * Digital signature of the committer for discharge.
         */
        this.dischargeSignature = "";
        this.committerXpub = committerXpub;
        this.committeeXpub = committeeXpub;
        this.attestationPayload = payload;
        this.derivationPath = derivationPath;
        // Generate UUID if attestationId is not provided
        this.attestationId = attestationId || (0, uuid_1.v4)();
        // Derive specific keys for this attestation
        this.committer = this.deriveChildPubKey(committerXpub, this.attestationId);
        this.committee = this.deriveChildPubKey(committeeXpub, this.attestationId);
        if (committeeSignature) {
            if (!this.verifySignature("committer", committerSignature)) {
                throw new utils_1.AttestationError("Invalid committer signature", "INVALID_SIGNATURE");
            }
        }
        if (committeeSignature) {
            if (!this.verifySignature("committee", committeeSignature)) {
                throw new utils_1.AttestationError("Invalid committee signature", "INVALID_SIGNATURE");
            }
        }
        if (dischargeSignature) {
            if (!this.verifySignature("discharge", dischargeSignature)) {
                throw new utils_1.AttestationError("Invalid discharge signature", "INVALID_SIGNATURE");
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
    getCommitteeSignature() {
        return this.committeeSignature;
    }
    /**
     * Sets the committee's signature.
     *
     * @param signature - The digital signature to set.
     */
    setCommitteeSignature(signature) {
        this.committeeSignature = signature;
    }
    /**
     * Retrieves the committer's signature.
     *
     * @returns The digital signature of the committer.
     */
    getCommitterSignature() {
        return this.committerSignature;
    }
    /**
     * Sets the committer's signature.
     *
     * @param signature - The digital signature to set.
     */
    setCommitterSignature(signature) {
        this.committerSignature = signature;
    }
    /**
     * Retrieves the discharge signature.
     *
     * @returns The digital signature for discharge.
     */
    getDischargeSignature() {
        return this.dischargeSignature;
    }
    /**
     * Sets the discharge signature.
     *
     * @param signature - The digital signature for discharge to set.
     */
    setDischargeSignature(signature) {
        this.dischargeSignature = signature;
    }
    /**
      * Generates a deterministic index for HD path derivation from a string value
      * @param value - String value to generate index from
      * @returns A number between 0 and 2^31-1
      * @throws Error if the input value is empty or invalid
      */
    generateHDPathIndex(value) {
        if (!value || typeof value !== 'string') {
            throw new Error('Input value must be a non-empty string');
        }
        try {
            const hash = (0, crypto_1.createHash)('sha256')
                .update(value)
                .digest('hex');
            // Use first 8 bytes (16 hex chars) for better distribution
            const number = parseInt(hash.slice(0, 16), 16);
            // Ensure we get a valid non-hardened derivation index
            return number % Attestation.HARDENED_OFFSET;
        }
        catch (error) {
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
    deriveChildPubKey(parentXpub, attestationId) {
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
        }
        catch (error) {
            throw new Error(`Failed to derive child public key: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    verifySignature(type, signature) {
        const publicKey = type === "committee" ? this.committee : this.committer;
        return siganture_service_1.SignatureService.verifySignature(JSON.stringify(this.attestationPayload), publicKey, signature);
    }
    /**
     * Initiates the attestation process.
     *
     * @throws Will throw an error if the attestation has already been initiated or the data provided in invalid.
     */
    initiateAttestation() {
        if (this.commitmentState !== utils_1.Attest.INITIATED) {
            throw new Error("Attestation is already initiated.");
        }
        this.commitmentState = utils_1.Attest.INITIATED;
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
    sign(mnemonic) {
        try {
            const seed = bip39.mnemonicToSeedSync(mnemonic);
            const root = siganture_service_1.SignatureService.bip32.fromSeed(seed);
            const derivationIndex = this.generateHDPathIndex(this.attestationId);
            const fullDerivationPath = `${this.derivationPath}/${derivationIndex}`;
            const node = root.derivePath(fullDerivationPath);
            if (!node.privateKey) {
                throw new Error("Private key not available");
            }
            const privateKeyBuffer = Buffer.from(node.privateKey);
            const signature = siganture_service_1.SignatureService.createSignature(JSON.stringify(this.attestationPayload), privateKeyBuffer);
            return Buffer.from(signature).toString("hex");
        }
        catch (error) {
            throw new utils_1.AttestationError(`Failed to sign payload: ${error.message}`, "SIGNING_FAILED");
        }
    }
    /**
     * Acknowledges the attestation, transitioning its state.
     *
     * @throws Will throw an error if the attestation is not in the "INITIATED" state or the data provided in invalid.
     */
    acknowledgeAttestation() {
        // Validation
        // committee should call this
        // commitment status
        // validate committee signature
        if (this.commitmentState !== utils_1.Attest.INITIATED) {
            throw new Error("Cannot acknowledge attestation. Invalid state.");
        }
        this.commitmentState = utils_1.Attest.ACKNOWLEDGED;
    }
    /**
     * Accepts the attestation, making it effective.
     *
     * @throws Will throw an error if the attestation is not in the "ACKNOWLEDGED" state or the data provided in invalid.
     */
    acceptAttestation() {
        // Validation
        // committer should call this
        // commitment status
        // validate committer signature
        if (this.commitmentState !== utils_1.Attest.ACKNOWLEDGED) {
            throw new Error("Cannot accept attestation. Invalid state.");
        }
        this.commitmentState = utils_1.Attest.EFFECTIVE;
    }
    /**
     * Discharges the attestation, marking it as completed.
     *
     * @throws Will throw an error if the attestation is not in the "EFFECTIVE" state or the data provided in invalid.
     */
    dischargeAttestation() {
        // Validation
        // committer should call this
        // commitment status
        // validate discharge signature
        if (this.commitmentState !== utils_1.Attest.EFFECTIVE) {
            throw new Error("Cannot discharge attestation. Invalid state.");
        }
        this.commitmentState = utils_1.Attest.DISCHARGED;
    }
}
exports.Attestation = Attestation;
Attestation.HARDENED_OFFSET = 2 ** 31;
