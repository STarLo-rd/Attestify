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
exports.SignatureService = void 0;
const ecc = __importStar(require("tiny-secp256k1"));
const crypto_1 = require("crypto");
const bip32_1 = require("bip32");
const utils_1 = require("./utils");
class SignatureService {
    /**
     * Verifies a signature against a payload and public key
     *
     * @param payload - The payload that was signed
     * @param publicKey - The public key to verify against (base58 xpub format)
     * @param signature - The signature to verify (hex format)
     * @returns boolean indicating if signature is valid
     */
    static verifySignature(payload, publicKey, signature) {
        try {
            const node = this.getPublicKeyNode(publicKey);
            const hash = this.hashPayload(payload);
            return ecc.verify(hash, node.publicKey, Buffer.from(signature, "hex"));
        }
        catch (error) {
            throw new utils_1.AttestationError(`Signature verification failed: ${error.message}`, "SIGNATURE_VERIFICATION_FAILED");
        }
    }
    /**
     * Creates a signature for a payload using a private key
     */
    static createSignature(payload, privateKey) {
        try {
            const hash = this.hashPayload(payload);
            const signature = ecc.sign(hash, privateKey);
            return Buffer.from(signature).toString("hex");
        }
        catch (error) {
            throw new utils_1.AttestationError(`Failed to create signature:  ${error.message}`, "SIGNATURE_CREATION_FAILED");
        }
    }
    /**
     * Creates a SHA-256 hash of the payload
     *
     * @param payload - Data to hash
     * @returns Buffer containing the hash
     */
    static hashPayload(payload) {
        return (0, crypto_1.createHash)("sha256").update(JSON.stringify(payload)).digest();
    }
    static getPublicKeyNode(publicKey) {
        try {
            const node = this.bip32.fromBase58(publicKey);
            if (!node.publicKey) {
                throw new utils_1.AttestationError("Invalid public key", "INVALID_PUBLIC_KEY");
            }
            return node;
        }
        catch (error) {
            throw new utils_1.AttestationError(`Invalid public key format: ${error.message}`, "INVALID_PUBLIC_KEY_FORMAT");
        }
    }
}
exports.SignatureService = SignatureService;
SignatureService.bip32 = (0, bip32_1.BIP32Factory)(ecc);
