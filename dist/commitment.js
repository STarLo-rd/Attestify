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
exports.Commitment = void 0;
const bip39 = __importStar(require("bip39"));
const ecc = __importStar(require("tiny-secp256k1"));
const bip32_1 = require("bip32");
const crypto = __importStar(require("crypto"));
const users_1 = require("./users");
const bip32 = (0, bip32_1.BIP32Factory)(ecc);
class Commitment {
    constructor(creatorId, committerId, assetPayload) {
        this.commitmentId = ++Commitment.commitmentId;
        this.creatorId = creatorId;
        this.committerId = committerId;
        this.assetPayload = assetPayload;
        this.status = "INITIATED";
        this.committeeSignature = null;
        this.committerSignature = null;
        const creator = users_1.Users.findById(creatorId);
        const committer = users_1.Users.findById(committerId);
        if (!creator || !committer) {
            throw new Error("Both creator and committer must be valid users");
        }
        this.committeeXpubkey = this.deriveCommitmentXpubKey(creator.xpubkey, this.commitmentId);
        this.committerXpubkey = this.deriveCommitmentXpubKey(committer.xpubkey, this.commitmentId);
        Commitment.commitments.push(this);
    }
    deriveCommitmentXpubKey(parentXpub, commitmentId) {
        const parentNode = bip32.fromBase58(parentXpub);
        const childNode = parentNode.derive(commitmentId);
        return childNode.neutered().toBase58();
    }
    static listCommitments() {
        return Commitment.commitments.map((commitment) => ({
            commitmentId: commitment.commitmentId,
            creatorId: commitment.creatorId,
            committerId: commitment.committerId,
            status: commitment.status,
            assetPayload: commitment.assetPayload,
        }));
    }
    // In the signCommitment method, add null check for privateKey
    signCommitment(userId, mnemonic) {
        const user = users_1.Users.findById(userId);
        if (!user)
            throw new Error("User not found");
        const seed = bip39.mnemonicToSeedSync(mnemonic);
        const root = bip32.fromSeed(seed);
        const node = root.derivePath(`m/44'/0'/0'/${this.commitmentId}`);
        if (!node.privateKey) {
            throw new Error("Private key not available");
        }
        const hash = crypto
            .createHash("sha256")
            .update(JSON.stringify(this.assetPayload))
            .digest();
        const signature = ecc.sign(hash, node.privateKey);
        if (userId === this.creatorId) {
            this.committeeSignature = signature;
        }
        else if (userId === this.committerId) {
            this.committerSignature = signature;
        }
        else {
            throw new Error("User is neither the creator nor the committer");
        }
        if (this.committeeSignature && this.committerSignature) {
            this.status = "ACKNOWLEDGED";
        }
    }
    verifyCommitmentSignature(userId, signature) {
        let xpubkey;
        if (userId === this.creatorId) {
            xpubkey = this.committeeXpubkey;
        }
        else if (userId === this.committerId) {
            xpubkey = this.committerXpubkey;
        }
        else {
            throw new Error("User is neither the creator nor the committer");
        }
        const node = bip32.fromBase58(xpubkey);
        const hash = crypto
            .createHash("sha256")
            .update(JSON.stringify(this.assetPayload))
            .digest();
        return ecc.verify(hash, node.publicKey, signature);
    }
    dischargeCommitment() {
        if (!this.committeeSignature || !this.committerSignature) {
            throw new Error("Cannot discharge: Missing signatures");
        }
        const committeeSignatureValid = this.verifyCommitmentSignature(this.creatorId, this.committeeSignature);
        const committerSignatureValid = this.verifyCommitmentSignature(this.committerId, this.committerSignature);
        if (committeeSignatureValid && committerSignatureValid) {
            this.status = "DISCHARGED";
            return true;
        }
        else {
            throw new Error("Cannot discharge: Invalid signatures");
        }
    }
    getStatus() {
        return {
            commitmentId: this.commitmentId,
            creatorId: this.creatorId,
            committerId: this.committerId,
            status: this.status,
            assetPayload: this.assetPayload,
        };
    }
}
exports.Commitment = Commitment;
Commitment.commitments = [];
Commitment.commitmentId = 0;
