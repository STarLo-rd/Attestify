import { AssetPayload, CommitmentStatus, CommitmentData } from './types';
export declare class Commitment {
    private static commitments;
    private static commitmentId;
    commitmentId: number;
    creatorId: number;
    committerId: number;
    assetPayload: AssetPayload;
    status: CommitmentStatus;
    committeeSignature: Buffer | null;
    committerSignature: Buffer | null;
    private committeePublicKey;
    private committerPublicKey;
    private commitmentXpubkey;
    constructor(creatorId: number, committerId: number, assetPayload: AssetPayload);
    private derivePublicKey;
    private deriveCommitmentXpubKey;
    static listCommitments(): CommitmentData[];
    signCommitment(userId: number, mnemonic: string): void;
    verifyCommitmentSignature(userId: number, signature: Buffer): boolean;
    dischargeCommitment(): boolean;
    getStatus(): CommitmentData;
}
