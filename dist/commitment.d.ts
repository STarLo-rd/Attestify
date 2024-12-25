import { AssetPayload, CommitmentStatus, CommitmentData } from "./types";
export declare class Commitment {
    private static commitments;
    private static commitmentId;
    commitmentId: number;
    creatorId: number;
    committerId: number;
    assetPayload: AssetPayload;
    status: CommitmentStatus;
    committeeSignature: any;
    committerSignature: any;
    private committerXpubkey;
    private committeeXpubkey;
    constructor(creatorId: number, committerId: number, assetPayload: AssetPayload);
    private deriveCommitmentXpubKey;
    static listCommitments(): CommitmentData[];
    signCommitment(userId: number, mnemonic: string): void;
    verifyCommitmentSignature(userId: number, signature: any): boolean;
    dischargeCommitment(): boolean;
    getStatus(): CommitmentData;
}
