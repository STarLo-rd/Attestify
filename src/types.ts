export interface UserData {
  id: number;
  name: string;
  xpubkey: string;
}

export interface AssetPayload {
  assetName: string;
  quantity: number;
  unit: string;
}

export type CommitmentStatus = "INITIATED" | "ACKNOWLEDGED" | "DISCHARGED";

export interface CommitmentData {
  commitmentId: number;
  creatorId: number;
  committerId: number;
  status: CommitmentStatus;
  assetPayload: AssetPayload;
}

export interface SignatureData {
  payload: string;
  publicKey: string;
  signature: string;
}
