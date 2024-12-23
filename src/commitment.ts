import * as bip39 from "bip39";
import * as ecc from "tiny-secp256k1";
import { BIP32Factory } from "bip32";
import * as crypto from "crypto";
import { Users } from "./users";
import { AssetPayload, CommitmentStatus, CommitmentData } from "./types";

const bip32 = BIP32Factory(ecc);

export class Commitment {
  private static commitments: Commitment[] = [];
  private static commitmentId = 0;

  public commitmentId: number;
  public creatorId: number;
  public committerId: number;
  public assetPayload: AssetPayload;
  public status: CommitmentStatus;
  public committeeSignature: any;
  public committerSignature: any;

  private committerXpubkey: string;
  private committeeXpubkey: string;
  constructor(
    creatorId: number,
    committerId: number,
    assetPayload: AssetPayload
  ) {
    this.commitmentId = ++Commitment.commitmentId;
    this.creatorId = creatorId;
    this.committerId = committerId;
    this.assetPayload = assetPayload;
    this.status = "INITIATED";
    this.committeeSignature = null;
    this.committerSignature = null;

    const creator = Users.findById(creatorId);
    const committer = Users.findById(committerId);

    if (!creator || !committer) {
      throw new Error("Both creator and committer must be valid users");
    }

    this.committeeXpubkey = this.deriveCommitmentXpubKey(
      creator.xpubkey,
      this.commitmentId
    );
    this.committerXpubkey = this.deriveCommitmentXpubKey(
      committer.xpubkey,
      this.commitmentId
    );

    Commitment.commitments.push(this);
  }

  private deriveCommitmentXpubKey(
    parentXpub: string,
    commitmentId: number
  ): string {
    const parentNode = bip32.fromBase58(parentXpub);
    const childNode = parentNode.derive(commitmentId);
    return childNode.neutered().toBase58();
  }

  static listCommitments(): CommitmentData[] {
    return Commitment.commitments.map((commitment) => ({
      commitmentId: commitment.commitmentId,
      creatorId: commitment.creatorId,
      committerId: commitment.committerId,
      status: commitment.status,
      assetPayload: commitment.assetPayload,
    }));
  }

  // In the signCommitment method, add null check for privateKey
  signCommitment(userId: number, mnemonic: string): void {
    const user = Users.findById(userId);
    if (!user) throw new Error("User not found");

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
    } else if (userId === this.committerId) {
      this.committerSignature = signature;
    } else {
      throw new Error("User is neither the creator nor the committer");
    }

    if (this.committeeSignature && this.committerSignature) {
      this.status = "ACKNOWLEDGED";
    }
  }

  verifyCommitmentSignature(userId: number, signature: any): boolean {
    let xpubkey: any;
    if (userId === this.creatorId) {
      xpubkey = this.committeeXpubkey;
    } else if (userId === this.committerId) {
      xpubkey = this.committerXpubkey;
    } else {
      throw new Error("User is neither the creator nor the committer");
    }
    const node = bip32.fromBase58(xpubkey);

    const hash = crypto
      .createHash("sha256")
      .update(JSON.stringify(this.assetPayload))
      .digest();

    return ecc.verify(hash, node.publicKey, signature);
  }

  dischargeCommitment(): boolean {
    if (!this.committeeSignature || !this.committerSignature) {
      throw new Error("Cannot discharge: Missing signatures");
    }

    const committeeSignatureValid = this.verifyCommitmentSignature(
      this.creatorId,
      this.committeeSignature
    );
    const committerSignatureValid = this.verifyCommitmentSignature(
      this.committerId,
      this.committerSignature
    );

    if (committeeSignatureValid && committerSignatureValid) {
      this.status = "DISCHARGED";
      return true;
    } else {
      throw new Error("Cannot discharge: Invalid signatures");
    }
  }

  getStatus(): CommitmentData {
    return {
      commitmentId: this.commitmentId,
      creatorId: this.creatorId,
      committerId: this.committerId,
      status: this.status,
      assetPayload: this.assetPayload,
    };
  }
}
