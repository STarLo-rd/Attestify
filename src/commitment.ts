import * as bip39 from 'bip39';
import * as ecc from 'tiny-secp256k1';
import { BIP32Factory } from 'bip32';
import * as crypto from 'crypto';
import { Users } from './users';
import { AssetPayload, CommitmentStatus, CommitmentData } from './types';

const bip32 = BIP32Factory(ecc);

export class Commitment {
  private static commitments: Commitment[] = [];
  private static commitmentId = 0;

  public commitmentId: number;
  public creatorId: number;
  public committerId: number;
  public assetPayload: AssetPayload;
  public status: CommitmentStatus;
  public committeeSignature: Buffer | null;
  public committerSignature: Buffer | null;

  private committeePublicKey: Buffer;
  private committerPublicKey: Buffer;

  private committerXpubkey: string;
  private committeeXpubkey:string;
  private commitmentXpubkey: string;

  constructor(creatorId: number, committerId: number, assetPayload: AssetPayload) {
    this.commitmentId = ++Commitment.commitmentId;
    this.creatorId = creatorId;
    this.committerId = committerId;
    this.assetPayload = assetPayload;
    this.status = 'INITIATED';
    this.committeeSignature = null;
    this.committerSignature = null;

    const creator = Users.findById(creatorId);
    const committer = Users.findById(committerId);

    if (!creator || !committer) {
      throw new Error("Both creator and committer must be valid users");
    }

    this.committeePublicKey = Buffer.from(this.derivePublicKey(creator.mnemonic));
    this.committerPublicKey = Buffer.from(this.derivePublicKey(committer.mnemonic));

    this.committeeXpubkey = this.deriveCommitmentXpubKey(creator.xpubkey, this.commitmentId);
    this.committerXpubkey = this.deriveCommitmentXpubKey(committer.xpubkey, this.commitmentId)
    this.commitmentXpubkey = this.deriveCommitmentXpubKey(creator.xpubkey, this.commitmentId);

    Commitment.commitments.push(this);
  }

  private derivePublicKey(mnemonic: string): Uint8Array {
    const seed = bip39.mnemonicToSeedSync(mnemonic);
    const node = bip32.fromSeed(seed);
    const derivedNode = node.derive(0).derive(0);
    return derivedNode.publicKey;
  }

  private deriveCommitmentXpubKey(xpubkey: string, commitmentId: number): string {
    const node = bip32.fromBase58(xpubkey); // Use xpubkey directly
    const commitmentPath = `m/44'/60'/0'/0/${commitmentId}`; // Derive commitment-specific path
    const commitmentNode = node.derivePath(commitmentPath); // Derive child key
    return commitmentNode.neutered().toBase58(); // Return derived xpubkey
  }

  private derivePublicKeyFromXpub(xpubkey: string, commitmentId: number): Uint8Array {
    const node = bip32.fromBase58(xpubkey); // Use xpubkey directly
    const commitmentPath = `m/44'/60'/0'/0/${commitmentId}`; // Derive public key path
    const derivedNode = node.derivePath(commitmentPath);
    return derivedNode.publicKey;
  }

  static listCommitments(): CommitmentData[] {
    return Commitment.commitments.map(commitment => ({
      commitmentId: commitment.commitmentId,
      creatorId: commitment.creatorId,
      committerId: commitment.committerId,
      status: commitment.status,
      assetPayload: commitment.assetPayload
    }));
  }

  signCommitment(userId: number, mnemonic: string): void {
    const user = Users.findById(userId);
    if (!user) throw new Error('User not found');

    const seed = bip39.mnemonicToSeedSync(mnemonic);
    const node = bip32.fromSeed(seed);

    const privateKeyNode = node.derive(0).derive(0);
    const privateKey = privateKeyNode.privateKey;
    if (!privateKey) throw new Error('Failed to derive private key');

    const hash = crypto.createHash('sha256')
      .update(JSON.stringify(this.assetPayload))
      .digest();

    const signature = Buffer.from(ecc.sign(hash, privateKey));

    if (userId === this.creatorId) {
      this.committeeSignature = signature;
    } else if (userId === this.committerId) {
      this.committerSignature = signature;
    } else {
      throw new Error('User is neither the creator nor the committer');
    }

    if (this.committeeSignature && this.committerSignature) {
      this.status = 'ACKNOWLEDGED';
    }
  }

  verifyCommitmentSignature(userId: number, signature: Buffer): boolean {
    let xpubkey: any;
    if (userId === this.creatorId) {
      xpubkey = this.committeeXpubkey;
    } else if (userId === this.committerId) {
      xpubkey = this.committeeXpubkey;
    } else {
      throw new Error('User is neither the creator nor the committer');
    }
    let publicKey = this.derivePublicKeyFromXpub(xpubkey, this.committerId);

    const hash = crypto.createHash('sha256')
      .update(JSON.stringify(this.assetPayload))
      .digest();
    
    return ecc.verify(hash, publicKey, signature);
  }

  dischargeCommitment(): boolean {
    if (!this.committeeSignature || !this.committerSignature) {
      throw new Error('Cannot discharge: Missing signatures');
    }

    const committeeSignatureValid = this.verifyCommitmentSignature(this.creatorId, this.committeeSignature);
    const committerSignatureValid = this.verifyCommitmentSignature(this.committerId, this.committerSignature);

    if (committeeSignatureValid && committerSignatureValid) {
      this.status = 'DISCHARGED';
      return true;
    } else {
      throw new Error('Cannot discharge: Invalid signatures');
    }
  }

  getStatus(): CommitmentData {
    return {
      commitmentId: this.commitmentId,
      creatorId: this.creatorId,
      committerId: this.committerId,
      status: this.status,
      assetPayload: this.assetPayload
    };
  }
}