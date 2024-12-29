import { mnemonicToSeedSync } from "bip39";
import * as ecc from "tiny-secp256k1";
import { BIP32Factory } from "bip32";
const bip32 = BIP32Factory(ecc);

export enum Attest {
  INITIATED = "INITIATED",
  ACKNOWLEDGED = "ACKNOWLEDGED",
  EFFECTIVE = "EFFECTIVE",
  DISCHARGED = "DISCHARGED",
}

export class AttestationError extends Error {
  constructor(message: string, public code: string) {
    super(message);
    this.name = "AttestationError";
  }
}

export const generateXpubkey = (mnemonic: string, derivationPath: string) => {
  const seed = mnemonicToSeedSync(mnemonic);
  const node = bip32.fromSeed(seed);
  const pathNode = node.derivePath(derivationPath);
  const xpub = pathNode.neutered().toBase58();
  return xpub;
};
