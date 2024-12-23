import * as bip39 from "bip39";
import * as ecc from "tiny-secp256k1";
import { BIP32Factory } from "bip32";
import { UserData } from "./types";

const bip32 = BIP32Factory(ecc);

export class Users {
  private static userId = 0;
  private static users: Users[] = [];

  public id: number;
  public name: string;
  public mnemonic: string;
  public xpubkey: string;

  constructor(mnemonic: string, name: string) {
    this.id = ++Users.userId;
    this.name = name;
    this.mnemonic = mnemonic;
    this.xpubkey = this.deriveXpubKey(mnemonic);
    Users.users.push(this);
  }

  private deriveXpubKey(mnemonic: string): string {
    const seed = bip39.mnemonicToSeedSync(mnemonic);
    const root = bip32.fromSeed(seed);
    const path = "m/44'/0'/0'";
    const account = root.derivePath(path);
    return account.neutered().toBase58();
  }

  static listUsers(): UserData[] {
    return Users.users.map((user) => ({
      id: user.id,
      name: user.name,
      xpubkey: user.xpubkey,
    }));
  }

  static findById(id: number): Users | undefined {
    return Users.users.find((user) => user.id === id);
  }

  static generateMnemonic(): string {
    return bip39.generateMnemonic();
  }
}
