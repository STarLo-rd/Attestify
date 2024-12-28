import * as ecc from "tiny-secp256k1";
import { createHash } from "crypto";
import { BIP32Factory, BIP32Interface } from "bip32";
import { AttestationError } from "./utils";
const { ec: EC } = require("elliptic");
const ec = new EC("secp256k1");
import { ERROR_CODES, ERROR_MESSAGES } from "./constants";

export class SignatureService {
  public static readonly bip32 = BIP32Factory(ecc);

  /**
   * Verifies a signature against a payload and public key
   *
   * @param payload - The payload that was signed
   * @param publicKey - The public key to verify against (base58 xpub format)
   * @param signature - The signature to verify (hex format)
   * @returns boolean indicating if signature is valid
   */
  static verifySignature(
    payload: string,
    publicKey: string,
    signature: string
  ): boolean {
    try {
      const hash = this.hashPayload(payload);
      const pubPoint = ec.keyFromPublic(publicKey, "hex");
      const isValid = pubPoint.verify(hash, signature);
      return isValid;
    } catch (error) {
      throw new AttestationError(
        ERROR_MESSAGES.SIGNATURE_VERIFICATION_FAILED((error as Error).message),
        ERROR_CODES.SIGNATURE_VERIFICATION_FAILED
      );
    }
  }

  /**
   * Creates a signature for a payload using a private key
   */
  public static createSignature(payload: string, privateKey: any): string {
    try {
      const hash = this.hashPayload(payload);
      const keyPair = ec.keyFromPrivate(privateKey);
      const signature = keyPair.sign(hash);
      console.log("signature", signature);
      return signature;
    } catch (error) {
      throw new AttestationError(
        ERROR_MESSAGES.SIGNATURE_CREATION_FAILED((error as Error).message),
        ERROR_CODES.SIGNATURE_CREATION_FAILED
      );
    }
  }

  /**
   * Creates a SHA-256 hash of the payload
   *
   * @param payload - Data to hash
   * @returns string containing the hash
   */
  static hashPayload(payload: string): string {
    return createHash("sha256").update(payload).digest("hex");
  }

  private static getPublicKeyNode(publicKey: string): BIP32Interface {
    try {
      const node = this.bip32.fromBase58(publicKey);
      if (!node.publicKey) {
        throw new AttestationError(
          ERROR_MESSAGES.INVALID_PUBLIC_KEY,
          ERROR_CODES.INVALID_PUBLIC_KEY
        );
      }
      return node;
    } catch (error) {
      throw new AttestationError(
        ERROR_MESSAGES.INVALID_PUBLIC_KEY_FORMAT((error as Error).message),
        ERROR_CODES.INVALID_PUBLIC_KEY_FORMAT
      );
    }
  }
}
