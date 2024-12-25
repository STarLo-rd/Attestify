import * as ecc from "tiny-secp256k1";
import { createHash } from "crypto";
import { BIP32Factory, BIP32Interface } from "bip32";
import { AttestationError } from "./utils";

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
      const node = this.getPublicKeyNode(publicKey);
      const hash = this.hashPayload(payload);
      return ecc.verify(hash, node.publicKey, Buffer.from(signature, "hex"));
    } catch (error) {
      throw new AttestationError(
        `Signature verification failed: ${(error as Error).message}`,
        "SIGNATURE_VERIFICATION_FAILED"
      );
    }
  }

  /**
   * Creates a signature for a payload using a private key
   */
  public static createSignature(payload: string, privateKey: Buffer): string {
    try {
      const hash = this.hashPayload(payload);
      const signature = ecc.sign(hash, privateKey);
      return Buffer.from(signature).toString("hex");
    } catch (error) {
      throw new AttestationError(
        `Failed to create signature:  ${(error as Error).message}`,
        "SIGNATURE_CREATION_FAILED"
      );
    }
  }

  /**
   * Creates a SHA-256 hash of the payload
   *
   * @param payload - Data to hash
   * @returns Buffer containing the hash
   */
  static hashPayload(payload: string): Buffer {
    return createHash("sha256").update(JSON.stringify(payload)).digest();
  }

  private static getPublicKeyNode(publicKey: string): BIP32Interface {
    try {
      const node = this.bip32.fromBase58(publicKey);
      if (!node.publicKey) {
        throw new AttestationError("Invalid public key", "INVALID_PUBLIC_KEY");
      }
      return node;
    } catch (error) {
      throw new AttestationError(
        `Invalid public key format: ${(error as Error).message}`,
        "INVALID_PUBLIC_KEY_FORMAT"
      );
    }
  }
}
