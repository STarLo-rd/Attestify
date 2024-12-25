export declare class SignatureService {
    static readonly bip32: import("bip32").BIP32API;
    /**
     * Verifies a signature against a payload and public key
     *
     * @param payload - The payload that was signed
     * @param publicKey - The public key to verify against (base58 xpub format)
     * @param signature - The signature to verify (hex format)
     * @returns boolean indicating if signature is valid
     */
    static verifySignature(payload: string, publicKey: string, signature: string): boolean;
    /**
     * Creates a signature for a payload using a private key
     */
    static createSignature(payload: string, privateKey: Buffer): string;
    /**
     * Creates a SHA-256 hash of the payload
     *
     * @param payload - Data to hash
     * @returns Buffer containing the hash
     */
    static hashPayload(payload: string): Buffer;
    private static getPublicKeyNode;
}
