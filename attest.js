const bip39 = require("bip39");
const { ec: EC } = require("elliptic");
const ecc = require("tiny-secp256k1");
const { BIP32Factory } = require("bip32");
const crypto = require("crypto");
const { v4: uuidv4 } = require('uuid');

const bip32 = BIP32Factory(ecc);
const { mnemonicToSeedSync } = bip39;

// Create a new instance of elliptic curve for secp256k1
const ec = new EC("secp256k1");

// Constants
const HARDENED_OFFSET = 0x80000000;

// Mnemonic
const committerMnemonic = "empty expose treat boss purchase someone dawn later fat icon exile broccoli";

// Generate attestation ID
const attestationId = uuidv4();
console.log("Attestation ID:", attestationId);

/**
 * Generates a deterministic index for HD path derivation from a string value
 */
function generateHDPathIndex(value) {
    const hash = crypto.createHash("sha256").update(value).digest("hex");
    const number = parseInt(hash.slice(0, 16), 16);
    return number % HARDENED_OFFSET;
}

/**
 * Derives a child public key from a parent extended public key using the attestation ID
 */
function deriveChildPubKey(parentXpub, attestationId) {
    const derivationIndex = generateHDPathIndex(attestationId);
    const parentNode = bip32.fromBase58(parentXpub);
    
    if (!parentNode.isNeutered()) {
        throw new Error("Parent key must be a public key (xpub)");
    }

    // Derive child node using calculated index
    const childNode = parentNode.derive(derivationIndex);
    
    // Convert the public key to a point on the curve
    const key = ec.keyFromPublic(childNode.publicKey);
    // Get the compressed public key in hex format
    const compressedPubKey = key.getPublic(true, 'hex');
    
    console.log("Derived child public key (compressed):", compressedPubKey);
    return compressedPubKey;
}

// Step 1: Derive the xpub from the mnemonic
const committerSeed = mnemonicToSeedSync(committerMnemonic);
const committerNode = bip32.fromSeed(committerSeed);
const committerPathNode = committerNode.derivePath("m/44'/60'/0'/0");
const committerXpub = committerPathNode.neutered().toBase58();

console.log("Extended Public Key (xpub):", committerXpub);

// Step 2: Derive the private key with the same derivation path
const derivationIndex = generateHDPathIndex(attestationId);
const derivedPrivateNode = committerPathNode.derive(derivationIndex);
const privateKey = derivedPrivateNode.privateKey;
console.log("Derived Private Key:", privateKey.toString('hex'));

// Step 3: Derive the child public key using attestation ID
const childPubKeyHex = deriveChildPubKey(committerXpub, attestationId);
const pubPoint = ec.keyFromPublic(childPubKeyHex, 'hex');
console.log("Child Public Key (hex):", childPubKeyHex);

// Step 4: Sign a message using the derived private key
const keyPair = ec.keyFromPrivate(privateKey);
const message = "Hello, this is a signed message!";
const messageHash = crypto.createHash("sha256").update(message).digest();
const signature = keyPair.sign(messageHash);

console.log("Message:", message);
console.log("Signature:", {
    r: signature.r.toString("hex"),
    s: signature.s.toString("hex"),
});

// Step 5: Verify the signature using the derived child public key
const isValid = pubPoint.verify(messageHash, signature);
console.log("Is signature valid?", isValid);