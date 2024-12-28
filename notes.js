const bip39 = require("bip39");
const { ec: EC } = require("elliptic");
const ecc = require("tiny-secp256k1");
const { BIP32Factory } = require("bip32");
const crypto = require("crypto");

const bip32 = BIP32Factory(ecc);
const { mnemonicToSeedSync } = bip39;

// Create a new instance of elliptic curve for secp256k1
const ec = new EC("secp256k1");

// Mnemonic
const committerMnemonic = "empty expose treat boss purchase someone dawn later fat icon exile broccoli";

// Step 1: Derive the xpub from the mnemonic
const committerSeed = mnemonicToSeedSync(committerMnemonic);
const committerNode = bip32.fromSeed(committerSeed);
const committerPathNode = committerNode.derivePath("m/44'/60'/0'/0");
const committerXpub = committerPathNode.neutered().toBase58();

console.log("Extended Public Key (xpub):", committerXpub);

// Step 2: Derive the private key from the mnemonic
const privateKey = committerPathNode.privateKey;
console.log("Private Key:", privateKey.toString('hex'));

// Step 3: Derive the public key from the xpub
const xpubNode = bip32.fromBase58(committerXpub);
const publicKeyBuffer = xpubNode.publicKey;
const pubPoint = ec.keyFromPublic(publicKeyBuffer);
const compressedPublicKey = pubPoint.getPublic(true, 'hex');
console.log("Compressed Public Key (derived from xpub):", compressedPublicKey);

// Step 4: Sign a message using the private key
const keyPair = ec.keyFromPrivate(privateKey);
const message = "Hello, this is a signed message!";
const messageHash = crypto.createHash("sha256").update(message).digest();
const signature = keyPair.sign(messageHash);

console.log("Message:", message);
console.log("Signature:", {
  r: signature.r.toString("hex"),
  s: signature.s.toString("hex"),
});

// Step 5: Verify the signature using the public key derived from xpub
const isValid = pubPoint.verify(messageHash, signature);
console.log("Is signature valid?", isValid);