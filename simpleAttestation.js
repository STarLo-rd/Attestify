const bip39 = require('bip39');
const ecc = require('tiny-secp256k1');
const { BIP32Factory } = require('bip32');
const { ec } = require('elliptic');
const crypto = require('crypto');

// Create BIP32 instance
const bip32 = BIP32Factory(ecc);

// Function to derive a key pair from a mnemonic
function getKeyPairFromMnemonic(mnemonic, derivationPath = "m/44'/60'/0'/0/0") {
  if (!bip39.validateMnemonic(mnemonic)) {
    throw new Error('Invalid mnemonic');
  }
  
  const seed = bip39.mnemonicToSeedSync(mnemonic);
  const ecdsa = new ec('secp256k1');
  
  const node = bip32.fromSeed(seed);
  const child = node.derivePath(derivationPath);
  
  if (!child.privateKey) {
    throw new Error('Failed to derive private key');
  }
  
  const privateKey = child.privateKey.toString('hex');
  const keyPair = ecdsa.keyFromPrivate(privateKey);
  
  return keyPair;
}

// Signing a message
function signMessage(message, keyPair) {
  const hash = crypto.createHash('sha256').update(message).digest('hex');
  const signature = keyPair.sign(hash);
  return signature.toDER('hex');
}

// Verifying a signature
function verifySignature(message, signature, keyPair) {
  const hash = crypto.createHash('sha256').update(message).digest('hex');
  return keyPair.verify(hash, signature);
}

// Test Example
const mnemonicA = "empty expose treat boss purchase someone dawn later fat icon exile broccoli";
const mnemonicB = "universe pulse thank truth rescue business elite seed grab black repair trim";

const keyPairA = getKeyPairFromMnemonic(mnemonicA);
const keyPairB = getKeyPairFromMnemonic(mnemonicB);

// Node A signs a message
const messageA = "Hello, this is Node A!";
const signatureA = signMessage(messageA, keyPairA);

// Node B verifies Node A's signature
const isValidA = verifySignature(messageA, signatureA, keyPairA);
console.log("Node A's signature is valid:", isValidA);

// Node B responds
const messageB = "Hello, this is Node B!";
const signatureB = signMessage(messageB, keyPairB);

// Node A verifies Node B's signature
const isValidB = verifySignature(messageB, signatureB, keyPairB);
console.log("Node B's signature is valid:", isValidB);
