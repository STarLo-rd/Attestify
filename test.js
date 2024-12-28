
const bip39 = require('bip39');
const ecc = require('tiny-secp256k1');
const { BIP32Factory } = require('bip32');
const { ec } = require('elliptic');
const crypto = require('crypto');
// Create BIP32 instance
const bip32 = BIP32Factory(ecc);
// Function to derive a key pair from a mnemonic
function getKeyPairFromMnemonic(mnemonic, derivationPath = "m/44'/60'/0'/0/930985984") {
  if (!bip39.validateMnemonic(mnemonic)) {
    throw new Error('Invalid mnemonic');
  }
  
  const seed = bip39.mnemonicToSeedSync(mnemonic);
  const ecdsa = new ec('secp256k1');
  
  const node = bip32.fromSeed(seed);
  const child = node.derivePath(derivationPath);
  console.log(Buffer.from(child.publicKey).toString('base64'))
  
  if (!child.privateKey) {
    throw new Error('Failed to derive private key');
  }
  
  const privateKey = child.privateKey.toString();
  console.log("privateKey :", child.privateKey)
  console.log("privateKey :", privateKey)
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
    console.log('payload', message)
  const hash = crypto.createHash('sha256').update(message).digest('hex');
  console.log('hash', hash)
  console.log('sig', signature)
  return keyPair.verify(hash, signature);
}
// Test Example
const mnemonicA = "empty expose treat boss purchase someone dawn later fat icon exile broccoli";
const mnemonicB = "universe pulse thank truth rescue business elite seed grab black repair trim";
const keyPairA = getKeyPairFromMnemonic(mnemonicA);
const keyPairB = getKeyPairFromMnemonic(mnemonicB);
// Node A signs a message
const messageA = JSON.stringify({ uri: "https://pdfobject.com/pdf/sample.pdf" });;
const signatureA = signMessage(messageA, keyPairA);
// Node B verifies Node A's signature
const isValidA = verifySignature(messageA, signatureA, keyPairA);
console.log("Node A's signature is valid:", isValidA);
// Node B responds
const messageB = JSON.stringify({ uri: "https://pdfobject.com/pdf/sample.pdf" });;
const signatureB = signMessage(messageB, keyPairB);
// Node A verifies Node B's signature
const isValidB = verifySignature(messageB, signatureB, keyPairB);
console.log("Node B's signature is valid:", isValidB);