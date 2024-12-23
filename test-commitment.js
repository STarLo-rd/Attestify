const bip39 = require('bip39')
const { BIP32Factory } = require('bip32')
const ecc = require('tiny-secp256k1')
const crypto = require('crypto')

const bip32 = BIP32Factory(ecc)

class Users {
    static users = {}

    static initialize() {
        // Create two test users
        this.createNewUser(1)
        this.createNewUser(2)
    }

    static findById(id) {
        return this.users[id]
    }

    static createNewUser(id) {
        const mnemonic = bip39.generateMnemonic()
        const seed = bip39.mnemonicToSeedSync(mnemonic)
        const root = bip32.fromSeed(seed)
        const path = "m/44'/0'/0'"
        const account = root.derivePath(path)
        const xpubkey = account.neutered().toBase58()

        const newUser = { id, mnemonic, xpubkey }
        this.users[id] = newUser
        return newUser
    }
}

class Commitment {
    constructor(committerId, committeeId, commitmentId) {
        this.commitmentId = commitmentId
        this.committerId = committerId
        this.committeeId = committeeId

        const committee = Users.findById(committeeId)
        const committer = Users.findById(committerId)

        this.committeeXpubkey = this.deriveCommitmentXpubKey(committee.xpubkey, this.commitmentId)
        this.committerXpubkey = this.deriveCommitmentXpubKey(committer.xpubkey, this.commitmentId)
    }

    deriveCommitmentXpubKey(parentXpub, commitmentId) {
        const parentNode = bip32.fromBase58(parentXpub)
        const childNode = parentNode.derive(commitmentId)
        return childNode.neutered().toBase58()
    }

    signMessage(message, userMnemonic) {
        const seed = bip39.mnemonicToSeedSync(userMnemonic)
        const root = bip32.fromSeed(seed)
        const node = root.derivePath(`m/44'/0'/0'/${this.commitmentId}`)
        
        const messageHash = crypto.createHash('sha256').update(message).digest()
        return ecc.sign(messageHash, node.privateKey)
    }

    verifySignature(message, signature, isCommitter) {
        const xpubkey = isCommitter ? this.committerXpubkey : this.committeeXpubkey
        const node = bip32.fromBase58(xpubkey)
        
        const messageHash = crypto.createHash('sha256').update(message).digest()
        return ecc.verify(messageHash, node.publicKey, signature)
    }
}

// Example usage:
Users.initialize()

const commitment = new Commitment(1, 2, 1) // commitmentId = 1
const message = "Test message"

// Sign with committer's key
const committer = Users.findById(1)
const signature = commitment.signMessage(message, committer.mnemonic)

// Verify signature
const isValid = commitment.verifySignature(message, signature, true)
console.log('Signature verification:', isValid)