import { Users } from '../src/users';
import { Commitment } from '../src/commitment';

describe('Commitment', () => {
  let alice: Users, bob: Users;

  beforeEach(() => {
    const mnemonicAlice = Users.generateMnemonic();
    const mnemonicBob = Users.generateMnemonic();
    
    alice = new Users(mnemonicAlice, 'Alice');
    bob = new Users(mnemonicBob, 'Bob');
  });

  it('should create a commitment', () => {
    const commitment = new Commitment(alice.id, bob.id, { 
      assetName: 'Gold', 
      quantity: 100, 
      unit: 'grams' 
    });

    expect(commitment.creatorId).toBe(alice.id);
    expect(commitment.committerId).toBe(bob.id);
    expect(commitment.status).toBe('INITIATED');
  });

  it('should sign and discharge a commitment', () => {
    const commitment = new Commitment(alice.id, bob.id, { 
      assetName: 'Gold', 
      quantity: 100, 
      unit: 'grams' 
    });

    const aliceMnemonic = alice.mnemonic;
    const bobMnemonic = bob.mnemonic;

    commitment.signCommitment(alice.id, aliceMnemonic);
    commitment.signCommitment(bob.id, bobMnemonic);

    expect(commitment.status).toBe('ACKNOWLEDGED');

    const discharged = commitment.dischargeCommitment();
    expect(discharged).toBeTruthy();
    expect(commitment.status).toBe('DISCHARGED');
  });
});