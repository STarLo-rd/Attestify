import { Users } from '../src/users';

describe('Users', () => {
  it('should create a new user', () => {
    const mnemonic = Users.generateMnemonic();
    const user = new Users(mnemonic, 'TestUser');

    expect(user.name).toBe('TestUser');
    expect(user.mnemonic).toBe(mnemonic);
    expect(user.xpubkey).toBeTruthy();
  });

  it('should list users', () => {
    const mnemonic1 = Users.generateMnemonic();
    const mnemonic2 = Users.generateMnemonic();

    const user1 = new Users(mnemonic1, 'User1');
    const user2 = new Users(mnemonic2, 'User2');

    const userList = Users.listUsers();
    expect(userList.length).toBeGreaterThanOrEqual(2);
    expect(userList.some(u => u.name === 'User1')).toBeTruthy();
    expect(userList.some(u => u.name === 'User2')).toBeTruthy();
  });
});