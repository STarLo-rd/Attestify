import { UserData } from "./types";
export declare class Users {
    private static userId;
    private static users;
    id: number;
    name: string;
    mnemonic: string;
    xpubkey: string;
    constructor(mnemonic: string, name: string);
    private deriveXpubKey;
    static listUsers(): UserData[];
    static findById(id: number): Users | undefined;
    static generateMnemonic(): string;
}
