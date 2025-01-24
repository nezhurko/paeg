import * as fs from 'node:fs';
import { generateKeypair } from '../utils/rsa';

interface Voter {
    id: number;
    name: string;
    privateKey: {
        n: bigint;
        d: bigint;
    };
    publicKey: {
        n: bigint;
        e: bigint;
    };
}

function generateRandomName(): string {
    const names = ['Alice', 'Bob', 'Charlie', 'David', 'Eve', 'Frank', 'Grace', 'Heidi', 'Ivan', 'Judy'];
    return names[Math.floor(Math.random() * names.length)];
}

function generateVoters(count: number): Voter[] {
    const voters: Voter[] = [];
    for (let i = 0; i < count; i++) {
        const { publicKey, privateKey } = generateKeypair();

        voters.push({
            id: i + 1,
            name: generateRandomName(),
            privateKey: privateKey,
            publicKey: publicKey
        });
    }
    return voters;
}

const voters = generateVoters(100);
fs.writeFileSync('data/voters.json', JSON.stringify(voters, null, 2));