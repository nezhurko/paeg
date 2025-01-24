import fs from 'node:fs';
import { verify } from '../utils/rsa';

const ballots = JSON.parse(fs.readFileSync('data/ballots.json', 'utf-8'));

ballots.forEach((ballot: any, index: number) => {
    try {
        if (!ballot.publicKey || !ballot.hash || !ballot.signature) throw new Error('Invalid ballot');

        const {
            publicKey: { n, e },
            hash,
            signature
        } = {
            publicKey: {
                n: BigInt(ballot.publicKey.n),
                e: BigInt(ballot.publicKey.e),
            },
            hash: BigInt(ballot.hash),
            signature: BigInt(ballot.signature),
        };

        if (!verify(signature, { n, e }, hash)) throw new Error('Invalid signature');

        console.log(`Ballot ${index+1} \x1b[32m✓\x1b[0m`);
    } catch (error) {
        console.log(`Ballot ${index+1} \x1b[31m✖\x1b[0m | ${error}`);
    }
});