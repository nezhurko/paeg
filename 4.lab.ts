//🟩1. Voters form the list of voters
//🟩2. Voters create ballots and encrypt them according to rules (first, the ballot is encrypted with keys in descending order order)
//🟩3. Then before each encryption to got ciphrotext adding random column
//🟥4. All voters sends ballots to first one
//🟥5. First voter decrypts all ballots with his privateKey, make sure that there is his ballot also
//🟥6. Then he mixes and then send to next voter in list bes desc
//🟥7. Each next voter do the same, till the last one
//🟥8. After that all ballots sends again to first voter
//🟥9. First voter decrypts all ballots, check his ballots
//🟥10. He signing and send that list to each voter
//🟥11. Each voter check the signature and make sure his ballot there
//🟥12. From all ballots selects random lines and checks results

//🟥 To encrypt messages should be used RSA encryption.
//🟥 To sign messages should be used ElGamal.

import fs from 'node:fs';
import crypto from 'crypto';
import { createCipheriv } from 'node:crypto';

const voters = JSON.parse(fs.readFileSync('data/voters_4.json', 'utf-8'));

const candidates = JSON.parse(fs.readFileSync('data/candidates.json', 'utf-8'));

const initialBallotsList: { encryptedBallot: bigint }[] = [];

function generateRandomString(length: number): string {
    return crypto.randomBytes(length).toString('hex');
}

function encryptBallot(ballot: string, keys: string[]): string {
    let encryptedBallot = ballot;
    for (const key of keys) {
        const cipher = createCipheriv('aes-256-gcm', key, generateRandomString(16));
        encryptedBallot = cipher.update(encryptedBallot, 'utf8', 'hex') + cipher.final('hex');
        encryptedBallot = generateRandomString(16) + encryptedBallot;
    }
    return encryptedBallot;
}

voters.forEach(voter => {
    const ballot = JSON.stringify({ voterId: voter.id, candidateId: voter.vote });
    const keys = voter.keys.sort().reverse();
    const encryptedBallot = encryptBallot(ballot, keys);
    initialBallotsList.push({ encryptedBallot: BigInt('0x' + encryptedBallot) });
});

