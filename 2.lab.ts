// Import required modules
import { generateKeypair, hash, sign, verify, encrypt, decrypt, generateBlindSignature, unblindSignature, bigintToString, stringToBigInt } from "./utils/rsa";
import { gcd, modPow, randomInt } from "./utils/math";
import fs from 'node:fs';

const voters = JSON.parse(fs.readFileSync('data/voters.json', 'utf-8'));
const candidates = JSON.parse(fs.readFileSync('data/candidates.json', 'utf-8'));

function generateRandomR(n: bigint) {
    const randomBigInt = () => {
        let result = 0n;
        for (let i = 0; i < 8; i++) { // Generate 8 random bytes
            result = (result << 8n) | BigInt(Math.floor(Math.random() * 256));
        }
        return result % (n - 1n) + 1n; // Ensure r is in the range [1, n-1]
    };

    let r;
    do {
        r = randomBigInt();
    } while (gcd(r, n) !== 1n);
    return r;
}

const electionsCommissionKeypair = generateKeypair();

let ballots: { decryptedBallot: bigint }[] = [];

let ballotsHistory: any = [];

voters.forEach((voter: any) => {
    try{
        //voter part
        if(!voter.able_to_vote)throw new Error('Voter is not permitted to vote');

        const r = generateRandomR(electionsCommissionKeypair.publicKey.n);

        let blindedBallots = [];

        const id = voter.id;

        for(let i = 0; i < candidates.length*2; i++){
            const ballot = `${candidates[i % candidates.length].name}-${id}`;
            const { blindSignature, r: blindR } = generateBlindSignature(ballot, r, electionsCommissionKeypair.publicKey, electionsCommissionKeypair.privateKey);
            blindedBallots.push({ originalBallot: ballot, blindSignature, blindR});
        }

        if(ballotsHistory.some((ballot: any) => blindedBallots.some((blindedBallot: any) => blindedBallot.originalBallot === ballot.originalBallot)))throw new Error('Duplicate vote');

        const signedBallots = blindedBallots.map(ballot => {
            const { blindSignature, blindR, originalBallot } = ballot;
            const signedByEC = sign(stringToBigInt(originalBallot), electionsCommissionKeypair.privateKey);
        
            return {
                blindR,
                blindSignature,
                signedByEC,
                originalBallot
            };
        });

        ballotsHistory.push(...signedBallots);

        //voter part
        const selectedBallot = signedBallots[randomInt(0, signedBallots.length - 1)];

        const unblindedSignature = unblindSignature(selectedBallot.blindSignature, selectedBallot.blindR, electionsCommissionKeypair.publicKey);

        if(unblindedSignature !== selectedBallot.signedByEC)throw new Error('Invalid election commission signature');

        const encryptedBallot = encrypt(
            unblindedSignature,
            electionsCommissionKeypair.publicKey
        );

        //election commission part

        const decryptedBallot = decrypt(encryptedBallot, electionsCommissionKeypair.privateKey);

        const voterSelectedBallot: any = signedBallots.find(ballot => ballot.signedByEC === decryptedBallot);

        if(!verify(decryptedBallot, electionsCommissionKeypair.publicKey, stringToBigInt(voterSelectedBallot.originalBallot)))throw new Error('Invalid signature');

        const [candidateName, voterId] = voterSelectedBallot.originalBallot.split('-');

        ballots.push({
            decryptedBallot,
        });
    }catch(error){
        console.log(`Voter ${voter.name} was unable to vote: ${error}`);
    }
});

fs.writeFileSync('data/ballots.json', JSON.stringify(ballots, null, 2));