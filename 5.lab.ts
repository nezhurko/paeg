//🟩1. Centrak Election Commission gives Number for each candidate and voter
//🟩2. Each voter take Number of the candidate he wants to vote and divide this number by arbitary factors
//🟩3. Voter createds 2 ballots with these results
//🟩4. Voter encrypt both of ballots with publicKey of CEC
//🟩5. Then adding his Number , then sign it and send to the 2 ECs
//🟩6. After EC num 1 and EC num 2 gets all votes, they publish it
//🟩7. Then combine both parts of ballots and decrypts it
//🟩8. Then publish open data

//🟩 There need to be 2 ECs.
//🟩 To ecnrypt messages should be used RSA
//🟩 To sign messages should be used DSA
import { randomInt } from 'node:crypto';
import fs from 'node:fs';
import { generateRandomByCiphers } from './utils/math';
import { decrypt, encrypt, generateKeypair, stringToBigInt, bigintToString } from './utils/rsa';
import { generateKeypairDSA, sign } from './utils/dsa';

const voters = JSON.parse(fs.readFileSync('data/voters_5.json', 'utf-8')).map((voter: any) => {
        return {
            ...voter,
            uniqueNumber: generateRandomByCiphers(6)
        }
});

console.log(`Voters: ${voters.length}`);

const candidates = JSON.parse(fs.readFileSync('data/candidates.json', 'utf-8')).map((candidate: any) => {
    return {
        ...candidate,
        uniqueNumber: generateRandomByCiphers(4)
    }
});

console.log(candidates);

function getRandomDivisor(n: bigint) {
    const bigN = BigInt(n); // Convert input to bigint
    let divisors = [];
    
    for (let i = 1n; i <= bigN; i += 1n) {
        if (bigN % i === 0n) {
            divisors.push(i);
        }
    }

    // Get a random index (not using bigint for index)
    const randomIndex = Math.floor(Math.random() * divisors.length);
    return divisors[randomIndex];
}

const [EC1List, EC2List]: { message: string; signature: string; }[][] = [[], []];

class ElectionCommission{
    static submitVote(voterRequest: { message: string, signature: string}, commissionId: number){
        try{
            switch (commissionId){
                case 1:
                    EC1List.push(voterRequest);
                    break;
                case 2:
                    EC2List.push(voterRequest);
                    break;
                default:
                    throw new Error('Invalid commission id');
            }
        }catch(error){
            console.log(`Voter was unable to vote: ${error}`);
        }
    }

    static publishVotes(){
        fs.writeFileSync('data/votes.json', JSON.stringify([
            ...EC1List,
            ...EC2List
        ]));
    }

    static combineVotes(){
        return [
            ...EC1List,
            ...EC2List
        ]
    }
}

const electionsCommissions = [
    generateKeypair(), //1
    generateKeypair() //2
];

voters.forEach((voter: any) => {
    try{
        const { publicKey, privateKey } = generateKeypairDSA()

        const candidate = candidates[randomInt(0, candidates.length)];

        const n1 = getRandomDivisor(BigInt(candidate.uniqueNumber));
        const n2 = BigInt(candidate.uniqueNumber) / n1;

        const divisors = [];
        divisors.push(Number(n1), Number(n2));

        //console.log((divisors[0] * divisors[1]) === candidate.uniqueNumber);

        for(let i = 0; i < divisors.length; i++){
            const ballot = `${voter.uniqueNumber}-${divisors[i].toString()}`;

            //console.log(ballot);

            const encryptedBallot = encrypt(stringToBigInt(ballot), electionsCommissions[i].publicKey);

            const message = JSON.stringify({
                voterUniqueNumber: voter.uniqueNumber,
                encryptedBallot: encryptedBallot.toString()
            });

            const voteRequest = {
                message,
                signature: sign(message, privateKey)
            };

            ElectionCommission.submitVote(voteRequest, i+1);
        }
    }catch(error){
        console.log(error)
    }
});

ElectionCommission.publishVotes();

const overallVotes = ElectionCommission.combineVotes();

console.log(`Overall votes: ${overallVotes.length}`);

const decryptedVotes = overallVotes.map((vote: any) => {
    const decryptedBallot = () => {
        for(let i = 0; i < electionsCommissions.length; i++){
            try{
                const message = JSON.parse(vote.message);
                const decrypted = bigintToString(decrypt(BigInt(message.encryptedBallot), electionsCommissions[i].privateKey));
                
                if(decrypted.includes(message.voterUniqueNumber)) {
                    return decrypted; // Correctly returns from the decryptedBallot function
                }
            }catch(error){
                console.log(error);
            }
        }
        return null;
    };

    return {
        decryptedBallot: decryptedBallot()
    }
}).filter((vote: any) => (vote.decryptedBallot && vote.decryptedBallot !== null));

console.log(`Decrypted votes: ${decryptedVotes.filter((vote: any) => vote.decryptedBallot).length}`);

const results = decryptedVotes.map((vote: any) => {
    const parts = vote.decryptedBallot.split('-');
    if (parts.length !== 2) return;
    return {
        uniqueVoterNumber: parts[0],
        candidateNumberDiv: parts[1]
    };
}).filter((result) => result !== undefined).reduce((acc: { [key: string]: number }, { uniqueVoterNumber, candidateNumberDiv }) => {
    acc[uniqueVoterNumber] = acc[uniqueVoterNumber] || 1; // Initialize if not already set
    acc[uniqueVoterNumber] *= parseInt(candidateNumberDiv); // Multiply the divisions
    return acc;
  }, {});

console.log(results);

console.log(`Results: ${Object.keys(results).length}`);

fs.writeFileSync('data/results_5.json', JSON.stringify(results));