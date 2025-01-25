//🟩0.Write Blum Blum Shub utils
//🟩1. Registraton Center counts estimate amount of voters, generate ID for each one and send to EC
//🟩2. Election Center generate the same amount of keypairs for random bytes generator
//🟩3. For encryption of ballots, generates the same keys for each voter
//🟩4. EC saves voters ids and related privateKey
//🟩5. EC creates tokens that includes voter ID and publicKey, then sends to RC
//🟩6. Voter goes to RC, fill the Name Surname
//🟩7. RC saves data, add to them unique serial number and gives token to voter
//🟩8. Also gives login and password for the voting app
//🟩9. User login with credentials to the voting app
//🟩10. Voter choose the candidate and start process of creating ballot
//🟩11. App uses info from token to encrypt ballot and sends it to EC
//🟩12. EC decrypts ballots and give the results

//🟩 To code the message should be used ElGamal algorithm
//🟩 To code the ballot should be used Blum Blum Shub
import fs from 'node:fs';
import { generateRandomByCiphers } from './utils/math';
import { bbsGenerate, decryptBBS, encryptBBS, generateKeypairBBS, bitsToString, stringToBits } from './utils/bbs';
import { encrypt, decrypt, generateKeypairElGamal } from './utils/elgamal';
import { bigintToString, stringToBigInt } from './utils/rsa';

const votersCredentialsDatabase: any = [];

const ECKeypair = generateKeypairElGamal();

let results: any = [];

const voters = JSON.parse(fs.readFileSync('data/voters_6.json', 'utf-8')).map((voter: any) => {
    return {
        ...voter,
        uniqueNumber: generateRandomByCiphers(8),
        elGamalKeypair: generateKeypairElGamal(),
    }
});

const candidates = JSON.parse(fs.readFileSync('data/candidates.json', 'utf-8')).map((candidate: any) => {
    return {
        ...candidate,
        uniqueNumber: generateRandomByCiphers(4)
    }
});

console.log(candidates);

class VoteApp{
    static login(login: number, password: number){
        console.log(`Login: ${login}, Password: ${password}`);

        const userToken = votersCredentialsDatabase.find((voter: any) => voter.login === login && voter.password === password).token;

        if(!userToken)throw new Error('Invalid login or password');

        //return inique voter id
        return votersWithTokens.find((voter: any) => voter.token === userToken).uniqueNumber;
    }

    static vote(ballot: any, voterToken: any){
        const decryptedVote = decrypt(ballot, ECKeypair.privateKey.x, ECKeypair.publicKey.p);

        const [encryptedBits, keyBits] = decryptedVote.split('|');

        const encryptedBallot = {
            encryptedBits: stringToBits(encryptedBits),
            keyBits: stringToBits(keyBits)
        }

        const decryptedBallot = decryptBBS(encryptedBallot.encryptedBits, encryptedBallot.keyBits);

        const [userId, candidateId] = decryptedBallot.decrypted.split('-');

        console.log(`User: ${userId}, Candidate: ${candidateId}`);

        results.push({
            userId,
            candidate: candidates.find((candidate: any) => candidate.uniqueNumber === +candidateId).name
        });
    }
}

const publicBbsKeypair = generateKeypairBBS();

const votersWithTokens = voters.map((voter: any) => {
    return {
        ...voter,
        token: encrypt(voter.uniqueNumber, ECKeypair.publicKey)
    }
});

voters.forEach((voter: any) => {
    const voterToken = votersWithTokens.find((voterWithToken: any) => voterWithToken.uniqueNumber === voter.uniqueNumber);
    
    const [login, password] = [generateRandomByCiphers(4), generateRandomByCiphers(9)]; //generate random login and password for voter

    votersCredentialsDatabase.push({
        login,
        password,
        token: voterToken.token
    });

    const userId = VoteApp.login(login, password);

    const ballot = `${userId}-${candidates[Math.floor(Math.random() * candidates.length)].uniqueNumber}`;

    const encryptedBallot = encryptBBS(ballot, publicBbsKeypair.publicKey, BigInt(userId)); //bbs

    const encryptedBallotString = `${encryptedBallot.encryptedBits}|${encryptedBallot.keyBits}`.replace(/,/g, '');

    const finalBallot = encrypt(encryptedBallotString, ECKeypair.publicKey); //elgamal

    VoteApp.vote(finalBallot, voterToken.token);
});

console.log(results); 