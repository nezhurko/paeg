//🟩1. Voter request a register number
//🟩2. Registration center sends a number and saves it and the voter's public key
//🟩3. Registration center sends list with numbers and public keys to the election commission
//🟩4. Each voter creates a random number
//🟩5. Voter create a message with number from RC, his random number and candidate name, sign it and send it to the election commission
//🟩6. EC checks singature check registration number from list, if number in list, it removes it and saves the vote
//🟩7. After election ends, EC publishes ballots which contains voters indentification number and candidate name

import { generateKeyPairSync, KeyLike, KeyObject, KeyPairKeyObjectResult, randomUUID, UUID } from "node:crypto";
import { generateKeypairDSA, sign, verify } from "./utils/dsa";
import { hash } from "./utils/rsa";
import fs from 'node:fs';
import { decrypt, encrypt, generateKeypairElGamal } from "./utils/elgamal";

//🟩 There need to be 2 EC.
//🟥 To code messages should be used ElGamal encryption.
//🟩 To sign messages should be used DSA.

const voters = JSON.parse(fs.readFileSync('data/voters_3.json', 'utf-8'));
const candidates = JSON.parse(fs.readFileSync('data/candidates.json', 'utf-8'));

let ballots: any = [];

let registeredVoters: { commissionUUID: UUID, publicKey: KeyObject, voted: boolean}[] = [];

interface ElGamalKeyPair {
    publicKey: { p: bigint, g: bigint, y: bigint };
    privateKey: { x: bigint };
}

interface CommissionKeyPairs {
    [key: number]: ElGamalKeyPair;
}

const commissionKeypairs: CommissionKeyPairs = {
    1: generateKeypairElGamal(),
    2: generateKeypairElGamal()
};

class ElectionCommission{
    // public publicKey: { p: bigint, g: bigint, y: bigint };
    // public privateKey: KeyObject;

    constructor(
        commissionKeypair: KeyPairKeyObjectResult
    ){
        // this.publicKey = commissionKeypair.publicKey;
        // this.privateKey = commissionKeypair.privateKey;
    }

    // getPublicKey(){
    //     return this.publicKey;
    // }

    submitVote(voterRequest: {  publicKey: KeyObject, signature: string, message: string }){
        try{
            //const decodedRequest = decrypt(voterRequest, this.privateKey.x, this.publicKey.p);

            if(!verify(voterRequest.signature, voterRequest.message, voterRequest.publicKey))throw new Error('Invalid signature');

            const { commissionUUID: voterCommissionUUID, customUUID: voterCustomUUID, candidate } = JSON.parse(voterRequest.message);

            if(!registeredVoters.some(voter => voter.commissionUUID === voterCommissionUUID))throw new Error('Voter is not registered');

            if(ballots.some((ballot: { customUUID: UUID }) => ballot.customUUID === voterCustomUUID))throw new Error('Duplicate vote');

            ballots.push({
                customUUID: voterCustomUUID,
                candidate
            });

            console.log(`\x1b[32mVoter ${voterCustomUUID} voted for ${candidate}\x1b[0m`);
        }catch(error){
            console.log(`\x1b[31mVote ${voterRequest.message}... was unable to vote:\x1b[0m ${error}`);
        }
    }
}

const ElectionCommissions = Object.values(commissionKeypairs).map(commissionKeypair => new ElectionCommission(commissionKeypair));

function encryptAndSubmitVote(voterRequest: { publicKey: KeyObject, signature: string, message: string }) {

    // const publicKey = ElectionCommissions1.getPublicKey();
    // const encryptedRequest = encrypt(voterRequest, publicKey);
    ElectionCommissions.forEach(electionCommission => {
        electionCommission.submitVote(voterRequest);
    });
    
    // ElectionCommissions.forEach(electionCommission => {
    //     const publicKey = electionCommission.getPublicKey();
    //     const encryptedRequest = encrypt(voterRequest, publicKey);
    //     electionCommission.submitVote(encryptedRequest);
    // });
}

for(const voter of voters) {
    try{
        //registration center part
        const { publicKey, privateKey } = generateKeypairDSA();

        if(!voter.able_to_vote)throw new Error('Voter is not permitted to vote');

        const commissionUUID: UUID = voter.uuid;

        if(registeredVoters.some(voter => voter.commissionUUID === commissionUUID)){
            console.log(`\x1b[31mVoter ${voter.uuid} is already registered\x1b[0m`);
        }else{
            registeredVoters.push({ commissionUUID, publicKey, voted: false });
            console.log(`Voter ${voter.uuid} is now registered`);
        }

        //voter part
        const customUUID: any = randomUUID();

        const message = JSON.stringify({ 
            commissionUUID, 
            customUUID,
            candidate: candidates[Math.floor(Math.random() * candidates.length)].name 
        });

        const signature = sign(message, privateKey);

        console.log(message);

        const voterRequest = {
            publicKey,
            signature,
            message
        };

        //election commission part
        //2 ECs
        encryptAndSubmitVote(voterRequest);
    }catch(error){
        console.log(`\x1b[31mVoter ${voter.uuid} was unable to vote:\x1b[0m ${error}`);
    }
};

fs.writeFileSync('data/ballots_3.json', JSON.stringify(ballots, null, 2));