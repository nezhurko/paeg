import { generateKeypair, hash, sign, verify } from "./utils/rsa";
import fs from 'node:fs';

const voters = JSON.parse(fs.readFileSync('data/voters.json', 'utf-8'));
const candidates = JSON.parse(fs.readFileSync('data/candidates.json', 'utf-8'));

const ballots: { signature: bigint, candidate: string, hash: bigint, publicKey: bigint }[] = [];

voters.forEach((voter: any) => {
    try{
        //voter part
        if(!voter.able_to_vote)throw new Error('Voter is not permitted to vote');

        const { publicKey, privateKey } = generateKeypair();
        [voter.publicKey, voter.privateKey] = [publicKey, privateKey];

        const chose = Math.floor(Math.random() * candidates.length); //randomly choose a candidate

        const message = `${voter.id}-${candidates[chose].name}`;

        const hashed = hash(message, voter.publicKey.n);

        const signature = sign(hashed, voter.privateKey);

        const vote = {
            voterId: voter.id,
            publicKey: voter.publicKey,
            hash: hashed,
            signature
        };

        //election commission part
        if(!verify(vote.signature, vote.publicKey, vote.hash))throw new Error('Invalid signature');

        //if any of all possible hashes already in ballots, throw an error
        if(candidates.map((candidate: { name: string }) => hash(`${vote.voterId}-${candidate.name}`, voter.publicKey.n)).some((hash: bigint) => ballots.find(ballot => ballot.hash === hash)))throw new Error('Duplicate vote');

        for(let candidate of candidates){
            if(hash(`${vote.voterId}-${candidate.name}`, voter.publicKey.n) === vote.hash){
                console.log(`Voter ${voter.name} voted for ${candidate.name}`);

                ballots.push({
                    publicKey: vote.publicKey,
                    hash: vote.hash,
                    signature: vote.signature,
                    candidate: candidate.name
                })
            }
        }
    }catch(error){
        console.log(`Voter ${voter.name} was unable to vote: ${error}`);
    }
});

const results = candidates.map((candidate: { name: string }) => {
    return {
        name: candidate.name,
        votes: ballots.filter(ballot => ballot.candidate === candidate.name).length
    }
});

console.log(results.sort((a: any, b: any) => b.votes - a.votes));

fs.writeFileSync('data/ballots.json', JSON.stringify(ballots, (key, value) => typeof value === 'bigint' ? value.toString() : value, 2));

fs.writeFileSync('data/ballots_public.json', JSON.stringify(ballots.map((ballot) => ballot.signature), (key, value) => typeof value === 'bigint' ? value.toString() : value, 2));