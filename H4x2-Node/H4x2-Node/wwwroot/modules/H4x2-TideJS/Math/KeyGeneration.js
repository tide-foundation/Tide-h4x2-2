import Point from "../Ed25519/point.js";
import GenShardResponse from "../Models/GenShardResponse";
import PreCommitResponse from "../Models/PreCommitResponse.js";
import SetKeyResponse from "../Models/SetKeyResponse.js";
import { decryptData, encryptData } from "../Tools/AES.js";
import { SHA256_Digest, SHA512_Digest } from "../Tools/Hash.js";
import { BigIntFromByteArray, BigIntToByteArray, ConcatUint8Arrays, median, mod, StringToUint8Array } from "../Tools/Utils.js";
import { GetLi } from "./SecretShare.js";

/**
 * @param {GenShardResponse[]} genShardResponses 
 */
export function GenShardReply(genShardResponses){
    const gK = genShardResponses.reduce((sum, point) => sum.add(point.GK), Point.infinity);
    /**
    * @param {Point[]} share1 
    * @param {Point[]} share2 
    */
    const addShare = (share1, share2) => {
        return share1.map((s, i) => s.add(share2[i]))
    }
    const gMultiplied = genShardResponses.map(p => p.GMultiplied).reduce((sum, next) => addShare(sum, next)); // adds all of the respective gMultipliers together
    const sortedShares = SortShares(genShardResponses.map(resp => resp.EncryptedOrkShares)); // sort shares so they can easily be sent to respective orks
    const timestamp = median(genShardResponses.map(resp => resp.Timestampi));
    return {gK: gK, gMultiplied: gMultiplied, sortedShares: sortedShares, timestamp: timestamp};
}

/**
 * @param {SetKeyResponse[]} setKeyResponses
 * @param {string[]} orkIds 
 */
export function SetKeyReply(setKeyResponses, orkIds){
    // Calculate all lagrange coefficients for all the shards
    const ids = orkIds.map(id => BigInt(id)); 
    const lis = ids.map(id => GetLi(id, ids, Point.order));

    // Interpolate the key public
    const gKntest = setKeyResponses.map((_, i) => setKeyResponses.reduce((sum, next, j) => sum.add(next.gKtesti[i].times(lis[j])), Point.infinity));
    
    // Generate the partial EdDSA R
    const R2 = setKeyResponses.reduce((sum, next) => sum.add(next.gRi), Point.infinity);

    // Get signatures
    const gKsigni = setKeyResponses.map(resp => resp.gKsigni);

    // Get Tests from each ORK
    const gKntesti = setKeyResponses.map(resp => resp.gKtesti);

    // Get state ids from each ork
    const state_ids = setKeyResponses.map(resp => resp.state_id);

    return {gKntest: gKntest, R2: R2, gKsigni: gKsigni, gKntesti: gKntesti, state_ids: state_ids};
}

/**
 * 
 * @param {PreCommitResponse[]} preCommitResponses 
 * @param {string} keyID 
 * @param {Point} gK1 
 * @param {Point} gKtest
 * @param {number} timestamp 
 * @param {Point[]} mgORKi 
 * @param {Point} R2 
 */
export async function PreCommitValidation(preCommitResponses, keyID, gK1, gKtest, timestamp, mgORKi, R2){
    // Aggregate the signature
    const S = preCommitResponses.map(resp => BigInt(resp.S)).reduce((sum, next) => mod(sum + next, Point.order)); // sum all responses in finite field of Point.order

    // Generate EdDSA R from all the ORKs publics
    const M_data_to_hash = ConcatUint8Arrays([gK1.compress(), StringToUint8Array(timestamp.toString()), StringToUint8Array(keyID)]);
    const M = await SHA256_Digest(M_data_to_hash);
    const R = mgORKi.reduce((sum, next) => sum.add(next)).add(R2);

    // Prepare the signature message
    const H_data_to_hash = ConcatUint8Arrays([R.compress(), gKtest.compress(), M]);
    const H = BigIntFromByteArray(await SHA512_Digest(H_data_to_hash));

    // Verify signature validates
    if(!(Point.g.times(S).isEqual(R.add(gKtest.times(H))))) Promise.reject("PreCommit: Signature validation failed");

    // Create Encrypted State list
    const encCommitStatei = preCommitResponses.map(resp => resp.EncCommitStatei);

    return {S: S, encCommitStatei: encCommitStatei};
}

/**
 * This function is EXCLUSIVE to H4x2 3.x - after 3.x the CVK will NEVER exist in one place at one time again
 * @param {CryptoKey[]} prismAuthi 
 * @param {string[]} encryptedCVKi
 */
export async function Commit_DecryptCVK(prismAuthi, encryptedCVKi){
    const pre_CVKs = encryptedCVKi.map(async (encCVK, i) => await decryptData(encCVK, prismAuthi[i])); // decrypt CVKs with prismAuth of each ork
    const CVK = (await Promise.all(pre_CVKs)).map(cvk => BigInt(cvk)).reduce((sum, next) => mod(sum + next)); // sum all CVKs to find full CVK
    return CVK;
}






/**
 * @param {string[][]} sharesEncrypted 
 * @returns {string[][]}
 */
function SortShares(sharesEncrypted) {
    // Will sort array so that:
    // - Each ork receives a list of shares meant for them ('To')
    // - The shares are in the order which they were sent e.g. 'From' will be in same order
    // To do this, I had to grab the first share of the first response, then the first share of the second response etc. and put it into a list
    // Then I had to grab the second share of the first response, then the second share of the second response etc. and put it into a list
    // The put those lists together, so we have an array of GenShardShare arrays
    // This was all done in the below line of code. Remember we rely on the order the shares are sent back, not neccessarily the To and From fields
    // Maybe we remove the fields in future?
    return sharesEncrypted.map((_, i) => sharesEncrypted.map(share => share[i]))
}