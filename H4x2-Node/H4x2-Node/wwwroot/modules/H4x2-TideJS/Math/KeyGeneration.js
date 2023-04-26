import Point from "../Ed25519/point.js";
import GenShardResponse from "../Models/GenShardResponse.js";
import SendShardResponse from "../Models/SendShardResponse.js";
import { createAESKey, decryptData, encryptData } from "../Tools/AES.js";
import { SHA256_Digest, SHA512_Digest } from "../Tools/Hash.js";
import { BigIntFromByteArray, BigIntToByteArray, bytesToBase64, ConcatUint8Arrays, median, mod, StringToUint8Array } from "../Tools/Utils.js";
import { GetLi } from "./SecretShare.js";

/**
 * @param {GenShardResponse[]} genShardResponses 
 */
export function GenShardReply(genShardResponses){
    const sortedShares = SortShares(genShardResponses.map(resp => resp.YijCiphers)); // sort shares so they can easily be sent to respective orks
    const timestamp = median(genShardResponses.map(resp => resp.Timestampi));
    const R2 = genShardResponses.reduce((sum, next) => next.GRi.add(sum), Point.infinity);
    return {sortedShares: sortedShares, timestamp: timestamp, R2: R2};
}

/**
 * @param {string} keyId
 * @param {SendShardResponse[]} sendShardResponses
 * @param {Point[]} mgORKi 
 * @param {bigint} timestamp
 * @param {Point} R2
 */
export async function SendShardReply(keyId, sendShardResponses, mgORKi, timestamp, R2){
    // Verify all GK1s are the same
    if(!sendShardResponses.every(resp => resp.gK1.isEqual(sendShardResponses[0].gK1))) throw new Error("SendShardReply: Not all GK1s returned are the same.");

    // Aggregate the signature
    const S = mod(sendShardResponses.reduce((sum, next) =>  next.Si + sum, BigInt(0)));

    // Generate EdDSA R from all the ORKs publics
    const M_data_to_hash = ConcatUint8Arrays([sendShardResponses[0].gK1.compress(), StringToUint8Array(timestamp.toString()), StringToUint8Array(keyId)]);
    const M = await SHA256_Digest(M_data_to_hash);
    const R = mgORKi.reduce((sum, next) => sum.add(next)).add(R2);

    // Prepare the signature message
    const H_data_to_hash = ConcatUint8Arrays([R.compress(), sendShardResponses[0].gK1.compress(), M]);
    const H = mod(BigIntFromByteArray(await SHA512_Digest(H_data_to_hash)), Point.order);

    // Verify signature validates
    if(!(Point.g.times(S).isEqual(R.add(sendShardResponses[0].gK1.times(H))))) throw new Error("SendShard: Signature test failed");

    // Interpolate the gMultipliers
    const gMultiplied = sendShardResponses[0].gMultiplied.map((m, i) => m == null ? null : sendShardResponses.reduce((sum, next) => sum.add(next.gMultiplied[i]), Point.infinity));

    return {S: S, encCommitStatei: sendShardResponses.map(resp => resp.encCommitStatei), gMultiplied: gMultiplied};
}

/**
 * This function is EXCLUSIVE to H4x2 3.x - after 3.x the CVK will NEVER exist in one place at one time again
 * @param {CryptoKey[]} prismAuthi 
 * @param {string[]} encryptedCVKi
 * @param {string[]} orkIds
 */
export async function Commit_DecryptCVK(prismAuthi, encryptedCVKi, orkIds){
    const ids = orkIds.map(id => BigInt(id)); 
    const lis = ids.map(id => GetLi(id, ids, Point.order));

    const pre_CVKs = encryptedCVKi.map(async (encCVK, i) => await decryptData(encCVK, prismAuthi[i])); // decrypt CVKs with prismAuth of each ork
    const CVK = (await Promise.all(pre_CVKs)).map(cvk => BigInt(cvk)).reduce((sum, next, i) => mod(sum + (next * lis[i])), BigInt(0)); // sum all CVKs to find full CVK
    return CVK;
}






/**
 * @param {string[][]} sharesEncrypted 
 * @returns {string[][]}
 */
function SortShares(sharesEncrypted) {
    // Will sort array so that:
    // - Each ork receives a list of shares meant for them
    // - The shares are in the order which they were sent
    // To do this, I had to grab the first share of the first response, then the first share of the second response etc. and put it into a list
    // Then I had to grab the second share of the first response, then the second share of the second response etc. and put it into a list
    // The put those lists together, so we have an array of GenShardShare arrays
    // This was all done in the below line of code. Remember we rely on the order the shares are sent back
    return sharesEncrypted.map((_, i) => sharesEncrypted.map(share => share[i]))
}