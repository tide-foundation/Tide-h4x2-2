import Point from "../Ed25519/point.js";
import GenShardResponse from "../Models/GenShardResponse.js";
import SendShardResponse from "../Models/SendShardResponse.js";
import SetKeyResponse from "../Models/SetKeyResponse.js";
import { createAESKey, decryptData, encryptData } from "../Tools/AES.js";
import { SHA256_Digest, SHA512_Digest } from "../Tools/Hash.js";
import { BigIntFromByteArray, BigIntToByteArray, bytesToBase64, ConcatUint8Arrays, median, mod, StringToUint8Array } from "../Tools/Utils.js";
import { GetLi } from "./SecretShare.js";

/**
 * @param {GenShardResponse[]} genShardResponses 
 */
export function GenShardReply(genShardResponses){
    const sortedShares = SortShares(genShardResponses.map(resp => resp.YijCiphers)); // sort shares so they can easily be sent to respective orks
    const gKCiphers = genShardResponses.map(resp => resp.GKnCipher); // we need to send all gKCiphers to every ork
    const timestamp = median(genShardResponses.map(resp => resp.Timestampi));
    return {sortedShares: sortedShares, timestamp: timestamp, gKCiphers: gKCiphers};
}

/**
 * @param {SendShardResponse[]} sendShardResponses
 * @param {string[]} orkIds 
 * @param {string[][]} gKCiphers
 */
export async function SendShardReply(sendShardResponses, orkIds, gKCiphers){
    // Assert all ork returned same number of responses
    const equalLengthCheck = sendShardResponses.every(resp => resp.gKtesti.length == sendShardResponses[0].gKtesti.length && resp.gMultiplied.length == sendShardResponses[0].gMultiplied.length);
    if(!equalLengthCheck) throw new Error("SendShardReply: An ORK returned a different number of points that others");
    const cipherLengthCheck = gKCiphers.every(cipher => cipher.length == gKCiphers[0].length);
    if(!cipherLengthCheck) throw new Error("SendShardReply: ORKs returned different number of ciphers")

    // Decrypts the partial publics
    const pre_ephKeys = sendShardResponses.map(async resp => await createAESKey(BigIntToByteArray(BigInt(resp.ephKeyi)), ["decrypt"]));
    const ephKeys = await Promise.all(pre_ephKeys);
    const pre_gKni = gKCiphers[0].map(async (_, i) => await Promise.all(gKCiphers.map(async (cipher, j) => Point.fromB64(await decryptData(cipher[i], ephKeys[j]))))); // Resolving a double array of promises - quite confusing
    const gKni = await Promise.all(pre_gKni);
    const gKn = gKni.map(p => p.reduce((sum, next) => sum.add(next)));

    // Calculate all lagrange coefficients for all the shards
    const ids = orkIds.map(id => BigInt(id)); 
    const lis = ids.map(id => GetLi(id, ids, Point.order));

    // Interpolate the key public
    const gKntest = sendShardResponses[0].gKtesti.map((_, i) => sendShardResponses.reduce((sum, next, j) => sum.add(next.gKtesti[i].times(lis[j])), Point.infinity));
    
    // Interpolate the gMultipliers
    const gMultiplied = sendShardResponses[0].gMultiplied.map((m, i) => m == null ? null : sendShardResponses.reduce((sum, next) => sum.add(next.gMultiplied[i]), Point.infinity));

    // Generate the partial EdDSA R
    const R2 = sendShardResponses.reduce((sum, next) => sum.add(next.gRi), Point.infinity);

    //Check gKntest with gKn
    const gKtestCHECK = gKn.every((p, i) => p.isEqual(gKntest[i]));
    if(!gKtestCHECK) throw new Error("SendShardReply: GKTest check failed");

    return {gKntest: gKntest, R2: R2, gMultiplied: gMultiplied, gKn: gKn, ephKeys: sendShardResponses.map(resp => resp.ephKeyi)};
}

/**
 * 
 * @param {SetKeyResponse[]} setKeyResponses 
 * @param {string} keyID 
 * @param {Point[]} gKn 
 * @param {Point[]} gKntest
 * @param {bigint} timestamp 
 * @param {Point[]} mgORKi 
 * @param {Point} R2 
 */
export async function SetKeyValidation(setKeyResponses, keyID, gKn, gKntest, timestamp, mgORKi, R2){
    // Aggregate the signature
    const S = mod(setKeyResponses.map(resp => BigInt(resp.S)).reduce((sum, next) => sum + next), Point.order); // sum all responses in finite field of Point.order

    // Generate EdDSA R from all the ORKs publics
    const M_data_to_hash = ConcatUint8Arrays([gKn[0].compress(), StringToUint8Array(timestamp.toString()), StringToUint8Array(keyID)]);
    const M = await SHA256_Digest(M_data_to_hash);
    const R = mgORKi.reduce((sum, next) => sum.add(next)).add(R2);

    // Prepare the signature message
    const H_data_to_hash = ConcatUint8Arrays([R.compress(), gKntest[0].compress(), M]);
    const H = mod(BigIntFromByteArray(await SHA512_Digest(H_data_to_hash)), Point.order);

    // Verify signature validates
    if(!(Point.g.times(S).isEqual(R.add(gKntest[0].times(H))))) throw new Error("SetKeyValidation: Signature test failed");

    // Create Encrypted State list
    const encCommitStatei = setKeyResponses.map(resp => resp.EncCommitStatei);

    return {S: S, encCommitStatei: encCommitStatei};
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