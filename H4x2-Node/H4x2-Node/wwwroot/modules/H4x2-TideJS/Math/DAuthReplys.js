import Point from "../Ed25519/point.js";
import ConvertResponse from "../Models/ConvertResponse.js";
import { SHA256_Digest, SHA512_Digest } from "../Tools/Hash.js";
import { BigIntFromByteArray, ConcatUint8Arrays, StringToUint8Array, addSigtoJWT } from "../Tools/Utils.js";
import { createAESKey, decryptData } from "../Tools/AES.js"
import TranToken from "../Tools/TranToken.js";
import { GetLi } from "./SecretShare.js";

/**
 * @param {string} uid
 * @param {ConvertResponse[]} convertResponse 
 * @param {bigint} randomInv
 * @param {[string, string, Point][]} orks 
 */
export async function ConvertReply(uid, convertResponse, randomInv, orks) {
    const gPassPrism = convertResponse.map(a => a.GBlurPassPrism).reduce((sum, point) => sum.add(point), Point.infinity).times(randomInv);// li has already been multiplied above, so no need to do it here
    const gPRISMAuth = BigIntFromByteArray(await SHA256_Digest(gPassPrism.toArray()));

    const pre_prismAuths = orks.map(async ork => createAESKey(await SHA256_Digest(ork[2].times(gPRISMAuth).toArray()), ["encrypt", "decrypt"]));
    const prismAuths = await Promise.all(pre_prismAuths);

    const encryptedResponses = convertResponse.map(a => a.EncReply);

    const pre_decryptedResponses = encryptedResponses.map(async (cipher, i) => await decryptData(cipher, prismAuths[i]));
    const certTimes = (await Promise.all(pre_decryptedResponses)).map(a => TranToken.from(a));

    // functional function to append userID bytes to certTime bytes FAST
    const create_payload = (certTime_bytes) => {
        const newArray = new Uint8Array(Buffer.from(uid).length + certTime_bytes.length);
        newArray.set(Buffer.from(uid));
        newArray.set(certTime_bytes, Buffer.from(uid).length);
        return newArray // returns userID + certTime
    }
    const verifyi = certTimes.map((response, i) => new TranToken().sign(prismAuths[i], create_payload(response.toArray())));

    return [certTimes, verifyi];
}

/**
 * @param {string[]} preSingInCVKResponse
 * @param {bigint} Sesskey
 * @param {[string, string, Point][]} orks 
 */
export async function PreSignInCVKReply(preSingInCVKResponse, Sesskey, orks) {
    const pre_ECDHi = orks.map(async ork => (await SHA256_Digest(ork[2].times(Sesskey).toArray())));
    const ECDHi = await Promise.all(pre_ECDHi)
    // Calculate all lagrange coefficients for all the shards
    const ids = orks.map(ork => BigInt(ork[0]));
    const lis = ids.map(id => GetLi(id, ids, Point.order));

    const decrypted_gCVKRi = preSingInCVKResponse.map(async (enc_gCVKRi, i) => await decryptData(enc_gCVKRi, ECDHi[i]));
    const gCVKR = (await Promise.all(decrypted_gCVKRi)).map((gCVKRi, i) => Point.fromB64(gCVKRi).times(lis[i])).reduce((sum, p) => sum.add(p), Point.infinity);

    return { gCVKR: gCVKR, ECDHi: ECDHi };
}


/**
 * @param {string[]} singInCVKResponse
 * @param {Point} gCVKR
 * @param {string} jwt 
 * @param {[string, string, Point][]} orks 
 * @param { Uint8Array[]} ECDHi
 * @param {Point} cvkPub
 */
export async function SignInCVKReply(singInCVKResponse, gCVKR, jwt, orks, ECDHi, cvkPub) {
    // Calculate all lagrange coefficients for all the shards
    const ids = orks.map(ork => BigInt(ork[0]));
    const lis = ids.map(id => GetLi(id, ids, Point.order));

    const _8N = BigInt(8);
    const decrypted_Response = await singInCVKResponse.map(async (res, i) => await decryptData(res, ECDHi[i]));
    const CVKS = (await Promise.all(decrypted_Response)).map((CVKsigni, i) => BigIntFromByteArray(Buffer.from(CVKsigni, 'base64')) * (lis[i])).reduce((sum, p) => sum + p) % (Point.order);  // change later

    const H_cvk = BigIntFromByteArray(await SHA512_Digest(ConcatUint8Arrays([gCVKR.compress(), cvkPub.compress(), StringToUint8Array(jwt)])));

    if (!Point.g.times(CVKS).times(_8N).isEqual(gCVKR.times(_8N).add(cvkPub.times(H_cvk).times(_8N)))) { // everything good. JWT should verify
        return Promise.reject("Ork CVK Signature Invalid")
    }

    const finalJWT = addSigtoJWT(jwt, gCVKR, CVKS); // Need to fix this function (bigint.toArray())
    const finalPem = getPemPublic(cvkPub);

    /// IT WORKS! finalJWT can be verified by finalPem with ANY library out there that supports EdDSA!!!!

    return { tideJWT: finalJWT, cvkPubPem: finalPem };
}


/** 
 * @param {Point} point
 * @returns {string} 
 * */
function getPemPublic(point) {
    const header = Buffer.from("MCowBQYDK2VwAyEA", 'base64');
    const key = Buffer.from(point.compress());
    return Buffer.concat([header, key]).toString('base64');
}
