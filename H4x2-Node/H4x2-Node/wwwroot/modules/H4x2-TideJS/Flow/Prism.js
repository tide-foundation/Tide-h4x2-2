// 
// Tide Protocol - Infrastructure for a TRUE Zero-Trust paradigm
// Copyright (C) 2022 Tide Foundation Ltd
// 
// This program is free software and is subject to the terms of 
// the Tide Community Open Code License as published by the 
// Tide Foundation Limited. You may modify it and redistribute 
// it in accordance with and subject to the terms of that License.
// This program is distributed WITHOUT WARRANTY of any kind, 
// including without any implied warranty of MERCHANTABILITY or 
// FITNESS FOR A PARTICULAR PURPOSE.
// See the Tide Community Open Code License for more details.
// You should have received a copy of the Tide Community Open 
// Code License along with this program.
// If not, see https://tide.org/licenses_tcoc2-0-0-en
//


import NodeClient from "../Clients/NodeClient.js"
import Point from "../Ed25519/point.js"
import { createAESKey, decryptData, encryptData } from "../Tools/AES.js"
import { SHA256_Digest } from "../Tools/Hash.js"
import { BigIntFromByteArray, BigIntToByteArray } from "../Tools/Utils.js"
import { RandomBigInt, mod, mod_inv, bytesToBase64 } from "../Tools/Utils.js"
import DAuthFlow from "./DAuthFlow.js"
import { Bytes2Hex } from "../Tools/Utils.js"
import { GenShardReply } from "../Math/KeyGeneration.js"
import dKeyGenerationFlow from "./dKeyGenerationFlow.js"

export default class PrismFlow {

    /**
     * @param {[string, string, Point][]} orks 
     */
    constructor(orks) {
        /**
         * @type {[string, string, Point][]}  // everything about orks of this user - orkID, orkURL, orkPublic
         */
        this.orks = orks;
    }

    /**
     * Starts the Prism Flow to attempt to decrypt the supplied data with the given password
     * @param {Point} passwordPoint The password of a user
     * @param {string} uid The username of a user
     * @returns {Promise<bigint>}
     */
    async Authenticate(uid, passwordPoint) {
        const random = RandomBigInt();
        const passwordPoint_R = passwordPoint.times(random); // password point * random
        const clients = this.orks.map(ork => new NodeClient(ork[1])) // create node clients

        const pre_appliedPoints = clients.map(client => client.ApplyPRISM(uid, passwordPoint_R)); // appllied responses consist of [encryptedState, appliedPoint][]
        const keyPoint_R = (await Promise.all(pre_appliedPoints)).reduce((sum, next) => sum.add(next));
        const hashed_keyPoint = BigIntFromByteArray(await SHA256_Digest(keyPoint_R.times(mod_inv(random)).toBase64())); // remove the random to get the authentication point

        const pre_prismAuthi = this.orks.map(async ork => createAESKey(await SHA256_Digest(ork[2].times(hashed_keyPoint).toArray()), ["encrypt", "decrypt"])) // create a prismAuthi for each ork
        const prismAuthi = await Promise.all(pre_prismAuthi); // wait for all async functions to finish
        const pre_authDatai = prismAuthi.map(async prismAuth => await encryptData("Authenticated", prismAuth)); // construct authData to authenticate to orks
        const authDatai = await Promise.all(pre_authDatai);

        const pre_encryptedCVKs = clients.map((client, i) => client.ApplyAuthData(uid, authDatai[i])); // authenticate to ORKs and retirve CVK
        const encryptedCVKs = await Promise.all(pre_encryptedCVKs);
        const pre_CVKs = encryptedCVKs.map(async (encCVK, i) => await decryptData(encCVK, prismAuthi[i])); // decrypt CVKs with prismAuth of each ork
        const CVK = (await Promise.all(pre_CVKs)).map(cvk => BigInt(cvk)).reduce((sum, next) => mod(sum + next)); // sum all CVKs to find full CVK
        return CVK;
    }

    /**
     * To be used for account creation. This flow creates an account with the orks, and returns the required data
     * for the simulator and vendor.
     * @param {Point} passwordPoint The password of a user
     * @param {string} uid The username of a user
     * @param {string} dataToEncrypt
     * @returns {Promise<[string, string[]]>}
     */
    async SetUp(uid, passwordPoint, dataToEncrypt) {
        const random = RandomBigInt();
        const passwordPoint_R = passwordPoint.times(random); // password point * random
        const clients = this.orks.map(ork => new NodeClient(ork[1])) // create node clients
        const pre_createPRISMResponses = clients.map(client => client.CreatePRISM(uid, passwordPoint_R)); // appllied responses consist of [encryptedState, appliedPoint][]
        const createPRISMResponses = await Promise.all(pre_createPRISMResponses);

        const keyPoint_R = createPRISMResponses.map(p => p[1]).reduce((sum, next) => sum.add(next)); // sum all points returned from nodes
        const hashed_keyPoint = BigIntFromByteArray(await SHA256_Digest(keyPoint_R.times(mod_inv(random)).toBase64())); // remove the random to get the authentication point

        const pre_prismAuthi = this.orks.map(async ork => createAESKey(await SHA256_Digest(ork[2].times(hashed_keyPoint).toArray()), ["encrypt", "decrypt"])) // create a prismAuthi for each ork
        const prismAuthi = await Promise.all(pre_prismAuthi); // wait for all async functions to finish
        const prismPub = Point.g.times(hashed_keyPoint); // its like a DiffieHellman, so we can get PrismAuth to the ORKs, while keeping keyPoint secret

        const encryptedStateList = createPRISMResponses.map(resp => resp[0]);
        const pre_createAccountResponses = clients.map((client, i) => client.CreateAccount(uid, prismPub, encryptedStateList[i])); // request orks to create your account
        const createAccountResponses = await Promise.all(pre_createAccountResponses);

        const pre_CVKs = createAccountResponses.map(async (resp, i) => await decryptData(resp[0], prismAuthi[i])); // decrypt CVKs with prismAuth of each ork
        const CVK = (await Promise.all(pre_CVKs)).map(cvk => BigInt(cvk)).reduce((sum, next) => mod(sum + next)); // sum all CVKs to find full CVK
        const encryptedCode = await encryptData(dataToEncrypt, BigIntToByteArray(CVK)); // the secretCode encrypted by the CVK - will be sent to vendor
        const signedEntries = createAccountResponses.map(sig => sig[1]); // the proof each ork created this user. will be sent to simulator
        return [encryptedCode, signedEntries];
    }


    /**
     * @param {Point} passwordPoint_R The password of a user
     * @param {bigint} random
     */
    async GetPrismAuths(passwordPoint_R, random) {
        const keyPoint = passwordPoint_R.times(mod_inv(random));
        const hashed_keyPoint = BigIntFromByteArray(await SHA256_Digest(keyPoint.toBase64())); // remove the random to get the authentication point
        const pre_prismAuthi = this.orks.map(async ork => createAESKey(await SHA256_Digest(ork[2].times(hashed_keyPoint).toArray()), ["encrypt", "decrypt"])) // create a prismAuthi for each ork
        const prismAuthi = await Promise.all(pre_prismAuthi); // wait for all async functions to finish
        return prismAuthi;
    }

    /**
     * @param {Point} passwordPoint_R The password of a user
     * @param {bigint} random
     */
    async GetGPrismAuth(passwordPoint_R, random) {
        const keyPoint = passwordPoint_R.times(mod_inv(random));
        const hashed_keyPoint = BigIntFromByteArray(await SHA256_Digest(keyPoint.toBase64())); // remove the random to get the authentication point
        const gPrismAuth = Point.g.times(hashed_keyPoint); // its like a DiffieHellman, so we can get PrismAuth to the ORKs, while keeping keyPoint secret
        return gPrismAuth;
    }

    responseString(decryptedMessage, timeOut = null) {
        if (decryptedMessage == null) { return "Decryption failed" }
        else if (decryptedMessage === "") { return `Blocked: ${Math.floor(parseInt(timeOut) / 60)} min` }
        else { return `Congratulations! | The code is... | ${decryptedMessage}` }
    }
}