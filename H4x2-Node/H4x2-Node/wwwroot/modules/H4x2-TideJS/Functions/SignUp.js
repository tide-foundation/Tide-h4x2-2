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

import Point from "../Ed25519/point.js"
import PrismFlow from "../Flow/Prism.js"
import { SHA256_Digest } from "../Tools/Hash.js"
import VendorClient from "../Clients/VendorClient.js"
import { BigIntFromByteArray, BigIntToByteArray, Bytes2Hex, mod_inv, RandomBigInt } from "../Tools/Utils.js"
import dKeyGenerationFlow from "../Flow/dKeyGenerationFlow.js"
import { createAESKey, encryptData } from "../Tools/AES.js"

export default class SignUp {
    /**
     * Config should include key/value pairs of: 
     * @example
     * {
     *  orkInfo: [string, string Point][]
     *  simulatorUrl: string  
     *  vendorUrl: string
     * }
     * @example
     * @param {object} config 
     */
    constructor(config) {
        if (!Object.hasOwn(config, 'orkInfo')) { throw Error("OrkInfo has not been included in config") }
        if (!Object.hasOwn(config, 'simulatorUrl')) { throw Error("Simulator Url has not been included in config") }
        if (!Object.hasOwn(config, 'vendorUrl')) { throw Error("Vendor Url has not been included in config") }

        /**
         * @type {[string, string, Point][]}
         */
        this.orkInfo = config.orkInfo
        /**
         * @type {string}
         */
        this.simulatorUrl = config.simulatorUrl
        /**
         * @type {string}
         */
        this.vendorUrl = config.vendorUrl
    }

    /**
     * 
     * @param {string} username 
     * @param {string} password 
     * @param {string} secretCode 
     */
    async start(username, password, secretCode) {
        //hash username
        const uid = Bytes2Hex(await SHA256_Digest(username.toLowerCase())).toString();
        //convert password to point
        const passwordPoint = (await Point.fromString(password));

        const random = RandomBigInt();
        const passwordPoint_R = passwordPoint.times(random); // password point * random

        // Start Key Generation Flow
        const KeyGenFlow = new dKeyGenerationFlow(this.orkInfo);
        const {sortedShares, timestamp, R2} = await KeyGenFlow.GenShard(uid, 2);  // GenShard
        const {S, encCommitStatei, gMultiplied} = await KeyGenFlow.SendShard(uid, sortedShares, R2, [null, passwordPoint_R], timestamp);   
        
        // Do Prism Flow
        const prismFlow = new PrismFlow(this.orkInfo);
        const gPRISMAuth = await prismFlow.GetGPrismAuth(gMultiplied[1], random); // there are some redundant calcs by calling these functions serpately
        const prismAuthi = await prismFlow.GetPrismAuths(gMultiplied[1], random); // but later on, we'll only need one or the other, so i'm keeping them seperate

        // Resume Key Generation Flow 
        const CVK = await KeyGenFlow.Commit(uid, S, encCommitStatei, prismAuthi, gPRISMAuth)
        const encryptedCode = await encryptData(secretCode, BigIntToByteArray(CVK));

        // Vendor Flow 
        const vendorClient = new VendorClient(this.vendorUrl, uid);
        await vendorClient.AddToVendor(encryptedCode);
    }

    /**
     * A function for just signing up to tide. Meant for the Heimdall SDK.
     * @param {string} username 
     * @param {string} password 
     */
    async start_Heimdall(username, password) {
        //hash username
        const uid = Bytes2Hex(await SHA256_Digest(username.toLowerCase())).toString();
        //convert password to point
        const passwordPoint = (await Point.fromString(password));

        const random = RandomBigInt();
        const passwordPoint_R = passwordPoint.times(random); // password point * random

        // Start Key Generation Flow
        const KeyGenFlow = new dKeyGenerationFlow(this.orkInfo);
        const {sortedShares, timestamp, R2} = await KeyGenFlow.GenShard(uid, 2);  // GenShard
        const {S, encCommitStatei, gMultiplied} = await KeyGenFlow.SendShard(uid, sortedShares, R2, [null, passwordPoint_R], timestamp);   
        
        // Do Prism Flow
        const prismFlow = new PrismFlow(this.orkInfo);
        const gPRISMAuth = await prismFlow.GetGPrismAuth(gMultiplied[1], random); // there are some redundant calcs by calling these functions serpately
        const prismAuthi = await prismFlow.GetPrismAuths(gMultiplied[1], random); // but later on, we'll only need one or the other, so i'm keeping them seperate

        // Resume Key Generation Flow 
        const CVK = await KeyGenFlow.Commit(uid, S, encCommitStatei, prismAuthi, gPRISMAuth)

        return {CVK: CVK, UID: uid}
    }
}
