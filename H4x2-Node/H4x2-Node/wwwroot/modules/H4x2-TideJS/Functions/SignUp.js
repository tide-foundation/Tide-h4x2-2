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
import EntryFlow from "../Flow/EntryFlow.js"
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
     *  orkInfo: [string, Point][]
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

    async start(username, password, secretCode) {
        //hash username
        const uid = Bytes2Hex(await SHA256_Digest(username)).toString();
        //convert password to point
        const passwordPoint = (await Point.fromString(password));

        const random = RandomBigInt();
        const passwordPoint_R = passwordPoint.times(random); // password point * random

        // Start Key Generation Flow
        const KeyGenFlow = new dKeyGenerationFlow(this.orkInfo);
        const {gK: gCVK, gMultiplied, sortedShares, timestamp} = await KeyGenFlow.GenShard(uid, 2, [null, passwordPoint_R]);  // GenShard
        
        // Do Prism Flow
        const prismFlow = new PrismFlow(this.orkInfo);
        const gPRISMAuth = await prismFlow.GetGPrismAuth(gMultiplied[1], random); // there are some redundant calcs by calling these functions serpately
        const prismAuthi = await prismFlow.GetPrismAuths(gMultiplied[1], random); // but later on, we'll only need one or the other, so i'm keeping them seperate

        // Resume Key Generation Flow 
        const {gKntest, R2, gKsigni, gKntesti, state_ids} = await KeyGenFlow.SetKey(uid, sortedShares);                                    // SetKey
        const {S, encCommitStatei} = await KeyGenFlow.PreCommit(uid, gKntesti, gKsigni, gKntest[0], gCVK, R2, timestamp, this.orkInfo.map(ork => ork[2]), state_ids); 
        const CVK = await KeyGenFlow.Commit(uid, S, encCommitStatei, prismAuthi, gPRISMAuth)
        const encryptedCode = await encryptData(secretCode, BigIntToByteArray(CVK));

        // Vendor flow
    }
}
