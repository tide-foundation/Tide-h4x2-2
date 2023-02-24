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

import PrismFlow from "../Flow/Prism.js"
import { SHA256_Digest } from "../Tools/Hash.js"
import Point from "../Ed25519/point.js"
import { Bytes2Hex, RandomBigInt } from "../Tools/Utils.js"
import dKeyGenerationFlow from "../Flow/dKeyGenerationFlow.js"
import DAuthFlow from "../Flow/DAuthFlow.js"

export default class ChangePassword {
    /**
     * Config should include key/value pairs of: 
     * @example
     * {
     *  orkInfo: [string, string, Point][]
     * }
     * @example
     * @param {object} config 
     */
    constructor(config) {
        if (!Object.hasOwn(config, 'orkInfo')) { throw Error("OrkInfo has not been included in config") }

        /**
         * @type {[string, string, Point][]}
         */
        this.orkInfo = config.orkInfo
    }


    /**
     * To be used for change password. 
     * @param {string} username 
     * @param {string} password 
     * @param {string} newpassword
     */
    async start(username, password, newpassword) {
        //hash username
        const uid = Bytes2Hex(await SHA256_Digest(username)).toString();
        //convert password to point
        const passwordPoint = (await Point.fromString(password));

        const clients = new DAuthFlow(this.orkInfo)
        const [decryptedResponses, verifyi] = await clients.DoConvert(uid, passwordPoint);

        //convert new password to point
        const newPasswordPoint = (await Point.fromString(newpassword));
        const random = RandomBigInt();
        const newPasswordPoint_R = newPasswordPoint.times(random); // new password point * random

        // Start Key Generation Flow
        const KeyGenFlow = new dKeyGenerationFlow(this.orkInfo);
        const { gK: gCVK, gMultiplied, sortedShares, timestamp } = await KeyGenFlow.GenShard(uid, 1, [null, newPasswordPoint_R]);  // GenShard
        // Do Prism Flow
        const prismFlow = new PrismFlow(this.orkInfo);
        const gPRISMAuth = await prismFlow.GetGPrismAuth(gMultiplied[1], random); // there are some redundant calcs by calling these functions serpately
        // Resume Key Generation Flow 
        const { gKntest, R2, EncSetKeyStatei } = await KeyGenFlow.SetKey(uid, sortedShares);                            // SetKey
        await KeyGenFlow.CommitPrism(uid, gKntest[0], EncSetKeyStatei, decryptedResponses, gPRISMAuth, verifyi);       // CommitPrism
    }
}
