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
import { Bytes2Hex } from "../Tools/Utils.js"
import VendorClient from "../Clients/VendorClient.js"

export default class SignUp{
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
    constructor(config){
        if(!Object.hasOwn(config, 'orkInfo')){ throw Error("OrkInfo has not been included in config")}
        if(!Object.hasOwn(config, 'simulatorUrl')){ throw Error("Simulator Url has not been included in config")}
        if(!Object.hasOwn(config, 'vendorUrl')){ throw Error("Vendor Url has not been included in config")}
        
        /**
         * @type {[string, Point][]}
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

    async start(username, password, secretCode){
        //hash username
        const uid = Bytes2Hex(await SHA256_Digest(username)).toString();
        //convert password to point
        const passwordPoint = (await Point.fromString(password));
        
        const prismFlow = new PrismFlow(this.orkInfo);
        const [encryptedCode, signedEntries] = await prismFlow.SetUp(uid, passwordPoint, secretCode);
        
        const entryFlow = new EntryFlow(this.simulatorUrl);
        await entryFlow.SubmitEntry(uid, signedEntries, this.orkInfo.map(ork => ork[0]))

        const vendorClient = new VendorClient(this.vendorUrl, uid);
        await vendorClient.AddToVendor(encryptedCode);
    }
}
