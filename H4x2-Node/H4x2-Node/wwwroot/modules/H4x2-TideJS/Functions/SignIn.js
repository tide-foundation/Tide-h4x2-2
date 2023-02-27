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
import { BigIntToByteArray, Bytes2Hex, getCSharpTime } from "../Tools/Utils.js"
import SimulatorClient from "../Clients/SimulatorClient.js"
import VendorClient from "../Clients/VendorClient.js"
import DAuthFlow from "../Flow/DAuthFlow.js"
import NodeClient from "../Clients/NodeClient.js"

export default class SignIn {
    /**
     * Config should include key/value pairs of: 
     * @example
     * {
     *  simulatorUrl: string
     *  vendorUrl: string
     * }
     * @example
     * @param {object} config 
     */
    constructor(config) {
        if (!Object.hasOwn(config, 'simulatorUrl')) { throw Error("Simulator Url has not been included in config") }
        if (!Object.hasOwn(config, 'vendorUrl')) { throw Error("Vendor Url has not been included in config") }

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
     * Authenticates a user to the ORKs and decrypts their encrypted secret held by vendor.
     * @param {string} username 
     * @param {string} password 
     */
    async start(username, password) {
        //hash username
        const uid = Bytes2Hex(await SHA256_Digest(username)).toString();
        //convert password to point
        const passwordPoint = (await Point.fromString(password));

        // get ork urls
        const simClient = new SimulatorClient(this.simulatorUrl);
        const orkInfo = await simClient.GetUserORKs(uid);

        const startTimer = getCSharpTime(Date.now());

        const clients = new DAuthFlow(orkInfo)
        const [certimes, verifyi] = await clients.DoConvert(uid, passwordPoint);

        await clients.SignInCVK(uid, certimes, startTimer);

        await clients.Authenticate(uid, certimes, verifyi);
    }
}
