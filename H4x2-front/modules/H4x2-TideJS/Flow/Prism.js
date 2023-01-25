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
import { decryptData, encryptData } from "../Tools/AES.js"
import { SHA256_Digest } from "../Tools/Hash.js"
import { BigIntFromByteArray } from "../Tools/Utils.js"
import { RandomBigInt, mod, mod_inv, bytesToBase64 } from "../Tools/Utils.js"

export default class PrismFlow{
    /**
     * Config should include key/value pairs of: 
     * @example
     * {
     *  urls: string[]
     *  encryptedData: string[] <- Can be [] for setUp or ["xxxx"] for signle decryption or ["xxxx", "yyyyy"] for multi decryption
     * }
     * @example
     * @param {object} config 
     */
    constructor(config){
        if(!Object.hasOwn(config, 'urls')){ throw Error("Urls has not been included in config")}
        if(!Object.hasOwn(config, 'encryptedData')){ throw Error("EncryptedData has not been included in config")}
        
        /**
         * @type {string[]}
         */
        this.urls = config.urls
        /**
         * @type {string[]}
         */
        this.encryptedData = config.encryptedData
    }

    /**
     * Starts the Prism Flow to attempt to decrypt the supplied data with the given password.
     * NOTE: It will attempt to decrypt the data on both keyIds (Test and Prize)
     * * Requires config object to include urls and encryptedData
     * @param {string} pass The password to encrypt your data
     * @param {string} user
     * @returns {Promise<string>}
     */
    async run(user, pass){                                                                                                                                                                                                                                                                                
        const random = RandomBigInt();
        const uid = BigIntFromByteArray(await SHA256_Digest(user)).toString();
        const passwordPoint_R = (await Point.fromString(pass)).times(random); // password point * random
        const clients = this.urls.map(url => new NodeClient(url, "Prism")) // create node clients
        const appliedPoints = clients.map(client => client.Apply(uid, passwordPoint_R)); // get the applied points from clients

        var authPoint_R;
        try{
            authPoint_R = (await Promise.all(appliedPoints)).reduce((sum, next) => sum.add(next)); // sum all points returned from nodes
        }catch(err){
            return this.responseString("", err) // catch on TimeOut. This is messy but we really wanted to show timeout length to user
        }
        
        const authPoint = authPoint_R.times(mod_inv(random)); // remove the random to get the authentication point
        
        const keyToEncrypt = await SHA256_Digest(authPoint.toBase64()); // Hash the authentication point for added security

        var decrypted = null;
        var i;
        for(i = 0; i< this.encryptedData.length && decrypted == null; i++){
            try{
                decrypted = await decryptData(this.encryptedData[i], keyToEncrypt); // Attempt to decrypt the data with the authPoint as a base64 string (acting as password)
            }catch{
                decrypted = null;
            }
        }
        return this.responseString(decrypted);
    }

    /**
     * Encrypts the supplied data with the specified keyId held by the nodes.
     * * Requires config object to include url. EncryptedData of this object will be set following this function.
     * @param {string} pass The password to encrypt your data
     * @param {string} keyId The keyId the flow will target (Test or Prize)
     * @param {string} dataToEncrypt
     */
    async setUp(user, pass, keyId, dataToEncrypt){
        const random = RandomBigInt();
        const uid = BigIntFromByteArray(await SHA256_Digest(user)).toString();
        const passwordPoint_R = (await Point.fromString(pass)).times(random); // password point * random
        const clients = this.urls.map(url => new NodeClient(url, keyId)) // create node clients
        const appliedPoints = clients.map(client => client.Apply(uid, passwordPoint_R)); // get the applied points from clients

        var authPoint_R;
        try{
            authPoint_R = (await Promise.all(appliedPoints)).reduce((sum, next) => sum.add(next)); // sum all points returned from nodes
        }catch(err){
            return this.responseString(null, err) // catch on TimeOut. This is messy but we really wanted to show timeout length to user
        }
        const authPoint = authPoint_R.times(mod_inv(random)); // remove the random to get the authentication point

        const keyToEncrypt = await SHA256_Digest(authPoint.toBase64()); // Hash the authentication point for added security

        // Add encrypted data to existing array
        this.encryptedData.push(await encryptData(dataToEncrypt, keyToEncrypt)); // Use the hashed point as a key to encrypt the data
    }

    responseString(decryptedMessage, timeOut=null){
        if(decryptedMessage == null){return "Decryption failed"}
        else if(decryptedMessage === ""){return `Blocked: ${Math.floor(parseInt(timeOut)/60)} min`}
        else{return `Congratulations! | The code is... | ${decryptedMessage}`}
    }
}