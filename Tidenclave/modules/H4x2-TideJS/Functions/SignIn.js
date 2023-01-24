import Point from "../Ed25519/point.js"
import EntryFlow from "../Flow/EntryFlow.js"
import PrismFlow from "../Flow/Prism.js"
import { SHA256_Digest } from "../Tools/Hash.js"
import { BigIntFromByteArray, BigIntToByteArray, Bytes2Hex } from "../Tools/Utils.js"
import SimulatorClient from "../Clients/SimulatorClient.js"
import VendorClient from "../Clients/VendorClient.js"
import { decryptData } from "../Tools/AES.js"

export default class SignIn{
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
    constructor(config){
        if(!Object.hasOwn(config, 'simulatorUrl')){ throw Error("Simulator Url has not been included in config")}
        if(!Object.hasOwn(config, 'vendorUrl')){ throw Error("Vendor Url has not been included in config")}
        
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
     * @returns {Promise<string>}
     */
    async start(username, password){
        //hash username
        const uid = Bytes2Hex(await SHA256_Digest(username)).toString();
        //convert password to point
        const passwordPoint = (await Point.fromString(password));

        // get ork urls
        const simClient = new SimulatorClient(this.simulatorUrl);
        const orkInfo = await simClient.GetUserORKs(uid);
        
        const prismFlow = new PrismFlow(orkInfo);
        const CVK = await prismFlow.Authenticate(uid, passwordPoint);

        const vendorClient = new VendorClient(this.vendorUrl, uid);
        const encryptedCode = await vendorClient.GetUserCode();

        return await decryptData(encryptedCode, BigIntToByteArray(CVK));
    }
}
