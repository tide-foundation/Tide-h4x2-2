import NodeClient from "../Clients/NodeClient.js";
import Point from "../Ed25519/point.js";
import { Commit_DecryptCVK, GenShardReply, SendShardReply, SetKeyValidation } from "../Math/KeyGeneration.js";
import SetKeyResponse from "../Models/SetKeyResponse.js";
import TranToken from "../Tools/TranToken.js";

export default class dKeyGenerationFlow {
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
     * @param {string} uid 
     * @param {number} numKeys 
     */
    async GenShard(uid, numKeys) {
        const clients = this.orks.map(ork => new NodeClient(ork[1])) // create node clients

        const ids = this.orks.map(ork => BigInt(ork[0]));
        const pre_GenShardResponses = clients.map(client => client.GenShard(uid, ids, numKeys));
        const GenShardResponses = await Promise.all(pre_GenShardResponses);

        return GenShardReply(GenShardResponses);
    }

    /**
     * @param {string} uid 
     * @param {string[][]} YijCipher 
     * @param {string[][]} gKnCipher
     * @param {Point[]} gMultipliers
     */
    async SendShard(uid, YijCipher, gKnCipher, gMultipliers) {
        const clients = this.orks.map(ork => new NodeClient(ork[1])) // create node clients

        const pre_SendShardResponses = clients.map((client, i) => client.SendShard(uid, YijCipher[i], gKnCipher[i], gMultipliers))
        const SendShardResponses = await Promise.all(pre_SendShardResponses);

        return SendShardReply(SendShardResponses, this.orks.map(ork => ork[0]), gKnCipher);
    }

    /**
     * @param {string} uid
     * @param {Point[]} gKntest 
     * @param {Point[]} gKn
     * @param {Point} R2 
     * @param {number} timestamp
     * @param {Point[]} mgORKi
     * @param {string[]} ephKeyj
     */
    async SetKey(uid, gKntest, gKn, R2, timestamp, mgORKi, ephKeyj) {
        const clients = this.orks.map(ork => new NodeClient(ork[1])) // create node clients

        const pre_setKeyResponses = clients.map((client, i) => client.SetKey(uid, gKntest, R2, ephKeyj));
        const SetKeyResponses = await Promise.all(pre_setKeyResponses);

        return await SetKeyValidation(SetKeyResponses, uid, gKn, gKntest, timestamp, mgORKi, R2);
    }

    /**
     * @param {string} uid
     * @param {bigint} S 
     * @param {string[]} EncSetKeyStatei 
     * @param {CryptoKey[]} prismAuthi
     * @param {Point} gPRISMAuth
     */
    async Commit(uid, S, EncSetKeyStatei, prismAuthi, gPRISMAuth) {
        const clients = this.orks.map(ork => new NodeClient(ork[1])) // create node clients

        const pre_CommitResponses = clients.map((client, i) => client.Commit(uid, S, EncSetKeyStatei[i], gPRISMAuth));
        const CommitResponses = await Promise.all(pre_CommitResponses);


        return await Commit_DecryptCVK(prismAuthi, CommitResponses);
    }

    /**
      * @param {string} uid
      * @param {Point} gPRISMtest
      * @param {string[]} state
      * @param {TranToken[]} certimes
      * @param {Point} gPrismAuth
      * @param {TranToken[]} verifyi
      */
    async CommitPrism(uid, gPRISMtest, state, certimes, gPrismAuth, verifyi) {
        const clients = this.orks.map(ork => new NodeClient(ork[1])) // create node clients

        await clients.map((client, i) => client.CommitPrism(uid, state[i], certimes[i], verifyi[i], gPRISMtest, gPrismAuth));
    }
}