import NodeClient from "../Clients/NodeClient.js";
import Point from "../Ed25519/point.js";
import { Commit_DecryptCVK, GenShardReply, SendShardReply } from "../Math/KeyGeneration.js";

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
     * @param {Point} R2
     * @param {Point[]} gMultipliers
     * @param {bigint} timestamp
     */
    async SendShard(uid, YijCipher, R2, gMultipliers, timestamp) {
        const clients = this.orks.map(ork => new NodeClient(ork[1])) // create node clients

        const pre_SendShardResponses = clients.map((client, i) => client.SendShard(uid, YijCipher[i], R2, gMultipliers))
        const SendShardResponses = await Promise.all(pre_SendShardResponses);

        return SendShardReply(uid, SendShardResponses, this.orks.map(ork => ork[2]), timestamp, R2);
    }

    /**
     * @param {string} uid
     * @param {bigint} S 
     * @param {string[]} EncCommitStatei 
     * @param {CryptoKey[]} prismAuthi
     * @param {Point} gPRISMAuth
     */
    async Commit(uid, S, EncCommitStatei, prismAuthi, gPRISMAuth) {
        const clients = this.orks.map(ork => new NodeClient(ork[1])) // create node clients

        const pre_CommitResponses = clients.map((client, i) => client.Commit(uid, S, EncCommitStatei[i], gPRISMAuth));
        const CommitResponses = await Promise.all(pre_CommitResponses);


        return await Commit_DecryptCVK(prismAuthi, CommitResponses, this.orks.map(ork => ork[0]));
    }
}