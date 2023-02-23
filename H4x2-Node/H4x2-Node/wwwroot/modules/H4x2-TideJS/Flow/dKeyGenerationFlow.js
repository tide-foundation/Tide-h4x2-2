import NodeClient from "../Clients/NodeClient.js";
import Point from "../Ed25519/point.js";
import { Commit_DecryptCVK, GenShardReply, PreCommitValidation, SetKeyReply } from "../Math/KeyGeneration.js";
import GenShardShare from "../Models/GenShardShare.js";

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
     * @param {Point[]} gMultiplier 
     */
    async GenShard(uid, numKeys, gMultiplier) {
        const clients = this.orks.map(ork => new NodeClient(ork[1])) // create node clients

        const ids = this.orks.map(ork => BigInt(ork[0]));
        const pre_GenShardResponses = clients.map(client => client.GenShard(uid, ids, numKeys, gMultiplier));
        const GenShardResponses = await Promise.all(pre_GenShardResponses);

        return GenShardReply(GenShardResponses);
    }

    /**
     * @param {string} uid 
     * @param {GenShardShare[][]} YijCipher 
     */
    async SetKey(uid, YijCipher) {
        const clients = this.orks.map(ork => new NodeClient(ork[1])) // create node clients

        const pre_SetKeyResponses = clients.map((client, i) => client.SetKey(uid, YijCipher[i]))
        const SetKeyResponses = await Promise.all(pre_SetKeyResponses);

        return SetKeyReply(SetKeyResponses, this.orks.map(ork => ork[0]));
    }

    /**
     * @param {string} uid
     * @param {Point[]} gKntest 
     * @param {Point} gK
     * @param {Point} R2 
     * @param {string[]} EncSetKeyStatei 
     * @param {number} timestamp
     * @param {Point[]} mgORKi
     */
    async PreCommit(uid, gKntest, gK, R2, EncSetKeyStatei, timestamp, mgORKi) {
        const clients = this.orks.map(ork => new NodeClient(ork[1])) // create node clients

        const pre_PreCommitResponses = clients.map((client, i) => client.PreCommit(uid, gKntest, R2, EncSetKeyStatei[i]));
        const PreCommitResponses = await Promise.all(pre_PreCommitResponses);

        return await PreCommitValidation(PreCommitResponses, uid, gK, gKntest[0], timestamp, mgORKi, R2);
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
}