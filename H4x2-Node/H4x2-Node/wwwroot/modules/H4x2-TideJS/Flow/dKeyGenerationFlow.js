import NodeClient from "../Clients/NodeClient.js";
import Point from "../Ed25519/point.js";
import { Commit_DecryptCVK, GenShardReply, PreCommitValidation, SetKeyReply } from "../Math/KeyGeneration.js";
import TranToken from "../Tools/TranToken.js";
import ApplyResponseDecrypted from "../Models/ApplyResponseDecrypted.js";

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
     * @param {string[][]} YijCipher 
     */
    async SetKey(uid, YijCipher) {
        const clients = this.orks.map(ork => new NodeClient(ork[1])) // create node clients

        const pre_SetKeyResponses = clients.map((client, i) => client.SetKey(uid, YijCipher[i]))
        const SetKeyResponses = await Promise.all(pre_SetKeyResponses);

        return SetKeyReply(SetKeyResponses, this.orks.map(ork => ork[0]));
    }

    /**
     * @param {string} uid
     * @param {Point[][]} gKntesti 
     * @param {string[]} gKsigni
     * @param {Point} gKtest1
     * @param {Point} gK
     * @param {Point} R2 
     * @param {number} timestamp
     * @param {Point[]} mgORKi
     * @param {string[]} state_ids
     */
    async PreCommit(uid, gKntesti, gKsigni, gKtest1, gK, R2, timestamp, mgORKi, state_ids) {
        const clients = this.orks.map(ork => new NodeClient(ork[1])) // create node clients

        const pre_PreCommitResponses = clients.map((client, i) => client.PreCommit(uid, gKntesti, gKsigni, R2, state_ids[i]));
        const PreCommitResponses = await Promise.all(pre_PreCommitResponses);

        return await PreCommitValidation(PreCommitResponses, uid, gK, gKtest1, timestamp, mgORKi, R2);
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


        return await Commit_DecryptCVK(prismAuthi, CommitResponses);
    }

    /**
     * @param {string} uid
     * @param {Point} gPRISMtest
     * @param {string[]} state
     * @param {ApplyResponseDecrypted[]} decryptedResponses
     * @param {Point} gPrismAuth
     * @param {TranToken[]} verifyi
     */
    async CommitPrism(uid, gPRISMtest, state, decryptedResponses, gPrismAuth, verifyi) {
        const clients = this.orks.map(ork => new NodeClient(ork[1])) // create node clients

        await clients.map((client, i) => client.CommitPrism(uid, state[i], decryptedResponses[i].certTime, verifyi[i], gPRISMtest, gPrismAuth));
    }
}