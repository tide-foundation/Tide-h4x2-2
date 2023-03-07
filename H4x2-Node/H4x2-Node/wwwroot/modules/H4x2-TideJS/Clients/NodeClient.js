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
import GenShardResponse from "../Models/GenShardResponse.js";
import SetKeyResponse from "../Models/SetKeyResponse.js";
import ClientBase from "./ClientBase.js"
import TranToken from "../Tools/TranToken.js";
import SendShardResponse from "../Models/SendShardResponse.js";

export default class NodeClient extends ClientBase {
    /**
     * @param {string} url
     */
    constructor(url) {
        super(url)
    }

    /**
     * @param {Point} point
     * @param {string} uid 
     * @returns {Promise<Point>}
     */
    async ApplyPRISM(uid, point) {
        const data = this._createFormData({ 'point': point.toBase64() })
        var response;
        try {
            response = await this._post(`/Apply/Prism?uid=${uid}`, data)
        } catch {
            return Promise.reject("You account's ORKs are down !")
        }
        const responseData = await this._handleError(response, "Apply Prism");
        const resp_obj = JSON.parse(responseData);
        return Point.fromB64(resp_obj.applied);

    }

    /**
     * @param {string} authData
     * @param {string} uid 
     * @returns {Promise<string>}
     */
    async ApplyAuthData(uid, authData) {
        const data = this._createFormData({ 'authData': authData })
        const response = await this._post(`/Apply/AuthData?uid=${uid}`, data)

        const responseData = await this._handleError(response, "Apply AuthData");
        const resp_obj = JSON.parse(await responseData);
        return resp_obj.encryptedCVK;;
    }

    /**
     * @param {string} uid
     * @param {bigint[]} mIdORKij
     * @param {number} numKeys
     * @returns {Promise<GenShardResponse>}
     */
    async GenShard(uid, mIdORKij, numKeys) {
        const data = this._createFormData(
            {
                'mIdORKij': mIdORKij.map(n => n.toString()),
                'numKeys': numKeys
            }
        );
        const response = await this._post(`/Create/GenShard?uid=${uid}`, data);

        const responseData = await this._handleError(response, "GenShard");
        return GenShardResponse.from(responseData);
    }

    /**
     * @param {string} uid 
     * @param {string[]} shares 
     * @param {string[][]} gKnCiphers
     * @param {Point[]} gMultipliers
     */
    async SendShard(uid, shares, gKnCiphers, gMultipliers) {
        const data = this._createFormData(
            { 
                'yijCipher': shares, 
                'gKnCipher': gKnCiphers,
                'gMultipliers': gMultipliers.map(p => p == null ? "" : p.toBase64())
            });
        const response = await this._post(`/Create/SendShard?uid=${uid}`, data);

        const responseData = await this._handleError(response, "SendShard");
        return SendShardResponse.from(responseData);
    }

    /**
     * @param {string} uid
     * @param {Point[]} gKntest 
     * @param {Point} R2  
     * @param {string[]} ephKeyj
     */
    async SetKey(uid, gKntest, R2, ephKeyj) {
        const data = this._createFormData(
            {
                'gKntesti': gKntest.map(gKtest => gKtest.toBase64()),
                'R2': R2.toBase64(),
                'ephKeyj': ephKeyj
            }
        );
        const response = await this._post(`/Create/SetKey?uid=${uid}`, data);
        const responseData = await this._handleError(response, "SetKey");   
        return SetKeyResponse.from(responseData)
    }


    /**
     * @param {string} uid 
     * @param {bigint} S 
     * @param {string} EncCommitStatei 
     * @param {Point} gPrismAuth
     */
    async Commit(uid, S, EncCommitStatei, gPrismAuth) {
        const data = this._createFormData(
            {
                'S': S.toString(),
                'EncCommitStatei': EncCommitStatei,
                'gPrismAuth': gPrismAuth.toBase64()
            }
        );
        const response = await this._post(`/Create/Commit?uid=${uid}`, data);
        const responseData = await this._handleError(response, "Commit");
        //if(responseData !== "Account Created") Promise.reject("Commit: Accound creation failed"); For later
        return responseData;
    }

    /** 
     * @param {string} uid
     * @param { string } state
     * @param { TranToken } certTimei
     * @param { TranToken } verifyi
     * @param { Point } gPRISMtest
     * @param {Point} gPrismAuth
     *  @returns {Promise<string>} 
    */
    async CommitPrism(uid, state, certTimei, verifyi, gPRISMtest, gPrismAuth) {
        const data = this._createFormData(
            {
                'gPRISMtest': gPRISMtest.toBase64(),
                'gPRISMAuth': gPrismAuth.toBase64(),
                'state': state
            }
        );
        const response = await this._put(`/Apply/CommitPrism?uid=${uid}&certTimei=${certTimei}&token=${verifyi}`, data);
        const responseData = await this._handleError(response, "CommitPrism");
        return responseData;
    }
}