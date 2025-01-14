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
import ClientBase from "./ClientBase.js"
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
        const response = await this._post(`/Apply/Prism?uid=${uid}`, data)
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
     * @param {Point} R2
     * @param {Point[]} gMultipliers
     */
    async SendShard(uid, shares, R2, gMultipliers) {
        const data = this._createFormData(
            { 
                'yijCipher': shares, 
                'R2': R2.toBase64(),
                'gMultipliers': gMultipliers.map(p => p == null ? "" : p.toBase64())
            });
        const response = await this._post(`/Create/SendShard?uid=${uid}`, data);

        const responseData = await this._handleError(response, "SendShard");
        return SendShardResponse.from(responseData);
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
}