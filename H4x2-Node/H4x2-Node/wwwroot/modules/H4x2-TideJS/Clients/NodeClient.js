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
import PreCommitResponse from "../Models/PreCommitResponse.js";

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
     * @param {Point} point
     * @param {string} uid 
     * @returns {Promise<[string, Point]>}
     */
    async CreatePRISM(uid, point) {
        const data = this._createFormData({ 'point': point.toBase64() })
        const response = await this._post(`/Create/Prism?uid=${uid}`, data)

        const responseData = await this._handleError(response, "Create Prism");
        const resp_obj = JSON.parse(responseData);
        return [resp_obj.encryptedState, Point.fromB64(resp_obj.point)];
    }

    /**
     * @param {string} uid
     * @param {Point} prismPub 
     * @param {string} encryptedState 
     * @returns {Promise<[string, string]>}
     */
    async CreateAccount(uid, prismPub, encryptedState) {
        const data = this._createFormData({ 'prismPub': prismPub.toBase64(), 'encryptedState': encryptedState })
        const response = await this._post(`/Create/Account?uid=${uid}`, data);

        const responseData = await this._handleError(response, "Create Account");
        const resp_obj = JSON.parse(responseData);
        return [resp_obj.encryptedCVK, resp_obj.signedUID]
    }

    /**
     * @param {string} uid
     * @param {bigint[]} mIdORKij
     * @param {number} numKeys
     * @param {Point[]} gMultiplier
     * @returns {Promise<GenShardResponse>}
     */
    async GenShard(uid, mIdORKij, numKeys, gMultiplier) {
        const data = this._createFormData(
            {
                'mIdORKij': mIdORKij.map(n => n.toString()),
                'numKeys': numKeys,
                'gMultiplier': gMultiplier.map(p => p == null ? null : p.toBase64())
            }
        );
        const response = await this._post(`/Create/GenShard?uid=${uid}`, data);

        const responseData = await this._handleError(response, "GenShard");
        return GenShardResponse.from(responseData);
    }

    /**
     * @param {string} uid 
     * @param {string[]} shares 
     */
    async SetKey(uid, shares) {
        const data = this._createFormData({ 'YijCipher': shares });
        const response = await this._post(`/Create/SetKey?uid=${uid}`, data);

        const responseData = await this._handleError(response, "SetKey");
        return SetKeyResponse.from(responseData);
    }

    /**
     * @param {string} uid
     * @param {Point[][]} gKntesti 
     * @param {string[]} gKsigni
     * @param {Point} R2  
     * @param {string} state_id
     */
    async PreCommit(uid, gKntesti, gKsigni, R2, state_id) {
        const data = this._createFormData(
            {
                'gKntesti': gKntesti.map(gKtest => gKtest.map(p => p.toBase64())),
                'gKsigni': gKsigni,
                'R2': R2.toBase64(),
                'state_id': state_id
            }
        );
        const response = await this._post(`/Create/PreCommit?uid=${uid}`, data);
        const responseData = await this._handleError(response, "PreCommit");

        return PreCommitResponse.from(responseData) // S from EdDSA
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
                'GPrismAuth': gPrismAuth.toBase64()
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