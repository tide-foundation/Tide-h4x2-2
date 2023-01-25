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
import ClientBase from "./ClientBase.js"

export default class NodeClient extends ClientBase {
    /**
     * @param {string} url
     */
    constructor(url){
        super(url)
    }

    /**
     * @param {Point} point
     * @param {string} uid 
     * @returns {Promise<Point>}
     */
    async ApplyPRISM(uid, point){
        const data = this._createFormData({'point': point.toBase64()})
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
    async ApplyAuthData(uid, authData){
        const data = this._createFormData({'authData': authData})
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
    async CreatePRISM(uid, point){
        const data = this._createFormData({'point': point.toBase64()})
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
    async CreateAccount(uid, prismPub, encryptedState){
        const data = this._createFormData({'prismPub': prismPub.toBase64(), 'encryptedState': encryptedState})
        const response = await this._post(`/Create/Account?uid=${uid}`, data);

        const responseData = await this._handleError(response, "Create Account");
        const resp_obj = JSON.parse(responseData);
        return [resp_obj.encryptedCVK, resp_obj.signedUID]
    }
}