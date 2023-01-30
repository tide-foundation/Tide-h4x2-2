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

import ClientBase from "./ClientBase.js"

export default class VendorClient extends ClientBase {
    /**
     * @param {string} url 
     * @param {string} userID
     */
    constructor(url, userID){
        super(url)
        this.userID = userID
    }

    /**
     * @param {string} secret
     * @returns {Promise}
     */
    async AddToVendor(secret){
        const user = {
            UID: this.userID,
            Secret: secret
        }
        const response =  this._postJSON(`users`, user);
        await response.then((res) => { 
            const responseData =  this._handleErrorNew(res, "Add to Vendor");
            return responseData;
        }).catch((res) => { 
           return Promise.reject("Adding user to vendor failed : " + res)
        });
        
    }

    /**
     * @returns {Promise}
     */
    async GetUserCode(){
        var response =  this._get(`users/code/${this.userID}`);
        await response.then((res) => { 
            const responseData =  this._handleErrorNew(res, "Get User Code");
            return responseData;
        }).catch((res) => { 
           return Promise.reject("Vendor Client: Cannot retrieve user code.: " + res)
        });
       
    }
}