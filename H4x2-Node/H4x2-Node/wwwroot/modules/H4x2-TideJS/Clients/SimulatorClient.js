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

export default class SimulatorClient extends ClientBase {
    /**
     * @param {string} url
     */
    constructor(url){
        super(url)
    }

    /**
     * This method will query the simulator for all information about all ORKs and return
     * an array compromising of each ORK's name, url and public.
     * @returns {Promise<[string, string, string, string][]>}
     */
    async GetAllORKs(){
        const response = await this._get('/orks'); // endpoint is at /
        const formattedResponse = JSON.parse(await response.text())
        const returnedResponse = formattedResponse.map(orkEntry => [orkEntry.orkId, orkEntry.orkName, orkEntry.orkUrl, orkEntry.orkPub]);
        return returnedResponse;
    }

    async AddUserEntry(userID, signedEntries, ORKIds){
        var user = {
            userId: userID,
            orkIds: ORKIds,
            singedUIds: signedEntries
        }
        const response = await this._postJSON('Users', user);
        if(!response.ok){
            return Promise.reject("Adding user to simulator failed.")
        }
    }

    /**
     * 
     * @param {string} uid 
     * @returns {Promise}
     */
    async GetUserORKs(uid){
        const response = await this._get(`userOrks/userId/${uid}`);
        const responseData = await this._handleErrorSimulator(response);
        const resp_obj = JSON.parse(responseData);
        const pubs = resp_obj.orkPubs.map(pub => Point.fromB64(pub));
        const returnData = pubs.map((pub, i) => [resp_obj.orkIds[i], resp_obj.orkUrls[i], pub]);  // format data so instead of ( [urls], [points] ) we have (url1, point1), (url2, point2) []
        return returnData

    }

     /**
     * This method will query the simulator for all information about all active ORKs and return
     * an array compromising of each ORK's name, url and public.
     * @returns {Promise<[string, string, string, string][]>}
     */
    async GetActiveORKs(){
        const response = await this._get('/orks/active'); 
        const formattedResponse = JSON.parse(await response.text())
        const returnedResponse = formattedResponse.map(orkEntry => [orkEntry.orkId, orkEntry.orkName, orkEntry.orkUrl, orkEntry.orkPub]);
        return returnedResponse;
    }

}