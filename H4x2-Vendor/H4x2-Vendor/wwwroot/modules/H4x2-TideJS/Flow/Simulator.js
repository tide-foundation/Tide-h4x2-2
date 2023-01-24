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


import SimulatorClient from "../Clients/SimulatorClient.js"

export default class SimulatorFlow{
    /**
     * Config should include key/value pairs of: 
     * @example
     * {
     *  urls: string
     * }
     * @example
     * @param {object} config 
     */
    constructor(config){
        if(!Object.hasOwn(config, 'url')){ throw Error("Url has not been included in config")}
        /**
         * @type {string}
         */
        this.url = config.url
    
    }

     /**
     * Starts the Flow to attempt to get the Tide ork's url.
     * * Requires config object to include url 
     * @returns {Promise<string>}
     */
    async getTideOrk(){
        const client = new SimulatorClient(this.url); 
        const res = await client.GetTideOrk(); 
        return res;
    }


}