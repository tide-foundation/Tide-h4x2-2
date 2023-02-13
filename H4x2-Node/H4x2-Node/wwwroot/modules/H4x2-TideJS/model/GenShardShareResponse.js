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

export default class GenShardShareResponse {
    /**
    * @param {string} to
    * @param {string} from
    * @param {string} encryptedData
    */
    constructor(to, from, encryptedData) {
        this.to = to;
        this.from = from;
        this.encryptedData = encryptedData;

    }

    toString() { return JSON.stringify(this); }
 
    inspect() { return JSON.stringify(this); }
    
   

    /** @param {string|object} data */
    static from(data) {

        const obj = typeof data === 'string' ? JSON.parse(data) : data;
        if (!obj.To || !obj.From || !obj.EncryptedData)
            throw Error(`The JSON is not in the correct format: ${data}`);

        const to = obj.To;
        const from = obj.From;
        const encryptedData = obj.EncryptedData;
  
        return new GenShardShareResponse(to, from, encryptedData);
    }

}