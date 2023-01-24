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

export default class ClientBase {
     /**
     * @param {string} url 
     */
      constructor(url){
        this.url = url
    }

    /**
     * @param {Object} form
     * @returns {FormData}
     */
    _createFormData(form){
        const formData = new FormData();

        Object.entries(form).forEach(([key, value]) => {
            formData.append(key, value)
        });

        return formData
    }

    /** 
     * @param {string} endpoint 
     * @returns {Promise<Response>}
     */
     _get(endpoint){
        return fetch(this.url + endpoint, {
            method: 'GET'
        });
    }

    /** 
     * @param {string} endpoint 
     * @param {FormData} data
     * @returns {Promise<Response>}
     */
    async _post(endpoint, data){
       return fetch(this.url + endpoint, {
            method: 'POST',
            body: data
        });
    }

    /** 
     * @param {string} endpoint 
     * @param {Object} data
     * @returns {Promise<Response>}
     */
    async _postJSON(endpoint, data){
        return fetch(this.url + endpoint, {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
         });
     }
}