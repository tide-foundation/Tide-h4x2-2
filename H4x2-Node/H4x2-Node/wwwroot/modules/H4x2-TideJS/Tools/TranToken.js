/**
 * Babel Starter Kit (https://www.kriasoft.com/babel-starter-kit)
 *
 * Copyright © 2015-2016 Kriasoft, LLC. All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE.txt file in the root directory of this source tree.
 */

import { HMAC_Buffer } from './Hash.js';

export default class TranToken {
    /** @param {CryptoKey} key */
    constructor(key = null) {
        this.id = window.crypto.getRandomValues((new Uint8Array(8)));
        this.ticks = getTicks();

        this.signature = key == null ? new Uint8Array()
            : getSignature(key, this.id, this.ticks);
    }

    /** @param {CryptoKey} key
     *  @param {Uint8Array} data */
    sign(key, data = null) {
        this.signature = getSignature(key, this.id, this.ticks, data);
        return this;
    }

    /** @param {CryptoKey} key
    *  @param {Uint8Array} data */
    async check(key, data = null) {
        const signature = await getSignature(key, this.id, this.ticks, data);
        return secureEqual(signature, await this.signature);
    }
    // copy() {
    //     return TranToken.from(this.toArray())
    // }

    // toString() {
    //     return Buffer.from(this.toArray()).toString('base64');
    // }

    /** @returns {Promise<Uint8Array>} */
    async toArray() {
        const buffer = Buffer.alloc(32);
        buffer.set(this.id);
        buffer.set(Buffer.from(this.ticks.toString()), 8);
        buffer.set(await this.signature, 16);

        return buffer;
    }

    /** @param {Uint8Array|string} data */
    static from(data) {
        const buffer = typeof data === 'string' ? Buffer.from(data, 'base64') : data
        const token = new TranToken();

        token.id = buffer.slice(0, 8);
        token.ticks = buffer.slice(8, 16);
        token.signature = buffer.slice(16);

        return token;
    }

    inspect() {
        return this.toString();
    }


}

function getTicks() {
    return (new Date().getTime() * 10000) + 621355968000000000;
}

/**
 * @param {CryptoKey} key
 * @param {Uint8Array} id
 * @param {number} ticks
 * @param {Uint8Array} data
 * @returns 
 */
async function getSignature(key, id, ticks, data = null) {
    const length = 16 + (data !== null ? data.length : 0)
    const buffer = Buffer.alloc(length);

    buffer.set(id);
    buffer.set(Buffer.from(ticks.toString()), 8);
    if (data !== null)
        buffer.set(data, 16);
    const pre_signature = HMAC_Buffer(buffer, key);
    const signature = await pre_signature;
    return signature.slice(16);
}

/**
 * @param {Uint8Array} arr1 
 * @param {Uint8Array} arr2 
 * @returns {boolean}
 */
function secureEqual(arr1, arr2) {
    if (!arr1 || !arr2) return false;

    if (arr1.length > arr2.length) [arr1, arr2] = [arr2, arr1];

    return 0 === arr1.reduce((sum, _, i) => (arr1[i] ^ arr2[i]) + sum, arr1.length ^ arr2.length);
}
