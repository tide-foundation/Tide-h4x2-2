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

import Point from "../Ed25519/point.js";
import { SHA512_Digest } from "./Hash.js";
import { base64ToBytes, BigIntFromByteArray, BigIntToByteArray, bytesToBase64, ConcatUint8Arrays, mod, RandomBigInt, StringToUint8Array } from "./Utils.js";

/**
 * DO NOT USE ME UNLESS YOU KNOW WHAT YOURE DOING
 * Sign the msg with a private key in a deterministic form - without the use of random  number generators.
 * Keep in mind the Point.g.times(priv) is not the public in this case. It'll be Point.g times the first half of hash(priv).
 * @param {string | Uint8Array} msg 
 * @param {bigint} priv This will typically be a CVK. To conform to the RFC standard, this priv will be used as a seed.
 * @returns A base64 encoding of the signature
*/
export async function sign_deterministic(msg, priv){
    if(typeof(msg) == 'string'){
        msg = StringToUint8Array(msg);
    }

    const priv_bytes = BigIntToByteArray(priv);
    const h = await SHA512_Digest(priv_bytes);
    const s = BigIntFromByteArray(h.slice(0, 32));
    const A = Point.g.times(s).toArray();
    const prefix = h.slice(-32);
    const to_hash = ConcatUint8Arrays([prefix, msg])
    const r = mod(BigIntFromByteArray(await SHA512_Digest(to_hash)));
    const R = Point.g.times(r).toArray();

    const to_hash2 = ConcatUint8Arrays([R, A, msg]);
    const k = mod(BigIntFromByteArray(await SHA512_Digest(to_hash2)));
    const S = mod(r + (k * s));

    const sig_bytes = ConcatUint8Arrays([R, BigIntToByteArray(S)]);
    return bytesToBase64(sig_bytes);
}

/**
 * Sign the msg with a private key in non-standard way as it uses a random number generator. Non-deterministic.
 * @param {string | Uint8Array} msg 
 * @param {bigint} priv // Most likely the CVK
 * @returns A base64 encoding of the signature
 */
export async function sign(msg, priv){
    if(typeof(msg) == 'string'){
        msg = StringToUint8Array(msg);
    }

    const A = Point.g.times(priv).toArray();
    const r = RandomBigInt();
    const R = Point.g.times(r).toArray();

    const to_hash2 = ConcatUint8Arrays([R, A, msg]);
    const k = mod(BigIntFromByteArray(await SHA512_Digest(to_hash2)));
    const S = mod(r + (k * priv));

    const sig_bytes = ConcatUint8Arrays([R, BigIntToByteArray(S)]);
    return bytesToBase64(sig_bytes);
}

/**
 * Verify a EdDSA signature, given a signature, public key and message.
 * @param {string} sig In base64
 * @param {string | PublicKey} pub 
 * @param {string | Uint8Array} msg 
 * @returns Boolean dependant on whether the signature is valid or not.
 */
export async function verify(sig, pub, msg){
    try{
        if(typeof(msg) == 'string'){
            msg = StringToUint8Array(msg);
        }
    
        const sig_bytes = base64ToBytes(sig);
        if(sig_bytes.length != 64) return false;
    
        const R = Point.from(sig_bytes.slice(0, 32));
        const S = BigIntFromByteArray(sig_bytes.slice(-32));
        if(S <= BigInt(0) || S >= Point.order) return false;
    
        if(typeof(pub) == 'string') pub = Point.fromB64(pub);
    
        const to_hash = ConcatUint8Arrays([R.toArray(), pub.toArray(), msg]);
        const k = BigIntFromByteArray(await SHA512_Digest(to_hash));
    
        return Point.g.times(S).times(BigInt(8)).isEqual(R.times(BigInt(8)).add(pub.times(k).times(BigInt(8))));
    }catch{
        return false // very strict indeed
    }
}

export class PublicKey extends Point{

    /**
     * @param {bigint} secret_num 
     * @returns A Ed25519 Public Key
     */
    static fromPrivate(secret_num){
        return PublicKey.g.times(secret_num);
    }
}