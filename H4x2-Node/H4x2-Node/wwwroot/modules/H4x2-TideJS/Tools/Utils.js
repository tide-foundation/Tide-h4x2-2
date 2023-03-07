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

import { SHA256_Digest } from "./Hash.js";
import Point from "../Ed25519/point.js";


const ed25519_order = BigInt("7237005577332262213973186563042994240857116359379907606001950938285454250989");

const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);
///////////////////////////////////// TODO: Fix the uses of Mod and Modinv in Point.js and here
/**
 * @param {bigint} a 
 * @param {bigint} b 
 * @returns {bigint}
 */
export function mod(a, b = ed25519_order) {
	var res = a % b;
	return res >= BigInt(0) ? res : b + res;
}

/**
 * @param {bigint} number 
 * @param {bigint} modulo 
 * @returns {bigint}
 */
export function mod_inv(number, modulo = ed25519_order) {
	if (number === _0n || modulo <= _0n) {
		throw new Error(`invert: expected positive integers, got n=${number} mod=${modulo}`);
	}
	let a = mod(number, modulo);
	let b = modulo;
	// prettier-ignore
	let x = _0n, y = _1n, u = _1n, v = _0n;
	while (a !== _0n) {
		const q = b / a;
		const r = b % a;
		const m = x - u * q;
		const n = y - v * q;
		// prettier-ignore
		b = a, a = r, x = u, y = v, u = m, v = n;
	}
	const gcd = b;
	if (gcd !== _1n) throw new Error('invert: does not exist');
	return mod(x, modulo);
}

export function RandomBigInt() {
	const buf = new Uint8Array(32);
	window.crypto.getRandomValues(buf);
	return mod(BigIntFromByteArray(buf), ed25519_order);
}

/**
 * @param {BigInt} num 
 * @returns {Uint8Array}
 */
export function BigIntToByteArray(num) {
	const hex = num.toString(16).padStart(32 * 2, '0');
	return Hex2Bytes(hex).reverse();
}

/**
 * @param {Uint8Array} bytes 
 * @returns {bigint}
 */
export function BigIntFromByteArray(bytes) {
	const hex = Bytes2Hex(bytes.reverse());
	return BigInt("0x" + hex);
}

/**
 * 
 * @param {Uint8Array[]} arrays 
 */
export function ConcatUint8Arrays(arrays) {
	const totalLength = arrays.reduce((sum, next) => next.length + sum, 0);
	var newArray = new Uint8Array(totalLength);
	var offset = 0;
	arrays.forEach(item => {
		newArray.set(item, offset);
		offset += item.length;
	});
	return newArray;
}

/**
 * @param {string} string 
 */
export function StringToUint8Array(string) {
	const enc = new TextEncoder();
	return enc.encode(string);
}

/**
 * @param {string} string 
 * @returns {Uint8Array}
 */
export function Hex2Bytes(string) {
	const normal = string.length % 2 ? "0" + string : string; // Make even length
	const bytes = new Uint8Array(normal.length / 2);
	for (let index = 0; index < bytes.length; ++index) {
		const c1 = normal.charCodeAt(index * 2);
		const c2 = normal.charCodeAt(index * 2 + 1);
		const n1 = c1 - (c1 < 58 ? 48 : 87);
		const n2 = c2 - (c2 < 58 ? 48 : 87);
		bytes[index] = n1 * 16 + n2;
	}
	return bytes;
}

/**
 * @param {Uint8Array} byteArray 
 * @returns {string}
 */
export function Bytes2Hex(byteArray) {
	const chars = new Uint8Array(byteArray.length * 2);
	const alpha = 'a'.charCodeAt(0) - 10;
	const digit = '0'.charCodeAt(0);

	let p = 0;
	for (let i = 0; i < byteArray.length; i++) {
		let nibble = byteArray[i] >>> 4;
		chars[p++] = nibble > 9 ? nibble + alpha : nibble + digit;
		nibble = byteArray[i] & 0xF;
		chars[p++] = nibble > 9 ? nibble + alpha : nibble + digit;
	}
	return String.fromCharCode.apply(null, chars);
}

/**
 * Credits to Egor Nepomnyaschih for the below code
 * Link: https://gist.github.com/enepomnyaschih/72c423f727d395eeaa09697058238727
*/
const base64abc = [
	"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
	"N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
	"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
	"n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "+", "/"
];

const base64codes = [
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62, 255, 255, 255, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 255, 255, 255, 0, 255, 255,
	255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 255, 255, 255, 255, 255,
	255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
];

function getBase64Code(charCode) {
	if (charCode >= base64codes.length) {
		throw new Error("Unable to parse base64 string.");
	}
	const code = base64codes[charCode];
	if (code === 255) {
		throw new Error("Unable to parse base64 string.");
	}
	return code;
}

/**
 * @param {Uint8Array} bytes 
 * @returns {string}
 */
export function bytesToBase64(bytes) {
	let result = '', i, l = bytes.length;
	for (i = 2; i < l; i += 3) {
		result += base64abc[bytes[i - 2] >> 2];
		result += base64abc[((bytes[i - 2] & 0x03) << 4) | (bytes[i - 1] >> 4)];
		result += base64abc[((bytes[i - 1] & 0x0F) << 2) | (bytes[i] >> 6)];
		result += base64abc[bytes[i] & 0x3F];
	}
	if (i === l + 1) { // 1 octet yet to write
		result += base64abc[bytes[i - 2] >> 2];
		result += base64abc[(bytes[i - 2] & 0x03) << 4];
		result += "==";
	}
	if (i === l) { // 2 octets yet to write
		result += base64abc[bytes[i - 2] >> 2];
		result += base64abc[((bytes[i - 2] & 0x03) << 4) | (bytes[i - 1] >> 4)];
		result += base64abc[(bytes[i - 1] & 0x0F) << 2];
		result += "=";
	}
	return result;
}

/**
 * @param {string} str 
 * @returns {Uint8Array}
 */
export function base64ToBytes(str) {
	if (str.length % 4 !== 0) {
		throw new Error("Unable to parse base64 string.");
	}
	const index = str.indexOf("=");
	if (index !== -1 && index < str.length - 2) {
		throw new Error("Unable to parse base64 string.");
	}
	let missingOctets = str.endsWith("==") ? 2 : str.endsWith("=") ? 1 : 0,
		n = str.length,
		result = new Uint8Array(3 * (n / 4)),
		buffer;
	for (let i = 0, j = 0; i < n; i += 4, j += 3) {
		buffer =
			getBase64Code(str.charCodeAt(i)) << 18 |
			getBase64Code(str.charCodeAt(i + 1)) << 12 |
			getBase64Code(str.charCodeAt(i + 2)) << 6 |
			getBase64Code(str.charCodeAt(i + 3));
		result[j] = buffer >> 16;
		result[j + 1] = (buffer >> 8) & 0xFF;
		result[j + 2] = buffer & 0xFF;
	}
	return result.subarray(0, result.length - missingOctets);
}

//////////////////////////// Maths
/**
 * 
 * @param {bigint[]} numbers 
 * @returns 
 */
export function median(numbers) {
	const sorted = Array.from(numbers).sort();
	const middle = Math.floor(sorted.length / 2);

	if (sorted.length % 2 === 0) {
		return ((sorted[middle - 1] + (sorted[middle])) / _2n);
	}

	return sorted[middle];
}

export function getCSharpTime(ticks) {
	return (ticks * 10000);
}


/////////////////////// ORK Key ID
export async function Generate_ORK_ID(orkpub) {
	return mod(BigIntFromByteArray(await SHA256_Digest(orkpub)), Point.order); // Ork.cs on Simulator has similar function to generate ID
}


