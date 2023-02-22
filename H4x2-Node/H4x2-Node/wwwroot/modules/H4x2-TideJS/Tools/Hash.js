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

/**
 * @param {string|Uint8Array} message 
 * @returns 
 */
export async function SHA256_Digest(message) {
  const data = typeof (message) === 'string' ? new TextEncoder().encode(message) : message;
  const hash = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hash);

}

/**
 * @param {string|Uint8Array} message 
 * @returns 
 */
export async function SHA512_Digest(message) {
  const data = typeof (message) === 'string' ? new TextEncoder().encode(message) : message;
  const hash = await crypto.subtle.digest('SHA-512', data);
  return new Uint8Array(hash);

}

/**
 * @param {string|Uint8Array} message 
 * @returns 
 */
export async function HMAC_Buffer(message, secret) {
  const data = typeof (message) === 'string' ? new TextEncoder().encode(message) : message;
  const encSecret = typeof (message) === 'string' ? new TextEncoder().encode(secret) : secret;
  let algorithm = { name: "HMAC", hash: "SHA-256" };
  let key = await crypto.subtle.importKey("raw", encSecret, algorithm, true, ["sign", "verify"]);
  let signature = await crypto.subtle.sign(algorithm.name, key, data);
  return new Uint8Array(signature);
}
