import { base64ToBytes, bytesToBase64, ConcatUint8Arrays } from "./Utils.js";

/**
 * Credits to https://github.com/bradyjoslin for the below AES implementation
 */
const enc = new TextEncoder();
const dec = new TextDecoder();

const getPasswordKey = (password) =>
    window.crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, [
        "deriveKey",
]);

const deriveKey = (passwordKey, salt, keyUsage) =>
    window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 250000,
            hash: "SHA-256",
        },
            passwordKey,
        { name: "AES-GCM", length: 256 },
        false,
        keyUsage
);

/**
 * 
 * @param {Uint8Array} rawKey 
 * @param {Iterable} keyUsage 
 * @returns 
 */
function importSecretKey(rawKey, keyUsage) {
    return window.crypto.subtle.importKey(
      "raw",
      rawKey,
      "AES-GCM",
      true,
      keyUsage
    );
  }

/**
 * @param {string} secretData 
 * @param {Uint8Array} key 
 * @returns 
 */
export async function encryptData(secretData, key) {
    const encoded = new TextEncoder().encode(secretData);
    const AESKey = await importSecretKey(key, ["encrypt"]);
    // iv will be needed for decryption
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedBuffer = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        AESKey,
        encoded
      );
    const buff = ConcatUint8Arrays([iv, new Uint8Array(encryptedBuffer)])
    return bytesToBase64(buff);
}


/**
 * @param {string} encryptedData 
 * @param {Uint8Array} key 
 * @returns 
 */
export async function decryptData(encryptedData, key, num) {
    try {
        const encryptedDataBuff = base64ToBytes(encryptedData);

        const iv = encryptedDataBuff.slice(0, 12);
        const data = encryptedDataBuff.slice(12);
        const aesKey = await importSecretKey(key, ["decrypt"]);
        const decryptedContent = await window.crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        aesKey,
        data
        );
        return dec.decode(decryptedContent);
    } catch (e) {
        console.log(`Error - ${e}`);
        return "Decryption Failed";
    }
}