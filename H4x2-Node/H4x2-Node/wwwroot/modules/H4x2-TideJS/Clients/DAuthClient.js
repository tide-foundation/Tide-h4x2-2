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
import Point from "../Ed25519/point.js"

export default class DAuthClient extends ClientBase {
  /**
   * @param {string} url
   * @param {string} userID
   */
  constructor(url, userID) {
    super(url);
    this.userID = userID;
  }


  /** 
   * @param {[string, string, Point][]} mIdORKij 
   * @param {number} numKeys
   * @param {string[]} multipliers
   * @returns {Promise<[Point, string, Point[], BigInt]>}
   */
  async genShard(mIdORKij, numKeys, multipliers) {

    const orkIds = mIdORKij.map(id => `orkIds=${id[0]}`).join('&');
    const orkPubs = []
    mIdORKij.map(ork => orkPubs.push(ork[2].toBase64())); // check this work
    const data = this._createFormData({ 'orkPubs': orkPubs, 'multipliers': multipliers })
    const resp = await this._post(`/Create/GenShard?uid=${this.userID}&numKeys=${numKeys.toString()}&${orkIds}`, data);
    if (!resp.ok) return Promise.reject(new Error(await resp.text()));

    const parsedObj = JSON.parse(await resp.text());
    const gMultiplied = parsedObj.GMultipliers.map(p => Point.fromB64(p)); // check this works
    return [Point.fromB64(parsedObj.GK), parsedObj.EncryptedOrkShares, gMultiplied, BigInt(parsedObj.Timestampi)];
  }

  /** 
    * @param {string[]} yijCipher
    * @param {string[]} orkPubs  
    * @returns {Promise<[Point[], Point, string, string]>}
    */
  async setKey(yijCipher, orkPubs) {
    try {
      const data = this._createFormData({ 'orkPubs': orkPubs, 'yijCipher': yijCipher })
      const resp = await this._post(`/Create/SetKey?uid=${this.userID}`, data)
      if (!resp.ok) return Promise.reject(new Error(await resp.text()));

      const object = JSON.parse(resp.text.toString());
      const obj = JSON.parse(object.Response.toString());
      const gKTesti = obj.gKTesti.map(p => Point.fromB64(p));
      console.log(object.RandomKey);
      return [gKTesti, Point.fromB64(obj.gRi), obj.EncryptedData, object.RandomKey];
    } catch (err) {
      return Promise.reject(err);
    }
  }


  /**
   * @param {Point[]} gTests 
   * @param {string[]} orkPubs 
   * @param {Point} gCMKR2
   * @param {string} EncSetCMKStatei
   * @param {Point} gPrismAuth
   * @param {string} emaili
   * @param {string} randomKey
   * @returns {Promise<bigint>} 
   */
  async preCommit(gTests, gCMKR2, EncSetCMKStatei, randomKey, gPrismAuth, emaili, orkPubs) {
    try {

      const data = this._createFormData({
        'R2': gCMKR2.toBase64(), 'gCMKtest': gTests[0].toBase64(), 'gPRISMtest': gTests[1].toBase64(), 'gCMK2test': gTests[2].toBase64(), 'prismAuth': gPrismAuth.toBase64(),
        'orkPubs': orkPubs, 'encSetKey': EncSetCMKStatei, 'randomKey': randomKey
      })

      const resp = await this._post(`/Create/PreCommit?uid=${this.userID}&emaili=${emaili}`, data);
      if (!resp.ok) return Promise.reject(new Error(await resp.text()));
      return BigInt(await resp.text());
    } catch (err) {
      return Promise.reject(err);
    }
  }

  /**
   * @param {bigint} cmks
   * @param {string} EncSetCMKStatei
   * @param {Point} gCMKR2
   *  @param {string[]} orkPubs 
   */
  async commit(cmks, EncSetCMKStatei, gCMKR2, orkPubs) {
    const data = this._createFormData({ 'R2': gCMKR2.toBase64(), 'orkPubs': orkPubs, 'encryptedState': EncSetCMKStatei })

    const resp = await this._put(`/Create/Commit?uid=${this.userID}&S=${cmks.toString()}`, data)
    if (!resp.ok) return Promise.reject(new Error(await resp.text()));
    return resp.ok;
  }
}
