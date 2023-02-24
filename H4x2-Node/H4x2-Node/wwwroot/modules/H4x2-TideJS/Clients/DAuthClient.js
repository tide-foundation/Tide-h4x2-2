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
import TranToken from "../Tools/TranToken.js";

export default class DAuthClient extends ClientBase {
  /**
   * @param {string} url
   */
  constructor(url) {
    super(url);
  }


  /** 
   * @param { string } uid
   * @param {Point} gBlurPass
   * @param {bigint} li
   *  @returns {Promise<[Point, string]>} */
  async convert(uid, gBlurPass, li) {
    const data = this._createFormData(
      {
        'gBlurPass': gBlurPass.toBase64()
      });
    const response = await this._post(`/Apply/Convert?uid=${uid}`, data);
    const responseData = await this._handleError(response, "Convert");

    const object = JSON.parse(responseData);
    return [Point.fromB64(object.GBlurPassPrism).times(li), object.EncReply]
  }

}
