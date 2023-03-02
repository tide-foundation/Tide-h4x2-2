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
import ConvertResponse from "../Models/ConvertResponse.js";
import TranToken from "../Tools/TranToken.js";
import SignInCVKResponse from "../Models/SignInCVKResponse.js";

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
   *  @returns {Promise<ConvertResponse>} */
  async Convert(uid, gBlurPass, li) {
    const data = this._createFormData(
      {
        'gBlurPass': gBlurPass.toBase64()
      });
    const response = await this._post(`/Apply/Convert?uid=${uid}`, data);
    const responseData = await this._handleError(response, "Convert");
    return ConvertResponse.from(responseData, li);
  }

  /** 
   * @param { string} uid
   * @param { TranToken } certTimei
   * @param { TranToken } verifyi
   *  @returns {Promise<string>} */
  async Authenticate(uid, certTimei, verifyi) {
    const response = await this._get(`/Apply/Authenticate?uid=${uid}&certTimei=${encodeBase64Url(certTimei.toArray())}&token=${encodeBase64Url(verifyi.toArray())}`); // Check TranToken conversion
    const responseData = await this._handleError(response, "Authenticate");

    return responseData;
  }

  /**
   * @param {string} uid
   * @param {number} timestamp2
   * @param {Point} gSesskeyPub
   * @param {string} challenge
   * @returns {Promise<string>}
   */
  async PreSignInCVK(uid, timestamp2, gSesskeyPub, challenge) {
    const data = this._createFormData(
      {
        'gSessKeyPub': gSesskeyPub.toBase64()
      });
    const response = await this._post(`/Apply/PreSignCvk?uid=${uid}&timestamp2=${timestamp2.toString()}&challenge=${challenge}`, data);
    const responseData = await this._handleError(response, "PreSignInCVK");
    return responseData;
  }

  /** 
   * @param { string } uid
   * @param { number } timestamp2
   * @param { Point } gSesskeyPub
   * @param { string } challenge
   * @param {Point} gCVKR
   *  @returns {Promise<SignInCVKResponse>} */
  async SignInCVK(uid, timestamp2, gSesskeyPub, challenge, gCVKR) {
    const data = this._createFormData(
      {
        'gSessKeyPub': gSesskeyPub.toBase64(),
        'gCVKR': gCVKR.toBase64()
      });
    const response = await this._post(`/Apply/SignCvk?uid=${uid}&timestamp2=${timestamp2.toString()}&challenge=${challenge}`, data);
    const responseData = await this._handleError(response, "SignInCVK");
    return SignInCVKResponse.from(responseData);
  }

}

/** @param {string|Uint8Array|Buffer} data */
function encodeBase64Url(data) {
  const text = encodeBase64(data);
  return text.replace(/\=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}


/** @param {string|Uint8Array|Buffer|bigint} data */
export function encodeBase64(data) {
  return typeof data === "string" ? data
    : data instanceof Buffer ? data.toString("base64")
      : data instanceof Uint8Array ? Buffer.from(data).toString("base64")
        : Buffer.from(data.toArray(256).value).toString("base64");
}
