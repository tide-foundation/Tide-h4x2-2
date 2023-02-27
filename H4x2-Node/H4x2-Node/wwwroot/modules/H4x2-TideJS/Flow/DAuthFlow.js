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

import Point from "../Ed25519/point.js"
import { RandomBigInt, mod_inv, median, getCSharpTime, createJWT_toSign } from "../Tools/Utils.js"
import DAuthClient from "../Clients/DAuthClient.js"
import { GetLi } from "../Math/SecretShare.js"
import { ConvertReply, PreSignInCVKReply, SignInCVKReply } from "../Math/DAuthReplys.js"
import TranToken from "../Tools/TranToken.js"

export default class DAuthFlow {
  /**
   *@param {[string, string, Point][]} orks 
   */
  constructor(orks) {
    this.orks = orks;
    this.clients = orks.map(url => new DAuthClient(url[1]));
  }

  /**
    *  @param {string} uid
    *  @param {Point} passwordPoint
   */
  async DoConvert(uid, passwordPoint) {
    const n = Point.order;
    const random = RandomBigInt();
    const gPass = await Point.fromString(passwordPoint);   //convert password to point
    const gBlurPass = gPass.times(random); // password point * random
    const randomInv = mod_inv(random, n);

    // Calculate all lagrange coefficients for all the shards
    const ids = this.orks.map(ork => ork[0]).map(id => BigInt(id));
    const lis = ids.map(id => GetLi(id, ids, Point.order));

    const pre_Prismis = this.clients.map((dAuthClient, i) => dAuthClient.Convert(uid, gBlurPass, lis[i])); // li is not being sent to ORKs.Instead when gBlurPassPRISM is returned, it is multiplied by li locally
    const prismResponse = await Promise.all(pre_Prismis);

    return ConvertReply(uid, prismResponse, randomInv, this.orks);
  }

  /**
    *  @param {string} uid
    *  @param {TranToken []} certimes
    * @param {TranToken []} verifyi
   */
  async Authenticate(uid, certimes, verifyi) {
    const pre_authResponse = this.clients.map((dAuthClient, i) => dAuthClient.Authenticate(uid, certimes[i], verifyi[i]));
    const authResponse = await Promise.all(pre_authResponse);
    return authResponse;
  }

  /**
    * @param {string} uid
    * @param { TranToken[]} certimes
    * @param {number} startTimer
   */
  async SignInCVK(uid, certimes, startTimer) {
    const Sesskey = RandomBigInt();
    const gSesskeyPub = Point.g.times(Sesskey);

    const deltaTime = median(certimes.map(a => Number(a.ticks.toString()))) - startTimer;
    const timestamp2 = getCSharpTime(Date.now()) + deltaTime;

    const jwt = createJWT_toSign(uid, gSesskeyPub, timestamp2); // Tide JWT here 

    const pre_preSignInCVKResponse = this.clients.map(dAuthClient => dAuthClient.PreSignInCVK(uid, timestamp2, gSesskeyPub, jwt));  // PreSignInCVK
    const preSingInCVKResponse = await Promise.all(pre_preSignInCVKResponse);
    const { gCVKR: gCVKR, ECDHi: ECDHi } = await PreSignInCVKReply(preSingInCVKResponse, Sesskey, this.orks);

    const pre_signInCVKResponse = await this.clients.map((dAuthClient) => dAuthClient.SignInCVK(uid, timestamp2, gSesskeyPub, jwt, gCVKR)); // SignInCVK
    const signInCVKResponse = await Promise.all(pre_signInCVKResponse);

    return SignInCVKReply(signInCVKResponse, gCVKR, jwt, this.orks, ECDHi, cvkPub); // Need to get CvkPub
  }
}

