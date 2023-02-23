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
import { SHA256_Digest } from "../Tools/Hash.js"
import { BigIntFromByteArray } from "../Tools/Utils.js"
import { RandomBigInt, mod_inv } from "../Tools/Utils.js"
import DAuthClient from "../Clients/DAuthClient.js"
import { createAESKey, decryptData } from "../Tools/AES.js"
import ApplyResponseDecrypted from "../Models/ApplyResponseDecrypted.js"
import TranToken from "../Tools/TranToken.js"
import { GetLi } from "../Math/SecretShare.js"

export default class DAuthFlow {
  /**
   *@param {[string, string, Point][]} orks 
   * @param {string} userID
   */
  constructor(orks, userID) {
    this.orks = orks;
    this.clients = orks.map(url => new DAuthClient(url[1], userID));
    this.userID = userID;
  }

  /**
    *  @param {string} uid
    *  @param {Point} passwordPoint
    *  @returns {Promise<[ApplyResponseDecrypted[], TranToken[]]>} 
   */
  async DoConvert(uid, passwordPoint) {
    try {
      const n = Point.order;
      const random = RandomBigInt();
      const gPass = await Point.fromString(passwordPoint);   //convert password to point
      const gBlurPass = gPass.times(random); // password point * random
      const r2Inv = mod_inv(random, n);

      // Calculate all lagrange coefficients for all the shards
      const ids = this.orks.map(ork => ork[0]).map(id => BigInt(id));
      const lis = ids.map(id => GetLi(id, ids, Point.order));

      const pre_Prismis = this.clients.map((DAuthClient, i) => DAuthClient.convert(uid, gBlurPass, lis[i])); // li is not being sent to ORKs. Instead, when gBlurPassPRISM is returned, it is multiplied by li locally
      const prismResponse = await Promise.all(pre_Prismis);
      const gPassPrism = prismResponse.map(a => a[0]).reduce((sum, point) => sum.add(point), Point.infinity).times(r2Inv);// li has already been multiplied above, so no need to do it here
      const gPRISMAuth = BigIntFromByteArray(await SHA256_Digest(gPassPrism.toArray()));

      const pre_prismAuths = this.orks.map(async ork => createAESKey(await SHA256_Digest(ork[2].times(gPRISMAuth).toArray()), ["encrypt", "decrypt"]));
      const prismAuths = await Promise.all(pre_prismAuths);

      const encryptedResponses = prismResponse.map(a => a[1]);

      const pre_decryptedResponses = encryptedResponses.map(async (cipher, i) => ApplyResponseDecrypted.from(await decryptData(cipher, prismAuths[i])));
      const decryptedResponses = await Promise.all(pre_decryptedResponses);

      // functional function to append userID bytes to certTime bytes FAST
      const create_payload = (certTime_bytes) => {
        const newArray = new Uint8Array(Buffer.from(this.userID).length + certTime_bytes.length);
        newArray.set(Buffer.from(this.userID));
        newArray.set(certTime_bytes, Buffer.from(this.userID).length);
        return newArray // returns userID + certTime
      }

      const verifyi = decryptedResponses.map((response, i) => new TranToken().sign(prismAuths[i], create_payload(response.certTime.toArray())));
      return [decryptedResponses, verifyi];
    } catch (err) {
      return Promise.reject(err);
    }
  }

}

