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
import { SHA256_Digest, SHA512_Digest } from "../Tools/Hash.js"
import { BigIntFromByteArray } from "../Tools/Utils.js"
import { RandomBigInt, mod_inv } from "../Tools/Utils.js"
import SecretShare from "../Tools/secretShare.js"
import GenShardShareResponse from "../model/GenShardShareResponse.js"
import DAuthClient from "../Clients/DAuthClient.js"
import { createAESKey, decryptData } from "../Tools/AES.js"
import ApplyResponseDecrypted from "../model/ApplyResponseDecrypted.js"
import TranToken from "../Tools/TranToken.js"

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

  async GenShard(username, password) {
    try {
      const n = Point.order;
      const random1 = RandomBigInt();
      const random2 = RandomBigInt();
      const gUser = await Point.fromString(username)  //convert username to point
      const gPass = await Point.fromString(password);   //convert password to point
      const gBlurUser = gUser.times(random1); // username point * random
      const gBlurPass = gPass.times(random2); // password point * random
      const r1Inv = mod_inv(random1, n);
      const r2Inv = mod_inv(random2, n);
      const gMul1 = gBlurUser.toBase64(); //convert username point to string base64
      const gMul2 = gBlurPass.toBase64(); //convert password point to string base64
      const multipliers = [gMul1, gMul2];

      const pre_genShardResp = this.clients.map(dAuthClient => dAuthClient.genShard(this.orks, 3, multipliers));
      const genShardResp = await Promise.all(pre_genShardResp);
      const gCMK = genShardResp.map(a => a[0]).reduce((sum, point) => sum.add(point), Point.infinity);

      /**
       * @param {Point[]} share1 
       * @param {Point[]} share2 
       */
      const addShare = (share1, share2) => {
        return share1.map((s, i) => s.add(share2[i]))
      }
      const gMultiplied = genShardResp.map(p => p[2]).reduce((sum, next) => addShare(sum, next)); // adds all of the respective gMultipliers together

      const gUserCMK = gMultiplied[0].times(r1Inv);  //remove the random to get user * cmk
      const gPassPrism = gMultiplied[1].times(r2Inv);  //remove the random to get the password * prism

      const hash_gUserCMK = await SHA512_Digest(gUserCMK.toBase64());
      const CMKmul = BigIntFromByteArray(hash_gUserCMK.subarray(0, 32)); // first 32 bytes

      //const VUID = IdGenerator.seed(hash_gUserCMK.subarray(32, 64)); /// last 32 bytes 
      const gCMKAuth = gCMK.times(CMKmul);
      const gPRISMAuth = Point.g.times(BigIntFromByteArray(await SHA256_Digest(gPassPrism.toBase64())));
      const timestamp = median(genShardResp.map(resp => resp[3]));

      const mergeShare = (share) => {
        return share.map(p => GenShardShareResponse.from(p));
      }
      const shareEncrypted = genShardResp.map(a => a[1]).map(s => mergeShare(s));
      const sortedShareArray = sorting(shareEncrypted);

      return { gCMKAuth: gCMKAuth, gPRISMAuth: gPRISMAuth, timestampCMK: timestamp, ciphersCMK: sortedShareArray, gCMK: gCMK }

    } catch (err) {
      Promise.reject(err);
    }
  }

  async SetKey(ciphers) {
    try {
      const mIdORKs = this.orks.map(ork => ork[2].toBase64());
      const pre_setResponse = this.clients.map((DAuthClient, i) => DAuthClient.setKey(filtering(ciphers.filter(element => element.orkId === this.orks[i][0])), mIdORKs));

      // const idGens = await this.orks.map(c => c.getClientGenerator()); // implement method to only use first 3 orks that reply
      // const ids = idGens.map(idGen => idGen.id);
      // const lis = ids.map(id => SecretShare.getLi(id, ids.values, Point.order));

      const setKeyResponse = await Promise.all(pre_setResponse);

      // const gCMKtest = setKeyResponse.map(resp => resp[0]).reduce((sum, next, i) => sum.add(next[0].times(lis.get(i))), Point.infinity);
      // const gPRISMtest = setKeyResponse.map(resp => resp[0]).reduce((sum, next, i) => sum.add(next[1].times(lis.get(i))), Point.infinity);
      // const gCMK2test = setKeyResponse.map(resp => resp[0]).reduce((sum, next, i) => sum.add(next[2].times(lis.get(i))), Point.infinity);

      const gCMKtest = setKeyResponse.map(resp => resp[0]).reduce((sum, next, i) => sum.add(next[0]), Point.infinity);
      const gPRISMtest = setKeyResponse.map(resp => resp[0]).reduce((sum, next, i) => sum.add(next[1]), Point.infinity);
      const gCMK2test = setKeyResponse.map(resp => resp[0]).reduce((sum, next, i) => sum.add(next[2]), Point.infinity);
      const gCMKR2 = setKeyResponse.reduce((sum, next) => sum.add(next[1]), Point.infinity); // Does Sum (gCMKR2)

      const encryptedStatei = setKeyResponse.map(resp => resp[2]);
      const randomKey = setKeyResponse.map(r => r[3]);

      return { gTests: [gCMKtest, gPRISMtest, gCMK2test], gCMKR2: gCMKR2, state: encryptedStatei, randomKey: randomKey };
    } catch (err) {
      Promise.reject(err);
    }

  }

  async PreCommit(gTests, gCMKR2, state, randomKey, timestamp, gPrismAuth, email) {
    try {
      const mIdORKs = this.orks.map(ork => ork[2].toBase64());
      const pre_commitResponse = this.clients.map((DAuthClient, i) => DAuthClient.preCommit(gTests, gCMKR2, state[i], randomKey[i], gPrismAuth, email, mIdORKs));
      const preCommitResponse = await Promise.all(pre_commitResponse);

      const CMKS = preCommitResponse.reduce((sum, s) => (sum + s) % Point.order);

      const CMKM = await SHA256_Digest(gTests[0].toBase64() + timestamp.toString() + this.userID); // TODO: Add point.to_base64 function . Works? 
      const CMKR = mIdORKs.map(pub => Point.fromB64(pub)).reduce((sum, p) => sum.add(p), Point.infinity).add(gCMKR2);
      const CMKH = await SHA512_Digest(CMKR.toBase64() + gTests[0].toBase64() + CMKM.toString());  //TODO: works?

      const CMKH_int = BigIntFromByteArray(CMKH);

      if (!Point.g.times(CMKS).isEqual(CMKR.add(gTests[0].times(CMKH_int)))) {
        return Promise.reject("Ork Signature Invalid")
      }

      await this.clients.map((DAuthClient, i) => DAuthClient.commit(CMKS, state[i], gCMKR2, mIdORKs));

    } catch (err) {
      Promise.reject(err);
    }
  }




  /**
    *  @param {string} username
    *  @param {string} password
    *  @returns {Promise<[ApplyResponseDecrypted[], TranToken[]]>} 
   */
  async DoConvert(username, password) {
    try {
      const n = Point.order;
      const random1 = RandomBigInt();
      const random2 = RandomBigInt();
      const gUser = await Point.fromString(username)  //convert username to point
      const gPass = await Point.fromString(password);   //convert password to point
      const gBlurUser = gUser.times(random1); // username point * random
      const gBlurPass = gPass.times(random2); // password point * random
      const r2Inv = mod_inv(random2, n);

      const idGens = await this.clienSet.all(c => c.getClientGenerator()); // implement method to only use first 14 orks that reply
      const ids = idGens.map(idGen => idGen.id);
      const lis = ids.map(id => SecretShare.getLi(id, ids.values, Point.order));
      const pre_Prismis = this.clients.map(lis, (DAuthClient, li) => DAuthClient.convert(gBlurUser, gBlurPass, li)); // li is not being sent to ORKs. Instead, when gBlurPassPRISM is returned, it is multiplied by li locally
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

      const VERIFYi = decryptedResponses.map((response, i) => new TranToken().sign(prismAuths[i], create_payload(response.certTime.toArray())));
      return [decryptedResponses, VERIFYi];
    } catch (err) {
      return Promise.reject(err);
    }
  }

  /**
    * @param {string} password
   */
  async GenShardPassword(password) {
    try {
      const n = Point.order;

      const random = RandomBigInt();
      const gPass = await Point.fromString(password);
      const gBlurPass = gPass.times(random);
      const rInv = mod_inv(random, n);

      const gMul1 = gBlurPass.toBase64();
      const multipliers = [gMul1];

      const pre_genShardResp = this.clients.map(DAuthClient => DAuthClient.genShard(this.orks, 1, multipliers));
      const genShardResp = await Promise.all(pre_genShardResp);
      /**
       * @param {Point[]} share1 
       * @param {Point[]} share2 
       */
      const addShare = (share1, share2) => {
        return share1.map((s, i) => s.add(share2[i]))
      }
      const gMultiplied = genShardResp.map(p => p[2]).reduce((sum, next) => addShare(sum, next));

      const gPassPrism = gMultiplied[0].times(rInv);

      const gPRISMAuth = Point.g.times(BigIntFromByteArray(await SHA256_Digest(gPassPrism.toBase64())));

      const mergeShare = (share) => {
        return share.map(p => GenShardShareResponse.from(p));
      }
      const shareEncrypted = genShardResp.map(a => a[1]).map(s => mergeShare(s));
      const sortedShareArray = sorting(shareEncrypted);

      return { gPRISMAuth: gPRISMAuth, ciphers: sortedShareArray }

    } catch (err) {
      Promise.reject(err);
    }
  }

  /**
   * 
   * @param {{orkId: any,data: string}[]} ciphers 
   */
  async SetPRISM(ciphers) {
    try {
      const mIdORKs = this.orks.map(ork => ork[2].toBase64());

      const pre_setPrismResponse = this.clients.map((DAuthClient, i) => DAuthClient.setKey(filtering(ciphers.filter(element => element.orkId === this.orks[i][0])), mIdORKs));

      const idGens = await this.clienSet.all(c => c.getClientGenerator()); // implement method to only use first 14 orks that reply
      const ids = idGens.map(idGen => idGen.id);
      const lis = ids.map(id => SecretShare.getLi(id, ids.values, Point.order));

      const setPrismResponse = await Promise.all(pre_setPrismResponse);

      const gPRISMtest = setPrismResponse.map(resp => resp[0]).reduce((sum, next, i) => sum.add(next[0].times(lis.get(i))), Point.infinity);

      const encryptedStatei = setPrismResponse.map(resp => resp[2]);

      return { gPRISMtest: gPRISMtest, state: encryptedStatei };
    } catch (err) {
      Promise.reject(err);
    }

  }
  /**
   * @param {Point} gPRISMtest
   * @param {string[]} state
   * @param {ApplyResponseDecrypted[]} decryptedResponses
   * @param {Point} gPrismAuth
   * @param {TranToken[]} VERIFYi
   */
  async CommitPRISM(gPRISMtest, state, decryptedResponses, gPrismAuth, VERIFYi) {
    try {
      await this.clients.map((DAuthClient, i) => DAuthClient.commitPrism(state[i], decryptedResponses[i].certTime, VERIFYi[i], gPRISMtest, gPrismAuth));
    } catch (err) {
      Promise.reject(err);
    }
  }
}


function median(numbers) {
  const sorted = numbers.sort();
  const middle = Math.floor(sorted.length / 2);

  if (sorted.length % 2 === 0) {
    return (sorted[middle - 1] + (sorted[middle]) / (BigInt(2)));
  }

  return sorted[middle];
}


//The array  is a combined list from all the orks returns
function sorting(shareEncrypted) {
  const shareArray = shareEncrypted.flat();
  let sortedShareArray = shareArray.sort((a, b) => a.to.localeCompare(b.to) || a.from.localeCompare(b.from)); //Sorting shareEncrypted based on 'to' and then 'from'
  let newarray = [];
  for (let i = 0; i < sortedShareArray.length; i++) {
    let e = {
      "orkId": sortedShareArray[i].to,
      "data": JSON.stringify({ To: sortedShareArray[i].to, From: sortedShareArray[i].from, EncryptedData: sortedShareArray[i].encryptedData })
    }
    newarray.push(e);
  }
  return newarray;
}

function filtering(array) {
  let results = array.map(a => a.data);
  return results;
}

