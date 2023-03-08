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


import NodeClient from "../Clients/NodeClient.js";
import Point from "../Ed25519/point.js";
import PrismFlow from "../Flow/Prism.js";
import { decryptData, encryptData } from "../Tools/AES.js";
import { BigIntToByteArray, RandomBigInt } from "../Tools/Utils.js";
import { SHA256_Digest } from "../Tools/Hash.js"
import { BigIntFromByteArray } from "../Tools/Utils.js"
import SignUp from "../Functions/SignUp.js";
import SignIn from "../Functions/SignIn.js";

var tx = new TextEncoder();

export async function test1(){ // initial client testing
  var x = BigInt("215705799318138126118833849183230698878695522441687139620595388287016472195");
  var pub = Point.g.times(x).toBase64();
  console.log(pub);
}

export async function test2(){ // test Prism flow
  
}

export async function test3(){ // full set up and decryption test
  /**
   * @type {[string, Point][]}
   */
  var orkUrls = [['http://localhost', Point.fromB64('Ds5DKE6hxYNfpNcVRY4NCKznMxh9OwQ9bARan0w4qzbJo/hqrkZfDlZROGRRDzmXVh+iyeheoh3CKSMJ881gIg==')]];

  var pflow = new PrismFlow(orkUrls);
  var pass = "pass1";
  var pPoint = await Point.fromString(pass);

  var CVK = await pflow.Authenticate('myfirstuid5', pPoint);

  var decrypted = await decryptData('9ZVVQCfJsQ5t6TJk7hNT+C97CQm6R3CovhAcVaPqMaoL+ViLxwux', BigIntToByteArray(CVK));

  console.log(decrypted)
}

export async function test4(){ // Test to encrypt data
  /**
   * @type {[string, Point][]}
   */
  var orkUrls = [['http://localhost', Point.fromB64('Ds5DKE6hxYNfpNcVRY4NCKznMxh9OwQ9bARan0w4qzbJo/hqrkZfDlZROGRRDzmXVh+iyeheoh3CKSMJ881gIg==')]];

  var config = {
    orkInfo: orkUrls,
    simulatorUrl: 'http://localhost:5062/',
    vendorUrl: 'http://localhost:5231/'
  }

  var signup = new SignUp(config);
  await signup.start('hulio3', 'password1', 'mySecret2');
}

export async function test5(){ // test to decrypt data
  /**
   * @type {[string, Point][]}
   */
  var orkUrls = [['https://26e511d500104f11.tunnel.tide.org', Point.fromB64('jAcA22UePnZzMbNSxSVt7sozlKA86cGEM77pdoPR1z0CQBhFBdXiNU+XswIqD/4IWSIa/MI0qtaF22vZIfnKFQ==')], ['https://a530acffa31b53a1.tunnel.tide.org', Point.fromB64('YoOu8R56f9pTCVs7unc3BpZkDWXJKK4d0TqrBkxvBkXTOqSFM+O4YCH/TEXZ9wY8dsADYC6eAEjpRSSFutV6Rw==')]];

  var config = {
    simulatorUrl: 'http://localhost:5062/',
    vendorUrl: 'http://localhost:5231/'
  }

  var signin = new SignIn(config);
  var decrypted = await signin.start('hulio', 'password1')
  console.log(decrypted);
}

export async function getRandom(){
  alert(RandomBigInt().toString()) // don't let anyone tell you alert() is bad
}
