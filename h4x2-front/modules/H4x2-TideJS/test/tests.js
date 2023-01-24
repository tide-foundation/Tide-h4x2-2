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
import { RandomBigInt } from "../Tools/Utils.js";
import { SHA256_Digest } from "../Tools/Hash.js"
import { BigIntFromByteArray } from "../Tools/Utils.js"

var tx = new TextEncoder();

export async function test1(){ // initial client testing
  var nodeclient = new NodeClient('http://localhost:6001', 'Prism');
  const uid = BigIntFromByteArray(await SHA256_Digest("user")).toString();
  var applied = await nodeclient.Apply(uid, Point.fromB64('uG7uZxtPjT+YBruVT3D/vml8kAs1yi713Mos/DcTbmN0GtOpZo3G1jQBRTIQz8JV2sMB3XT343U+LAsWk9b0Mw=='));
  console.log(applied.toBase64());
}

export async function test2(){ // test AES encryptions
  
  var pass = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  var data = "Chickens"
  var encrypted = await encryptData(data, tx.encode(pass));

  console.log(encrypted)

  var decrypted = await decryptData(encrypted, tx.encode(pass));
  console.log(decrypted);
}

export async function test3(){ // full set up and decryption test
  var config = {
    urls: ["http://localhost:6001", "http://localhost:7001"],
    encryptedData: []
  }

  const flow = new PrismFlow(config);
  await flow.setUp("Julio's UserName","Julio's Password", "Prism", "Encrypt My Chickens");
  // At this point the message "Encrypt My Chickens" will be encrypted with the prismFlow using the password "Julio's Password"
  // The strength of this is that no-one can offline attack the AES encrypted data, even if the password is very short. The attacker MUST 
  // bruteforce by requesting the Test/Prize keys from the orks, which allows us to throttle and MAJORLY slow the attack.
  const decrypted = await flow.run("Julio's UserName","Julio's Password");
  console.log(decrypted);
}

export async function test4(){ // Test to encrypt data
  var config = {
    urls: ["http://localhost:6001", "http://localhost:7001"],
    encryptedData: []
  }

  const flow = new PrismFlow(config);

  await flow.setUp("Julio's UserName","AAA", "Prism", "Example")

  console.log(flow.encryptedData)
}

export async function test5(){ // test to decrypt data
  var config = {
    urls: ["http://localhost:6001", "http://localhost:7001"],
    encryptedData: ["G4GmY31zIa35tEwck14URCEAIjeTA8NV+DgjHpngxASGnTU="] // change this value
  }

  const flow = new PrismFlow(config)
  const decrypted = await flow.run("Julio's UserName","AAA")

  console.log(decrypted)
}

export async function getRandom(){
  alert(RandomBigInt().toString()) // don't let anyone tell you alert() is bad
}
