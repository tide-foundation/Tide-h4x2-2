// Tide Protocol - Infrastructure for the Personal Data economy
// Copyright (C) 2019 Tide Foundation Ltd
//
// This program is free software and is subject to the terms of
// the Tide Community Open Source License as published by the
// Tide Foundation Limited. You may modify it and redistribute
// it in accordance with and subject to the terms of that License.
// This program is distributed WITHOUT WARRANTY of any kind,
// including without any implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE.
// See the Tide Community Open Source License for more details.
// You should have received a copy of the Tide Community Open
// Source License along with this program.
// If not, see https://tide.org/licenses_tcosl-1-0-en
// @ts-check
import Point from "../Ed25519/point.js";
import TranToken from "../Tools/TranToken.js";

export default class ApplyResponseDecrypted {
    /**
    * @param { Point } gBlurUserCMKi
    * @param { Point } gCMK2
    * @param { TranToken } certTimei
    */
    constructor(gBlurUserCMKi, gCMK2, certTimei) {
        this.gBlurUserCMKi = gBlurUserCMKi;
        this.gCMK2 = gCMK2;
        this.certTime = certTimei;
    }

    /** @param {string|object} data */
    static from(data) {
        const obj = typeof data === 'string' ? JSON.parse(data) : data;
        if (!obj.GBlurUserCMKi || !obj.GCMK2 || !obj.CertTimei)
            throw Error(`ApplyResponseDecrypted: The JSON is not in the correct format: ${data}`);

        const gBlurUserCMKi = Point.fromB64(obj.GBlurUserCMKi);
        const gCMK2 = Point.fromB64(obj.GCMK2);
        const certTimei = TranToken.from(obj.CertTimei);

        return new ApplyResponseDecrypted(gBlurUserCMKi, gCMK2, certTimei);
    }
}
