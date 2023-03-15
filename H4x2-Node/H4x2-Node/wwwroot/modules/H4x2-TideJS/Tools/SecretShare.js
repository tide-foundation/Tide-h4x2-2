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


export default class SecretShare {
    /**
     * @param {bigint} xi
     * @param {bigint[]} xs
     * @param {bigint} m
     * @returns {bigint}
     */
    static getLi(xi, xs, m) {
        return basisPoly(xi, xs, m)
    }

}

function basisPoly(xi, xs, m) {
    var li = xs.filter(xj => !xj.equals(xi))
        .map(xj => xj.minus(xi).modInv(m).times(xj).mod(m))
        .reduce((li, num) => li.times(num).mod(m));
    return li.sign ? m.plus(li) : li; //library does not support unsigned mod (╯°□°)╯
}





