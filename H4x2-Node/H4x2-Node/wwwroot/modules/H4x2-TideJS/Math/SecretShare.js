import { mod, mod_inv } from "../Tools/Utils.js";

/**
 * @param {bigint} xi
 * @param {bigint[]} xs 
 * @param {bigint} m 
 * @returns {bigint}
 */
export function GetLi(xi, xs, m) {
    var li = xs.filter(xj => xj != xi)
        .map(xj => mod(mod_inv(xj-xi, m) * xj), m)
        .reduce((li, num) => mod(li * num, m));
    return li;
}