import Point from "../Ed25519/point.js";
import { BigIntFromByteArray, base64ToBytes } from "../Tools/Utils.js";

export default class SendShardResponse{
    /**
     * @param {bigint} Si 
     * @param {Point} gK1 
     * @param {string} encCommitStatei
     * @param {Point[]} gMultiplied
     */
    constructor(Si, gK1, encCommitStatei, gMultiplied){
        this.Si = Si
        this.gK1 = gK1
        this.encCommitStatei = encCommitStatei
        this.gMultiplied = gMultiplied
    }

    static from(data){
        const obj = JSON.parse(data);
        const si = BigIntFromByteArray(base64ToBytes(obj.Si));
        const gK1 = Point.fromB64(obj.GK1);
        const gMultiplied = obj.GMultiplied.map(p => p == null ? null : Point.fromB64(p));
        return new SendShardResponse(si, gK1, obj.EncCommitStatei, gMultiplied);
    }
}