import Point from "../Ed25519/point.js"
import GenShardShare from "./GenShardShare.js"

export default class GenShardResponse{
    /**
     * @param {Point} GK 
     * @param {GenShardShare[]} EncryptedOrkShares 
     * @param {Point[]} GMultiplied 
     * @param {number} Timestampi 
     */
    constructor(GK, EncryptedOrkShares, GMultiplied, Timestampi){
        this.GK = GK
        this.EncryptedOrkShares = EncryptedOrkShares
        this.GMultiplied = GMultiplied
        this.Timestampi = Timestampi
    }
    static from(data){
        const obj = JSON.parse(data);
        const gK = Point.fromB64(obj.GK);
        const encryptedORKShares = obj.EncryptedOrkShares.map(share => GenShardShare.from(share));
        const gMultiplied = obj.GMultiplied.map(point => Point.fromB64(point));
        const timestampi = parseInt(obj.Timestampi);
        return new GenShardResponse(gK, encryptedORKShares, gMultiplied, timestampi);
    }
}