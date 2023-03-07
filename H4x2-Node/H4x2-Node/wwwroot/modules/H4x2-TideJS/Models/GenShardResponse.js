import Point from "../Ed25519/point.js"

export default class GenShardResponse{
    /** 
     * @param {string[]} YijCiphers 
     * @param {string[]} gKnCipher
     * @param {bigint} Timestampi 
     */
    constructor(YijCiphers, gKnCipher, Timestampi){
        this.YijCiphers = YijCiphers
        this.GKnCipher = gKnCipher
        this.Timestampi = Timestampi
    }
    static from(data){
        const obj = JSON.parse(data);
        const timestampi = BigInt(obj.Timestampi);
        return new GenShardResponse(obj.YijCiphers, obj.GKnCiphers, timestampi);
    }
}