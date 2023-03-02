import Point from "../Ed25519/point.js"

export default class GenShardResponse{
    /** 
     * @param {string[]} YijCiphers 
     * @param {string[]} gKnCipher
     * @param {number} Timestampi 
     */
    constructor(YijCiphers, gKnCipher, Timestampi){
        this.YijCiphers = YijCiphers
        this.gKnCipher = gKnCipher
        this.Timestampi = Timestampi
    }
    static from(data){
        const obj = JSON.parse(data);
        const timestampi = parseInt(obj.Timestampi);
        return new GenShardResponse(obj.YijCiphers, obj.GKCiphers, timestampi);
    }
}