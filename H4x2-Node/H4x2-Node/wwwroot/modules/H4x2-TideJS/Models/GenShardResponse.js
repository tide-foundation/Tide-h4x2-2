import Point from "../Ed25519/point.js"

export default class GenShardResponse{
    /** 
     * @param {string[]} YijCiphers 
     * @param {Point} GRi
     * @param {bigint} Timestampi 
     */
    constructor(YijCiphers, GRi, Timestampi){
        this.YijCiphers = YijCiphers
        this.GRi = GRi
        this.Timestampi = Timestampi
    }
    static from(data){
        const obj = JSON.parse(data);
        const timestampi = BigInt(obj.Timestampi);
        const gRi = Point.fromB64(obj.GRi)
        return new GenShardResponse(obj.YijCiphers, gRi, timestampi);
    }
}