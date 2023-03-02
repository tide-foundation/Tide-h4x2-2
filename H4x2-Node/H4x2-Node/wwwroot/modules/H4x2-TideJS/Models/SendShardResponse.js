import Point from "../Ed25519/point.js";

export default class SendShardResponse{
    /**
     * @param {Point[]} gKtesti 
     * @param {Point} gRi 
     * @param {Point[]} gMultiplied
     * @param {string[]} ephKeyi 
     */
    constructor(gKtesti, gRi, gMultiplied, ephKeyi){
        this.gKtesti = gKtesti
        this.gRi = gRi
        this.gMultiplied = gMultiplied
        this.ephKeyi = ephKeyi
    }

    static from(data){
        const obj = JSON.parse(data);
        const gKtesti = obj.GKntesti.map(p => Point.fromB64(p));
        const gRi = Point.fromB64(obj.GRi);
        const gMultiplied = obj.GMultiplied.map(p => Point.fromB64(p));
        return new SendShardResponse(gKtesti, gRi, gMultiplied, obj.EphKeyi);
    }
}