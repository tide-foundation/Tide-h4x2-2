import Point from "../Ed25519/point.js";

export default class SetKeyResponse{
    /**
     * @param {Point[]} gKtesti 
     * @param {Point} gRi 
     * @param {string} EncSetKeyStatei 
     */
    constructor(gKtesti, gRi, EncSetKeyStatei){
        this.gKtesti = gKtesti
        this.gRi = gRi
        this.EncSetKeyStatei = EncSetKeyStatei
    }

    static from(data){
        const obj = JSON.parse(data);
        const gKtesti = obj.gKtesti.map(p => Point.fromB64(p));
        const gRi = Point.fromB64(obj.gRi);
        return new SetKeyResponse(gKtesti, gRi, obj.EncSetKeyStatei);
    }
}