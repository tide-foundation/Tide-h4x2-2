import Point from "../Ed25519/point.js";

export default class SetKeyResponse{
    /**
     * @param {Point[]} gKtesti 
     * @param {Point} gRi 
     * @param {string} gKsigni 
     * @param {string} state_id
     */
    constructor(gKtesti, gRi, gKsigni, state_id){
        this.gKtesti = gKtesti
        this.gRi = gRi
        this.gKsigni = gKsigni
        this.state_id = state_id
    }

    static from(data){
        const obj = JSON.parse(data);
        const gKtesti = obj.gKtesti.map(p => Point.fromB64(p));
        const gRi = Point.fromB64(obj.gRi);
        return new SetKeyResponse(gKtesti, gRi, obj.gKsigni, obj.state_id);
    }
}