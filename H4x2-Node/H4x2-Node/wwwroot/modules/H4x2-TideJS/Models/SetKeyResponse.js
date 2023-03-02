import Point from "../Ed25519/point";

export default class SetKeyResponse{
    /**
     * 
     * @param {bigint} s 
     * @param {string} encCommitStatei 
     * @param {Point[]} gKn
     */
    constructor(s, encCommitStatei, gKn){
        this.S = s
        this.EncCommitStatei = encCommitStatei
        this.gKn = gKn
    }

    static from(data){
        const obj = JSON.parse(data);
        const gKn = obj.GKn.map(p => Point.fromB64(p));
        return new SetKeyResponse(BigInt(obj.Si), obj.EncCommitStatei, gKn);
    }
}