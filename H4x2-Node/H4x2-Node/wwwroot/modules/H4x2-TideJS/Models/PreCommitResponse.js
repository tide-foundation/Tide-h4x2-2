export default class PreCommitResponse{
    /**
     * 
     * @param {bigint} s 
     * @param {string} encCommitStatei 
     */
    constructor(s, encCommitStatei){
        this.S = s
        this.EncCommitStatei = encCommitStatei
    }

    static from(data){
        const obj = JSON.parse(data);
        return new PreCommitResponse(BigInt(obj.S), obj.EncCommitStatei)
    }
}