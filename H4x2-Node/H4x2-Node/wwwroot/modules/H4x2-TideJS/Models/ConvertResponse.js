import Point from "../Ed25519/point.js"

export default class ConvertResponse {
    /**
     * @param {Point} GBlurPassPrism 
     * @param {string} EncReply 
     */
    constructor(GBlurPassPrism, EncReply) {
        this.GBlurPassPrism = GBlurPassPrism
        this.EncReply = EncReply
    }
    static from(data, li) {
        const obj = JSON.parse(data);
        const gBlurPassPrism = Point.fromB64(obj.GBlurPassPrism).times(li);
        const encReply = obj.EncReply;
        return new ConvertResponse(gBlurPassPrism, encReply);
    }
}