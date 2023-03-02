import Point from "../Ed25519/point.js"

export default class SignInCVKResponse {
    /**
     * @param {Point} UserCVK 
     * @param {string} EncCVKSi 
     */
    constructor(UserCVK, EncCVKSi) {
        this.UserCVK = UserCVK
        this.EncCVKSi = EncCVKSi
    }
    static from(data) {
        const obj = JSON.parse(data);
        const userCVK = Point.fromB64(obj.UserCVK);
        const encCVKSi = obj.EncCVKSi;
        return new SignInCVKResponse(userCVK, encCVKSi);
    }
}