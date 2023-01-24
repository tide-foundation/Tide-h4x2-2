import SimulatorClient from "../Clients/SimulatorClient.js"

export default class EntryFlow{
    /**
     * @param {string} url
     */
    constructor(url){
        /**
         * @type {string}
         */
        this.url = url
    }

    async SubmitEntry(userID, signedEntries, ORKUrls){
        const client = new SimulatorClient(this.url);
        await client.AddUserEntry(userID, signedEntries, ORKUrls);
    }
}
