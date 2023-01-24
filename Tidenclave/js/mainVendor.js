import {SimulatorFlow} from "../modules/H4x2-TideJS/index.js";
(function ($) {
    "use strict";

    $('.validate-form').on('submit', function () {
    
        
        performAction();;
        //window.location.href = "https://docs.microsoft.com/aspnet/core/client-side/bundling-and-minification";
        
        return false;
    });

    async function performAction() {
        
        var config = {
            urls: ["http://localhost:5001"],
        }
     
        const flow = new SimulatorFlow(config);
        const decrypted = await flow.getTideOrk(); 
    
    }


})(jQuery);