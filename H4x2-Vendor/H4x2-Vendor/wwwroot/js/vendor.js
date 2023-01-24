
import {SimulatorFlow} from "../modules/H4x2-TideJS/index.js";

$('.validate-form').on('submit', function () {
    
    performAction();
  
    return false;
});

async function performAction() {
    
    var config = {
        url: ["http://localhost:5001"],
    }
 
    const flow = new SimulatorFlow(config);
    const res = await flow.getTideOrk(); 
    console.log(res);
    window.location.href = "https://docs.microsoft.com/aspnet/core/client-side/bundling-and-minification"; // change the url with with the res
    
}


