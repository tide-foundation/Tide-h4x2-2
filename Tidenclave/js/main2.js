'use strict';

import {PrismFlow} from "../modules/H4x2-TideJS/index.js";

function validate (input) {
    if($(input).attr('type') == 'email' || $(input).attr('name') == 'email') {
        if($(input).val().trim().match(/^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{1,5}|[0-9]{1,3})(\]?)$/) == null) {
            return false;
        }
    }
    else {
        if($(input).val().trim() == ''){
            return false;
        }
    }
}

var S = {
  init: function () {
    var action = window.location.href,
        i = action.indexOf('?a=');

    S.UI.init();

  }
};
window.addEventListener('load', function () {
    S.init();
  });

S.UI = (function () {
    async function performAction(user, pass) {
      var action,
          current;
  
        var config = {
          urls: ["http://localhost:8001", "http://localhost:7001"],
          encryptedData: [document.getElementById("test").innerText, document.getElementById("prize").innerText]
        }
      
        const flow = new PrismFlow(config);
        const decrypted = await flow.run(user, pass); 
        
        value = decrypted;
     
    }
  
    function bindEvents() {
      document.addEventListener('click', (e) => {
        var input = document.querySelectorAll(".input100");
        if(input[0].value.trim() != '' && input[1].value.trim() != '')
            performAction(input[0].value,input[1].value);
        
      });

    }
    return {
      init: function () {
        bindEvents();
      },

    };
  }());


