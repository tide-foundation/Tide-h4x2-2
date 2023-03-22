// 
// Tide Protocol - Infrastructure for a TRUE Zero-Trust paradigm
// Copyright (C) 2022 Tide Foundation Ltd
// 
// This program is free software and is subject to the terms of 
// the Tide Community Open Code License as published by the 
// Tide Foundation Limited. You may modify it and redistribute 
// it in accordance with and subject to the terms of that License.
// This program is distributed WITHOUT WARRANTY of any kind, 
// including without any implied warranty of MERCHANTABILITY or 
// FITNESS FOR A PARTICULAR PURPOSE.
// See the Tide Community Open Code License for more details.
// You should have received a copy of the Tide Community Open 
// Code License along with this program.
// If not, see https://tide.org/licenses_tcoc2-0-0-en
//

import { SignIn, SimulatorFlow, SignUp, Point } from "../modules/H4x2-TideJS/index.js";

(function ($) {
    "use strict";
    window.onload = getAllOrks();
    $('#loader').hide();
    /*==================================================================
    [ Focus input ]*/
    $('.input100').each(function(){
        $(this).on('blur', function(){
            if($(this).val().trim() != "") {
                $(this).addClass('has-val');
            }
            else {
                $(this).removeClass('has-val');
            }
        })    
    })
  
    /*==================================================================
    [ Validate ]*/
    

    $('.validate-form-si').on('submit',function(){
        var input = $('.validate-input-si .input100');

        $('#submit-btn-si').prop('disabled', true);
        var check = true;
        
        for(var i=0; i<input.length; i++) {
            if(validate(input[i]) == false){
                showValidate(input[i]);
                check=false;
            }
        }  
        if(check){
            var el = document.getElementById("on-vendor");
            if(el.innerText === "true"){
                signin_Heimdall(input[0].value, input[1].value);
            }else{
                signin(input[0].value , input[1].value); 
            }
        }  
        else
            $('#submit-btn-si').prop('disabled', false);
        return false;
    });

    $('.validate-form-su').on('submit', function () {
        var input = $('.validate-input-su .input100');
        $('#submit-btn-su').prop('disabled', true);
        var check = true;

        for (var i = 0; i < input.length; i++) {
            if (validate(input[i]) == false) {
                showValidate(input[i]);
                check = false;
            }
        }
        if (input[1].value != input[2].value) {
            check = false;
            showValidate(input[2]);
        }
        var values = $('#ork-drop-down').val();
        if (values.length < 5 && window.location.hostname != "localhost") {
            check = false;
            showValidate('#ork-drop-down');
        }
        if (check){
            var el = document.getElementById("on-vendor");
            if(el.innerText === "true"){
                signup_Heimdall(input[0].value, input[1].value, values);
            }else{
                signup(input[0].value, input[1].value, input[3].value, values);
            }
        }
            
        else
            $('#submit-btn-su').prop('disabled', false);
        return false;
    });

    $('#ork-drop-down').change(function () {
        hideValidate(this);
    });

    $('.validate-form-si .input100').each(function(){
        $(this).focus(function(){
           hideValidate(this);
        });  
    });

    function validate(input) {
        if ($(input).attr('type') == 'email' || $(input).attr('name') == 'email') {
            if ($(input).val().trim().match(/^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{1,5}|[0-9]{1,3})(\]?)$/) == null) {
                return false;
            }
        }
        else {
            if ($(input).val().trim() == '') {
                return false;
            }
        }
    }

    function showValidate(input) {
        var thisAlert = $(input).parent();

        $(thisAlert).addClass('alert-validate');
    }

    function hideValidate(input) {
        var thisAlert = $(input).parent();

        $(thisAlert).removeClass('alert-validate');
    }

    async function getAllOrks() {

        var config = {
            urls: ["https://new-simulator.australiaeast.cloudapp.azure.com"],
        }
        const flow = new SimulatorFlow(config);

        const activeOrks = await flow.getActiveOrks(); 
       
        var select = document.getElementById("ork-drop-down");
        for(var i = 0; i < activeOrks.length; i++) {
            var opt = activeOrks[i];
            var el = document.createElement("option");
            el.textContent = opt[1];
            el.value = opt;
            select.add(el);                       
        } 
        
        $('#orkloader').hide();
        if(activeOrks.length <= 0)  {
            $('#alert-su').text("There is no orks found !"); 
            $('#alert-su').show();
        }  
            
    }
    
    async function signin_Heimdall(user, pass) {
        $('#loader').show();
        var config = {
            simulatorUrl: 'https://new-simulator.australiaeast.cloudapp.azure.com/',
            vendorUrl: 'https://h4x-staging-vendor.azurewebsites.net/'
        } 
        var signin = new SignIn(config);
        var signinResponse = signin.return_UID_CVK(user, pass);

        signinResponse.then((res) => { 
            $('#loader').hide();
            try{parent.heimdall(res)}catch{alert("Could not find heimdall function implemented in vendor OR heimdall function failed")} // HEIMDALL FUNCITON HERE
            $('#submit-btn-si').prop('disabled', false);
        }).catch((res) => { 
            $('#alert-si').text(res); 
            $('#alert-si').show();
            $('#submit-btn-si').prop('disabled', false);
            $('#loader').hide();
        });
       
    }

    async function signin(user, pass) {
        $('#loader').show();
        var config = {
            simulatorUrl: 'https://new-simulator.australiaeast.cloudapp.azure.com/',
            vendorUrl: 'https://h4x-staging-vendor.azurewebsites.net/'
        } 
        var signin = new SignIn(config);
        var signinResponse = signin.start(user, pass);

        signinResponse.then((res) => { 
            $('#loader').hide();
            sessionStorage.setItem("secret", res);
            window.location.href = "./secretpage.html" ;
        }).catch((res) => { 
            $('#alert-si').text(res); 
            $('#alert-si').show();
            $('#submit-btn-si').prop('disabled', false);
            $('#loader').hide();
        });
       
    }

    async function signup_Heimdall(user, pass, selectedOrks) {
        $('#loader-su').show();
        /**
         * @type {[string, string, Point][]}
         */
        var orkUrls = [];
        selectedOrks.forEach(element => {
            const myArray = element.split(",");
            orkUrls.push([myArray[0], myArray[2], Point.fromB64(myArray[3])]);
        });

        var config = {
            orkInfo: orkUrls.sort((a, b) => a[0].localeCompare(b[0])), //Sorting orklist based on ork Id,
            simulatorUrl: 'https://new-simulator.australiaeast.cloudapp.azure.com/',
            vendorUrl: 'https://h4x-staging-vendor.azurewebsites.net/'
        }

        var signup = new SignUp(config);

        var signupResponse =  signup.start_Heimdall(user, pass);
        signupResponse.then((res) => { 
            $('#loader-su').hide();
            try{parent.heimdall(res)}catch{alert("Could not find heimdall function implemented in vendor OR heimdall function failed")} // HEIMDALL FUNCITON HERE
            $('#submit-btn-su').prop('disabled', false);
        }).catch((res) => {
            $('#alert-su').text(res);
            $('#alert-su').show();
            $('#submit-btn-su').prop('disabled', false);
            $('#loader-su').hide();
        });
    }

    async function signup(user, pass, secretCode, selectedOrks) {
        $('#loader-su').show();
        /**
         * @type {[string, string, Point][]}
         */
        var orkUrls = [];
        selectedOrks.forEach(element => {
            const myArray = element.split(",");
            orkUrls.push([myArray[0], myArray[2], Point.fromB64(myArray[3])]);
        });

        var config = {
            orkInfo: orkUrls.sort((a, b) => a[0].localeCompare(b[0])), //Sorting orklist based on ork Id,
            simulatorUrl: 'https://new-simulator.australiaeast.cloudapp.azure.com/',
            vendorUrl: 'https://h4x-staging-vendor.azurewebsites.net/'
        }

        var signup = new SignUp(config);

        var signupResponse =  signup.start(user, pass, secretCode);
        signupResponse.then((res) => { 
            $('#loader-su').hide();
            window.location.href = "./index.html";
        }).catch((res) => {
            $('#alert-su').text(res);
            $('#alert-su').show();
            $('#submit-btn-su').prop('disabled', false);
            $('#loader-su').hide();
        });
    }

    
})(jQuery);

