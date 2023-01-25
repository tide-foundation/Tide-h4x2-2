import { SimulatorFlow, SignUp, Point } from "../modules/H4x2-TideJS/index.js";

(function ($) {
    "use strict";
    window.onload = getAllOrks();
    
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
    var input = $('.validate-input .input100');

    $('.validate-form').on('submit',function(){
        var check = true;
        
        for(var i=0; i<input.length; i++) {
            if(validate(input[i]) == false){
                showValidate(input[i]);
                check=false;
            }
        }
        if(input[1].value != input[2].value){
            check = false;
            alert('Passwords are not match!');
        }
        var values = $('#ork-drop-down').val(); //get the values from multiple drop down
        if(values.length < 3 && window.location.hostname != "localhost"){
            check = false;
            alert('You have to select 3 ork urls !');
        }
        if(check){
            signup(input[0].value , input[1].value, input[3].value, values); 
            //window.location.href = "../modules/H4x2-TideJS/test.html";
        }
        return false;
    });

    $('.validate-form .input100').each(function(){
        $(this).focus(function(){
           hideValidate(this);
        });  
    });

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

    function showValidate(input) {
        var thisAlert = $(input).parent();

        $(thisAlert).addClass('alert-validate');
    }

    function hideValidate(input) {
        var thisAlert = $(input).parent();

        $(thisAlert).removeClass('alert-validate');
    }
    
    /*==================================================================
    [ Show pass ]*/
    var showPass = 0;
    $('.btn-show-pass').on('click', function(){
      
        if(showPass == 0) {
            $(this).next('input').attr('type','text');
            $(this).addClass('active');
            showPass = 1;
        }
        else {
            $(this).next('input').attr('type','password');
            $(this).removeClass('active');
            showPass = 0;
        }
        
        
    });

    async function getAllOrks() {
     
        var config = {
            urls: ["http://localhost:5062"],
        }     
        const flow = new SimulatorFlow(config);
        const activeOrks = await flow.getAllOrks(); 
       
            var select = document.getElementById("ork-drop-down");
            for(var i = 0; i < activeOrks.length; i++) {
                var opt = activeOrks[i];
                var el = document.createElement("option");
                el.textContent = opt[1];
                el.value = opt;
                select.add(el);                       
            }     
    }

    async function signup(user, pass, secretCode, selectedOrks) {
        /**
         * @type {[string, Point][]}
         */
        var orkUrls = [];
        selectedOrks.forEach(element => {
            const myArray = element.split(",");
            orkUrls.push([myArray[2], Point.fromB64(myArray[3])]);
        });

        var config = {
            orkInfo: orkUrls,
            simulatorUrl: 'http://localhost:5062/',
            vendorUrl: 'http://localhost:5231/'
        }
        
        var signup = new SignUp(config);
        await signup.start(user, pass, secretCode);
    }

})(jQuery);

