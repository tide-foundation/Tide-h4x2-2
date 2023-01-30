import { SignIn } from "../modules/H4x2-TideJS/index.js";

(function ($) {
    "use strict";
    $('#alert').hide();
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
        $('#submit-btn').prop('disabled', true);
        var check = true;
        
        for(var i=0; i<input.length; i++) {
            if(validate(input[i]) == false){
                showValidate(input[i]);
                check=false;
            }
        }  
        if(check)
            signin(input[0].value , input[1].value); 
        else
            $('#submit-btn').prop('disabled', false);
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
    

    async function signin(user, pass) {
        
        var config = {
            simulatorUrl: 'https://h4x22simulator.azurewebsites.net/',
            vendorUrl: 'https://h4x22vendor.azurewebsites.net/'
        } 
        var signin = new SignIn(config);
        var signinResponse = signin.start(user, pass);

        signinResponse.then((res) => { 
            window.location.href = "./secretpage.html?secret=" + res;
        }).catch((res) => { 
            $('#alert').text(res); 
            $('#alert').show();
            $('#submit-btn').prop('disabled', false);
        });
       
    }

    
})(jQuery);

