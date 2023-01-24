import {PrismFlow, SimulatorFlow} from "../modules/H4x2-TideJS/index.js";
(function ($) {
    "use strict";
    window.onload = performAction();
    // $('#ork-drop-down').change(function() {
    //     if (this.selectedOptions.length < 3) {
    //         $(this).find(':selected').addClass('selected');
    //         $(this).find(':not(:selected)').removeClass('selected');
    //     }else{
    //         $(this)
    //         .find(':selected:not(.selected)')
    //         .prop('selected', false);
    //         alert('You can select upto 3 options only');
    //     }
    //   });  
   
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
        var values = $('#ork-drop-down').val(); //get the values from multiple drop down
        if(values.length < 3){
            check = false;
            alert('You have to select 3 ork urls !');
        }
        if(check){
            performAction2(input[0].value , input[1].value); 
            performAction3(input[0].value , input[3].value);
            window.location.href = "../modules/H4x2-TideJS/test.html";
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

    async function performAction() {
     
        var config = {
            urls: ["http://localhost:5001"],
        }
            
        const flow = new SimulatorFlow(config);
        const res = await flow.getAllOrks(); 
        Promise.all(res).then((r) => {
            console.log(r);
            var urls = r[0];
            var select = document.getElementById("ork-drop-down");
            console.log(urls.length);
        
            for(var i = 0; i < urls.length; i++) {
                var opt = urls[i];
                var el = document.createElement("option");
                el.textContent = opt[2];
                el.value = opt;
                select.add(el);
               
            }
           
       });  
    }

    async function performAction2(user, pass) {
      
        var config = {
            urls: ["http://localhost:6001", "http://localhost:7001"],
            encryptedData: [document.getElementById("test").innerText, document.getElementById("prize").innerText]
        }
     
        const flow = new PrismFlow(config);
        const decrypted = await flow.singup(user, pass); 

    }

    async function performAction3(user, secret) {

        var config = {
            urls: ["http://localhost:8001"],
            encryptedData: [document.getElementById("test").innerText, document.getElementById("prize").innerText]
        }
        
        const flow = new PrismFlow(config);
        const decrypted = await flow.storeToVender(user, secret); 
    
    }

    
})(jQuery);

