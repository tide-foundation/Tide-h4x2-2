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

import { ChangePassword } from "../modules/H4x2-TideJS/index.js";

(function ($) {
    "use strict";
    $('#alert').hide();
    /*==================================================================
    [ Focus input ]*/
    $('.input100').each(function () {
        $(this).on('blur', function () {
            if ($(this).val().trim() != "") {
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

    $('.validate-form').on('submit', function () {
        $('#submit-btn').prop('disabled', true);
        var check = true;

        for (var i = 0; i < input.length; i++) {
            if (validate(input[i]) == false) {
                showValidate(input[i]);
                check = false;
            }
        }
        if (input[2].value != input[3].value) {
            check = false;
            showValidate(input[3]);
        }
        if (check)
            changePassword(input[0].value, input[1].value, input[2].value);
        else
            $('#submit-btn').prop('disabled', false);
        return false;
    });

    $('.validate-form .input100').each(function () {
        $(this).focus(function () {
            hideValidate(this);
        });
    });

    function validate(input) {
        if ($(input).val().trim() == '') {
            return false;
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


    async function changePassword(user, pass, newPass) {

        var config = {
            simulatorUrl: 'https://h4x22simulator.azurewebsites.net/',
        }
        var changepassword = new ChangePassword(config);
        var changepasswordResponse = changepassword.start(user, pass, newPass);

        changepasswordResponse.then((res) => {
            window.location.href = "./index.html";
        }).catch((res) => {
            $('#alert').text(res);
            $('#alert').show();
            $('#submit-btn').prop('disabled', false);
        });

    }


})(jQuery);

