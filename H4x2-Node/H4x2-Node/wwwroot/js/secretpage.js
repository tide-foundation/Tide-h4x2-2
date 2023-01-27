(function ($) {
    "use strict";
    const queryString = window.location.search;
    const param = new URLSearchParams(queryString);
    const secret = param.get('secret');
    $('#secret').text(secret);

    $('.validate-form').on('submit',function(){
        $('#submit-btn').prop('disabled', true);
        deleteCookies(); 
        window.location.href = "./index.html"; 
        return false;
    });

    function deleteCookies() {
        var cookies = document.cookie.split("; ");
        for (var c = 0; c < cookies.length; c++) {
            var d = window.location.hostname.split(".");
            while (d.length > 0) {
                var cookieBase = encodeURIComponent(cookies[c].split(";")[0].split("=")[0]) + '=; expires= '+ new Date().toUTCString() +'; domain=' + d.join('.') + ' ;path=';
                var p = location.pathname.split('/');
                document.cookie = cookieBase + '/';
                while (p.length > 0) {
                    document.cookie = cookieBase + p.join('/');
                    p.pop();
                };
                d.shift();
            }
        }

    }
    
})(jQuery);
