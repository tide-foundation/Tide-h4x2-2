
const queryString = window.location.search;
const param = new URLSearchParams(queryString);
const secret = param.get('secret');
$('#secret').text(secret);