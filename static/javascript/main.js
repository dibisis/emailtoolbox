$(document).ready(function () {
    $("#domain").keyup(function (event) {
        if (event.keyCode == 13) {
            $("#submit").click();
        }
    });
});
window.onload = function () {


    document.getElementById("submit").onclick = function callRoute() {
        returnDnsDetails(document.getElementById("domain").value, document.getElementById("file").value)
    };



    function returnDnsDetails(domain, callType) {

        if (domain.length == 0) {
            document.getElementById("txtHint").innerHTML = " 검색어가 필요합니다.";

        } else {
            var xmlhttp = new XMLHttpRequest();

            xmlhttp.onreadystatechange = function () {
                var date = new Date();
                if (this.readyState == 4 && this.status == 200) {
                    //Clears the hint field
                    document.getElementById("txtHint").innerHTML = "";
                    document.getElementById("loading").innerHTML = '';


                    $('.responseTable').prepend("<div class='panel panel-primary'>" + this.responseText + "<div>")
                }
            };
            document.getElementById("loading").innerHTML = '<div class="sk-three-bounce"><div class="sk-child sk-bounce1"></div><div class="sk-child sk-bounce2"></div><div class="sk-child sk-bounce3"></div></div>';
            if (callType == 'decode6' || callType == 'decode5') {
                xmlhttp.open("GET", '/' + callType + '?siteurl=' + domain, true);
            } else
                xmlhttp.open("GET", '/' + callType + '/' + domain, true);
            xmlhttp.send();

        }
    }

};
